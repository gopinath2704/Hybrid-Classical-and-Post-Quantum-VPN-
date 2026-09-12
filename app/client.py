"""
PQ-VPN Desktop Client — GUI and Privileged Service.

Single-file implementation providing:
  1. PySide6 desktop GUI (runs as normal user)
  2. Privileged client service (runs as root/CAP_NET_ADMIN via systemd)
  3. Local Unix-domain-socket IPC with peer credential authorization

Usage:
    python -m app.client                        # Launch GUI
    python -m app.client --service              # Launch privileged service
    python -m app.client --service --config P   # Service with custom config
"""
from __future__ import annotations

import argparse
import enum
import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_VERSION = "2.0.0"
MAX_IPC_MESSAGE = 16384
DEFAULT_CONFIG = "/etc/pqvpn/client.toml"
FALLBACK_CONFIG = "config/client.toml"

# Socket paths: /run/pqvpn is created by RuntimeDirectory= in the systemd unit.
# For development without systemd, fall back to /tmp.
_RUNTIME_DIR = Path(os.environ.get("PQVPN_RUNTIME_DIR", "/run/pqvpn"))
_FALLBACK_DIR = Path("/tmp")

logger = logging.getLogger("pqvpn.client")


def _socket_path() -> Path:
    """Return the IPC socket path, preferring /run/pqvpn."""
    if _RUNTIME_DIR.is_dir():
        return _RUNTIME_DIR / "client.sock"
    return _FALLBACK_DIR / "pqvpn-client.sock"


# ---------------------------------------------------------------------------
# Connection state model
# ---------------------------------------------------------------------------

class ConnectionState(enum.Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    DISCONNECTING = "DISCONNECTING"
    FAILED = "FAILED"
    SETUP_REQUIRED = "SETUP_REQUIRED"


@dataclass
class ClientStatus:
    """Serializable snapshot of the current VPN client state."""
    state: str = ConnectionState.DISCONNECTED.value
    error: str = ""
    uptime_seconds: float = 0.0
    client_vpn_ip: str | None = None
    server_host: str | None = None
    server_vpn_ip: str | None = None
    tun_name: str | None = None
    tun_mode: str | None = None
    epoch: int | None = None
    pqc_mode: str | None = None
    is_quantum_safe: bool = False
    rekey_countdown: float | None = None
    rtt_ms: float | None = None
    jitter_ms: float | None = None
    loss_rate: float | None = None
    ipv6_guard_active: bool = False
    dns_managed: bool = False
    mtu: int | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_json(cls, data: str) -> ClientStatus:
        return cls(**json.loads(data))


# ---------------------------------------------------------------------------
# IPC framing helpers (shared by GUI client and service)
# ---------------------------------------------------------------------------

def ipc_send(sock: socket.socket, payload: dict) -> None:
    """Send a length-prefixed JSON message. Raises on oversized payloads."""
    raw = json.dumps(payload).encode("utf-8")
    if len(raw) > MAX_IPC_MESSAGE:
        raise ValueError("IPC message exceeds maximum size")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def ipc_recv(sock: socket.socket, timeout: float = 10.0) -> dict:
    """Receive a length-prefixed JSON message with bounded size."""
    sock.settimeout(timeout)
    header = _recv_exact(sock, 4)
    if not header:
        raise ConnectionError("IPC connection closed")
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_IPC_MESSAGE:
        raise ValueError(f"IPC message size {size} out of bounds")
    data = _recv_exact(sock, size)
    return json.loads(data.decode("utf-8"))


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("IPC connection closed")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Peer credential check (Linux SO_PEERCRED)
# ---------------------------------------------------------------------------

def get_peer_uid(sock: socket.socket) -> int | None:
    """Return the UID of the connected peer using SO_PEERCRED (Linux)."""
    try:
        SO_PEERCRED = 17  # Linux constant
        cred = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("iII"))
        _pid, uid, _gid = struct.unpack("iII", cred)
        return uid
    except (OSError, struct.error):
        return None


# ═══════════════════════════════════════════════════════════════════════════
# PRIVILEGED CLIENT SERVICE
# ═══════════════════════════════════════════════════════════════════════════

class ClientService:
    """
    Privileged daemon managing VPNClient via local IPC.

    Listens on a Unix domain socket and accepts STATUS / CONNECT /
    DISCONNECT commands from the desktop GUI.  Only one VPN connection
    is active at a time; conflicting operations are serialized.
    """

    ALLOWED_UIDS: set[int] | None = None  # None = any local user (dev mode)

    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self._vpn: object | None = None  # VPNClient instance
        self._connected_at: float | None = None
        self._lock = threading.Lock()
        self._running = True
        self._server_sock: socket.socket | None = None
        self._config_valid = False
        self._config_error = ""
        self._validate_config()

    def _validate_config(self) -> None:
        """Pre-validate configuration at service startup."""
        try:
            path = Path(self.config_path)
            if not path.exists():
                self._config_error = f"Configuration not found: {self.config_path}"
                return
            from vpn.config import load_client_config
            load_client_config(path)
            self._config_valid = True
        except Exception as exc:
            self._config_error = str(exc)

    def _authorize_peer(self, conn: socket.socket) -> bool:
        """Check that the connecting peer is authorized."""
        uid = get_peer_uid(conn)
        if uid is None:
            return False
        # Root is always authorized
        if uid == 0:
            return True
        if self.ALLOWED_UIDS is not None:
            return uid in self.ALLOWED_UIDS
        # In development mode (no explicit allowlist), accept any local user
        return True

    def start(self) -> None:
        """Bind the IPC socket and serve client requests."""
        sock_path = _socket_path()

        # Clean up stale socket
        if sock_path.exists():
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                probe.settimeout(1)
                probe.connect(str(sock_path))
                probe.close()
                raise RuntimeError(f"Another service is already listening on {sock_path}")
            except (ConnectionRefusedError, OSError):
                sock_path.unlink(missing_ok=True)

        sock_path.parent.mkdir(parents=True, exist_ok=True)

        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(str(sock_path))

        # Allow local clients to connect; authorization is enforced via SO_PEERCRED
        os.chmod(str(sock_path), 0o666)

        self._server_sock.listen(4)
        self._server_sock.settimeout(1.0)

        logger.info("Client service listening on %s", sock_path)

        try:
            signal.signal(signal.SIGTERM, lambda *_: self.stop())
        except ValueError:
            pass

        try:
            while self._running:
                try:
                    conn, _ = self._server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        raise
                    break
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True,
                    name="pqvpn-ipc-handler",
                ).start()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        """Shut down the service, disconnecting any active VPN session."""
        self._running = False
        with self._lock:
            if self._vpn is not None:
                try:
                    self._vpn.disconnect()
                except Exception:
                    pass
                self._vpn = None
                self._connected_at = None
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        sock_path = _socket_path()
        sock_path.unlink(missing_ok=True)
        logger.info("Client service stopped")

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle a single IPC client connection."""
        try:
            if not self._authorize_peer(conn):
                logger.warning("Unauthorized IPC peer rejected")
                ipc_send(conn, {"error": "unauthorized"})
                return

            msg = ipc_recv(conn)
            command = msg.get("command", "").upper()

            if command == "STATUS":
                ipc_send(conn, {"status": asdict(self._get_status())})
            elif command == "CONNECT":
                result = self._do_connect()
                ipc_send(conn, result)
            elif command == "DISCONNECT":
                result = self._do_disconnect()
                ipc_send(conn, result)
            else:
                ipc_send(conn, {"error": f"unknown command: {command}"})
        except (ConnectionError, ValueError, json.JSONDecodeError) as exc:
            logger.debug("IPC handler error: %s", exc)
        except Exception:
            logger.exception("Unexpected IPC handler error")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _get_status(self) -> ClientStatus:
        """Build a ClientStatus snapshot from real VPN state."""
        if not self._config_valid:
            return ClientStatus(
                state=ConnectionState.SETUP_REQUIRED.value,
                error=self._config_error,
            )

        vpn = self._vpn
        if vpn is None:
            return ClientStatus(state=ConnectionState.DISCONNECTED.value)

        try:
            from crypto.hybrid_crypto import get_crypto_status
            crypto = get_crypto_status()
        except Exception:
            crypto = {"pqc_mode": "unknown", "is_quantum_safe": False}

        session = getattr(vpn, "session", None)
        tun = getattr(vpn, "tun", None)
        quality = vpn.quality.snapshot() if getattr(vpn, "quality", None) else None
        network = getattr(vpn, "network", None)
        tunnel = getattr(vpn, "tunnel", {}) or {}
        next_rekey = getattr(vpn, "next_rekey", None)
        now = time.monotonic()

        connected = getattr(vpn, "state", "") == "CONNECTED"
        uptime = now - self._connected_at if connected and self._connected_at else 0.0

        status = ClientStatus(
            state=getattr(vpn, "state", ConnectionState.DISCONNECTED.value),
            error=getattr(vpn, "error", ""),
            uptime_seconds=uptime,
            client_vpn_ip=tunnel.get("client_vpn_ip") if connected else None,
            server_host=getattr(vpn, "server_ip", None),
            server_vpn_ip=tunnel.get("server_vpn_ip") if connected else None,
            tun_name=tun.name if tun else None,
            tun_mode=tun.mode.name if tun else None,
            epoch=session.epoch if session else None,
            pqc_mode=crypto.get("pqc_mode"),
            is_quantum_safe=crypto.get("is_quantum_safe", False),
            rekey_countdown=max(0, next_rekey - now) if connected and next_rekey else None,
            mtu=tun.mtu if tun else None,
            ipv6_guard_active=getattr(network, "ipv6", None) is not None
                              and getattr(getattr(network, "ipv6", None), "_table_name", None) is not None
                              if network else False,
            dns_managed=getattr(network, "dns_cleanup_registered", False) if network else False,
        )

        if quality:
            snap = quality.to_dict() if hasattr(quality, "to_dict") else {}
            status.rtt_ms = snap.get("rtt_ms")
            status.jitter_ms = snap.get("jitter_ms")
            status.loss_rate = snap.get("loss_rate")

        return status

    def _do_connect(self) -> dict:
        """Initiate a VPN connection. Serialized by _lock."""
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            if self._vpn is not None:
                state = getattr(self._vpn, "state", "")
                if state in ("CONNECTING", "CONNECTED"):
                    return {"error": "already connected"}

            if not self._config_valid:
                self._validate_config()
            if not self._config_valid:
                return {"error": self._config_error or "configuration invalid"}

            from vpn.config import load_client_config
            from vpn.runtime import VPNClient

            cfg = load_client_config(self.config_path)
            self._vpn = VPNClient(cfg)
            info = self._vpn.connect()
            self._connected_at = time.monotonic()
            return {"status": "connected", "info": info}
        except Exception as exc:
            self._vpn = None
            self._connected_at = None
            return {"error": str(exc)}
        finally:
            self._lock.release()

    def _do_disconnect(self) -> dict:
        """Disconnect the VPN. Serialized by _lock."""
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            if self._vpn is None:
                return {"error": "not connected"}
            self._vpn.disconnect()
            self._vpn = None
            self._connected_at = None
            return {"status": "disconnected"}
        except Exception as exc:
            return {"error": str(exc)}
        finally:
            self._lock.release()


# ═══════════════════════════════════════════════════════════════════════════
# IPC CLIENT (used by the GUI to talk to the service)
# ═══════════════════════════════════════════════════════════════════════════

class IPCClient:
    """Non-privileged IPC client for communicating with the service."""

    def send_command(self, command: str) -> dict:
        """Send a single command and return the response."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(_socket_path()))
            ipc_send(sock, {"command": command})
            return ipc_recv(sock)
        except (ConnectionRefusedError, FileNotFoundError):
            return {"error": "Service not running. Start with: python -m app.client --service"}
        except Exception as exc:
            return {"error": str(exc)}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def status(self) -> ClientStatus:
        resp = self.send_command("STATUS")
        if "error" in resp:
            return ClientStatus(
                state=ConnectionState.FAILED.value,
                error=resp["error"],
            )
        return ClientStatus(**resp.get("status", {}))

    def connect(self) -> dict:
        return self.send_command("CONNECT")

    def disconnect(self) -> dict:
        return self.send_command("DISCONNECT")


# ═══════════════════════════════════════════════════════════════════════════
# PYSIDE6 GUI
# ═══════════════════════════════════════════════════════════════════════════

# Guard the PySide6 import so the service mode, tests, and non-GUI
# environments never require desktop libraries.

def _launch_gui() -> None:
    """Import PySide6 and run the desktop application."""
    try:
        from PySide6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QPushButton, QFrame, QGraphicsDropShadowEffect,
            QSizePolicy, QGridLayout,
        )
        from PySide6.QtCore import Qt, QTimer, QSize
        from PySide6.QtGui import QFont, QColor, QPalette, QIcon
    except ImportError:
        print(
            "PySide6 is not installed.  Install with:\n"
            "  pip install 'pqvpn[desktop]'\n"
            "or:\n"
            "  pip install PySide6",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Color palette ──────────────────────────────────────────────────

    COLORS = {
        "bg_primary": "#0B0F19",
        "bg_secondary": "#101624",
        "bg_card": "#131A2B",
        "bg_sidebar": "#0D1220",
        "border": "#1C2640",
        "accent_green": "#00E676",
        "accent_cyan": "#00F0FF",
        "accent_red": "#EF4444",
        "accent_orange": "#F59E0B",
        "accent_blue": "#3B82F6",
        "text_primary": "#E8ECF4",
        "text_secondary": "#8B95A8",
        "text_muted": "#5A6478",
    }

    STATE_COLORS = {
        "DISCONNECTED": COLORS["text_muted"],
        "CONNECTING": COLORS["accent_orange"],
        "CONNECTED": COLORS["accent_green"],
        "DISCONNECTING": COLORS["accent_orange"],
        "FAILED": COLORS["accent_red"],
        "SETUP_REQUIRED": COLORS["accent_orange"],
    }

    # ── Shared stylesheet ──────────────────────────────────────────────

    STYLESHEET = f"""
        QMainWindow {{
            background-color: {COLORS['bg_primary']};
        }}
        QWidget {{
            color: {COLORS['text_primary']};
            font-family: 'Inter', 'Segoe UI', 'Helvetica Neue', sans-serif;
        }}
        QLabel {{
            background: transparent;
        }}
        QPushButton {{
            border: none;
            border-radius: 8px;
            padding: 10px 24px;
            font-weight: 600;
            font-size: 13px;
        }}
        QPushButton:disabled {{
            opacity: 0.5;
        }}
    """

    # ── Helper to make styled cards ────────────────────────────────────

    def make_card() -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 14px;
                padding: 20px;
            }}
        """)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(24)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(0, 0, 0, 90))
        card.setGraphicsEffect(shadow)
        return card

    def make_label(text: str, size: int = 13, color: str = "", bold: bool = False) -> QLabel:
        lbl = QLabel(text)
        weight = "600" if bold else "400"
        c = color or COLORS["text_primary"]
        lbl.setStyleSheet(f"font-size: {size}px; font-weight: {weight}; color: {c};")
        return lbl

    # ── Power button widget ────────────────────────────────────────────

    class PowerButton(QPushButton):
        """Large circular connect/disconnect control."""

        def __init__(self) -> None:
            super().__init__("⏻")
            self.setFixedSize(120, 120)
            self._state = "DISCONNECTED"
            self._update_style()

        def set_state(self, state: str) -> None:
            self._state = state
            self._update_style()

        def _update_style(self) -> None:
            color = STATE_COLORS.get(self._state, COLORS["text_muted"])
            glow = color + "40"
            border_color = color
            bg = COLORS["bg_secondary"]
            if self._state == "CONNECTED":
                bg = "#0a2a1a"
            elif self._state in ("CONNECTING", "DISCONNECTING"):
                bg = "#2a1f0a"
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {bg};
                    border: 3px solid {border_color};
                    border-radius: 60px;
                    font-size: 42px;
                    color: {color};
                }}
                QPushButton:hover {{
                    background-color: {glow};
                    border: 3px solid {color};
                }}
                QPushButton:pressed {{
                    background-color: {color}30;
                }}
            """)
            disabled = self._state in ("CONNECTING", "DISCONNECTING", "SETUP_REQUIRED")
            self.setEnabled(not disabled)

    # ── Navigation rail ────────────────────────────────────────────────

    class NavRail(QFrame):
        """Left sidebar with branding and navigation placeholders."""

        def __init__(self) -> None:
            super().__init__()
            self.setFixedWidth(200)
            self.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['bg_sidebar']};
                    border-right: 1px solid {COLORS['border']};
                }}
            """)
            layout = QVBoxLayout(self)
            layout.setContentsMargins(16, 20, 16, 16)
            layout.setSpacing(4)

            # Brand
            brand = QLabel("🛡  PQ-VPN")
            brand.setStyleSheet(f"""
                font-size: 18px; font-weight: 700;
                color: {COLORS['accent_cyan']};
                padding-bottom: 4px;
            """)
            subtitle = QLabel("Post-Quantum Secure")
            subtitle.setStyleSheet(f"font-size: 11px; color: {COLORS['text_muted']};")
            layout.addWidget(brand)
            layout.addWidget(subtitle)
            layout.addSpacing(20)

            # Nav items
            items = [
                ("📊", "Dashboard", True),
                ("🖥", "Servers", False),
                ("🛡", "Security", False),
                ("⚙️", "Settings", False),
                ("📋", "Logs", False),
                ("ℹ️", "About", False),
            ]
            for icon, label, active in items:
                btn = QPushButton(f"  {icon}  {label}")
                btn.setFixedHeight(38)
                if active:
                    btn.setStyleSheet(f"""
                        QPushButton {{
                            background-color: {COLORS['accent_green']}15;
                            color: {COLORS['accent_green']};
                            text-align: left;
                            padding-left: 12px;
                            border-radius: 8px;
                            font-weight: 600;
                            font-size: 13px;
                        }}
                    """)
                else:
                    btn.setStyleSheet(f"""
                        QPushButton {{
                            background: transparent;
                            color: {COLORS['text_muted']};
                            text-align: left;
                            padding-left: 12px;
                            border-radius: 8px;
                            font-size: 13px;
                        }}
                        QPushButton:hover {{
                            background-color: {COLORS['bg_card']};
                        }}
                    """)
                    btn.setToolTip("Coming in a future milestone")
                btn.setEnabled(active)
                layout.addWidget(btn)

            layout.addStretch()

            # Footer version
            ver = QLabel(f"v{APP_VERSION}")
            ver.setStyleSheet(f"font-size: 10px; color: {COLORS['text_muted']};")
            ver.setAlignment(Qt.AlignCenter)
            layout.addWidget(ver)

    # ── Detail row helper ──────────────────────────────────────────────

    class DetailRow(QHBoxLayout):
        def __init__(self, icon: str, label: str) -> None:
            super().__init__()
            self.icon_label = QLabel(icon)
            self.icon_label.setFixedWidth(24)
            self.icon_label.setStyleSheet("font-size: 14px;")
            self.name_label = make_label(label, size=12, color=COLORS["text_secondary"])
            self.name_label.setFixedWidth(170)
            self.value_label = make_label("—", size=12)
            self.value_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.addWidget(self.icon_label)
            self.addWidget(self.name_label)
            self.addStretch()
            self.addWidget(self.value_label)

        def set_value(self, text: str, color: str = "") -> None:
            c = color or COLORS["text_primary"]
            self.value_label.setText(text or "—")
            self.value_label.setStyleSheet(f"font-size: 12px; color: {c};")

    # ── Security indicator row ─────────────────────────────────────────

    class SecurityRow(QHBoxLayout):
        def __init__(self, label: str) -> None:
            super().__init__()
            self.name_label = make_label(label, size=12, color=COLORS["text_secondary"])
            self.status_label = make_label("—", size=11)
            self.addWidget(self.name_label)
            self.addStretch()
            self.addWidget(self.status_label)

        def set_active(self, active: bool, text: str = "") -> None:
            if active:
                display = text or "Active"
                color = COLORS["accent_green"]
            else:
                display = text or "Inactive"
                color = COLORS["text_muted"]
            self.status_label.setText(display)
            self.status_label.setStyleSheet(f"font-size: 11px; color: {color}; font-weight: 600;")

    # ── Main window ────────────────────────────────────────────────────

    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle("PQ-VPN — Post-Quantum Secure")
            self.setMinimumSize(960, 640)
            self.resize(1120, 740)

            self.ipc = IPCClient()
            self._busy = False

            # Central widget
            central = QWidget()
            self.setCentralWidget(central)
            root_layout = QHBoxLayout(central)
            root_layout.setContentsMargins(0, 0, 0, 0)
            root_layout.setSpacing(0)

            # Nav rail
            self.nav = NavRail()
            root_layout.addWidget(self.nav)

            # Main content area
            content = QWidget()
            content.setStyleSheet(f"background-color: {COLORS['bg_primary']};")
            content_layout = QVBoxLayout(content)
            content_layout.setContentsMargins(24, 20, 24, 20)
            content_layout.setSpacing(16)
            root_layout.addWidget(content)

            # ── Header ─────────────────────────────────────────────
            header_layout = QHBoxLayout()
            title = make_label("Dashboard", size=22, bold=True)
            self.pqc_badge = make_label("PQC: —", size=11, color=COLORS["text_muted"])
            self.pqc_badge.setStyleSheet(f"""
                font-size: 11px; color: {COLORS['text_muted']};
                background-color: {COLORS['bg_card']};
                border: 1px solid {COLORS['border']};
                border-radius: 6px;
                padding: 4px 10px;
            """)
            header_layout.addWidget(title)
            header_layout.addStretch()
            header_layout.addWidget(self.pqc_badge)
            content_layout.addLayout(header_layout)

            # ── Top row: Connection card + Power button ────────────
            top_row = QHBoxLayout()
            top_row.setSpacing(16)

            # Connection info card
            conn_card = make_card()
            conn_layout = QVBoxLayout(conn_card)
            conn_layout.setSpacing(8)

            self.state_label = make_label("DISCONNECTED", size=18, bold=True,
                                          color=COLORS["text_muted"])
            self.subtitle_label = make_label("Not connected to any server", size=12,
                                              color=COLORS["text_secondary"])
            conn_layout.addWidget(self.state_label)
            conn_layout.addWidget(self.subtitle_label)
            conn_layout.addSpacing(8)

            # Detail rows
            self.detail_uptime = DetailRow("⏱", "Uptime")
            self.detail_vpn_ip = DetailRow("🌐", "VPN IP Address")
            self.detail_server = DetailRow("📍", "Server")
            self.detail_protocol = DetailRow("🔒", "Protocol")
            self.detail_client_auth = DetailRow("🔑", "Client Auth")
            self.detail_tun = DetailRow("🌐", "TUN Interface")
            self.detail_pqc = DetailRow("⚛️", "PQC Mode")
            self.detail_rekey = DetailRow("🔄", "Next Key Rotation")
            self.detail_rtt = DetailRow("📶", "Latency (RTT)")
            self.detail_jitter = DetailRow("📊", "Jitter")
            self.detail_loss = DetailRow("📉", "Packet Loss")

            for row in (self.detail_uptime, self.detail_vpn_ip, self.detail_server,
                        self.detail_protocol, self.detail_client_auth,
                        self.detail_tun, self.detail_pqc,
                        self.detail_rekey, self.detail_rtt, self.detail_jitter,
                        self.detail_loss):
                conn_layout.addLayout(row)

            conn_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            top_row.addWidget(conn_card, stretch=3)

            # Power button area
            power_card = make_card()
            power_layout = QVBoxLayout(power_card)
            power_layout.setAlignment(Qt.AlignCenter)

            self.power_btn = PowerButton()
            self.power_btn.clicked.connect(self._on_toggle)

            self.hero_label = make_label("DISCONNECTED", size=14, bold=True,
                                          color=COLORS["text_muted"])
            self.hero_label.setAlignment(Qt.AlignCenter)

            self.hero_sub = make_label("Click to connect", size=11,
                                        color=COLORS["text_secondary"])
            self.hero_sub.setAlignment(Qt.AlignCenter)

            self.action_btn = QPushButton("Connect")
            self.action_btn.setFixedSize(160, 42)
            self.action_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['accent_green']};
                    color: #000000;
                    border-radius: 8px;
                    font-weight: 700;
                    font-size: 14px;
                }}
                QPushButton:hover {{
                    background-color: {COLORS['accent_green']}cc;
                }}
                QPushButton:disabled {{
                    background-color: {COLORS['text_muted']};
                }}
            """)
            self.action_btn.clicked.connect(self._on_toggle)

            power_layout.addStretch()
            power_layout.addWidget(self.power_btn, alignment=Qt.AlignCenter)
            power_layout.addSpacing(12)
            power_layout.addWidget(self.hero_label)
            power_layout.addWidget(self.hero_sub)
            power_layout.addSpacing(12)
            power_layout.addWidget(self.action_btn, alignment=Qt.AlignCenter)
            power_layout.addStretch()

            power_card.setFixedWidth(260)
            top_row.addWidget(power_card, stretch=1)

            content_layout.addLayout(top_row)

            # ── Bottom row: Security panel ─────────────────────────
            sec_card = make_card()
            sec_layout = QVBoxLayout(sec_card)
            sec_header = make_label("Security Posture", size=14, bold=True)
            sec_layout.addWidget(sec_header)
            sec_layout.addSpacing(8)

            self.sec_pq = SecurityRow("Post-Quantum Handshake")
            self.sec_encryption = SecurityRow("Traffic Encryption")
            self.sec_ipv6 = SecurityRow("IPv6 Protection")
            self.sec_dns = SecurityRow("DNS Protection")

            for row in (self.sec_pq, self.sec_encryption, self.sec_ipv6, self.sec_dns):
                sec_layout.addLayout(row)

            # Set static crypto info that doesn't change with state
            self.sec_encryption.set_active(True, "AES-256-GCM (Configured)")
            self.sec_pq.set_active(False, "ML-KEM-768 (Idle)")

            content_layout.addWidget(sec_card)

            content_layout.addStretch()

            # ── Footer ─────────────────────────────────────────────
            footer = QFrame()
            footer.setFixedHeight(36)
            footer.setStyleSheet(f"""
                QFrame {{
                    background-color: {COLORS['bg_secondary']};
                    border-top: 1px solid {COLORS['border']};
                }}
            """)
            footer_layout = QHBoxLayout(footer)
            footer_layout.setContentsMargins(16, 0, 16, 0)
            self.footer_state = make_label("Disconnected", size=11,
                                            color=COLORS["text_muted"])
            self.footer_protocol = make_label(
                "KEMTLS-inspired hybrid  •  ML-KEM-768 + X25519  •  AES-256-GCM",
                size=10, color=COLORS["text_muted"],
            )
            footer_layout.addWidget(self.footer_state)
            footer_layout.addStretch()
            footer_layout.addWidget(self.footer_protocol)
            content_layout.addWidget(footer)

            # ── Polling timer ──────────────────────────────────────
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._poll_status)
            self._timer.start(2000)

            # Initial poll
            QTimer.singleShot(100, self._poll_status)

        # ── Actions ────────────────────────────────────────────────────

        def _on_toggle(self) -> None:
            if self._busy:
                return
            self._busy = True
            self.action_btn.setEnabled(False)
            self.power_btn.setEnabled(False)

            current = self.state_label.text()
            if current == "CONNECTED":
                self._set_visual_state("DISCONNECTING")
                threading.Thread(target=self._do_disconnect, daemon=True).start()
            else:
                self._set_visual_state("CONNECTING")
                threading.Thread(target=self._do_connect, daemon=True).start()

        def _do_connect(self) -> None:
            try:
                result = self.ipc.connect()
                if "error" in result:
                    self._apply_error(result["error"])
                else:
                    QTimer.singleShot(0, self._poll_status)
            except Exception as exc:
                self._apply_error(str(exc))
            finally:
                self._busy = False

        def _do_disconnect(self) -> None:
            try:
                result = self.ipc.disconnect()
                if "error" in result:
                    self._apply_error(result["error"])
                else:
                    QTimer.singleShot(0, self._poll_status)
            except Exception as exc:
                self._apply_error(str(exc))
            finally:
                self._busy = False

        def _apply_error(self, error: str) -> None:
            def _update():
                self._set_visual_state("FAILED")
                self.subtitle_label.setText(error)
                self.hero_sub.setText(error)
            QTimer.singleShot(0, _update)

        # ── Polling & render ───────────────────────────────────────────

        def _poll_status(self) -> None:
            """Fetch status from the service and update the GUI."""
            try:
                status = self.ipc.status()
                self._render(status)
            except Exception:
                self._set_visual_state("FAILED")
                self.subtitle_label.setText("Service communication error")

        def _render(self, s: ClientStatus) -> None:
            """Update all GUI elements from a ClientStatus snapshot."""
            state = s.state
            self._set_visual_state(state)

            # Subtitle
            if state == "CONNECTED":
                self.subtitle_label.setText(f"Connected to {s.server_host or '—'}")
            elif state == "SETUP_REQUIRED":
                self.subtitle_label.setText(s.error or "Configuration required")
            elif state == "FAILED":
                self.subtitle_label.setText(s.error or "Connection failed")
            elif state == "CONNECTING":
                self.subtitle_label.setText("Establishing secure tunnel…")
            elif state == "DISCONNECTING":
                self.subtitle_label.setText("Cleaning up…")
            else:
                self.subtitle_label.setText("Not connected to any server")

            # Details
            if s.uptime_seconds > 0:
                h, rem = divmod(int(s.uptime_seconds), 3600)
                m, sec = divmod(rem, 60)
                self.detail_uptime.set_value(f"{h:02d}:{m:02d}:{sec:02d}")
            else:
                self.detail_uptime.set_value("—")

            self.detail_vpn_ip.set_value(s.client_vpn_ip or "—")
            self.detail_server.set_value(s.server_host or "—")

            if state == "CONNECTED":
                self.detail_protocol.set_value("KEMTLS-inspired hybrid")
                self.detail_client_auth.set_value("Ed25519 (Classical)")
            else:
                self.detail_protocol.set_value("—")
                self.detail_client_auth.set_value("—")

            tun_display = s.tun_name or "—"
            if s.tun_mode:
                tun_display += f" ({s.tun_mode})"
            self.detail_tun.set_value(tun_display)
            self.detail_pqc.set_value(s.pqc_mode or "—")

            if s.rekey_countdown is not None:
                self.detail_rekey.set_value(f"{int(s.rekey_countdown)}s")
            else:
                self.detail_rekey.set_value("—")

            # Network quality
            if s.rtt_ms is not None:
                self.detail_rtt.set_value(f"{s.rtt_ms:.1f} ms")
            else:
                self.detail_rtt.set_value("—")
            if s.jitter_ms is not None:
                self.detail_jitter.set_value(f"{s.jitter_ms:.1f} ms")
            else:
                self.detail_jitter.set_value("—")
            if s.loss_rate is not None:
                self.detail_loss.set_value(f"{s.loss_rate * 100:.2f}%")
            else:
                self.detail_loss.set_value("—")

            # PQC badge
            if s.pqc_mode:
                badge_color = COLORS["accent_green"] if s.is_quantum_safe else COLORS["accent_orange"]
                self.pqc_badge.setText(f"PQC: {s.pqc_mode}")
                self.pqc_badge.setStyleSheet(f"""
                    font-size: 11px; color: {badge_color};
                    background-color: {COLORS['bg_card']};
                    border: 1px solid {badge_color}40;
                    border-radius: 6px; padding: 4px 10px;
                """)

            # Security posture
            connected = state == "CONNECTED"
            if connected and s.is_quantum_safe:
                self.sec_pq.set_active(True, "ML-KEM-768 (Active)")
            elif connected:
                self.sec_pq.set_active(False, f"ML-KEM-768 ({s.pqc_mode or 'unknown'})")
            else:
                self.sec_pq.set_active(False, "ML-KEM-768 (Idle)")

            self.sec_ipv6.set_active(
                s.ipv6_guard_active,
                "Active" if s.ipv6_guard_active else "Inactive",
            )
            self.sec_dns.set_active(
                s.dns_managed,
                "Managed" if s.dns_managed else "Unmanaged",
            )

            # Footer
            self.footer_state.setText(state)
            color = STATE_COLORS.get(state, COLORS["text_muted"])
            self.footer_state.setStyleSheet(f"font-size: 11px; color: {color}; font-weight: 600;")

        def _set_visual_state(self, state: str) -> None:
            """Update power button, hero text, and action button for a state."""
            color = STATE_COLORS.get(state, COLORS["text_muted"])
            self.state_label.setText(state)
            self.state_label.setStyleSheet(
                f"font-size: 18px; font-weight: 600; color: {color};")
            self.power_btn.set_state(state)
            self.hero_label.setText(state)
            self.hero_label.setStyleSheet(
                f"font-size: 14px; font-weight: 600; color: {color};")

            if state == "CONNECTED":
                self.action_btn.setText("Disconnect")
                self.action_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS['accent_red']};
                        color: #ffffff; border-radius: 8px;
                        font-weight: 700; font-size: 14px;
                    }}
                    QPushButton:hover {{ background-color: {COLORS['accent_red']}cc; }}
                    QPushButton:disabled {{ background-color: {COLORS['text_muted']}; }}
                """)
                self.hero_sub.setText("Tunnel active")
            elif state == "CONNECTING":
                self.action_btn.setText("Connecting…")
                self.hero_sub.setText("Establishing secure tunnel…")
            elif state == "DISCONNECTING":
                self.action_btn.setText("Disconnecting…")
                self.hero_sub.setText("Restoring network…")
            elif state == "FAILED":
                self.action_btn.setText("Retry")
                self.action_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS['accent_orange']};
                        color: #000000; border-radius: 8px;
                        font-weight: 700; font-size: 14px;
                    }}
                    QPushButton:hover {{ background-color: {COLORS['accent_orange']}cc; }}
                    QPushButton:disabled {{ background-color: {COLORS['text_muted']}; }}
                """)
            elif state == "SETUP_REQUIRED":
                self.action_btn.setText("Setup Required")
                self.hero_sub.setText("Configure /etc/pqvpn/client.toml")
            else:
                self.action_btn.setText("Connect")
                self.action_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLORS['accent_green']};
                        color: #000000; border-radius: 8px;
                        font-weight: 700; font-size: 14px;
                    }}
                    QPushButton:hover {{ background-color: {COLORS['accent_green']}cc; }}
                    QPushButton:disabled {{ background-color: {COLORS['text_muted']}; }}
                """)
                self.hero_sub.setText("Click to connect")

            enabled = state not in ("CONNECTING", "DISCONNECTING", "SETUP_REQUIRED")
            self.action_btn.setEnabled(enabled and not self._busy)

    # ── Application entry ──────────────────────────────────────────────

    os.environ.setdefault("QT_QPA_PLATFORM", "wayland;xcb")
    app = QApplication(sys.argv)
    app.setApplicationName("PQ-VPN")
    app.setApplicationVersion(APP_VERSION)
    app.setStyleSheet(STYLESHEET)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m app.client",
        description="PQ-VPN Desktop Client — GUI and Privileged Service",
    )
    parser.add_argument(
        "--service", action="store_true",
        help="Run as privileged client service (requires CAP_NET_ADMIN)",
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help=f"Client configuration path (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.service:
        config = args.config or DEFAULT_CONFIG
        if not Path(config).exists():
            config = FALLBACK_CONFIG
        logger.info("Starting PQ-VPN client service (config: %s)", config)
        service = ClientService(config)
        service.start()
    else:
        _launch_gui()


if __name__ == "__main__":
    main()
