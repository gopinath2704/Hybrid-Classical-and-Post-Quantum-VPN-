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
import queue
import re
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque
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


def sanitize_error(value: object, limit: int = 280) -> str:
    """Return a bounded, single-line error safe for UI and event-log display."""
    text = " ".join(str(value).split())
    text = re.sub(
        r"(?i)(bearer|token|secret|password|private[_ -]?key)\s*[:=]\s*\S+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[redacted]", text)
    return text[:limit] + ("…" if len(text) > limit else "")


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
    config_path: str | None = None
    server_control_port: int | None = None
    connected_endpoint: str | None = None
    expected_vpn_subnet: str | None = None
    server_fingerprint: str | None = None
    full_tunnel: bool | None = None
    split_tunnel: list[str] = field(default_factory=list)
    ipv6_policy: str | None = None
    dns_mode: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    configured_tun_name: str | None = None
    rekey_interval: int | None = None

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
    DISCONNECT / LOGS commands from the desktop GUI.  Only one VPN
    connection is active at a time; conflicting operations are serialized.
    """

    ALLOWED_UIDS: set[int] | None = None  # None = any local user (dev mode)

    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self._vpn: object | None = None  # VPNClient instance
        self._config: object | None = None
        self._connected_at: float | None = None
        self._lock = threading.Lock()
        self._event_lock = threading.Lock()
        self._events: deque[dict[str, str]] = deque(maxlen=300)
        self._running = True
        self._server_sock: socket.socket | None = None
        self._config_valid = False
        self._config_error = ""
        self._last_failure = ""
        self._last_observed_state: str | None = None
        self._last_observed_epoch: int | None = None
        self._validate_config()

    def _validate_config(self) -> None:
        """Pre-validate configuration at service startup."""
        self._config_valid = False
        self._config_error = ""
        self._config = None
        try:
            path = Path(self.config_path)
            if not path.exists():
                self._config_error = f"Configuration not found: {self.config_path}"
                self._record_event("warning", self._config_error)
                return
            from vpn.config import load_client_config
            self._config = load_client_config(path)
            self._config_valid = True
            self._record_event("info", f"Configuration ready: {self.config_path}")
        except Exception as exc:
            self._config_error = sanitize_error(exc)
            self._record_event("warning", f"Configuration invalid: {self._config_error}")

    def _record_event(self, level: str, message: object) -> None:
        """Append a bounded, sanitized service event without secret material."""
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "level": level.lower() if level in {"info", "warning", "error"} else "info",
            "message": sanitize_error(message),
        }
        with self._event_lock:
            self._events.append(entry)

    def _get_logs(self) -> list[dict[str, str]]:
        with self._event_lock:
            return list(self._events)

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
        self._record_event("info", "Client service started")

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
            elif command == "LOGS":
                ipc_send(conn, {"logs": self._get_logs()})
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
        cfg = self._config
        base = {
            "config_path": self.config_path,
            "server_host": getattr(cfg, "server_host", None),
            "server_control_port": getattr(cfg, "server_control_port", None),
            "expected_vpn_subnet": getattr(cfg, "expected_vpn_subnet", None),
            "server_fingerprint": getattr(cfg, "server_identity_fingerprint", None),
            "full_tunnel": getattr(cfg, "full_tunnel", None),
            "split_tunnel": list(getattr(cfg, "split_tunnel", []) or []),
            "ipv6_policy": getattr(cfg, "ipv6_policy", None),
            "dns_mode": getattr(cfg, "dns_mode", None),
            "dns_servers": list(getattr(cfg, "dns_servers", []) or []),
            "configured_tun_name": getattr(cfg, "tun_name", None),
        }
        if not self._config_valid:
            status = ClientStatus(
                state=ConnectionState.SETUP_REQUIRED.value,
                error=self._config_error,
                **base,
            )
            self._observe_state(status)
            return status

        try:
            from crypto.hybrid_crypto import get_crypto_status
            crypto = get_crypto_status()
        except Exception:
            crypto = {"pqc_mode": "unavailable", "is_quantum_safe": False}

        vpn = self._vpn
        if vpn is None:
            status = ClientStatus(
                state=(ConnectionState.FAILED.value if self._last_failure
                       else ConnectionState.DISCONNECTED.value),
                error=self._last_failure,
                pqc_mode=crypto.get("pqc_mode"),
                is_quantum_safe=crypto.get("is_quantum_safe", False),
                **base,
            )
            self._observe_state(status)
            return status

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
            error=sanitize_error(getattr(vpn, "error", "")),
            uptime_seconds=uptime,
            client_vpn_ip=tunnel.get("client_vpn_ip") if connected else None,
            connected_endpoint=getattr(vpn, "server_ip", None),
            server_vpn_ip=tunnel.get("server_vpn_ip") if connected else None,
            tun_name=tun.name if tun else None,
            tun_mode=tun.mode.name if tun else None,
            epoch=session.epoch if session else None,
            pqc_mode=crypto.get("pqc_mode"),
            is_quantum_safe=crypto.get("is_quantum_safe", False),
            rekey_countdown=max(0, next_rekey - now) if connected and next_rekey else None,
            mtu=tun.mtu if tun else None,
            ipv6_guard_active=(
                bool(getattr(getattr(network, "ipv6", None), "table", None)
                     or getattr(getattr(network, "ipv6", None), "_table_name", None))
                if network else False
            ),
            dns_managed=getattr(network, "dns_cleanup_registered", False) if network else False,
            rekey_interval=(int(tunnel.get("rekey_interval", 0)) or None),
            **base,
        )

        if quality:
            snap = quality.to_dict() if hasattr(quality, "to_dict") else {}
            received = int(snap.get("probes_received", 0) or 0)
            lost = int(getattr(getattr(vpn, "quality", None), "lost", 0) or 0)
            if received:
                status.rtt_ms = snap.get("rtt_ms")
                status.jitter_ms = snap.get("jitter_ms")
            if received or lost:
                status.loss_rate = snap.get("loss_rate")

        self._observe_state(status)
        return status

    def _observe_state(self, status: ClientStatus) -> None:
        if status.state != self._last_observed_state:
            detail = f": {status.error}" if status.error else ""
            self._record_event("error" if status.state == "FAILED" else "info",
                               f"Connection state: {status.state}{detail}")
            self._last_observed_state = status.state
        if status.state == ConnectionState.CONNECTED.value and status.epoch is not None:
            if (self._last_observed_epoch is not None
                    and status.epoch > self._last_observed_epoch):
                self._record_event("info", f"Session rekey completed: epoch {status.epoch}")
            self._last_observed_epoch = status.epoch
        elif status.state != ConnectionState.CONNECTING.value:
            self._last_observed_epoch = None

    def _do_connect(self) -> dict:
        """Initiate a VPN connection. Serialized by _lock."""
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            self._last_failure = ""
            self._record_event("info", "Connect requested")
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
            self._record_event("info", "Secure tunnel connected")
            return {"status": "connected", "info": info}
        except Exception as exc:
            self._vpn = None
            self._connected_at = None
            self._last_failure = sanitize_error(exc)
            self._record_event("error", f"Connection failed: {self._last_failure}")
            return {"error": self._last_failure}
        finally:
            self._lock.release()

    def _do_disconnect(self) -> dict:
        """Disconnect the VPN. Serialized by _lock."""
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            self._record_event("info", "Disconnect requested")
            if self._vpn is None:
                return {"error": "not connected"}
            self._vpn.disconnect()
            self._vpn = None
            self._connected_at = None
            self._last_failure = ""
            self._record_event("info", "Network restored; tunnel disconnected")
            return {"status": "disconnected"}
        except Exception as exc:
            error = sanitize_error(exc)
            self._record_event("error", f"Disconnect failed: {error}")
            return {"error": error}
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

    def logs(self) -> list[dict[str, str]]:
        resp = self.send_command("LOGS")
        if "error" in resp:
            return [{
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "level": "error",
                "message": sanitize_error(resp["error"]),
            }]
        return list(resp.get("logs", []))[-300:]


# ═══════════════════════════════════════════════════════════════════════════
# PYSIDE6 GUI — DESKTOP MILESTONE 2
# ═══════════════════════════════════════════════════════════════════════════

# PySide6 remains optional for service-only deployments.  Keeping these imports
# guarded means the privileged service never needs to initialize a GUI stack.
try:
    from PySide6.QtCore import QObject, QPointF, QRectF, QSize, Qt, QTimer, Signal
    from PySide6.QtGui import QColor, QFont, QGuiApplication, QPainter, QPen
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QScrollArea,
        QSizePolicy,
        QStackedWidget,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by service-only installs
    PYSIDE6_AVAILABLE = False


GUI_COLORS = {
    "background": "#0B0F14",
    "sidebar": "#0D1219",
    "surface": "#101720",
    "card": "#111A24",
    "card_hover": "#15212D",
    "border": "#22303D",
    "border_soft": "#19242E",
    "green": "#00E676",
    "green_dim": "#0B3A27",
    "cyan": "#55C7D9",
    "amber": "#F5A524",
    "red": "#FF5D6C",
    "text": "#F2F5F7",
    "secondary": "#9AA8B5",
    "muted": "#627180",
}

GUI_STATE_COLORS = {
    ConnectionState.DISCONNECTED.value: GUI_COLORS["muted"],
    ConnectionState.CONNECTING.value: GUI_COLORS["amber"],
    ConnectionState.CONNECTED.value: GUI_COLORS["green"],
    ConnectionState.DISCONNECTING.value: GUI_COLORS["amber"],
    ConnectionState.FAILED.value: GUI_COLORS["red"],
    ConnectionState.SETUP_REQUIRED.value: GUI_COLORS["amber"],
}


def format_duration(seconds: float | None) -> str:
    if seconds is None or seconds <= 0:
        return "—"
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def truncate_fingerprint(value: str | None) -> str:
    if not value:
        return "—"
    return value if len(value) <= 24 else f"{value[:12]}…{value[-12:]}"


if PYSIDE6_AVAILABLE:
    MILESTONE2_STYLESHEET = f"""
        QMainWindow, QWidget#root {{
            background-color: {GUI_COLORS['background']};
        }}
        QWidget {{
            color: {GUI_COLORS['text']};
            font-family: "Inter", "Noto Sans", "Segoe UI", sans-serif;
        }}
        QLabel {{ background: transparent; }}
        QFrame#card {{
            background-color: {GUI_COLORS['card']};
            border: 1px solid {GUI_COLORS['border_soft']};
            border-radius: 12px;
        }}
        QFrame#summaryBlock {{
            background-color: {GUI_COLORS['surface']};
            border: 1px solid {GUI_COLORS['border_soft']};
            border-radius: 9px;
        }}
        QScrollArea {{ border: none; background: transparent; }}
        QScrollArea > QWidget > QWidget {{ background: transparent; }}
        QPushButton {{
            border: 1px solid {GUI_COLORS['border']};
            border-radius: 8px;
            background-color: {GUI_COLORS['surface']};
            color: {GUI_COLORS['text']};
            padding: 9px 18px;
            font-size: 12px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: {GUI_COLORS['card_hover']};
            border-color: #344758;
        }}
        QPushButton:disabled {{
            color: {GUI_COLORS['muted']};
            background-color: #10151B;
            border-color: {GUI_COLORS['border_soft']};
        }}
        QPlainTextEdit {{
            background-color: #0C1218;
            color: #C8D2DB;
            border: 1px solid {GUI_COLORS['border_soft']};
            border-radius: 9px;
            padding: 12px;
            selection-background-color: #214833;
            font-family: "JetBrains Mono", "Noto Sans Mono", monospace;
            font-size: 11px;
        }}
        QProgressBar {{
            border: none;
            border-radius: 2px;
            background: {GUI_COLORS['border_soft']};
            max-height: 3px;
        }}
        QProgressBar::chunk {{
            border-radius: 2px;
            background: {GUI_COLORS['amber']};
        }}
    """

    def gui_label(
        text: str,
        size: int = 12,
        color: str | None = None,
        weight: int = 400,
    ) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet(
            f"font-size: {size}px; color: {color or GUI_COLORS['text']}; "
            f"font-weight: {weight};"
        )
        return label


    class Card(QFrame):
        def __init__(self, title: str | None = None, description: str | None = None) -> None:
            super().__init__()
            self.setObjectName("card")
            self.body = QVBoxLayout(self)
            self.body.setContentsMargins(20, 18, 20, 18)
            self.body.setSpacing(12)
            if title:
                self.title_label = gui_label(title, 14, weight=650)
                self.body.addWidget(self.title_label)
            if description:
                desc = gui_label(description, 11, GUI_COLORS["secondary"])
                desc.setWordWrap(True)
                self.body.addWidget(desc)


    class DataRow(QWidget):
        """Compact name/value row used on read-only detail pages."""

        def __init__(self, name: str, value: str = "—") -> None:
            super().__init__()
            row = QHBoxLayout(self)
            row.setContentsMargins(0, 7, 0, 7)
            row.setSpacing(16)
            self.name_label = gui_label(name, 11, GUI_COLORS["secondary"])
            self.value_label = gui_label(value, 11, weight=550)
            self.value_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(self.name_label)
            row.addStretch(1)
            row.addWidget(self.value_label, 2)

        def set_value(self, text: object, color: str | None = None) -> None:
            display = str(text) if text not in (None, "") else "—"
            self.value_label.setText(display)
            self.value_label.setStyleSheet(
                f"font-size: 11px; color: {color or GUI_COLORS['text']}; font-weight: 550;"
            )


    class StatusRow(DataRow):
        def __init__(self, name: str) -> None:
            super().__init__(name)
            self.status_label = self.value_label

        def set_status(self, text: str, active: bool = False, warning: bool = False) -> None:
            color = (GUI_COLORS["green"] if active else
                     GUI_COLORS["amber"] if warning else GUI_COLORS["secondary"])
            self.set_value(text, color)

        # Compatibility with the Milestone 1 helper contract.
        def set_active(self, active: bool, text: str = "") -> None:
            self.set_status(text or ("Active" if active else "Inactive"), active=active)


    class SummaryBlock(QFrame):
        def __init__(self, name: str, value: str = "—") -> None:
            super().__init__()
            self.setObjectName("summaryBlock")
            layout = QVBoxLayout(self)
            layout.setContentsMargins(14, 10, 14, 10)
            layout.setSpacing(3)
            self.name_label = gui_label(name.upper(), 9, GUI_COLORS["muted"], 650)
            self.value_label = gui_label(value, 12, weight=600)
            self.value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(self.name_label)
            layout.addWidget(self.value_label)

        def set_value(self, value: object, color: str | None = None) -> None:
            self.value_label.setText(str(value) if value not in (None, "") else "—")
            self.value_label.setStyleSheet(
                f"font-size: 12px; color: {color or GUI_COLORS['text']}; font-weight: 600;"
            )


    class MetricCard(Card):
        def __init__(self, name: str, note: str) -> None:
            super().__init__()
            self.body.setContentsMargins(15, 14, 15, 14)
            self.body.setSpacing(5)
            self.name_label = gui_label(name.upper(), 9, GUI_COLORS["muted"], 650)
            self.value_label = gui_label("—", 22, weight=650)
            self.note_label = gui_label(note, 9, GUI_COLORS["muted"])
            self.body.addWidget(self.name_label)
            self.body.addWidget(self.value_label)
            self.body.addWidget(self.note_label)

        def set_value(self, value: str, active: bool = False) -> None:
            self.value_label.setText(value or "—")
            color = GUI_COLORS["text"] if active else GUI_COLORS["secondary"]
            self.value_label.setStyleSheet(
                f"font-size: 22px; color: {color}; font-weight: 650;"
            )


    class PowerButton(QPushButton):
        """Painted circular control with an animated legitimate busy state."""

        def __init__(self) -> None:
            super().__init__()
            self.setFixedSize(170, 170)
            self.setCursor(Qt.PointingHandCursor)
            self.setAccessibleName("Connect to VPN")
            self.setToolTip("Connect")
            self.setStyleSheet("QPushButton { background: transparent; border: none; padding: 0; }")
            self._state = ConnectionState.DISCONNECTED.value
            self._hovered = False
            self._phase = 0
            self._animation = QTimer(self)
            self._animation.setInterval(40)
            self._animation.timeout.connect(self._advance)

        def set_state(self, state: str) -> None:
            self._state = state
            if state in {ConnectionState.CONNECTING.value, ConnectionState.DISCONNECTING.value}:
                self._animation.start()
            else:
                self._animation.stop()
            connected = state == ConnectionState.CONNECTED.value
            self.setAccessibleName("Disconnect VPN" if connected else "Connect to VPN")
            self.setToolTip("Disconnect" if connected else "Connect")
            self.update()

        def _advance(self) -> None:
            self._phase = (self._phase + 8) % 360
            self.update()

        def enterEvent(self, event) -> None:
            self._hovered = True
            self.update()
            super().enterEvent(event)

        def leaveEvent(self, event) -> None:
            self._hovered = False
            self.update()
            super().leaveEvent(event)

        def paintEvent(self, event) -> None:  # noqa: N802 - Qt API
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            bounds = QRectF(10, 10, 150, 150)
            state_color = QColor(GUI_STATE_COLORS.get(self._state, GUI_COLORS["muted"]))
            if self._state == ConnectionState.DISCONNECTED.value and self._hovered:
                state_color = QColor(GUI_COLORS["green"])

            if self._state == ConnectionState.CONNECTED.value:
                for width, alpha in ((12, 24), (7, 38)):
                    glow = QColor(state_color)
                    glow.setAlpha(alpha)
                    painter.setPen(QPen(glow, width))
                    painter.drawEllipse(bounds.adjusted(width / 2, width / 2, -width / 2, -width / 2))

            fill = QColor(GUI_COLORS["surface"])
            if self._state == ConnectionState.CONNECTED.value:
                fill = QColor(GUI_COLORS["green_dim"])
            elif self._state in {ConnectionState.CONNECTING.value,
                                ConnectionState.DISCONNECTING.value}:
                fill = QColor("#2B2112")
            elif self._state == ConnectionState.FAILED.value:
                fill = QColor("#2B171B")
            painter.setBrush(fill)
            painter.setPen(QPen(state_color, 4))
            painter.drawEllipse(bounds)

            if self._state in {ConnectionState.CONNECTING.value,
                               ConnectionState.DISCONNECTING.value}:
                painter.setBrush(Qt.NoBrush)
                painter.setPen(QPen(state_color, 5, Qt.SolidLine, Qt.RoundCap))
                painter.drawArc(bounds.adjusted(-3, -3, 3, 3),
                                int(-self._phase * 16), int(105 * 16))

            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(state_color, 7, Qt.SolidLine, Qt.RoundCap))
            icon = bounds.adjusted(48, 45, -48, -45)
            painter.drawArc(icon, 45 * 16, 270 * 16)
            painter.drawLine(QPointF(85, 55), QPointF(85, 88))


    class NavButton(QPushButton):
        def __init__(self, label: str) -> None:
            super().__init__(label)
            self.setCheckable(True)
            self.setFixedHeight(42)
            self.setCursor(Qt.PointingHandCursor)
            self.setStyleSheet(f"""
                QPushButton {{
                    border: none;
                    border-left: 3px solid transparent;
                    border-radius: 7px;
                    background: transparent;
                    color: {GUI_COLORS['secondary']};
                    text-align: left;
                    padding: 8px 13px;
                    font-size: 12px;
                    font-weight: 550;
                }}
                QPushButton:hover {{
                    background: {GUI_COLORS['surface']};
                    color: {GUI_COLORS['text']};
                }}
                QPushButton:checked {{
                    background: #10251D;
                    border-left-color: {GUI_COLORS['green']};
                    color: {GUI_COLORS['green']};
                    font-weight: 650;
                }}
            """)


    class NavRail(QFrame):
        page_selected = Signal(int, str)
        ITEMS = ("Home", "Servers", "Security", "Settings", "Logs", "About")

        def __init__(self) -> None:
            super().__init__()
            self.setFixedWidth(208)
            self.setStyleSheet(
                f"background: {GUI_COLORS['sidebar']}; "
                f"border-right: 1px solid {GUI_COLORS['border_soft']};"
            )
            layout = QVBoxLayout(self)
            layout.setContentsMargins(18, 24, 18, 18)
            layout.setSpacing(5)

            brand_row = QHBoxLayout()
            mark = QLabel("PQ")
            mark.setAlignment(Qt.AlignCenter)
            mark.setFixedSize(38, 38)
            mark.setStyleSheet(f"""
                background: #0E3423;
                color: {GUI_COLORS['green']};
                border: 1px solid #1B5B3D;
                border-radius: 10px;
                font-size: 12px;
                font-weight: 750;
            """)
            names = QVBoxLayout()
            names.setSpacing(0)
            names.addWidget(gui_label("PQ-VPN", 16, weight=700))
            names.addWidget(gui_label("DESKTOP", 8, GUI_COLORS["muted"], 700))
            brand_row.addWidget(mark)
            brand_row.addSpacing(8)
            brand_row.addLayout(names)
            brand_row.addStretch()
            layout.addLayout(brand_row)
            layout.addSpacing(28)

            self.buttons: list[NavButton] = []
            for index, name in enumerate(self.ITEMS):
                button = NavButton(name)
                button.clicked.connect(
                    lambda checked=False, i=index, n=name: self.page_selected.emit(i, n)
                )
                self.buttons.append(button)
                layout.addWidget(button)
            layout.addStretch(1)

            boundary = gui_label("PRIVILEGED CORE", 8, GUI_COLORS["muted"], 700)
            boundary.setAlignment(Qt.AlignCenter)
            detail = gui_label("Connected through local IPC", 9, GUI_COLORS["muted"])
            detail.setAlignment(Qt.AlignCenter)
            version = gui_label(f"Version {APP_VERSION}", 9, GUI_COLORS["muted"])
            version.setAlignment(Qt.AlignCenter)
            layout.addWidget(boundary)
            layout.addWidget(detail)
            layout.addSpacing(11)
            layout.addWidget(version)
            self.activate(0)

        def activate(self, index: int) -> None:
            for item_index, button in enumerate(self.buttons):
                button.setChecked(item_index == index)


    class _IPCWorker(QObject):
        """One daemon worker serializes status, action, and log IPC calls."""

        status_ready = Signal(object)
        action_finished = Signal(str, object)
        logs_ready = Signal(object)

        def __init__(self, ipc: IPCClient) -> None:
            super().__init__()
            self.ipc = ipc
            self._queue: queue.Queue[tuple[str, object | None]] = queue.Queue()
            self._stop_event = threading.Event()
            self._pending_lock = threading.Lock()
            self._status_pending = False
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="pqvpn-gui-ipc"
            )
            self._thread.start()

        def request_status(self) -> None:
            with self._pending_lock:
                if self._status_pending:
                    return
                self._status_pending = True
            self._queue.put(("status", None))

        def request_action(self, action: str) -> None:
            self._queue.put((action, None))

        def request_logs(self) -> None:
            self._queue.put(("logs", None))

        def stop(self) -> None:
            self._stop_event.set()
            self._queue.put(("stop", None))

        def _run(self) -> None:
            while not self._stop_event.is_set():
                command, _ = self._queue.get()
                if command == "stop":
                    return
                try:
                    if command == "status":
                        self.status_ready.emit(self.ipc.status())
                    elif command == "logs":
                        self.logs_ready.emit(self.ipc.logs())
                    elif command in {"connect", "disconnect"}:
                        result = getattr(self.ipc, command)()
                        self.action_finished.emit(command, result)
                except Exception as exc:
                    error = {"error": sanitize_error(exc)}
                    if command == "status":
                        self.status_ready.emit(ClientStatus(
                            state=ConnectionState.FAILED.value,
                            error=error["error"],
                        ))
                    elif command == "logs":
                        self.logs_ready.emit([{
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                            "level": "error",
                            "message": error["error"],
                        }])
                    else:
                        self.action_finished.emit(command, error)
                finally:
                    if command == "status":
                        with self._pending_lock:
                            self._status_pending = False


    def scroll_page(page: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(page)
        return scroll


    class MainWindow(QMainWindow):
        PAGE_TITLES = (
            ("Home", "Connection overview and live tunnel health"),
            ("Servers", "Current pre-provisioned server profile"),
            ("Security", "Cryptography, network protection, and identity"),
            ("Settings", "Validated service-owned configuration (read-only)"),
            ("Logs", "Bounded, sanitized client service events"),
            ("About", "Project scope and security boundaries"),
        )

        def __init__(self, ipc: IPCClient | None = None, start_polling: bool = True) -> None:
            super().__init__()
            self.setObjectName("pqvpnMainWindow")
            self.setWindowTitle("PQ-VPN")
            self.setMinimumSize(980, 650)
            self.resize(1180, 760)
            self.ipc = ipc or IPCClient()
            self._busy = False
            self._last_status = ClientStatus()
            self._gui_events: deque[dict[str, str]] = deque(maxlen=80)

            root = QWidget()
            root.setObjectName("root")
            self.setCentralWidget(root)
            root_layout = QHBoxLayout(root)
            root_layout.setContentsMargins(0, 0, 0, 0)
            root_layout.setSpacing(0)

            self.nav = NavRail()
            self.nav.page_selected.connect(self.switch_page)
            root_layout.addWidget(self.nav)

            shell = QWidget()
            shell_layout = QVBoxLayout(shell)
            shell_layout.setContentsMargins(27, 22, 27, 16)
            shell_layout.setSpacing(14)
            root_layout.addWidget(shell, 1)

            header = QHBoxLayout()
            header_titles = QVBoxLayout()
            header_titles.setSpacing(2)
            self.page_title = gui_label("Home", 23, weight=680)
            self.page_subtitle = gui_label(
                "Connection overview and live tunnel health", 10, GUI_COLORS["secondary"]
            )
            header_titles.addWidget(self.page_title)
            header_titles.addWidget(self.page_subtitle)
            self.pqc_badge = gui_label("PQC backend · CHECKING", 9, GUI_COLORS["muted"], 700)
            self.pqc_badge.setAlignment(Qt.AlignCenter)
            self.pqc_badge.setStyleSheet(self._badge_style(GUI_COLORS["muted"]))
            header.addLayout(header_titles)
            header.addStretch(1)
            header.addWidget(self.pqc_badge)
            shell_layout.addLayout(header)

            self.pages = QStackedWidget()
            self.pages.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self.pages.addWidget(scroll_page(self._build_home_page()))
            self.pages.addWidget(scroll_page(self._build_servers_page()))
            self.pages.addWidget(scroll_page(self._build_security_page()))
            self.pages.addWidget(scroll_page(self._build_settings_page()))
            self.pages.addWidget(self._build_logs_page())
            self.pages.addWidget(scroll_page(self._build_about_page()))
            shell_layout.addWidget(self.pages, 1)

            footer = QHBoxLayout()
            self.footer_state = gui_label("DISCONNECTED", 9, GUI_COLORS["muted"], 700)
            footer.addWidget(self.footer_state)
            footer.addStretch(1)
            footer.addWidget(gui_label(
                "KEMTLS-inspired hybrid  ·  normal-user GUI  ·  privileged service",
                9, GUI_COLORS["muted"]
            ))
            shell_layout.addLayout(footer)

            self._worker = _IPCWorker(self.ipc)
            self._worker.status_ready.connect(self._render)
            self._worker.action_finished.connect(self._action_finished)
            self._worker.logs_ready.connect(self._render_logs)

            self._timer = QTimer(self)
            self._timer.setInterval(1000)
            self._timer.timeout.connect(self._poll_status)
            if start_polling:
                self._timer.start()
                QTimer.singleShot(80, self._poll_status)

        @staticmethod
        def _badge_style(color: str) -> str:
            return (
                f"font-size: 9px; color: {color}; font-weight: 700; "
                f"background: {GUI_COLORS['surface']}; border: 1px solid {color}55; "
                "border-radius: 7px; padding: 7px 11px;"
            )

        def _build_home_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 2, 0, 10)
            layout.setSpacing(10)

            hero = Card()
            hero.body.setContentsMargins(26, 13, 26, 14)
            hero.body.setSpacing(5)

            state_row = QHBoxLayout()
            self.connection_badge = gui_label("OFFLINE", 9, GUI_COLORS["muted"], 700)
            self.connection_badge.setStyleSheet(self._badge_style(GUI_COLORS["muted"]))
            state_row.addStretch(1)
            state_row.addWidget(self.connection_badge)
            hero.body.addLayout(state_row)

            self.power_btn = PowerButton()
            self.power_btn.clicked.connect(self._on_toggle)
            hero.body.addWidget(self.power_btn, alignment=Qt.AlignHCenter)

            self.state_label = gui_label("DISCONNECTED", 20, GUI_COLORS["muted"], 720)
            self.state_label.setAlignment(Qt.AlignCenter)
            self.subtitle_label = gui_label("Ready to establish a secure tunnel", 11,
                                            GUI_COLORS["secondary"])
            self.subtitle_label.setAlignment(Qt.AlignCenter)
            self.subtitle_label.setWordWrap(True)
            self.error_label = gui_label("", 10, GUI_COLORS["red"], 550)
            self.error_label.setAlignment(Qt.AlignCenter)
            self.error_label.setWordWrap(True)
            self.error_label.hide()
            hero.body.addWidget(self.state_label)
            hero.body.addWidget(self.subtitle_label)
            hero.body.addWidget(self.error_label)

            self.connection_progress = QProgressBar()
            self.connection_progress.setRange(0, 0)
            self.connection_progress.setFixedWidth(210)
            self.connection_progress.setTextVisible(False)
            self.connection_progress.hide()
            hero.body.addWidget(self.connection_progress, alignment=Qt.AlignHCenter)

            summary = QHBoxLayout()
            summary.setSpacing(9)
            self.detail_server = SummaryBlock("Configured server")
            self.detail_vpn_ip = SummaryBlock("VPN address")
            self.detail_uptime = SummaryBlock("Connected time")
            summary.addWidget(self.detail_server, 1)
            summary.addWidget(self.detail_vpn_ip, 1)
            summary.addWidget(self.detail_uptime, 1)
            hero.body.addLayout(summary)

            self.action_btn = QPushButton("Connect")
            self.action_btn.setFixedWidth(184)
            self.action_btn.setCursor(Qt.PointingHandCursor)
            self.action_btn.clicked.connect(self._on_toggle)
            hero.body.addWidget(self.action_btn, alignment=Qt.AlignHCenter)
            layout.addWidget(hero)

            metrics = QGridLayout()
            metrics.setContentsMargins(0, 0, 0, 0)
            metrics.setHorizontalSpacing(10)
            metrics.setVerticalSpacing(10)
            self.detail_rtt = MetricCard("Latency", "Authenticated RTT")
            self.detail_jitter = MetricCard("Jitter", "Probe variation")
            self.detail_loss = MetricCard("Packet loss", "Probe window")
            self.detail_rekey = MetricCard("Next rekey", "Session rotation")
            for column, card in enumerate((self.detail_rtt, self.detail_jitter,
                                           self.detail_loss, self.detail_rekey)):
                metrics.addWidget(card, 0, column)
                metrics.setColumnStretch(column, 1)
            layout.addLayout(metrics)

            security = Card("Security at a glance")
            security_grid = QGridLayout()
            security_grid.setHorizontalSpacing(22)
            self.home_pq_title = gui_label("HYBRID KEY ESTABLISHMENT", 9,
                                           GUI_COLORS["muted"], 700)
            self.home_pq_value = gui_label("Configured · ML-KEM-768 + X25519", 11,
                                           GUI_COLORS["secondary"], 600)
            auth_title = gui_label("CLIENT AUTHENTICATION", 9, GUI_COLORS["muted"], 700)
            self.home_auth_value = gui_label("Configured · Ed25519 (classical)", 11,
                                             GUI_COLORS["secondary"], 600)
            traffic_title = gui_label("TRAFFIC CIPHER", 9, GUI_COLORS["muted"], 700)
            self.home_traffic_value = gui_label("Configured · AES-256-GCM", 11,
                                                GUI_COLORS["secondary"], 600)
            for column, pair in enumerate(((self.home_pq_title, self.home_pq_value),
                                           (auth_title, self.home_auth_value),
                                           (traffic_title, self.home_traffic_value))):
                security_grid.addWidget(pair[0], 0, column)
                security_grid.addWidget(pair[1], 1, column)
                security_grid.setColumnStretch(column, 1)
            security.body.addLayout(security_grid)
            layout.addWidget(security)
            layout.addStretch(1)
            return page

        def _build_servers_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 2, 0, 10)
            layout.setSpacing(14)
            card = Card("Configured Server", "This profile is provisioned and owned by the client service.")
            self.server_host_row = DataRow("Server host")
            self.server_port_row = DataRow("Control port")
            self.server_subnet_row = DataRow("Expected VPN subnet")
            self.server_route_row = DataRow("Routing mode")
            self.server_fp_row = DataRow("Server fingerprint")
            for row in (self.server_host_row, self.server_port_row, self.server_subnet_row,
                        self.server_route_row, self.server_fp_row):
                card.body.addWidget(row)
            buttons = QHBoxLayout()
            self.server_refresh_btn = QPushButton("Refresh profile")
            self.server_refresh_btn.clicked.connect(self._poll_status)
            self.server_copy_btn = QPushButton("Copy fingerprint")
            self.server_copy_btn.clicked.connect(self._copy_fingerprint)
            buttons.addWidget(self.server_refresh_btn)
            buttons.addWidget(self.server_copy_btn)
            buttons.addStretch(1)
            card.body.addLayout(buttons)
            layout.addWidget(card)
            self.servers_setup_label = gui_label("", 11, GUI_COLORS["amber"], 550)
            self.servers_setup_label.setWordWrap(True)
            self.servers_setup_label.hide()
            layout.addWidget(self.servers_setup_label)
            note = Card("Milestone 2 scope")
            note.body.addWidget(gui_label(
                "One pre-provisioned profile is shown. No discovery, geolocation, load, "
                "enrollment, or fabricated latency data is used.",
                11, GUI_COLORS["secondary"]
            ))
            layout.addWidget(note)
            layout.addStretch(1)
            return page

        def _build_security_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 2, 0, 10)
            layout.setSpacing(14)
            crypto = Card("Cryptography")
            self.sec_hybrid = StatusRow("Server / session protection")
            self.sec_client_auth = StatusRow("Client authentication")
            self.sec_encryption = StatusRow("Traffic encryption")
            self.sec_protocol = DataRow("Protocol", "KEMTLS-inspired hybrid")
            self.sec_backend = StatusRow("PQC backend")
            self.sec_epoch = DataRow("Current epoch")
            self.sec_rekey = DataRow("Next rekey")
            for row in (self.sec_hybrid, self.sec_client_auth, self.sec_encryption,
                        self.sec_protocol, self.sec_backend, self.sec_epoch, self.sec_rekey):
                crypto.body.addWidget(row)
            layout.addWidget(crypto)

            network = Card("Network protection")
            self.sec_ipv6 = StatusRow("IPv6 protection")
            self.sec_dns = StatusRow("DNS management")
            self.sec_tun = DataRow("TUN mode")
            self.sec_mtu = DataRow("MTU")
            for row in (self.sec_ipv6, self.sec_dns, self.sec_tun, self.sec_mtu):
                network.body.addWidget(row)
            layout.addWidget(network)

            identity = Card("Identity")
            self.sec_fingerprint = DataRow("Pinned server fingerprint")
            self.sec_identity_note = gui_label(
                "Private client key material is never returned over IPC or displayed.",
                10, GUI_COLORS["secondary"]
            )
            identity.body.addWidget(self.sec_fingerprint)
            identity.body.addWidget(self.sec_identity_note)
            layout.addWidget(identity)
            layout.addStretch(1)
            return page

        def _build_settings_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 2, 0, 10)
            layout.setSpacing(14)
            read_only = gui_label("READ-ONLY", 9, GUI_COLORS["cyan"], 700)
            read_only.setStyleSheet(self._badge_style(GUI_COLORS["cyan"]))
            layout.addWidget(read_only, alignment=Qt.AlignLeft)
            card = Card("Connection policy", "Values are validated and owned by the privileged service.")
            self.settings_tunnel = DataRow("Tunnel routing")
            self.settings_ipv6 = DataRow("IPv6 policy")
            self.settings_dns_mode = DataRow("DNS mode")
            self.settings_dns_servers = DataRow("DNS servers")
            self.settings_tun = DataRow("TUN name")
            self.settings_server = DataRow("Configured server")
            self.settings_rekey = DataRow("Rekey interval")
            self.settings_path = DataRow("Configuration path")
            for row in (self.settings_tunnel, self.settings_ipv6, self.settings_dns_mode,
                        self.settings_dns_servers, self.settings_tun, self.settings_server,
                        self.settings_rekey, self.settings_path):
                card.body.addWidget(row)
            layout.addWidget(card)
            layout.addWidget(gui_label(
                "Configuration editing is intentionally deferred: reconnect-safe privileged "
                "writes need a dedicated, narrow API.",
                10, GUI_COLORS["secondary"]
            ))
            layout.addStretch(1)
            return page

        def _build_logs_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 2, 0, 10)
            layout.setSpacing(12)
            actions = QHBoxLayout()
            self.logs_refresh_btn = QPushButton("Refresh")
            self.logs_refresh_btn.clicked.connect(self._refresh_logs)
            self.logs_copy_btn = QPushButton("Copy")
            self.logs_copy_btn.clicked.connect(self._copy_logs)
            actions.addWidget(self.logs_refresh_btn)
            actions.addWidget(self.logs_copy_btn)
            actions.addStretch(1)
            actions.addWidget(gui_label("Maximum 300 service events", 9, GUI_COLORS["muted"]))
            layout.addLayout(actions)
            self.logs_view = QPlainTextEdit()
            self.logs_view.setReadOnly(True)
            self.logs_view.setPlaceholderText("No client service events reported.")
            self.logs_view.document().setMaximumBlockCount(300)
            layout.addWidget(self.logs_view, 1)
            return page

        def _build_about_page(self) -> QWidget:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(0, 2, 0, 10)
            layout.setSpacing(14)
            card = Card()
            title = gui_label("PQ-VPN", 27, weight=720)
            version = gui_label(f"Version {APP_VERSION}", 11, GUI_COLORS["green"], 650)
            description = gui_label(
                "Hybrid Classical + Post-Quantum VPN for Linux", 14,
                GUI_COLORS["secondary"], 550
            )
            description.setWordWrap(True)
            card.body.addWidget(title)
            card.body.addWidget(version)
            card.body.addSpacing(5)
            card.body.addWidget(description)
            card.body.addWidget(gui_label("Research / prototype", 10, GUI_COLORS["amber"], 650))
            layout.addWidget(card)

            crypto = Card("Cryptographic summary")
            crypto.body.addWidget(gui_label("ML-KEM-768 + X25519 server/session protection", 11))
            crypto.body.addWidget(gui_label("Ed25519 client authentication (classical)", 11))
            crypto.body.addWidget(gui_label("AES-256-GCM traffic encryption", 11))
            layout.addWidget(crypto)

            warning = Card("Important security scope")
            warning.body.addWidget(gui_label(
                "Custom KEMTLS-inspired protocol. Not formally verified. Not fully "
                "post-quantum mutual authentication.",
                11, GUI_COLORS["secondary"], 550
            ))
            layout.addWidget(warning)
            layout.addStretch(1)
            return page

        def switch_page(self, index: int, name: str | None = None) -> None:
            if not 0 <= index < self.pages.count():
                return
            self.pages.setCurrentIndex(index)
            self.nav.activate(index)
            title, subtitle = self.PAGE_TITLES[index]
            self.page_title.setText(title)
            self.page_subtitle.setText(subtitle)
            if index == 4:
                self._refresh_logs()

        def _poll_status(self) -> None:
            self._worker.request_status()

        def _refresh_logs(self) -> None:
            self._worker.request_logs()

        def _on_toggle(self) -> None:
            state = self._last_status.state
            if self._busy or state in {ConnectionState.CONNECTING.value,
                                      ConnectionState.DISCONNECTING.value,
                                      ConnectionState.SETUP_REQUIRED.value}:
                return
            action = "disconnect" if state == ConnectionState.CONNECTED.value else "connect"
            transient = (ConnectionState.DISCONNECTING.value if action == "disconnect"
                         else ConnectionState.CONNECTING.value)
            self._busy = True
            self._set_visual_state(transient)
            self._add_gui_event("info", f"{action.title()} requested from desktop")
            self._worker.request_action(action)

        def _action_finished(self, action: str, result: object) -> None:
            self._busy = False
            result = result if isinstance(result, dict) else {"error": "Invalid service response"}
            if "error" in result:
                error = sanitize_error(result["error"])
                values = asdict(self._last_status)
                values.update(state=ConnectionState.FAILED.value, error=error)
                self._render(ClientStatus(**values))
                self._add_gui_event("error", f"{action.title()} failed: {error}")
            else:
                self._add_gui_event("info", f"{action.title()} completed")
            self._worker.request_status()
            if self.pages.currentIndex() == 4:
                self._worker.request_logs()

        def _add_gui_event(self, level: str, message: str) -> None:
            self._gui_events.append({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "level": level,
                "message": sanitize_error(message),
            })

        def _render(self, status: object) -> None:
            if not isinstance(status, ClientStatus):
                status = ClientStatus(
                    state=ConnectionState.FAILED.value,
                    error="Invalid status returned by client service",
                )
            valid_states = {state.value for state in ConnectionState}
            if status.state not in valid_states:
                values = asdict(status)
                values.update(state=ConnectionState.FAILED.value,
                              error="Unsupported connection state returned by service")
                status = ClientStatus(**values)
            self._last_status = status
            state = status.state
            connected = state == ConnectionState.CONNECTED.value
            self._set_visual_state(state)

            messages = {
                ConnectionState.DISCONNECTED.value: "Ready to establish a secure tunnel",
                ConnectionState.CONNECTING.value: "Establishing secure tunnel…",
                ConnectionState.CONNECTED.value: "Encrypted tunnel is active",
                ConnectionState.DISCONNECTING.value: "Restoring network…",
                ConnectionState.FAILED.value: "The connection could not be completed",
                ConnectionState.SETUP_REQUIRED.value: "Client configuration is required",
            }
            self.subtitle_label.setText(messages[state])
            error = sanitize_error(status.error) if status.error else ""
            if state == ConnectionState.SETUP_REQUIRED.value:
                error = error or f"Configuration required: {status.config_path or DEFAULT_CONFIG}"
            self.error_label.setText(error)
            self.error_label.setVisible(bool(error))

            server_display = status.server_host or "—"
            if connected and status.connected_endpoint and status.connected_endpoint != status.server_host:
                server_display = f"{status.server_host or 'Configured Server'} · {status.connected_endpoint}"
            self.detail_server.set_value(server_display)
            self.detail_vpn_ip.set_value(status.client_vpn_ip if connected else "—")
            self.detail_uptime.set_value(format_duration(status.uptime_seconds) if connected else "—")
            self.detail_rtt.set_value(
                f"{status.rtt_ms:.1f} ms" if connected and status.rtt_ms is not None else "—",
                connected and status.rtt_ms is not None,
            )
            self.detail_jitter.set_value(
                f"{status.jitter_ms:.1f} ms" if connected and status.jitter_ms is not None else "—",
                connected and status.jitter_ms is not None,
            )
            self.detail_loss.set_value(
                f"{status.loss_rate * 100:.2f}%" if connected and status.loss_rate is not None else "—",
                connected and status.loss_rate is not None,
            )
            self.detail_rekey.set_value(
                f"{int(status.rekey_countdown)}s"
                if connected and status.rekey_countdown is not None else "—",
                connected and status.rekey_countdown is not None,
            )

            self._render_pq(status, connected)
            self._render_servers(status)
            self._render_security(status, connected)
            self._render_settings(status, connected)

        def _render_pq(self, status: ClientStatus, connected: bool) -> None:
            if connected and status.is_quantum_safe:
                badge = "SERVER PQ PROTECTION · ACTIVE"
                color = GUI_COLORS["green"]
                pq_text = "Active · ML-KEM-768 + X25519"
                pq_color = GUI_COLORS["green"]
            elif connected:
                badge = "SERVER PQ PROTECTION · UNAVAILABLE"
                color = GUI_COLORS["amber"]
                pq_text = "Unavailable · native ML-KEM not reported"
                pq_color = GUI_COLORS["amber"]
            elif status.is_quantum_safe:
                badge = "HYBRID PQ PROTECTION · IDLE"
                color = GUI_COLORS["secondary"]
                pq_text = "Configured · ML-KEM-768 + X25519"
                pq_color = GUI_COLORS["secondary"]
            elif not status.pqc_mode:
                badge = "PQC BACKEND · NOT REPORTED"
                color = GUI_COLORS["muted"]
                pq_text = "Configured · runtime status not reported"
                pq_color = GUI_COLORS["secondary"]
            else:
                badge = "PQC BACKEND · UNAVAILABLE"
                color = GUI_COLORS["amber"]
                pq_text = "Configured · backend unavailable"
                pq_color = GUI_COLORS["amber"]
            self.pqc_badge.setText(badge)
            self.pqc_badge.setStyleSheet(self._badge_style(color))
            self.home_pq_value.setText(pq_text)
            self.home_pq_value.setStyleSheet(
                f"font-size: 11px; color: {pq_color}; font-weight: 600;"
            )
            prefix = "Active" if connected else "Configured"
            active_color = GUI_COLORS["green"] if connected else GUI_COLORS["secondary"]
            self.home_auth_value.setText(f"{prefix} · Ed25519 (classical)")
            self.home_traffic_value.setText(f"{prefix} · AES-256-GCM")
            for label in (self.home_auth_value, self.home_traffic_value):
                label.setStyleSheet(
                    f"font-size: 11px; color: {active_color}; font-weight: 600;"
                )

        def _render_servers(self, status: ClientStatus) -> None:
            self.server_host_row.set_value(status.server_host)
            self.server_port_row.set_value(status.server_control_port)
            self.server_subnet_row.set_value(status.expected_vpn_subnet)
            if status.full_tunnel is True:
                routing = "Full tunnel"
            elif status.full_tunnel is False:
                routing = "Split tunnel" + (f" · {len(status.split_tunnel)} routes"
                                              if status.split_tunnel else "")
            else:
                routing = "—"
            self.server_route_row.set_value(routing)
            self.server_fp_row.set_value(truncate_fingerprint(status.server_fingerprint))
            self.server_copy_btn.setEnabled(bool(status.server_fingerprint))
            setup = (status.state == ConnectionState.SETUP_REQUIRED.value)
            self.servers_setup_label.setText(
                status.error or f"Configuration required: {status.config_path or DEFAULT_CONFIG}"
            )
            self.servers_setup_label.setVisible(setup)

        def _render_security(self, status: ClientStatus, connected: bool) -> None:
            if connected and status.is_quantum_safe:
                self.sec_hybrid.set_status("Active: ML-KEM-768 + X25519", active=True)
            elif connected:
                self.sec_hybrid.set_status("Unavailable: native ML-KEM not active", warning=True)
            else:
                self.sec_hybrid.set_status("Configured: ML-KEM-768 + X25519")
            self.sec_client_auth.set_status(
                ("Active: " if connected else "Configured: ") + "Ed25519 (classical)",
                active=connected,
            )
            self.sec_encryption.set_status(
                ("Active: " if connected else "Configured: ") + "AES-256-GCM",
                active=connected,
            )
            self.sec_protocol.set_value("KEMTLS-inspired hybrid")

            backend = status.pqc_mode or "Not reported"
            if connected and status.is_quantum_safe:
                self.sec_backend.set_status(f"Active: {backend}", active=True)
            elif status.is_quantum_safe:
                self.sec_backend.set_status(f"Available: {backend}")
            elif not status.pqc_mode:
                self.sec_backend.set_status("Not reported")
            else:
                self.sec_backend.set_status(f"Unavailable: {backend}", warning=True)
            self.sec_epoch.set_value(status.epoch if connected and status.epoch is not None else "—")
            self.sec_rekey.set_value(
                f"{int(status.rekey_countdown)} seconds"
                if connected and status.rekey_countdown is not None else "Idle"
            )

            ipv6_active = connected and status.ipv6_guard_active
            dns_active = connected and status.dns_managed
            if connected:
                self.sec_ipv6.set_status("Active" if ipv6_active else "Inactive",
                                         active=ipv6_active)
                self.sec_dns.set_status("Managed" if dns_active else "Unmanaged",
                                        active=dns_active)
            else:
                policy = status.ipv6_policy
                if policy is None and status.full_tunnel is not None:
                    policy = "block" if status.full_tunnel else "allow"
                self.sec_ipv6.set_status(
                    f"Configured: {policy} · Idle" if policy else "Unavailable"
                )
                self.sec_dns.set_status(
                    f"Configured: {status.dns_mode} · Idle"
                    if status.dns_mode else "Unavailable"
                )
            self.sec_tun.set_value(status.tun_mode if connected else "Idle")
            self.sec_mtu.set_value(status.mtu if connected and status.mtu is not None else "—")
            self.sec_fingerprint.set_value(truncate_fingerprint(status.server_fingerprint))

        def _render_settings(self, status: ClientStatus, connected: bool) -> None:
            if status.full_tunnel is True:
                tunnel = "Full tunnel"
            elif status.full_tunnel is False:
                tunnel = "Split tunnel" + (
                    f" · {', '.join(status.split_tunnel)}" if status.split_tunnel else " · no routes"
                )
            else:
                tunnel = "Unavailable"
            policy = status.ipv6_policy
            if policy is None and status.full_tunnel is not None:
                policy = "block (full-tunnel default)" if status.full_tunnel else "allow (split default)"
            self.settings_tunnel.set_value(tunnel)
            self.settings_ipv6.set_value(policy or "Unavailable")
            self.settings_dns_mode.set_value(status.dns_mode or "Unavailable")
            self.settings_dns_servers.set_value(
                ", ".join(status.dns_servers) if status.dns_servers
                else "Provided by server" if status.dns_mode is not None
                else "Unavailable"
            )
            self.settings_tun.set_value(status.configured_tun_name)
            endpoint = status.server_host or "—"
            if status.server_control_port:
                endpoint = f"{endpoint}:{status.server_control_port}"
            self.settings_server.set_value(endpoint)
            self.settings_rekey.set_value(
                f"{status.rekey_interval} seconds" if connected and status.rekey_interval
                else "Negotiated with server on connect" if status.full_tunnel is not None
                else "Not reported"
            )
            self.settings_path.set_value(status.config_path or DEFAULT_CONFIG)

        def _set_visual_state(self, state: str) -> None:
            color = GUI_STATE_COLORS.get(state, GUI_COLORS["muted"])
            self.state_label.setText(state.replace("_", " "))
            self.state_label.setStyleSheet(
                f"font-size: 20px; color: {color}; font-weight: 720;"
            )
            self.power_btn.set_state(state)
            self.connection_badge.setText(
                "PROTECTED" if state == ConnectionState.CONNECTED.value else
                "WORKING" if state in {ConnectionState.CONNECTING.value,
                                       ConnectionState.DISCONNECTING.value} else
                "ATTENTION" if state in {ConnectionState.FAILED.value,
                                         ConnectionState.SETUP_REQUIRED.value} else "OFFLINE"
            )
            self.connection_badge.setStyleSheet(self._badge_style(color))
            self.footer_state.setText(state.replace("_", " "))
            self.footer_state.setStyleSheet(
                f"font-size: 9px; color: {color}; font-weight: 700;"
            )
            busy_state = state in {ConnectionState.CONNECTING.value,
                                   ConnectionState.DISCONNECTING.value}
            self.connection_progress.setVisible(busy_state)

            if state == ConnectionState.CONNECTED.value:
                text = "Disconnect"
                background, foreground, border = "#2A171B", GUI_COLORS["red"], "#63303A"
            elif state == ConnectionState.CONNECTING.value:
                text = "Connecting…"
                background, foreground, border = "#2B2112", GUI_COLORS["amber"], "#61491C"
            elif state == ConnectionState.DISCONNECTING.value:
                text = "Disconnecting…"
                background, foreground, border = "#2B2112", GUI_COLORS["amber"], "#61491C"
            elif state == ConnectionState.FAILED.value:
                text = "Retry"
                background, foreground, border = "#32191E", GUI_COLORS["red"], "#71313C"
            elif state == ConnectionState.SETUP_REQUIRED.value:
                text = "Setup required"
                background, foreground, border = "#211D16", GUI_COLORS["amber"], "#4E4025"
            else:
                text = "Connect"
                background, foreground, border = GUI_COLORS["green"], "#06110B", GUI_COLORS["green"]
            self.action_btn.setText(text)
            self.action_btn.setStyleSheet(f"""
                QPushButton {{
                    min-height: 22px;
                    background: {background}; color: {foreground};
                    border: 1px solid {border}; border-radius: 9px;
                    padding: 10px 22px; font-size: 12px; font-weight: 700;
                }}
                QPushButton:hover {{ border-color: {foreground}; }}
                QPushButton:disabled {{
                    background: #11161C; color: {GUI_COLORS['muted']};
                    border-color: {GUI_COLORS['border_soft']};
                }}
            """)
            enabled = not self._busy and state not in {
                ConnectionState.CONNECTING.value,
                ConnectionState.DISCONNECTING.value,
                ConnectionState.SETUP_REQUIRED.value,
            }
            self.action_btn.setEnabled(enabled)
            self.power_btn.setEnabled(enabled)

        def _copy_fingerprint(self) -> None:
            fingerprint = self._last_status.server_fingerprint
            if fingerprint:
                QGuiApplication.clipboard().setText(fingerprint)

        def _render_logs(self, entries: object) -> None:
            safe_entries: list[dict[str, str]] = []
            if isinstance(entries, list):
                for item in entries[-300:]:
                    if not isinstance(item, dict):
                        continue
                    safe_entries.append({
                        "timestamp": sanitize_error(item.get("timestamp", "—"), 48),
                        "level": sanitize_error(item.get("level", "info"), 12).upper(),
                        "message": sanitize_error(item.get("message", "")),
                    })
            combined = safe_entries + list(self._gui_events)
            combined = combined[-300:]
            lines = [
                f"[{item.get('timestamp', '—')}] "
                f"{str(item.get('level', 'info')).upper():7} "
                f"{sanitize_error(item.get('message', ''))}"
                for item in combined
            ]
            self.logs_view.setPlainText("\n".join(lines))

        def _copy_logs(self) -> None:
            QGuiApplication.clipboard().setText(self.logs_view.toPlainText())

        def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
            self._timer.stop()
            self._worker.stop()
            super().closeEvent(event)


    def _launch_gui() -> None:
        """Launch the normal-user Milestone 2 desktop client."""
        os.environ.setdefault("QT_QPA_PLATFORM", "wayland;xcb")
        app = QApplication(sys.argv)
        app.setApplicationName("PQ-VPN")
        app.setApplicationVersion(APP_VERSION)
        app.setStyleSheet(MILESTONE2_STYLESHEET)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())

else:
    def _launch_gui() -> None:
        print(
            "PySide6 is not installed.  Install with:\n"
            "  pip install 'pqvpn[desktop]'\n"
            "or:\n"
            "  pip install PySide6",
            file=sys.stderr,
        )
        raise SystemExit(1)


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
