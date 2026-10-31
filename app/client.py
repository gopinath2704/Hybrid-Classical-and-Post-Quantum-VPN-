"""PQ-VPN Desktop Client — PySide6 GUI, privileged service, and Unix IPC."""
from __future__ import annotations

import argparse
import base64
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
from types import SimpleNamespace

APP_VERSION = "2.0.0"
MAX_IPC_MESSAGE = 16384
DEFAULT_CONFIG = "/etc/pqvpn/client.toml"
DEFAULT_STATE_DIR = "/var/lib/pqvpn"

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


class ConnectionState(enum.Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    DISCONNECTING = "DISCONNECTING"
    FAILED = "FAILED"
    SETUP_REQUIRED = "SETUP_REQUIRED"
    # The kill switch is holding all traffic after a lost session or a crash; Disconnect releases it.
    BLOCKED = "BLOCKED"


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
    kill_switch_active: bool = False
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
    managed_mode: bool = False
    setup_complete: bool = True
    identity_ready: bool = False
    identity_fingerprint: str | None = None
    active_profile_id: str | None = None
    active_profile_name: str | None = None
    connected_profile_id: str | None = None
    connected_profile_name: str | None = None
    profile_store_path: str | None = None
    identity_path: str | None = None
    profiles: list[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_json(cls, data: str) -> ClientStatus:
        return cls(**json.loads(data))


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


def get_peer_uid(sock: socket.socket) -> int | None:
    """Return the UID of the connected peer using SO_PEERCRED (Linux)."""
    try:
        SO_PEERCRED = 17  # Linux constant
        cred = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("iII"))
        _pid, uid, _gid = struct.unpack("iII", cred)
        return uid
    except (OSError, struct.error):
        return None


def parse_allowed_uids(value: str) -> set[int]:
    """Parse comma-separated uids; any malformed entry yields an empty set (fail closed)."""
    value = value.replace(" ", "")
    if not value:
        return set()
    if not re.fullmatch(r"[0-9]+(,[0-9]+)*", value):
        logger.warning("Ignoring malformed PQVPN_ALLOWED_UIDS; only root may use the IPC socket")
        return set()
    return {int(uid) for uid in value.split(",")}


class ClientService:
    """Privileged daemon managing VPNClient via local IPC."""

    ALLOWED_UIDS: set[int] = set()  # non-root uids allowed on the IPC socket

    def __init__(self, config_path: str | None = None, state_dir: Path | None = None,
                 pqvpnd_path: str = "/usr/bin/pqvpnd") -> None:
        # A fixed path, never PATH or the environment: this service runs as root.
        self.pqvpnd_path = pqvpnd_path
        self.managed_mode = config_path is None
        self.ALLOWED_UIDS = parse_allowed_uids(os.environ.get("PQVPN_ALLOWED_UIDS", ""))
        self.config_path = config_path
        self.state_dir = Path(
            state_dir or os.environ.get("PQVPN_STATE_DIR", DEFAULT_STATE_DIR)
        )
        self.identity_dir = self.state_dir / "identity"
        self.client_private_path = self.identity_dir / "client_identity_private.key"
        self.client_public_path = self.identity_dir / "client_identity_public.key"
        self.profile_store = None
        if self.managed_mode:
            from vpn.identity import ProfileStore
            self.profile_store = ProfileStore(self.state_dir / "profiles")
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
        self._identity_fingerprint: str | None = None
        self._connected_profile_id: str | None = None
        self._connected_profile_name: str | None = None
        self._kill_switch_stale = _kill_switch_present()
        if self.managed_mode:
            self._ensure_identity_startup()
        self._validate_config()

    def _ensure_identity_startup(self) -> None:
        try:
            from vpn.identity import ensure_client_identity
            self._identity_fingerprint = ensure_client_identity(
                self.client_private_path, self.client_public_path
            )
            self._record_event("info", "Device identity ready")
        except Exception as exc:
            self._identity_fingerprint = None
            self._config_error = sanitize_error(exc)
            self._record_event("error", f"Device identity unavailable: {self._config_error}")

    def _validate_config(self) -> None:
        """Pre-validate configuration at service startup."""
        self._config_valid = False
        self._config_error = ""
        self._config = None
        try:
            if self.managed_mode:
                if not self._identity_fingerprint:
                    self._ensure_identity_startup()
                if not self._identity_fingerprint:
                    self._config_error = "Device identity is unavailable"
                    return
                profile = self.profile_store.active()
                if profile is None:
                    self._config_error = "Import and select a server profile"
                    return
                self._config = self.profile_store.client_config(
                    profile, self.client_private_path
                )
                self._config_valid = True
                self._record_event("info", f"Managed profile ready: {profile.name}")
                return
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

    @staticmethod
    def _require_fields(msg: object, allowed: set[str], required: set[str] | None = None) -> dict:
        if not isinstance(msg, dict):
            raise ValueError("IPC request must be an object")
        if set(msg) - allowed:
            raise ValueError("IPC request contains unknown fields")
        if required and not required.issubset(msg):
            raise ValueError("IPC request is missing required fields")
        if not isinstance(msg.get("command"), str) or not msg["command"]:
            raise ValueError("IPC command must be a nonempty string")
        return msg

    def _public_profiles(self) -> tuple[list[dict], str | None]:
        if not self.managed_mode:
            return [], None
        profiles = [profile.to_dict() for profile in self.profile_store.list()]
        active = self.profile_store.active_id()
        for item in profiles:
            item["active"] = item["profile_id"] == active
        return profiles, active

    def _setup_status(self) -> dict:
        if not self.managed_mode:
            return {
                "managed_mode": False,
                "setup_complete": self._config_valid,
                "identity_ready": False,
                "profiles": [],
                "active_profile_id": None,
                "config_source": self.config_path,
            }
        from vpn.identity import client_public_identity
        profiles, active = self._public_profiles()
        public_key = None
        identity_fingerprint = None
        try:
            public, identity_fingerprint = client_public_identity(
                self.client_private_path, self.client_public_path
            )
            public_key = base64.b64encode(public).decode("ascii")
        except Exception:
            pass
        return {
            "managed_mode": True,
            "setup_complete": bool(identity_fingerprint and active and self._config_valid),
            "identity_ready": bool(identity_fingerprint),
            "identity_public_key": public_key,
            "identity_fingerprint": identity_fingerprint,
            "profiles": profiles,
            "active_profile_id": active,
            "profile_store_path": str(self.profile_store.path),
            "identity_path": str(self.identity_dir),
        }

    def _require_managed(self) -> None:
        if not self.managed_mode:
            raise ValueError("onboarding commands are unavailable in explicit --config mode")

    def _require_profile_mutation_state(self) -> None:
        state = getattr(self._vpn, "state", "") if self._vpn is not None else ""
        if state in {"CONNECTING", "CONNECTED", "DISCONNECTING"}:
            raise ValueError("disconnect before changing server profiles")

    def _ensure_identity(self) -> dict:
        self._require_managed()
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            self._require_profile_mutation_state()
            from vpn.identity import ensure_client_identity
            self._identity_fingerprint = ensure_client_identity(
                self.client_private_path, self.client_public_path
            )
            self._validate_config()
            self._record_event("info", "Device identity ensured without rotation")
            return {"identity": self._setup_status()}
        finally:
            self._lock.release()

    def _import_profile(self, content: object, replace: object = False) -> dict:
        self._require_managed()
        if not isinstance(content, str):
            raise ValueError("profile must be JSON text")
        if type(replace) is not bool:
            raise ValueError("replace must be boolean")
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            self._require_profile_mutation_state()
            from vpn.identity import parse_profile
            profile = parse_profile(content)
            self.profile_store.import_profile(profile, replace=replace)
            self._validate_config()
            self._record_event("info", f"Server profile imported: {profile.name}")
            return {"profile": profile.to_dict()}
        finally:
            self._lock.release()

    def _select_profile(self, profile_id: object) -> dict:
        self._require_managed()
        if not isinstance(profile_id, str):
            raise ValueError("profile_id must be a string")
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            self._require_profile_mutation_state()
            self.profile_store.select(profile_id)
            self._validate_config()
            selected = self.profile_store.get(profile_id)
            self._last_failure = ""
            self._record_event("info", f"Server profile selected: {selected.name}")
            return {"selected_profile_id": profile_id}
        finally:
            self._lock.release()

    def _delete_profile(self, profile_id: object) -> dict:
        self._require_managed()
        if not isinstance(profile_id, str):
            raise ValueError("profile_id must be a string")
        if not self._lock.acquire(blocking=False):
            return {"error": "operation in progress"}
        try:
            self._require_profile_mutation_state()
            self.profile_store.remove(profile_id)
            self._validate_config()
            self._last_failure = ""
            self._record_event("info", f"Server profile removed: {profile_id}")
            return {"removed_profile_id": profile_id}
        finally:
            self._lock.release()

    def _export_enrollment_request(self, client_id: object) -> dict:
        self._require_managed()
        if not isinstance(client_id, str):
            raise ValueError("client_id must be a string")
        from vpn.identity import EnrollmentRequest
        from vpn.identity import client_public_identity
        public, _ = client_public_identity(self.client_private_path, self.client_public_path)
        request = EnrollmentRequest.create(client_id, public)
        self._record_event("info", f"Public enrollment request created for {client_id}")
        return {"enrollment": request.to_dict(), "content": request.to_json()}

    def _dispatch(self, msg: object) -> dict:
        if not isinstance(msg, dict) or not isinstance(msg.get("command"), str):
            raise ValueError("IPC command must be a nonempty string")
        command = msg["command"].upper()
        if command == "STATUS":
            self._require_fields(msg, {"command"})
            return {"status": asdict(self._get_status())}
        if command == "CONNECT":
            self._require_fields(msg, {"command"})
            return self._do_connect()
        if command == "DISCONNECT":
            self._require_fields(msg, {"command"})
            return self._do_disconnect()
        if command == "LOGS":
            self._require_fields(msg, {"command"})
            return {"logs": self._get_logs()}
        if command == "SETUP_STATUS":
            self._require_fields(msg, {"command"})
            return {"setup": self._setup_status()}
        if command == "ENSURE_IDENTITY":
            self._require_fields(msg, {"command"})
            return self._ensure_identity()
        if command == "LIST_PROFILES":
            self._require_fields(msg, {"command"})
            self._require_managed()
            profiles, active = self._public_profiles()
            return {"profiles": profiles, "active_profile_id": active}
        if command == "IMPORT_PROFILE":
            request = self._require_fields(
                msg, {"command", "profile", "replace"}, {"profile"}
            )
            return self._import_profile(request["profile"], request.get("replace", False))
        if command == "SELECT_PROFILE":
            request = self._require_fields(msg, {"command", "profile_id"}, {"profile_id"})
            return self._select_profile(request["profile_id"])
        if command == "DELETE_PROFILE":
            request = self._require_fields(msg, {"command", "profile_id"}, {"profile_id"})
            return self._delete_profile(request["profile_id"])
        if command == "EXPORT_ENROLLMENT_REQUEST":
            request = self._require_fields(msg, {"command", "client_id"}, {"client_id"})
            return self._export_enrollment_request(request["client_id"])
        raise ValueError(f"unknown command: {command}")

    def _authorize_peer(self, conn: socket.socket) -> bool:
        """Check that the connecting peer is authorized."""
        uid = get_peer_uid(conn)
        return uid is not None and (uid == 0 or uid in self.ALLOWED_UIDS)

    def start(self) -> None:
        """Bind the IPC socket and serve client requests."""
        sock_path = _socket_path()

        # Clean up stale socket
        if sock_path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(1)
                probe.connect(str(sock_path))
                raise RuntimeError(f"Another service is already listening on {sock_path}")
            except (ConnectionRefusedError, OSError):
                sock_path.unlink(missing_ok=True)
            finally:
                probe.close()

        sock_path.parent.mkdir(parents=True, exist_ok=True)

        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(str(sock_path))

        # Reachable by any local user; SO_PEERCRED + ALLOWED_UIDS authorize before any command
        os.chmod(str(sock_path), 0o666)

        self._server_sock.listen(4)
        self._server_sock.settimeout(1.0)

        logger.info("Client service listening on %s", sock_path)
        if not self.ALLOWED_UIDS:
            logger.warning("PQVPN_ALLOWED_UIDS is unset: only root may use the IPC socket")
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
                self._connected_profile_id = None
                self._connected_profile_name = None
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

            try:
                ipc_send(conn, self._dispatch(ipc_recv(conn)))
            except (ValueError, json.JSONDecodeError, TypeError) as exc:
                logger.debug("IPC request rejected: %s", exc)
                ipc_send(conn, {"error": sanitize_error(exc) or "invalid request"})
        except ConnectionError as exc:
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
        profiles: list[dict] = []
        active_profile_id = None
        active_profile_name = None
        if self.managed_mode:
            try:
                profiles, active_profile_id = self._public_profiles()
                active = self.profile_store.get(active_profile_id) if active_profile_id else None
                active_profile_name = active.name if active else None
            except Exception as exc:
                self._config_valid = False
                self._config_error = sanitize_error(exc)
        base = {
            "config_path": (str(self.profile_store.path) if self.managed_mode
                            else self.config_path),
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
            "managed_mode": self.managed_mode,
            "setup_complete": self._config_valid,
            "identity_ready": bool(self._identity_fingerprint) if self.managed_mode else False,
            "identity_fingerprint": self._identity_fingerprint if self.managed_mode else None,
            "active_profile_id": active_profile_id,
            "active_profile_name": active_profile_name,
            "connected_profile_id": self._connected_profile_id,
            "connected_profile_name": self._connected_profile_name,
            "profile_store_path": (str(self.profile_store.path)
                                   if self.managed_mode else None),
            "identity_path": str(self.identity_dir) if self.managed_mode else None,
            "profiles": profiles,
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
        if isinstance(self._vpn, NativeClient):
            # pqvpnd's own aws-lc ML-KEM-768, not this process's liboqs; quantum-safe once a hybrid suite is negotiated.
            crypto = {"pqc_mode": "native_aws_lc", "is_quantum_safe": self._vpn.suite in HYBRID_SUITES}

        vpn = self._vpn
        if vpn is None and self._kill_switch_stale:
            status = ClientStatus(
                state=ConnectionState.BLOCKED.value,
                error="A kill switch left by an earlier session is blocking all traffic; disconnect to restore the network",
                kill_switch_active=True,
                pqc_mode=crypto.get("pqc_mode"),
                is_quantum_safe=crypto.get("is_quantum_safe", False),
                **base,
            )
            self._observe_state(status)
            return status
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
            kill_switch_active=(vpn.kill_switch_active if isinstance(vpn, NativeClient) else
                                bool(getattr(getattr(vpn, "cfg", None), "kill_switch", False))
                                and getattr(vpn, "state", "") in ("CONNECTED", "BLOCKED")),
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

            from vpn.runtime import VPNClient
            if self.managed_mode:
                profile = self.profile_store.active()
                if profile is None:
                    return {"error": "Import and select a server profile"}
                cfg = self.profile_store.client_config(profile, self.client_private_path)
                self._connected_profile_id = profile.profile_id
                self._connected_profile_name = profile.name
            else:
                from vpn.config import load_client_config
                cfg = load_client_config(self.config_path)
                self._connected_profile_id = None
                self._connected_profile_name = None
            self._config = cfg
            self._vpn = NativeClient(cfg, self.pqvpnd_path) if cfg.client_backend == "native" else VPNClient(cfg)
            info = self._vpn.connect()
            self._kill_switch_stale = False
            self._connected_at = time.monotonic()
            self._record_event("info", "Secure tunnel connected")
            return {"status": "connected", "info": info}
        except Exception as exc:
            if getattr(self._vpn, "state", "") != ConnectionState.BLOCKED.value:
                self._vpn = None  # a still-blocking client stays, so its status shows and Disconnect can release it
            self._connected_at = None
            raw_error = sanitize_error(exc)
            if self.managed_mode and any(
                phrase in raw_error.lower()
                for phrase in ("connection closed", "connection reset", "broken pipe")
            ):
                raw_error = (
                    "The selected server closed authentication. This device may not yet "
                    "be authorized; ask its administrator to import your enrollment request."
                )
            self._last_failure = raw_error
            self._connected_profile_id = None
            self._connected_profile_name = None
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
            if self._vpn is None and self._kill_switch_stale:
                from vpn.network import KillSwitch
                KillSwitch.remove()
                self._kill_switch_stale = False
                self._record_event("info", "Kill switch removed; network restored")
                return {"status": "disconnected"}
            if self._vpn is None:
                return {"error": "not connected"}
            self._vpn.disconnect()
            self._vpn = None
            self._connected_at = None
            self._connected_profile_id = None
            self._connected_profile_name = None
            self._last_failure = ""
            self._record_event("info", "Network restored; tunnel disconnected")
            return {"status": "disconnected"}
        except Exception as exc:
            error = sanitize_error(exc)
            self._record_event("error", f"Disconnect failed: {error}")
            return {"error": error}
        finally:
            self._lock.release()


# Both suites put X25519 and ML-KEM-768 into every session key (the hybrid-only invariant).
HYBRID_SUITES = frozenset({"v2-ed25519", "v3-kem"})
_STATUS_STATES = frozenset({"CONNECTING", "CONNECTED", "DISCONNECTED", "FAILED", "BLOCKED"})
_STATUS_CONNECTED = {"client_vpn_ip": str, "server_vpn_ip": str, "prefix": int, "endpoint": str, "tun_name": str,
                     "mtu": int, "suite": str, "ipv6_guard": bool, "dns_managed": bool, "epoch": int, "probes": dict}
_CONFIG_PATHS = ("server_identity_public_key", "client_identity_private_key", "client_identity_public_key")


def parse_status_line(raw: str) -> dict:
    """One pqvpnd --status-json line (wire spec v1), or ValueError: the stream is untrusted until it parses."""
    if len(raw.encode()) > 4096 or not raw.endswith("\n"):
        raise ValueError("status line framing")
    line = json.loads(raw)
    if not (isinstance(line, dict) and line.get("v") == 1 and line.get("state") in _STATUS_STATES
            and type(line.get("error")) is str and type(line.get("kill_switch")) is bool):
        raise ValueError("status line header")
    if line["state"] == "CONNECTED":
        probes = line.get("probes")
        rtts = probes.get("rtts_ms") if isinstance(probes, dict) else None
        if (any(type(line.get(key)) is not kind for key, kind in _STATUS_CONNECTED.items())
                or any(line.get(key) is not None and (type(line[key]) not in (int, float) or line[key] < 0)
                       for key in ("rekey_in", "rehandshake_in"))
                or type(probes.get("sent")) is not int or type(probes.get("lost")) is not int
                or not isinstance(rtts, list) or len(rtts) > 64
                or any(type(rtt) not in (int, float) for rtt in rtts)):
            raise ValueError("status line CONNECTED fields")
    return line


def client_toml(cfg: object) -> str:
    """The [client] table pqvpnd reads: every set field, paths absolute (VPNClient resolves them from its cwd)."""
    from dataclasses import fields
    lines = ["[client]"]
    for item in fields(cfg):
        value = getattr(cfg, item.name)
        if value is None:
            continue
        if item.name in _CONFIG_PATHS:
            value = str(Path(value).absolute())
        if item.name in ("data_plane", "handshake"):
            value = "rust"  # pqvpnd is both by construction
        lines.append(f"{item.name} = {json.dumps(value)}")  # JSON scalars, strings and string lists are valid TOML
    return "\n".join(lines) + "\n"


class NativeClient:
    """client_backend = "native": supervises `pqvpnd connect --status-json` and exposes the attributes
    `ClientService._get_status` reads from a VPNClient, so both backends meet one STATUS contract."""
    STOP_TIMEOUT = 12.0
    CONNECT_TIMEOUT = 60.0

    def __init__(self, cfg: object, pqvpnd_path: str) -> None:
        from vpn.network import NetworkQualityMonitor
        self.cfg, self.pqvpnd_path = cfg, pqvpnd_path
        self.state, self.error = "DISCONNECTED", ""
        self.session = self.tun = self.network = self.next_rekey = self.server_ip = self.suite = None
        self.tunnel: dict = {}
        # What pqvpnd reports for its table (spec v1 "kill_switch"), or what this service did on its behalf.
        self.kill_switch_active = False
        self.quality = NetworkQualityMonitor()
        self._process: object | None = None
        self._config_path: str | None = None
        self._final = threading.Event()
        self._connected = threading.Event()
        self._invalid = False

    def connect(self) -> dict:
        import subprocess
        import tempfile
        # mkstemp is O_EXCL and 0600 wherever it lands; the file holds paths and a fingerprint, no secrets.
        directory = _RUNTIME_DIR if os.access(_RUNTIME_DIR, os.W_OK) else None
        fd, self._config_path = tempfile.mkstemp(prefix="pqvpnd-", suffix=".toml", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(client_toml(self.cfg))
        self.state = "CONNECTING"
        self._process = subprocess.Popen([self.pqvpnd_path, "connect", "--config", self._config_path, "--status-json"],
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, encoding="utf-8")
        threading.Thread(target=self._read, daemon=True, name="pqvpnd-status").start()
        deadline = time.monotonic() + self.CONNECT_TIMEOUT
        while not self._connected.wait(0.05):
            if self._final.is_set():
                raise RuntimeError(self.error or "pqvpnd exited before connecting")
            if time.monotonic() > deadline:
                self.disconnect()
                raise RuntimeError("pqvpnd did not connect in time")
        return self.tunnel

    def _read(self) -> None:
        try:
            while raw := self._process.stdout.readline(4097):
                self._apply(parse_status_line(raw))
        except (ValueError, UnicodeDecodeError) as exc:
            logger.error("pqvpnd status stream invalid: %s", exc)
            self._fail_closed()
        finally:
            self._exited()

    def _apply(self, line: dict) -> None:
        state = line["state"]
        self.kill_switch_active = line["kill_switch"]
        if state == "CONNECTED":
            self.tunnel = {key: line[key] for key in ("client_vpn_ip", "server_vpn_ip", "prefix", "mtu")}
            self.tunnel.update(rekey_interval=0, udp_port=int(line["endpoint"].rsplit(":", 1)[1]))
            self.server_ip, self.suite = line["endpoint"].rsplit(":", 1)[0], line["suite"]
            self.session = SimpleNamespace(epoch=line["epoch"])
            self.tun = SimpleNamespace(name=line["tun_name"], mode=SimpleNamespace(name="NATIVE"), mtu=line["mtu"])
            self.network = SimpleNamespace(ipv6=SimpleNamespace(table="pqvpnd" if line["ipv6_guard"] else None),
                                           dns_cleanup_registered=line["dns_managed"])
            self.next_rekey = time.monotonic() + line["rekey_in"] if line["rekey_in"] is not None else None
            probes = line["probes"]
            for _ in range(probes["sent"]):
                self.quality.record_probe_sent()
            for _ in range(probes["lost"]):
                self.quality.record_loss()
            for rtt in probes["rtts_ms"]:
                self.quality.record_rtt(rtt)
            self.state = state
            self._connected.set()
        elif state == "CONNECTING":
            self.state = state
        else:
            self._finish(state, line["error"])

    def _finish(self, state: str, error: str) -> None:
        self.session = self.tun = self.network = self.next_rekey = None
        self.state, self.error = state, error
        self._final.set()

    def _fail_closed(self) -> None:
        """An unreadable child: stop it cleanly, then keep traffic blocked ourselves if a kill switch is configured."""
        self._invalid = True
        self._stop_child()
        if getattr(self.cfg, "kill_switch", False):
            from vpn.network import KillSwitch
            try:
                KillSwitch.install("connecting", self.cfg.server_host, self.cfg.server_control_port)
            except Exception:
                logger.exception("kill switch reinstall failed after an invalid pqvpnd stream")
            self.kill_switch_active = True
            self._finish("BLOCKED", "pqvpnd status stream invalid")
        else:
            self._finish("FAILED", "pqvpnd status stream invalid")

    def _exited(self) -> None:
        code = self._process.wait()
        if self._config_path:
            Path(self._config_path).unlink(missing_ok=True)
        if not self._final.is_set():  # EOF without a final line: a crash or SIGKILL
            from vpn.network import KillSwitch
            how = f"signal {-code}" if code < 0 else f"code {code}"
            blocked = getattr(self.cfg, "kill_switch", False) and KillSwitch.present()
            self.kill_switch_active = blocked
            self._finish("BLOCKED" if blocked else "FAILED", f"pqvpnd exited unexpectedly ({how})")

    def _stop_child(self) -> bool:
        """SIGTERM (pqvpnd's own clean teardown), SIGKILL after STOP_TIMEOUT; True if it stopped in time."""
        import subprocess
        if self._process is None or self._process.poll() is not None:
            return True
        self._process.send_signal(signal.SIGTERM)
        try:
            self._process.wait(self.STOP_TIMEOUT)
            return True
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
            return False

    def disconnect(self) -> None:
        """The user's disconnect: the one action that lifts a kill switch, whatever state the child left."""
        stopped = self._stop_child()
        self._final.wait(self.STOP_TIMEOUT)
        if getattr(self.cfg, "kill_switch", False) and (not stopped or self.state == "BLOCKED"):
            from vpn.network import KillSwitch
            KillSwitch.remove()
            self.kill_switch_active = False
        if stopped:
            self._finish("DISCONNECTED", "")
        else:
            self._finish("FAILED", "pqvpnd did not stop in time; network state may need `pqvpnd recover`")


def _kill_switch_present() -> bool:
    """A kill switch table outliving its session (crash or service restart) is reported, never silently kept or dropped."""
    try:
        from vpn.network import KillSwitch
        return KillSwitch.present()
    except Exception:
        return False


class IPCClient:
    """Non-privileged IPC client for communicating with the service."""

    def send_command(self, command: str, **fields: object) -> dict:
        """Send a single command and return the response."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(str(_socket_path()))
            # The /tmp fallback is squattable; only a root-owned service is trusted.
            if get_peer_uid(sock) != 0:
                return {"error": "Refusing IPC service that is not running as root"}
            try:
                ipc_send(sock, {"command": command, **fields})
            except (BrokenPipeError, ConnectionResetError):
                pass  # a rejected peer is answered and closed unread; the reply is still buffered
            resp = ipc_recv(sock)
            if resp.get("error") == "unauthorized":
                return {"error": "This user is not authorized by the PQ-VPN service; add your uid to "
                                 "PQVPN_ALLOWED_UIDS (see docs/deployment.md)"}
            return resp
        except (ConnectionRefusedError, FileNotFoundError):
            return {"error": "Service not running. Start with: python -m app.client --service"}
        except Exception as exc:
            return {"error": sanitize_error(exc)}
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

    def setup_status(self) -> dict:
        return self.send_command("SETUP_STATUS")

    def ensure_identity(self) -> dict:
        return self.send_command("ENSURE_IDENTITY")

    def list_profiles(self) -> dict:
        return self.send_command("LIST_PROFILES")

    def import_profile(self, content: str, *, replace: bool = False) -> dict:
        return self.send_command("IMPORT_PROFILE", profile=content, replace=replace)

    def select_profile(self, profile_id: str) -> dict:
        return self.send_command("SELECT_PROFILE", profile_id=profile_id)

    def delete_profile(self, profile_id: str) -> dict:
        return self.send_command("DELETE_PROFILE", profile_id=profile_id)

    def enrollment_request(self, client_id: str) -> dict:
        return self.send_command("EXPORT_ENROLLMENT_REQUEST", client_id=client_id)



DEFAULT_ACCOUNT_API_URL = "https://52.62.237.95:8443"
# Public self-signed certificate of the default server, used as its trust anchor.
BUNDLED_ACCOUNT_CA_CERT = Path(__file__).with_name("server-account-api.crt")
ACCOUNT_API_TIMEOUT = 10.0
MAX_ACCOUNT_RESPONSE = 64 * 1024
ACCOUNT_SESSION_CHECK_MS = 60_000
DEVICE_STATUS_LABELS = {
    "pending": "Pending administrator approval",
    "approved": "Approved",
    "rejected": "Rejected",
    "revoked": "Revoked",
}

_ACCOUNT_ERROR_MESSAGES = {
    "invalid_credentials": "Invalid username/email or password.",
    "invalid_session": "Your session has expired. Please sign in again.",
    "account_exists": "An account with this username or email already exists.",
    "invalid_registration": "Registration details are invalid. Please check your inputs.",
    "invalid_request": "The request was rejected. Please check your inputs.",
    "rate_limited": "Too many attempts. Please wait before trying again.",
    "request_too_large": "The request was too large.",
    "unsupported_media_type": "Unsupported content type.",
    "internal_error": "The account service encountered an internal error.",
    "invalid_response": "The account service returned an invalid response.",
    "mfa_required": "A TOTP code is required to complete sign-in.",
    "invalid_totp": "The TOTP code is incorrect. Please try again.",
    "account_locked": "Your account is temporarily locked. Please try again later.",
    "invalid_password": "Password change failed. Check your current password and try again.",
    "mfa_already_enabled": "Multi-factor authentication is already enabled.",
    "mfa_not_enabled": "Multi-factor authentication is not enabled.",
    "invalid_invite": "The invite code is invalid, expired, or already used.",
}


class AccountAPIError(Exception):
    """Structured, user-safe error from the account API or transport layer."""

    def __init__(self, code: str, message: str, status_code: int = 0, retry_after: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after


def _sanitized_message(code: str, status_code: int) -> str:
    """Map an API error code to a uniform message that never echoes server text."""
    if code in _ACCOUNT_ERROR_MESSAGES:
        return _ACCOUNT_ERROR_MESSAGES[code]
    if status_code >= 500:
        return "The account service is temporarily unavailable."
    return "An unexpected error occurred."


def _invalid_response() -> AccountAPIError:
    return AccountAPIError("invalid_response", _ACCOUNT_ERROR_MESSAGES["invalid_response"])


def _unavailable() -> AccountAPIError:
    return AccountAPIError(
        "connection_error", "Cannot reach Account API. Check network or server configuration."
    )


class AccountClient:
    """Blocking HTTPS client for pqvpn-account-api; call from a worker thread."""

    def __init__(self, base_url: str, ca_cert: Path | None = None,
                 timeout: float = ACCOUNT_API_TIMEOUT) -> None:
        self.base_url = base_url.strip().rstrip("/")
        self.ca_cert = ca_cert
        self.timeout = timeout
        self._ssl_context = self._create_ssl_context()

    @classmethod
    def from_env(cls) -> AccountClient:
        """Built-in server and pinned cert by default; env vars override both."""
        url = os.environ.get("PQVPN_ACCOUNT_API_URL")
        ca = os.environ.get("PQVPN_ACCOUNT_CA_CERT")
        if ca:
            return cls(url or DEFAULT_ACCOUNT_API_URL, Path(ca))
        # The bundled cert only vouches for the built-in server; other URLs use the system store.
        if not url or url.strip().rstrip("/") == DEFAULT_ACCOUNT_API_URL:
            return cls(DEFAULT_ACCOUNT_API_URL, BUNDLED_ACCOUNT_CA_CERT)
        return cls(url)

    def _create_ssl_context(self):
        import ipaddress
        import ssl
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(self.base_url)
            host = parts.hostname or ""
            parts.port  # noqa: B018 - raises ValueError for an invalid port
        except ValueError:
            raise AccountAPIError("invalid_url", "Account API URL is invalid.") from None
        if parts.scheme not in {"http", "https"} or not host or parts.query or parts.fragment:
            raise AccountAPIError("invalid_url", "Account API URL is invalid.")
        if parts.username or parts.password:
            raise AccountAPIError("invalid_url", "Account API URL must not contain credentials.")
        if parts.scheme == "http":
            # Cleartext is permitted only for explicit loopback development.
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise AccountAPIError(
                    "tls_required", "Cleartext HTTP is only permitted on loopback addresses."
                )
            return None
        if self.ca_cert is None:
            return ssl.create_default_context()
        try:
            # cafile replaces the system store: a configured cert is an exclusive pin.
            return ssl.create_default_context(cafile=str(self.ca_cert))
        except (OSError, ssl.SSLError):
            raise AccountAPIError(
                "ssl_error", "The configured CA certificate could not be loaded."
            ) from None

    def _request(self, method: str, path: str, body: dict | None = None,
                 token: str | None = None) -> dict | None:
        import urllib.error
        import urllib.request

        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self._ssl_context
            ) as response:
                raw = response.read(MAX_ACCOUNT_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            raise self._http_error(exc) from None
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", exc)).upper()
            if "CERTIFICATE" in reason or "SSL" in reason:
                raise AccountAPIError(
                    "ssl_error", "Secure connection failed. Untrusted or invalid certificate."
                ) from None
            raise _unavailable() from None
        except (OSError, ValueError):
            raise _unavailable() from None
        if len(raw) > MAX_ACCOUNT_RESPONSE:
            raise _invalid_response()
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise _invalid_response() from None
        if not isinstance(parsed, dict):
            raise _invalid_response()
        return parsed

    @staticmethod
    def _http_error(exc) -> AccountAPIError:
        try:
            parsed = json.loads(exc.read(MAX_ACCOUNT_RESPONSE) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            parsed = {}
        error = parsed.get("error") if isinstance(parsed, dict) else None
        code = error.get("code") if isinstance(error, dict) else None
        if not isinstance(code, str):
            code = "unknown_error"
        retry_after = 0
        try:
            retry_after = max(0, int((exc.headers or {}).get("Retry-After", "0")))
        except (TypeError, ValueError):
            pass
        message = _sanitized_message(code, exc.code)
        if retry_after > 0:
            message = f"Too many attempts. Please wait {retry_after} seconds."
        return AccountAPIError(code, message, exc.code, retry_after)

    @staticmethod
    def _user(body: dict | None) -> dict:
        user = body.get("user") if isinstance(body, dict) else None
        if not isinstance(user, dict) or not isinstance(user.get("username"), str):
            raise _invalid_response()
        return user

    def register(self, username: str, email: str, password: str, invite_code: str = "") -> dict:
        """Register a new account and return its public user fields."""
        body = {"username": username, "email": email, "password": password}
        if invite_code:
            body["invite_code"] = invite_code
        user = self._user(self._request("POST", "/auth/register", body=body))
        logger.info("account registration succeeded")
        return user

    def login(self, identifier: str, password: str, totp_code: str | None = None) -> tuple[str, dict, str]:
        """Authenticate and return (token, user, expires_at)."""
        payload: dict = {"identifier": identifier, "password": password}
        if totp_code is not None:
            payload["totp_code"] = totp_code
        body = self._request("POST", "/auth/login", body=payload)
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token or len(token) > 256:
            raise _invalid_response()
        user = self._user(body)
        expires_at = body.get("expires_at")
        logger.info("account login succeeded")
        return token, user, expires_at if isinstance(expires_at, str) else ""

    def get_me(self, token: str) -> dict:
        """Validate the session and return the current public user fields."""
        return self._user(self._request("GET", "/auth/me", token=token))

    def logout(self, token: str, fingerprint: str | None = None) -> None:
        """Revoke the session and, given this device's fingerprint, suspend its VPN access."""
        body = {"fingerprint": fingerprint} if fingerprint else None
        self._request("POST", "/auth/logout", body=body, token=token)
        logger.info("account logout completed")

    def list_devices(self, token: str) -> list[dict]:
        """Return the public device records bound to the signed-in account."""
        body = self._request("GET", "/devices", token=token)
        devices = body.get("devices") if isinstance(body, dict) else None
        if not isinstance(devices, list) or not all(isinstance(d, dict) for d in devices):
            raise _invalid_response()
        return devices

    def mfa_setup(self, token: str) -> dict:
        """Request a new TOTP secret and provisioning URI."""
        body = self._request("POST", "/mfa/setup", token=token)
        if not isinstance(body, dict) or "secret" not in body:
            raise _invalid_response()
        return body

    def mfa_confirm(self, token: str, secret: str, code: str) -> dict:
        """Confirm MFA enrollment with the TOTP code from the authenticator."""
        body = self._request("POST", "/mfa/confirm", token=token, body={"secret": secret, "code": code})
        if not isinstance(body, dict):
            raise _invalid_response()
        return body

    def mfa_disable(self, token: str, code: str) -> dict:
        """Disable MFA with a valid TOTP code."""
        body = self._request("POST", "/mfa/disable", token=token, body={"code": code})
        if not isinstance(body, dict):
            raise _invalid_response()
        return body

    def change_password(self, token: str, old_password: str, new_password: str) -> dict:
        """Change the account password."""
        body = self._request("POST", "/auth/change-password", token=token, body={
            "old_password": old_password, "new_password": new_password,
        })
        if not isinstance(body, dict):
            raise _invalid_response()
        return body

    def bind_device(self, token: str, device_name: str, public_key: str, fingerprint: str) -> dict:
        """Bind a public device identity; for a bound approved device this restores signed-out access."""
        body = self._request("POST", "/devices", token=token, body={
            "device_name": device_name, "public_key": public_key, "fingerprint": fingerprint,
        })
        device = body.get("device") if isinstance(body, dict) else None
        if not isinstance(device, dict) or device.get("fingerprint") != fingerprint:
            raise _invalid_response()
        logger.info("device bound to account")
        return device

    def server_info(self) -> dict:
        """Fetch public server connection info (no auth required)."""
        body = self._request("GET", "/server/info")
        if not isinstance(body, dict):
            raise _invalid_response()
        return body


def account_ux_state(
    session_state: SessionState,
    *,
    api_available: bool,
    identity_ready: bool,
    device: dict | None,
    vpn_state: str,
) -> tuple[str, str, str, str]:
    """Combine account, device, and VPN state into one (key, title, detail, tone)."""
    # Revoked/rejected/disabled device always takes priority — even over an active tunnel,
    # because the server will terminate the session shortly.
    if device is not None:
        if device.get("enabled") is False:
            return ("device_disabled", "Device disabled",
                    "An administrator disabled this device.", "red")
        status = device.get("status")
        if status == "revoked":
            detail = ("VPN access for this device was revoked by an administrator."
                      if vpn_state != ConnectionState.CONNECTED.value
                      else "Device was revoked — the tunnel will terminate shortly.")
            return "device_revoked", "Device revoked", detail, "red"
        if status == "rejected":
            return "device_rejected", "Device rejected", "An administrator rejected this device.", "red"
    if vpn_state == ConnectionState.CONNECTED.value:
        return "vpn_connected", "VPN connected", "Encrypted tunnel is active.", "green"
    if vpn_state in {ConnectionState.CONNECTING.value, ConnectionState.DISCONNECTING.value}:
        return "vpn_connecting", "VPN connecting", "Tunnel state is changing.", "amber"
    if session_state == SessionState.SESSION_EXPIRED:
        return ("session_expired", "Session expired",
                "Sign in again to see your account and device status.", "amber")
    if session_state != SessionState.AUTHENTICATED:
        return ("logged_out", "Signed out",
                "Sign in on the Account page to register and track this device.", "muted")
    if not api_available:
        return ("server_unavailable", "Account server unavailable",
                "Account and device status may be out of date.", "amber")
    if device is None:
        detail = ("Register this device on the Account page." if identity_ready
                  else "Create the device identity first, then register it.")
        return "no_device", "Device not registered", detail, "cyan"
    if device.get("status") == "approved":
        return ("approved_disconnected", "Device approved",
                "Ready to connect when a server profile is selected.", "green")
    return ("device_pending", "Pending approval",
            "An administrator must approve this device before it can connect.", "amber")


def public_device_identity(setup: object) -> tuple[str, str]:
    """Extract and verify the managed public identity from a SETUP_STATUS reply."""
    import hashlib

    identity = setup.get("setup") if isinstance(setup, dict) else None
    public_key = identity.get("identity_public_key") if isinstance(identity, dict) else None
    fingerprint = identity.get("identity_fingerprint") if isinstance(identity, dict) else None
    if not isinstance(public_key, str) or not isinstance(fingerprint, str):
        raise AccountAPIError(
            "identity_unavailable", "Device identity is not ready. Create it on the Home page first."
        )
    try:
        raw = base64.b64decode(public_key, validate=True)
    except ValueError:
        raw = b""
    if len(raw) != 32 or hashlib.sha256(raw).hexdigest() != fingerprint:
        raise AccountAPIError("identity_unavailable", "Device identity failed its consistency check.")
    return public_key, fingerprint


def restore_device_access(client: AccountClient, token: str, setup: object) -> list[dict]:
    """After sign-in, re-bind this already-approved device so the server restores its VPN access.

    Only a device the account already lists is re-bound; signing in never binds a new one.
    """
    devices = client.list_devices(token)
    try:
        public_key, fingerprint = public_device_identity(setup)
    except AccountAPIError:
        return devices  # no managed identity (e.g. explicit --config service): nothing to restore
    current = next((d for d in devices if d.get("fingerprint") == fingerprint), None)
    if current is None or current.get("status") != "approved" or current.get("enabled") is False:
        return devices
    name = str(current.get("device_name") or "device")
    restored = client.bind_device(token, name, public_key, fingerprint)
    return [restored if d is current else d for d in devices]


@dataclass(frozen=True)
class UserProfile:
    """Immutable snapshot of the authenticated user, safe for UI display."""

    id: int
    username: str
    email: str
    enabled: bool
    created_at: str
    mfa_enabled: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> UserProfile:
        return cls(
            id=int(data.get("id", 0)),
            username=str(data.get("username", "")),
            email=str(data.get("email", "")),
            enabled=bool(data.get("enabled", True)),
            created_at=str(data.get("created_at", "")),
            mfa_enabled=bool(data.get("mfa_enabled", False)),
        )


class SessionState(enum.Enum):
    LOGGED_OUT = "logged_out"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    SESSION_EXPIRED = "session_expired"


class AccountSession:
    """Thread-safe, memory-only session container (token never written to disk)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = SessionState.LOGGED_OUT
        self._token: str | None = None
        self._user: UserProfile | None = None
        self._expires_at: str | None = None

    def set_authenticating(self) -> None:
        with self._lock:
            self._state = SessionState.AUTHENTICATING

    def set_session(self, token: str, user: UserProfile, expires_at: str) -> None:
        with self._lock:
            self._token = token
            self._user = user
            self._expires_at = expires_at
            self._state = SessionState.AUTHENTICATED

    def update_user(self, user: UserProfile) -> None:
        with self._lock:
            if self._state == SessionState.AUTHENTICATED:
                self._user = user

    def clear_session(self, *, expired: bool = False) -> None:
        with self._lock:
            self._token = None
            self._user = None
            self._expires_at = None
            self._state = SessionState.SESSION_EXPIRED if expired else SessionState.LOGGED_OUT

    @property
    def state(self) -> SessionState:
        with self._lock:
            return self._state

    @property
    def is_authenticated(self) -> bool:
        with self._lock:
            return self._state == SessionState.AUTHENTICATED and self._token is not None

    def get_token(self) -> str | None:
        with self._lock:
            return self._token if self._state == SessionState.AUTHENTICATED else None

    def get_user(self) -> UserProfile | None:
        with self._lock:
            return self._user

    def get_expires_at(self) -> str | None:
        with self._lock:
            return self._expires_at

    def __repr__(self) -> str:
        with self._lock:
            user = self._user.username if self._user else None
            return f"AccountSession(state={self._state.value!r}, user={user!r}, token=[REDACTED])"

    __str__ = __repr__


# PySide6 remains optional for service-only deployments.  Keeping these imports
# guarded means the privileged service never needs to initialize a GUI stack.
try:
    from PySide6.QtCore import QObject, QPointF, QRectF, Qt, QTimer, Signal
    from PySide6.QtGui import QColor, QPainter, QPen
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QScrollArea,
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
    _PRIMARY_BTN_STYLE = f"""
        QPushButton {{
            min-height: 22px;
            background: {GUI_COLORS['green']}; color: #06110B;
            border: 1px solid {GUI_COLORS['green']}; border-radius: 9px;
            padding: 10px 22px; font-size: 13px; font-weight: 700;
        }}
        QPushButton:hover {{ background: #2EE88A; border-color: #2EE88A; }}
        QPushButton:disabled {{
            background: #10151B; color: {GUI_COLORS['muted']};
            border-color: {GUI_COLORS['border_soft']};
        }}
    """
    _LINK_BTN_STYLE = f"""
        QPushButton {{
            background: transparent; border: none; color: {GUI_COLORS['cyan']};
            font-size: 12px; font-weight: 550; padding: 8px 0px;
        }}
        QPushButton:hover {{ color: #7FD9E8; }}
    """
    _DANGER_BTN_STYLE = f"""
        QPushButton {{
            min-height: 22px;
            background: #2A171B; color: {GUI_COLORS['red']};
            border: 1px solid #63303A; border-radius: 9px;
            padding: 10px 22px; font-size: 12px; font-weight: 700;
        }}
        QPushButton:hover {{ border-color: {GUI_COLORS['red']}; }}
        QPushButton:disabled {{
            background: #10151B; color: {GUI_COLORS['muted']};
            border-color: {GUI_COLORS['border_soft']};
        }}
    """
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
        QLineEdit {{
            background-color: {GUI_COLORS['surface']};
            color: {GUI_COLORS['text']};
            border: 1px solid {GUI_COLORS['border']};
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 13px;
            selection-background-color: #214833;
        }}
        QLineEdit:focus {{
            border-color: {GUI_COLORS['green']};
        }}
        QLineEdit:disabled {{
            color: {GUI_COLORS['muted']};
            background-color: #10151B;
            border-color: {GUI_COLORS['border_soft']};
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
        ITEMS = ("Home", "Servers", "Security", "Account", "Settings", "Logs", "About")

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

        def request_action(self, action: str, payload: object | None = None) -> None:
            self._queue.put((action, payload))

        def request_logs(self) -> None:
            self._queue.put(("logs", None))

        def stop(self) -> None:
            self._stop_event.set()
            self._queue.put(("stop", None))

        def _run(self) -> None:
            while not self._stop_event.is_set():
                command, payload = self._queue.get()
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
                    elif command == "ensure_identity":
                        self.action_finished.emit(command, self.ipc.ensure_identity())
                    elif command == "import_profile":
                        from vpn.identity import load_profile
                        content = load_profile(Path(str(payload))).to_json()
                        self.action_finished.emit(command, self.ipc.import_profile(content))
                    elif command == "import_profile_text":
                        result = self.ipc.import_profile(str(payload))
                        if "error" not in (result or {}):
                            profile = (result or {}).get("profile", {})
                            pid = profile.get("profile_id")
                            if pid:
                                self.ipc.select_profile(pid)
                        self.action_finished.emit(command, result)
                    elif command == "select_profile":
                        self.action_finished.emit(command, self.ipc.select_profile(str(payload)))
                    elif command == "delete_profile":
                        self.action_finished.emit(command, self.ipc.delete_profile(str(payload)))
                    elif command in {"copy_enrollment", "export_enrollment"}:
                        if command == "export_enrollment":
                            client_id, output = payload
                        else:
                            client_id, output = str(payload), None
                        result = self.ipc.enrollment_request(client_id)
                        if output is not None and "error" not in result:
                            from vpn.identity import parse_enrollment, write_enrollment
                            request = parse_enrollment(result.get("content", ""))
                            write_enrollment(Path(output), request)
                            result["output"] = str(output)
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


    class _AccountWorker(QObject):
        """Background worker that serializes blocking account API calls."""

        finished = Signal(str, bool, object, str, int, int)

        def __init__(self) -> None:
            super().__init__()
            self._queue: queue.Queue = queue.Queue()
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="pqvpn-gui-account"
            )
            self._thread.start()

        def submit(self, op: str, call) -> None:
            self._queue.put((op, call))

        def stop(self) -> None:
            self._queue.put(None)

        def _run(self) -> None:
            while (item := self._queue.get()) is not None:
                op, call = item
                try:
                    self.finished.emit(op, True, call(), "", 0, 0)
                except AccountAPIError as exc:
                    self.finished.emit(
                        op, False, exc.code, exc.message, exc.status_code, exc.retry_after
                    )
                except Exception as exc:
                    self.finished.emit(op, False, "client_error", sanitize_error(exc), 0, 0)


    def scroll_page(page: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(page)
        return scroll


    def _launch_gui() -> None:
        """Launch the normal-user desktop client (login window → main window)."""
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            raise SystemExit("Refusing to run the PQ-VPN desktop GUI as root")
        from app.ui.login import LoginWindow
        from app.ui.window import MainWindow
        from app.ui.theme import STYLESHEET
        os.environ.setdefault("QT_QPA_PLATFORM", "wayland;xcb")
        app = QApplication(sys.argv)
        app.setApplicationName("PQ-VPN")
        app.setApplicationVersion(APP_VERSION)
        app.setStyleSheet(STYLESHEET)
        login = LoginWindow()

        def _on_authenticated() -> None:
            window = MainWindow(
                account_client=login.account_client,
                session_token=login.session_token,
                session_user=login.session_user,
                session_expires_at=login.session_expires_at,
            )
            login.session_token = login.session_user = None  # MainWindow owns the session now
            window.signed_out.connect(_on_signed_out)
            app.pqvpn_main_window = window  # prevent GC
            window.show()
            login.hide()

        def _on_signed_out(message: str) -> None:
            window = app.pqvpn_main_window
            app.pqvpn_main_window = None
            window.shutdown()
            window.deleteLater()
            login.show_signed_out(message)

        login.login_succeeded.connect(_on_authenticated)
        login.show()
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
        help="Explicit legacy client TOML path; omitting it selects managed onboarding mode",
    )
    parser.add_argument(
        "--state-dir", type=Path, default=None,
        help=f"Managed service state directory (default: {DEFAULT_STATE_DIR})",
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
        source = args.config or f"managed state in {args.state_dir or DEFAULT_STATE_DIR}"
        logger.info("Starting PQ-VPN client service (%s)", source)
        service = ClientService(args.config, state_dir=args.state_dir)
        service.start()
    else:
        _launch_gui()


if __name__ == "__main__":
    main()
