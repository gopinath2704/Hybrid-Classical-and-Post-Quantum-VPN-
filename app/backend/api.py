"""
FastAPI Backend Controller for PQ-VPN Desktop Application.

REST API endpoints for VPN connection lifecycle, status monitoring,
server management, and configuration. Serves the frontend static files
and provides the WebSocket telemetry endpoint.

Endpoints:
    POST /api/v1/vpn/connect      — Run KEMTLS handshake & start real tunnel
    POST /api/v1/vpn/disconnect   — Stop tunnel & securely wipe session keys
    POST /api/v1/vpn/rekey        — Trigger in-session key rotation
    GET  /api/v1/vpn/status       — Connection state, real uptime, cipher info
    GET  /api/v1/vpn/servers      — Available VPN server list
    GET  /api/v1/vpn/config       — Active tunnel configuration
    GET  /api/v1/crypto/status    — PQC library availability and mode flags
    GET  /api/v1/logs             — Recent activity log entries

Security notes:
    - PQC mode is fail-closed by default; set ALLOW_MOCK_PQC=1 for dev/testing
    - Concurrent connect requests are rejected with HTTP 409 Conflict
    - Disconnect securely zeroes all session key material in memory
    - Key rotation derives forward-secret successor keys using HKDF ratchet
"""

from __future__ import annotations

import os
import sys
import time
import uuid
import json
import asyncio
import logging
import threading
from pathlib import Path
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Add project root to path for imports
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from crypto.hybrid_crypto import get_crypto_status, ALLOW_MOCK_PQC, _OQS_AVAILABLE
from vpn.engine import VPNService, ServiceState, VPNTelemetry
from vpn.cli import VPNServerDaemon

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("pqvpn.api")


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Telemetry Manager & History Buffers
# ─────────────────────────────────────────────────────────────────────────────

MAX_HISTORY_POINTS = 120  # 60 seconds at 500ms intervals

# Shared history deques (thread-safe append/popleft)
download_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)
upload_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)
latency_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)
loss_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)


class ConnectionManager:
    """
    Manages active WebSocket connections for telemetry broadcasting.

    Handles client connect/disconnect lifecycle and provides broadcast
    capability to push telemetry frames to all connected clients.
    """

    def __init__(self) -> None:
        self._active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self._active_connections.append(websocket)
        logger.info(
            "WebSocket client connected. Active: %d",
            len(self._active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket client."""
        if websocket in self._active_connections:
            self._active_connections.remove(websocket)
        logger.info(
            "WebSocket client disconnected. Active: %d",
            len(self._active_connections),
        )

    async def broadcast(self, data: dict) -> None:
        """Send a JSON payload to all connected clients."""
        message = json.dumps(data)
        disconnected = []
        for connection in self._active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

    @property
    def client_count(self) -> int:
        """Number of active WebSocket connections."""
        return len(self._active_connections)


ws_manager = ConnectionManager()


# ─────────────────────────────────────────────────────────────────────────────
# Connection State Model (API-facing enum)
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionState(str, Enum):
    """VPN connection lifecycle states (API-facing)."""
    DISCONNECTED  = "DISCONNECTED"
    CONNECTING    = "CONNECTING"
    CONNECTED     = "CONNECTED"
    DISCONNECTING = "DISCONNECTING"
    ERROR         = "ERROR"


@dataclass
class ServerInfo:
    """VPN server profile."""
    id: str
    name: str
    location: str
    country: str
    flag: str
    host: str
    port: int
    load: float          # 0.0–1.0
    latency_ms: float    # Estimated latency


@dataclass
class ActivityLogEntry:
    """A single activity log event."""
    timestamp: float
    time_str: str
    message: str
    level: str = "info"  # info, warning, error, success


# ─────────────────────────────────────────────────────────────────────────────
# Global Application State
# ─────────────────────────────────────────────────────────────────────────────

# The single global VPN service instance
_vpn_service: VPNService = VPNService(key_rotation_interval=300)

# A threading lock for API-level concurrency guard (connect/disconnect racing)
_api_lock = threading.Lock()

# Activity log (in-memory, max 200 entries)
_activity_log: list[ActivityLogEntry] = []

# Selected server ID (persisted across connect calls for status display)
_selected_server_id: str = "local-test"

# Optional embedded development server, enabled by app/main.py.  This makes
# the Local Test Node usable from the dashboard without pretending that the
# undeployed public profiles are reachable.
_local_server: Optional[VPNServerDaemon] = None
_local_server_thread: Optional[threading.Thread] = None


# ─────────────────────────────────────────────────────────────────────────────
# Available VPN Servers
# ─────────────────────────────────────────────────────────────────────────────

SERVERS: list[ServerInfo] = [
    ServerInfo(
        id="local-test", name="Local Test Node",
        location="Localhost (Testing)",
        country="Local", flag="🖥️", host="127.0.0.1",
        port=51820, load=0.0, latency_ms=0.1,
    ),
    ServerInfo(
        id="fra-01", name="Frankfurt #1", location="Frankfurt, Germany",
        country="Germany", flag="🇩🇪", host="fra-01.pq-vpn.net",
        port=51820, load=0.42, latency_ms=23.6,
    ),
    ServerInfo(
        id="lon-01", name="London #1", location="London, United Kingdom",
        country="United Kingdom", flag="🇬🇧", host="lon-01.pq-vpn.net",
        port=51820, load=0.38, latency_ms=31.2,
    ),
    ServerInfo(
        id="nyc-01", name="New York #1", location="New York, United States",
        country="United States", flag="🇺🇸", host="nyc-01.pq-vpn.net",
        port=51820, load=0.55, latency_ms=89.4,
    ),
    ServerInfo(
        id="tok-01", name="Tokyo #1", location="Tokyo, Japan",
        country="Japan", flag="🇯🇵", host="tok-01.pq-vpn.net",
        port=51820, load=0.61, latency_ms=145.8,
    ),
    ServerInfo(
        id="sgp-01", name="Singapore #1", location="Singapore",
        country="Singapore", flag="🇸🇬", host="sgp-01.pq-vpn.net",
        port=51820, load=0.29, latency_ms=112.3,
    ),
    ServerInfo(
        id="syd-01", name="Sydney #1", location="Sydney, Australia",
        country="Australia", flag="🇦🇺", host="syd-01.pq-vpn.net",
        port=51820, load=0.35, latency_ms=178.5,
    ),
]

_server_map = {s.id: s for s in SERVERS}


# ─────────────────────────────────────────────────────────────────────────────
# Logging Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _add_log(message: str, level: str = "info") -> None:
    """Append an activity log entry."""
    now = time.time()
    entry = ActivityLogEntry(
        timestamp=now,
        time_str=time.strftime("%H:%M:%S", time.localtime(now)),
        message=message,
        level=level,
    )
    _activity_log.insert(0, entry)
    if len(_activity_log) > 200:
        _activity_log[:] = _activity_log[:200]
    logger.info("[%s] %s", level.upper(), message)


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PQ-VPN Controller API",
    version="1.0.0",
    description=(
        "Hybrid Classical & Post-Quantum VPN Desktop Controller. "
        "Connects real KEMTLS handshakes to a live AES-256-GCM UDP tunnel."
    ),
)

# CORS for local desktop webview
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Serve static frontend files
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.on_event("startup")
async def startup_event():
    """Log application start and emit crypto status."""
    crypto = get_crypto_status()
    _add_log("Application started — PQ-VPN Client", "success")
    if not _OQS_AVAILABLE:
        if ALLOW_MOCK_PQC:
            _add_log(
                "⚠️  INSECURE MOCK MODE: liboqs unavailable — "
                "using SHA-based PQC simulation. NO quantum protection.",
                "warning",
            )
        else:
            _add_log(
                "❌  PQC UNAVAILABLE: liboqs not installed. "
                "Connect will fail unless ALLOW_MOCK_PQC=1 is set.",
                "error",
            )
    else:
        _add_log("✅  Native liboqs active — ML-KEM/Kyber768 quantum-safe.", "success")

    if os.environ.get("AUTO_START_LOCAL_VPN_SERVER", "0") == "1":
        global _local_server, _local_server_thread
        _local_server = VPNServerDaemon(
            bind_host="127.0.0.1",
            bind_port=51820,
            tun_name="pqvpn-server0",
        )
        _local_server_thread = threading.Thread(
            target=_local_server.start,
            name="pqvpn-local-test-server",
            daemon=True,
        )
        _local_server_thread.start()
        _add_log(
            "Local Test Node started at 127.0.0.1:51820",
            "success",
        )


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up VPN connection on shutdown."""
    if _vpn_service.state not in (ServiceState.DISCONNECTED, ServiceState.ERROR):
        try:
            _vpn_service.disconnect()
        except Exception:
            pass
    if _local_server is not None:
        _local_server.stop()


# ─────────────────── Static File Serving ───────────────────

@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the main dashboard HTML page."""
    return FileResponse(_FRONTEND_DIR / "index.html")


if (_FRONTEND_DIR / "css").exists():
    app.mount("/css", StaticFiles(directory=str(_FRONTEND_DIR / "css")), name="css")
if (_FRONTEND_DIR / "js").exists():
    app.mount("/js", StaticFiles(directory=str(_FRONTEND_DIR / "js")), name="js")
if (_FRONTEND_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIR / "assets")), name="assets")


# ─────────────────── Crypto Status Endpoint ───────────────────

@app.get("/api/v1/crypto/status")
async def crypto_status():
    """
    Return runtime PQC library availability status.

    Clients should use this to display an accurate mode badge:
    - native_liboqs: Real ML-KEM/Kyber768 — quantum-safe
    - mock_sha_fallback: Insecure dev mock — NOT quantum-safe
    - unavailable: liboqs not installed, connection will fail
    """
    return get_crypto_status()


# ─────────────────── VPN Connection Endpoints ───────────────────

@app.post("/api/v1/vpn/connect")
async def vpn_connect(
    server_id: str = "local-test",
    host: Optional[str] = None,
    port: Optional[int] = None,
):
    """
    Initiate a VPN connection to the specified server.

    Performs a real KEMTLS handshake over TCP, allocates a TUN interface,
    and starts the AES-256-GCM encrypted UDP tunnel daemon.

    Rejects the request with HTTP 409 if a connection attempt is already
    in progress or the tunnel is already active.
    """
    global _selected_server_id

    # Concurrency guard — reject if already connecting/connected/disconnecting
    current_state = _vpn_service.state
    if current_state in (
        ServiceState.CONNECTING,
        ServiceState.CONNECTED,
        ServiceState.DISCONNECTING,
    ):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot connect: current state is {current_state!r}. "
                   "Disconnect first.",
        )

    if server_id not in _server_map:
        raise HTTPException(
            status_code=404,
            detail=f"Server '{server_id}' not found. "
                   f"Available: {list(_server_map.keys())}",
        )

    server = _server_map[server_id]
    connect_host = host or server.host
    connect_port = port or server.port
    _selected_server_id = server_id

    _add_log(f"Connecting to {server.name} — {connect_host}:{connect_port}", "info")
    _add_log("Performing KEMTLS hybrid handshake (X25519 + Kyber768)…", "info")

    # Run the blocking connect in a thread so we don't block the event loop
    loop = asyncio.get_event_loop()
    try:
        telemetry: VPNTelemetry = await loop.run_in_executor(
            None,
            lambda: _vpn_service.connect(
                host=connect_host,
                port=connect_port,
            ),
        )
    except Exception as exc:
        error_msg = str(exc)
        _add_log(f"Connection failed: {error_msg}", "error")
        raise HTTPException(
            status_code=503,
            detail=f"VPN connection failed: {error_msg}",
        )

    crypto = get_crypto_status()
    _add_log(
        f"Connected — session {telemetry.session_id[:16]}… "
        f"| PQC: {crypto['pqc_mode']} "
        f"| TUN: {telemetry.tun_mode}",
        "success",
    )

    return {
        "status": "connected",
        "session_id": telemetry.session_id,
        "server": server.location,
        "vpn_ip": telemetry.vpn_ip,
        "tun_mode": telemetry.tun_mode,
        "pqc_mode": telemetry.pqc_mode,
        "is_quantum_safe": telemetry.is_quantum_safe,
    }


@app.post("/api/v1/vpn/disconnect")
async def vpn_disconnect():
    """
    Disconnect from the VPN tunnel.

    Stops the tunnel daemon, closes the TUN interface, securely zeroes
    all session keys in memory, and resets connection state.
    """
    if _vpn_service.state == ServiceState.DISCONNECTED:
        raise HTTPException(status_code=409, detail="Not connected")

    _add_log("Disconnecting — wiping session keys…", "info")

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _vpn_service.disconnect)
    except Exception as exc:
        _add_log(f"Disconnect error: {exc}", "error")
        raise HTTPException(status_code=500, detail=str(exc))

    _add_log("Disconnected — session keys securely zeroed.", "success")
    return {"status": "disconnected"}


@app.post("/api/v1/vpn/rekey")
async def vpn_rekey():
    """
    Trigger in-session key rotation.

    Derives forward-secret successor keys from the current session material,
    installs them into the AES-256-GCM cipher, and securely zeros the old keys.

    Returns the rekey nonce hex (for audit logging only — not a secret).
    """
    if _vpn_service.state != ServiceState.CONNECTED:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot rekey: not connected (state={_vpn_service.state!r})",
        )

    loop = asyncio.get_event_loop()
    try:
        nonce_hex = await loop.run_in_executor(None, _vpn_service.rotate_keys)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    _add_log(f"Key rotation complete — nonce={nonce_hex}…", "success")
    return {"status": "rekeyed", "nonce": nonce_hex}


@app.get("/api/v1/vpn/status")
async def vpn_status():
    """
    Get current VPN connection status and live metrics.

    Returns real tunnel stats, network quality measurements, and
    cryptographic posture indicators. When connected, all values
    are sourced from the live VPNTunnelDaemon and NetworkQualityMonitor.
    No values are simulated.
    """
    telemetry = _vpn_service.get_telemetry()
    server = _server_map.get(_selected_server_id)

    uptime = telemetry.uptime_seconds
    key_rotation_remaining = 300.0
    if telemetry.last_key_rotation:
        elapsed = time.time() - telemetry.last_key_rotation
        key_rotation_remaining = max(
            0.0, _vpn_service._key_rotation_interval - elapsed
        )

    return {
        "connection_state": telemetry.state,
        "session_id": telemetry.session_id,
        "vpn_ip": telemetry.vpn_ip,
        "uptime_seconds": round(uptime, 1),
        "is_simulated": False,

        # Server info
        "server": {
            "id": server.id if server else "",
            "name": server.name if server else "",
            "location": server.location if server else "",
            "flag": server.flag if server else "",
            "host": server.host if server else "",
        } if server else None,

        # Crypto suite
        "crypto": {
            "cipher": "AES-256-GCM",
            "key_exchange": "Hybrid (X25519 + Kyber768)",
            "handshake": "KEMTLS 1.0",
            "integrity": "HMAC-SHA256",
            "pqc_algorithm": "ML-KEM / Kyber768 (NIST)",
            "classical_algorithm": "X25519 ECDH",
            "pqc_mode": telemetry.pqc_mode,
            "is_quantum_safe": telemetry.is_quantum_safe,
            "tun_mode": telemetry.tun_mode,
            "key_rotation_remaining": round(key_rotation_remaining, 0),
            "key_rotation_count": telemetry.key_rotation_count,
        },

        # Real tunnel stats
        "tunnel": {
            "bytes_sent": telemetry.bytes_sent,
            "bytes_received": telemetry.bytes_received,
            "packets_sent": telemetry.packets_sent,
            "packets_received": telemetry.packets_received,
            "packets_dropped": telemetry.packets_dropped,
        },

        # Real network quality
        "network": {
            "download_mbps": telemetry.download_mbps,
            "upload_mbps": telemetry.upload_mbps,
            "latency_ms": telemetry.latency_ms,
            "jitter_ms": telemetry.jitter_ms,
            "loss_rate": telemetry.loss_rate,
            "mtu": telemetry.mtu,
        },

        # Error info
        "error_message": telemetry.error_message,
    }


@app.get("/api/v1/vpn/servers")
async def vpn_servers():
    """Return the list of available VPN server profiles."""
    return {
        "servers": [
            {
                "id": s.id,
                "name": s.name,
                "location": s.location,
                "country": s.country,
                "flag": s.flag,
                "host": s.host,
                "port": s.port,
                "load": s.load,
                "latency_ms": s.latency_ms,
                "is_test_node": s.id == "local-test",
            }
            for s in SERVERS
        ]
    }


@app.get("/api/v1/vpn/config")
async def vpn_config():
    """Return the active VPN tunnel configuration parameters."""
    return {
        "cipher_suite": "AES-256-GCM",
        "key_exchange": "Hybrid (X25519 + Kyber768)",
        "handshake_protocol": "KEMTLS 1.0",
        "integrity": "HMAC-SHA256",
        "key_rotation_interval": _vpn_service._key_rotation_interval,
        "selected_server": _selected_server_id,
        "pqc_mode": get_crypto_status()["pqc_mode"],
        "is_quantum_safe": _OQS_AVAILABLE,
        "is_simulated": False,
    }


@app.get("/api/v1/logs")
async def get_logs(limit: int = 50):
    """
    Return recent activity log entries.

    Args:
        limit: Maximum number of log entries to return (default 50).
    """
    entries = _activity_log[:limit]
    return {
        "logs": [
            {
                "timestamp": e.timestamp,
                "time": e.time_str,
                "message": e.message,
                "level": e.level,
            }
            for e in entries
        ]
    }


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Telemetry Endpoint
# ─────────────────────────────────────────────────────────────────────────────

def _build_telemetry_frame() -> dict:
    """
    Build a telemetry JSON frame from the live VPNService.

    All values come from the real VPN tunnel daemon and network quality
    monitor — no values are simulated or randomly generated.
    """
    t = _vpn_service.get_telemetry()
    now = time.time()
    crypto = get_crypto_status()

    # Record history for charts
    is_connected = t.state == "CONNECTED"
    download_history.append(t.download_mbps if is_connected else 0.0)
    upload_history.append(t.upload_mbps if is_connected else 0.0)
    latency_history.append(t.latency_ms if is_connected else 0.0)
    loss_history.append((t.loss_rate * 100) if is_connected else 0.0)

    # Key rotation countdown
    key_rotation_remaining = 300.0
    if t.last_key_rotation:
        elapsed = now - t.last_key_rotation
        key_rotation_remaining = max(0.0, 300.0 - elapsed)

    return {
        "type": "telemetry",
        "timestamp": round(now, 3),
        "connection_state": t.state,
        "uptime_seconds": round(t.uptime_seconds, 1),
        "session_id": t.session_id,
        "vpn_ip": t.vpn_ip,
        "is_simulated": False,

        # Bandwidth
        "download_mbps": t.download_mbps,
        "upload_mbps": t.upload_mbps,

        # Network quality (real measurements)
        "latency_ms": t.latency_ms,
        "jitter_ms": t.jitter_ms,
        "loss_rate": t.loss_rate,
        "mtu": t.mtu,

        # Tunnel stats (real counters from daemon)
        "bytes_sent": t.bytes_sent,
        "bytes_received": t.bytes_received,
        "packets_sent": t.packets_sent,
        "packets_received": t.packets_received,
        "packets_dropped": t.packets_dropped,

        # Key rotation
        "key_rotation_remaining": round(key_rotation_remaining, 0),
        "key_rotation_count": t.key_rotation_count,

        # Crypto / mode transparency flags
        "pqc_mode": t.pqc_mode or crypto["pqc_mode"],
        "tun_mode": t.tun_mode,
        "is_quantum_safe": t.is_quantum_safe,

        # Time-series history arrays (for charts)
        "download_history": list(download_history),
        "upload_history": list(upload_history),
        "latency_history": list(latency_history),
        "loss_history": list(loss_history),
    }


@app.websocket("/ws/telemetry")
async def telemetry_websocket(websocket: WebSocket):
    """
    Live telemetry WebSocket endpoint.

    Pushes telemetry frames to the client every 500ms while connected.
    The client can send JSON control messages (e.g. change update rate).
    """
    await ws_manager.connect(websocket)

    try:
        while True:
            # Build and send telemetry frame
            frame = _build_telemetry_frame()
            try:
                await websocket.send_text(json.dumps(frame))
            except Exception:
                break

            # Wait 500ms, also listen for client messages
            try:
                msg = await asyncio.wait_for(
                    websocket.receive_text(), timeout=0.5
                )
                try:
                    control = json.loads(msg)
                    logger.debug("WS control message: %s", control)
                except json.JSONDecodeError:
                    pass
            except asyncio.TimeoutError:
                pass  # Normal — no message received, continue streaming

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("WebSocket error: %s", e)
    finally:
        ws_manager.disconnect(websocket)


# ─────────────────────────────────────────────────────────────────────────────
# vpn_state compatibility shim
# ─────────────────────────────────────────────────────────────────────────────

class _VPNStateProxy:
    """
    Compatibility shim that forwards attribute reads to the live VPNTelemetry.
    """

    @property
    def connection_state(self) -> ConnectionState:
        s = _vpn_service.state
        _map = {
            ServiceState.DISCONNECTED:  ConnectionState.DISCONNECTED,
            ServiceState.CONNECTING:    ConnectionState.CONNECTING,
            ServiceState.CONNECTED:     ConnectionState.CONNECTED,
            ServiceState.DISCONNECTING: ConnectionState.DISCONNECTING,
            ServiceState.ERROR:         ConnectionState.ERROR,
        }
        return _map.get(s, ConnectionState.DISCONNECTED)

    def __getattr__(self, name: str):
        t = _vpn_service.get_telemetry()
        mapping = {
            "session_id": t.session_id,
            "vpn_ip": t.vpn_ip,
            "connected_at": t.connected_at,
            "download_speed_mbps": t.download_mbps,
            "upload_speed_mbps": t.upload_mbps,
            "current_latency_ms": t.latency_ms,
            "current_jitter_ms": t.jitter_ms,
            "current_loss_rate": t.loss_rate,
            "current_mtu": t.mtu,
            "bytes_sent": t.bytes_sent,
            "bytes_received": t.bytes_received,
            "packets_sent": t.packets_sent,
            "packets_received": t.packets_received,
            "packets_dropped": t.packets_dropped,
            "key_rotation_interval": t.key_rotation_interval,
            "last_key_rotation": t.last_key_rotation,
        }
        if name in mapping:
            return mapping[name]
        raise AttributeError(f"_VPNStateProxy has no attribute {name!r}")


# Global proxy instance
vpn_state = _VPNStateProxy()
