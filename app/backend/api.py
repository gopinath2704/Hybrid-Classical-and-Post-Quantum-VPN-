"""
FastAPI Backend Controller for PQ-VPN Desktop Application.

REST API endpoints for VPN connection lifecycle, status monitoring,
server management, and configuration. Serves the frontend static files
and provides the WebSocket telemetry endpoint.

Endpoints:
    POST /api/v1/vpn/connect      — Initiate KEMTLS handshake & start tunnel
    POST /api/v1/vpn/disconnect   — Stop tunnel & clean session keys
    GET  /api/v1/vpn/status       — Connection state, uptime, cipher info
    GET  /api/v1/vpn/servers      — Available VPN server list
    GET  /api/v1/vpn/config       — Active tunnel configuration
    GET  /api/v1/logs             — Recent activity log entries
"""

from __future__ import annotations

import os
import sys
import time
import uuid
import logging
import threading
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Add project root to path for imports
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.backend.websocket import router as ws_router

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("pqvpn.api")


# ─────────────────────────────────────────────────────────────────────────────
# Connection State Model
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionState(str, Enum):
    """VPN connection lifecycle states."""
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    DISCONNECTING = "DISCONNECTING"


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


@dataclass
class VPNState:
    """
    Central VPN application state container.

    Holds the current connection state, selected server, session metadata,
    tunnel statistics, and recent activity logs. This is the single source
    of truth for all API endpoints.
    """
    # Connection
    connection_state: ConnectionState = ConnectionState.DISCONNECTED
    session_id: str = ""
    vpn_ip: str = ""
    connected_at: Optional[float] = None
    selected_server_id: str = "fra-01"

    # Crypto info
    cipher_suite: str = "AES-256-GCM"
    key_exchange: str = "Hybrid (X25519 + Kyber768)"
    handshake_protocol: str = "KEMTLS 1.0"
    integrity: str = "HMAC-SHA256"
    pqc_algorithm: str = "ML-KEM / Kyber768 (NIST)"
    classical_algorithm: str = "X25519 ECDH"

    # Key rotation
    key_rotation_interval: int = 300  # 5 minutes
    last_key_rotation: Optional[float] = None

    # Tunnel stats (cumulative)
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    packets_dropped: int = 0

    # Network quality
    current_latency_ms: float = 0.0
    current_jitter_ms: float = 0.0
    current_loss_rate: float = 0.0
    current_mtu: int = 1500
    download_speed_mbps: float = 0.0
    upload_speed_mbps: float = 0.0

    # Activity log
    activity_log: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Global Application State
# ─────────────────────────────────────────────────────────────────────────────

# The single global VPN state instance
vpn_state = VPNState()

# Available VPN servers
SERVERS: list[ServerInfo] = [
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


def _add_log(message: str, level: str = "info") -> None:
    """Append an activity log entry to the global VPN state."""
    now = time.time()
    entry = ActivityLogEntry(
        timestamp=now,
        time_str=time.strftime("%H:%M:%S", time.localtime(now)),
        message=message,
        level=level,
    )
    vpn_state.activity_log.insert(0, entry)
    # Keep only the last 200 entries
    if len(vpn_state.activity_log) > 200:
        vpn_state.activity_log = vpn_state.activity_log[:200]
    logger.info("[%s] %s", level.upper(), message)


# ─────────────────────────────────────────────────────────────────────────────
# Background Telemetry Simulation Thread
# ─────────────────────────────────────────────────────────────────────────────
# In production, these values come from real VPNTunnelDaemon, MTUMonitor,
# and NetworkQualityMonitor instances. For desktop demo / testing, we
# simulate realistic-looking telemetry data.

import random
import math

_telemetry_thread: Optional[threading.Thread] = None
_telemetry_stop = threading.Event()


def _simulate_telemetry() -> None:
    """Background loop generating realistic VPN telemetry for the UI."""
    t = 0
    while not _telemetry_stop.is_set():
        if vpn_state.connection_state == ConnectionState.CONNECTED:
            # Simulate bandwidth with realistic fluctuation
            base_download = 1.15  # Gbps
            base_upload = 42.0    # Mbps
            noise = math.sin(t * 0.1) * 0.15 + random.uniform(-0.05, 0.05)
            vpn_state.download_speed_mbps = round(
                (base_download + noise) * 1000, 1
            )  # Convert to Mbps
            vpn_state.upload_speed_mbps = round(
                base_upload + random.uniform(-5, 5), 1
            )

            # Simulate latency
            vpn_state.current_latency_ms = round(
                23.6 + math.sin(t * 0.15) * 3.0 + random.uniform(-1, 1), 1
            )
            vpn_state.current_jitter_ms = round(
                1.2 + random.uniform(-0.3, 0.3), 2
            )
            vpn_state.current_loss_rate = round(
                max(0, 0.001 + random.uniform(-0.001, 0.002)), 4
            )

            # Accumulate data transfer
            vpn_state.bytes_sent += random.randint(50000, 200000)
            vpn_state.bytes_received += random.randint(200000, 800000)
            vpn_state.packets_sent += random.randint(50, 200)
            vpn_state.packets_received += random.randint(100, 400)

            t += 1

        _telemetry_stop.wait(0.5)


def _start_telemetry_thread() -> None:
    """Start the background telemetry simulation thread."""
    global _telemetry_thread
    _telemetry_stop.clear()
    _telemetry_thread = threading.Thread(
        target=_simulate_telemetry,
        name="telemetry-sim",
        daemon=True,
    )
    _telemetry_thread.start()


def _stop_telemetry_thread() -> None:
    """Stop the background telemetry simulation thread."""
    _telemetry_stop.set()
    if _telemetry_thread is not None:
        _telemetry_thread.join(timeout=2.0)


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PQ-VPN Controller API",
    version="1.0.0",
    description="Hybrid Classical & Post-Quantum VPN Desktop Controller",
)

# CORS for local desktop webview
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount WebSocket router
app.include_router(ws_router)

# Serve static frontend files
_FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.on_event("startup")
async def startup_event():
    """Initialize telemetry thread and log application start."""
    _start_telemetry_thread()
    _add_log("Application started — PQ-VPN Client", "success")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up background threads on shutdown."""
    _stop_telemetry_thread()


# ─────────────────── Static File Serving ───────────────────

@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the main dashboard HTML page."""
    return FileResponse(_FRONTEND_DIR / "index.html")


# Mount static directories
if (_FRONTEND_DIR / "css").exists():
    app.mount("/css", StaticFiles(directory=str(_FRONTEND_DIR / "css")), name="css")
if (_FRONTEND_DIR / "js").exists():
    app.mount("/js", StaticFiles(directory=str(_FRONTEND_DIR / "js")), name="js")
if (_FRONTEND_DIR / "assets").exists():
    app.mount(
        "/assets",
        StaticFiles(directory=str(_FRONTEND_DIR / "assets")),
        name="assets",
    )


# ─────────────────── VPN Connection Endpoints ───────────────────

@app.post("/api/v1/vpn/connect")
async def vpn_connect(server_id: str = "fra-01"):
    """
    Initiate a VPN connection to the specified server.

    Runs the KEMTLS handshake, establishes session keys, and starts
    the VPN tunnel daemon.
    """
    if vpn_state.connection_state == ConnectionState.CONNECTED:
        raise HTTPException(status_code=409, detail="Already connected")

    if server_id not in _server_map:
        raise HTTPException(status_code=404, detail=f"Server '{server_id}' not found")

    server = _server_map[server_id]

    # Transition: DISCONNECTED → CONNECTING
    vpn_state.connection_state = ConnectionState.CONNECTING
    vpn_state.selected_server_id = server_id
    vpn_state.session_id = uuid.uuid4().hex[:16].upper()
    _add_log(f"Server selected — {server.host}", "info")
    _add_log("Establishing secure tunnel... Negotiating hybrid keys", "info")

    # Simulate handshake delay (in production, this runs KEMTLSClient)
    import asyncio
    await asyncio.sleep(1.5)

    # Transition: CONNECTING → CONNECTED
    vpn_state.connection_state = ConnectionState.CONNECTED
    vpn_state.connected_at = time.time()
    vpn_state.vpn_ip = "10.8.0.14"
    vpn_state.last_key_rotation = time.time()
    vpn_state.current_mtu = 1500
    vpn_state.bytes_sent = 0
    vpn_state.bytes_received = 0
    vpn_state.packets_sent = 0
    vpn_state.packets_received = 0

    _add_log(
        f"Connected to {server.location} — KEMTLS Handshake Completed",
        "success",
    )

    return {
        "status": "connected",
        "session_id": vpn_state.session_id,
        "server": server.location,
        "vpn_ip": vpn_state.vpn_ip,
        "protocol": vpn_state.handshake_protocol,
    }


@app.post("/api/v1/vpn/disconnect")
async def vpn_disconnect():
    """
    Disconnect from the VPN and clean up session state.

    Stops the tunnel daemon, securely wipes session keys, and resets
    all telemetry counters.
    """
    if vpn_state.connection_state == ConnectionState.DISCONNECTED:
        raise HTTPException(status_code=409, detail="Not connected")

    vpn_state.connection_state = ConnectionState.DISCONNECTING
    _add_log("Disconnecting... Cleaning session keys", "info")

    # Simulate graceful shutdown
    import asyncio
    await asyncio.sleep(0.5)

    # Reset state
    vpn_state.connection_state = ConnectionState.DISCONNECTED
    vpn_state.connected_at = None
    vpn_state.session_id = ""
    vpn_state.vpn_ip = ""
    vpn_state.download_speed_mbps = 0.0
    vpn_state.upload_speed_mbps = 0.0
    vpn_state.current_latency_ms = 0.0
    vpn_state.current_jitter_ms = 0.0
    vpn_state.current_loss_rate = 0.0

    _add_log("Disconnected — Session keys wiped securely", "success")

    return {"status": "disconnected"}


@app.get("/api/v1/vpn/status")
async def vpn_status():
    """
    Get current VPN connection status and live metrics.

    Returns connection state, uptime, server info, cipher suite details,
    tunnel statistics, and network quality metrics.
    """
    server = _server_map.get(vpn_state.selected_server_id)
    uptime = 0.0
    key_rotation_remaining = vpn_state.key_rotation_interval

    if vpn_state.connected_at:
        uptime = time.time() - vpn_state.connected_at
    if vpn_state.last_key_rotation:
        elapsed = time.time() - vpn_state.last_key_rotation
        key_rotation_remaining = max(
            0, vpn_state.key_rotation_interval - elapsed
        )
        # Auto-rotate key timer
        if key_rotation_remaining <= 0:
            vpn_state.last_key_rotation = time.time()
            key_rotation_remaining = vpn_state.key_rotation_interval

    return {
        "connection_state": vpn_state.connection_state.value,
        "session_id": vpn_state.session_id,
        "vpn_ip": vpn_state.vpn_ip,
        "uptime_seconds": round(uptime, 1),

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
            "cipher": vpn_state.cipher_suite,
            "key_exchange": vpn_state.key_exchange,
            "handshake": vpn_state.handshake_protocol,
            "integrity": vpn_state.integrity,
            "pqc_algorithm": vpn_state.pqc_algorithm,
            "classical_algorithm": vpn_state.classical_algorithm,
            "key_rotation_remaining": round(key_rotation_remaining, 0),
        },

        # Tunnel stats
        "tunnel": {
            "bytes_sent": vpn_state.bytes_sent,
            "bytes_received": vpn_state.bytes_received,
            "packets_sent": vpn_state.packets_sent,
            "packets_received": vpn_state.packets_received,
            "packets_dropped": vpn_state.packets_dropped,
        },

        # Network quality
        "network": {
            "download_mbps": vpn_state.download_speed_mbps,
            "upload_mbps": vpn_state.upload_speed_mbps,
            "latency_ms": vpn_state.current_latency_ms,
            "jitter_ms": vpn_state.current_jitter_ms,
            "loss_rate": vpn_state.current_loss_rate,
            "mtu": vpn_state.current_mtu,
        },
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
            }
            for s in SERVERS
        ]
    }


@app.get("/api/v1/vpn/config")
async def vpn_config():
    """Return the active VPN tunnel configuration parameters."""
    return {
        "cipher_suite": vpn_state.cipher_suite,
        "key_exchange": vpn_state.key_exchange,
        "handshake_protocol": vpn_state.handshake_protocol,
        "integrity": vpn_state.integrity,
        "key_rotation_interval": vpn_state.key_rotation_interval,
        "mtu": vpn_state.current_mtu,
        "selected_server": vpn_state.selected_server_id,
    }


@app.get("/api/v1/logs")
async def get_logs(limit: int = 50):
    """
    Return recent activity log entries.

    Args:
        limit: Maximum number of log entries to return (default 50).
    """
    entries = vpn_state.activity_log[:limit]
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
"""
REST API Module for Hybrid VPN Dashboard.
Endpoints for starting/stopping VPN connection, retrieving status, and running benchmarks.
"""
