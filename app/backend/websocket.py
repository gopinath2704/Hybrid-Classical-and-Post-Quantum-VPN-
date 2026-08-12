"""
WebSocket Telemetry Streaming Module.

Broadcasts live VPN telemetry data to connected frontend clients every 500ms.
Streams real-time bandwidth, latency, jitter, packet loss, MTU, and tunnel
statistics as JSON frames over a persistent WebSocket connection.

Endpoint:
    ws://127.0.0.1:8000/ws/telemetry

JSON Frame Schema:
    {
        "type": "telemetry",
        "timestamp": 1723456789.123,
        "connection_state": "CONNECTED",
        "uptime_seconds": 1543.2,
        "download_mbps": 1150.0,
        "upload_mbps": 42.7,
        "latency_ms": 23.6,
        "jitter_ms": 1.2,
        "loss_rate": 0.001,
        "mtu": 1500,
        "bytes_sent": 1320000000,
        "bytes_received": 478150000,
        "packets_sent": 981234,
        "packets_received": 1642311,
        "key_rotation_remaining": 274,
        "bandwidth_history": [...],
        "latency_history": [...]
    }
"""

from __future__ import annotations

import time
import json
import asyncio
import logging
import math
import random
from collections import deque

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("pqvpn.websocket")

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# Time-series history buffers (rolling 60-second windows)
# ─────────────────────────────────────────────────────────────────────────────

MAX_HISTORY_POINTS = 120  # 60 seconds at 500ms intervals

# Shared history deques (thread-safe append/popleft)
download_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)
upload_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)
latency_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)
loss_history: deque[float] = deque(maxlen=MAX_HISTORY_POINTS)


# ─────────────────────────────────────────────────────────────────────────────
# Connected WebSocket Client Manager
# ─────────────────────────────────────────────────────────────────────────────

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


manager = ConnectionManager()


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry Frame Builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_telemetry_frame() -> dict:
    """
    Build a telemetry JSON frame from the global VPN state.

    Imports vpn_state lazily to avoid circular imports.
    """
    # Lazy import to avoid circular dependency
    from app.backend.api import vpn_state, ConnectionState

    now = time.time()
    uptime = 0.0
    key_rotation_remaining = vpn_state.key_rotation_interval

    if vpn_state.connected_at:
        uptime = now - vpn_state.connected_at
    if vpn_state.last_key_rotation:
        elapsed = now - vpn_state.last_key_rotation
        key_rotation_remaining = max(
            0, vpn_state.key_rotation_interval - elapsed
        )

    # Only record history when connected
    if vpn_state.connection_state == ConnectionState.CONNECTED:
        download_history.append(vpn_state.download_speed_mbps)
        upload_history.append(vpn_state.upload_speed_mbps)
        latency_history.append(vpn_state.current_latency_ms)
        loss_history.append(vpn_state.current_loss_rate * 100)  # percentage
    else:
        download_history.append(0.0)
        upload_history.append(0.0)
        latency_history.append(0.0)
        loss_history.append(0.0)

    return {
        "type": "telemetry",
        "timestamp": round(now, 3),
        "connection_state": vpn_state.connection_state.value,
        "uptime_seconds": round(uptime, 1),

        # Bandwidth
        "download_mbps": vpn_state.download_speed_mbps,
        "upload_mbps": vpn_state.upload_speed_mbps,

        # Network quality
        "latency_ms": vpn_state.current_latency_ms,
        "jitter_ms": vpn_state.current_jitter_ms,
        "loss_rate": vpn_state.current_loss_rate,
        "mtu": vpn_state.current_mtu,

        # Tunnel stats
        "bytes_sent": vpn_state.bytes_sent,
        "bytes_received": vpn_state.bytes_received,
        "packets_sent": vpn_state.packets_sent,
        "packets_received": vpn_state.packets_received,

        # Key rotation
        "key_rotation_remaining": round(key_rotation_remaining, 0),

        # Time-series history arrays (for charts)
        "download_history": list(download_history),
        "upload_history": list(upload_history),
        "latency_history": list(latency_history),
        "loss_history": list(loss_history),
    }


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@router.websocket("/ws/telemetry")
async def telemetry_websocket(websocket: WebSocket):
    """
    Live telemetry WebSocket endpoint.

    Pushes telemetry frames to the client every 500ms while connected.
    The client can send JSON control messages (e.g. change update rate).
    """
    await manager.connect(websocket)

    try:
        while True:
            # Build and broadcast telemetry frame
            frame = _build_telemetry_frame()
            try:
                await websocket.send_text(json.dumps(frame))
            except Exception:
                break

            # Wait 500ms, but also listen for client messages
            try:
                # Use asyncio.wait_for to allow receiving messages during wait
                msg = await asyncio.wait_for(
                    websocket.receive_text(), timeout=0.5
                )
                # Handle client control messages if needed
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
        manager.disconnect(websocket)
