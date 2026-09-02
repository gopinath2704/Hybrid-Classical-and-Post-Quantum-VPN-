"""
PQ-VPN Application Backend — Controller API & WebSocket Telemetry.

Re-exports the FastAPI app instance and connection state model
for use by the desktop launcher (app/main.py).
"""

from app.backend.api import app, vpn_state, ConnectionState, ws_manager

__all__ = [
    "app",
    "vpn_state",
    "ConnectionState",
    "ws_manager",
]
