"""
PQ-VPN Application Backend — Controller API & WebSocket Telemetry.

Re-exports the FastAPI app instance and WebSocket telemetry router
for use by the desktop launcher (app/main.py).
"""

from app.backend.api import app, vpn_state, ConnectionState
from app.backend.websocket import router as ws_router, manager as ws_manager

__all__ = [
    "app",
    "vpn_state",
    "ConnectionState",
    "ws_router",
    "ws_manager",
]
