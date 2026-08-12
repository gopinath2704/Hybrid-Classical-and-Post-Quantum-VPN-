"""
VPN Engine & Dynamic Network Agility — Public API.

Re-exports all public symbols from the unified engine module for
convenient top-level imports::

    from vpn import TUNInterface, VPNTunnelDaemon, MTUMonitor
    from vpn import NetworkQualityMonitor, OpenVPNManager
"""

from vpn.engine import (
    # §1 TUN Interface
    TUNInterface,
    TUNMode,

    # §2 VPN Tunnel Daemon
    VPNTunnelDaemon,
    TunnelState,
    TunnelStats,
    FRAME_OVERHEAD_TOTAL,
    DEFAULT_VPN_PORT,

    # §3 MTU Monitor
    MTUMonitor,
    DEFAULT_MTU,
    MIN_MTU,
    VPN_TOTAL_OVERHEAD,

    # §4 Network Quality Monitor
    NetworkQualityMonitor,
    QualitySnapshot,

    # §5 OpenVPN Manager
    OpenVPNManager,
)

__all__ = [
    # §1 TUN Interface
    "TUNInterface",
    "TUNMode",

    # §2 VPN Tunnel Daemon
    "VPNTunnelDaemon",
    "TunnelState",
    "TunnelStats",
    "FRAME_OVERHEAD_TOTAL",
    "DEFAULT_VPN_PORT",

    # §3 MTU Monitor
    "MTUMonitor",
    "DEFAULT_MTU",
    "MIN_MTU",
    "VPN_TOTAL_OVERHEAD",

    # §4 Network Quality Monitor
    "NetworkQualityMonitor",
    "QualitySnapshot",

    # §5 OpenVPN Manager
    "OpenVPNManager",
]
