"""
Unified VPN CLI — Server & Client Entrypoints.

Consolidates the standalone server daemon and client into a single CLI
with subcommands:

    python -m vpn.cli server                         # default settings
    python -m vpn.cli server --bind 0.0.0.0 --port 51820
    python -m vpn.cli server --dashboard --api-port 8000
    python -m vpn.cli client --server 127.0.0.1 --port 51820
    python -m vpn.cli client --server fra-01.pq-vpn.net --vpn-ip 10.8.0.2 -v

Environment:
    ALLOW_MOCK_PQC=1   Enable insecure SHA-based PQC mock (dev/testing only)
"""

from __future__ import annotations

import os
import sys
import time
import signal
import socket
import logging
import argparse
import threading
from pathlib import Path

# Ensure project root is importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from crypto.hybrid_crypto import get_crypto_status, ALLOW_MOCK_PQC
from vpn.engine import (
    VPNServerDaemon,
    VPNService,
    ServiceState,
    DEFAULT_VPN_PORT,
)


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s │ %(name)-24s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )


logger = logging.getLogger("pqvpn.cli")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Subcommands
# ═══════════════════════════════════════════════════════════════════════════════

def _run_server(args) -> None:
    """Run the VPN server daemon."""
    _setup_logging(args.verbose)

    if args.dashboard:
        import uvicorn
        def _run_api():
            uvicorn.run(
                "app.backend.api:app",
                host="0.0.0.0",
                port=args.api_port,
                log_level="info",
            )
        threading.Thread(target=_run_api, daemon=True).start()
        logger.info("Dashboard starting on http://0.0.0.0:%d", args.api_port)

    server = VPNServerDaemon(
        bind_host=args.bind,
        bind_port=args.port,
        pqc_algorithm=args.pqc,
    )
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


def _run_client(args) -> None:
    """Run the VPN client daemon."""
    _setup_logging(args.verbose)

    crypto = get_crypto_status()
    logger.info("━" * 60)
    logger.info("  PQ-VPN Client v1.0.0")
    logger.info("  PQC mode  : %s", crypto["pqc_mode"])
    logger.info("  Quantum   : %s", "✅ SAFE" if crypto["is_quantum_safe"] else "❌ NOT SAFE")
    if not crypto["is_quantum_safe"] and ALLOW_MOCK_PQC:
        logger.warning("  ⚠️  RUNNING WITH MOCK PQC — FOR DEVELOPMENT ONLY")
    logger.info("━" * 60)

    service = VPNService(
        key_rotation_interval=args.rekey_interval,
        pqc_algorithm=args.pqc,
    )

    # Graceful shutdown on SIGINT/SIGTERM
    def _shutdown(sig, frame):
        logger.info("Signal %d received — disconnecting…", sig)
        if service.state == ServiceState.CONNECTED:
            service.disconnect()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Connect
    logger.info("Connecting to %s:%d…", args.server, args.port)
    try:
        telemetry = service.connect(
            host=args.server,
            port=args.port,
            vpn_ip=args.vpn_ip,
        )
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    logger.info(
        "Connected — session=%s | vpn_ip=%s | tun=%s | pqc=%s",
        telemetry.session_id[:16], telemetry.vpn_ip,
        telemetry.tun_mode, telemetry.pqc_mode,
    )

    # Main loop: periodic stats + key rotation
    next_rekey = time.time() + args.rekey_interval
    while service.state == ServiceState.CONNECTED:
        time.sleep(5)
        t = service.get_telemetry()
        logger.info(
            "Up %ds | ↑%s MB ↓%s MB | pkt_sent=%d pkt_recv=%d | "
            "latency=%.1fms jitter=%.2fms loss=%.3f%%",
            int(t.uptime_seconds),
            round(t.bytes_sent / 1e6, 2),
            round(t.bytes_received / 1e6, 2),
            t.packets_sent, t.packets_received,
            t.latency_ms, t.jitter_ms, t.loss_rate * 100,
        )

        if time.time() >= next_rekey:
            try:
                nonce = service.rotate_keys()
                logger.info("Keys rotated — nonce=%s…", nonce)
            except Exception as e:
                logger.warning("Key rotation failed: %s", e)
            next_rekey = time.time() + args.rekey_interval


def main() -> None:
    """Unified VPN CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PQ-VPN — Hybrid Classical & Post-Quantum VPN",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Server subcommand
    server_parser = subparsers.add_parser(
        "server",
        description="PQ-VPN Server — Hybrid Classical & Post-Quantum VPN Server",
        help="Start VPN server daemon",
    )
    server_parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    server_parser.add_argument("--port", type=int, default=DEFAULT_VPN_PORT, help="Handshake port")
    server_parser.add_argument("--pqc", default="Kyber768", choices=["Kyber512", "Kyber768", "Kyber1024"])
    server_parser.add_argument("--dashboard", action="store_true", help="Also start FastAPI dashboard")
    server_parser.add_argument("--api-port", type=int, default=8000, help="Dashboard API port")
    server_parser.add_argument("-v", "--verbose", action="store_true")

    # Client subcommand
    client_parser = subparsers.add_parser(
        "client",
        description="PQ-VPN Client — Hybrid Classical & Post-Quantum VPN Client",
        help="Connect to VPN server",
    )
    client_parser.add_argument("--server", required=True, help="Server hostname or IP")
    client_parser.add_argument("--port", type=int, default=DEFAULT_VPN_PORT, help="Server port")
    client_parser.add_argument("--vpn-ip", default="10.8.0.2", help="VPN IP to assign to TUN")
    client_parser.add_argument("--pqc", default="Kyber768", choices=["Kyber512", "Kyber768", "Kyber1024"])
    client_parser.add_argument("--rekey-interval", type=int, default=300, help="Key rotation interval (s)")
    client_parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    if args.command == "server":
        _run_server(args)
    elif args.command == "client":
        _run_client(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
