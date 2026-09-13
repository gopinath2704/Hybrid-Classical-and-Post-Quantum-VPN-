"""Provisioning and Linux VPN client/server command line."""
from __future__ import annotations

import argparse
import base64
import logging
import signal
import sys
from pathlib import Path

from crypto.hybrid_crypto import get_crypto_status
from vpn.config import load_client_config, load_server_config, validate_client
from vpn.enrollment import (
    EnrollmentRequest,
    load_ed25519_public_key,
    load_enrollment,
    write_enrollment,
)
from vpn.identity import AuthorizedClients, generate_client_identity, generate_server_identity
from vpn.runtime import VPNClient, VPNServer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m vpn.cli")
    parser.add_argument("-v", "--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser("doctor")
    doctor.add_argument("role", choices=["server", "client"])
    doctor.add_argument("--config", required=True)

    identity = commands.add_parser("identity")
    identity_actions = identity.add_subparsers(dest="action", required=True)
    generate = identity_actions.add_parser("generate")
    generate.add_argument("--private", default="config/server_identity_private.key")
    generate.add_argument("--public", default="config/server_identity_public.key")

    client_key = commands.add_parser("client-key")
    key_actions = client_key.add_subparsers(dest="action", required=True)
    generate_key = key_actions.add_parser("generate")
    generate_key.add_argument("--private", default="config/client_identity_private.key")
    generate_key.add_argument("--public", default="config/client_identity_public.key")

    client = commands.add_parser("client")
    client_actions = client.add_subparsers(dest="action", required=True)
    authorize = client_actions.add_parser("authorize")
    authorize.add_argument("public_key")
    authorize.add_argument("--database", default="config/authorized_clients.json")
    authorize.add_argument("--client-id")
    authorize.add_argument("--vpn-ip")

    authorize_request = client_actions.add_parser(
        "authorize-request", description="Authorize a strict public .pqenroll request"
    )
    authorize_request.add_argument("request")
    authorize_request.add_argument("--database", default="config/authorized_clients.json")
    authorize_request.add_argument("--vpn-ip")

    enrollment = client_actions.add_parser(
        "enrollment-request", description="Create a public-only .pqenroll request"
    )
    enrollment.add_argument("--output", required=True)
    enrollment.add_argument("--client-id", required=True)
    enrollment.add_argument("--public-key", required=True)

    revoke = client_actions.add_parser(
        "revoke",
        description=("Revoke new sessions only. Restart the VPN server to terminate "
                     "existing sessions; no live reload is implemented."),
    )
    revoke.add_argument("fingerprint")
    revoke.add_argument("--database", default="config/authorized_clients.json")

    connect = client_actions.add_parser("connect")
    connect.add_argument("--config", default="config/client.toml")
    connect.add_argument("--server-host", help="validated deployment override for the configured server host")
    connect.add_argument("--dev-emulated-tun", action="store_true")
    connect.add_argument(
        "--allow-mock-pqc", action="store_true",
        help="explicitly permit insecure mock PQC for tests/development",
    )

    server = commands.add_parser("server")
    server.add_argument("--config", default="config/server.toml")
    server.add_argument("--dev-emulated-tun", action="store_true")
    server.add_argument(
        "--allow-mock-pqc", action="store_true",
        help="explicitly permit insecure mock PQC for tests/development",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if args.command == "doctor":
        from vpn.doctor import run
        raise SystemExit(run(args.role, args.config))
    if args.command == "identity":
        result = generate_server_identity(Path(args.private), Path(args.public))
        print(f"server identity fingerprint: {result}")
        return
    if args.command == "client-key":
        result = generate_client_identity(Path(args.private), Path(args.public))
        print(f"client identity fingerprint: {result}")
        return
    if args.command == "client" and args.action == "authorize":
        candidate = Path(args.public_key)
        raw = candidate.read_bytes() if candidate.exists() else base64.b64decode(
            args.public_key, validate=True
        )
        print(AuthorizedClients(Path(args.database)).authorize(
            raw, args.client_id, args.vpn_ip
        ))
        return
    if args.command == "client" and args.action == "enrollment-request":
        public_key = load_ed25519_public_key(Path(args.public_key))
        request = EnrollmentRequest.create(args.client_id, public_key)
        write_enrollment(Path(args.output), request)
        print("Enrollment request created")
        print(f"Client ID: {request.client_id}")
        print(f"Fingerprint: {request.client_fingerprint}")
        print(f"Output: {args.output}")
        return
    if args.command == "client" and args.action == "authorize-request":
        request = load_enrollment(Path(args.request))
        AuthorizedClients(Path(args.database)).authorize(
            request.public_key_bytes, request.client_id, args.vpn_ip
        )
        print("Client authorized")
        print(f"Client ID: {request.client_id}")
        print(f"Fingerprint: {request.client_fingerprint}")
        print(f"Assigned VPN IP: {args.vpn_ip or 'auto'}")
        return
    if args.command == "client" and args.action == "revoke":
        if not AuthorizedClients(Path(args.database)).revoke(args.fingerprint):
            raise SystemExit("client fingerprint not found")
        print(
            "Client revoked for new sessions. Existing active sessions continue until "
            "disconnect/expiration/server restart. Restart the VPN server to terminate "
            "existing sessions (all clients); live reload is not implemented."
        )
        return

    status = get_crypto_status()
    if not status["is_quantum_safe"]:
        if (status["pqc_mode"] == "mock_sha_fallback"
                and getattr(args, "allow_mock_pqc", False)):
            logging.critical("*** INSECURE MOCK PQC ACTIVE: NOT QUANTUM SAFE; DEVELOPMENT ONLY ***")
        else:
            raise SystemExit("native ML-KEM-768 unavailable; production start refused")
    if args.command == "server":
        cfg = load_server_config(args.config)
        cfg.dev_emulated_tun = args.dev_emulated_tun
        service = VPNServer(cfg)
        signal.signal(signal.SIGTERM, lambda *_: service.stop())
        try:
            service.start()
        except KeyboardInterrupt:
            service.stop()
        return

    cfg = load_client_config(args.config)
    cfg.dev_emulated_tun = args.dev_emulated_tun
    if args.server_host:
        cfg.server_host = args.server_host
        validate_client(cfg)
    service = VPNClient(cfg)
    signal.signal(signal.SIGTERM, lambda *_: service.stop_event.set())
    info = service.connect()
    print(f"connected: {info['client_vpn_ip']} via UDP {info['udp_port']}")
    try:
        service.stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        service.disconnect()
    if getattr(service, "state", "") == "FAILED":
        raise SystemExit(service.error)


if __name__ == "__main__":
    main()
