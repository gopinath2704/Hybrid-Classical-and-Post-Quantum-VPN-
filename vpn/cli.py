"""Provisioning and Linux VPN client/server command line."""
from __future__ import annotations

import argparse
import base64
import logging
import signal
import sys
from pathlib import Path

from crypto.hybrid_crypto import get_crypto_status
from vpn.accounts import DEFAULT_ACCOUNT_DATABASE, DEVICE_STATUSES, AccountError, AccountStore
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

    account = commands.add_parser(
        "account",
        description=("Administrator review of account-bound devices. Only 'approve' grants "
                     "VPN access and only 'revoke' withdraws it; run on the server as root."),
    )
    account_actions = account.add_subparsers(dest="action", required=True)
    account_devices = account_actions.add_parser("devices", description="List account-bound devices")
    account_devices.add_argument("--status", choices=DEVICE_STATUSES)
    account_devices.add_argument("--accounts-db", default=str(DEFAULT_ACCOUNT_DATABASE))
    approve = account_actions.add_parser(
        "approve", description="Approve a pending/rejected/revoked device and authorize it for VPN"
    )
    approve.add_argument("device_id", type=int)
    approve.add_argument("--accounts-db", default=str(DEFAULT_ACCOUNT_DATABASE))
    approve.add_argument("--database", default="config/authorized_clients.json")
    approve.add_argument("--vpn-ip")
    reject = account_actions.add_parser("reject", description="Reject a pending device")
    reject.add_argument("device_id", type=int)
    reject.add_argument("--accounts-db", default=str(DEFAULT_ACCOUNT_DATABASE))
    account_revoke = account_actions.add_parser(
        "revoke",
        description=("Revoke an approved device for new sessions. Restart the VPN server "
                     "to terminate existing sessions; no live reload is implemented."),
    )
    account_revoke.add_argument("device_id", type=int)
    account_revoke.add_argument("--accounts-db", default=str(DEFAULT_ACCOUNT_DATABASE))
    account_revoke.add_argument("--database", default="config/authorized_clients.json")

    server = commands.add_parser("server")
    server.add_argument("--config", default="config/server.toml")
    server.add_argument("--dev-emulated-tun", action="store_true")
    server.add_argument(
        "--allow-mock-pqc", action="store_true",
        help="explicitly permit insecure mock PQC for tests/development",
    )
    return parser


def _account_command(args: argparse.Namespace) -> None:
    """Administrator device review: the explicit trust boundary into AuthorizedClients."""
    store = AccountStore(Path(args.accounts_db))
    store.initialize()
    if args.action == "devices":
        devices = store.list_devices(args.status)
        if not devices:
            print("No devices")
        for device in devices:
            owner = store.get_user_by_id(device.user_id)
            print(
                f"{device.id:>5}  {device.status:<8}  "
                f"{'enabled' if device.enabled else 'disabled':<8}  "
                f"{owner.username if owner else '?':<20}  {device.client_fingerprint}  "
                f"{device.device_name}"
            )
        return
    device = store.get_device_by_id(args.device_id)
    if device is None:
        raise SystemExit("device not found")
    owner = store.get_user_by_id(device.user_id)
    if args.action == "approve":
        if device.status == "approved":
            raise SystemExit("device is already approved")
        if owner is None or not owner.enabled or not device.enabled:
            raise SystemExit("refusing to approve: account or device is disabled")
        authorized = AuthorizedClients(Path(args.database))
        client_id = f"{owner.username}-{device.id}"
        authorized.authorize(device.client_public_key, client_id, args.vpn_ip)
        try:
            store.set_device_status(device.id, "approved", expected=(device.status,))
        except Exception:
            authorized.revoke(device.client_fingerprint)
            raise
        print("Device approved and authorized for VPN")
        print(f"Client ID: {client_id}")
        print(f"Fingerprint: {device.client_fingerprint}")
        print(f"Assigned VPN IP: {args.vpn_ip or 'auto'}")
        return
    if args.action == "reject":
        if device.status != "pending":
            raise SystemExit(
                f"device is {device.status}; only pending devices can be rejected"
                + (" (use 'account revoke')" if device.status == "approved" else "")
            )
        store.set_device_status(device.id, "rejected", expected=("pending",))
        print("Device rejected; AuthorizedClients was not changed")
        return
    if args.action == "revoke":
        if device.status != "approved":
            raise SystemExit(f"device is {device.status}; only approved devices can be revoked")
        # Remove tunnel authorization first so a failure cannot leave it active.
        AuthorizedClients(Path(args.database)).revoke(device.client_fingerprint)
        store.set_device_status(device.id, "revoked", expected=("approved",))
        print(
            "Device revoked for new sessions. Restart the VPN server to terminate "
            "existing sessions (all clients); live reload is not implemented."
        )


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
    if args.command == "account":
        try:
            _account_command(args)
        except (AccountError, ValueError, OSError) as exc:
            raise SystemExit(f"account error: {exc}") from None
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
