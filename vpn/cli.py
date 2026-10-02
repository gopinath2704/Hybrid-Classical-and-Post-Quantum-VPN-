"""Provisioning, diagnostics, and Linux VPN client/server command line."""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import logging
import os
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
from pathlib import Path

from crypto.hybrid_crypto import PQCProvider, _OQS_AVAILABLE, _oqs_module, get_crypto_status
from vpn.accounts import DEFAULT_ACCOUNT_DATABASE, DEVICE_STATUSES, AccountError, AccountStore
from vpn.config import load_client_config, load_server_config, validate_client
from vpn.identity import (
    AuthorizedClients, EnrollmentRequest, fingerprint, generate_client_identity,
    generate_client_identity_kem, generate_server_identity,
    load_client_private, load_client_public_key, load_ed25519_public_key,
    load_enrollment, validate_server_identity, write_enrollment,
)
from vpn.network import connectivity, effective_policy
from vpn.runtime import VPNClient, VPNServer


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=5).stdout


def overlapping_routes(routes, subnet):
    network = ipaddress.IPv4Network(subnet)
    conflicts = []
    for route in routes:
        destination = route.get('dst', 'default')
        if destination == 'default': continue
        try: other = ipaddress.IPv4Network(destination, strict=False)
        except ValueError: continue
        if other.overlaps(network): conflicts.append(f"{destination} dev {route.get('dev', '?')}")
    return conflicts


def readable_as(path, username):
    account = pwd.getpwnam(username)
    groups = os.getgrouplist(username, account.pw_gid)
    target = Path(path).resolve(strict=True)
    for entry in [*reversed(target.parents), target]:
        info = entry.stat()
        bits = (info.st_mode >> 6 if info.st_uid == account.pw_uid else
                info.st_mode >> 3 if info.st_gid in groups else info.st_mode)
        required = 1 if entry.is_dir() else 4
        if not bits & required: return False
    return True


PRODUCTION_ROOT = Path('/opt/pqvpn')


def production_deployment(config_path):
    """Apply the packaged systemd layout only to production diagnostics."""
    return (Path(config_path).absolute().is_relative_to('/etc/pqvpn') or
            Path(__file__).resolve().is_relative_to(PRODUCTION_ROOT) or
            Path(sys.executable).absolute().is_relative_to(PRODUCTION_ROOT))


def privileged_code_permissions(root=PRODUCTION_ROOT):
    """Audit the code/venv tree, symlink targets and replacement-capable parents."""
    root = Path(root).absolute()
    for required in ('scripts/server-network.sh',
                     'vpn/network.py', 'handshake', 'crypto', '.venv/bin/python'):
        (root / required).stat()
    seen = set()

    def inspect(path):
        info = path.lstat()
        if info.st_uid != 0:
            raise ValueError(f'{path}: privileged code must be root-owned')
        if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
            raise ValueError(f'{path}: privileged code is group/world writable')
        if stat.S_ISLNK(info.st_mode):
            visit(resolve_trusted_link(path))
        elif stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError(f'{path}: unexpected privileged code file type')

    def resolve_trusted_link(path):
        pending = list(path.parts[1:])
        current = Path(path.anchor)
        links = 0
        while pending:
            part = pending.pop(0)
            if part == '..':
                current = current.parent
                continue
            candidate = current / part
            info = candidate.lstat()
            if info.st_uid != 0:
                raise ValueError(f'{candidate}: privileged code must be root-owned')
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 40:
                    raise ValueError(f'{path}: excessive or cyclic symlinks')
                target = Path(os.readlink(candidate))
                if target.is_absolute():
                    current = Path(target.anchor)
                    pending = list(target.parts[1:]) + pending
                else:
                    pending = list(target.parts) + pending
            else:
                inspect_metadata(candidate)
                current = candidate
        return current

    def inspect_metadata(path):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f'{path}: privileged code ancestor must be root-owned and not group/world writable')

    def visit(path):
        if path in seen:
            return
        seen.add(path)
        inspect(path)

    for parent in reversed(root.parents):
        inspect_metadata(parent)
    visit(root)
    return f'{root}: root-owned code/venv, no group/world writes; symlink targets and ancestors checked'


def doctor_run(role, config_path):
    rows = []
    def report(level, label, detail=''):
        rows.append((level, label, detail))
    def check(label, function):
        try:
            detail = function()
            if detail is False: raise ValueError('check failed')
            report('PASS', label, '' if detail is None or detail is True else str(detail))
        except Exception as exc:
            report('FAIL', label, str(exc))
    if role == 'server':
        if production_deployment(config_path):
            check('Privileged systemd code ownership', privileged_code_permissions)
        else:
            report('PASS', 'Privileged systemd code ownership',
                   'not applicable: development paths; production /opt/pqvpn not audited')
    check('Python minimum runtime version (3.11)', lambda: sys.version_info >= (3, 11))
    report('PASS' if sys.version_info[:3] == (3, 14, 7) else 'WARN',
           'Python tested baseline', '3.14.7; other versions require fresh validation')
    def native():
        if not _OQS_AVAILABLE: raise ValueError('native ML-KEM-768 is unavailable; install liboqs explicitly')
        if os.environ.get('ALLOW_MOCK_PQC') == '1': raise ValueError('unset ALLOW_MOCK_PQC for deployment')
        provider = PQCProvider()
        secret, public = provider.generate_keypair()
        ct, a = provider.encapsulate(public)
        if provider.decapsulate(secret, ct) != a or not provider.is_quantum_safe: raise ValueError('native self-test failed')
        return f'Python {sys.version.split()[0]}, liboqs-python {_oqs_module.oqs_python_version()}, liboqs {_oqs_module.oqs_version()}'
    check('Native ML-KEM-768 / no mock / self-test', native)
    try:
        cfg = (load_server_config if role == 'server' else load_client_config)(config_path)
        report('PASS', 'Configuration')
    except Exception as exc:
        report('FAIL', 'Configuration', str(exc))
        cfg = None
    check('Linux TUN device', lambda: stat.S_ISCHR(Path('/dev/net/tun').stat().st_mode))
    for executable in (('ip', 'nft', 'sysctl', 'ss') if role == 'server' else ('ip',)):
        check(f'{executable} executable', lambda executable=executable: bool(shutil.which(executable)))
    if cfg:
        subnet = cfg.vpn_subnet if role == 'server' else cfg.expected_vpn_subnet
        def routes():
            conflicts = overlapping_routes(json.loads(command('ip', '-j', '-4', 'route', 'show', 'table', 'all')), subnet)
            for interface in json.loads(command('ip', '-j', '-4', 'addr', 'show')):
                for address in interface.get('addr_info', []):
                    cidr = f"{address['local']}/{address['prefixlen']}"
                    if ipaddress.IPv4Network(cidr, strict=False).overlaps(ipaddress.IPv4Network(subnet)):
                        conflicts.append(f"{cidr} on {interface['ifname']}")
            if conflicts: raise ValueError('VPN subnet overlaps: ' + ', '.join(conflicts))
            return f'no visible route/interface conflicts with {subnet}'
        check('VPN subnet collisions (including visible container routes)', routes)
        if role == 'server':
            check('Server identity pair and private permissions', lambda: bool(validate_server_identity(Path(cfg.server_identity_private_key), Path(cfg.server_identity_public_key))))
            def database():
                db = AuthorizedClients(Path(cfg.authorized_clients_file))._load(required=True, subnet=cfg.vpn_subnet, server_ip=cfg.server_vpn_ip)
                return f"{len(db['clients'])} validated records"
            check('Authorized client database', database)
            def wan():
                default = json.loads(command('ip', '-j', '-4', 'route', 'show', 'default'))
                if not default: raise ValueError('no default IPv4 route')
                name = cfg.outbound_interface or default[0]['dev']
                command('ip', 'link', 'show', 'dev', name)
                return name
            check('Default IPv4 route and WAN interface', wan)
            def forwarding():
                value = command('sysctl', '-n', 'net.ipv4.ip_forward').strip()
                if value != '1' and not cfg.manage_ip_forward: raise ValueError('forwarding disabled while manage_ip_forward=false')
                return f'{value}; manage_ip_forward={cfg.manage_ip_forward}'
            check('IP forwarding state', forwarding)
            for protocol, port in [('tcp', cfg.control_port), ('udp', cfg.udp_port)]:
                def available(protocol=protocol, port=port):
                    output = command('ss', '-H', '-ln' + ('t' if protocol == 'tcp' else 'u'))
                    if any(re.search(rf':{port}$', line.split()[3]) for line in output.splitlines() if len(line.split()) >= 4):
                        raise ValueError(f'{protocol}/{port} already in use')
                    return f'{protocol}/{port} appears available (read-only snapshot)'
                check(f'{protocol} listener availability', available)
            for path in [config_path, cfg.server_identity_private_key, cfg.server_identity_public_key, cfg.authorized_clients_file]:
                check(f'{cfg.service_user} can read {path}', lambda path=path: readable_as(path, cfg.service_user))
            report('WARN', 'External provider/host firewall requires operator verification',
                   f'allow {cfg.control_port}/TCP and {cfg.udp_port}/UDP; keep 8000 private; restrict SSH administrator sources; inspect ss -lntup and nft list ruleset')
        else:
            policy = effective_policy(cfg.full_tunnel, cfg.ipv6_policy)
            def ipv6_policy():
                visible = connectivity(command)
                if policy == 'fail' and visible:
                    raise ValueError('IPv6 connectivity exists: ' + '; '.join(visible))
                if policy == 'block' and not shutil.which('nft'):
                    raise ValueError('ipv6_policy=block requires nft')
                return f'{policy}; {len(visible)} visible IPv6 routes/addresses (read-only snapshot)'
            if cfg.full_tunnel or cfg.ipv6_policy is not None:
                check('IPv6 leak policy', ipv6_policy)
            if policy == 'allow':
                report('WARN', 'IPv6 bypass explicitly permitted' if cfg.ipv6_policy else 'Split-tunnel IPv6 outside VPN scope',
                       'IPv6 traffic is not protected by PQVPN')
            def server_pin():
                public = Path(cfg.server_identity_public_key).read_bytes()
                if len(public) != 1184: raise ValueError('server public key must be 1184 bytes')
                if not re.fullmatch('[0-9a-fA-F]{64}', cfg.server_identity_fingerprint): raise ValueError('server fingerprint must be exactly 64 hex characters')
                if fingerprint(public) != cfg.server_identity_fingerprint.lower(): raise ValueError('server fingerprint mismatch')
            check('Provisioned server identity and pin', server_pin)
            check('Client private identity and permissions', lambda: bool(load_client_private(Path(cfg.client_identity_private_key))))
            if cfg.dns_mode == 'none': report('WARN', 'DNS explicitly unmanaged', 'DNS may bypass the VPN')
            else: check('systemd-resolved DNS manager', lambda: bool(shutil.which('resolvectl')) and bool(command('resolvectl', 'status')))
            def resolve():
                address = socket.gethostbyname(cfg.server_host)
                command('ip', '-4', 'route', 'get', address)
                return address
            check('Server hostname resolves and IPv4 route exists', resolve)
    for level, label, detail in rows:
        print(f'{level} {label}' + (f': {detail}' if detail else ''))
    return 1 if any(level == 'FAIL' for level, _, _ in rows) else 0


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
    generate_key.add_argument("--kem", action="store_true", help="generate ML-KEM-768 identity for v3 protocol")

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
        raise SystemExit(doctor_run(args.role, args.config))
    if args.command == "identity":
        result = generate_server_identity(Path(args.private), Path(args.public))
        print(f"server identity fingerprint: {result}")
        return
    if args.command == "client-key":
        if args.kem:
            result = generate_client_identity_kem(Path(args.private), Path(args.public))
            print(f"client ML-KEM-768 identity fingerprint: {result}")
        else:
            result = generate_client_identity(Path(args.private), Path(args.public))
            print(f"client identity fingerprint: {result}")
        return
    if args.command == "client" and args.action == "authorize":
        candidate = Path(args.public_key)
        if candidate.exists():
            raw = candidate.read_bytes()
        else:
            raw = base64.b64decode(args.public_key, validate=True)
        print(AuthorizedClients(Path(args.database)).authorize(
            raw, args.client_id, args.vpn_ip
        ))
        return
    if args.command == "client" and args.action == "enrollment-request":
        public_key = load_client_public_key(Path(args.public_key))
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
