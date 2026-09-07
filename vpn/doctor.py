"""Read-only deployment diagnostics. No TUN, sockets, routes, or firewall mutations."""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys

from vpn.config import load_client_config, load_server_config
from vpn.identity import AuthorizedClients, fingerprint, load_client_private, validate_server_identity
from crypto.hybrid_crypto import PQCProvider, _OQS_AVAILABLE, _oqs_module
from vpn.ipv6 import connectivity, effective_policy


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


def run(role, config_path):
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
