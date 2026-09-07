"""Unsupported IPv6 policy: read-only preflight and temporary client firewall."""
from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import subprocess

logger = logging.getLogger("pqvpn.ipv6")


def effective_policy(full_tunnel: bool, configured: str | None) -> str:
    return configured if configured is not None else ("block" if full_tunnel else "allow")


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=5).stdout


def connectivity(read=command) -> list[str]:
    """Conservative snapshot, not a reachability probe. ULA is usable IPv6 too."""
    routes = json.loads(read('ip', '-j', '-6', 'route', 'show', 'table', 'all'))
    addresses = json.loads(read('ip', '-j', '-6', 'addr', 'show'))
    found = []
    for route in routes:
        if route.get('type', 'unicast') != 'unicast' or route.get('dev') == 'lo':
            continue
        dst = route.get('dst', 'default')
        network = ipaddress.IPv6Network('::/0' if dst == 'default' else dst, strict=False)
        if not network.is_link_local and not network.is_multicast:
            found.append(f"route {dst} dev {route.get('dev', '?')}")
    for interface in addresses:
        for address in interface.get('addr_info', []):
            if (address.get('scope') == 'global'
                    and not {'tentative', 'dadfailed'} & set(address.get('flags', []))
                    and not address.get('tentative') and not address.get('dadfailed')):
                found.append(f"address {address['local']} on {interface['ifname']}")
    return found


def preflight(policy: str) -> None:
    if policy == 'fail' and connectivity():
        raise RuntimeError('IPv6 connectivity exists; ipv6_policy=fail refuses unsupported IPv6 bypass')


class IPv6Guard:
    def __init__(self, policy: str):
        self.policy = policy
        self.table: str | None = None

    def apply(self) -> None:
        if self.table is not None:
            return
        if self.policy == 'allow':
            logger.warning('IPv6 bypass explicitly permitted or outside split-tunnel scope: '
                           'IPv6 traffic is NOT protected by PQVPN')
            return
        if self.policy == 'fail':
            preflight(self.policy)
            return
        if self.policy != 'block':
            raise ValueError('unknown IPv6 policy')
        # Exclusive creation and one atomic batch: never replace another table.
        table = 'pqvpn_client6_' + secrets.token_hex(16)
        rules = (f'create table ip6 {table}\n'
                 f'add chain ip6 {table} output {{ type filter hook output priority filter; policy accept; }}\n'
                 f'add rule ip6 {table} output oifname "lo" accept\n'
                 f'add rule ip6 {table} output counter drop\n'
                 f'add chain ip6 {table} forward {{ type filter hook forward priority filter; policy drop; }}\n')
        subprocess.run(['nft', '-f', '-'], input=rules, text=True, capture_output=True, check=True)
        self.table = table

    def restore(self) -> None:
        if self.table is not None:
            # Keep ownership recorded if deletion fails, and surface the exact table.
            try:
                subprocess.run(['nft', 'delete', 'table', 'ip6', self.table],
                               capture_output=True, text=True, check=True)
            except Exception:
                logger.exception('IPv6 cleanup failed; owned table remains: ip6 %s', self.table)
                raise
            self.table = None
