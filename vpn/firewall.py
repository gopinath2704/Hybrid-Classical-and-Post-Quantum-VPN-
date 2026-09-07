"""Render only PQVPN-owned nftables policy; called by the privileged setup helper."""
import os
import sys
import ipaddress
from vpn.config import ServerConfig, load_server_config, validate_server, interface_name

# Filter packet destinations, never the address of a private WAN gateway.
DENIED = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
          '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
          '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4')


def render(cfg, wan):
    validate_server(cfg)
    interface_name(wan, 'WAN interface')
    tun, subnet = cfg.tun_name, cfg.vpn_subnet
    if wan == tun: raise ValueError('WAN interface must differ from VPN TUN')
    lines = ['table inet pqvpn {', ' chain forward { type filter hook forward priority filter; policy accept;']
    # These precede allowlists so an exception cannot silently enable peer access.
    lines += [f'  iifname "{tun}" oifname "{tun}" drop',
              f'  iifname "{tun}" ip daddr {subnet} drop',
              f'  iifname "{tun}" ip saddr != {subnet} drop']
    for network in cfg.allowed_forward_networks:
        lines.append(f'  iifname "{tun}" oifname "{wan}" ip daddr {network} accept')
    lines += [f'  iifname "{tun}" ip daddr {{ {", ".join(DENIED)} }} drop',
              f'  iifname "{tun}" oifname "{wan}" ip saddr {subnet} accept',
              f'  iifname "{wan}" oifname "{tun}" ip daddr {subnet} ct state established,related accept',
              f'  iifname "{tun}" drop', f'  oifname "{tun}" drop', ' }',
              ' chain input { type filter hook input priority filter; policy accept;']
    if cfg.allow_server_ping:
        lines.append(f'  iifname "{tun}" ip daddr {cfg.server_vpn_ip} icmp type echo-request accept')
    lines += [f'  iifname "{tun}" drop', ' }', '}',
              'table ip pqvpn_nat {', ' chain postrouting { type nat hook postrouting priority srcnat; policy accept;',
              f'  ip saddr {subnet} oifname "{wan}" masquerade', ' }', '}',
              'table inet pqvpn_mangle {', ' chain forward { type filter hook forward priority mangle; policy accept;',
              f'  iifname "{tun}" tcp flags syn tcp option maxseg size set rt mtu', ' }', '}']
    return '\n'.join(lines) + '\n'


def main():
    path, wan, mode = sys.argv[1:]
    if path:
        cfg = load_server_config(path)
    else:
        subnet = os.environ.get('VPN_SUBNET', '10.8.0.0/24')
        cfg = ServerConfig(vpn_subnet=subnet, server_vpn_ip=str(ipaddress.IPv4Network(subnet).network_address + 1),
                           tun_name=os.environ.get('VPN_TUN', 'pqvpn0'), outbound_interface=os.environ.get('WAN_IF', ''))
        validate_server(cfg)
    if mode == 'settings':
        print(cfg.outbound_interface)
        print('1' if cfg.manage_ip_forward else '0')
    else:
        print(render(cfg, wan), end='')

if __name__ == '__main__': main()
