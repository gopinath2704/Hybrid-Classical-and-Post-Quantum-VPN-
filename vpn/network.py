"""Small Linux TUN and authenticated-path telemetry primitives."""
from __future__ import annotations
import enum,os,socket,statistics,struct,sys,time
from collections import deque
from dataclasses import dataclass,field
from typing import Optional
# Privileged server nftables policy renderer
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

if __name__ == '__main__': main(); raise SystemExit
from handshake.kemtls import DATA_FRAME_OVERHEAD
_TUNSETIFF=0x400454CA;_IFF_TUN=1;_IFF_NO_PI=0x1000;_TUN_READ_BUFFER=65535
class TUNMode(enum.Enum):NATIVE="native";SOCKET_PIPE="socket_pipe"
@dataclass
class TUNInterface:
    name:str="pqvpn0";mtu:int=1380;mode:TUNMode=TUNMode.NATIVE;is_open:bool=False
    _fd:Optional[int]=field(default=None,repr=False);_sock_local:Optional[socket.socket]=field(default=None,repr=False);_sock_remote:Optional[socket.socket]=field(default=None,repr=False)
    def open(self):
        if self.is_open:raise RuntimeError("TUN interface is already open")
        if self.mode==TUNMode.NATIVE:
            if sys.platform!="linux":raise OSError("native TUN is Linux-only")
            import fcntl
            fd=os.open("/dev/net/tun",os.O_RDWR)
            try:fcntl.ioctl(fd,_TUNSETIFF,struct.pack("16sH",self.name.encode(),_IFF_TUN|_IFF_NO_PI))
            except Exception:os.close(fd);raise
            self._fd=fd
        else:
            self._sock_local,self._sock_remote=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM);self._sock_local.setblocking(False);self._sock_remote.setblocking(False)
        self.is_open=True
    def read(self,size=_TUN_READ_BUFFER):
        if not self.is_open:raise RuntimeError("TUN interface is not open")
        return os.read(self._fd,size) if self.mode==TUNMode.NATIVE else self._sock_local.recv(size)
    def write(self,packet):
        if not self.is_open:raise RuntimeError("TUN interface is not open")
        return os.write(self._fd,packet) if self.mode==TUNMode.NATIVE else self._sock_local.send(packet)
    def inject(self,packet):
        if self.mode!=TUNMode.SOCKET_PIPE or not self.is_open:raise RuntimeError("inject requires an open SOCKET_PIPE")
        return self._sock_remote.send(packet)
    def drain(self,size=_TUN_READ_BUFFER):
        if self.mode!=TUNMode.SOCKET_PIPE or not self.is_open:raise RuntimeError("drain requires an open SOCKET_PIPE")
        return self._sock_remote.recv(size)
    def fileno(self):
        if not self.is_open:raise RuntimeError("TUN interface is not open")
        return self._fd if self.mode==TUNMode.NATIVE else self._sock_local.fileno()
    def close(self):
        if not self.is_open:return
        if self._fd is not None:os.close(self._fd);self._fd=None
        for name in ("_sock_local","_sock_remote"):
            value=getattr(self,name)
            if value:value.close();setattr(self,name,None)
        self.is_open=False
    def get_info(self):return {"name":self.name,"mtu":self.mtu,"mode":self.mode.value,"is_open":self.is_open}
    def __enter__(self):self.open();return self
    def __exit__(self,*_):self.close()

DEFAULT_MTU=1500;MIN_MTU=1280;IPV4_HEADER_SIZE=20;IPV6_HEADER_SIZE=40;UDP_HEADER_SIZE=8;TCP_HEADER_SIZE=20
VPN_TOTAL_OVERHEAD=DATA_FRAME_OVERHEAD
# Compatibility constants for the benchmark reporter. Data records transmit no nonce or length prefix.
FRAME_OVERHEAD_NONCE=0;FRAME_OVERHEAD_TAG=16;FRAME_OVERHEAD_TOTAL=DATA_FRAME_OVERHEAD;VPN_LENGTH_PREFIX=0
class MTUMonitor:
    def __init__(self,path_mtu=DEFAULT_MTU):self._path_mtu=path_mtu;self._history=[(time.time(),path_mtu)]
    @property
    def path_mtu(self):return self._path_mtu
    def update_mtu(self,value):
        if value<MIN_MTU:raise ValueError("MTU below supported minimum")
        self._path_mtu=value;self._history.append((time.time(),value))
    def total_overhead(self,ipv6=False):return (IPV6_HEADER_SIZE if ipv6 else IPV4_HEADER_SIZE)+UDP_HEADER_SIZE+DATA_FRAME_OVERHEAD
    def max_payload_size(self,ipv6=False):return self.path_mtu-self.total_overhead(ipv6)
    def tcp_mss_clamp(self,ipv6=False):return self.max_payload_size(ipv6)-(40 if ipv6 else 40)
    @property
    def mtu_history(self):return list(self._history)
    def get_info(self):
        return {"path_mtu":self.path_mtu,"max_payload_ipv4":self.max_payload_size(False),"max_payload_ipv6":self.max_payload_size(True),"tcp_mss_ipv4":self.tcp_mss_clamp(False),"tcp_mss_ipv6":self.tcp_mss_clamp(True),"total_overhead_ipv4":self.total_overhead(False),"total_overhead_ipv6":self.total_overhead(True),"history_count":len(self._history)}

@dataclass
class QualitySnapshot:
    timestamp:float;rtt_ms:float;jitter_ms:float;loss_rate:float;probes_sent:int;probes_received:int
    def to_dict(self):return {"timestamp":round(self.timestamp,3),"rtt_ms":round(self.rtt_ms,3),"jitter_ms":round(self.jitter_ms,3),"loss_rate":round(self.loss_rate,4),"probes_sent":self.probes_sent,"probes_received":self.probes_received}
class NetworkQualityMonitor:
    def __init__(self,window_size=100):self._window_size=window_size;self.samples=deque(maxlen=window_size);self._jitter=0.;self._last=None;self.sent=0;self.received=0;self.lost=0
    @property
    def window_size(self):return self._window_size
    @property
    def rtt_samples(self):return list(self.samples)
    @property
    def avg_rtt(self):return statistics.mean(self.samples) if self.samples else 0.
    @property
    def min_rtt(self):return min(self.samples) if self.samples else 0.
    @property
    def max_rtt(self):return max(self.samples) if self.samples else 0.
    @property
    def jitter(self):return self._jitter
    @property
    def loss_rate(self):return self.lost/self.sent if self.sent else 0.
    def record_probe_sent(self):self.sent+=1
    def record_rtt(self,value):
        if value<0:raise ValueError("RTT cannot be negative")
        self.samples.append(value);self.received+=1
        if self._last is not None:self._jitter+=(abs(value-self._last)-self._jitter)/16
        self._last=value
    def record_loss(self):self.lost+=1
    def snapshot(self):return QualitySnapshot(time.time(),statistics.mean(self.samples) if self.samples else 0.,self._jitter,self.lost/self.sent if self.sent else 0.,self.sent,self.received)
    def reset(self):self.samples.clear();self._jitter=0.;self._last=None;self.sent=0;self.received=0;self.lost=0
    def get_info(self):return {"window_size":self.window_size,"sample_count":len(self.samples),"avg_rtt_ms":round(self.avg_rtt,3),"min_rtt_ms":round(self.min_rtt,3),"max_rtt_ms":round(self.max_rtt,3),"jitter_ms":round(self.jitter,3),"loss_rate":round(self.loss_rate,4),"probes_sent":self.sent,"probes_received":self.received}
# IPv6 leak policy and temporary client firewall

import ipaddress
import json
import logging
import secrets
import subprocess

logger = logging.getLogger("pqvpn.network")


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
