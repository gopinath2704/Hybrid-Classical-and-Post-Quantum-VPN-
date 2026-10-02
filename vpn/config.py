"""TOML configuration models with deployment-safe defaults."""
from __future__ import annotations
import tomllib
import ipaddress
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

_VALID_SUITES = {"v2-ed25519", "v3-kem", "v3-mldsa"}

@dataclass
class ServerConfig:
    listen_host:str="0.0.0.0"; control_port:int=51820; udp_port:int=51820
    vpn_subnet:str="10.8.0.0/24"; server_vpn_ip:str="10.8.0.1"; tun_name:str="pqvpn0"; mtu:int=1380
    outbound_interface:str=""; dns_servers:list[str]=field(default_factory=lambda:["1.1.1.1","9.9.9.9"])
    max_clients:int=64; handshake_timeout:int=10; idle_timeout:int=300; session_timeout:int=86400; rekey_interval:int=3600; rehandshake_interval:int=0
    connections_per_source:int=10; rate_limit_window:float=60.0
    server_identity_private_key:str="config/server_identity_private.key"; server_identity_public_key:str="config/server_identity_public.key"
    authorized_clients_file:str="config/authorized_clients.json"
    protocol_version:int=2
    cookie_mode:str="off"
    cookie_threshold:int=10
    dev_emulated_tun:bool=False
    allowed_forward_networks:list[str]=field(default_factory=list)
    allow_server_ping:bool=True
    manage_ip_forward:bool=True
    service_user:str="pqvpn"
    experimental_suite:str=""
@dataclass
class ClientConfig:
    server_host:str="127.0.0.1"; server_control_port:int=51820
    server_identity_public_key:str="config/server_identity_public.key"; server_identity_fingerprint:str=""
    client_identity_private_key:str="config/client_identity_private.key"
    client_identity_public_key:str="config/client_identity_public.key"
    protocol_version:int=2
    full_tunnel:bool=True
    split_tunnel:list[str]=field(default_factory=list); dns_servers:list[str]=field(default_factory=list); kill_switch:bool=False
    tun_name:str="pqvpn0"; dev_emulated_tun:bool=False
    ping_interval:float=5.0; ping_timeout:float=4.0; dead_peer_timeout:float=30.0
    dns_mode:str="systemd-resolved"
    dns_routing_domains:list[str]=field(default_factory=list)
    expected_vpn_subnet:str="10.8.0.0/24"
    # Omitted: block in full mode, leave unrelated IPv6 alone in split mode.
    ipv6_policy:str|None=None
    experimental_suite:str=""
def _load(path, section, cls):
    config_path=Path(path).resolve()
    values=tomllib.loads(config_path.read_text(encoding="utf-8")).get(section,{})
    known={x for x in cls.__dataclass_fields__}
    unknown=set(values)-known
    if unknown: raise ValueError(f"unknown {section} config fields: {sorted(unknown)}")
    file_fields=("server_identity_private_key","server_identity_public_key","authorized_clients_file",
                 "client_identity_private_key","client_identity_public_key")
    for name in file_fields:
        if name in known:
            # Omitted paths use the standard filename next to the TOML, too.
            default = Path(cls.__dataclass_fields__[name].default).name
            value=Path(values.get(name, default))
            values[name]=str(value if value.is_absolute() else config_path.parent/value)
    cfg = cls(**values)
    (validate_server if cls is ServerConfig else validate_client)(cfg)
    return cfg
def load_server_config(path): return _load(path,"server",ServerConfig)
def load_client_config(path): return _load(path,"client",ClientConfig)


def interface_name(value: str, field_name: str = "tun_name") -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,14}", value):
        raise ValueError(f"{field_name}: expected a Linux interface name of 1-15 characters")


def number(value, name, minimum, maximum=float('inf'), integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum or (integer and not isinstance(value, int)):
        raise ValueError(f"{name}: expected {'integer' if integer else 'number'} in [{minimum}, {maximum}]")


def addresses(values, name):
    if not isinstance(values, list): raise ValueError(f"{name}: expected a list")
    for value in values:
        if not isinstance(value, str): raise ValueError(f"{name}: expected IP address strings")
        ipaddress.ip_address(value)


def validate_server(cfg: ServerConfig, *, test_ports=False) -> None:
    for name in ('control_port', 'udp_port'):
        number(getattr(cfg, name), name, 0 if test_ports else 1, 65535, True)
    network = ipaddress.IPv4Network(cfg.vpn_subnet)
    server = ipaddress.IPv4Address(cfg.server_vpn_ip)
    if network.prefixlen > 30 or server not in network or server in (network.network_address, network.broadcast_address):
        raise ValueError("server_vpn_ip: must be a usable host within an IPv4 subnet with client capacity")
    number(cfg.max_clients, 'max_clients', 1, network.num_addresses - 3, True)
    interface_name(cfg.tun_name)
    if cfg.outbound_interface: interface_name(cfg.outbound_interface, 'outbound_interface')
    number(cfg.mtu, 'mtu', 576, 1400, True)
    for name in ('handshake_timeout', 'idle_timeout', 'session_timeout', 'rate_limit_window'):
        number(getattr(cfg, name), name, .001)
    if cfg.session_timeout <= cfg.idle_timeout: raise ValueError('session_timeout must exceed idle_timeout')
    number(cfg.rekey_interval, 'rekey_interval', 0, 86400, True)
    number(cfg.connections_per_source, 'connections_per_source', 1, integer=True)
    addresses(cfg.dns_servers, 'dns_servers')
    if not isinstance(cfg.allowed_forward_networks, list): raise ValueError('allowed_forward_networks must be a list')
    for cidr in cfg.allowed_forward_networks: ipaddress.IPv4Network(cidr)
    for name in ('manage_ip_forward', 'allow_server_ping', 'dev_emulated_tun'):
        if type(getattr(cfg, name)) is not bool: raise ValueError(f'{name} must be boolean')
    if not isinstance(cfg.service_user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]*', cfg.service_user):
        raise ValueError('service_user must be a valid account name')
    if not isinstance(cfg.listen_host, str) or not cfg.listen_host: raise ValueError('listen_host must be nonempty')
    if cfg.protocol_version not in (2, 3): raise ValueError('protocol_version must be 2 or 3')
    if cfg.cookie_mode not in ('off', 'under_load', 'always'): raise ValueError('cookie_mode must be off, under_load, or always')
    number(cfg.cookie_threshold, 'cookie_threshold', 1, integer=True)
    if cfg.experimental_suite and cfg.experimental_suite not in _VALID_SUITES:
        raise ValueError(f'experimental_suite must be one of {sorted(_VALID_SUITES)} or empty')


def validate_client(cfg: ClientConfig) -> None:
    if cfg.ipv6_policy is not None and cfg.ipv6_policy not in ('block', 'fail', 'allow'):
        raise ValueError('ipv6_policy must be block, fail or allow')
    number(cfg.server_control_port, 'server_control_port', 1, 65535, True)
    interface_name(cfg.tun_name)
    for name in ('ping_interval', 'ping_timeout', 'dead_peer_timeout'):
        number(getattr(cfg, name), name, .05, 3600)
    if cfg.dead_peer_timeout <= max(cfg.ping_interval, cfg.ping_timeout):
        raise ValueError('dead_peer_timeout must exceed ping_interval and ping_timeout')
    if cfg.dns_mode not in ('systemd-resolved', 'none'): raise ValueError('dns_mode must be systemd-resolved or none')
    addresses(cfg.dns_servers, 'dns_servers')
    ipaddress.IPv4Network(cfg.expected_vpn_subnet)
    if not isinstance(cfg.split_tunnel, list): raise ValueError('split_tunnel must be a list')
    for route in cfg.split_tunnel: ipaddress.IPv4Network(route)
    if not isinstance(cfg.dns_routing_domains, list): raise ValueError('dns_routing_domains must be a list')
    for domain in cfg.dns_routing_domains:
        if not isinstance(domain, str) or not re.fullmatch(r'~?[a-zA-Z0-9][a-zA-Z0-9.-]*|~\.', domain):
            raise ValueError('invalid DNS routing domain')
    for name in ('full_tunnel', 'kill_switch', 'dev_emulated_tun'):
        if type(getattr(cfg, name)) is not bool: raise ValueError(f'{name} must be boolean')
    if cfg.protocol_version not in (2, 3): raise ValueError('protocol_version must be 2 or 3')
    if cfg.experimental_suite and cfg.experimental_suite not in _VALID_SUITES:
        raise ValueError(f'experimental_suite must be one of {sorted(_VALID_SUITES)} or empty')
