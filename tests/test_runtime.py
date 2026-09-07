import pytest
from vpn.runtime import IPPool,validate_client_packet
from vpn.config import ServerConfig,ClientConfig
from handshake.kemtls import DATA_FRAME_OVERHEAD
from vpn.engine import MTUMonitor

def test_ip_pool_allocation_release():
    p=IPPool("10.8.0.0/29","10.8.0.1");a=p.allocate("a");b=p.allocate("b");assert a!=b and a!="10.8.0.1";p.release("a");assert p.allocate("c")==a
def test_static_ip_duplicate_prevention():
    p=IPPool("10.8.0.0/29","10.8.0.1");assert p.allocate("a","10.8.0.5")=="10.8.0.5"
    with pytest.raises(ValueError):p.allocate("b","10.8.0.5")
@pytest.mark.parametrize("address",["10.8.0.0","10.8.0.1","10.8.0.7","8.8.8.8","not-an-ip"])
def test_invalid_preferred_ip_rejected(address):
    p=IPPool("10.8.0.0/29","10.8.0.1")
    with pytest.raises(ValueError):p.allocate("a",address)
def ipv4(source,destination="1.1.1.1",payload=b""):
    import ipaddress,struct
    total=20+len(payload)
    return b"\x45\x00"+struct.pack("!H",total)+b"\0"*8+ipaddress.IPv4Address(source).packed+ipaddress.IPv4Address(destination).packed+payload
def test_inner_source_validation():
    assert validate_client_packet(ipv4("10.8.0.2"),"10.8.0.2")
    assert not validate_client_packet(ipv4("10.8.0.3"),"10.8.0.2")
    assert not validate_client_packet(ipv4("8.8.8.8"),"10.8.0.2")
    assert not validate_client_packet(b"malformed","10.8.0.2")
    assert not validate_client_packet(b"\x60"+b"\0"*39,"10.8.0.2")
@pytest.mark.parametrize("path_mtu",[1500,1400,1280])
def test_mtu_safe_datagram(path_mtu):
    monitor=MTUMonitor(path_mtu);tun_mtu=monitor.max_payload_size(False);assert tun_mtu+DATA_FRAME_OVERHEAD+28<=path_mtu
@pytest.mark.parametrize("path_mtu",[1500,1400,1280])
def test_ipv6_mtu_safe_datagram(path_mtu):
    monitor=MTUMonitor(path_mtu);tun_mtu=monitor.max_payload_size(True);assert tun_mtu+DATA_FRAME_OVERHEAD+48<=path_mtu
def test_configuration_defaults_are_safe():
    s=ServerConfig();assert not s.dev_emulated_tun and s.max_clients>0 and s.connections_per_source>0
    c=ClientConfig();assert not c.dev_emulated_tun and c.full_tunnel
