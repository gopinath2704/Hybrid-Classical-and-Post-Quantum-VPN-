import socket,subprocess,threading,time
from pathlib import Path
from types import SimpleNamespace
import pytest
import vpn.runtime as runtime
from vpn.config import ClientConfig,ServerConfig,load_client_config,load_server_config
from vpn.engine import TUNMode

class Tun:
    name="pqvpn0";mode=TUNMode.NATIVE;mtu=1380
    def __init__(self):self.closed=False
    def close(self):self.closed=True

def test_exact_previous_route_restoration(monkeypatch):
    calls=[]
    def ip(*args,check=True):
        calls.append(args)
        if args[:2]==("route","get"):return SimpleNamespace(stdout="8.8.8.8 via 192.0.2.1 dev eth0\n")
        if args[:4]==("route","show","exact","8.8.8.8/32"):return SimpleNamespace(stdout="8.8.8.8 via 192.0.2.254 dev eth9 metric 77\n")
        if args[:3]==("route","show","exact"):return SimpleNamespace(stdout="")
        return SimpleNamespace(stdout="")
    monkeypatch.setattr(runtime,"run_ip",ip);monkeypatch.setattr(runtime.subprocess,"run",lambda *a,**k:SimpleNamespace(returncode=1))
    network=runtime.ClientNetwork(Tun(),"8.8.8.8",True,[],[]);network.apply();network.restore()
    assert ("route","replace","8.8.8.8","via","192.0.2.254","dev","eth9","metric","77") in calls

def test_route_apply_failure_rolls_back(monkeypatch):
    calls=[]
    def ip(*args,check=True):
        calls.append(args)
        if args[:2]==("route","get"):return SimpleNamespace(stdout="8.8.8.8 via 192.0.2.1 dev eth0\n")
        if args[:3]==("route","show","exact"):return SimpleNamespace(stdout="")
        if args[:3]==("route","replace","0.0.0.0/1"):raise subprocess.CalledProcessError(2,args)
        return SimpleNamespace(stdout="")
    monkeypatch.setattr(runtime,"run_ip",ip);monkeypatch.setattr(runtime.subprocess,"run",lambda *a,**k:SimpleNamespace(returncode=1))
    with pytest.raises(subprocess.CalledProcessError):runtime.ClientNetwork(Tun(),"8.8.8.8",True,[],[]).apply()
    assert any(call[:3]==("route","del","8.8.8.8/32") for call in calls)

def test_partial_dns_failure_always_reverts(monkeypatch):
    commands=[]
    def ip(*args,check=True):
        if args[:2]==("route","get"):return SimpleNamespace(stdout="8.8.8.8 via 192.0.2.1 dev eth0\n")
        return SimpleNamespace(stdout="")
    def process(command,**kwargs):
        commands.append(command)
        if command[:2]==["resolvectl","domain"]:raise subprocess.CalledProcessError(1,command)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(runtime,"run_ip",ip);monkeypatch.setattr(runtime.subprocess,"run",process)
    with pytest.raises(subprocess.CalledProcessError):runtime.ClientNetwork(Tun(),"8.8.8.8",True,[],["1.1.1.1"]).apply()
    assert ["resolvectl","revert","pqvpn0"] in commands

def test_udp_bind_failure_cleans_every_resource(monkeypatch,tmp_path):
    class Session:
        def __init__(self):self.wiped=False
        def decrypt_control(self,*_):return None,b'{"server_vpn_ip":"10.8.0.1","client_vpn_ip":"10.8.0.2","prefix":24,"mtu":1380,"dns":[],"udp_port":51820}'
        def encrypt_frame(self,*_):return b"bind"
        def secure_wipe(self):self.wiped=True
    session=Session();tun=Tun()
    class Handshake:
        def __init__(self,*_):pass
        def initiate_handshake(self):return b"ch"
        def process_server_hello(self,_):return b"cke"
        def process_server_finished(self,_):return session
    class Control:
        closed=False
        def settimeout(self,_):pass
        def close(self):self.closed=True
    control=Control()
    class UDP:
        closed=False
        def bind(self,_):pass
        def settimeout(self,_):pass
        def sendto(self,*_):pass
        def recvfrom(self,_):raise socket.timeout()
        def close(self):self.closed=True
    udp=UDP()
    class Network:
        restored=False
        def apply(self):pass
        def restore(self):self.restored=True
    network=Network()
    monkeypatch.setattr(Path,"read_bytes",lambda _:b"x"*1184);monkeypatch.setattr(runtime,"load_client_private",lambda _:object())
    monkeypatch.setattr(runtime,"KEMTLSClient",Handshake);monkeypatch.setattr(runtime.socket,"create_connection",lambda *_args,**_kwargs:control)
    monkeypatch.setattr(runtime,"send_message",lambda *_:None);monkeypatch.setattr(runtime,"recv_message",lambda _:b"record")
    monkeypatch.setattr(runtime,"open_tun",lambda *_:tun);monkeypatch.setattr(runtime,"configure_tun",lambda *_:None)
    monkeypatch.setattr(runtime,"ClientNetwork",lambda *_:network);monkeypatch.setattr(runtime.socket,"socket",lambda *_:udp);monkeypatch.setattr(runtime.socket,"gethostbyname",lambda _:"192.0.2.1")
    client=runtime.VPNClient(ClientConfig())
    with pytest.raises(socket.timeout):client.connect()
    assert tun.closed and udp.closed and control.closed and network.restored and session.wiped
    assert client.tun is client.udp is client.control is client.session is None

def test_config_paths_resolve_from_toml_not_cwd(monkeypatch,tmp_path):
    server_file=tmp_path/"server.toml";server_file.write_text('[server]\nserver_identity_private_key="server.key"\nserver_identity_public_key="server.pub"\nauthorized_clients_file="clients.json"\n')
    client_file=tmp_path/"client.toml";client_file.write_text('[client]\nserver_identity_public_key="server.pub"\nclient_identity_private_key="client.key"\n')
    monkeypatch.chdir("/");server=load_server_config(server_file);client=load_client_config(client_file)
    assert server.server_identity_private_key==str(tmp_path/"server.key")
    assert server.authorized_clients_file==str(tmp_path/"clients.json")
    assert client.server_identity_public_key==str(tmp_path/"server.pub")
    assert client.client_identity_private_key==str(tmp_path/"client.key")

def test_omitted_identity_paths_resolve_beside_toml(monkeypatch,tmp_path):
    server_file=tmp_path/'server.toml';server_file.write_text('[server]\n')
    client_file=tmp_path/'client.toml';client_file.write_text('[client]\n')
    monkeypatch.chdir('/')
    server=load_server_config(server_file);client=load_client_config(client_file)
    assert server.server_identity_private_key==str(tmp_path/'server_identity_private.key')
    assert server.server_identity_public_key==str(tmp_path/'server_identity_public.key')
    assert server.authorized_clients_file==str(tmp_path/'authorized_clients.json')
    assert client.server_identity_public_key==str(tmp_path/'server_identity_public.key')
    assert client.client_identity_private_key==str(tmp_path/'client_identity_private.key')
