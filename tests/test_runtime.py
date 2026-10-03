import json
import pytest
from vpn.runtime import IPPool,validate_client_packet
from vpn.config import ServerConfig,ClientConfig
from handshake.kemtls import DATA_FRAME_OVERHEAD
from vpn.network import MTUMonitor

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
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
import vpn.runtime as runtime
from handshake.kemtls import FrameType, HandshakeError
from vpn.config import ClientConfig
from test_crypto_protocol import exchange


def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(): return
        time.sleep(.01)
    assert predicate()


def test_sigterm_cli_exits(tmp_path):
    # Exercise the real CLI signal handler/main loop in a fresh process.
    script = '''
import threading
from unittest.mock import patch
import vpn.cli as cli
class Client:
    def __init__(self, cfg): self.stop_event=threading.Event()
    def connect(self): return {"client_vpn_ip":"10.8.0.2","udp_port":51820}
    def disconnect(self): print("cleaned", flush=True)
with patch.object(cli,"VPNClient",Client), patch.object(cli,"load_client_config"), patch.object(cli,"get_crypto_status",return_value={"is_quantum_safe":True}):
    cli.main()
'''
    proc = subprocess.Popen([sys.executable, '-u', '-c', script, 'client', 'connect'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        import select
        assert select.select([proc.stdout], [], [], 5)[0]
        deadline = time.monotonic() + 5
        while 'connected:' not in proc.stdout.readline():
            assert time.monotonic() < deadline
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, err
        assert 'cleaned' in out
    finally:
        if proc.poll() is None: proc.kill(); proc.wait()


@pytest.mark.parametrize('ending', ['eof', 'close', 'error', 'invalid'])
def test_control_loss_restores_resources(identities, ending):
    cs, ss = exchange(identities)
    client = runtime.VPNClient(ClientConfig())
    client.session = cs
    client.control, peer = socket.socketpair()
    network, tun, udp = Mock(), Mock(), Mock()
    client.network, client.tun, client.udp = network, tun, udp
    client.state = 'CONNECTED'
    thread = threading.Thread(target=client._control_loop)
    client._control_thread = thread
    thread.start()
    if ending == 'eof': peer.close()
    else:
        record = b'invalid' if ending == 'invalid' else ss.encrypt_control(b'operational reason', FrameType.CLOSE if ending == 'close' else FrameType.ERROR)
        runtime.send_message(peer, record)
    thread.join(4)
    assert not thread.is_alive()
    assert client.state == 'FAILED' and client.error
    network.restore.assert_called_once()
    tun.close.assert_called_once()
    udp.close.assert_called_once()
    assert client.session is client.control is None
    peer.close()


def test_delayed_rekey_keeps_data_forwarding(identities):
    cs, ss = exchange(identities)
    client = runtime.VPNClient(ClientConfig())
    client.session = cs
    client.control, peer = socket.socketpair()
    client.tun = runtime.open_tun('test', 1380, True)
    client.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.udp.bind(('127.0.0.1', 0))
    remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    remote.bind(('127.0.0.1', 0)); remote.settimeout(2)
    client.server_udp = remote.getsockname()
    client.tunnel = {'mtu':1380, 'rekey_interval':100, 'client_vpn_ip':'10.8.0.2'}
    client.next_rekey = time.monotonic()
    client._thread = threading.Thread(target=client._loop)
    client._control_thread = threading.Thread(target=client._control_loop)
    client._scheduler_thread = threading.Thread(target=client._schedule_rekey)
    for thread in (client._thread, client._control_thread, client._scheduler_thread): thread.start()
    try:
        _, payload = ss.decrypt_control(runtime.recv_message(peer), FrameType.REKEY_REQUEST)
        # Hold the authenticated response until both directions have forwarded DATA.
        for i in range(8):
            from test_runtime import ipv4
            packet = ipv4('1.1.1.1', '10.8.0.2', f'data-{i}'.encode())
            client.tun.inject(packet)
            data, endpoint = remote.recvfrom(4096)
            assert ss.decrypt_frame(data)[1] == packet
            remote.sendto(ss.encrypt_frame(packet), endpoint)
            import select
            assert select.select([client.tun._sock_remote], [], [], 2)[0]
            assert client.tun.drain() == packet
        import hashlib, hmac, struct
        epoch = struct.unpack('!I', payload[:4])[0]
        keys = ss.derive_next_epoch(epoch, payload[4:])
        confirmation = hmac.new(bytes(ss.secrets.control_confirm_key), b'rekey response'+payload, hashlib.sha256).digest()
        runtime.send_message(peer, ss.encrypt_control(payload[:4]+confirmation, FrameType.REKEY_RESPONSE))
        ss.activate_epoch(epoch, keys)
        until(lambda: cs.epoch == 1)
    finally:
        client.disconnect(); peer.close(); remote.close()


@pytest.mark.parametrize('lock_name', ['_data_send_lock', '_data_receive_lock', '_control_send_lock', '_control_receive_lock'])
def test_wipe_waits_for_active_record(identities, lock_name):
    client, server = exchange(identities)
    lock = getattr(client, lock_name)
    lock.acquire()
    done = threading.Event()
    worker = threading.Thread(target=lambda: (client.secure_wipe(), done.set()))
    worker.start()
    assert not done.wait(.05)
    lock.release(); worker.join(2)
    assert done.is_set()
    with pytest.raises(HandshakeError, match='closed'): client.encrypt_frame(b'after wipe')


def test_rate_limiter_prunes_sources():
    limiter = runtime.SourceRateLimiter(2, 10)
    for i in range(1000): assert limiter.allow(str(i), 0)
    assert limiter.allow('new', 11)
    assert list(limiter.events) == ['new']


def test_server_ip_pinned_for_all_paths(monkeypatch):
    import json
    calls = []
    addresses = iter(['192.0.2.10', '192.0.2.20', '192.0.2.30'])
    def resolve(host): calls.append(host); return next(addresses)
    monkeypatch.setattr(runtime.socket, 'gethostbyname', resolve)
    control, udp, tun, session = Mock(), Mock(), Mock(), Mock()
    info = {'server_vpn_ip':'10.8.0.1', 'client_vpn_ip':'10.8.0.2','prefix':24,'mtu':1380,'dns':[], 'udp_port':51820}
    session.decrypt_control.return_value = (FrameType.CONFIG, json.dumps(info).encode())
    session.encrypt_frame.return_value = b'bind'
    session.decrypt_frame.return_value = (FrameType.UDP_BIND_ACK, b'ok')
    udp.recvfrom.return_value = (b'ack', ('192.0.2.10',51820))
    handshake = Mock()
    handshake.process_server_finished.return_value = session
    monkeypatch.setattr(runtime, 'KEMTLSClient', Mock(return_value=handshake))
    monkeypatch.setattr(Path, 'read_bytes', lambda _: b'key')
    monkeypatch.setattr(runtime, 'load_client_private', Mock())
    connection = Mock(return_value=control)
    monkeypatch.setattr(runtime.socket, 'create_connection', connection)
    monkeypatch.setattr(runtime.socket, 'socket', Mock(return_value=udp))
    monkeypatch.setattr(runtime, 'send_message', Mock())
    monkeypatch.setattr(runtime, 'recv_message', Mock(return_value=b'record'))
    monkeypatch.setattr(runtime, 'open_tun', Mock(return_value=tun))
    monkeypatch.setattr(runtime, 'configure_tun', Mock())
    network = Mock()
    monkeypatch.setattr(runtime, 'ClientNetwork', network)
    monkeypatch.setattr(runtime.threading, 'Thread', Mock())
    client = runtime.VPNClient(ClientConfig(server_host='round-robin.example'))
    client.connect()
    assert calls == ['round-robin.example']
    assert connection.call_args.args[0] == ('192.0.2.10',51820)
    assert network.call_args.args[1] == '192.0.2.10'
    assert client.server_udp == ('192.0.2.10',51820)
    client.disconnect()


def test_compose_profile_and_secret_paths():
    compose = Path('docker-compose.yml').read_text()
    assert 'SERVER_HOST=' not in compose and '/app/config/' not in compose
    assert './config/client.toml:/etc/pqvpn/client.toml:ro' in compose
    assert '"--server-host", "vpn-server"' in compose
    assert compose.count('dockerfile: Dockerfile') == 2
    for name in ['server_identity_private.key','server_identity_public.key','authorized_clients.json','client_identity_private.key']:
        assert f'./config/{name}:/etc/pqvpn/{name}:ro' in compose


def test_setup_uses_nondefault_toml(tmp_path):
    from vpn.config import load_server_config
    from vpn.network import render
    config = tmp_path/'server.toml'
    config.write_text('[server]\nvpn_subnet="10.50.0.0/24"\nserver_vpn_ip="10.50.0.1"\ntun_name="shadowvpn0"\noutbound_interface="uplink0"\n')
    cfg = load_server_config(config)
    rules = render(cfg, cfg.outbound_interface)
    assert '10.50.0.0/24' in rules and 'shadowvpn0' in rules and 'uplink0' in rules
    assert '10.8.0.0/24' not in rules
    assert 'server-network.sh setup /etc/pqvpn/server.toml' in Path('packaging/common/pqvpn-server.service').read_text()


def test_server_session_timeout_disconnects_client(tmp_path):
    from vpn.config import ServerConfig
    from vpn.identity import generate_server_identity, generate_client_identity, AuthorizedClients
    fp = generate_server_identity(tmp_path/'server.key',tmp_path/'server.pub',allow_mock=True)
    generate_client_identity(tmp_path/'client.key',tmp_path/'client.pub')
    AuthorizedClients(tmp_path/'clients.json').authorize((tmp_path/'client.pub').read_bytes(), 'test-client')
    server = runtime.VPNServer(ServerConfig(listen_host='127.0.0.1',control_port=0,udp_port=0,
        server_identity_private_key=str(tmp_path/'server.key'),server_identity_public_key=str(tmp_path/'server.pub'),
        authorized_clients_file=str(tmp_path/'clients.json'),dev_emulated_tun=True,idle_timeout=.5,session_timeout=1))
    worker = threading.Thread(target=server.start)
    worker.start()
    client = None
    try:
        until(lambda: server.tcp is not None and server.udp is not None)
        server.cfg.udp_port = server.udp.getsockname()[1]
        client = runtime.VPNClient(ClientConfig(server_host='127.0.0.1', server_control_port=server.tcp.getsockname()[1],
            server_identity_public_key=str(tmp_path/'server.pub'), server_identity_fingerprint=fp,
            client_identity_private_key=str(tmp_path/'client.key'), dev_emulated_tun=True))
        client.PING_INITIAL_DELAY = .1
        client.PING_INTERVAL = .1
        client.connect()
        network = client.network
        network.restore = Mock(wraps=network.restore)
        assert client.state == 'CONNECTED'
        until(lambda: client._cleanup_done.is_set(), 5)
        assert client.state == 'FAILED' and client.session is None
        network.restore.assert_called_once()
    finally:
        if client: client.disconnect()
        server.stop(); worker.join(3)
    assert not worker.is_alive()


def test_client_status_serialization_and_real_schema():
    from app.client import ClientStatus, ConnectionState
    status = ClientStatus(
        state=ConnectionState.FAILED.value,
        error='control channel lost',
        client_vpn_ip='10.8.0.2',
        epoch=5,
        rtt_ms=1.5,
        jitter_ms=0.3,
        loss_rate=0.01,
        mtu=1380,
        pqc_mode='native',
        tun_mode='NATIVE',
        rekey_countdown=3500.0,
    )
    data = json.loads(status.to_json())
    assert data['state'] == 'FAILED'
    assert data['error'] == 'control channel lost'
    assert {'client_vpn_ip','epoch','rtt_ms','jitter_ms','loss_rate','mtu','pqc_mode','tun_mode','rekey_countdown'} <= data.keys()
    # Round-trip
    restored = ClientStatus.from_json(status.to_json())
    assert restored.state == 'FAILED' and restored.error == 'control channel lost'
    assert restored.epoch == 5


def test_rate_limiter_caps_unique_sources():
    limiter = runtime.SourceRateLimiter(max_sources=2)
    assert limiter.allow('a',0) and limiter.allow('b',0)
    assert not limiter.allow('c',0)
    assert limiter.allow('c',61)
import socket,threading,time
from types import SimpleNamespace
import pytest
import vpn.runtime as runtime
from vpn.config import ServerConfig,ClientConfig
from handshake.kemtls import HandshakeError

class FakeTun:
    name="pqvpn0";mtu=1380;closed=False
    def close(self):self.closed=True

class FakeSocket:
    def __init__(self):self.closed=False
    def bind(self,_):pass
    def setblocking(self,_):pass
    def setsockopt(self,*_):pass
    def listen(self,_):pass
    def settimeout(self,_):pass
    def accept(self):
        if self.closed:raise OSError(9,"closed")
        time.sleep(.005);raise socket.timeout()
    def close(self):self.closed=True

def test_graceful_server_stop_has_no_exception(monkeypatch,tmp_path):
    secret=tmp_path/"server.key";public=tmp_path/"server.pub";clients=tmp_path/"clients.json"
    from vpn.identity import generate_server_identity
    generate_server_identity(secret, public, allow_mock=True)
    clients.write_text('{"clients":[]}')
    cfg=ServerConfig(server_identity_private_key=str(secret),server_identity_public_key=str(public),authorized_clients_file=str(clients),dev_emulated_tun=True)
    tun=FakeTun();sockets=[]
    monkeypatch.setattr(runtime,"open_tun",lambda *_:tun);monkeypatch.setattr(runtime,"configure_tun",lambda *_:None)
    def make_socket(*_):value=FakeSocket();sockets.append(value);return value
    monkeypatch.setattr(runtime.socket,"socket",make_socket)
    server=runtime.VPNServer(cfg);server._data_loop=lambda:server.stop_event.wait()
    failures=[]
    def run():
        try:server.start()
        except Exception as exc:failures.append(exc)
    thread=threading.Thread(target=run);thread.start();time.sleep(.03);server.stop();thread.join(2)
    assert not thread.is_alive() and not failures and tun.closed and all(item.closed for item in sockets)

def test_source_rate_limiter_window():
    limiter=runtime.SourceRateLimiter(2,10);assert limiter.allow("a",0) and limiter.allow("a",1);assert not limiter.allow("a",2);assert limiter.allow("a",11)

def test_automatic_rekey_short_interval(monkeypatch):
    client=runtime.VPNClient(ClientConfig());client.tunnel={"rekey_interval":1};client.next_rekey=5;calls=[];monkeypatch.setattr(client,"rekey",lambda:calls.append("rekey"))
    assert not client._maybe_auto_rekey(4.9);assert client._maybe_auto_rekey(5);assert calls==["rekey"] and client.next_rekey==6

def test_overlapping_rekey_rejected():
    client=runtime.VPNClient(ClientConfig());client._rekey_lock.acquire()
    try:
        with pytest.raises(HandshakeError,match="already"):client.rekey()
    finally:client._rekey_lock.release()

def test_client_rekey_protocol_uses_control_domain(monkeypatch,identities):
    import hashlib,hmac,struct
    from test_crypto_protocol import exchange
    from handshake.kemtls import FrameType
    client_session,server_session=exchange(identities);client=runtime.VPNClient(ClientConfig());client.session=client_session;client.control=object();responses=[]
    def send(_,frame):
        typ,payload=server_session.decrypt_control(frame,FrameType.REKEY_REQUEST);epoch=struct.unpack("!I",payload[:4])[0];keys=server_session.derive_next_epoch(epoch,payload[4:])
        confirmation=hmac.new(bytes(server_session.secrets.control_confirm_key),b"rekey response"+payload,hashlib.sha256).digest()
        responses.append(server_session.encrypt_control(payload[:4]+confirmation,FrameType.REKEY_RESPONSE));server_session.activate_epoch(epoch,keys)
    monkeypatch.setattr(runtime,"send_message",send);monkeypatch.setattr(runtime,"recv_message",lambda _:responses.pop())
    client.rekey();assert client_session.epoch==server_session.epoch==1
    assert server_session.decrypt_frame(client_session.encrypt_frame(b"after"))[1]==b"after"
"""Authenticated quiet-session liveness and rejection/expiry regressions."""
import os
import struct
import threading
import time
from unittest.mock import Mock

import pytest
import vpn.runtime as runtime
from handshake.kemtls import FrameType
from vpn.config import ClientConfig, ServerConfig
from vpn.identity import AuthorizedClients, generate_client_identity, generate_server_identity
from test_crypto_protocol import exchange


@pytest.fixture
def connected(tmp_path):
    native = os.environ.get('PQVPN_TEST_NATIVE_TUN') == '1'
    previous_routes = runtime.run_ip('route', 'show').stdout if native else None
    fp = generate_server_identity(tmp_path/'server.key', tmp_path/'server.pub', allow_mock=True)
    generate_client_identity(tmp_path/'client.key', tmp_path/'client.pub')
    AuthorizedClients(tmp_path/'clients.json').authorize((tmp_path/'client.pub').read_bytes(), 'idle-test')
    server = runtime.VPNServer(ServerConfig(listen_host='127.0.0.1', control_port=51831 if native else 0, udp_port=51832 if native else 0,
        server_identity_private_key=str(tmp_path/'server.key'), server_identity_public_key=str(tmp_path/'server.pub'),
        authorized_clients_file=str(tmp_path/'clients.json'), dev_emulated_tun=not native, tun_name="pqidle0", dns_servers=[], idle_timeout=2, rekey_interval=0))
    worker = threading.Thread(target=server.start)
    worker.start()
    client = None
    try:
        until(lambda: server._data_thread is not None and server._data_thread.is_alive())
        server.cfg.udp_port = server.udp.getsockname()[1]
        client = runtime.VPNClient(ClientConfig(server_host='127.0.0.1', server_control_port=server.tcp.getsockname()[1],
            server_identity_public_key=str(tmp_path/'server.pub'), server_identity_fingerprint=fp,
            client_identity_private_key=str(tmp_path/'client.key'), dev_emulated_tun=not native, tun_name='pqidle1', full_tunnel=False))
        # Inject intervals without changing the deployed defaults.
        client.PING_INITIAL_DELAY = .1
        client.PING_INTERVAL = .3
        yield server, client
    finally:
        if client: client.disconnect()
        server.stop()
        worker.join(4)
        assert not worker.is_alive()
        if native:
            assert runtime.run_ip("route", "show").stdout == previous_routes


def test_authenticated_keepalive_prevents_idle_expiry(connected):
    server, client = connected
    client.connect()
    item = next(iter(server.sessions.by_id.values()))
    start = item.last_seen
    # Real encrypted PING/PONG, real TCP/UDP, no TUN DATA or rekey activity.
    pong = Mock(wraps=client.quality.record_rtt)
    client.quality.record_rtt = pong
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert client.state == 'CONNECTED'
        assert server.sessions.by_id.get(item.crypto.session_id[:8]) is item
        time.sleep(.05)
    assert item.last_seen > start + server.cfg.idle_timeout
    assert pong.call_count >= 5
    count = pong.call_count
    until(lambda: pong.call_count > count)


def test_genuinely_idle_session_expires_and_cleans_up(connected, caplog, monkeypatch):
    server, client = connected
    client.PING_INITIAL_DELAY = 3600
    client.connect()
    item = next(iter(server.sessions.by_id.values()))
    server_keys = item.crypto.secrets
    client_keys = client.session.secrets
    network = client.network
    network.restore = Mock(wraps=network.restore)
    # Exercise route/DNS undo on idle loss even in the unprivileged run.
    commands = []
    if client.cfg.dev_emulated_tun:
        network.route_undo.append(runtime.RouteUndo('203.0.113.0/24',
            ['203.0.113.0/24', 'dev', 'pqidle1'], [['203.0.113.0/24', 'dev', 'eth0', 'metric', '77']]))
        network.dns_cleanup_registered = True
        monkeypatch.setattr(runtime, 'run_ip', lambda *args, **kw: commands.append(args))
        monkeypatch.setattr(runtime.subprocess, 'run', lambda args, **kw: commands.append(tuple(args)))
    with caplog.at_level('INFO', logger='pqvpn.runtime'):
        until(lambda: client._cleanup_done.is_set(), 6)
    assert client.state == 'FAILED' and client.stop_event.is_set()
    assert not server.sessions.by_id and not server.sessions.by_ip
    assert item.endpoint is None and item.client_id not in server.pool._leases
    assert server.pool.allocate('replacement') == item.vpn_ip
    for keys in (server_keys, client_keys):
        for value in vars(keys).values():
            if isinstance(value, bytearray): assert not any(value)
    assert client.session is client.tun is client.control is client.udp is None
    network.restore.assert_called_once()
    assert 'session expired reason=idle timeout' in caplog.text
    if client.cfg.dev_emulated_tun:
        assert ('resolvectl', 'revert', 'pqidle1') in commands
        assert ('route', 'del', '203.0.113.0/24', 'dev', 'pqidle1') in commands
        assert ('route', 'replace', '203.0.113.0/24', 'dev', 'eth0', 'metric', '77') in commands
    assert not network.route_undo and not network.dns_cleanup_registered


@pytest.mark.parametrize('case', ['ping', 'data', 'replay', 'wrong_session', 'unknown_session',
    'wrong_endpoint', 'malformed_ping', 'bad_tag', 'truncated', 'spoof', 'malformed_data', 'old_epoch', 'control_domain', 'bad_bind'])
def test_only_authorized_current_records_touch_activity(identities, case):
    cs, ss = exchange(identities)
    server = object.__new__(runtime.VPNServer)
    server.sessions = runtime.SessionManager()
    server.udp, server.tun = Mock(), Mock(mtu=1380)
    endpoint = ('127.0.0.1', 12345)
    item = runtime.ServerSession(ss, '10.8.0.2', Mock(), 'client', endpoint, last_seen=1)
    server.sessions.add(item)
    payload = struct.pack('!d', time.monotonic())
    frame = cs.encrypt_frame(payload, FrameType.PING)
    if case == 'replay':
        server._handle_datagram(frame, endpoint)
        item.last_seen = 1
        server.udp.reset_mock()
    elif case == 'wrong_session':
        other, _ = exchange(identities)
        frame = other.encrypt_frame(payload, FrameType.PING)
        server.sessions.by_id[other.session_id[:8]] = item
    elif case == 'unknown_session':
        other, _ = exchange(identities)
        frame = other.encrypt_frame(payload, FrameType.PING)
    elif case == 'wrong_endpoint': endpoint = ('127.0.0.1', 54321)
    elif case == 'malformed_ping': frame = cs.encrypt_frame(b'bad', FrameType.PING)
    elif case == 'bad_tag': frame = frame[:-1] + bytes([frame[-1] ^ 1])
    elif case == 'truncated': frame = frame[:10]
    elif case in {'data', 'spoof', 'malformed_data'}:
        frame = cs.encrypt_frame(b'bad' if case == 'malformed_data' else ipv4('10.8.0.3' if case == 'spoof' else item.vpn_ip))
    elif case == 'old_epoch':
        ss.activate_epoch(1, ss.derive_next_epoch(1, b'n'*32))
    elif case == 'control_domain': frame = cs.encrypt_control(payload, FrameType.ERROR)
    elif case == 'bad_bind': frame = cs.encrypt_frame(b'bad', FrameType.UDP_BIND)
    server._handle_datagram(frame, endpoint)
    if case in {'ping', 'data'}:
        assert item.last_seen > 1
        if case == 'ping':
            pong, address = server.udp.sendto.call_args.args
            assert address == endpoint
            assert cs.decrypt_frame(pong, FrameType.PONG)[1] == payload
        else: server.tun.write.assert_called_once()
    else:
        assert item.last_seen == 1
        server.udp.sendto.assert_not_called()
        server.tun.write.assert_not_called()


@pytest.mark.parametrize('valid', [True, False])
def test_control_activity_is_counted_after_validation(connected, valid):
    server, client = connected
    client.PING_INITIAL_DELAY = 3600
    client.connect()
    item = next(iter(server.sessions.by_id.values()))
    before = item.last_seen
    if valid:
        client.rekey()
        until(lambda: item.last_seen > before)
        assert item.crypto.epoch == client.session.epoch == 1
    else:
        runtime.send_message(client.control, client.session.encrypt_control(b'malformed', FrameType.REKEY_REQUEST))
        until(lambda: client._cleanup_done.is_set())
        assert item.last_seen == before
        assert client.state == 'FAILED'
import time
import threading
from unittest.mock import Mock

import pytest
from handshake.kemtls import FrameType


class PongFilter:
    def __init__(self, sock): self.sock=sock; self.drop=False; self.saved=None
    def __getattr__(self,name):return getattr(self.sock,name)
    def fileno(self): return self.sock.fileno()
    def sendto(self, data, address):
        # The test captures authenticated server output, without changing crypto.
        if self.drop:
            if self.saved is None: self.saved=(data,address)
            return len(data)
        return self.sock.sendto(data,address)


@pytest.mark.parametrize('traffic', ['healthy','blackhole','data','replay','invalid'])
def test_udp_dead_peer_cleanup(connected, traffic):
    server,client=connected
    client.cfg.dead_peer_timeout=1.0
    client.cfg.ping_timeout=.2
    client.PING_INTERVAL=.15;client.PING_INITIAL_DELAY=.1
    filtered=PongFilter(server.udp);server.udp=filtered
    client.connect()
    item=next(iter(server.sessions.by_id.values()))
    network=client.network;network.restore=Mock(wraps=network.restore)
    keys=client.session.secrets
    # Confirm a PONG has been authenticated before blackholing UDP.
    before=client.last_authenticated_udp_rx
    until(lambda:client.last_authenticated_udp_rx>before)
    if traffic!='healthy':filtered.drop=True
    end=time.monotonic()+2.2
    while time.monotonic()<end and client.state=='CONNECTED':
        if traffic=='data':
            packet=ipv4('1.1.1.1',item.vpn_ip,b'valid server DATA')
            filtered.sock.sendto(item.crypto.encrypt_frame(packet),item.endpoint)
        elif traffic in ('replay','invalid') and filtered.saved:
            data,address=filtered.saved
            # First replay may be valid once; repeats cannot prolong the deadline.
            filtered.sock.sendto(data if traffic=='replay' else data[:-1]+bytes([data[-1]^1]),address)
        time.sleep(.1)
    if traffic in ('healthy','data'):
        assert client.state=='CONNECTED'
    else:
        until(lambda:client._cleanup_done.is_set(),4)
        assert client.state=='FAILED' and 'dead-peer' in client.error
        network.restore.assert_called_once()
        assert client.session is client.tun is client.udp is client.control is None
        assert all(not any(v) for v in vars(keys).values() if isinstance(v,bytearray))
        until(lambda:not server.sessions.by_id)


def test_manual_and_automatic_rekey_during_authenticated_traffic(connected):
    server,client=connected
    server.cfg.rekey_interval=1
    client.PING_INTERVAL=.2;client.PING_INITIAL_DELAY=.1
    client.connect()
    client.rekey()
    assert client.session.epoch==1
    until(lambda:client.session is not None and client.session.epoch>=3,5)
    assert client.state=='CONNECTED'
    until(lambda:next(iter(server.sessions.by_id.values())).crypto.epoch==client.session.epoch)


def test_cookie_always_mode_handshake_completes(tmp_path):
    fp = generate_server_identity(tmp_path/'server.key', tmp_path/'server.pub', allow_mock=True)
    generate_client_identity(tmp_path/'client.key', tmp_path/'client.pub')
    AuthorizedClients(tmp_path/'clients.json').authorize((tmp_path/'client.pub').read_bytes(), 'cookie-test')
    server = runtime.VPNServer(ServerConfig(listen_host='127.0.0.1', control_port=0, udp_port=0,
        server_identity_private_key=str(tmp_path/'server.key'), server_identity_public_key=str(tmp_path/'server.pub'),
        authorized_clients_file=str(tmp_path/'clients.json'), dev_emulated_tun=True,
        cookie_mode='always', idle_timeout=5, rekey_interval=0))
    worker = threading.Thread(target=server.start)
    worker.start()
    client = None
    try:
        until(lambda: server._data_thread is not None and server._data_thread.is_alive())
        server.cfg.udp_port = server.udp.getsockname()[1]
        client = runtime.VPNClient(ClientConfig(server_host='127.0.0.1',
            server_control_port=server.tcp.getsockname()[1],
            server_identity_public_key=str(tmp_path/'server.pub'), server_identity_fingerprint=fp,
            client_identity_private_key=str(tmp_path/'client.key'), dev_emulated_tun=True,
            full_tunnel=False))
        client.PING_INITIAL_DELAY = .1
        client.PING_INTERVAL = .5
        tunnel = client.connect()
        assert client.state == 'CONNECTED'
        assert tunnel['client_vpn_ip']
    finally:
        if client: client.disconnect()
        server.stop(); worker.join(3)
    assert not worker.is_alive()


def test_cookie_off_mode_no_challenge(tmp_path):
    fp = generate_server_identity(tmp_path/'server.key', tmp_path/'server.pub', allow_mock=True)
    generate_client_identity(tmp_path/'client.key', tmp_path/'client.pub')
    AuthorizedClients(tmp_path/'clients.json').authorize((tmp_path/'client.pub').read_bytes(), 'no-cookie')
    server = runtime.VPNServer(ServerConfig(listen_host='127.0.0.1', control_port=0, udp_port=0,
        server_identity_private_key=str(tmp_path/'server.key'), server_identity_public_key=str(tmp_path/'server.pub'),
        authorized_clients_file=str(tmp_path/'clients.json'), dev_emulated_tun=True,
        cookie_mode='off', idle_timeout=5, rekey_interval=0))
    assert server._cookie is None
    worker = threading.Thread(target=server.start)
    worker.start()
    client = None
    try:
        until(lambda: server._data_thread is not None and server._data_thread.is_alive())
        server.cfg.udp_port = server.udp.getsockname()[1]
        client = runtime.VPNClient(ClientConfig(server_host='127.0.0.1',
            server_control_port=server.tcp.getsockname()[1],
            server_identity_public_key=str(tmp_path/'server.pub'), server_identity_fingerprint=fp,
            client_identity_private_key=str(tmp_path/'client.key'), dev_emulated_tun=True,
            full_tunnel=False))
        client.PING_INITIAL_DELAY = .1
        client.PING_INTERVAL = .5
        tunnel = client.connect()
        assert client.state == 'CONNECTED'
    finally:
        if client: client.disconnect()
        server.stop(); worker.join(3)


def test_rehandshake_succeeds_and_advances_epoch(connected):
    server, client = connected
    client.connect()
    assert client.session.epoch == 0
    client.rehandshake()
    assert client.session.epoch == 1
    srv_item = next(iter(server.sessions.by_id.values()))
    until(lambda: srv_item.crypto.epoch == 1)
    assert client.state == 'CONNECTED'


def test_rehandshake_tampered_confirmation_fails_client(connected, monkeypatch):
    server, client = connected
    client.connect()
    original = runtime.VPNServer._rehandshake_server

    def tampered(self, item, payload):
        import struct as st
        from crypto.hybrid_crypto import HybridKEM
        epoch = st.unpack("!I", payload[:4])[0]
        hybrid = HybridKEM("ML-KEM-768")
        dh_priv, dh_pub = hybrid.ecc.generate_keypair()
        dh_ss = hybrid.ecc.derive_shared_secret(dh_priv, payload[4:36])
        ct, k = hybrid.pqc.encapsulate(payload[36:])
        body = st.pack("!I", epoch) + dh_pub + ct
        transcript = payload + body
        nk = item.crypto.derive_rehandshake_epoch(epoch, dh_ss, k, transcript)
        bad_confirm = b"\xff" * 32
        runtime.send_message(item.control, item.crypto.encrypt_control(body + bad_confirm, FrameType.REHANDSHAKE_RESPONSE))
        nk.wipe()

    monkeypatch.setattr(runtime.VPNServer, '_rehandshake_server', tampered)
    with pytest.raises(HandshakeError, match="rehandshake key confirmation failed"):
        client.rehandshake()
    until(lambda: client.state != 'CONNECTED')


def test_rehandshake_after_rekey(connected):
    server, client = connected
    client.connect()
    client.rekey()
    assert client.session.epoch == 1
    client.rehandshake()
    assert client.session.epoch == 2
    srv_item = next(iter(server.sessions.by_id.values()))
    until(lambda: srv_item.crypto.epoch == 2)
    assert client.state == 'CONNECTED'
