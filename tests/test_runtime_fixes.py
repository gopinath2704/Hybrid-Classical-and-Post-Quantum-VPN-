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
from test_security_protocol import exchange


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
    import tomllib
    compose = Path('docker-compose.yml').read_text()
    assert 'SERVER_HOST=' not in compose and '/app/config/' not in compose
    assert './config/client.docker.toml:/etc/pqvpn/client.toml:ro' in compose
    config = tomllib.loads(Path('config/client.docker.toml').read_text())['client']
    assert config['server_host'] == 'vpn-server'
    for name in ['server_identity_private.key','server_identity_public.key','authorized_clients.json','client_identity_private.key']:
        assert f'./config/{name}:/etc/pqvpn/{name}:ro' in compose


def test_setup_uses_nondefault_toml(tmp_path):
    from vpn.config import load_server_config
    from vpn.firewall import render
    config = tmp_path/'server.toml'
    config.write_text('[server]\nvpn_subnet="10.50.0.0/24"\nserver_vpn_ip="10.50.0.1"\ntun_name="shadowvpn0"\noutbound_interface="uplink0"\n')
    cfg = load_server_config(config)
    rules = render(cfg, cfg.outbound_interface)
    assert '10.50.0.0/24' in rules and 'shadowvpn0' in rules and 'uplink0' in rules
    assert '10.8.0.0/24' not in rules
    assert 'server-setup.sh /etc/pqvpn/server.toml' in Path('deploy/pqvpn-server.service').read_text()


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


def test_api_exposes_runtime_failure_and_real_schema(monkeypatch):
    import asyncio
    from test_api_security import load_api
    api = load_api(monkeypatch)
    api.service = runtime.VPNClient(ClientConfig())
    api.service.state, api.service.error = 'FAILED', 'control channel lost'
    api.state.update(connection_state='CONNECTED',connected_at=time.time())
    result = asyncio.run(api.status())
    assert result['connection_state'] == 'FAILED'
    assert result['error'] == 'control channel lost'
    assert {'client_vpn_ip','epoch','network','tun_mtu','pqc_mode','tun_mode','rekey_countdown'} <= result.keys()
    assert {'rtt_ms','jitter_ms','loss_rate'} <= result['network'].keys()
    assert 'download_mbps' not in result and 'bytes_sent' not in result
    js = Path('app/frontend/js/app.js').read_text()
    assert '/logs' not in js and 'server_id:' not in js and 'server.flag' not in js


def test_rate_limiter_caps_unique_sources():
    limiter = runtime.SourceRateLimiter(max_sources=2)
    assert limiter.allow('a',0) and limiter.allow('b',0)
    assert not limiter.allow('c',0)
    assert limiter.allow('c',61)
