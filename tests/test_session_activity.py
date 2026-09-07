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
from test_runtime_fixes import until
from test_security_protocol import exchange
from test_runtime import ipv4


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
