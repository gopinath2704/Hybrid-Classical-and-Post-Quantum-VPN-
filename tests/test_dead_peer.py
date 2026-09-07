import time
import threading
from unittest.mock import Mock

import pytest
from handshake.kemtls import FrameType
from test_session_activity import connected
from test_runtime_fixes import until
from test_runtime import ipv4


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
