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
    from test_security_protocol import exchange
    from handshake.kemtls import FrameType
    client_session,server_session=exchange(identities);client=runtime.VPNClient(ClientConfig());client.session=client_session;client.control=object();responses=[]
    def send(_,frame):
        typ,payload=server_session.decrypt_control(frame,FrameType.REKEY_REQUEST);epoch=struct.unpack("!I",payload[:4])[0];keys=server_session.derive_next_epoch(epoch,payload[4:])
        confirmation=hmac.new(bytes(server_session.secrets.control_confirm_key),b"rekey response"+payload,hashlib.sha256).digest()
        responses.append(server_session.encrypt_control(payload[:4]+confirmation,FrameType.REKEY_RESPONSE));server_session.activate_epoch(epoch,keys)
    monkeypatch.setattr(runtime,"send_message",send);monkeypatch.setattr(runtime,"recv_message",lambda _:responses.pop())
    client.rekey();assert client_session.epoch==server_session.epoch==1
    assert server_session.decrypt_frame(client_session.encrypt_frame(b"after"))[1]==b"after"
