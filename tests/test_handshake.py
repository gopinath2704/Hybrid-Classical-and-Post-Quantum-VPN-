"""Still-relevant v1 coverage restored and adapted to authenticated v2."""
import hashlib,os,struct
import pytest
from handshake.kemtls import *
from handshake.kemtls import _pack_header,_unpack_header,_compute_finished_mac,_verify_finished_mac,_CLIENT_FINISHED_LABEL,_SERVER_FINISHED_LABEL
from test_security_protocol import exchange

def test_header_roundtrip_and_errors():
    raw=_pack_header(MessageType.CLIENT_HELLO,ClientHello.SIZE);assert _unpack_header(raw+b"\0"*ClientHello.SIZE)[3]==ClientHello.SIZE
    with pytest.raises(HandshakeError):_unpack_header(b"x")
    bad=bytearray(raw+b"\0"*ClientHello.SIZE);bad[:2]=b"xx"
    with pytest.raises(HandshakeError):_unpack_header(bytes(bad))
def test_message_pack_unpack_roundtrips():
    messages=[ClientHello(os.urandom(32),os.urandom(32),os.urandom(32),os.urandom(1184),os.urandom(32)),ServerHello(os.urandom(32),os.urandom(32),os.urandom(32),os.urandom(1088),os.urandom(32)),ClientKeyExchange(os.urandom(1088),os.urandom(64),os.urandom(32)),ServerFinished(os.urandom(32))]
    for message in messages:assert type(message).unpack(message.pack())==message
def test_message_fixed_sizes():
    assert ClientHello.SIZE==1312 and ServerHello.SIZE==1216 and ClientKeyExchange.SIZE==1184
def test_transcript_hash_copy_and_count():
    transcript=TranscriptHasher();assert transcript.digest()==hashlib.sha256(b"").digest();transcript.update(b"a");copy=transcript.copy();transcript.update(b"b")
    assert transcript.digest()==hashlib.sha256(b"ab").digest() and copy.digest()==hashlib.sha256(b"a").digest() and transcript.message_count==2
def test_finished_mac_labels_and_tampering():
    digest,key=os.urandom(32),os.urandom(32);mac=_compute_finished_mac(digest,key,_CLIENT_FINISHED_LABEL)
    assert _verify_finished_mac(digest,key,_CLIENT_FINISHED_LABEL,mac)
    assert not _verify_finished_mac(digest,key,_SERVER_FINISHED_LABEL,mac)
def test_data_roundtrip_empty_large_tamper(identities):
    client,server=exchange(identities)
    for payload in (b"",os.urandom(65536)):assert server.decrypt_frame(client.encrypt_frame(payload))[1]==payload
    frame=bytearray(client.encrypt_frame(b"secret"));frame[-1]^=1
    with pytest.raises(HandshakeError):server.decrypt_frame(bytes(frame))
def test_handshake_state_transitions(identities):
    sk,pk,csk,_=identities
    from vpn.identity import fingerprint
    client=KEMTLSClient(pk,fingerprint(pk),csk,True);server=KEMTLSServer(sk,pk,lambda _:{"client_id":"a"},True)
    with pytest.raises(HandshakeError):client.process_server_hello(b"x")
    hello=client.initiate_handshake()
    with pytest.raises(HandshakeError):client.initiate_handshake()
    server.process_client_hello(hello)
    with pytest.raises(HandshakeError):server.process_client_hello(hello)
def test_session_info_and_cross_session_isolation(identities):
    client,server=exchange(identities);assert client.get_info()["role"]=="client"
    other_client,_=exchange(identities)
    with pytest.raises(HandshakeError):server.decrypt_frame(other_client.encrypt_frame(b"wrong"))
