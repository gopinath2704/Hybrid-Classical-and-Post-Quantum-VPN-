import concurrent.futures
import struct
import threading
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crypto.hybrid_crypto import PQCProvider
from handshake.kemtls import DATA_HEADER_FORMAT,DATA_HEADER_SIZE,Channel,FrameType,HandshakeError
from test_security_protocol import exchange

@pytest.fixture
def identities():
    kem=PQCProvider(allow_mock=True);server_sk,server_pk=kem.generate_keypair();client_sk=Ed25519PrivateKey.generate()
    return server_sk,server_pk,client_sk,client_sk.public_key().public_bytes_raw()

def header(frame):return struct.unpack(DATA_HEADER_FORMAT,frame[:DATA_HEADER_SIZE])

def test_concurrent_encrypt_sequence_and_nonce_uniqueness(identities):
    client,server=exchange(identities)
    def produce(i):return client.encrypt_frame(struct.pack("!I",i))
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        frames=list(pool.map(produce,range(4000)))
    sequences=[header(frame)[-1] for frame in frames]
    nonces=[client._nonce(client._data_send_nonce_base,seq) for seq in sequences]
    assert len(sequences)==len(set(sequences))==4000
    assert len(nonces)==len(set(nonces))==4000
    for frame in sorted(frames,key=lambda value:header(value)[-1]):
        assert server.decrypt_frame(frame)[0]==FrameType.DATA

def test_concurrent_duplicate_replay_exactly_one_success(identities):
    client,server=exchange(identities);frame=client.encrypt_frame(b"once");barrier=threading.Barrier(2)
    def consume():
        barrier.wait()
        try:return server.decrypt_frame(frame)[1]
        except HandshakeError as exc:return str(exc)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:consume(),range(2)))
    assert results.count(b"once")==1
    assert sum("replayed" in str(value) for value in results)==1

def test_control_and_data_sequence_domains_are_independent(identities):
    client,server=exchange(identities)
    control=client.encrypt_control(b"cfg",FrameType.CONFIG)
    data=client.encrypt_frame(b"packet")
    assert header(control)[2]==Channel.CONTROL and header(control)[-1]==0
    assert header(data)[2]==Channel.DATA and header(data)[-1]==0
    assert server.decrypt_frame(data)[1]==b"packet"
    assert server.decrypt_control(control)[1]==b"cfg"

def test_delayed_control_survives_more_than_replay_window_data(identities):
    client,server=exchange(identities);control=client.encrypt_control(b"delayed",FrameType.CONFIG)
    for _ in range(300):server.decrypt_frame(client.encrypt_frame(b"udp"))
    assert server.decrypt_control(control)[1]==b"delayed"

def test_cross_channel_ciphertext_rejected(identities):
    client,server=exchange(identities)
    with pytest.raises(HandshakeError,match="channel"):server.decrypt_control(client.encrypt_frame(b"data"))
    with pytest.raises(HandshakeError,match="channel"):server.decrypt_frame(client.encrypt_control(b"control",FrameType.CONFIG))
