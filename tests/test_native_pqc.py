import pytest
from crypto.hybrid_crypto import PQCProvider,_OQS_AVAILABLE
@pytest.mark.native_pqc
@pytest.mark.skipif(not _OQS_AVAILABLE,reason="native liboqs ML-KEM-768 unavailable")
def test_native_mlkem_self_test():
    p=PQCProvider();sk,pk=p.generate_keypair();ct,a=p.encapsulate(pk);b=p.decapsulate(sk,ct);assert a==b and p.is_quantum_safe

@pytest.mark.native_pqc
@pytest.mark.skipif(not _OQS_AVAILABLE, reason='native liboqs ML-KEM-768 unavailable')
def test_native_authenticated_session_records(identities):
    from test_crypto_protocol import exchange
    from handshake.kemtls import FrameType
    assert PQCProvider().is_quantum_safe
    client, server = exchange(identities)
    ping = client.encrypt_frame(b'12345678', FrameType.PING)
    assert server.decrypt_frame(ping, FrameType.PING)[1] == b'12345678'
    assert client.decrypt_frame(server.encrypt_frame(b'12345678', FrameType.PONG), FrameType.PONG)[1] == b'12345678'
    client.secure_wipe(); server.secure_wipe()
