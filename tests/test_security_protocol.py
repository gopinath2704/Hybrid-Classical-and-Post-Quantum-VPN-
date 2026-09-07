import os,struct
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crypto.hybrid_crypto import PQCProvider,get_crypto_status,_OQS_AVAILABLE
from handshake.kemtls import *
from handshake.kemtls import _unpack_header
from vpn.identity import fingerprint

@pytest.fixture
def identities():
    kem=PQCProvider(allow_mock=True); server_sk,server_pk=kem.generate_keypair(); client_sk=Ed25519PrivateKey.generate(); client_pk=client_sk.public_key().public_bytes_raw()
    return server_sk,server_pk,client_sk,client_pk
def exchange(ids,authorized=True):
    sk,pk,csk,cpk=ids
    c=KEMTLSClient(pk,fingerprint(pk),csk,True);s=KEMTLSServer(sk,pk,lambda key:{"client_id":"alice"} if authorized and key==cpk else None,True)
    ch=c.initiate_handshake();sh=s.process_client_hello(ch);cke=c.process_server_hello(sh);sf,ss=s.process_client_key_exchange(cke);cs=c.process_server_finished(sf);return cs,ss

@pytest.mark.mock_pqc
def test_authenticated_handshake_and_directional_keys(identities):
    c,s=exchange(identities);assert c.session_id==s.session_id
    assert c.secrets.client_to_server_key!=c.secrets.server_to_client_key
    typ,p=s.decrypt_frame(c.encrypt_frame(b"request"));assert typ==FrameType.DATA and p==b"request"
    typ,p=c.decrypt_frame(s.encrypt_frame(b"response"));assert p==b"response"
def test_wrong_server_fingerprint_rejected(identities):
    _,pk,csk,_=identities
    with pytest.raises(HandshakeError,match="fingerprint"):KEMTLSClient(pk,"00"*32,csk,True)
def test_mitm_identity_substitution_rejected(identities):
    sk,pk,csk,cpk=identities;other=PQCProvider(allow_mock=True).generate_keypair()[1]
    c=KEMTLSClient(pk,fingerprint(pk),csk,True);s=KEMTLSServer(sk,other,lambda _: {"client_id":"alice"},True)
    with pytest.raises(HandshakeError,match="substitution"):c.process_server_hello(s.process_client_hello(c.initiate_handshake()))
def test_unauthorized_client_rejected(identities):
    sk,pk,csk,_=identities;c=KEMTLSClient(pk,fingerprint(pk),csk,True);s=KEMTLSServer(sk,pk,lambda _:None,True)
    with pytest.raises(HandshakeError,match="unauthorized"):s.process_client_hello(c.initiate_handshake())
def test_transcript_tampering_rejected(identities):
    sk,pk,csk,cpk=identities;c=KEMTLSClient(pk,fingerprint(pk),csk,True);s=KEMTLSServer(sk,pk,lambda _:{"client_id":"a"},True)
    ch=c.initiate_handshake();sh=s.process_client_hello(ch);cke=bytearray(c.process_server_hello(sh));cke[-40]^=1
    with pytest.raises(HandshakeError):s.process_client_key_exchange(bytes(cke))
@pytest.mark.parametrize("message",[
    lambda: ClientHello(os.urandom(32),os.urandom(32),os.urandom(32),os.urandom(1184),os.urandom(32)).pack(),
    lambda: ServerFinished(os.urandom(32)).pack()])
def test_trailing_and_header_mismatch_rejected(message):
    wire=message()
    with pytest.raises(HandshakeError):_unpack_header(wire+b"x")
    bad=bytearray(wire);bad[4:6]=struct.pack("!H",struct.unpack("!H",bad[4:6])[0]-1)
    with pytest.raises(HandshakeError):_unpack_header(bytes(bad))
def test_replay_and_out_of_order_window(identities):
    c,s=exchange(identities);frames=[c.encrypt_frame(str(i).encode()) for i in range(4)]
    assert s.decrypt_frame(frames[3])[1]==b"3";assert s.decrypt_frame(frames[1])[1]==b"1"
    with pytest.raises(HandshakeError,match="replayed"):s.decrypt_frame(frames[1])
def test_wrong_session_direction_and_epoch_rejected(identities):
    c,s=exchange(identities);frame=bytearray(c.encrypt_frame(b"x"))
    frame[6]^=1
    with pytest.raises(HandshakeError):s.decrypt_frame(bytes(frame))
    frame=bytearray(c.encrypt_frame(b"x"));frame[5]=Direction.SERVER_TO_CLIENT
    with pytest.raises(HandshakeError):s.decrypt_frame(bytes(frame))
    frame=bytearray(c.encrypt_frame(b"x"));frame[14:18]=struct.pack("!I",1)
    with pytest.raises(HandshakeError):s.decrypt_frame(bytes(frame))
def test_nonce_uniqueness(identities):
    c,_=exchange(identities);frames=[c.encrypt_frame(b"x") for _ in range(100)];assert len(set(x[:DATA_HEADER_SIZE] for x in frames))==100
def test_synchronized_rekey_and_old_epoch_rejection(identities):
    c,s=exchange(identities);old=c.encrypt_frame(b"old");nonce=os.urandom(32);cn=c.derive_next_epoch(1,nonce);sn=s.derive_next_epoch(1,nonce);c.activate_epoch(1,cn);s.activate_epoch(1,sn)
    assert s.decrypt_frame(c.encrypt_frame(b"new"))[1]==b"new"
    with pytest.raises(HandshakeError):s.decrypt_frame(old)
    with pytest.raises(HandshakeError):s.derive_next_epoch(1,nonce)
def test_cross_direction_ciphertext_rejected(identities):
    c,s=exchange(identities)
    with pytest.raises(HandshakeError):c.decrypt_frame(c.encrypt_frame(b"reflection"))
def test_server_identity_key_omitted_but_fingerprint_bound(identities):
    sk,pk,csk,_=identities;c=KEMTLSClient(pk,fingerprint(pk),csk,True);s=KEMTLSServer(sk,pk,lambda _:{"client_id":"a"},True)
    hello=ServerHello.unpack(s.process_client_hello(c.initiate_handshake()))
    assert hello.identity_id==bytes.fromhex(fingerprint(pk))
    assert pk not in hello.pack()
def test_exact_reduced_handshake_sizes(identities):
    sk,pk,csk,_=identities;c=KEMTLSClient(pk,fingerprint(pk),csk,True);s=KEMTLSServer(sk,pk,lambda _:{"client_id":"a"},True)
    ch=c.initiate_handshake();sh=s.process_client_hello(ch);cke=c.process_server_hello(sh);sf,_=s.process_client_key_exchange(cke)
    assert [len(ch),len(sh),len(cke),len(sf)]==[1318,1222,1190,38]
    assert sum(map(len,(ch,sh,cke,sf)))==3768
@pytest.mark.skipif(_OQS_AVAILABLE,reason="native provider takes precedence over mock opt-in")
def test_mock_never_quantum_safe():assert get_crypto_status()["is_quantum_safe"] is False
