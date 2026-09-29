"""
Unit & Integration Tests for the Cryptography Module (crypto/).

Tests cover:
    - ECCProvider: X25519 keypair generation & ECDH shared secret
    - PQCProvider: ML-KEM (Kyber) keygen, encapsulation, decapsulation
    - KeyManager: HKDF-SHA256 determinism, salt variation, key pairs
    - SessionKeyStore: CRUD operations, secure revocation
    - HybridKEM: Full end-to-end hybrid key exchange simulation

Run with:
    python -m pytest tests/test_crypto_protocol.py -v
"""

import pytest

from crypto.hybrid_crypto import (
    ECCProvider,
    PQCProvider,
    SUPPORTED_ALGORITHMS,
    KeyManager,
    SessionKeyStore,
    HybridKEM,
    HybridKeyBundle,
)


# ─── ECC Provider Tests ─────────────────────────────────────────────────────


class TestECCProvider:
    """Tests for the classical X25519 ECDH provider."""

    def setup_method(self):
        self.ecc = ECCProvider()

    def test_keypair_generation(self):
        """X25519 keypair produces a 32-byte public key."""
        private_key, public_bytes = self.ecc.generate_keypair()
        assert private_key is not None
        assert isinstance(public_bytes, bytes)
        assert len(public_bytes) == 32

    def test_keypair_uniqueness(self):
        """Each call generates a distinct keypair."""
        _, pub_a = self.ecc.generate_keypair()
        _, pub_b = self.ecc.generate_keypair()
        assert pub_a != pub_b

    def test_shared_secret_agreement(self):
        """Two parties performing ECDH derive the identical shared secret."""
        priv_a, pub_a = self.ecc.generate_keypair()
        priv_b, pub_b = self.ecc.generate_keypair()

        secret_a = self.ecc.derive_shared_secret(priv_a, pub_b)
        secret_b = self.ecc.derive_shared_secret(priv_b, pub_a)

        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_shared_secret_is_bytes(self):
        """Shared secret is returned as raw bytes."""
        priv_a, pub_a = self.ecc.generate_keypair()
        priv_b, pub_b = self.ecc.generate_keypair()
        secret = self.ecc.derive_shared_secret(priv_a, pub_b)
        assert isinstance(secret, bytes)

    def test_invalid_public_key_length(self):
        """Passing an invalid-length public key raises ValueError."""
        priv, _ = self.ecc.generate_keypair()
        with pytest.raises(ValueError, match="must be 32 bytes"):
            self.ecc.derive_shared_secret(priv, b"\x00" * 16)

    def test_serialize_deserialize_roundtrip(self):
        """Public key survives a serialize → deserialize roundtrip."""
        priv, pub_bytes = self.ecc.generate_keypair()
        pub_obj = self.ecc.deserialize_public_key(pub_bytes)
        re_serialized = self.ecc.serialize_public_key(pub_obj)
        assert re_serialized == pub_bytes


# ─── PQC Provider Tests ─────────────────────────────────────────────────────


class TestPQCProvider:
    """Tests for the post-quantum ML-KEM (Kyber) provider."""

    def setup_method(self):
        self.pqc = PQCProvider("ML-KEM-768")

    def test_keypair_generation(self):
        """ML-KEM-768 keypair produces non-empty key material."""
        secret_key, public_key = self.pqc.generate_keypair()
        assert isinstance(secret_key, bytes) and len(secret_key) > 0
        assert isinstance(public_key, bytes) and len(public_key) > 0

    def test_keypair_uniqueness(self):
        """Each keypair is distinct."""
        _, pub_a = self.pqc.generate_keypair()
        _, pub_b = self.pqc.generate_keypair()
        assert pub_a != pub_b

    def test_encap_decap_agreement(self):
        """Encapsulation and decapsulation produce the same shared secret."""
        secret_key, public_key = self.pqc.generate_keypair()
        ciphertext, shared_secret_sender = self.pqc.encapsulate(public_key)
        shared_secret_receiver = self.pqc.decapsulate(secret_key, ciphertext)

        assert shared_secret_sender == shared_secret_receiver
        assert len(shared_secret_sender) == 32

    def test_ciphertext_is_nonempty(self):
        """Encapsulation produces non-empty ciphertext."""
        _, public_key = self.pqc.generate_keypair()
        ciphertext, _ = self.pqc.encapsulate(public_key)
        assert isinstance(ciphertext, bytes) and len(ciphertext) > 0

    @pytest.mark.parametrize("algorithm", SUPPORTED_ALGORITHMS)
    def test_all_supported_algorithms(self, algorithm):
        """All supported ML-KEM variants work correctly."""
        pqc = PQCProvider(algorithm)
        sk, pk = pqc.generate_keypair()
        ct, ss_sender = pqc.encapsulate(pk)
        ss_receiver = pqc.decapsulate(sk, ct)
        assert ss_sender == ss_receiver

    def test_unsupported_algorithm_raises(self):
        """Requesting an unsupported algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            PQCProvider("ML-KEM-256")

    def test_algorithm_details(self):
        """get_algorithm_details() returns a dict with expected keys."""
        details = self.pqc.get_algorithm_details()
        assert details["algorithm"] == "ML-KEM-768"
        assert details["nist_level"] == 3
        assert "public_key_length" in details
        assert "ciphertext_length" in details
        assert "shared_secret_length" in details


# ─── Key Manager Tests ───────────────────────────────────────────────────────


class TestKeyManager:
    """Tests for HKDF-SHA256 key derivation."""

    def setup_method(self):
        self.km = KeyManager()
        self.secret = b"\xaa" * 32 + b"\xbb" * 32  # 64-byte combined secret

    def test_derive_key_length(self):
        """Derived key has the requested length."""
        key = self.km.derive_key(self.secret)
        assert len(key) == 32

    def test_derive_key_custom_length(self):
        """Custom output length is respected."""
        key = self.km.derive_key(self.secret, length=64)
        assert len(key) == 64

    def test_derive_key_deterministic(self):
        """Same inputs produce the same output (deterministic)."""
        salt = b"\x00" * 32
        key1 = self.km.derive_key(self.secret, salt=salt)
        key2 = self.km.derive_key(self.secret, salt=salt)
        assert key1 == key2

    def test_derive_key_different_salts(self):
        """Different salts produce different keys."""
        key1 = self.km.derive_key(self.secret, salt=b"\x01" * 32)
        key2 = self.km.derive_key(self.secret, salt=b"\x02" * 32)
        assert key1 != key2

    def test_derive_key_different_info(self):
        """Different info labels produce different keys."""
        key1 = self.km.derive_key(self.secret, info=b"label-A")
        key2 = self.km.derive_key(self.secret, info=b"label-B")
        assert key1 != key2

    def test_derive_key_empty_secret_raises(self):
        """Empty secret raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            self.km.derive_key(b"")

    def test_derive_key_pair(self):
        """derive_key_pair() returns two distinct 32-byte keys."""
        enc_key, mac_key = self.km.derive_key_pair(self.secret)
        assert len(enc_key) == 32
        assert len(mac_key) == 32
        assert enc_key != mac_key

    def test_generate_salt(self):
        """Generated salts are the requested size and unique."""
        salt1 = KeyManager.generate_salt()
        salt2 = KeyManager.generate_salt()
        assert len(salt1) == 32
        assert salt1 != salt2


class TestSessionKeyStore:
    """Tests for the in-memory session key store."""

    def setup_method(self):
        self.store = SessionKeyStore()
        self.enc = b"\x11" * 32
        self.mac = b"\x22" * 32

    def test_store_and_retrieve(self):
        """Store a session and retrieve its keys."""
        self.store.store_session("s1", self.enc, self.mac)
        record = self.store.get_session("s1")
        assert bytes(record.encryption_key) == self.enc
        assert bytes(record.mac_key) == self.mac

    def test_store_with_metadata(self):
        """Session metadata is preserved."""
        meta = {"peer": "10.0.0.1", "port": 443}
        self.store.store_session("s1", self.enc, self.mac, metadata=meta)
        record = self.store.get_session("s1")
        assert record.metadata == meta

    def test_list_sessions(self):
        """list_sessions() returns sorted session IDs."""
        self.store.store_session("sess-b", self.enc, self.mac)
        self.store.store_session("sess-a", self.enc, self.mac)
        assert self.store.list_sessions() == ["sess-a", "sess-b"]

    def test_revoke_session(self):
        """Revoked session is no longer retrievable."""
        self.store.store_session("s1", self.enc, self.mac)
        self.store.revoke_session("s1")
        with pytest.raises(KeyError):
            self.store.get_session("s1")

    def test_revoke_wipes_keys(self):
        """Revocation overwrites key buffers with zeros."""
        self.store.store_session("s1", self.enc, self.mac)
        record = self.store.get_session("s1")
        # Keep references to the mutable bytearrays
        enc_ref = record.encryption_key
        mac_ref = record.mac_key
        self.store.revoke_session("s1")
        # After revocation, the bytearrays should be all zeros
        assert enc_ref == bytearray(32)
        assert mac_ref == bytearray(32)

    def test_duplicate_session_raises(self):
        """Storing a duplicate session ID raises ValueError."""
        self.store.store_session("s1", self.enc, self.mac)
        with pytest.raises(ValueError, match="already exists"):
            self.store.store_session("s1", self.enc, self.mac)

    def test_get_nonexistent_raises(self):
        """Getting a nonexistent session raises KeyError."""
        with pytest.raises(KeyError):
            self.store.get_session("does-not-exist")

    def test_revoke_all(self):
        """revoke_all() removes all sessions."""
        self.store.store_session("s1", self.enc, self.mac)
        self.store.store_session("s2", self.enc, self.mac)
        count = self.store.revoke_all()
        assert count == 2
        assert self.store.count == 0

    def test_count_property(self):
        """count property tracks the number of active sessions."""
        assert self.store.count == 0
        self.store.store_session("s1", self.enc, self.mac)
        assert self.store.count == 1


# ─── Hybrid KEM Integration Tests ───────────────────────────────────────────


class TestHybridKEM:
    """Integration tests for the full hybrid key exchange."""

    def setup_method(self):
        self.hybrid = HybridKEM("ML-KEM-768")

    def test_generate_keypairs(self):
        """generate_keypairs() returns a complete HybridKeyBundle."""
        bundle = self.hybrid.generate_keypairs()
        assert isinstance(bundle, HybridKeyBundle)
        assert len(bundle.ecc_public) == 32
        assert len(bundle.pqc_secret) > 0
        assert len(bundle.pqc_public) > 0

    def test_full_hybrid_exchange(self):
        """
        Full two-party hybrid key exchange:
        Client encapsulates → Server decapsulates → both derive same session key.
        """
        # Both parties generate their keypairs
        server_keys = self.hybrid.generate_keypairs()
        client_keys = self.hybrid.generate_keypairs()

        # Client (initiator) encapsulates towards server
        pqc_ct, ecc_ss_client, pqc_ss_client = self.hybrid.encapsulate(
            peer_ecc_public=server_keys.ecc_public,
            peer_pqc_public=server_keys.pqc_public,
            own_ecc_private=client_keys.ecc_private,
        )

        # Server (responder) decapsulates
        ecc_ss_server, pqc_ss_server = self.hybrid.decapsulate(
            pqc_secret_key=server_keys.pqc_secret,
            pqc_ciphertext=pqc_ct,
            own_ecc_private=server_keys.ecc_private,
            peer_ecc_public=client_keys.ecc_public,
        )

        # Shared secrets must match
        assert ecc_ss_client == ecc_ss_server, "ECC shared secrets mismatch"
        assert pqc_ss_client == pqc_ss_server, "PQC shared secrets mismatch"

        # Derive final session keys
        session_key_client = self.hybrid.combine_secrets(
            ecc_ss_client, pqc_ss_client
        )
        session_key_server = self.hybrid.combine_secrets(
            ecc_ss_server, pqc_ss_server
        )
        assert session_key_client == session_key_server
        assert len(session_key_client) == 32

    def test_full_hybrid_key_pair_derivation(self):
        """
        Hybrid exchange producing separate encryption + MAC keys.
        """
        server_keys = self.hybrid.generate_keypairs()
        client_keys = self.hybrid.generate_keypairs()

        pqc_ct, ecc_ss_c, pqc_ss_c = self.hybrid.encapsulate(
            server_keys.ecc_public,
            server_keys.pqc_public,
            client_keys.ecc_private,
        )
        ecc_ss_s, pqc_ss_s = self.hybrid.decapsulate(
            server_keys.pqc_secret,
            pqc_ct,
            server_keys.ecc_private,
            client_keys.ecc_public,
        )

        enc_c, mac_c = self.hybrid.combine_secrets_to_pair(ecc_ss_c, pqc_ss_c)
        enc_s, mac_s = self.hybrid.combine_secrets_to_pair(ecc_ss_s, pqc_ss_s)

        assert enc_c == enc_s
        assert mac_c == mac_s
        assert enc_c != mac_c  # enc and mac keys are distinct

    def test_get_info(self):
        """get_info() returns both classical and PQ algorithm details."""
        info = self.hybrid.get_info()
        assert info["classical"]["algorithm"] == "X25519"
        assert info["post_quantum"]["algorithm"] == "ML-KEM-768"

    def test_end_to_end_with_session_store(self):
        """
        Full end-to-end: hybrid exchange → derive keys → store in session store.
        """
        server = self.hybrid.generate_keypairs()
        client = self.hybrid.generate_keypairs()

        pqc_ct, ecc_ss, pqc_ss = self.hybrid.encapsulate(
            server.ecc_public, server.pqc_public, client.ecc_private,
        )
        ecc_ss_s, pqc_ss_s = self.hybrid.decapsulate(
            server.pqc_secret, pqc_ct, server.ecc_private, client.ecc_public,
        )

        # Derive enc + mac keys
        enc_key, mac_key = self.hybrid.combine_secrets_to_pair(ecc_ss, pqc_ss)

        # Store in session key store
        store = SessionKeyStore()
        store.store_session(
            "vpn-session-001",
            enc_key,
            mac_key,
            metadata={"peer": "192.168.1.100", "algorithm": "ML-KEM-768"},
        )

        record = store.get_session("vpn-session-001")
        assert bytes(record.encryption_key) == enc_key
        assert record.metadata["algorithm"] == "ML-KEM-768"

        # Clean up
        store.revoke_session("vpn-session-001")
        assert store.count == 0
import os,struct
import pytest
from crypto.hybrid_crypto import PQCProvider,get_crypto_status,_OQS_AVAILABLE
from handshake.kemtls import *
from handshake.kemtls import _unpack_header
from vpn.identity import fingerprint

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
"""Still-relevant v1 coverage restored and adapted to authenticated v2."""
import hashlib,os,struct
import pytest
from handshake.kemtls import *
from handshake.kemtls import _pack_header,_unpack_header,_compute_finished_mac,_verify_finished_mac,_CLIENT_FINISHED_LABEL,_SERVER_FINISHED_LABEL

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


def test_frozen_v2_handshake_serialization():
    """Refactors must not change message headers, field order, or wire bytes."""
    messages = [
        ClientHello(bytes([1])*32, bytes([2])*32, bytes([3])*32, bytes([4])*1184, bytes([5])*32),
        ServerHello(bytes([6])*32, bytes([7])*32, bytes([8])*32, bytes([9])*1088, bytes([10])*32),
        ClientKeyExchange(bytes([11])*1088, bytes([12])*64, bytes([13])*32),
        ServerFinished(bytes([14])*32),
    ]
    expected = [
        (1318, '485620010520', '5cb01f9aa02ff578a960569d57c98eab1509b100e0ebf8c3a9d0db345b599a1a'),
        (1222, '4856200204c0', '3c3679256f04ee03a54f92eefd77074fe70347d727b54b46268cd6a7bc55b80f'),
        (1190, '4856200304a0', 'b9a86d625f7354371b8c9219cbb8c4836346d25dccd2bdd1ab5901feb78785e5'),
        (38, '485620040020', 'ffee0af94d03c49c9711872d9146d8bd2f0f8488d31e4c3a42ce6c4c2073dc0f'),
    ]
    for message, (length, header, digest) in zip(messages, expected):
        wire = message.pack()
        assert len(wire) == length
        assert wire[:6].hex() == header
        assert hashlib.sha256(wire).hexdigest() == digest
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
import concurrent.futures
import struct
import threading
import pytest
from handshake.kemtls import DATA_HEADER_FORMAT,DATA_HEADER_SIZE,Channel,FrameType,HandshakeError

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
