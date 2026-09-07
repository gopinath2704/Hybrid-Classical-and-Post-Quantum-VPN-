"""
Unit & Integration Tests for the Cryptography Module (crypto/).

Tests cover:
    - ECCProvider: X25519 keypair generation & ECDH shared secret
    - PQCProvider: ML-KEM (Kyber) keygen, encapsulation, decapsulation
    - KeyManager: HKDF-SHA256 determinism, salt variation, key pairs
    - SessionKeyStore: CRUD operations, secure revocation
    - HybridKEM: Full end-to-end hybrid key exchange simulation

Run with:
    python -m pytest tests/test_crypto.py -v
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
