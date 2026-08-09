"""
Unit & Integration Tests for the Handshake Module (handshake/).

Tests cover:
    - §1 Wire Protocol: Binary pack/unpack roundtrips for all message types
    - §2 Transcript Hasher: Digest computation, update ordering, copy
    - §3 Session Context: AES-256-GCM encrypt/decrypt frame roundtrip
    - §4/5 State Machines: Full client-server handshake exchange simulation
    - Security: Tampered ciphertext detection, out-of-order rejection,
                corrupted MAC detection

Run with:
    python -m pytest tests/test_handshake.py -v
"""

import os
import struct
import pytest

from handshake.kemtls import (
    # Constants
    MAGIC,
    PROTOCOL_VERSION,
    HEADER_SIZE,
    HEADER_FORMAT,
    RANDOM_SIZE,
    SESSION_ID_SIZE,
    ECC_PUBLIC_KEY_SIZE,
    PQC_PUBLIC_KEY_SIZE,
    PQC_CIPHERTEXT_SIZE,
    FINISHED_MAC_SIZE,

    # Types & errors
    MessageType,
    HandshakeError,

    # Messages
    ClientHello,
    ServerHello,
    ClientKeyExchange,
    ServerFinished,
    _pack_header,
    _unpack_header,

    # Transcript
    TranscriptHasher,
    _compute_finished_mac,
    _verify_finished_mac,
    _CLIENT_FINISHED_LABEL,
    _SERVER_FINISHED_LABEL,

    # Session
    HandshakeState,
    HandshakeSession,

    # State machines
    KEMTLSClient,
    KEMTLSServer,
)


# ═══════════════════════════════════════════════════════════════════════════════
# §1 Wire Protocol Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestHeader:
    """Tests for the binary wire header pack/unpack."""

    def test_header_size_is_6(self):
        """Header struct is exactly 6 bytes."""
        assert HEADER_SIZE == 6

    def test_pack_unpack_roundtrip(self):
        """Header survives a pack → unpack roundtrip."""
        raw = _pack_header(MessageType.CLIENT_HELLO, 1280)
        magic, version, msg_type, length = _unpack_header(raw)
        assert magic == MAGIC
        assert version == PROTOCOL_VERSION
        assert msg_type == MessageType.CLIENT_HELLO
        assert length == 1280

    def test_invalid_magic_raises(self):
        """Wrong magic bytes raise HandshakeError."""
        bad = struct.pack(HEADER_FORMAT, 0xDEAD, PROTOCOL_VERSION, 0x01, 100)
        with pytest.raises(HandshakeError, match="Invalid magic"):
            _unpack_header(bad)

    def test_unsupported_version_raises(self):
        """Unknown version raises HandshakeError."""
        bad = struct.pack(HEADER_FORMAT, MAGIC, 0xFF, 0x01, 100)
        with pytest.raises(HandshakeError, match="Unsupported version"):
            _unpack_header(bad)

    def test_truncated_header_raises(self):
        """Header shorter than 6 bytes raises HandshakeError."""
        with pytest.raises(HandshakeError, match="Header too short"):
            _unpack_header(b"\x00\x01")


class TestClientHello:
    """Tests for ClientHello message serialization."""

    def _make_client_hello(self):
        return ClientHello(
            client_random=os.urandom(RANDOM_SIZE),
            session_id=os.urandom(SESSION_ID_SIZE),
            ecc_public_key=os.urandom(ECC_PUBLIC_KEY_SIZE),
            pqc_public_key=os.urandom(PQC_PUBLIC_KEY_SIZE),
        )

    def test_pack_unpack_roundtrip(self):
        """ClientHello survives pack → unpack."""
        original = self._make_client_hello()
        wire = original.pack()
        parsed = ClientHello.unpack(wire)

        assert parsed.client_random == original.client_random
        assert parsed.session_id == original.session_id
        assert parsed.ecc_public_key == original.ecc_public_key
        assert parsed.pqc_public_key == original.pqc_public_key

    def test_expected_wire_size(self):
        """ClientHello wire bytes have the expected total size."""
        msg = self._make_client_hello()
        wire = msg.pack()
        expected = HEADER_SIZE + RANDOM_SIZE + SESSION_ID_SIZE + ECC_PUBLIC_KEY_SIZE + PQC_PUBLIC_KEY_SIZE
        assert len(wire) == expected

    def test_wrong_type_raises(self):
        """Unpacking a non-ClientHello type raises HandshakeError."""
        # Build a header with SERVER_HELLO type but try to parse as ClientHello
        payload = os.urandom(RANDOM_SIZE + SESSION_ID_SIZE + ECC_PUBLIC_KEY_SIZE + PQC_PUBLIC_KEY_SIZE)
        header = _pack_header(MessageType.SERVER_HELLO, len(payload))
        with pytest.raises(HandshakeError, match="Expected CLIENT_HELLO"):
            ClientHello.unpack(header + payload)

    def test_truncated_payload_raises(self):
        """Short payload raises HandshakeError."""
        header = _pack_header(MessageType.CLIENT_HELLO, 10)
        with pytest.raises(HandshakeError, match="payload too short"):
            ClientHello.unpack(header + b"\x00" * 10)


class TestServerHello:
    """Tests for ServerHello message serialization."""

    def _make_server_hello(self):
        return ServerHello(
            server_random=os.urandom(RANDOM_SIZE),
            session_id=os.urandom(SESSION_ID_SIZE),
            ecc_public_key=os.urandom(ECC_PUBLIC_KEY_SIZE),
            pqc_public_key=os.urandom(PQC_PUBLIC_KEY_SIZE),
            pqc_ciphertext=os.urandom(PQC_CIPHERTEXT_SIZE),
        )

    def test_pack_unpack_roundtrip(self):
        """ServerHello survives pack → unpack."""
        original = self._make_server_hello()
        wire = original.pack()
        parsed = ServerHello.unpack(wire)

        assert parsed.server_random == original.server_random
        assert parsed.session_id == original.session_id
        assert parsed.ecc_public_key == original.ecc_public_key
        assert parsed.pqc_public_key == original.pqc_public_key
        assert parsed.pqc_ciphertext == original.pqc_ciphertext

    def test_expected_wire_size(self):
        """ServerHello wire bytes have the expected total size."""
        msg = self._make_server_hello()
        wire = msg.pack()
        expected = HEADER_SIZE + RANDOM_SIZE + SESSION_ID_SIZE + ECC_PUBLIC_KEY_SIZE + PQC_PUBLIC_KEY_SIZE + PQC_CIPHERTEXT_SIZE
        assert len(wire) == expected


class TestClientKeyExchange:
    """Tests for ClientKeyExchange message serialization."""

    def test_pack_unpack_roundtrip(self):
        """ClientKeyExchange survives pack → unpack."""
        original = ClientKeyExchange(
            pqc_ciphertext=os.urandom(PQC_CIPHERTEXT_SIZE),
            finished_mac=os.urandom(FINISHED_MAC_SIZE),
        )
        wire = original.pack()
        parsed = ClientKeyExchange.unpack(wire)

        assert parsed.pqc_ciphertext == original.pqc_ciphertext
        assert parsed.finished_mac == original.finished_mac

    def test_expected_wire_size(self):
        """ClientKeyExchange wire bytes have the expected total size."""
        msg = ClientKeyExchange(
            pqc_ciphertext=os.urandom(PQC_CIPHERTEXT_SIZE),
            finished_mac=os.urandom(FINISHED_MAC_SIZE),
        )
        wire = msg.pack()
        expected = HEADER_SIZE + PQC_CIPHERTEXT_SIZE + FINISHED_MAC_SIZE
        assert len(wire) == expected


class TestServerFinished:
    """Tests for ServerFinished message serialization."""

    def test_pack_unpack_roundtrip(self):
        """ServerFinished survives pack → unpack."""
        original = ServerFinished(finished_mac=os.urandom(FINISHED_MAC_SIZE))
        wire = original.pack()
        parsed = ServerFinished.unpack(wire)
        assert parsed.finished_mac == original.finished_mac

    def test_expected_wire_size(self):
        """ServerFinished wire bytes have the expected total size."""
        msg = ServerFinished(finished_mac=os.urandom(FINISHED_MAC_SIZE))
        wire = msg.pack()
        expected = HEADER_SIZE + FINISHED_MAC_SIZE
        assert len(wire) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# §2 Transcript Hasher Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTranscriptHasher:
    """Tests for the SHA-256 transcript accumulator."""

    def test_empty_digest(self):
        """Empty hasher produces the SHA-256 of empty input."""
        h = TranscriptHasher()
        import hashlib
        assert h.digest() == hashlib.sha256(b"").digest()

    def test_single_update(self):
        """Single update produces correct digest."""
        h = TranscriptHasher()
        data = b"ClientHello data"
        h.update(data)
        import hashlib
        assert h.digest() == hashlib.sha256(data).digest()

    def test_multiple_updates_are_cumulative(self):
        """Multiple updates are equivalent to hashing the concatenation."""
        h = TranscriptHasher()
        d1, d2 = b"first message", b"second message"
        h.update(d1)
        h.update(d2)
        import hashlib
        assert h.digest() == hashlib.sha256(d1 + d2).digest()

    def test_message_count(self):
        """Message count tracks the number of updates."""
        h = TranscriptHasher()
        assert h.message_count == 0
        h.update(b"a")
        h.update(b"b")
        assert h.message_count == 2

    def test_copy_is_independent(self):
        """Copy produces an independent snapshot."""
        h = TranscriptHasher()
        h.update(b"first")
        clone = h.copy()
        h.update(b"second")
        # Clone should not have the second update
        assert clone.digest() != h.digest()
        assert clone.message_count == 1
        assert h.message_count == 2

    def test_digest_does_not_finalize(self):
        """Calling digest() does not prevent further updates."""
        h = TranscriptHasher()
        h.update(b"a")
        _ = h.digest()
        h.update(b"b")
        import hashlib
        assert h.digest() == hashlib.sha256(b"ab").digest()


class TestFinishedMAC:
    """Tests for the HMAC-based Finished MAC computation."""

    def test_compute_and_verify(self):
        """Compute a MAC and verify it succeeds."""
        digest = os.urandom(32)
        key = os.urandom(32)
        mac = _compute_finished_mac(digest, key, _CLIENT_FINISHED_LABEL)
        assert len(mac) == 32
        assert _verify_finished_mac(digest, key, _CLIENT_FINISHED_LABEL, mac)

    def test_wrong_key_fails(self):
        """MAC computed with one key fails verification with another."""
        digest = os.urandom(32)
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        mac = _compute_finished_mac(digest, key1, _CLIENT_FINISHED_LABEL)
        assert not _verify_finished_mac(digest, key2, _CLIENT_FINISHED_LABEL, mac)

    def test_wrong_label_fails(self):
        """MAC fails if label is different (client vs. server)."""
        digest = os.urandom(32)
        key = os.urandom(32)
        mac = _compute_finished_mac(digest, key, _CLIENT_FINISHED_LABEL)
        assert not _verify_finished_mac(digest, key, _SERVER_FINISHED_LABEL, mac)

    def test_tampered_mac_fails(self):
        """Flipping a bit in the MAC causes verification failure."""
        digest = os.urandom(32)
        key = os.urandom(32)
        mac = _compute_finished_mac(digest, key, _CLIENT_FINISHED_LABEL)
        tampered = bytearray(mac)
        tampered[0] ^= 0xFF
        assert not _verify_finished_mac(digest, key, _CLIENT_FINISHED_LABEL, bytes(tampered))


# ═══════════════════════════════════════════════════════════════════════════════
# §3 Session Context Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestHandshakeSession:
    """Tests for the AES-256-GCM session frame cipher."""

    def _make_session(self):
        return HandshakeSession(
            session_id=os.urandom(32),
            encryption_key=os.urandom(32),
            mac_key=os.urandom(32),
            client_random=os.urandom(32),
            server_random=os.urandom(32),
        )

    def test_encrypt_decrypt_roundtrip(self):
        """Plaintext survives encrypt → decrypt."""
        session = self._make_session()
        plaintext = b"Hello, post-quantum world!"
        frame = session.encrypt_frame(plaintext)
        recovered = session.decrypt_frame(frame)
        assert recovered == plaintext

    def test_encrypt_decrypt_empty(self):
        """Empty plaintext survives encrypt → decrypt."""
        session = self._make_session()
        frame = session.encrypt_frame(b"")
        assert session.decrypt_frame(frame) == b""

    def test_encrypt_decrypt_large(self):
        """Large payload (64 KB) survives encrypt → decrypt."""
        session = self._make_session()
        plaintext = os.urandom(65536)
        frame = session.encrypt_frame(plaintext)
        assert session.decrypt_frame(frame) == plaintext

    def test_tampered_ciphertext_fails(self):
        """Flipping a bit in the ciphertext causes decryption failure."""
        session = self._make_session()
        frame = session.encrypt_frame(b"secret data")
        tampered = bytearray(frame)
        tampered[-1] ^= 0xFF  # flip last byte (in the GCM tag)
        with pytest.raises(HandshakeError, match="decryption failed"):
            session.decrypt_frame(bytes(tampered))

    def test_truncated_frame_raises(self):
        """Frame shorter than nonce + tag raises HandshakeError."""
        session = self._make_session()
        with pytest.raises(HandshakeError, match="Frame too short"):
            session.decrypt_frame(b"\x00" * 10)

    def test_get_info(self):
        """get_info() returns expected metadata keys."""
        session = self._make_session()
        info = session.get_info()
        assert "session_id" in info
        assert info["encryption_key_size"] == 32
        assert info["mac_key_size"] == 32

    def test_different_keys_cannot_decrypt(self):
        """A different session's keys cannot decrypt another session's frames."""
        session_a = self._make_session()
        session_b = self._make_session()
        frame = session_a.encrypt_frame(b"for session A only")
        with pytest.raises(HandshakeError, match="decryption failed"):
            session_b.decrypt_frame(frame)


# ═══════════════════════════════════════════════════════════════════════════════
# §4/5 Full Handshake Exchange Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestFullHandshake:
    """
    End-to-end integration tests simulating a complete client-server
    KEMTLS handshake and subsequent encrypted data exchange.
    """

    def test_full_handshake_succeeds(self):
        """
        Complete 4-message handshake:
            Client → Server : ClientHello
            Server → Client : ServerHello
            Client → Server : ClientKeyExchange
            Server → Client : ServerFinished
        Both parties end in ESTABLISHED state with matching session keys.
        """
        client = KEMTLSClient()
        server = KEMTLSServer()

        # Flight 1: ClientHello
        assert client.state == HandshakeState.IDLE
        ch_bytes = client.initiate_handshake()
        assert client.state == HandshakeState.CLIENT_HELLO_SENT

        # Flight 2: ServerHello
        assert server.state == HandshakeState.IDLE
        sh_bytes = server.process_client_hello(ch_bytes)
        assert server.state == HandshakeState.SERVER_HELLO_SENT

        # Flight 3: ClientKeyExchange
        cke_bytes = client.process_server_hello(sh_bytes)
        assert client.state == HandshakeState.KEY_EXCHANGE_SENT

        # Flight 4: ServerFinished
        sf_bytes, server_session = server.process_client_key_exchange(cke_bytes)
        assert server.state == HandshakeState.ESTABLISHED

        # Client processes ServerFinished
        client_session = client.process_server_finished(sf_bytes)
        assert client.state == HandshakeState.ESTABLISHED

        # Both sessions must have matching keys
        assert client_session.encryption_key == server_session.encryption_key
        assert client_session.mac_key == server_session.mac_key
        assert client_session.session_id == server_session.session_id

    def test_handshake_then_data_exchange(self):
        """
        After handshake, client encrypts a message and server decrypts it,
        then server encrypts a response and client decrypts it.
        """
        client = KEMTLSClient()
        server = KEMTLSServer()

        ch = client.initiate_handshake()
        sh = server.process_client_hello(ch)
        cke = client.process_server_hello(sh)
        sf, server_session = server.process_client_key_exchange(cke)
        client_session = client.process_server_finished(sf)

        # Client → Server data
        client_msg = b"Hello from client!"
        frame = client_session.encrypt_frame(client_msg)
        assert server_session.decrypt_frame(frame) == client_msg

        # Server → Client data
        server_msg = b"Hello from server!"
        frame = server_session.encrypt_frame(server_msg)
        assert client_session.decrypt_frame(frame) == server_msg

    def test_multiple_data_frames(self):
        """Multiple sequential frames decrypt correctly."""
        client = KEMTLSClient()
        server = KEMTLSServer()

        ch = client.initiate_handshake()
        sh = server.process_client_hello(ch)
        cke = client.process_server_hello(sh)
        sf, server_session = server.process_client_key_exchange(cke)
        client_session = client.process_server_finished(sf)

        for i in range(10):
            msg = f"message #{i}".encode()
            frame = client_session.encrypt_frame(msg)
            assert server_session.decrypt_frame(frame) == msg

    def test_tampered_client_hello_fails(self):
        """
        Tampering with ClientHello bytes causes handshake failure because
        the derived secrets won't match, leading to MAC verification failure.
        """
        client = KEMTLSClient()
        server = KEMTLSServer()

        ch_bytes = client.initiate_handshake()

        # Tamper with a byte in the middle of the payload (ECC public key area)
        tampered = bytearray(ch_bytes)
        tampered[HEADER_SIZE + RANDOM_SIZE + SESSION_ID_SIZE + 5] ^= 0xFF
        tampered = bytes(tampered)

        # Server processes the tampered ClientHello — it will parse fine
        # but derive different shared secrets
        sh_bytes = server.process_client_hello(tampered)

        # Client processes ServerHello — session ID will mismatch
        # because the tampered ClientHello has the same session ID
        # but server's keys won't match. The crypto divergence shows
        # up when verifying MACs.
        cke_bytes = client.process_server_hello(sh_bytes)

        # Server's MAC verification should fail
        with pytest.raises(HandshakeError, match="MAC verification failed"):
            server.process_client_key_exchange(cke_bytes)

    def test_tampered_server_finished_fails(self):
        """Tampering with ServerFinished MAC causes client to reject."""
        client = KEMTLSClient()
        server = KEMTLSServer()

        ch = client.initiate_handshake()
        sh = server.process_client_hello(ch)
        cke = client.process_server_hello(sh)
        sf_bytes, _ = server.process_client_key_exchange(cke)

        # Tamper with the finished MAC
        tampered = bytearray(sf_bytes)
        tampered[-1] ^= 0xFF
        with pytest.raises(HandshakeError, match="MAC verification failed"):
            client.process_server_finished(bytes(tampered))

    def test_client_state_after_failure(self):
        """Client transitions to FAILED state on MAC verification failure."""
        client = KEMTLSClient()
        server = KEMTLSServer()

        ch = client.initiate_handshake()
        sh = server.process_client_hello(ch)
        cke = client.process_server_hello(sh)
        sf_bytes, _ = server.process_client_key_exchange(cke)

        tampered = bytearray(sf_bytes)
        tampered[-1] ^= 0xFF
        with pytest.raises(HandshakeError):
            client.process_server_finished(bytes(tampered))
        assert client.state == HandshakeState.FAILED


class TestStateValidation:
    """Tests for out-of-order state machine transitions."""

    def test_client_cannot_process_server_hello_before_init(self):
        """Client rejects ServerHello if handshake not yet initiated."""
        client = KEMTLSClient()
        dummy = os.urandom(2400)  # arbitrary bytes
        with pytest.raises(HandshakeError, match="Cannot process ServerHello"):
            client.process_server_hello(dummy)

    def test_client_cannot_initiate_twice(self):
        """Client rejects double initiation."""
        client = KEMTLSClient()
        client.initiate_handshake()
        with pytest.raises(HandshakeError, match="Cannot initiate"):
            client.initiate_handshake()

    def test_server_cannot_process_cke_before_ch(self):
        """Server rejects ClientKeyExchange before receiving ClientHello."""
        server = KEMTLSServer()
        dummy = os.urandom(1200)
        with pytest.raises(HandshakeError, match="Cannot process ClientKeyExchange"):
            server.process_client_key_exchange(dummy)

    def test_server_cannot_process_ch_twice(self):
        """Server rejects a second ClientHello after the first."""
        client = KEMTLSClient()
        server = KEMTLSServer()
        ch = client.initiate_handshake()
        server.process_client_hello(ch)
        with pytest.raises(HandshakeError, match="Cannot process ClientHello"):
            server.process_client_hello(ch)

    def test_client_cannot_process_finished_before_cke(self):
        """Client rejects ServerFinished if ClientKeyExchange hasn't been sent."""
        client = KEMTLSClient()
        client.initiate_handshake()
        dummy = os.urandom(100)
        with pytest.raises(HandshakeError, match="Cannot process ServerFinished"):
            client.process_server_finished(dummy)
