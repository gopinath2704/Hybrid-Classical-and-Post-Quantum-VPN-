"""
Signature-Free KEMTLS-Inspired Handshake — Unified Module.

Consolidates the entire handshake layer into a single file:
    §1  Wire Protocol       — Binary message types, headers, pack/unpack
    §2  Transcript Hasher   — SHA-256 cumulative transcript binding
    §3  Session Context     — HandshakeSession with AES-256-GCM frame cipher
    §4  Client State Machine — KEMTLSClient (initiator)
    §5  Server State Machine — KEMTLSServer (responder)

Protocol overview (1.5 RTT):
    Client → Server : ClientHello       (client ECC+PQC public keys)
    Server → Client : ServerHello       (server ECC+PQC public keys + KEM ciphertext)
    Client → Server : ClientKeyExchange (KEM ciphertext + finished MAC)
    Server → Client : ServerFinished    (finished MAC)

Security model:
    Both classical (X25519 ECDH) and post-quantum (ML-KEM / Kyber768) shared
    secrets are combined via HKDF-SHA256 to derive symmetric session keys.
    The handshake is authenticated through transcript MACs — any tampering
    causes immediate abort. The resulting AES-256-GCM session encrypts all
    subsequent data frames.
"""

from __future__ import annotations

import os
import enum
import hmac
import struct
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import from the consolidated crypto module
from crypto.hybrid_crypto import (
    HybridKEM,
    HybridKeyBundle,
    KeyManager,
    ALLOW_MOCK_PQC,
)


# ═══════════════════════════════════════════════════════════════════════════════
# §1  Wire Protocol — Binary Message Types, Headers, Pack / Unpack
# ═══════════════════════════════════════════════════════════════════════════════

# Wire-format constants
MAGIC = 0x4856          # "HV" — Hybrid VPN protocol magic bytes
PROTOCOL_VERSION = 0x10  # Version 1.0

# Fixed sizes (bytes) — matching Kyber768 NIST FIPS 203
RANDOM_SIZE = 32
SESSION_ID_SIZE = 32
ECC_PUBLIC_KEY_SIZE = 32
PQC_PUBLIC_KEY_SIZE = 1184       # Kyber768 public key
PQC_CIPHERTEXT_SIZE = 1088      # Kyber768 ciphertext
FINISHED_MAC_SIZE = 32           # HMAC-SHA256 tag

# Header: Magic(2) + Version(1) + Type(1) + Length(2) = 6 bytes
HEADER_FORMAT = "!HBBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 6 bytes


class MessageType(enum.IntEnum):
    """Handshake message type identifiers carried in the wire header."""
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    CLIENT_KEY_EXCHANGE = 0x03
    SERVER_FINISHED = 0x04
    REKEY_REQUEST = 0x05    # Initiator requests in-session key rotation
    REKEY_RESPONSE = 0x06  # Responder acknowledges with new cipher material
    HANDSHAKE_ERROR = 0xFF


class HandshakeError(Exception):
    """Raised when the handshake encounters a fatal protocol error."""
    pass


def _pack_header(msg_type: MessageType, payload_length: int) -> bytes:
    """
    Pack a 6-byte wire header.

    Format: Magic(2B) | Version(1B) | Type(1B) | PayloadLength(2B)
    All fields are big-endian (network byte order).
    """
    return struct.pack(HEADER_FORMAT, MAGIC, PROTOCOL_VERSION, msg_type, payload_length)


def _unpack_header(data: bytes) -> tuple[int, int, int, int]:
    """
    Unpack a 6-byte wire header.

    Returns:
        tuple: (magic, version, msg_type, payload_length)

    Raises:
        HandshakeError: If data is too short, magic is wrong, or version
                        is unsupported.
    """
    if len(data) < HEADER_SIZE:
        raise HandshakeError(
            f"Header too short: expected {HEADER_SIZE} bytes, got {len(data)}"
        )
    magic, version, msg_type, payload_length = struct.unpack(
        HEADER_FORMAT, data[:HEADER_SIZE]
    )
    if magic != MAGIC:
        raise HandshakeError(
            f"Invalid magic: expected 0x{MAGIC:04X}, got 0x{magic:04X}"
        )
    if version != PROTOCOL_VERSION:
        raise HandshakeError(
            f"Unsupported version: expected 0x{PROTOCOL_VERSION:02X}, "
            f"got 0x{version:02X}"
        )
    return magic, version, msg_type, payload_length


# ─── Message Data Classes ────────────────────────────────────────────────────


@dataclass
class ClientHello:
    """
    Client → Server: First handshake flight.

    Payload layout:
        client_random      (32B)
        session_id         (32B)
        ecc_public_key     (32B)
        pqc_public_key     (1184B)
    Total payload: 1,280 bytes
    """
    client_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_public_key: bytes

    def pack(self) -> bytes:
        """Serialize to wire bytes (header + payload)."""
        payload = (
            self.client_random
            + self.session_id
            + self.ecc_public_key
            + self.pqc_public_key
        )
        header = _pack_header(MessageType.CLIENT_HELLO, len(payload))
        return header + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientHello":
        """
        Deserialize from wire bytes.

        Args:
            data: Raw bytes including the 6-byte header.

        Returns:
            ClientHello: Parsed message.

        Raises:
            HandshakeError: On invalid header, wrong type, or bad length.
        """
        _, _, msg_type, payload_length = _unpack_header(data)
        if msg_type != MessageType.CLIENT_HELLO:
            raise HandshakeError(
                f"Expected CLIENT_HELLO (0x{MessageType.CLIENT_HELLO:02X}), "
                f"got 0x{msg_type:02X}"
            )

        payload = data[HEADER_SIZE:]
        expected = RANDOM_SIZE + SESSION_ID_SIZE + ECC_PUBLIC_KEY_SIZE + PQC_PUBLIC_KEY_SIZE
        if len(payload) < expected:
            raise HandshakeError(
                f"ClientHello payload too short: expected {expected}, got {len(payload)}"
            )

        offset = 0
        client_random = payload[offset: offset + RANDOM_SIZE]; offset += RANDOM_SIZE
        session_id = payload[offset: offset + SESSION_ID_SIZE]; offset += SESSION_ID_SIZE
        ecc_pk = payload[offset: offset + ECC_PUBLIC_KEY_SIZE]; offset += ECC_PUBLIC_KEY_SIZE
        pqc_pk = payload[offset: offset + PQC_PUBLIC_KEY_SIZE]

        return cls(
            client_random=client_random,
            session_id=session_id,
            ecc_public_key=ecc_pk,
            pqc_public_key=pqc_pk,
        )


@dataclass
class ServerHello:
    """
    Server → Client: Second handshake flight.

    Payload layout:
        server_random      (32B)
        session_id         (32B)    — echoed from ClientHello
        ecc_public_key     (32B)
        pqc_public_key     (1184B)
        pqc_ciphertext     (1088B)  — KEM ciphertext to client's PQC key
    Total payload: 2,368 bytes
    """
    server_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_public_key: bytes
    pqc_ciphertext: bytes

    def pack(self) -> bytes:
        """Serialize to wire bytes (header + payload)."""
        payload = (
            self.server_random
            + self.session_id
            + self.ecc_public_key
            + self.pqc_public_key
            + self.pqc_ciphertext
        )
        header = _pack_header(MessageType.SERVER_HELLO, len(payload))
        return header + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ServerHello":
        """
        Deserialize from wire bytes.

        Raises:
            HandshakeError: On invalid header, wrong type, or bad length.
        """
        _, _, msg_type, payload_length = _unpack_header(data)
        if msg_type != MessageType.SERVER_HELLO:
            raise HandshakeError(
                f"Expected SERVER_HELLO (0x{MessageType.SERVER_HELLO:02X}), "
                f"got 0x{msg_type:02X}"
            )

        payload = data[HEADER_SIZE:]
        expected = (
            RANDOM_SIZE + SESSION_ID_SIZE + ECC_PUBLIC_KEY_SIZE
            + PQC_PUBLIC_KEY_SIZE + PQC_CIPHERTEXT_SIZE
        )
        if len(payload) < expected:
            raise HandshakeError(
                f"ServerHello payload too short: expected {expected}, got {len(payload)}"
            )

        offset = 0
        server_random = payload[offset: offset + RANDOM_SIZE]; offset += RANDOM_SIZE
        session_id = payload[offset: offset + SESSION_ID_SIZE]; offset += SESSION_ID_SIZE
        ecc_pk = payload[offset: offset + ECC_PUBLIC_KEY_SIZE]; offset += ECC_PUBLIC_KEY_SIZE
        pqc_pk = payload[offset: offset + PQC_PUBLIC_KEY_SIZE]; offset += PQC_PUBLIC_KEY_SIZE
        pqc_ct = payload[offset: offset + PQC_CIPHERTEXT_SIZE]

        return cls(
            server_random=server_random,
            session_id=session_id,
            ecc_public_key=ecc_pk,
            pqc_public_key=pqc_pk,
            pqc_ciphertext=pqc_ct,
        )


@dataclass
class ClientKeyExchange:
    """
    Client → Server: Third handshake flight.

    Payload layout:
        pqc_ciphertext     (1088B)  — KEM ciphertext to server's PQC key
        finished_mac       (32B)    — HMAC-SHA256 over transcript hash
    Total payload: 1,120 bytes
    """
    pqc_ciphertext: bytes
    finished_mac: bytes

    def pack(self) -> bytes:
        """Serialize to wire bytes (header + payload)."""
        payload = self.pqc_ciphertext + self.finished_mac
        header = _pack_header(MessageType.CLIENT_KEY_EXCHANGE, len(payload))
        return header + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientKeyExchange":
        """
        Deserialize from wire bytes.

        Raises:
            HandshakeError: On invalid header, wrong type, or bad length.
        """
        _, _, msg_type, payload_length = _unpack_header(data)
        if msg_type != MessageType.CLIENT_KEY_EXCHANGE:
            raise HandshakeError(
                f"Expected CLIENT_KEY_EXCHANGE (0x{MessageType.CLIENT_KEY_EXCHANGE:02X}), "
                f"got 0x{msg_type:02X}"
            )

        payload = data[HEADER_SIZE:]
        expected = PQC_CIPHERTEXT_SIZE + FINISHED_MAC_SIZE
        if len(payload) < expected:
            raise HandshakeError(
                f"ClientKeyExchange payload too short: expected {expected}, "
                f"got {len(payload)}"
            )

        pqc_ct = payload[:PQC_CIPHERTEXT_SIZE]
        finished_mac = payload[PQC_CIPHERTEXT_SIZE: PQC_CIPHERTEXT_SIZE + FINISHED_MAC_SIZE]
        return cls(pqc_ciphertext=pqc_ct, finished_mac=finished_mac)


@dataclass
class ServerFinished:
    """
    Server → Client: Fourth (final) handshake flight.

    Payload layout:
        finished_mac       (32B)    — HMAC-SHA256 over transcript hash
    Total payload: 32 bytes
    """
    finished_mac: bytes

    def pack(self) -> bytes:
        """Serialize to wire bytes (header + payload)."""
        header = _pack_header(MessageType.SERVER_FINISHED, len(self.finished_mac))
        return header + self.finished_mac

    @classmethod
    def unpack(cls, data: bytes) -> "ServerFinished":
        """
        Deserialize from wire bytes.

        Raises:
            HandshakeError: On invalid header, wrong type, or bad length.
        """
        _, _, msg_type, payload_length = _unpack_header(data)
        if msg_type != MessageType.SERVER_FINISHED:
            raise HandshakeError(
                f"Expected SERVER_FINISHED (0x{MessageType.SERVER_FINISHED:02X}), "
                f"got 0x{msg_type:02X}"
            )

        payload = data[HEADER_SIZE:]
        if len(payload) < FINISHED_MAC_SIZE:
            raise HandshakeError(
                f"ServerFinished payload too short: expected {FINISHED_MAC_SIZE}, "
                f"got {len(payload)}"
            )
        return cls(finished_mac=payload[:FINISHED_MAC_SIZE])


# ═══════════════════════════════════════════════════════════════════════════════
# §2  Transcript Hasher — SHA-256 Cumulative Transcript Binding
# ═══════════════════════════════════════════════════════════════════════════════


class TranscriptHasher:
    """
    Accumulates handshake message bytes and computes a running SHA-256
    digest over the full transcript.

    Every packed message exchanged during the handshake is fed into this
    hasher. The current digest is used to compute Finished MACs, binding
    authentication to the exact byte sequence both parties observed.

    Usage:
        hasher = TranscriptHasher()
        hasher.update(client_hello_bytes)
        hasher.update(server_hello_bytes)
        digest = hasher.digest()   # 32-byte SHA-256 of all messages so far
    """

    def __init__(self) -> None:
        self._hash = hashlib.sha256()
        self._message_count = 0

    def update(self, data: bytes) -> None:
        """
        Feed raw message bytes (header + payload) into the transcript.

        Args:
            data: Complete wire-format message bytes.
        """
        self._hash.update(data)
        self._message_count += 1

    def digest(self) -> bytes:
        """
        Return the current 32-byte SHA-256 digest of the transcript.

        This does NOT finalize the hasher — subsequent updates are allowed.
        """
        return self._hash.copy().digest()

    @property
    def message_count(self) -> int:
        """Number of messages fed into the transcript so far."""
        return self._message_count

    def copy(self) -> "TranscriptHasher":
        """Return an independent copy of this hasher's state."""
        clone = TranscriptHasher()
        clone._hash = self._hash.copy()
        clone._message_count = self._message_count
        return clone


def _compute_finished_mac(
    transcript_digest: bytes,
    finished_key: bytes,
    label: bytes,
) -> bytes:
    """
    Compute a Finished MAC using HMAC-SHA256.

    Args:
        transcript_digest: Current 32-byte transcript hash.
        finished_key: 32-byte key derived from the handshake secret.
        label: Context label (b"client finished" or b"server finished").

    Returns:
        bytes: 32-byte HMAC tag.
    """
    return hmac.new(
        finished_key,
        label + transcript_digest,
        hashlib.sha256,
    ).digest()


def _verify_finished_mac(
    transcript_digest: bytes,
    finished_key: bytes,
    label: bytes,
    received_mac: bytes,
) -> bool:
    """
    Verify a Finished MAC in constant time.

    Returns:
        bool: True if the MAC is valid, False otherwise.
    """
    expected = _compute_finished_mac(transcript_digest, finished_key, label)
    return hmac.compare_digest(expected, received_mac)


# Finished MAC labels (distinct for client and server to prevent reflection)
_CLIENT_FINISHED_LABEL = b"client finished"
_SERVER_FINISHED_LABEL = b"server finished"

# HKDF info labels for handshake key derivation
_INFO_HANDSHAKE_SECRET = b"hybrid-vpn-handshake-secret"
_INFO_FINISHED_KEY = b"hybrid-vpn-finished-key"
_INFO_SESSION_ENC = b"hybrid-vpn-session-enc"
_INFO_SESSION_MAC = b"hybrid-vpn-session-mac"


# ═══════════════════════════════════════════════════════════════════════════════
# §3  Session Context — HandshakeSession with AES-256-GCM Frame Cipher
# ═══════════════════════════════════════════════════════════════════════════════


class HandshakeState(enum.Enum):
    """State machine states for the handshake lifecycle."""
    IDLE = "IDLE"
    CLIENT_HELLO_SENT = "CLIENT_HELLO_SENT"
    SERVER_HELLO_SENT = "SERVER_HELLO_SENT"
    KEY_EXCHANGE_SENT = "KEY_EXCHANGE_SENT"
    ESTABLISHED = "ESTABLISHED"
    FAILED = "FAILED"


@dataclass
class HandshakeSession:
    """
    Represents a fully established handshake session.

    After a successful KEMTLS exchange, this object holds:
    - The derived AES-256-GCM encryption key and MAC key.
    - An AESGCM cipher instance for frame-level encryption.
    - Session metadata (IDs, randoms, timing).

    Usage:
        session = HandshakeSession(...)
        ciphertext = session.encrypt_frame(b"hello world")
        plaintext  = session.decrypt_frame(ciphertext)
    """
    session_id: bytes
    encryption_key: bytes
    mac_key: bytes
    client_random: bytes
    server_random: bytes
    established_at: float = field(default_factory=time.time)
    _cipher: Optional[AESGCM] = field(default=None, repr=False)
    _seq_num: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        """Initialise the AES-256-GCM cipher from the encryption key."""
        if self._cipher is None:
            self._cipher = AESGCM(self.encryption_key)

    def encrypt_frame(self, plaintext: bytes) -> bytes:
        """
        Encrypt a data frame using AES-256-GCM.

        Format of returned bytes:
            nonce (12B) || ciphertext+tag (variable)

        The nonce is constructed as:
            seq_num (8B big-endian) || random_pad (4B)

        Args:
            plaintext: Raw data to encrypt.

        Returns:
            bytes: Nonce-prepended authenticated ciphertext.
        """
        # Build 12-byte nonce: 8-byte sequence number + 4-byte random
        nonce = struct.pack("!Q", self._seq_num) + os.urandom(4)
        self._seq_num += 1

        ciphertext = self._cipher.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_frame(self, frame: bytes) -> bytes:
        """
        Decrypt a data frame encrypted by encrypt_frame().

        Args:
            frame: Nonce-prepended ciphertext as returned by encrypt_frame().

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            HandshakeError: If the frame is too short or authentication fails.
        """
        nonce_size = 12
        if len(frame) < nonce_size + 16:  # 16-byte GCM tag minimum
            raise HandshakeError(
                f"Frame too short for decryption: {len(frame)} bytes"
            )
        nonce = frame[:nonce_size]
        ciphertext = frame[nonce_size:]

        try:
            return self._cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise HandshakeError(f"Frame decryption failed: {e}") from e

    def rekey(
        self,
        key_manager: Optional["KeyManager"] = None,
    ) -> bytes:
        """
        Perform in-session key rotation (forward secrecy ratchet).

        Derives a fresh AES-256-GCM encryption key and MAC key from the
        current key material plus a fresh random nonce, installs the new
        keys into the cipher, and securely zeroes the old keys.

        Returns:
            bytes: The 32-byte rekey nonce (for logging / audit only).
                   This should NOT be sent over the wire; each peer performs
                   rekeying independently using locally stored key material.
        """
        if key_manager is None:
            key_manager = KeyManager()

        rekey_nonce = os.urandom(32)

        # Derive successor keys from current encryption_key + fresh nonce
        new_enc_key, new_mac_key = key_manager.derive_rekey_pair(
            bytes(self.encryption_key) if isinstance(self.encryption_key, bytearray)
            else self.encryption_key,
            rekey_nonce,
        )

        # Securely erase old key material
        if isinstance(self.encryption_key, bytearray):
            import ctypes
            ctypes.memset(
                (ctypes.c_char * len(self.encryption_key))
                .from_buffer(self.encryption_key),
                0, len(self.encryption_key),
            )
        if isinstance(self.mac_key, bytearray):
            import ctypes
            ctypes.memset(
                (ctypes.c_char * len(self.mac_key))
                .from_buffer(self.mac_key),
                0, len(self.mac_key),
            )

        # Install new keys
        self.encryption_key = new_enc_key
        self.mac_key = new_mac_key
        self._cipher = AESGCM(new_enc_key)
        # Reset sequence counter for new cipher epoch
        self._seq_num = 0

        return rekey_nonce

    def secure_wipe(self) -> None:
        """
        Securely zero all session key material in memory.

        Call this on disconnect or session expiry to minimise the window
        during which keys are recoverable from process memory.
        """
        import ctypes

        def _wipe(buf: bytes | bytearray) -> None:
            ba = bytearray(buf) if isinstance(buf, bytes) else buf
            ctypes.memset(
                (ctypes.c_char * len(ba)).from_buffer(ba), 0, len(ba)
            )

        _wipe(self.encryption_key if isinstance(self.encryption_key, bytearray)
              else bytearray(self.encryption_key))
        _wipe(self.mac_key if isinstance(self.mac_key, bytearray)
              else bytearray(self.mac_key))
        self._cipher = None
        self._seq_num = 0

    def get_info(self) -> dict:
        """Return session metadata as a dictionary."""
        return {
            "session_id": self.session_id.hex(),
            "established_at": self.established_at,
            "encryption_key_size": len(self.encryption_key),
            "mac_key_size": len(self.mac_key),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# §4  Client State Machine — KEMTLSClient (Initiator)
# ═══════════════════════════════════════════════════════════════════════════════


class KEMTLSClient:
    """
    Client-side KEMTLS handshake state machine.

    Drives the initiator through the full handshake lifecycle:
        1. initiate_handshake()   → produces ClientHello wire bytes
        2. process_server_hello() → consumes ServerHello, produces ClientKeyExchange
        3. process_server_finished() → consumes ServerFinished, returns HandshakeSession

    Usage:
        client = KEMTLSClient()
        ch_bytes = client.initiate_handshake()
        # ... send ch_bytes, receive sh_bytes ...
        cke_bytes = client.process_server_hello(sh_bytes)
        # ... send cke_bytes, receive sf_bytes ...
        session = client.process_server_finished(sf_bytes)
        # session is now a HandshakeSession with AES-256-GCM
    """

    def __init__(
        self,
        pqc_algorithm: str = "Kyber768",
        allow_mock_pqc: bool = False,
    ) -> None:
        self._hybrid = HybridKEM(
            pqc_algorithm=pqc_algorithm,
            allow_mock_pqc=allow_mock_pqc or ALLOW_MOCK_PQC,
        )
        self._key_manager = KeyManager()
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

        # Ephemeral key material (populated during handshake)
        self._client_keys: Optional[HybridKeyBundle] = None
        self._client_random: Optional[bytes] = None
        self._session_id: Optional[bytes] = None

        # Derived secrets (populated after processing ServerHello)
        self._handshake_secret: Optional[bytes] = None
        self._finished_key: Optional[bytes] = None
        self._encryption_key: Optional[bytes] = None
        self._mac_key: Optional[bytes] = None
        self._server_random: Optional[bytes] = None

    @property
    def state(self) -> HandshakeState:
        """Current handshake state."""
        return self._state

    def initiate_handshake(self) -> bytes:
        """
        Start the handshake by generating a ClientHello message.

        Generates ephemeral ECC + PQC keypairs and a random session ID.

        Returns:
            bytes: Wire-format ClientHello message.

        Raises:
            HandshakeError: If not in IDLE state.
        """
        if self._state != HandshakeState.IDLE:
            raise HandshakeError(
                f"Cannot initiate handshake from state {self._state.value}"
            )

        # Generate ephemeral key material
        self._client_keys = self._hybrid.generate_keypairs()
        self._client_random = os.urandom(RANDOM_SIZE)
        self._session_id = os.urandom(SESSION_ID_SIZE)

        # Build and serialize ClientHello
        msg = ClientHello(
            client_random=self._client_random,
            session_id=self._session_id,
            ecc_public_key=self._client_keys.ecc_public,
            pqc_public_key=self._client_keys.pqc_public,
        )
        wire_bytes = msg.pack()

        # Update transcript
        self._transcript.update(wire_bytes)
        self._state = HandshakeState.CLIENT_HELLO_SENT

        return wire_bytes

    def process_server_hello(self, server_hello_bytes: bytes) -> bytes:
        """
        Process the ServerHello and produce a ClientKeyExchange.

        Performs:
        1. Parse ServerHello (server ECC/PQC keys + PQC ciphertext).
        2. Decapsulate the server's PQC ciphertext → pqc_shared_secret_1.
        3. Perform X25519 ECDH with server ECC key → ecc_shared_secret.
        4. Encapsulate towards server's PQC public key → pqc_shared_secret_2 + ciphertext.
        5. Combine all secrets via HKDF → handshake keys.
        6. Compute Finished MAC over transcript.

        Args:
            server_hello_bytes: Wire-format ServerHello message.

        Returns:
            bytes: Wire-format ClientKeyExchange message.

        Raises:
            HandshakeError: On state error, parse failure, or crypto failure.
        """
        if self._state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError(
                f"Cannot process ServerHello from state {self._state.value}"
            )

        # Parse ServerHello
        sh = ServerHello.unpack(server_hello_bytes)

        # Verify session ID echo
        if sh.session_id != self._session_id:
            raise HandshakeError("Session ID mismatch in ServerHello")

        self._server_random = sh.server_random

        # Update transcript with ServerHello
        self._transcript.update(server_hello_bytes)

        # --- Cryptographic operations ---

        # 1. X25519 ECDH → shared secret
        ecc_shared = self._hybrid.ecc.derive_shared_secret(
            self._client_keys.ecc_private, sh.ecc_public_key
        )

        # 2. Decapsulate server's PQC ciphertext (encrypted to our PQC public key)
        pqc_shared_1 = self._hybrid.pqc.decapsulate(
            self._client_keys.pqc_secret, sh.pqc_ciphertext
        )

        # 3. Encapsulate towards server's PQC public key
        pqc_ciphertext_to_server, pqc_shared_2 = self._hybrid.pqc.encapsulate(
            sh.pqc_public_key
        )

        # 4. Combine all shared secrets: ECC || PQC_1 || PQC_2
        combined_secret = ecc_shared + pqc_shared_1 + pqc_shared_2

        # 5. Derive handshake keys via HKDF
        salt = self._client_random + self._server_random
        self._handshake_secret = self._key_manager.derive_key(
            combined_secret, salt=salt, info=_INFO_HANDSHAKE_SECRET
        )
        self._finished_key = self._key_manager.derive_key(
            self._handshake_secret, salt=None, info=_INFO_FINISHED_KEY
        )
        self._encryption_key = self._key_manager.derive_key(
            self._handshake_secret, salt=None, info=_INFO_SESSION_ENC
        )
        self._mac_key = self._key_manager.derive_key(
            self._handshake_secret, salt=None, info=_INFO_SESSION_MAC
        )

        # 6. Compute Client Finished MAC
        transcript_digest = self._transcript.digest()
        client_finished_mac = _compute_finished_mac(
            transcript_digest, self._finished_key, _CLIENT_FINISHED_LABEL
        )

        # Build ClientKeyExchange
        cke = ClientKeyExchange(
            pqc_ciphertext=pqc_ciphertext_to_server,
            finished_mac=client_finished_mac,
        )
        cke_bytes = cke.pack()

        # Update transcript with ClientKeyExchange
        self._transcript.update(cke_bytes)
        self._state = HandshakeState.KEY_EXCHANGE_SENT

        return cke_bytes

    def process_server_finished(self, server_finished_bytes: bytes) -> HandshakeSession:
        """
        Process the ServerFinished message and establish the session.

        Verifies the server's transcript MAC. On success, returns a fully
        initialized HandshakeSession with AES-256-GCM encryption.

        Args:
            server_finished_bytes: Wire-format ServerFinished message.

        Returns:
            HandshakeSession: Ready for encrypted data transport.

        Raises:
            HandshakeError: On state error, MAC verification failure.
        """
        if self._state != HandshakeState.KEY_EXCHANGE_SENT:
            raise HandshakeError(
                f"Cannot process ServerFinished from state {self._state.value}"
            )

        # Parse ServerFinished
        sf = ServerFinished.unpack(server_finished_bytes)

        # Verify server finished MAC
        transcript_digest = self._transcript.digest()
        if not _verify_finished_mac(
            transcript_digest, self._finished_key,
            _SERVER_FINISHED_LABEL, sf.finished_mac
        ):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Server Finished MAC verification failed")

        # Update transcript with ServerFinished
        self._transcript.update(server_finished_bytes)
        self._state = HandshakeState.ESTABLISHED

        return HandshakeSession(
            session_id=self._session_id,
            encryption_key=self._encryption_key,
            mac_key=self._mac_key,
            client_random=self._client_random,
            server_random=self._server_random,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# §5  Server State Machine — KEMTLSServer (Responder)
# ═══════════════════════════════════════════════════════════════════════════════


class KEMTLSServer:
    """
    Server-side KEMTLS handshake state machine.

    Drives the responder through the full handshake lifecycle:
        1. process_client_hello()       → consumes ClientHello, produces ServerHello
        2. process_client_key_exchange() → consumes ClientKeyExchange, produces
                                           (ServerFinished bytes, HandshakeSession)

    Usage:
        server = KEMTLSServer()
        sh_bytes = server.process_client_hello(ch_bytes)
        # ... send sh_bytes, receive cke_bytes ...
        sf_bytes, session = server.process_client_key_exchange(cke_bytes)
        # ... send sf_bytes ...
        # session is now a HandshakeSession with AES-256-GCM
    """

    def __init__(
        self,
        pqc_algorithm: str = "Kyber768",
        allow_mock_pqc: bool = False,
    ) -> None:
        self._hybrid = HybridKEM(
            pqc_algorithm=pqc_algorithm,
            allow_mock_pqc=allow_mock_pqc or ALLOW_MOCK_PQC,
        )
        self._key_manager = KeyManager()
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

        # Ephemeral key material
        self._server_keys: Optional[HybridKeyBundle] = None
        self._server_random: Optional[bytes] = None
        self._session_id: Optional[bytes] = None
        self._client_random: Optional[bytes] = None

        # Peer key material (from ClientHello)
        self._client_ecc_public: Optional[bytes] = None
        self._client_pqc_public: Optional[bytes] = None

        # Derived secrets
        self._ecc_shared: Optional[bytes] = None
        self._pqc_shared_1: Optional[bytes] = None
        self._handshake_secret: Optional[bytes] = None
        self._finished_key: Optional[bytes] = None
        self._encryption_key: Optional[bytes] = None
        self._mac_key: Optional[bytes] = None

    @property
    def state(self) -> HandshakeState:
        """Current handshake state."""
        return self._state

    def process_client_hello(self, client_hello_bytes: bytes) -> bytes:
        """
        Process the ClientHello and produce a ServerHello.

        Performs:
        1. Parse ClientHello (client ECC/PQC public keys).
        2. Generate server ephemeral ECC + PQC keypairs.
        3. Perform X25519 ECDH → ecc_shared_secret.
        4. Encapsulate towards client's PQC key → pqc_shared_secret_1 + ciphertext.

        Args:
            client_hello_bytes: Wire-format ClientHello message.

        Returns:
            bytes: Wire-format ServerHello message.

        Raises:
            HandshakeError: On state error or parse failure.
        """
        if self._state != HandshakeState.IDLE:
            raise HandshakeError(
                f"Cannot process ClientHello from state {self._state.value}"
            )

        # Parse ClientHello
        ch = ClientHello.unpack(client_hello_bytes)

        # Update transcript
        self._transcript.update(client_hello_bytes)

        # Store client's material
        self._session_id = ch.session_id
        self._client_random = ch.client_random
        self._client_ecc_public = ch.ecc_public_key
        self._client_pqc_public = ch.pqc_public_key

        # Generate server ephemeral keys
        self._server_keys = self._hybrid.generate_keypairs()
        self._server_random = os.urandom(RANDOM_SIZE)

        # X25519 ECDH
        self._ecc_shared = self._hybrid.ecc.derive_shared_secret(
            self._server_keys.ecc_private, self._client_ecc_public
        )

        # KEM encapsulate towards client PQC public key
        pqc_ct_to_client, self._pqc_shared_1 = self._hybrid.pqc.encapsulate(
            self._client_pqc_public
        )

        # Build ServerHello
        sh = ServerHello(
            server_random=self._server_random,
            session_id=self._session_id,
            ecc_public_key=self._server_keys.ecc_public,
            pqc_public_key=self._server_keys.pqc_public,
            pqc_ciphertext=pqc_ct_to_client,
        )
        sh_bytes = sh.pack()

        # Update transcript
        self._transcript.update(sh_bytes)
        self._state = HandshakeState.SERVER_HELLO_SENT

        return sh_bytes

    def process_client_key_exchange(
        self, client_key_exchange_bytes: bytes
    ) -> tuple[bytes, HandshakeSession]:
        """
        Process the ClientKeyExchange and produce ServerFinished + session.

        Performs:
        1. Parse ClientKeyExchange (PQC ciphertext + finished MAC).
        2. Decapsulate client's PQC ciphertext → pqc_shared_secret_2.
        3. Combine all secrets: ECC || PQC_1 || PQC_2 → HKDF → keys.
        4. Verify client's finished MAC.
        5. Compute server finished MAC.

        Args:
            client_key_exchange_bytes: Wire-format ClientKeyExchange message.

        Returns:
            tuple: (ServerFinished wire bytes, HandshakeSession)

        Raises:
            HandshakeError: On state error, parse failure, or MAC mismatch.
        """
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError(
                f"Cannot process ClientKeyExchange from state {self._state.value}"
            )

        # Parse ClientKeyExchange
        cke = ClientKeyExchange.unpack(client_key_exchange_bytes)

        # Decapsulate client's PQC ciphertext (encrypted to our PQC key)
        pqc_shared_2 = self._hybrid.pqc.decapsulate(
            self._server_keys.pqc_secret, cke.pqc_ciphertext
        )

        # Combine all shared secrets: ECC || PQC_1 || PQC_2
        combined_secret = self._ecc_shared + self._pqc_shared_1 + pqc_shared_2

        # Derive handshake keys
        salt = self._client_random + self._server_random
        self._handshake_secret = self._key_manager.derive_key(
            combined_secret, salt=salt, info=_INFO_HANDSHAKE_SECRET
        )
        self._finished_key = self._key_manager.derive_key(
            self._handshake_secret, salt=None, info=_INFO_FINISHED_KEY
        )
        self._encryption_key = self._key_manager.derive_key(
            self._handshake_secret, salt=None, info=_INFO_SESSION_ENC
        )
        self._mac_key = self._key_manager.derive_key(
            self._handshake_secret, salt=None, info=_INFO_SESSION_MAC
        )

        # Verify client finished MAC
        # The transcript at this point contains: ClientHello + ServerHello
        # (ClientKeyExchange is NOT yet in the transcript for verification)
        transcript_digest = self._transcript.digest()
        if not _verify_finished_mac(
            transcript_digest, self._finished_key,
            _CLIENT_FINISHED_LABEL, cke.finished_mac
        ):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Client Finished MAC verification failed")

        # Update transcript with ClientKeyExchange
        self._transcript.update(client_key_exchange_bytes)

        # Compute server finished MAC (over transcript including CKE)
        server_transcript_digest = self._transcript.digest()
        server_finished_mac = _compute_finished_mac(
            server_transcript_digest, self._finished_key, _SERVER_FINISHED_LABEL
        )

        # Build ServerFinished
        sf = ServerFinished(finished_mac=server_finished_mac)
        sf_bytes = sf.pack()

        # Update transcript
        self._transcript.update(sf_bytes)
        self._state = HandshakeState.ESTABLISHED

        session = HandshakeSession(
            session_id=self._session_id,
            encryption_key=self._encryption_key,
            mac_key=self._mac_key,
            client_random=self._client_random,
            server_random=self._server_random,
        )

        return sf_bytes, session


# ─────────────────────────────────────────────────────────────────────────────
