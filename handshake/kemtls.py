"""Strict authenticated KEMTLS-inspired handshake and thread-safe record layer."""
from __future__ import annotations

import enum
import hashlib
import hmac
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, TypeVar

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from crypto.hybrid_crypto import HybridKEM, KeyManager, PQSignatureProvider, MLDSA44_PARAMS, _secure_zero
from vpn.identity import fingerprint, verify_client_signature

MAGIC = 0x4856
PROTOCOL_VERSION = 0x20
PROTOCOL_NAME = b"PQVPN-KEMTLS-INSPIRED-v2"
RANDOM_SIZE = 32
SESSION_ID_SIZE = 32
COMPACT_SESSION_ID_SIZE = 8
ECC_PUBLIC_KEY_SIZE = 32
PQC_PUBLIC_KEY_SIZE = 1184
PQC_CIPHERTEXT_SIZE = 1088
CLIENT_PUBLIC_KEY_SIZE = 32
CLIENT_SIGNATURE_SIZE = 64
FINISHED_MAC_SIZE = 32
IDENTITY_ID_SIZE = 32
HEADER_FORMAT = "!HBBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_HANDSHAKE_MESSAGE = 8192


class MessageType(enum.IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CLIENT_KEY_EXCHANGE = 3
    SERVER_FINISHED = 4
    COOKIE_CHALLENGE = 5
    COOKIE_RESPONSE = 6
    RESUMPTION_HELLO = 7
    RESUMPTION_ACCEPT = 8
    HANDSHAKE_ERROR = 0xFF


class FrameType(enum.IntEnum):
    DATA = 1
    UDP_BIND = 2
    UDP_BIND_ACK = 3
    PING = 4
    PONG = 5
    CLOSE = 6
    CONFIG = 7
    REKEY_REQUEST = 8
    REKEY_RESPONSE = 9
    ERROR = 10
    REHANDSHAKE_REQUEST = 11
    REHANDSHAKE_RESPONSE = 12
    RESUMPTION_TICKET = 13


class Direction(enum.IntEnum):
    CLIENT_TO_SERVER = 1
    SERVER_TO_CLIENT = 2


class Channel(enum.IntEnum):
    DATA = 1
    CONTROL = 2


class HandshakeError(Exception):
    pass


_T = TypeVar("_T")


def _primitive(operation: Callable[..., _T], *args: object) -> _T:
    """Run an X25519/ML-KEM primitive; malformed peer key material becomes a HandshakeError."""
    try:
        return operation(*args)
    except (ValueError, RuntimeError) as exc:
        raise HandshakeError(f"invalid peer key material ({type(exc).__name__})") from exc


def _pack_header(msg_type: MessageType, payload_length: int, version: int = PROTOCOL_VERSION) -> bytes:
    if payload_length <= 0 or payload_length > MAX_HANDSHAKE_MESSAGE - HEADER_SIZE:
        raise HandshakeError("invalid handshake payload length")
    return struct.pack(HEADER_FORMAT, MAGIC, version, int(msg_type), payload_length)


def _unpack_header(data: bytes, version: int = PROTOCOL_VERSION) -> tuple[int, int, int, int]:
    if len(data) < HEADER_SIZE:
        raise HandshakeError(f"Header too short: expected {HEADER_SIZE} bytes, got {len(data)}")
    magic, ver, msg_type, length = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    if magic != MAGIC:
        raise HandshakeError("Invalid magic")
    if ver != version:
        raise HandshakeError("Unsupported version")
    if length <= 0 or length > MAX_HANDSHAKE_MESSAGE - HEADER_SIZE:
        raise HandshakeError("invalid handshake payload length")
    if len(data) != HEADER_SIZE + length:
        raise HandshakeError("handshake header length mismatch")
    try:
        MessageType(msg_type)
    except ValueError as exc:
        raise HandshakeError("unexpected handshake message type") from exc
    return magic, ver, msg_type, length


def _fixed(data: bytes, wanted: MessageType, expected: int, version: int = PROTOCOL_VERSION) -> bytes:
    _, _, msg_type, length = _unpack_header(data, version)
    if msg_type != wanted:
        raise HandshakeError(f"Expected {wanted.name}")
    if length != expected:
        raise HandshakeError(f"{wanted.name} payload length mismatch")
    return data[HEADER_SIZE:]


def _fields(**values: tuple[bytes, int]) -> None:
    for name, (value, size) in values.items():
        if len(value) != size:
            raise HandshakeError(f"{name} must be exactly {size} bytes")


@dataclass(frozen=True)
class ClientHello:
    client_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_public_key: bytes
    client_public_key: bytes
    SIZE = 1312

    def pack(self) -> bytes:
        _fields(client_random=(self.client_random, 32), session_id=(self.session_id, 32),
                ecc_public_key=(self.ecc_public_key, 32), pqc_public_key=(self.pqc_public_key, 1184),
                client_public_key=(self.client_public_key, 32))
        payload = self.client_random + self.session_id + self.ecc_public_key + self.pqc_public_key + self.client_public_key
        return _pack_header(MessageType.CLIENT_HELLO, len(payload)) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientHello":
        payload = _fixed(data, MessageType.CLIENT_HELLO, cls.SIZE)
        return cls(payload[:32], payload[32:64], payload[64:96], payload[96:1280], payload[1280:])


@dataclass(frozen=True)
class ServerHello:
    server_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_ciphertext: bytes
    identity_id: bytes
    SIZE = 1216

    def pack(self) -> bytes:
        _fields(server_random=(self.server_random, 32), session_id=(self.session_id, 32),
                ecc_public_key=(self.ecc_public_key, 32), pqc_ciphertext=(self.pqc_ciphertext, 1088),
                identity_id=(self.identity_id, 32))
        payload = self.server_random + self.session_id + self.ecc_public_key + self.pqc_ciphertext + self.identity_id
        return _pack_header(MessageType.SERVER_HELLO, len(payload)) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ServerHello":
        payload = _fixed(data, MessageType.SERVER_HELLO, cls.SIZE)
        return cls(payload[:32], payload[32:64], payload[64:96], payload[96:1184], payload[1184:])


@dataclass(frozen=True)
class ClientKeyExchange:
    identity_ciphertext: bytes
    client_signature: bytes
    finished_mac: bytes
    SIZE = 1184

    def unsigned(self) -> bytes:
        return self.identity_ciphertext

    def pack(self) -> bytes:
        _fields(identity_ciphertext=(self.identity_ciphertext, 1088),
                client_signature=(self.client_signature, 64), finished_mac=(self.finished_mac, 32))
        payload = self.identity_ciphertext + self.client_signature + self.finished_mac
        return _pack_header(MessageType.CLIENT_KEY_EXCHANGE, len(payload)) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientKeyExchange":
        payload = _fixed(data, MessageType.CLIENT_KEY_EXCHANGE, cls.SIZE)
        return cls(payload[:1088], payload[1088:1152], payload[1152:])


@dataclass(frozen=True)
class ServerFinished:
    finished_mac: bytes

    def pack(self) -> bytes:
        _fields(finished_mac=(self.finished_mac, 32))
        return _pack_header(MessageType.SERVER_FINISHED, 32) + self.finished_mac

    @classmethod
    def unpack(cls, data: bytes) -> "ServerFinished":
        return cls(_fixed(data, MessageType.SERVER_FINISHED, 32))


COOKIE_SIZE = 32
COOKIE_BUCKET_SECONDS = 120


class CookieProtector:
    """Stateless HMAC cookie for DoS resistance (WireGuard pattern)."""

    def __init__(self, bucket_seconds: int = COOKIE_BUCKET_SECONDS) -> None:
        self._bucket = bucket_seconds
        self._secret = os.urandom(32)
        self._prev_secret = os.urandom(32)
        self._rotated_at = time.monotonic()

    def _rotate_if_needed(self) -> None:
        now = time.monotonic()
        if now - self._rotated_at >= self._bucket:
            self._prev_secret = self._secret
            self._secret = os.urandom(32)
            self._rotated_at = now

    def _mac(self, secret: bytes, client_ip: str, client_port: int) -> bytes:
        msg = client_ip.encode() + struct.pack("!H", client_port)
        return hmac.new(secret, msg, hashlib.sha256).digest()

    def generate(self, client_ip: str, client_port: int) -> bytes:
        self._rotate_if_needed()
        return self._mac(self._secret, client_ip, client_port)

    def verify(self, cookie: bytes, client_ip: str, client_port: int) -> bool:
        if len(cookie) != COOKIE_SIZE:
            return False
        self._rotate_if_needed()
        for secret in (self._secret, self._prev_secret):
            if hmac.compare_digest(cookie, self._mac(secret, client_ip, client_port)):
                return True
        return False


def pack_cookie_challenge(cookie: bytes, version: int = PROTOCOL_VERSION) -> bytes:
    if len(cookie) != COOKIE_SIZE:
        raise HandshakeError("invalid cookie size")
    fmt = HEADER_FORMAT
    return struct.pack(fmt, MAGIC, version, int(MessageType.COOKIE_CHALLENGE), COOKIE_SIZE) + cookie


def unpack_cookie_challenge(data: bytes) -> bytes:
    if len(data) < HEADER_SIZE:
        raise HandshakeError("cookie challenge too short")
    magic, version, msg_type, length = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    if magic != MAGIC:
        raise HandshakeError("Invalid magic")
    if msg_type != MessageType.COOKIE_CHALLENGE:
        raise HandshakeError("expected COOKIE_CHALLENGE")
    if length != COOKIE_SIZE:
        raise HandshakeError("invalid cookie challenge length")
    return data[HEADER_SIZE:HEADER_SIZE + COOKIE_SIZE]


def pack_cookie_response(cookie: bytes, client_hello: bytes, version: int = PROTOCOL_VERSION) -> bytes:
    if len(cookie) != COOKIE_SIZE:
        raise HandshakeError("invalid cookie size")
    payload = cookie + client_hello
    return struct.pack(HEADER_FORMAT, MAGIC, version, int(MessageType.COOKIE_RESPONSE), len(payload)) + payload


def unpack_cookie_response(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < HEADER_SIZE:
        raise HandshakeError("cookie response too short")
    magic, version, msg_type, length = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    if magic != MAGIC:
        raise HandshakeError("Invalid magic")
    if msg_type != MessageType.COOKIE_RESPONSE:
        raise HandshakeError("expected COOKIE_RESPONSE")
    payload = data[HEADER_SIZE:HEADER_SIZE + length]
    if len(payload) < COOKIE_SIZE + HEADER_SIZE:
        raise HandshakeError("cookie response payload too short")
    return payload[:COOKIE_SIZE], payload[COOKIE_SIZE:]


class TranscriptHasher:
    def __init__(self) -> None:
        self._hash = hashlib.sha256()
        self._message_count = 0

    def update(self, data: bytes) -> None:
        self._hash.update(data)
        self._message_count += 1

    def digest(self) -> bytes:
        return self._hash.copy().digest()

    @property
    def message_count(self) -> int:
        return self._message_count

    def copy(self) -> "TranscriptHasher":
        other = TranscriptHasher()
        other._hash = self._hash.copy()
        other._message_count = self._message_count
        return other


def _compute_finished_mac(digest: bytes, key: bytes, label: bytes) -> bytes:
    return hmac.new(key, label + digest, hashlib.sha256).digest()


def _verify_finished_mac(digest: bytes, key: bytes, label: bytes, value: bytes) -> bool:
    return hmac.compare_digest(_compute_finished_mac(digest, key, label), value)


_CLIENT_FINISHED_LABEL = b"client finished"
_SERVER_FINISHED_LABEL = b"server finished"


def _expand(prk: bytes, label: bytes, context: bytes, length: int) -> bytes:
    info = PROTOCOL_NAME + b"|" + label + b"|" + context
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


_SECRET_SPECS = (
    ("client_finished_key", b"client finished", 32),
    ("server_finished_key", b"server finished", 32),
    ("data_c2s_key", b"data c2s key", 32),
    ("data_s2c_key", b"data s2c key", 32),
    ("data_c2s_nonce_base", b"data c2s nonce", 12),
    ("data_s2c_nonce_base", b"data s2c nonce", 12),
    ("control_c2s_key", b"control c2s key", 32),
    ("control_s2c_key", b"control s2c key", 32),
    ("control_c2s_nonce_base", b"control c2s nonce", 12),
    ("control_s2c_nonce_base", b"control s2c nonce", 12),
    ("rekey_secret", b"rekey", 32),
    ("control_confirm_key", b"control confirm", 32),
)


@dataclass
class TrafficSecrets:
    client_finished_key: bytearray
    server_finished_key: bytearray
    data_c2s_key: bytearray
    data_s2c_key: bytearray
    data_c2s_nonce_base: bytearray
    data_s2c_nonce_base: bytearray
    control_c2s_key: bytearray
    control_s2c_key: bytearray
    control_c2s_nonce_base: bytearray
    control_s2c_nonce_base: bytearray
    rekey_secret: bytearray
    control_confirm_key: bytearray

    @property
    def client_to_server_key(self): return self.data_c2s_key
    @property
    def server_to_client_key(self): return self.data_s2c_key
    @property
    def client_to_server_nonce_base(self): return self.data_c2s_nonce_base
    @property
    def server_to_client_nonce_base(self): return self.data_s2c_nonce_base
    @property
    def control_key(self): return self.control_confirm_key

    def wipe(self) -> None:
        for value in vars(self).values():
            if isinstance(value, bytearray):
                _secure_zero(value)


def _derive_secrets(seed: bytes, context: bytes) -> TrafficSecrets:
    return TrafficSecrets(*[
        bytearray(_expand(seed, label, context, size)) for _, label, size in _SECRET_SPECS
    ])


def derive_schedule(hybrid_input: bytes, client_random: bytes, server_random: bytes,
                    session_id: bytes, transcript_hash: bytes) -> TrafficSecrets:
    context = (PROTOCOL_NAME + bytes([PROTOCOL_VERSION]) + b"|X25519|ML-KEM-768|AES-256-GCM|"
               + session_id + client_random + server_random + transcript_hash)
    salt = hashlib.sha256(b"pqvpn extract" + client_random + server_random + session_id).digest()
    master = KeyManager().derive_key(hybrid_input, salt=salt, info=b"pqvpn master secret")
    return _derive_secrets(master, context)


DATA_MAGIC = b"PV"
DATA_HEADER_FORMAT = "!2sBBBB8sIQ"
DATA_HEADER_SIZE = struct.calcsize(DATA_HEADER_FORMAT)  # 26 bytes
GCM_TAG_SIZE = 16
DATA_FRAME_OVERHEAD = DATA_HEADER_SIZE + GCM_TAG_SIZE  # 42 bytes
MAX_SEQUENCE = (1 << 64) - 1


class ReplayWindow:
    def __init__(self, size: int = 128) -> None:
        self.size = size
        self.highest = -1
        self.bitmap = 0

    def check(self, sequence: int) -> None:
        if sequence < 0 or sequence > MAX_SEQUENCE:
            raise HandshakeError("invalid sequence")
        if self.highest >= 0:
            delta = self.highest - sequence
            if delta >= self.size:
                raise HandshakeError("packet is outside replay window")
            if delta >= 0 and self.bitmap & (1 << delta):
                raise HandshakeError("replayed packet")

    def commit(self, sequence: int) -> None:
        if sequence > self.highest:
            shift = sequence - self.highest
            self.bitmap = 1 if shift >= self.size else ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            self.highest = sequence
        else:
            self.bitmap |= 1 << (self.highest - sequence)


class HandshakeState(enum.Enum):
    IDLE = "IDLE"
    CLIENT_HELLO_SENT = "CLIENT_HELLO_SENT"
    SERVER_HELLO_SENT = "SERVER_HELLO_SENT"
    KEY_EXCHANGE_SENT = "KEY_EXCHANGE_SENT"
    ESTABLISHED = "ESTABLISHED"
    FAILED = "FAILED"


# pqvpn_core ValueError kinds -> the messages HandshakeSession raises for the same rejection.
_RUST_REJECTIONS = {
    "short": "Frame too short", "header": "invalid record protocol or channel", "frame_type": "invalid frame type",
    "unexpected_type": "unexpected frame type", "binding": "wrong session, epoch, or direction",
    "replayed": "replayed packet", "outside_window": "packet is outside replay window", "tag": "Frame decryption failed",
    "closed": "session closed", "epoch": "non-monotonic epoch", "control_type": "control frame type requires encrypt_control",
    "exhausted": "sequence exhausted; rekey required", "invalid_key": "invalid data-plane key",
    "data_type": "data frame type requires encrypt_frame", "control_sequence": "unexpected control sequence",
    "control_tag": "Control decryption failed",
}


def _core():
    # Fails loudly without the Rust core: a rust-mode session never falls back to Python.
    import pqvpn_core
    return pqvpn_core


def _rust_data_session(*args: object) -> object:
    return _core().DataSession(*args)


def _rust(call: Callable[..., _T], *args: object) -> _T:
    """Runs a pqvpn_core call; its ValueError carries Python's message (or a record-layer kind) for HandshakeError."""
    try:
        return call(*args)
    except ValueError as exc:
        raise HandshakeError(_RUST_REJECTIONS.get(str(exc), str(exc))) from exc


def _rust_handshake(handshake: str, data_plane: str, allow_mock_pqc: bool) -> bool:
    """True for handshake="rust", which needs the Rust data plane (it owns the data keys) and has no mock PQC."""
    if handshake not in ("python", "rust"):
        raise ValueError("handshake must be python or rust")
    if handshake == "python":
        return False
    if data_plane != "rust":
        raise ValueError('handshake = "rust" requires data_plane = "rust"')
    if allow_mock_pqc:
        raise ValueError('handshake = "rust" has no mock PQC')
    return True


class RustHandshakeSession:
    """What a handshake="rust" handshake returns: HandshakeSession's surface, without `secrets`. Every key stays in
    pqvpn_core; Python gets sealed frames, plaintexts and the shared data-channel object, as with data_plane="rust"."""

    data_plane = "rust"

    def __init__(self, session: object, client_id: str = "") -> None:
        self._session, self._data = session, session.data()
        self.session_id, self.role = bytes(session.session_id), session.role
        self.protocol_version, self.client_id = session.protocol_version, client_id
        self.established_at, self.epoch = time.time(), 0

    def _changed(self) -> None:
        self.epoch = self._session.epoch

    def encrypt_control(self, plaintext: bytes, frame_type: FrameType) -> bytes:
        if frame_type not in HandshakeSession._CONTROL_TYPES:
            raise HandshakeError("data frame type requires encrypt_frame")
        return _rust(self._session.seal_control, int(frame_type), plaintext)

    def decrypt_control(self, frame: bytes, expected_type: FrameType | None = None) -> tuple[FrameType, bytes]:
        frame_type, plaintext = _rust(self._session.open_control, frame, None if expected_type is None else int(expected_type))
        return FrameType(frame_type), plaintext

    def encrypt_frame(self, plaintext: bytes, frame_type: FrameType = FrameType.DATA) -> bytes:
        raise HandshakeError("data channel is owned by the Rust data plane")

    decrypt_frame = encrypt_frame

    def seal_data(self, plaintext: bytes, frame_type: FrameType = FrameType.DATA) -> bytes:
        return _rust(self._data.seal, int(frame_type), plaintext)

    def open_data(self, frame: bytes, expected_type: FrameType | None = None) -> tuple[FrameType, bytes]:
        frame_type, plaintext = _rust(self._data.open, frame, None if expected_type is None else int(expected_type))
        return FrameType(frame_type), plaintext

    def begin_rekey(self) -> bytes:
        return _rust(self._session.begin_rekey)

    def finish_rekey(self, response: bytes) -> None:
        _rust(self._session.finish_rekey, response)
        self._changed()

    def respond_rekey(self, request: bytes) -> bytes:
        frame = _rust(self._session.respond_rekey, request)
        self._changed()
        return frame

    def begin_rehandshake(self) -> bytes:
        return _rust(self._session.begin_rehandshake)

    def finish_rehandshake(self, response: bytes) -> None:
        _rust(self._session.finish_rehandshake, response)
        self._changed()

    def respond_rehandshake(self, request: bytes) -> bytes:
        frame = _rust(self._session.respond_rehandshake, request)
        self._changed()
        return frame

    def abort_epoch_change(self) -> None:
        self._session.abort_epoch_change()

    def issue_ticket(self, ticket_key: object, lifetime: int, assigned_ip: str) -> bytes:
        return _rust(self._session.issue_ticket, ticket_key, self.client_id, lifetime, assigned_ip)

    def save_ticket(self, path: object, fingerprint: str, protocol_version: int, ticket: bytes) -> None:
        """Rust writes the ticket file itself; the resumption secret never reaches Python. Raises OSError."""
        self._session.save_ticket(str(path), fingerprint, protocol_version, ticket)

    def secure_wipe(self) -> None:
        self._session.close()

    def get_info(self) -> dict:
        return {"session_id": self.session_id.hex(), "established_at": self.established_at,
                "epoch": self.epoch, "role": self.role, "encryption_key_size": 32}


def _rust_step(owner: object, call: Callable[..., _T], *args: object, to: "HandshakeState") -> _T:
    """One delegated handshake step; a failure leaves the handshake FAILED (the Rust machine is spent)."""
    try:
        result = _rust(call, *args)
    except HandshakeError:
        owner._state = HandshakeState.FAILED
        raise
    owner._state = to
    return result


def _identity(identity: object, make: Callable[[], object]) -> object:
    """A prebuilt pqvpn_core.Identity is used as is; key material from Python is handed down once."""
    return identity if isinstance(identity, _core().Identity) else _rust(make)


@dataclass
class HandshakeSession:
    session_id: bytes
    secrets: TrafficSecrets
    client_random: bytes
    server_random: bytes
    role: str
    client_id: str = ""
    established_at: float = field(default_factory=time.time)
    epoch: int = 0
    protocol_version: int = field(default=PROTOCOL_VERSION)
    # Fixed at construction: with "rust", Python never holds data-channel ciphers, so no data
    # (key, nonce) can be sealed on both sides of a handoff.
    data_plane: str = "python"
    _data_send_sequence: int = field(default=0, repr=False)
    _control_send_sequence: int = field(default=0, repr=False)
    _control_receive_sequence: int = field(default=0, repr=False)
    _data_replay: ReplayWindow = field(default_factory=ReplayWindow, repr=False)
    _data_send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _data_receive_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _control_send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _control_receive_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _epoch_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _closed: bool = field(default=False, repr=False)
    _data: object | None = field(default=None, repr=False)
    # A client's epoch change between its request and the confirmation: (kind, epoch, request, state).
    _pending: tuple | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.role not in {"client", "server"} or len(self.session_id) != 32:
            raise ValueError("invalid session role or id")
        if self.data_plane not in {"python", "rust"}:
            raise ValueError("data_plane must be python or rust")
        self._install()

    def _install(self) -> None:
        if self.role == "client":
            self.send_direction, self.recv_direction = Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT
            data_send, data_recv = self.secrets.data_c2s_key, self.secrets.data_s2c_key
            data_send_nonce, data_recv_nonce = self.secrets.data_c2s_nonce_base, self.secrets.data_s2c_nonce_base
            control_send, control_recv = self.secrets.control_c2s_key, self.secrets.control_s2c_key
            control_send_nonce, control_recv_nonce = self.secrets.control_c2s_nonce_base, self.secrets.control_s2c_nonce_base
        else:
            self.send_direction, self.recv_direction = Direction.SERVER_TO_CLIENT, Direction.CLIENT_TO_SERVER
            data_send, data_recv = self.secrets.data_s2c_key, self.secrets.data_c2s_key
            data_send_nonce, data_recv_nonce = self.secrets.data_s2c_nonce_base, self.secrets.data_c2s_nonce_base
            control_send, control_recv = self.secrets.control_s2c_key, self.secrets.control_c2s_key
            control_send_nonce, control_recv_nonce = self.secrets.control_s2c_nonce_base, self.secrets.control_c2s_nonce_base
        self._control_send_cipher, self._control_recv_cipher = AESGCM(bytes(control_send)), AESGCM(bytes(control_recv))
        self._control_send_nonce_base, self._control_recv_nonce_base = control_send_nonce, control_recv_nonce
        if self.data_plane == "python":
            self._data_send_cipher, self._data_recv_cipher = AESGCM(bytes(data_send)), AESGCM(bytes(data_recv))
            self._data_send_nonce_base, self._data_recv_nonce_base = data_send_nonce, data_recv_nonce
            return
        # Rust copies the four data secrets straight from these bytearrays; then Python's copies are wiped.
        keys = (data_send, data_send_nonce, data_recv, data_recv_nonce)
        try:
            if self._data is None:
                self._data = _rust_data_session(self.role, self.session_id, self.protocol_version, self.epoch, *keys)
            else:
                self._data.rekey(self.epoch, *keys)
        except ValueError as exc:
            raise HandshakeError(_RUST_REJECTIONS.get(str(exc), str(exc))) from exc
        finally:
            for secret in keys:
                _secure_zero(secret)

    @staticmethod
    def _nonce(base: bytearray, sequence: int) -> bytes:
        encoded = b"\0" * 4 + sequence.to_bytes(8, "big")
        return bytes(a ^ b for a, b in zip(base, encoded))

    def _encrypt(self, plaintext: bytes, frame_type: FrameType, channel: Channel) -> bytes:
        if channel == Channel.DATA and self.data_plane == "rust":
            raise HandshakeError("data channel is owned by the Rust data plane")
        lock = self._data_send_lock if channel == Channel.DATA else self._control_send_lock
        with lock:
            if self._closed:
                raise HandshakeError("session closed")
            sequence = self._data_send_sequence if channel == Channel.DATA else self._control_send_sequence
            if sequence == MAX_SEQUENCE:
                raise HandshakeError("sequence exhausted; rekey required")
            header = struct.pack(DATA_HEADER_FORMAT, DATA_MAGIC, self.protocol_version, int(channel), int(frame_type),
                                 int(self.send_direction), self.session_id[:8], self.epoch, sequence)
            cipher = self._data_send_cipher if channel == Channel.DATA else self._control_send_cipher
            nonce_base = self._data_send_nonce_base if channel == Channel.DATA else self._control_send_nonce_base
            result = header + cipher.encrypt(self._nonce(nonce_base, sequence), plaintext, header)
            if channel == Channel.DATA:
                self._data_send_sequence += 1
            else:
                self._control_send_sequence += 1
            return result

    _CONTROL_TYPES = frozenset({
        FrameType.CONFIG, FrameType.REKEY_REQUEST, FrameType.REKEY_RESPONSE,
        FrameType.REHANDSHAKE_REQUEST, FrameType.REHANDSHAKE_RESPONSE,
        FrameType.CLOSE, FrameType.ERROR, FrameType.RESUMPTION_TICKET,
    })

    def encrypt_frame(self, plaintext: bytes, frame_type: FrameType = FrameType.DATA) -> bytes:
        if frame_type in self._CONTROL_TYPES:
            raise HandshakeError("control frame type requires encrypt_control")
        return self._encrypt(plaintext, frame_type, Channel.DATA)

    def encrypt_control(self, plaintext: bytes, frame_type: FrameType) -> bytes:
        if frame_type not in self._CONTROL_TYPES:
            raise HandshakeError("data frame type requires encrypt_frame")
        return self._encrypt(plaintext, frame_type, Channel.CONTROL)

    def _decrypt(self, frame: bytes, channel: Channel, expected_type: FrameType | None) -> tuple[FrameType, bytes]:
        if channel == Channel.DATA and self.data_plane == "rust":
            raise HandshakeError("data channel is owned by the Rust data plane")
        if len(frame) < DATA_FRAME_OVERHEAD:
            raise HandshakeError("Frame too short")
        header = frame[:DATA_HEADER_SIZE]
        magic, version, wire_channel, wire_type, direction, session_id, epoch, sequence = struct.unpack(DATA_HEADER_FORMAT, header)
        if magic != DATA_MAGIC or version != self.protocol_version or wire_channel != channel:
            raise HandshakeError("invalid record protocol or channel")
        try:
            frame_type = FrameType(wire_type)
        except ValueError as exc:
            raise HandshakeError("invalid frame type") from exc
        if expected_type is not None and frame_type != expected_type:
            raise HandshakeError("unexpected frame type")
        if channel == Channel.DATA:
            with self._data_receive_lock:
                if session_id != self.session_id[:8] or epoch != self.epoch or direction != self.recv_direction:
                    raise HandshakeError("wrong session, epoch, or direction")
                if self._closed:
                    raise HandshakeError("session closed")
                self._data_replay.check(sequence)
                try:
                    plaintext = self._data_recv_cipher.decrypt(self._nonce(self._data_recv_nonce_base, sequence), frame[DATA_HEADER_SIZE:], header)
                except InvalidTag as exc:
                    raise HandshakeError("Frame decryption failed") from exc
                self._data_replay.commit(sequence)
                return frame_type, plaintext
        with self._control_receive_lock:
            if session_id != self.session_id[:8] or epoch != self.epoch or direction != self.recv_direction:
                raise HandshakeError("wrong session, epoch, or direction")
            if self._control_recv_cipher is None:
                raise HandshakeError("session closed")
            if sequence != self._control_receive_sequence:
                raise HandshakeError("unexpected control sequence")
            try:
                plaintext = self._control_recv_cipher.decrypt(self._nonce(self._control_recv_nonce_base, sequence), frame[DATA_HEADER_SIZE:], header)
            except InvalidTag as exc:
                raise HandshakeError("Control decryption failed") from exc
            self._control_receive_sequence += 1
            return frame_type, plaintext

    def decrypt_frame(self, frame: bytes, expected_type: FrameType | None = None) -> tuple[FrameType, bytes]:
        return self._decrypt(frame, Channel.DATA, expected_type)

    def decrypt_control(self, frame: bytes, expected_type: FrameType | None = None) -> tuple[FrameType, bytes]:
        return self._decrypt(frame, Channel.CONTROL, expected_type)

    def seal_data(self, plaintext: bytes, frame_type: FrameType = FrameType.DATA) -> bytes:
        """Seal on the data channel with whichever data plane owns it."""
        if self.data_plane == "python":
            return self.encrypt_frame(plaintext, frame_type)
        try:
            return self._data.seal(int(frame_type), plaintext)
        except ValueError as exc:
            raise HandshakeError(_RUST_REJECTIONS.get(str(exc), str(exc))) from exc

    def open_data(self, frame: bytes, expected_type: FrameType | None = None) -> tuple[FrameType, bytes]:
        """Open a data-channel frame with whichever data plane owns it."""
        if self.data_plane == "python":
            return self.decrypt_frame(frame, expected_type)
        try:
            frame_type, plaintext = self._data.open(frame, None if expected_type is None else int(expected_type))
        except ValueError as exc:
            raise HandshakeError(_RUST_REJECTIONS.get(str(exc), str(exc))) from exc
        return FrameType(frame_type), plaintext

    def derive_next_epoch(self, epoch: int, nonce: bytes) -> TrafficSecrets:
        with self._epoch_lock:
            if self._closed:
                raise HandshakeError("session closed")
            if epoch != self.epoch + 1 or len(nonce) != 32:
                raise HandshakeError("invalid rekey epoch or nonce")
            context = self.session_id + epoch.to_bytes(4, "big") + nonce
            seed = _expand(bytes(self.secrets.rekey_secret), b"epoch", context, 32)
            return _derive_secrets(seed, context)

    def derive_rehandshake_epoch(self, epoch: int, dh_shared_secret: bytes,
                                  kem_shared_secret: bytes,
                                  transcript: bytes) -> TrafficSecrets:
        with self._epoch_lock:
            if self._closed:
                raise HandshakeError("session closed")
            if epoch != self.epoch + 1:
                raise HandshakeError("invalid rehandshake epoch")
            if len(dh_shared_secret) != 32 or len(kem_shared_secret) != 32:
                raise HandshakeError("invalid rehandshake shared secrets")
            if not transcript:
                raise HandshakeError("empty rehandshake transcript")
            transcript_hash = hashlib.sha256(transcript).digest()
            context = self.session_id + epoch.to_bytes(4, "big") + transcript_hash
            ikm = (bytes(self.secrets.rekey_secret) + dh_shared_secret
                   + kem_shared_secret + epoch.to_bytes(4, "big"))
            seed = hashlib.sha256(ikm).digest()
            return _derive_secrets(seed, context)

    def activate_epoch(self, epoch: int, secrets: TrafficSecrets) -> None:
        with self._epoch_lock, self._data_send_lock, self._data_receive_lock, self._control_send_lock, self._control_receive_lock:
            if self._closed:
                raise HandshakeError("session closed")
            if epoch != self.epoch + 1:
                raise HandshakeError("non-monotonic epoch")
            old = self.secrets
            self.secrets = secrets
            self.epoch = epoch
            self._data_send_sequence = 0
            self._control_send_sequence = 0
            self._control_receive_sequence = 0
            self._data_replay = ReplayWindow()
            self._install()
            old.wipe()

    def secure_wipe(self) -> None:
        with self._epoch_lock, self._data_send_lock, self._data_receive_lock, self._control_send_lock, self._control_receive_lock:
            self._closed = True
            self.secrets.wipe()
            if self._data is not None:
                self._data.close()
            self._data_send_cipher = self._data_recv_cipher = None
            self._control_send_cipher = self._control_recv_cipher = None

    def get_info(self) -> dict:
        return {"session_id": self.session_id.hex(), "established_at": self.established_at,
                "epoch": self.epoch, "role": self.role, "encryption_key_size": 32}

    # Epoch changes and tickets, shared with RustHandshakeSession so vpn/runtime.py never touches a secret.
    # Rekey is confirmed under the old control_confirm key, rehandshake under the new one.

    def _take_pending(self, kind: str) -> tuple:
        pending, self._pending = self._pending, None
        if pending is None or pending[0] != kind:
            self._wipe_pending(pending)
            raise HandshakeError("no rekey or rehandshake in progress")
        return pending

    @staticmethod
    def _wipe_pending(pending: tuple | None) -> None:
        if pending and pending[0] == "rekey":
            pending[3].wipe()

    def abort_epoch_change(self) -> None:
        pending, self._pending = self._pending, None
        self._wipe_pending(pending)

    def begin_rekey(self) -> bytes:
        """Client: the sealed REKEY_REQUEST; the next epoch is derived now and held until confirmed."""
        if self._pending is not None:
            raise HandshakeError("rekey/rehandshake already in progress")
        epoch, nonce = self.epoch + 1, os.urandom(32)
        request = struct.pack("!I", epoch) + nonce
        pending = self.derive_next_epoch(epoch, nonce)
        frame = self.encrypt_control(request, FrameType.REKEY_REQUEST)
        self._pending = ("rekey", epoch, request, pending)
        return frame

    def finish_rekey(self, response: bytes) -> None:
        _, epoch, request, pending = self._take_pending("rekey")
        expected = hmac.new(bytes(self.secrets.control_confirm_key), b"rekey response" + request, hashlib.sha256).digest()
        if response[:4] != request[:4] or not hmac.compare_digest(response[4:], expected):
            pending.wipe()
            raise HandshakeError("invalid rekey confirmation")
        self.activate_epoch(epoch, pending)

    def respond_rekey(self, request: bytes) -> bytes:
        """Server: derives the next epoch, seals the confirmation under the old keys, then activates."""
        if len(request) != 36:
            raise HandshakeError("invalid rekey request")
        epoch, nonce = struct.unpack("!I", request[:4])[0], request[4:]
        next_keys = self.derive_next_epoch(epoch, nonce)
        confirmation = hmac.new(bytes(self.secrets.control_confirm_key), b"rekey response" + request, hashlib.sha256).digest()
        frame = self.encrypt_control(request[:4] + confirmation, FrameType.REKEY_RESPONSE)
        self.activate_epoch(epoch, next_keys)
        return frame

    def begin_rehandshake(self) -> bytes:
        """Client: the sealed REHANDSHAKE_REQUEST with fresh X25519 and ML-KEM keys, held until the reply."""
        if self._pending is not None:
            raise HandshakeError("rekey/rehandshake already in progress")
        epoch = self.epoch + 1
        hybrid = HybridKEM("ML-KEM-768")
        dh_private, dh_public = hybrid.ecc.generate_keypair()
        kem_secret, kem_public = hybrid.pqc.generate_keypair()
        request = struct.pack("!I", epoch) + dh_public + kem_public
        frame = self.encrypt_control(request, FrameType.REHANDSHAKE_REQUEST)
        self._pending = ("rehandshake", epoch, request, (hybrid, dh_private, kem_secret))
        return frame

    def finish_rehandshake(self, response: bytes) -> None:
        _, epoch, request, (hybrid, dh_private, kem_secret) = self._take_pending("rehandshake")
        if len(response) != 4 + 32 + 1088 + 32:
            raise HandshakeError("invalid rehandshake response length")
        if struct.unpack("!I", response[:4])[0] != epoch:
            raise HandshakeError("rehandshake epoch mismatch")
        body, confirmation = response[:4 + 32 + 1088], response[4 + 32 + 1088:]
        dh_ss = _primitive(hybrid.ecc.derive_shared_secret, dh_private, body[4:36])
        k_mlkem = _primitive(hybrid.pqc.decapsulate, kem_secret, body[36:])
        transcript = request + body
        pending = self.derive_rehandshake_epoch(epoch, dh_ss, k_mlkem, transcript)
        expected = hmac.new(bytes(pending.control_confirm_key), b"rehandshake confirm" + transcript, hashlib.sha256).digest()
        if not hmac.compare_digest(confirmation, expected):
            pending.wipe()
            raise HandshakeError("rehandshake key confirmation failed")
        self.activate_epoch(epoch, pending)

    def respond_rehandshake(self, request: bytes) -> bytes:
        """Server: fresh X25519 and an encapsulation to the client's new key; sealed under the old keys."""
        if len(request) != 4 + 32 + 1184:
            raise HandshakeError("invalid rehandshake request")
        epoch = struct.unpack("!I", request[:4])[0]
        hybrid = HybridKEM("ML-KEM-768")
        server_private, server_public = hybrid.ecc.generate_keypair()
        dh_ss = _primitive(hybrid.ecc.derive_shared_secret, server_private, request[4:36])
        ct, k_mlkem = _primitive(hybrid.pqc.encapsulate, request[36:])
        body = struct.pack("!I", epoch) + server_public + ct
        transcript = request + body
        next_keys = self.derive_rehandshake_epoch(epoch, dh_ss, k_mlkem, transcript)
        confirmation = hmac.new(bytes(next_keys.control_confirm_key), b"rehandshake confirm" + transcript, hashlib.sha256).digest()
        frame = self.encrypt_control(body + confirmation, FrameType.REHANDSHAKE_RESPONSE)
        self.activate_epoch(epoch, next_keys)
        return frame

    def issue_ticket(self, ticket_key: "ResumptionTicketKey", lifetime: int, assigned_ip: str) -> bytes:
        return ticket_key.issue(bytes(self.secrets.rekey_secret), self.client_id, self.protocol_version, lifetime, assigned_ip)


class KEMTLSClient:
    def __init__(self, server_identity_public: bytes, server_fingerprint: str,
                 client_private_key: Ed25519PrivateKey, allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        self.data_plane = data_plane
        self._state, self._rust = HandshakeState.IDLE, None
        if _rust_handshake(handshake, data_plane, allow_mock_pqc):
            identity = _identity(client_private_key, lambda: _core().Identity.ed25519(client_private_key.private_bytes_raw()))
            self._rust = _rust(_core().ClientHandshake, PROTOCOL_VERSION, server_identity_public, server_fingerprint, identity)
            return
        expected = fingerprint(server_identity_public)
        if len(server_identity_public) != 1184 or not hmac.compare_digest(expected, server_fingerprint.lower()):
            raise HandshakeError("server identity fingerprint mismatch")
        self.identity_public = server_identity_public
        self.identity_id = bytes.fromhex(expected)
        self.client_private = client_private_key
        self.client_public = client_private_key.public_key().public_bytes_raw()
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def initiate_handshake(self) -> bytes:
        if self._rust:
            return _rust_step(self, self._rust.hello, to=HandshakeState.CLIENT_HELLO_SENT)
        if self._state != HandshakeState.IDLE:
            raise HandshakeError("Cannot initiate handshake")
        self.keys = self._hybrid.generate_keypairs()
        self.client_random, self.session_id = os.urandom(32), os.urandom(32)
        wire = ClientHello(self.client_random, self.session_id, self.keys.ecc_public,
                           self.keys.pqc_public, self.client_public).pack()
        self._transcript.update(wire)
        self._state = HandshakeState.CLIENT_HELLO_SENT
        return wire

    def process_server_hello(self, wire: bytes) -> bytes:
        if self._rust:
            return _rust_step(self, self._rust.on_server_hello, wire, to=HandshakeState.KEY_EXCHANGE_SENT)
        if self._state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError("Cannot process ServerHello")
        hello = ServerHello.unpack(wire)
        if hello.session_id != self.session_id:
            raise HandshakeError("Session ID mismatch")
        if not hmac.compare_digest(hello.identity_id, self.identity_id):
            raise HandshakeError("server identity substitution detected")
        self._transcript.update(wire)
        self.server_random = hello.server_random
        ecc = _primitive(self._hybrid.ecc.derive_shared_secret, self.keys.ecc_private, hello.ecc_public_key)
        ephemeral_pq = _primitive(self._hybrid.pqc.decapsulate, self.keys.pqc_secret, hello.pqc_ciphertext)
        identity_ciphertext, identity_secret = _primitive(self._hybrid.pqc.encapsulate, self.identity_public)
        digest = self._transcript.digest()
        self.schedule = derive_schedule(ecc + ephemeral_pq + identity_secret, self.client_random,
                                        self.server_random, self.session_id, digest)
        signed = PROTOCOL_NAME + b" client proof " + digest + identity_ciphertext
        signature = self.client_private.sign(signed)
        partial = identity_ciphertext + signature
        finished = _compute_finished_mac(hashlib.sha256(digest + partial).digest(),
                                         bytes(self.schedule.client_finished_key), _CLIENT_FINISHED_LABEL)
        exchange = ClientKeyExchange(identity_ciphertext, signature, finished).pack()
        self._transcript.update(exchange)
        self._state = HandshakeState.KEY_EXCHANGE_SENT
        return exchange

    def process_server_finished(self, wire: bytes) -> HandshakeSession:
        if self._rust:
            return RustHandshakeSession(_rust_step(self, self._rust.on_server_finished, wire, to=HandshakeState.ESTABLISHED))
        if self._state != HandshakeState.KEY_EXCHANGE_SENT:
            raise HandshakeError("Cannot process ServerFinished")
        finished = ServerFinished.unpack(wire)
        if not _verify_finished_mac(self._transcript.digest(), bytes(self.schedule.server_finished_key),
                                    _SERVER_FINISHED_LABEL, finished.finished_mac):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Server Finished MAC verification failed")
        self._transcript.update(wire)
        self._state = HandshakeState.ESTABLISHED
        return HandshakeSession(self.session_id, self.schedule, self.client_random, self.server_random, "client", data_plane=self.data_plane)


class KEMTLSServer:
    def __init__(self, server_identity_secret: bytes, server_identity_public: bytes,
                 authorize_client: Callable[[bytes], dict | None], allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        self.data_plane = data_plane
        if len(server_identity_public) != 1184:
            raise ValueError("invalid server identity public key")
        self.identity_id = bytes.fromhex(fingerprint(server_identity_public))
        self.authorize_client = authorize_client
        self._state, self._rust = HandshakeState.IDLE, None
        if _rust_handshake(handshake, data_plane, allow_mock_pqc):
            identity = _identity(server_identity_secret, lambda: _core().Identity.kem(server_identity_secret, server_identity_public))
            self._rust = _rust(_core().ServerHandshake, PROTOCOL_VERSION, identity)
            return
        self.identity_secret = server_identity_secret
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def process_client_hello(self, wire: bytes) -> bytes:
        if self._rust:
            # Authorization happens here, between parsing the hello and any server key material.
            authorization = self.authorize_client(_rust_step(self, self._rust.client_identity, wire, to=self._state))
            if not authorization:
                self._state = HandshakeState.FAILED
                raise HandshakeError("unauthorized client")
            self.authz = authorization
            return _rust_step(self, self._rust.respond, to=HandshakeState.SERVER_HELLO_SENT)
        if self._state != HandshakeState.IDLE:
            raise HandshakeError("Cannot process ClientHello")
        hello = ClientHello.unpack(wire)
        authorization = self.authorize_client(hello.client_public_key)
        if not authorization:
            self._state = HandshakeState.FAILED
            raise HandshakeError("unauthorized client")
        self.authz, self.ch = authorization, hello
        self._transcript.update(wire)
        self.server_ecc_private, server_ecc_public = self._hybrid.ecc.generate_keypair()
        self.server_random = os.urandom(32)
        self.ecc = _primitive(self._hybrid.ecc.derive_shared_secret, self.server_ecc_private, hello.ecc_public_key)
        ciphertext, self.ephemeral_pq = _primitive(self._hybrid.pqc.encapsulate, hello.pqc_public_key)
        response = ServerHello(self.server_random, hello.session_id, server_ecc_public,
                               ciphertext, self.identity_id).pack()
        self._transcript.update(response)
        self._state = HandshakeState.SERVER_HELLO_SENT
        return response

    def process_client_key_exchange(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
        if self._rust:
            finished, session = _rust_step(self, self._rust.on_key_exchange, wire, to=HandshakeState.ESTABLISHED)
            return finished, RustHandshakeSession(session, self.authz.get("client_id", ""))
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError("Cannot process ClientKeyExchange")
        exchange = ClientKeyExchange.unpack(wire)
        digest = self._transcript.digest()
        identity_secret = _primitive(self._hybrid.pqc.decapsulate, self.identity_secret, exchange.identity_ciphertext)
        schedule = derive_schedule(self.ecc + self.ephemeral_pq + identity_secret, self.ch.client_random,
                                   self.server_random, self.ch.session_id, digest)
        try:
            verify_client_signature(self.ch.client_public_key, exchange.client_signature,
                                    PROTOCOL_NAME + b" client proof " + digest + exchange.unsigned())
        except InvalidSignature as exc:
            self._state = HandshakeState.FAILED
            raise HandshakeError("client identity proof failed") from exc
        partial = exchange.unsigned() + exchange.client_signature
        if not _verify_finished_mac(hashlib.sha256(digest + partial).digest(),
                                    bytes(schedule.client_finished_key), _CLIENT_FINISHED_LABEL,
                                    exchange.finished_mac):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Client Finished MAC verification failed")
        self._transcript.update(wire)
        finished = ServerFinished(_compute_finished_mac(self._transcript.digest(),
                                  bytes(schedule.server_finished_key), _SERVER_FINISHED_LABEL)).pack()
        self._transcript.update(finished)
        self._state = HandshakeState.ESTABLISHED
        session = HandshakeSession(self.ch.session_id, schedule, self.ch.client_random,
                                   self.server_random, "server", self.authz.get("client_id", ""), data_plane=self.data_plane)
        return finished, session


PROTOCOL_VERSION_V3 = 0x30
PROTOCOL_NAME_V3 = b"PQVPN-KEMTLS-v3"




@dataclass(frozen=True)
class ClientHelloV3:
    client_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_public_key: bytes
    client_identity_hash: bytes
    SIZE = 1312

    def pack(self) -> bytes:
        _fields(client_random=(self.client_random, 32), session_id=(self.session_id, 32),
                ecc_public_key=(self.ecc_public_key, 32), pqc_public_key=(self.pqc_public_key, 1184),
                client_identity_hash=(self.client_identity_hash, 32))
        payload = (self.client_random + self.session_id + self.ecc_public_key
                   + self.pqc_public_key + self.client_identity_hash)
        return _pack_header(MessageType.CLIENT_HELLO, len(payload), PROTOCOL_VERSION_V3) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientHelloV3":
        payload = _fixed(data, MessageType.CLIENT_HELLO, cls.SIZE, PROTOCOL_VERSION_V3)
        return cls(payload[:32], payload[32:64], payload[64:96],
                   payload[96:1280], payload[1280:])


@dataclass(frozen=True)
class ServerHelloV3:
    server_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_ciphertext: bytes
    identity_id: bytes
    client_ciphertext: bytes
    SIZE = 2304

    def pack(self) -> bytes:
        _fields(server_random=(self.server_random, 32), session_id=(self.session_id, 32),
                ecc_public_key=(self.ecc_public_key, 32), pqc_ciphertext=(self.pqc_ciphertext, 1088),
                identity_id=(self.identity_id, 32), client_ciphertext=(self.client_ciphertext, 1088))
        payload = (self.server_random + self.session_id + self.ecc_public_key
                   + self.pqc_ciphertext + self.identity_id + self.client_ciphertext)
        return _pack_header(MessageType.SERVER_HELLO, len(payload), PROTOCOL_VERSION_V3) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ServerHelloV3":
        payload = _fixed(data, MessageType.SERVER_HELLO, cls.SIZE, PROTOCOL_VERSION_V3)
        return cls(payload[:32], payload[32:64], payload[64:96],
                   payload[96:1184], payload[1184:1216], payload[1216:])


@dataclass(frozen=True)
class ClientKeyExchangeV3:
    server_ciphertext: bytes
    finished_mac: bytes
    SIZE = 1120

    def pack(self) -> bytes:
        _fields(server_ciphertext=(self.server_ciphertext, 1088),
                finished_mac=(self.finished_mac, 32))
        payload = self.server_ciphertext + self.finished_mac
        return _pack_header(MessageType.CLIENT_KEY_EXCHANGE, len(payload), PROTOCOL_VERSION_V3) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientKeyExchangeV3":
        payload = _fixed(data, MessageType.CLIENT_KEY_EXCHANGE, cls.SIZE, PROTOCOL_VERSION_V3)
        return cls(payload[:1088], payload[1088:])


class ServerFinishedV3:
    def __init__(self, finished_mac: bytes):
        self.finished_mac = finished_mac

    def pack(self) -> bytes:
        _fields(finished_mac=(self.finished_mac, 32))
        return _pack_header(MessageType.SERVER_FINISHED, 32, PROTOCOL_VERSION_V3) + self.finished_mac

    @classmethod
    def unpack(cls, data: bytes) -> "ServerFinishedV3":
        return cls(_fixed(data, MessageType.SERVER_FINISHED, 32, PROTOCOL_VERSION_V3))


def derive_schedule_v3(hybrid_input: bytes, static_input: bytes,
                       client_random: bytes, server_random: bytes,
                       session_id: bytes, transcript_hash: bytes) -> TrafficSecrets:
    context = (PROTOCOL_NAME_V3 + bytes([PROTOCOL_VERSION_V3])
               + b"|X25519|ML-KEM-768|AES-256-GCM|"
               + session_id + client_random + server_random + transcript_hash)
    salt = hashlib.sha256(b"pqvpn extract" + client_random + server_random + session_id).digest()
    km = KeyManager()
    handshake_secret = km.derive_key(hybrid_input, salt=salt, info=b"pqvpn v3 handshake secret")
    auth_salt = hashlib.sha256(handshake_secret + transcript_hash).digest()
    master = km.derive_key(handshake_secret + static_input, salt=auth_salt,
                           info=b"pqvpn v3 authenticated master")
    return _derive_secrets(master, context)


class KEMTLSClientV3:
    def __init__(self, server_identity_public: bytes, server_fingerprint: str,
                 client_static_secret: bytes, client_static_public: bytes,
                 allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        self.data_plane = data_plane
        self._state, self._rust = HandshakeState.IDLE, None
        if _rust_handshake(handshake, data_plane, allow_mock_pqc):
            identity = _identity(client_static_secret, lambda: _core().Identity.kem(client_static_secret, client_static_public))
            self._rust = _rust(_core().ClientHandshake, PROTOCOL_VERSION_V3, server_identity_public, server_fingerprint, identity)
            return
        expected = fingerprint(server_identity_public)
        if len(server_identity_public) != 1184 or not hmac.compare_digest(expected, server_fingerprint.lower()):
            raise HandshakeError("server identity fingerprint mismatch")
        if len(client_static_secret) != 2400 or len(client_static_public) != 1184:
            raise HandshakeError("invalid client ML-KEM-768 identity")
        self.server_identity_public = server_identity_public
        self.server_identity_id = bytes.fromhex(expected)
        self.client_static_secret = client_static_secret
        self.client_static_public = client_static_public
        self.client_identity_hash = bytes.fromhex(fingerprint(client_static_public))
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def initiate_handshake(self) -> bytes:
        if self._rust:
            return _rust_step(self, self._rust.hello, to=HandshakeState.CLIENT_HELLO_SENT)
        if self._state != HandshakeState.IDLE:
            raise HandshakeError("Cannot initiate handshake")
        self.keys = self._hybrid.generate_keypairs()
        self.client_random, self.session_id = os.urandom(32), os.urandom(32)
        wire = ClientHelloV3(self.client_random, self.session_id, self.keys.ecc_public,
                             self.keys.pqc_public, self.client_identity_hash).pack()
        self._transcript.update(wire)
        self._state = HandshakeState.CLIENT_HELLO_SENT
        return wire

    def process_server_hello(self, wire: bytes) -> bytes:
        if self._rust:
            return _rust_step(self, self._rust.on_server_hello, wire, to=HandshakeState.KEY_EXCHANGE_SENT)
        if self._state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError("Cannot process ServerHello")
        hello = ServerHelloV3.unpack(wire)
        if hello.session_id != self.session_id:
            raise HandshakeError("Session ID mismatch")
        if not hmac.compare_digest(hello.identity_id, self.server_identity_id):
            raise HandshakeError("server identity substitution detected")
        self._transcript.update(wire)
        self.server_random = hello.server_random

        ecc_ss = _primitive(self._hybrid.ecc.derive_shared_secret, self.keys.ecc_private, hello.ecc_public_key)
        k_eph = _primitive(self._hybrid.pqc.decapsulate, self.keys.pqc_secret, hello.pqc_ciphertext)
        k_c = _primitive(self._hybrid.pqc.decapsulate, self.client_static_secret, hello.client_ciphertext)
        server_ct, k_s = _primitive(self._hybrid.pqc.encapsulate, self.server_identity_public)

        digest = self._transcript.digest()
        self.schedule = derive_schedule_v3(
            ecc_ss + k_eph, k_s + k_c,
            self.client_random, self.server_random, self.session_id, digest)

        finished = _compute_finished_mac(
            hashlib.sha256(digest + server_ct).digest(),
            bytes(self.schedule.client_finished_key), _CLIENT_FINISHED_LABEL)
        exchange = ClientKeyExchangeV3(server_ct, finished).pack()
        self._transcript.update(exchange)
        self._state = HandshakeState.KEY_EXCHANGE_SENT
        return exchange

    def process_server_finished(self, wire: bytes) -> HandshakeSession:
        if self._rust:
            return RustHandshakeSession(_rust_step(self, self._rust.on_server_finished, wire, to=HandshakeState.ESTABLISHED))
        if self._state != HandshakeState.KEY_EXCHANGE_SENT:
            raise HandshakeError("Cannot process ServerFinished")
        finished = ServerFinishedV3.unpack(wire)
        if not _verify_finished_mac(self._transcript.digest(),
                                    bytes(self.schedule.server_finished_key),
                                    _SERVER_FINISHED_LABEL, finished.finished_mac):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Server Finished MAC verification failed")
        self._transcript.update(wire)
        self._state = HandshakeState.ESTABLISHED
        return HandshakeSession(self.session_id, self.schedule,
                                self.client_random, self.server_random, "client",
                                protocol_version=PROTOCOL_VERSION_V3, data_plane=self.data_plane)


class KEMTLSServerV3:
    def __init__(self, server_identity_secret: bytes, server_identity_public: bytes,
                 find_client_kem_key: Callable[[str], tuple[bytes, dict] | None],
                 allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        self.data_plane = data_plane
        if len(server_identity_public) != 1184:
            raise ValueError("invalid server identity public key")
        self.identity_public = server_identity_public
        self.identity_id = bytes.fromhex(fingerprint(server_identity_public))
        self.find_client_kem_key = find_client_kem_key
        self._state, self._rust = HandshakeState.IDLE, None
        if _rust_handshake(handshake, data_plane, allow_mock_pqc):
            identity = _identity(server_identity_secret, lambda: _core().Identity.kem(server_identity_secret, server_identity_public))
            self._rust = _rust(_core().ServerHandshake, PROTOCOL_VERSION_V3, identity)
            return
        self.identity_secret = server_identity_secret
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def process_client_hello(self, wire: bytes) -> bytes:
        if self._rust:
            identity_hash = _rust_step(self, self._rust.client_identity, wire, to=self._state)
            result = self.find_client_kem_key(identity_hash.hex())
            if result is None:
                self._state = HandshakeState.FAILED
                raise HandshakeError("unauthorized client")
            client_kem_public, self.authz = result
            return _rust_step(self, self._rust.respond, client_kem_public, to=HandshakeState.SERVER_HELLO_SENT)
        if self._state != HandshakeState.IDLE:
            raise HandshakeError("Cannot process ClientHello")
        hello = ClientHelloV3.unpack(wire)
        result = self.find_client_kem_key(hello.client_identity_hash.hex())
        if result is None:
            self._state = HandshakeState.FAILED
            raise HandshakeError("unauthorized client")
        client_kem_public, self.authz = result
        if len(client_kem_public) != 1184:
            self._state = HandshakeState.FAILED
            raise HandshakeError("invalid client ML-KEM public key in store")
        if not hmac.compare_digest(bytes.fromhex(fingerprint(client_kem_public)),
                                   hello.client_identity_hash):
            self._state = HandshakeState.FAILED
            raise HandshakeError("client identity hash mismatch")
        self.ch = hello
        self.client_kem_public = client_kem_public
        self._transcript.update(wire)

        self.server_ecc_private, server_ecc_public = self._hybrid.ecc.generate_keypair()
        self.server_random = os.urandom(32)
        self.ecc_ss = _primitive(self._hybrid.ecc.derive_shared_secret, self.server_ecc_private, hello.ecc_public_key)
        eph_ct, self.k_eph = _primitive(self._hybrid.pqc.encapsulate, hello.pqc_public_key)
        client_ct, self.k_c = _primitive(self._hybrid.pqc.encapsulate, client_kem_public)

        response = ServerHelloV3(self.server_random, hello.session_id, server_ecc_public,
                                 eph_ct, self.identity_id, client_ct).pack()
        self._transcript.update(response)
        self._state = HandshakeState.SERVER_HELLO_SENT
        return response

    def process_client_key_exchange(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
        if self._rust:
            finished, session = _rust_step(self, self._rust.on_key_exchange, wire, to=HandshakeState.ESTABLISHED)
            return finished, RustHandshakeSession(session, self.authz.get("client_id", ""))
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError("Cannot process ClientKeyExchange")
        exchange = ClientKeyExchangeV3.unpack(wire)
        digest = self._transcript.digest()

        k_s = _primitive(self._hybrid.pqc.decapsulate, self.identity_secret, exchange.server_ciphertext)
        schedule = derive_schedule_v3(
            self.ecc_ss + self.k_eph, k_s + self.k_c,
            self.ch.client_random, self.server_random, self.ch.session_id, digest)

        if not _verify_finished_mac(
                hashlib.sha256(digest + exchange.server_ciphertext).digest(),
                bytes(schedule.client_finished_key), _CLIENT_FINISHED_LABEL,
                exchange.finished_mac):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Client Finished MAC verification failed")

        self._transcript.update(wire)
        finished = ServerFinishedV3(_compute_finished_mac(
            self._transcript.digest(),
            bytes(schedule.server_finished_key), _SERVER_FINISHED_LABEL)).pack()
        self._transcript.update(finished)
        self._state = HandshakeState.ESTABLISHED
        session = HandshakeSession(self.ch.session_id, schedule, self.ch.client_random,
                                   self.server_random, "server", self.authz.get("client_id", ""),
                                   protocol_version=PROTOCOL_VERSION_V3, data_plane=self.data_plane)
        return finished, session


PROTOCOL_VERSION_V3_MLDSA = 0x31


def _refuse_mldsa_rust(handshake: str) -> None:
    if handshake != "python":
        raise ValueError("v3-mldsa is not supported by the Rust handshake")
PROTOCOL_NAME_V3_MLDSA = b"PQVPN-MLDSA-v3"
MLDSA_SIG_SIZE = MLDSA44_PARAMS["signature_length"]  # 2420




@dataclass(frozen=True)
class ClientHelloMLDSA:
    client_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_public_key: bytes
    client_identity_hash: bytes
    SIZE = 1312

    def pack(self) -> bytes:
        _fields(client_random=(self.client_random, 32), session_id=(self.session_id, 32),
                ecc_public_key=(self.ecc_public_key, 32), pqc_public_key=(self.pqc_public_key, 1184),
                client_identity_hash=(self.client_identity_hash, 32))
        payload = (self.client_random + self.session_id + self.ecc_public_key
                   + self.pqc_public_key + self.client_identity_hash)
        return _pack_header(MessageType.CLIENT_HELLO, len(payload), PROTOCOL_VERSION_V3_MLDSA) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientHelloMLDSA":
        payload = _fixed(data, MessageType.CLIENT_HELLO, cls.SIZE, PROTOCOL_VERSION_V3_MLDSA)
        return cls(payload[:32], payload[32:64], payload[64:96],
                   payload[96:1280], payload[1280:])


@dataclass(frozen=True)
class ServerHelloMLDSA:
    server_random: bytes
    session_id: bytes
    ecc_public_key: bytes
    pqc_ciphertext: bytes
    identity_id: bytes
    SIZE = 1216

    def pack(self) -> bytes:
        _fields(server_random=(self.server_random, 32), session_id=(self.session_id, 32),
                ecc_public_key=(self.ecc_public_key, 32), pqc_ciphertext=(self.pqc_ciphertext, 1088),
                identity_id=(self.identity_id, 32))
        payload = (self.server_random + self.session_id + self.ecc_public_key
                   + self.pqc_ciphertext + self.identity_id)
        return _pack_header(MessageType.SERVER_HELLO, len(payload), PROTOCOL_VERSION_V3_MLDSA) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ServerHelloMLDSA":
        payload = _fixed(data, MessageType.SERVER_HELLO, cls.SIZE, PROTOCOL_VERSION_V3_MLDSA)
        return cls(payload[:32], payload[32:64], payload[64:96],
                   payload[96:1184], payload[1184:])


@dataclass(frozen=True)
class ClientKeyExchangeMLDSA:
    server_ciphertext: bytes
    mldsa_signature: bytes
    finished_mac: bytes
    SIZE = 3540

    def pack(self) -> bytes:
        _fields(server_ciphertext=(self.server_ciphertext, 1088),
                mldsa_signature=(self.mldsa_signature, MLDSA_SIG_SIZE),
                finished_mac=(self.finished_mac, 32))
        payload = self.server_ciphertext + self.mldsa_signature + self.finished_mac
        return _pack_header(MessageType.CLIENT_KEY_EXCHANGE, len(payload), PROTOCOL_VERSION_V3_MLDSA) + payload

    @classmethod
    def unpack(cls, data: bytes) -> "ClientKeyExchangeMLDSA":
        payload = _fixed(data, MessageType.CLIENT_KEY_EXCHANGE, cls.SIZE, PROTOCOL_VERSION_V3_MLDSA)
        return cls(payload[:1088], payload[1088:3508], payload[3508:])


class ServerFinishedMLDSA:
    def __init__(self, finished_mac: bytes):
        self.finished_mac = finished_mac

    def pack(self) -> bytes:
        _fields(finished_mac=(self.finished_mac, 32))
        return _pack_header(MessageType.SERVER_FINISHED, 32, PROTOCOL_VERSION_V3_MLDSA) + self.finished_mac

    @classmethod
    def unpack(cls, data: bytes) -> "ServerFinishedMLDSA":
        return cls(_fixed(data, MessageType.SERVER_FINISHED, 32, PROTOCOL_VERSION_V3_MLDSA))


def derive_schedule_mldsa(hybrid_input: bytes, client_random: bytes, server_random: bytes,
                          session_id: bytes, transcript_hash: bytes) -> TrafficSecrets:
    context = (PROTOCOL_NAME_V3_MLDSA + bytes([PROTOCOL_VERSION_V3_MLDSA])
               + b"|X25519|ML-KEM-768|ML-DSA-44|AES-256-GCM|"
               + session_id + client_random + server_random + transcript_hash)
    salt = hashlib.sha256(b"pqvpn extract" + client_random + server_random + session_id).digest()
    master = KeyManager().derive_key(hybrid_input, salt=salt, info=b"pqvpn mldsa master secret")
    return _derive_secrets(master, context)


class KEMTLSClientMLDSA:
    def __init__(self, server_identity_public: bytes, server_fingerprint: str,
                 client_sig_secret: bytes, client_sig_public: bytes,
                 allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        _refuse_mldsa_rust(handshake)
        self.data_plane, self._rust = data_plane, None
        expected = fingerprint(server_identity_public)
        if len(server_identity_public) != 1184 or not hmac.compare_digest(expected, server_fingerprint.lower()):
            raise HandshakeError("server identity fingerprint mismatch")
        if len(client_sig_secret) != MLDSA44_PARAMS["secret_key_length"]:
            raise HandshakeError("invalid client ML-DSA-44 secret key")
        if len(client_sig_public) != MLDSA44_PARAMS["public_key_length"]:
            raise HandshakeError("invalid client ML-DSA-44 public key")
        self.server_identity_public = server_identity_public
        self.server_identity_id = bytes.fromhex(expected)
        self.client_sig_secret = client_sig_secret
        self.client_sig_public = client_sig_public
        self.client_identity_hash = bytes.fromhex(fingerprint(client_sig_public))
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._sig = PQSignatureProvider(allow_mock=allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def initiate_handshake(self) -> bytes:
        if self._rust:
            return _rust_step(self, self._rust.hello, to=HandshakeState.CLIENT_HELLO_SENT)
        if self._state != HandshakeState.IDLE:
            raise HandshakeError("Cannot initiate handshake")
        self.keys = self._hybrid.generate_keypairs()
        self.client_random, self.session_id = os.urandom(32), os.urandom(32)
        wire = ClientHelloMLDSA(self.client_random, self.session_id, self.keys.ecc_public,
                                self.keys.pqc_public, self.client_identity_hash).pack()
        self._transcript.update(wire)
        self._state = HandshakeState.CLIENT_HELLO_SENT
        return wire

    def process_server_hello(self, wire: bytes) -> bytes:
        if self._rust:
            return _rust_step(self, self._rust.on_server_hello, wire, to=HandshakeState.KEY_EXCHANGE_SENT)
        if self._state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError("Cannot process ServerHello")
        hello = ServerHelloMLDSA.unpack(wire)
        if hello.session_id != self.session_id:
            raise HandshakeError("Session ID mismatch")
        if not hmac.compare_digest(hello.identity_id, self.server_identity_id):
            raise HandshakeError("server identity substitution detected")
        self._transcript.update(wire)
        self.server_random = hello.server_random

        ecc_ss = _primitive(self._hybrid.ecc.derive_shared_secret, self.keys.ecc_private, hello.ecc_public_key)
        k_eph = _primitive(self._hybrid.pqc.decapsulate, self.keys.pqc_secret, hello.pqc_ciphertext)
        server_ct, k_s = _primitive(self._hybrid.pqc.encapsulate, self.server_identity_public)

        digest = self._transcript.digest()
        self.schedule = derive_schedule_mldsa(
            ecc_ss + k_eph + k_s,
            self.client_random, self.server_random, self.session_id, digest)

        sign_data = PROTOCOL_NAME_V3_MLDSA + b" client proof " + digest + server_ct
        signature = self._sig.sign(self.client_sig_secret, sign_data)

        partial = server_ct + signature
        finished = _compute_finished_mac(
            hashlib.sha256(digest + partial).digest(),
            bytes(self.schedule.client_finished_key), _CLIENT_FINISHED_LABEL)
        exchange = ClientKeyExchangeMLDSA(server_ct, signature, finished).pack()
        self._transcript.update(exchange)
        self._state = HandshakeState.KEY_EXCHANGE_SENT
        return exchange

    def process_server_finished(self, wire: bytes) -> HandshakeSession:
        if self._rust:
            return RustHandshakeSession(_rust_step(self, self._rust.on_server_finished, wire, to=HandshakeState.ESTABLISHED))
        if self._state != HandshakeState.KEY_EXCHANGE_SENT:
            raise HandshakeError("Cannot process ServerFinished")
        finished = ServerFinishedMLDSA.unpack(wire)
        if not _verify_finished_mac(self._transcript.digest(),
                                    bytes(self.schedule.server_finished_key),
                                    _SERVER_FINISHED_LABEL, finished.finished_mac):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Server Finished MAC verification failed")
        self._transcript.update(wire)
        self._state = HandshakeState.ESTABLISHED
        return HandshakeSession(self.session_id, self.schedule,
                                self.client_random, self.server_random, "client",
                                protocol_version=PROTOCOL_VERSION_V3_MLDSA, data_plane=self.data_plane)


class KEMTLSServerMLDSA:
    def __init__(self, server_identity_secret: bytes, server_identity_public: bytes,
                 find_client_sig_key: Callable[[str], tuple[bytes, dict] | None],
                 allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        _refuse_mldsa_rust(handshake)
        self.data_plane, self._rust = data_plane, None
        if len(server_identity_public) != 1184:
            raise ValueError("invalid server identity public key")
        self.identity_secret = server_identity_secret
        self.identity_public = server_identity_public
        self.identity_id = bytes.fromhex(fingerprint(server_identity_public))
        self.find_client_sig_key = find_client_sig_key
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._sig = PQSignatureProvider(allow_mock=allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def process_client_hello(self, wire: bytes) -> bytes:
        if self._state != HandshakeState.IDLE:
            raise HandshakeError("Cannot process ClientHello")
        hello = ClientHelloMLDSA.unpack(wire)
        result = self.find_client_sig_key(hello.client_identity_hash.hex())
        if result is None:
            self._state = HandshakeState.FAILED
            raise HandshakeError("unauthorized client")
        client_sig_public, self.authz = result
        if len(client_sig_public) != MLDSA44_PARAMS["public_key_length"]:
            self._state = HandshakeState.FAILED
            raise HandshakeError("invalid client ML-DSA-44 public key in store")
        if not hmac.compare_digest(bytes.fromhex(fingerprint(client_sig_public)),
                                   hello.client_identity_hash):
            self._state = HandshakeState.FAILED
            raise HandshakeError("client identity hash mismatch")
        self.ch = hello
        self.client_sig_public = client_sig_public
        self._transcript.update(wire)

        self.server_ecc_private, server_ecc_public = self._hybrid.ecc.generate_keypair()
        self.server_random = os.urandom(32)
        self.ecc_ss = _primitive(self._hybrid.ecc.derive_shared_secret, self.server_ecc_private, hello.ecc_public_key)
        eph_ct, self.k_eph = _primitive(self._hybrid.pqc.encapsulate, hello.pqc_public_key)

        response = ServerHelloMLDSA(self.server_random, hello.session_id, server_ecc_public,
                                    eph_ct, self.identity_id).pack()
        self._transcript.update(response)
        self._state = HandshakeState.SERVER_HELLO_SENT
        return response

    def process_client_key_exchange(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
        if self._rust:
            finished, session = _rust_step(self, self._rust.on_key_exchange, wire, to=HandshakeState.ESTABLISHED)
            return finished, RustHandshakeSession(session, self.authz.get("client_id", ""))
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError("Cannot process ClientKeyExchange")
        exchange = ClientKeyExchangeMLDSA.unpack(wire)
        digest = self._transcript.digest()

        k_s = _primitive(self._hybrid.pqc.decapsulate, self.identity_secret, exchange.server_ciphertext)
        schedule = derive_schedule_mldsa(
            self.ecc_ss + self.k_eph + k_s,
            self.ch.client_random, self.server_random, self.ch.session_id, digest)

        sign_data = PROTOCOL_NAME_V3_MLDSA + b" client proof " + digest + exchange.server_ciphertext
        if not self._sig.verify(self.client_sig_public, sign_data, exchange.mldsa_signature):
            self._state = HandshakeState.FAILED
            raise HandshakeError("client ML-DSA-44 signature verification failed")

        partial = exchange.server_ciphertext + exchange.mldsa_signature
        if not _verify_finished_mac(
                hashlib.sha256(digest + partial).digest(),
                bytes(schedule.client_finished_key), _CLIENT_FINISHED_LABEL,
                exchange.finished_mac):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Client Finished MAC verification failed")

        self._transcript.update(wire)
        finished = ServerFinishedMLDSA(_compute_finished_mac(
            self._transcript.digest(),
            bytes(schedule.server_finished_key), _SERVER_FINISHED_LABEL)).pack()
        self._transcript.update(finished)
        self._state = HandshakeState.ESTABLISHED
        session = HandshakeSession(self.ch.session_id, schedule, self.ch.client_random,
                                   self.server_random, "server", self.authz.get("client_id", ""),
                                   protocol_version=PROTOCOL_VERSION_V3_MLDSA, data_plane=self.data_plane)
        return finished, session


# ---------------------------------------------------------------------------
# Session Resumption — 1-RTT reconnect with PQ forward secrecy
# ---------------------------------------------------------------------------

RESUMPTION_PROTOCOL = b"PQVPN-RESUME"


class ResumptionTicketKey:
    """Server-side AES-256-GCM ticket encryption.  Key lives in memory only —
    server restart invalidates all tickets, which is the safe default."""

    def __init__(self) -> None:
        self._cipher = AESGCM(os.urandom(32))

    def issue(self, resumption_secret: bytes, client_id: str,
              protocol_version: int, lifetime: int = 86400,
              assigned_ip: str = "") -> bytes:
        now = int(time.time())
        cid = client_id.encode("utf-8")
        aip = assigned_ip.encode("utf-8")
        plaintext = (resumption_secret
                     + struct.pack("!BqHH", protocol_version, now + lifetime,
                                   len(cid), len(aip))
                     + cid + aip)
        nonce = os.urandom(12)
        return nonce + self._cipher.encrypt(nonce, plaintext, RESUMPTION_PROTOCOL)

    def validate(self, ticket: bytes) -> tuple[bytes, str, int, str] | None:
        """→ (resumption_secret, client_id, protocol_version, assigned_ip) or None."""
        if len(ticket) < 12 + 16 + 32 + 13:  # nonce + tag + secret + header
            return None
        try:
            plaintext = self._cipher.decrypt(ticket[:12], ticket[12:],
                                             RESUMPTION_PROTOCOL)
        except Exception:
            return None
        if len(plaintext) < 45:
            return None
        secret = plaintext[:32]
        version, expiry, cid_len, aip_len = struct.unpack("!BqHH", plaintext[32:45])
        if len(plaintext) != 45 + cid_len + aip_len:
            return None
        if int(time.time()) > expiry:
            return None
        cid = plaintext[45:45 + cid_len].decode("utf-8")
        aip = plaintext[45 + cid_len:].decode("utf-8")
        return secret, cid, version, aip


def derive_schedule_resume(resumption_secret: bytes, ecc_ss: bytes, kem_ss: bytes,
                           client_random: bytes, server_random: bytes,
                           session_id: bytes, transcript_hash: bytes) -> TrafficSecrets:
    """Key schedule for resumed sessions — mixes old secret + fresh ephemeral material."""
    context = (RESUMPTION_PROTOCOL + bytes([PROTOCOL_VERSION_V3])
               + b"|X25519|ML-KEM-768|AES-256-GCM|"
               + session_id + client_random + server_random + transcript_hash)
    ikm = resumption_secret + ecc_ss + kem_ss
    salt = hashlib.sha256(b"pqvpn resume" + client_random + server_random + session_id).digest()
    master = KeyManager().derive_key(ikm, salt=salt, info=b"pqvpn resume master secret")
    return _derive_secrets(master, context)


@dataclass(frozen=True)
class ResumptionHello:
    """Client → Server: ticket + fresh ephemeral keys."""
    client_random: bytes   # 32
    ticket: bytes           # variable
    ecc_public_key: bytes  # 32
    pqc_public_key: bytes  # 1184

    def pack(self, version: int = PROTOCOL_VERSION_V3) -> bytes:
        payload = (self.client_random
                   + struct.pack("!H", len(self.ticket)) + self.ticket
                   + self.ecc_public_key + self.pqc_public_key)
        return _pack_header(MessageType.RESUMPTION_HELLO, len(payload), version) + payload

    @classmethod
    def unpack(cls, data: bytes, version: int = PROTOCOL_VERSION_V3) -> "ResumptionHello":
        _, _, msg_type, payload_len = _unpack_header(data, version)
        if msg_type != MessageType.RESUMPTION_HELLO:
            raise HandshakeError("expected RESUMPTION_HELLO")
        payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]
        if len(payload) < 34 + 32 + 1184:
            raise HandshakeError("RESUMPTION_HELLO too short")
        cr = payload[:32]
        tlen = struct.unpack("!H", payload[32:34])[0]
        if len(payload) != 34 + tlen + 32 + 1184:
            raise HandshakeError("RESUMPTION_HELLO size mismatch")
        return cls(cr, payload[34:34 + tlen],
                   payload[34 + tlen:34 + tlen + 32],
                   payload[34 + tlen + 32:])


@dataclass(frozen=True)
class ResumptionAccept:
    """Server → Client: new session keys with forward secrecy."""
    server_random: bytes     # 32
    session_id: bytes        # 32
    ecc_public_key: bytes    # 32
    pqc_ciphertext: bytes    # 1088
    finished_mac: bytes      # 32
    SIZE = 1216

    def pack(self, version: int = PROTOCOL_VERSION_V3) -> bytes:
        payload = (self.server_random + self.session_id + self.ecc_public_key
                   + self.pqc_ciphertext + self.finished_mac)
        return _pack_header(MessageType.RESUMPTION_ACCEPT, len(payload), version) + payload

    @classmethod
    def unpack(cls, data: bytes, version: int = PROTOCOL_VERSION_V3) -> "ResumptionAccept":
        payload = _fixed(data, MessageType.RESUMPTION_ACCEPT, cls.SIZE, version)
        return cls(payload[:32], payload[32:64], payload[64:96],
                   payload[96:1184], payload[1184:])


_RESUME_FINISHED_LABEL = b"pqvpn resume finished"


class ResumptionClientHandshake:
    """Client-side 1-RTT resumption handshake."""

    def __init__(self, resumption_secret: bytes | None, protocol_version: int = PROTOCOL_VERSION_V3,
                 allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        self.data_plane = data_plane
        self._secret = resumption_secret
        self._version = protocol_version
        self._rust = None
        self._is_rust = _rust_handshake(handshake, data_plane, allow_mock_pqc)
        if self._is_rust:
            return
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._transcript = TranscriptHasher()

    @classmethod
    def from_ticket_file(cls, path: object, fingerprint: str, protocol_version: int,
                         version: int) -> "ResumptionClientHandshake | None":
        """handshake="rust": Rust reads the ticket file itself, so the resumption secret never reaches Python."""
        loaded = _core().ResumeClient.load(str(path), fingerprint, protocol_version, version)
        if loaded is None:
            return None
        client = cls(None, version, data_plane="rust", handshake="rust")
        client._rust = loaded
        return client

    def initiate(self, ticket: bytes | None = None) -> bytes:
        if self._is_rust:
            if self._rust is None:
                self._rust = _rust(_core().ResumeClient, self._version, self._secret, ticket)
            return _rust(self._rust.hello)
        self.keys = self._hybrid.generate_keypairs()
        self.client_random = os.urandom(32)
        wire = ResumptionHello(self.client_random, ticket,
                               self.keys.ecc_public, self.keys.pqc_public).pack(self._version)
        self._transcript.update(wire)
        return wire

    def process_accept(self, wire: bytes) -> HandshakeSession:
        if self._is_rust:
            return RustHandshakeSession(_rust(self._rust.on_accept, wire))
        accept = ResumptionAccept.unpack(wire, self._version)
        self._transcript.update(wire[:HEADER_SIZE + ResumptionAccept.SIZE - 32])  # sans mac

        ecc_ss = _primitive(self._hybrid.ecc.derive_shared_secret, self.keys.ecc_private, accept.ecc_public_key)
        kem_ss = _primitive(self._hybrid.pqc.decapsulate, self.keys.pqc_secret, accept.pqc_ciphertext)

        schedule = derive_schedule_resume(
            self._secret, ecc_ss, kem_ss,
            self.client_random, accept.server_random,
            accept.session_id, self._transcript.digest())

        expected = _compute_finished_mac(self._transcript.digest(),
                                         bytes(schedule.server_finished_key),
                                         _RESUME_FINISHED_LABEL)
        if not hmac.compare_digest(accept.finished_mac, expected):
            raise HandshakeError("resumption finished MAC failed")

        return HandshakeSession(accept.session_id, schedule, self.client_random,
                                accept.server_random, "client",
                                protocol_version=self._version, data_plane=self.data_plane)


class ResumptionServerHandshake:
    """Server-side 1-RTT resumption handshake."""

    def __init__(self, ticket_key: ResumptionTicketKey,
                 protocol_version: int = PROTOCOL_VERSION_V3,
                 allow_mock_pqc: bool = False,
                 data_plane: str = "python", handshake: str = "python") -> None:
        self.data_plane = data_plane
        self._ticket_key = ticket_key
        self._version = protocol_version
        self._is_rust = _rust_handshake(handshake, data_plane, allow_mock_pqc)
        if self._is_rust and not isinstance(ticket_key, _core().TicketKey):
            raise TypeError('handshake = "rust" needs a pqvpn_core.TicketKey')
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._transcript = TranscriptHasher()
        self.client_id = ""
        self.assigned_ip: str = ""

    def process_hello(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
        if self._is_rust:
            accept, session, self.client_id, self.assigned_ip = _rust(_core().resume_server, self._ticket_key, wire, self._version)
            return accept, RustHandshakeSession(session, self.client_id)
        hello = ResumptionHello.unpack(wire, self._version)
        result = self._ticket_key.validate(hello.ticket)
        if result is None:
            raise HandshakeError("invalid or expired resumption ticket")
        resumption_secret, self.client_id, ticket_version, self.assigned_ip = result
        if ticket_version != self._version:
            raise HandshakeError("resumption ticket protocol version mismatch")

        self._transcript.update(wire)
        server_random = os.urandom(32)
        session_id = os.urandom(32)
        server_ecc_private, server_ecc_public = self._hybrid.ecc.generate_keypair()
        ecc_ss = _primitive(self._hybrid.ecc.derive_shared_secret, server_ecc_private, hello.ecc_public_key)
        pqc_ct, kem_ss = _primitive(self._hybrid.pqc.encapsulate, hello.pqc_public_key)

        # Build accept sans finished_mac for transcript
        accept_body = server_random + session_id + server_ecc_public + pqc_ct
        self._transcript.update(_pack_header(MessageType.RESUMPTION_ACCEPT,
                                             ResumptionAccept.SIZE, self._version) + accept_body)

        schedule = derive_schedule_resume(
            resumption_secret, ecc_ss, kem_ss,
            hello.client_random, server_random,
            session_id, self._transcript.digest())

        finished = _compute_finished_mac(self._transcript.digest(),
                                         bytes(schedule.server_finished_key),
                                         _RESUME_FINISHED_LABEL)

        accept = ResumptionAccept(server_random, session_id, server_ecc_public,
                                  pqc_ct, finished).pack(self._version)

        session = HandshakeSession(session_id, schedule, hello.client_random,
                                   server_random, "server", self.client_id,
                                   protocol_version=self._version, data_plane=self.data_plane)
        return accept, session
