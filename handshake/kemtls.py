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
from typing import Callable

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
    _data_send_sequence: int = field(default=0, repr=False)
    _control_send_sequence: int = field(default=0, repr=False)
    _control_receive_sequence: int = field(default=0, repr=False)
    _data_replay: ReplayWindow = field(default_factory=ReplayWindow, repr=False)
    _data_send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _data_receive_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _control_send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _control_receive_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _epoch_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        if self.role not in {"client", "server"} or len(self.session_id) != 32:
            raise ValueError("invalid session role or id")
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
        self._data_send_cipher, self._data_recv_cipher = AESGCM(bytes(data_send)), AESGCM(bytes(data_recv))
        self._control_send_cipher, self._control_recv_cipher = AESGCM(bytes(control_send)), AESGCM(bytes(control_recv))
        self._data_send_nonce_base, self._data_recv_nonce_base = data_send_nonce, data_recv_nonce
        self._control_send_nonce_base, self._control_recv_nonce_base = control_send_nonce, control_recv_nonce

    @staticmethod
    def _nonce(base: bytearray, sequence: int) -> bytes:
        encoded = b"\0" * 4 + sequence.to_bytes(8, "big")
        return bytes(a ^ b for a, b in zip(base, encoded))

    def _encrypt(self, plaintext: bytes, frame_type: FrameType, channel: Channel) -> bytes:
        lock = self._data_send_lock if channel == Channel.DATA else self._control_send_lock
        with lock:
            if self._data_send_cipher is None:
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
                if self._data_recv_cipher is None:
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

    def derive_next_epoch(self, epoch: int, nonce: bytes) -> TrafficSecrets:
        with self._epoch_lock:
            if self._data_send_cipher is None:
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
            if self._data_send_cipher is None:
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
            if self._data_send_cipher is None:
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
            self.secrets.wipe()
            self._data_send_cipher = self._data_recv_cipher = None
            self._control_send_cipher = self._control_recv_cipher = None

    def get_info(self) -> dict:
        return {"session_id": self.session_id.hex(), "established_at": self.established_at,
                "epoch": self.epoch, "role": self.role, "encryption_key_size": 32}


class KEMTLSClient:
    def __init__(self, server_identity_public: bytes, server_fingerprint: str,
                 client_private_key: Ed25519PrivateKey, allow_mock_pqc: bool = False) -> None:
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
        if self._state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError("Cannot process ServerHello")
        hello = ServerHello.unpack(wire)
        if hello.session_id != self.session_id:
            raise HandshakeError("Session ID mismatch")
        if not hmac.compare_digest(hello.identity_id, self.identity_id):
            raise HandshakeError("server identity substitution detected")
        self._transcript.update(wire)
        self.server_random = hello.server_random
        ecc = self._hybrid.ecc.derive_shared_secret(self.keys.ecc_private, hello.ecc_public_key)
        ephemeral_pq = self._hybrid.pqc.decapsulate(self.keys.pqc_secret, hello.pqc_ciphertext)
        identity_ciphertext, identity_secret = self._hybrid.pqc.encapsulate(self.identity_public)
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
        if self._state != HandshakeState.KEY_EXCHANGE_SENT:
            raise HandshakeError("Cannot process ServerFinished")
        finished = ServerFinished.unpack(wire)
        if not _verify_finished_mac(self._transcript.digest(), bytes(self.schedule.server_finished_key),
                                    _SERVER_FINISHED_LABEL, finished.finished_mac):
            self._state = HandshakeState.FAILED
            raise HandshakeError("Server Finished MAC verification failed")
        self._transcript.update(wire)
        self._state = HandshakeState.ESTABLISHED
        return HandshakeSession(self.session_id, self.schedule, self.client_random, self.server_random, "client")


class KEMTLSServer:
    def __init__(self, server_identity_secret: bytes, server_identity_public: bytes,
                 authorize_client: Callable[[bytes], dict | None], allow_mock_pqc: bool = False) -> None:
        if len(server_identity_public) != 1184:
            raise ValueError("invalid server identity public key")
        self.identity_secret = server_identity_secret
        self.identity_id = bytes.fromhex(fingerprint(server_identity_public))
        self.authorize_client = authorize_client
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def process_client_hello(self, wire: bytes) -> bytes:
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
        self.ecc = self._hybrid.ecc.derive_shared_secret(self.server_ecc_private, hello.ecc_public_key)
        ciphertext, self.ephemeral_pq = self._hybrid.pqc.encapsulate(hello.pqc_public_key)
        response = ServerHello(self.server_random, hello.session_id, server_ecc_public,
                               ciphertext, self.identity_id).pack()
        self._transcript.update(response)
        self._state = HandshakeState.SERVER_HELLO_SENT
        return response

    def process_client_key_exchange(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError("Cannot process ClientKeyExchange")
        exchange = ClientKeyExchange.unpack(wire)
        digest = self._transcript.digest()
        identity_secret = self._hybrid.pqc.decapsulate(self.identity_secret, exchange.identity_ciphertext)
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
                                   self.server_random, "server", self.authz.get("client_id", ""))
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
                 allow_mock_pqc: bool = False) -> None:
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
        if self._state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError("Cannot process ServerHello")
        hello = ServerHelloV3.unpack(wire)
        if hello.session_id != self.session_id:
            raise HandshakeError("Session ID mismatch")
        if not hmac.compare_digest(hello.identity_id, self.server_identity_id):
            raise HandshakeError("server identity substitution detected")
        self._transcript.update(wire)
        self.server_random = hello.server_random

        ecc_ss = self._hybrid.ecc.derive_shared_secret(self.keys.ecc_private, hello.ecc_public_key)
        k_eph = self._hybrid.pqc.decapsulate(self.keys.pqc_secret, hello.pqc_ciphertext)
        k_c = self._hybrid.pqc.decapsulate(self.client_static_secret, hello.client_ciphertext)
        server_ct, k_s = self._hybrid.pqc.encapsulate(self.server_identity_public)

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
                                protocol_version=PROTOCOL_VERSION_V3)


class KEMTLSServerV3:
    def __init__(self, server_identity_secret: bytes, server_identity_public: bytes,
                 find_client_kem_key: Callable[[str], tuple[bytes, dict] | None],
                 allow_mock_pqc: bool = False) -> None:
        if len(server_identity_public) != 1184:
            raise ValueError("invalid server identity public key")
        self.identity_secret = server_identity_secret
        self.identity_public = server_identity_public
        self.identity_id = bytes.fromhex(fingerprint(server_identity_public))
        self.find_client_kem_key = find_client_kem_key
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._state = HandshakeState.IDLE
        self._transcript = TranscriptHasher()

    @property
    def state(self): return self._state

    def process_client_hello(self, wire: bytes) -> bytes:
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
        self.ecc_ss = self._hybrid.ecc.derive_shared_secret(self.server_ecc_private, hello.ecc_public_key)
        eph_ct, self.k_eph = self._hybrid.pqc.encapsulate(hello.pqc_public_key)
        client_ct, self.k_c = self._hybrid.pqc.encapsulate(client_kem_public)

        response = ServerHelloV3(self.server_random, hello.session_id, server_ecc_public,
                                 eph_ct, self.identity_id, client_ct).pack()
        self._transcript.update(response)
        self._state = HandshakeState.SERVER_HELLO_SENT
        return response

    def process_client_key_exchange(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError("Cannot process ClientKeyExchange")
        exchange = ClientKeyExchangeV3.unpack(wire)
        digest = self._transcript.digest()

        k_s = self._hybrid.pqc.decapsulate(self.identity_secret, exchange.server_ciphertext)
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
                                   protocol_version=PROTOCOL_VERSION_V3)
        return finished, session


PROTOCOL_VERSION_V3_MLDSA = 0x31
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
                 allow_mock_pqc: bool = False) -> None:
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
        if self._state != HandshakeState.CLIENT_HELLO_SENT:
            raise HandshakeError("Cannot process ServerHello")
        hello = ServerHelloMLDSA.unpack(wire)
        if hello.session_id != self.session_id:
            raise HandshakeError("Session ID mismatch")
        if not hmac.compare_digest(hello.identity_id, self.server_identity_id):
            raise HandshakeError("server identity substitution detected")
        self._transcript.update(wire)
        self.server_random = hello.server_random

        ecc_ss = self._hybrid.ecc.derive_shared_secret(self.keys.ecc_private, hello.ecc_public_key)
        k_eph = self._hybrid.pqc.decapsulate(self.keys.pqc_secret, hello.pqc_ciphertext)
        server_ct, k_s = self._hybrid.pqc.encapsulate(self.server_identity_public)

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
                                protocol_version=PROTOCOL_VERSION_V3_MLDSA)


class KEMTLSServerMLDSA:
    def __init__(self, server_identity_secret: bytes, server_identity_public: bytes,
                 find_client_sig_key: Callable[[str], tuple[bytes, dict] | None],
                 allow_mock_pqc: bool = False) -> None:
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
        self.ecc_ss = self._hybrid.ecc.derive_shared_secret(self.server_ecc_private, hello.ecc_public_key)
        eph_ct, self.k_eph = self._hybrid.pqc.encapsulate(hello.pqc_public_key)

        response = ServerHelloMLDSA(self.server_random, hello.session_id, server_ecc_public,
                                    eph_ct, self.identity_id).pack()
        self._transcript.update(response)
        self._state = HandshakeState.SERVER_HELLO_SENT
        return response

    def process_client_key_exchange(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
        if self._state != HandshakeState.SERVER_HELLO_SENT:
            raise HandshakeError("Cannot process ClientKeyExchange")
        exchange = ClientKeyExchangeMLDSA.unpack(wire)
        digest = self._transcript.digest()

        k_s = self._hybrid.pqc.decapsulate(self.identity_secret, exchange.server_ciphertext)
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
                                   protocol_version=PROTOCOL_VERSION_V3_MLDSA)
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

    def __init__(self, resumption_secret: bytes, protocol_version: int = PROTOCOL_VERSION_V3,
                 allow_mock_pqc: bool = False) -> None:
        self._secret = resumption_secret
        self._version = protocol_version
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._transcript = TranscriptHasher()

    def initiate(self, ticket: bytes) -> bytes:
        self.keys = self._hybrid.generate_keypairs()
        self.client_random = os.urandom(32)
        wire = ResumptionHello(self.client_random, ticket,
                               self.keys.ecc_public, self.keys.pqc_public).pack(self._version)
        self._transcript.update(wire)
        return wire

    def process_accept(self, wire: bytes) -> HandshakeSession:
        accept = ResumptionAccept.unpack(wire, self._version)
        self._transcript.update(wire[:HEADER_SIZE + ResumptionAccept.SIZE - 32])  # sans mac

        ecc_ss = self._hybrid.ecc.derive_shared_secret(self.keys.ecc_private, accept.ecc_public_key)
        kem_ss = self._hybrid.pqc.decapsulate(self.keys.pqc_secret, accept.pqc_ciphertext)

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
                                protocol_version=self._version)


class ResumptionServerHandshake:
    """Server-side 1-RTT resumption handshake."""

    def __init__(self, ticket_key: ResumptionTicketKey,
                 protocol_version: int = PROTOCOL_VERSION_V3,
                 allow_mock_pqc: bool = False) -> None:
        self._ticket_key = ticket_key
        self._version = protocol_version
        self._hybrid = HybridKEM("ML-KEM-768", allow_mock_pqc)
        self._transcript = TranscriptHasher()
        self.client_id = ""
        self.assigned_ip: str = ""

    def process_hello(self, wire: bytes) -> tuple[bytes, HandshakeSession]:
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
        ecc_ss = self._hybrid.ecc.derive_shared_secret(server_ecc_private, hello.ecc_public_key)
        pqc_ct, kem_ss = self._hybrid.pqc.encapsulate(hello.pqc_public_key)

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
                                   protocol_version=self._version)
        return accept, session
