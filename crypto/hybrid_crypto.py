"""Hybrid Classical + Post-Quantum Cryptography — X25519 + ML-KEM-768 via liboqs."""

from __future__ import annotations

import os
import time
import ctypes
import ctypes.util
from pathlib import Path
import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_logger = logging.getLogger(__name__)



class PQCUnavailableError(RuntimeError):
    """Raised when native liboqs is required but not available."""


ALLOW_MOCK_PQC: bool = os.environ.get("ALLOW_MOCK_PQC", "0").strip() == "1"


class ECCProvider:
    """Classical X25519 ECDH key exchange."""

    # X25519 key sizes (bytes)
    PUBLIC_KEY_SIZE = 32
    SHARED_SECRET_SIZE = 32

    def generate_keypair(self) -> tuple[X25519PrivateKey, bytes]:
        """Generate a fresh X25519 keypair → (private_key, 32-byte public)."""
        private_key = X25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        return private_key, public_key_bytes

    def derive_shared_secret(
        self,
        private_key: X25519PrivateKey,
        peer_public_bytes: bytes,
    ) -> bytes:
        """X25519 ECDH → 32-byte shared secret."""
        if len(peer_public_bytes) != self.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Peer public key must be {self.PUBLIC_KEY_SIZE} bytes, "
                f"got {len(peer_public_bytes)}"
            )
        peer_public_key = self.deserialize_public_key(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret

    @staticmethod
    def serialize_public_key(public_key: X25519PublicKey) -> bytes:
        """Serialize an X25519PublicKey to 32-byte raw bytes."""
        return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def deserialize_public_key(raw_bytes: bytes) -> X25519PublicKey:
        """Deserialize 32-byte raw bytes into an X25519PublicKey."""
        if len(raw_bytes) != 32:
            raise ValueError(
                f"X25519 public key must be 32 bytes, got {len(raw_bytes)}"
            )
        return X25519PublicKey.from_public_bytes(raw_bytes)


SUPPORTED_ALGORITHMS = ("ML-KEM-768",)

MLKEM_PARAMS = {
    "ML-KEM-768": {
        "nist_level": 3,
        "public_key_length": 1184,
        "secret_key_length": 2400,
        "ciphertext_length": 1088,
        "shared_secret_length": 32,
    },
}
_OQS_AVAILABLE = False
_oqs_module = None
_OQS_LOAD_ERROR: Optional[str] = None

def _require_installed_liboqs():
    # liboqs-python otherwise downloads/builds on import. Probe exactly its Linux
    # search locations first, so missing native installations fail closed offline.
    prefix = Path(os.environ.get("OQS_INSTALL_PATH", str(Path.home() / "_oqs")))
    candidates = [ctypes.util.find_library("oqs"), ctypes.util.find_library("liboqs"),
                  str(prefix / "lib/liboqs.so"), str(prefix / "lib64/liboqs.so")]
    for candidate in candidates:
        if candidate:
            try: return ctypes.CDLL(candidate)
            except OSError: pass
    raise ImportError("native liboqs is not preinstalled; automatic download/build is disabled")


try:
    _native_library = _require_installed_liboqs()
    import oqs as _oqs_module  # type: ignore[import-untyped]
    if not hasattr(_oqs_module, "KeyEncapsulation"):
        raise ImportError(
            "oqs module loaded but KeyEncapsulation class is missing — "
            "the installed liboqs-python may be incomplete or mismatched."
        )
    enabled = tuple(_oqs_module.get_enabled_kem_mechanisms())
    if "ML-KEM-768" not in enabled:
        raise ImportError(
            "liboqs does not expose required ML-KEM-768; enabled mechanisms: "
            + ", ".join(enabled)
        )
    with _oqs_module.KeyEncapsulation("ML-KEM-768") as _test_kem:
        _pk = _test_kem.generate_keypair()
        _sk = _test_kem.export_secret_key()
    with _oqs_module.KeyEncapsulation("ML-KEM-768") as _enc:
        _ct, _ss1 = _enc.encap_secret(_pk)
    with _oqs_module.KeyEncapsulation("ML-KEM-768", _sk) as _dec:
        _ss2 = _dec.decap_secret(_ct)
    if not hmac.compare_digest(_ss1, _ss2):
        raise ImportError("ML-KEM-768 startup self-test failed")
    _OQS_AVAILABLE = True
    _logger.debug("liboqs loaded successfully — native ML-KEM active.")
except (ImportError, ModuleNotFoundError) as _e:
    _OQS_LOAD_ERROR = f"liboqs-python not installed: {_e}"
    _logger.warning(
        "[PQC] liboqs-python not installed. %s. "
        "Set ALLOW_MOCK_PQC=1 for insecure dev-only mock fallback.",
        _OQS_LOAD_ERROR,
    )
    _oqs_module = None
except AttributeError as _e:
    _OQS_LOAD_ERROR = f"liboqs-python API mismatch: {_e}"
    _logger.error(
        "[PQC] liboqs API mismatch — library may be corrupt or wrong version: %s",
        _OQS_LOAD_ERROR,
    )
    _oqs_module = None
except Exception as _e:
    _OQS_LOAD_ERROR = f"liboqs initialisation failed: {_e}"
    _logger.error(
        "[PQC] Unexpected error loading liboqs: %s", _OQS_LOAD_ERROR
    )
    _oqs_module = None


class _MockInsecurePQCProvider:
    """DEV/TEST ONLY — SHA-based mock of ML-KEM. NO quantum security."""

    _SECURITY_WARNING = (
        "INSECURE_MOCK_DO_NOT_USE_IN_PRODUCTION — "
        "SHA-based pseudo-KEM, provides NO quantum security"
    )

    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        self.params = MLKEM_PARAMS[algorithm]
        _logger.warning(
            "[PQC] *** MOCK INSECURE PROVIDER ACTIVE *** "
            "Algorithm %s is being simulated with SHA hashes. "
            "This provides NO quantum-safe protection.",
            algorithm,
        )

    def generate_keypair(self) -> tuple[bytes, bytes]:
        params = self.params
        seed = os.urandom(32)
        pk_raw = hashlib.sha512(b"MOCK_PQC_PK_" + seed).digest()
        sk_raw = hashlib.sha512(b"MOCK_PQC_SK_" + seed).digest()
        public_key = (
            pk_raw * (params["public_key_length"] // len(pk_raw) + 1)
        )[: params["public_key_length"]]
        secret_key = seed + (
            sk_raw * (params["secret_key_length"] // len(sk_raw) + 1)
        )[: params["secret_key_length"] - 32]
        return secret_key, public_key

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        params = self.params
        ephemeral = os.urandom(32)
        shared_secret = hashlib.sha256(
            b"MOCK_PQC_SS_" + ephemeral + peer_public_key[:32]
        ).digest()
        ct_raw = hashlib.sha512(
            b"MOCK_PQC_CT_" + ephemeral + peer_public_key[:32]
        ).digest()
        ciphertext = ephemeral + (
            ct_raw * (params["ciphertext_length"] // len(ct_raw) + 1)
        )[: params["ciphertext_length"] - 32]
        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        seed = secret_key[:32]
        ephemeral = ciphertext[:32]
        pk_raw = hashlib.sha512(b"MOCK_PQC_PK_" + seed).digest()
        params = self.params
        public_key_prefix = (
            pk_raw * (params["public_key_length"] // len(pk_raw) + 1)
        )[:32]
        return hashlib.sha256(
            b"MOCK_PQC_SS_" + ephemeral + public_key_prefix
        ).digest()

    def get_algorithm_details(self) -> dict:
        p = self.params
        return {
            "algorithm": self.algorithm,
            "nist_level": p["nist_level"],
            "public_key_length": p["public_key_length"],
            "secret_key_length": p["secret_key_length"],
            "ciphertext_length": p["ciphertext_length"],
            "shared_secret_length": p["shared_secret_length"],
            "provider": "mock_sha_fallback",
            "is_quantum_safe": False,
            "security_warning": self._SECURITY_WARNING,
        }


class PQCProvider:
    """Post-Quantum ML-KEM provider via liboqs (fail-closed, mock fallback for tests)."""

    def __init__(
        self,
        algorithm: str = "ML-KEM-768",
        allow_mock: bool = False,
    ) -> None:
        if algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                f"Choose from: {SUPPORTED_ALGORITHMS}"
            )
        self.algorithm = algorithm
        self._use_native = _OQS_AVAILABLE

        if not self._use_native:
            _mock_enabled = allow_mock or ALLOW_MOCK_PQC
            if not _mock_enabled:
                raise PQCUnavailableError(
                    f"Native liboqs is required but not available. "
                    f"Reason: {_OQS_LOAD_ERROR or 'unknown'}. "
                    f"Install liboqs-python with its native C library, or set "
                    f"ALLOW_MOCK_PQC=1 to enable an insecure SHA-based mock "
                    f"(development/testing only — provides NO quantum security)."
                )
            self._mock = _MockInsecurePQCProvider(algorithm)

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a fresh ML-KEM keypair."""
        if not self._use_native:
            return self._mock.generate_keypair()

        with _oqs_module.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return secret_key, public_key

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate: generate a shared secret and ciphertext for the peer."""
        if not self._use_native:
            return self._mock.encapsulate(peer_public_key)

        with _oqs_module.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate: recover the shared secret from ciphertext."""
        if not self._use_native:
            return self._mock.decapsulate(secret_key, ciphertext)

        with _oqs_module.KeyEncapsulation(self.algorithm, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    @property
    def is_quantum_safe(self) -> bool:
        """True only when backed by the native liboqs C library."""
        return self._use_native

    def get_algorithm_details(self) -> dict:
        """Return detailed information about the configured algorithm."""
        if not self._use_native:
            return self._mock.get_algorithm_details()

        with _oqs_module.KeyEncapsulation(self.algorithm) as kem:
            details = kem.details
        return {
            "algorithm": self.algorithm,
            "nist_level": 3,
            "public_key_length": details["length_public_key"],
            "secret_key_length": details["length_secret_key"],
            "ciphertext_length": details["length_ciphertext"],
            "shared_secret_length": details["length_shared_secret"],
            "provider": "native_liboqs",
            "is_quantum_safe": True,
        }


MLDSA44_PARAMS = {
    "public_key_length": 1312,
    "secret_key_length": 2560,
    "signature_length": 2420,
}


class _MockInsecureSigProvider:
    """DEV/TEST ONLY — SHA-based mock of ML-DSA-44 signature interface."""

    def __init__(self) -> None:
        _logger.warning("[PQSig] *** MOCK INSECURE SIGNATURE PROVIDER ACTIVE ***")

    def generate_keypair(self) -> tuple[bytes, bytes]:
        seed = os.urandom(32)
        pk_hash = hashlib.sha512(b"MOCK_SIG_PK_" + seed).digest()
        sk = seed + (pk_hash * 50)[:MLDSA44_PARAMS["secret_key_length"] - 32]
        pk = (pk_hash * 30)[:MLDSA44_PARAMS["public_key_length"]]
        return sk, pk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        seed = secret_key[:32]
        pk = (hashlib.sha512(b"MOCK_SIG_PK_" + seed).digest() * 30)[:MLDSA44_PARAMS["public_key_length"]]
        tag = hmac.new(seed, b"MOCK_SIG_" + message, hashlib.sha256).digest()
        pk_id = hashlib.sha256(pk).digest()
        raw = tag + pk_id
        return (raw * 50)[:MLDSA44_PARAMS["signature_length"]]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(signature) != MLDSA44_PARAMS["signature_length"]:
            return False
        pk_id = hashlib.sha256(public_key).digest()
        return signature[32:64] == pk_id


class PQSignatureProvider:
    """Post-quantum signature provider for ML-DSA-44 via liboqs."""

    def __init__(self, allow_mock: bool = False) -> None:
        self._use_native = _OQS_AVAILABLE
        if not self._use_native:
            if not (allow_mock or ALLOW_MOCK_PQC):
                raise PQCUnavailableError("Native liboqs required for ML-DSA-44")
            self._mock = _MockInsecureSigProvider()

    def generate_keypair(self) -> tuple[bytes, bytes]:
        if not self._use_native:
            return self._mock.generate_keypair()
        with _oqs_module.Signature("ML-DSA-44") as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return sk, pk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if not self._use_native:
            return self._mock.sign(secret_key, message)
        with _oqs_module.Signature("ML-DSA-44", secret_key) as sig:
            return sig.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not self._use_native:
            return self._mock.verify(public_key, message, signature)
        with _oqs_module.Signature("ML-DSA-44") as sig:
            return sig.verify(message, signature, public_key)


DEFAULT_SALT_SIZE = 32
DEFAULT_KEY_LENGTH = 32
DEFAULT_INFO = b"hybrid-vpn-session-key"
INFO_ENCRYPTION_KEY = b"hybrid-vpn-encryption-key"
INFO_MAC_KEY = b"hybrid-vpn-mac-key"


def _secure_zero(data: bytearray) -> None:
    """Overwrite a bytearray with zeros in-place (best-effort secure erasure)."""
    if isinstance(data, bytearray):
        ctypes.memset(
            (ctypes.c_char * len(data)).from_buffer(data), 0, len(data)
        )


@dataclass
class SessionRecord:
    """A stored session's keying material and metadata."""
    session_id: str
    encryption_key: bytearray
    mac_key: bytearray
    created_at: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)


class KeyManager:
    """HKDF-SHA256 key derivation for combined classical + PQC secrets."""

    def derive_key(
        self,
        combined_secret: bytes,
        salt: Optional[bytes] = None,
        info: bytes = DEFAULT_INFO,
        length: int = DEFAULT_KEY_LENGTH,
    ) -> bytes:
        """Derive a single key via HKDF-SHA256."""
        if not combined_secret:
            raise ValueError("combined_secret must not be empty")

        hkdf = HKDF(
            algorithm=SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(combined_secret)

    def derive_key_pair(
        self,
        combined_secret: bytes,
        salt: Optional[bytes] = None,
    ) -> tuple[bytes, bytes]:
        """Derive separate encryption and MAC keys with distinct HKDF labels."""
        enc_key = self.derive_key(
            combined_secret, salt=salt, info=INFO_ENCRYPTION_KEY
        )
        mac_key = self.derive_key(
            combined_secret, salt=salt, info=INFO_MAC_KEY
        )
        return enc_key, mac_key

    @staticmethod
    def generate_salt(size: int = DEFAULT_SALT_SIZE) -> bytes:
        """Generate a cryptographically secure random salt."""
        return os.urandom(size)

    def derive_rekey_material(
        self,
        current_key: bytes,
        rekey_nonce: bytes,
        info: bytes = b"hybrid-vpn-rekey",
        length: int = DEFAULT_KEY_LENGTH,
    ) -> bytes:
        """Derive a successor key from an existing key + fresh nonce."""
        if len(rekey_nonce) < 16:
            raise ValueError("rekey_nonce must be at least 16 bytes")
        return self.derive_key(current_key, salt=rekey_nonce, info=info, length=length)

    def derive_rekey_pair(
        self,
        current_enc_key: bytes,
        rekey_nonce: bytes,
    ) -> tuple[bytes, bytes]:
        """Derive new encryption + MAC keys for in-session rekeying."""
        new_enc = self.derive_rekey_material(
            current_enc_key, rekey_nonce,
            info=b"hybrid-vpn-rekey-enc",
        )
        new_mac = self.derive_rekey_material(
            current_enc_key, rekey_nonce,
            info=b"hybrid-vpn-rekey-mac",
        )
        return new_enc, new_mac


class SessionKeyStore:
    """In-memory session key store with secure zero-on-revoke."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    def store_session(
        self,
        session_id: str,
        encryption_key: bytes,
        mac_key: bytes,
        metadata: Optional[dict] = None,
    ) -> SessionRecord:
        """Store a session's keying material (copies keys into bytearrays)."""
        if session_id in self._sessions:
            raise ValueError(
                f"Session '{session_id}' already exists. "
                "Revoke it before storing a new one."
            )
        record = SessionRecord(
            session_id=session_id,
            encryption_key=bytearray(encryption_key),
            mac_key=bytearray(mac_key),
            metadata=metadata or {},
        )
        self._sessions[session_id] = record
        return record

    def get_session(self, session_id: str) -> SessionRecord:
        """Retrieve a session's keying material."""
        if session_id not in self._sessions:
            raise KeyError(f"Session '{session_id}' not found")
        return self._sessions[session_id]

    def list_sessions(self) -> list[str]:
        """Return sorted list of active session IDs."""
        return sorted(self._sessions.keys())

    def revoke_session(self, session_id: str) -> None:
        """Securely wipe key material and remove the session."""
        if session_id not in self._sessions:
            raise KeyError(f"Session '{session_id}' not found")

        record = self._sessions[session_id]
        _secure_zero(record.encryption_key)
        _secure_zero(record.mac_key)
        del self._sessions[session_id]

    def revoke_all(self) -> int:
        """Securely revoke all sessions, return count."""
        session_ids = list(self._sessions.keys())
        for sid in session_ids:
            self.revoke_session(sid)
        return len(session_ids)

    @property
    def count(self) -> int:
        """Return the number of active sessions."""
        return len(self._sessions)



@dataclass
class HybridKeyBundle:
    """Key material from hybrid key exchange (ECC + PQC keypairs)."""
    ecc_private: X25519PrivateKey
    ecc_public: bytes
    pqc_secret: bytes
    pqc_public: bytes


class HybridKEM:
    """Hybrid KEM combining X25519 ECDH + ML-KEM-768 with HKDF-SHA256."""

    def __init__(
        self,
        pqc_algorithm: str = "ML-KEM-768",
        allow_mock_pqc: bool = False,
    ) -> None:
        self.ecc = ECCProvider()
        self.pqc = PQCProvider(algorithm=pqc_algorithm, allow_mock=allow_mock_pqc)
        self.key_manager = KeyManager()
        self.pqc_algorithm = pqc_algorithm

    def generate_keypairs(self) -> HybridKeyBundle:
        """Generate a complete hybrid keypair (ECC + PQC)."""
        ecc_private, ecc_public = self.ecc.generate_keypair()
        pqc_secret, pqc_public = self.pqc.generate_keypair()

        return HybridKeyBundle(
            ecc_private=ecc_private,
            ecc_public=ecc_public,
            pqc_secret=pqc_secret,
            pqc_public=pqc_public,
        )

    def encapsulate(
        self,
        peer_ecc_public: bytes,
        peer_pqc_public: bytes,
        own_ecc_private: X25519PrivateKey,
    ) -> tuple[bytes, bytes, bytes]:
        """Initiator-side: ECDH + ML-KEM encap → (ciphertext, ecc_ss, pqc_ss)."""
        ecc_shared_secret = self.ecc.derive_shared_secret(
            own_ecc_private, peer_ecc_public
        )

        pqc_ciphertext, pqc_shared_secret = self.pqc.encapsulate(
            peer_pqc_public
        )

        return pqc_ciphertext, ecc_shared_secret, pqc_shared_secret

    def decapsulate(
        self,
        pqc_secret_key: bytes,
        pqc_ciphertext: bytes,
        own_ecc_private: X25519PrivateKey,
        peer_ecc_public: bytes,
    ) -> tuple[bytes, bytes]:
        """Responder-side: ECDH + ML-KEM decap → (ecc_ss, pqc_ss)."""
        ecc_shared_secret = self.ecc.derive_shared_secret(
            own_ecc_private, peer_ecc_public
        )

        pqc_shared_secret = self.pqc.decapsulate(
            pqc_secret_key, pqc_ciphertext
        )

        return ecc_shared_secret, pqc_shared_secret

    def combine_secrets(
        self,
        ecc_shared_secret: bytes,
        pqc_shared_secret: bytes,
        salt: bytes | None = None,
    ) -> bytes:
        """Combine ECC + PQC secrets via HKDF → 32-byte session key."""
        combined = ecc_shared_secret + pqc_shared_secret
        return self.key_manager.derive_key(combined, salt=salt)

    def combine_secrets_to_pair(
        self,
        ecc_shared_secret: bytes,
        pqc_shared_secret: bytes,
        salt: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Combine secrets → separate (encryption_key, mac_key)."""
        combined = ecc_shared_secret + pqc_shared_secret
        return self.key_manager.derive_key_pair(combined, salt=salt)

    def get_info(self) -> dict:
        """Return hybrid KEM configuration details."""
        return {
            "classical": {
                "algorithm": "X25519",
                "public_key_size": ECCProvider.PUBLIC_KEY_SIZE,
                "shared_secret_size": ECCProvider.SHARED_SECRET_SIZE,
            },
            "post_quantum": self.pqc.get_algorithm_details(),
        }


def get_crypto_status() -> dict:
    """Return runtime cryptographic capability summary."""
    return {
        "liboqs_available": _OQS_AVAILABLE,
        "pqc_mode": "native_liboqs" if _OQS_AVAILABLE else (
            "mock_sha_fallback" if ALLOW_MOCK_PQC else "unavailable"
        ),
        "is_quantum_safe": _OQS_AVAILABLE,
        "allow_mock_pqc": ALLOW_MOCK_PQC,
        "load_error": _OQS_LOAD_ERROR,
        "security_warning": (
            None if _OQS_AVAILABLE
            else "INSECURE_MOCK — NO quantum protection" if ALLOW_MOCK_PQC
            else "PQC unavailable — install liboqs-python"
        ),
    }
