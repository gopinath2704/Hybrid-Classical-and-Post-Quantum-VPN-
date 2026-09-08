"""
Hybrid Classical + Post-Quantum Cryptography — Unified Module.

Consolidates all cryptographic primitives into a single file:
    1. ECCProvider           — Classical X25519 ECDH key exchange
    2. PQCProvider           — Post-Quantum ML-KEM (Kyber) via liboqs (fail-closed)
    3. KeyManager            — HKDF-SHA256 key derivation + rekeying support
    4. SessionKeyStore       — In-memory session key storage with secure revocation
    5. HybridKEM             — Combined hybrid key exchange orchestrator

Security model:
    The hybrid approach concatenates classical and post-quantum shared secrets
    and feeds them through HKDF-SHA256. The resulting session key is secure as
    long as *at least one* of the two primitives remains unbroken.

Fail-closed PQC policy:
    When native liboqs is unavailable, `PQCProvider` raises `PQCUnavailableError`
    by default.  Set the environment variable `ALLOW_MOCK_PQC=1` **only** during
    development/testing to enable the insecure SHA-based mock fallback.  When the
    mock is active every API call returns `is_quantum_safe=False` and a
    `security_warning` field.  Production deployments MUST install native liboqs.

Installing native crypto:
    Install native liboqs explicitly before the pinned Python binding.
    See docs/deployment.md; imports never initiate a native build.
"""

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


# ═══════════════════════════════════════════════════════════════════════════════
# §0  PQC Availability — Fail-Closed Enforcement
# ═══════════════════════════════════════════════════════════════════════════════

class PQCUnavailableError(RuntimeError):
    """
    Raised when native liboqs is required but not available.

    Install liboqs-python and its native C library to use real post-quantum
    cryptography.  During testing only, set environment variable
    ``ALLOW_MOCK_PQC=1`` to enable the insecure SHA-based mock fallback.

    WARNING: The mock fallback provides NO quantum security whatsoever.  It
    exists only to allow unit tests to run without the native library.
    """


# Allow mock only when explicitly opted-in via environment variable.
# Default (unset or "0") is fail-closed: raise PQCUnavailableError.
ALLOW_MOCK_PQC: bool = os.environ.get("ALLOW_MOCK_PQC", "0").strip() == "1"


# ═══════════════════════════════════════════════════════════════════════════════
# §1  Classical ECC — X25519 ECDH
# ═══════════════════════════════════════════════════════════════════════════════


class ECCProvider:
    """
    Classical ECC (X25519) key exchange provider.

    Usage (two-party ECDH):
        provider = ECCProvider()

        # --- Party A ---
        priv_a, pub_a = provider.generate_keypair()

        # --- Party B ---
        priv_b, pub_b = provider.generate_keypair()

        # --- Both derive the same shared secret ---
        secret_a = provider.derive_shared_secret(priv_a, pub_b)
        secret_b = provider.derive_shared_secret(priv_b, pub_a)
        assert secret_a == secret_b  # 32-byte identical shared secret
    """

    # X25519 key sizes (bytes)
    PUBLIC_KEY_SIZE = 32
    SHARED_SECRET_SIZE = 32

    def generate_keypair(self) -> tuple[X25519PrivateKey, bytes]:
        """
        Generate a fresh X25519 keypair.

        Returns:
            tuple: (private_key_object, public_key_raw_bytes)
                - private_key_object: X25519PrivateKey instance (keep secret)
                - public_key_raw_bytes: 32-byte public key for wire transmission
        """
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
        """
        Perform X25519 ECDH to derive a shared secret.

        Args:
            private_key: Our X25519 private key object.
            peer_public_bytes: The remote party's 32-byte raw public key.

        Returns:
            bytes: 32-byte shared secret.

        Raises:
            ValueError: If peer_public_bytes is not exactly 32 bytes.
        """
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
        """
        Serialize an X25519 public key object to 32-byte raw bytes.

        Args:
            public_key: X25519PublicKey object.

        Returns:
            bytes: 32-byte raw public key suitable for wire transport.
        """
        return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def deserialize_public_key(raw_bytes: bytes) -> X25519PublicKey:
        """
        Deserialize 32-byte raw bytes into an X25519PublicKey object.

        Args:
            raw_bytes: 32-byte raw public key.

        Returns:
            X25519PublicKey: Reconstructed public key object.

        Raises:
            ValueError: If raw_bytes is not exactly 32 bytes.
        """
        if len(raw_bytes) != 32:
            raise ValueError(
                f"X25519 public key must be 32 bytes, got {len(raw_bytes)}"
            )
        return X25519PublicKey.from_public_bytes(raw_bytes)


# ═══════════════════════════════════════════════════════════════════════════════
# §2  Post-Quantum KEM — ML-KEM (Kyber) via liboqs
# ═══════════════════════════════════════════════════════════════════════════════

# Protocol version 2 deliberately supports one fixed-size standardized KEM.
SUPPORTED_ALGORITHMS = ("ML-KEM-768",)

# Algorithm parameter specs (bytes)
# Matches NIST FIPS 203 / Kyber specifications
MLKEM_PARAMS = {
    "ML-KEM-768": {
        "nist_level": 3,
        "public_key_length": 1184,
        "secret_key_length": 2400,
        "ciphertext_length": 1088,
        "shared_secret_length": 32,
    },
}
# Compatibility import only; no legacy name is accepted by the provider.
KYBER_PARAMS = MLKEM_PARAMS

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
    """
    DEV/TEST ONLY — SHA-based mock of ML-KEM KEM interface.

    WARNING: This provider performs NO real post-quantum cryptography.
    Key material is derived from SHA-256/SHA-512 hashes and provides
    ZERO quantum security.  It exists solely to allow the test suite to
    run without native liboqs installed.

    This class MUST NOT be used in any production or security-sensitive
    context.  Every method returns `is_quantum_safe=False` in its details
    and logs a prominent warning.
    """

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
    """
    Post-Quantum KEM provider backed by liboqs (with software fallback).

    Usage (two-party KEM):
        provider = PQCProvider("ML-KEM-768")

        # --- Receiver generates keypair ---
        secret_key, public_key = provider.generate_keypair()

        # --- Sender encapsulates ---
        ciphertext, shared_secret_sender = provider.encapsulate(public_key)

        # --- Receiver decapsulates ---
        shared_secret_receiver = provider.decapsulate(secret_key, ciphertext)

        assert shared_secret_sender == shared_secret_receiver
    """

    def __init__(
        self,
        algorithm: str = "ML-KEM-768",
        allow_mock: bool = False,
    ) -> None:
        """
        Args:
            algorithm:  Only 'ML-KEM-768' is supported by protocol v2.
            allow_mock: If True, allow the insecure SHA-based mock fallback
                        when native liboqs is unavailable.  Has no effect when
                        native liboqs is present.  Defaults to False (fail-closed).
                        The global ``ALLOW_MOCK_PQC`` env variable also enables this.
        """
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


# ═══════════════════════════════════════════════════════════════════════════════
# §3  Key Derivation — HKDF-SHA256
# ═══════════════════════════════════════════════════════════════════════════════

# Default HKDF parameters
DEFAULT_SALT_SIZE = 32        # 256-bit random salt
DEFAULT_KEY_LENGTH = 32       # 256-bit derived key
DEFAULT_INFO = b"hybrid-vpn-session-key"

# Separate info labels for encryption vs. MAC keys
INFO_ENCRYPTION_KEY = b"hybrid-vpn-encryption-key"
INFO_MAC_KEY = b"hybrid-vpn-mac-key"


def _secure_zero(data: bytearray) -> None:
    """
    Overwrite a bytearray with zeros in-place.

    This provides best-effort secure erasure. Python's garbage collector
    may still leave copies, but this prevents the most obvious leaks.
    """
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
    """
    HKDF-SHA256 key derivation for the hybrid VPN.

    Takes the concatenation of classical + post-quantum shared secrets
    and derives deterministic, cryptographically strong session keys.

    Usage:
        km = KeyManager()
        combined = ecc_shared + pqc_shared          # 64 bytes
        session_key = km.derive_key(combined)         # 32-byte key
        enc_key, mac_key = km.derive_key_pair(combined)  # two 32-byte keys
    """

    def derive_key(
        self,
        combined_secret: bytes,
        salt: Optional[bytes] = None,
        info: bytes = DEFAULT_INFO,
        length: int = DEFAULT_KEY_LENGTH,
    ) -> bytes:
        """
        Derive a single key from the combined shared secret.

        Args:
            combined_secret: Concatenated ECC + PQC shared secrets.
            salt: Optional salt bytes. If None, a random 32-byte salt is NOT
                  generated (salt=None is valid per RFC 5869 — HKDF uses a
                  zero-filled salt of hash length internally).
            info: Context/application-specific info string.
            length: Desired output key length in bytes.

        Returns:
            bytes: Derived key of the requested length.

        Raises:
            ValueError: If combined_secret is empty.
        """
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
        """
        Derive separate encryption and MAC keys from the combined secret.

        Uses distinct HKDF info labels to ensure cryptographic separation:
        - Encryption key: info = b"hybrid-vpn-encryption-key"
        - MAC key:        info = b"hybrid-vpn-mac-key"

        Args:
            combined_secret: Concatenated ECC + PQC shared secrets.
            salt: Optional salt (same salt used for both derivations).

        Returns:
            tuple: (encryption_key, mac_key) — both 32 bytes.
        """
        enc_key = self.derive_key(
            combined_secret, salt=salt, info=INFO_ENCRYPTION_KEY
        )
        mac_key = self.derive_key(
            combined_secret, salt=salt, info=INFO_MAC_KEY
        )
        return enc_key, mac_key

    @staticmethod
    def generate_salt(size: int = DEFAULT_SALT_SIZE) -> bytes:
        """
        Generate a cryptographically secure random salt.

        Args:
            size: Salt length in bytes (default 32).

        Returns:
            bytes: Random salt.
        """
        return os.urandom(size)

    def derive_rekey_material(
        self,
        current_key: bytes,
        rekey_nonce: bytes,
        info: bytes = b"hybrid-vpn-rekey",
        length: int = DEFAULT_KEY_LENGTH,
    ) -> bytes:
        """
        Derive a new key from an existing key for in-session rekeying.

        Uses the current session key as HKDF input keying material combined
        with a fresh random nonce to produce a successor key. This is key
        evolution, not recovery from compromise of the current key.
        After calling this, the caller should securely erase the old key.

        Args:
            current_key:  The current session key (will be used as IKM).
            rekey_nonce:  A fresh random nonce (≥16 bytes) to ensure uniqueness.
            info:         HKDF context label (default b"hybrid-vpn-rekey").
            length:       Output key length in bytes (default 32).

        Returns:
            bytes: New derived key for use as successor session key.
        """
        if len(rekey_nonce) < 16:
            raise ValueError("rekey_nonce must be at least 16 bytes")
        # Use the nonce as salt so each rekeying round is independent
        return self.derive_key(current_key, salt=rekey_nonce, info=info, length=length)

    def derive_rekey_pair(
        self,
        current_enc_key: bytes,
        rekey_nonce: bytes,
    ) -> tuple[bytes, bytes]:
        """
        Derive new encryption + MAC keys for in-session rekeying.

        Both keys use the same rekey_nonce so they are bound together.

        Args:
            current_enc_key: The current AES encryption key (used as IKM).
            rekey_nonce:     A fresh random nonce (≥16 bytes).

        Returns:
            tuple: (new_encryption_key, new_mac_key) — both 32 bytes.
        """
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
    """
    In-memory session key store with secure revocation.

    Stores derived encryption and MAC keys indexed by session ID.
    On revocation, key material is overwritten with zeros before deletion.

    Usage:
        store = SessionKeyStore()
        store.store_session("sess-001", enc_key, mac_key)
        record = store.get_session("sess-001")
        store.revoke_session("sess-001")
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    def store_session(
        self,
        session_id: str,
        encryption_key: bytes,
        mac_key: bytes,
        metadata: Optional[dict] = None,
    ) -> SessionRecord:
        """
        Store a session's keying material.

        Keys are copied into mutable bytearrays so they can be securely
        wiped on revocation.

        Args:
            session_id: Unique identifier for the session.
            encryption_key: 32-byte AES encryption key.
            mac_key: 32-byte MAC/authentication key.
            metadata: Optional dict of session metadata (peer info, etc.).

        Returns:
            SessionRecord: The stored session record.

        Raises:
            ValueError: If session_id already exists (use revoke first).
        """
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
        """
        Retrieve a session's keying material.

        Args:
            session_id: The session to look up.

        Returns:
            SessionRecord: The stored record.

        Raises:
            KeyError: If session_id is not found.
        """
        if session_id not in self._sessions:
            raise KeyError(f"Session '{session_id}' not found")
        return self._sessions[session_id]

    def list_sessions(self) -> list[str]:
        """
        List all active session IDs.

        Returns:
            list[str]: Sorted list of session IDs.
        """
        return sorted(self._sessions.keys())

    def revoke_session(self, session_id: str) -> None:
        """
        Securely revoke a session by wiping its key material.

        Overwrites encryption_key and mac_key with zeros, then
        removes the session from the store.

        Args:
            session_id: The session to revoke.

        Raises:
            KeyError: If session_id is not found.
        """
        if session_id not in self._sessions:
            raise KeyError(f"Session '{session_id}' not found")

        record = self._sessions[session_id]
        # Secure wipe key material
        _secure_zero(record.encryption_key)
        _secure_zero(record.mac_key)
        del self._sessions[session_id]

    def revoke_all(self) -> int:
        """
        Securely revoke all sessions.

        Returns:
            int: Number of sessions revoked.
        """
        session_ids = list(self._sessions.keys())
        for sid in session_ids:
            self.revoke_session(sid)
        return len(session_ids)

    @property
    def count(self) -> int:
        """Return the number of active sessions."""
        return len(self._sessions)


# ═══════════════════════════════════════════════════════════════════════════════
# §4  Hybrid KEM — X25519 + ML-KEM Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class HybridKeyBundle:
    """
    Container for all key material generated during hybrid key exchange.

    Attributes:
        ecc_private:  X25519 private key object (keep secret).
        ecc_public:   32-byte raw X25519 public key (send to peer).
        pqc_secret:   ML-KEM secret key bytes (keep secret, for decapsulation).
        pqc_public:   ML-KEM public key bytes (send to peer).
    """
    ecc_private: X25519PrivateKey
    ecc_public: bytes
    pqc_secret: bytes
    pqc_public: bytes


class HybridKEM:
    """
    Hybrid Key Encapsulation Mechanism combining X25519 + ML-KEM.

    Usage (full two-party exchange):
        hybrid = HybridKEM()

        # --- Server (responder) ---
        server_keys = hybrid.generate_keypairs()

        # --- Client (initiator) ---
        client_keys = hybrid.generate_keypairs()

        # Client encapsulates towards server
        pqc_ct, ecc_ss, pqc_ss = hybrid.encapsulate(
            peer_ecc_public=server_keys.ecc_public,
            peer_pqc_public=server_keys.pqc_public,
            own_ecc_private=client_keys.ecc_private,
        )

        # Server decapsulates
        ecc_ss_srv, pqc_ss_srv = hybrid.decapsulate(
            pqc_secret_key=server_keys.pqc_secret,
            pqc_ciphertext=pqc_ct,
            own_ecc_private=server_keys.ecc_private,
            peer_ecc_public=client_keys.ecc_public,
        )

        # Both derive the same session key
        session_key_client = hybrid.combine_secrets(ecc_ss, pqc_ss)
        session_key_server = hybrid.combine_secrets(ecc_ss_srv, pqc_ss_srv)
        assert session_key_client == session_key_server
    """

    def __init__(
        self,
        pqc_algorithm: str = "ML-KEM-768",
        allow_mock_pqc: bool = False,
    ) -> None:
        """
        Initialise the hybrid KEM.

        Args:
            pqc_algorithm:   Only 'ML-KEM-768' is supported by protocol v2.
            allow_mock_pqc:  Forward to PQCProvider — enables insecure mock fallback
                             when liboqs is unavailable.  Dev/testing only.
        """
        self.ecc = ECCProvider()
        self.pqc = PQCProvider(algorithm=pqc_algorithm, allow_mock=allow_mock_pqc)
        self.key_manager = KeyManager()
        self.pqc_algorithm = pqc_algorithm

    def generate_keypairs(self) -> HybridKeyBundle:
        """
        Generate a complete hybrid keypair (ECC + PQC).

        Returns:
            HybridKeyBundle: Contains all key material for one party.
        """
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
        """
        Initiator-side hybrid encapsulation.

        Performs:
        1. X25519 ECDH with peer's ECC public key → ecc_shared_secret (32 bytes)
        2. ML-KEM encapsulation with peer's PQC public key → (ciphertext, pqc_shared_secret)

        The PQC ciphertext must be transmitted to the peer for decapsulation.

        Args:
            peer_ecc_public: Peer's 32-byte X25519 public key.
            peer_pqc_public: Peer's ML-KEM public key bytes.
            own_ecc_private: Our X25519 private key.

        Returns:
            tuple: (pqc_ciphertext, ecc_shared_secret, pqc_shared_secret)
        """
        # Classical ECDH
        ecc_shared_secret = self.ecc.derive_shared_secret(
            own_ecc_private, peer_ecc_public
        )

        # Post-quantum KEM encapsulation
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
        """
        Responder-side hybrid decapsulation.

        Performs:
        1. X25519 ECDH with peer's ECC public key → ecc_shared_secret
        2. ML-KEM decapsulation of ciphertext → pqc_shared_secret

        Args:
            pqc_secret_key: Our ML-KEM secret key bytes.
            pqc_ciphertext: Ciphertext received from the initiator.
            own_ecc_private: Our X25519 private key.
            peer_ecc_public: Peer's 32-byte X25519 public key.

        Returns:
            tuple: (ecc_shared_secret, pqc_shared_secret) — both 32 bytes.
        """
        # Classical ECDH
        ecc_shared_secret = self.ecc.derive_shared_secret(
            own_ecc_private, peer_ecc_public
        )

        # Post-quantum KEM decapsulation
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
        """
        Combine classical and post-quantum shared secrets into a session key.

        Concatenates both secrets and passes them through HKDF-SHA256 to
        produce a single 32-byte session key.

        Args:
            ecc_shared_secret: 32-byte X25519 shared secret.
            pqc_shared_secret: 32-byte ML-KEM shared secret.
            salt: Optional HKDF salt.

        Returns:
            bytes: 32-byte derived session key.
        """
        combined = ecc_shared_secret + pqc_shared_secret
        return self.key_manager.derive_key(combined, salt=salt)

    def combine_secrets_to_pair(
        self,
        ecc_shared_secret: bytes,
        pqc_shared_secret: bytes,
        salt: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """
        Combine secrets and derive separate encryption + MAC keys.

        Args:
            ecc_shared_secret: 32-byte X25519 shared secret.
            pqc_shared_secret: 32-byte ML-KEM shared secret.
            salt: Optional HKDF salt.

        Returns:
            tuple: (encryption_key, mac_key) — both 32 bytes.
        """
        combined = ecc_shared_secret + pqc_shared_secret
        return self.key_manager.derive_key_pair(combined, salt=salt)

    def get_info(self) -> dict:
        """
        Return information about the hybrid KEM configuration.

        Returns:
            dict: Includes ECC details and PQC algorithm details.
        """
        return {
            "classical": {
                "algorithm": "X25519",
                "public_key_size": ECCProvider.PUBLIC_KEY_SIZE,
                "shared_secret_size": ECCProvider.SHARED_SECRET_SIZE,
            },
            "post_quantum": self.pqc.get_algorithm_details(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level availability summary (for logging / status endpoints)
# ─────────────────────────────────────────────────────────────────────────────

def get_crypto_status() -> dict:
    """
    Return a dictionary describing the runtime cryptographic capability.

    This is used by the API and UI to display accurate mode indicators.
    """
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
