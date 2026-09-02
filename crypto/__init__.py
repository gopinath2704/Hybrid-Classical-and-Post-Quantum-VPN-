"""
Hybrid Cryptography Package.

Provides classical ECC (X25519), post-quantum ML-KEM (Kyber-768),
and hybrid key exchange combining both with HKDF-SHA256 derivation.

Public API:
    ECCProvider       — X25519 ECDH key generation & shared secret derivation
    PQCProvider       — ML-KEM (Kyber) key encapsulation via liboqs
    HybridKEM         — Combined hybrid key exchange manager
    HybridKeyBundle   — Dataclass holding a party's complete key material
    KeyManager        — HKDF-SHA256 key derivation
    SessionKeyStore   — In-memory session key store with secure revocation
    PQCUnavailableError
    get_crypto_status
    ALLOW_MOCK_PQC
"""

from crypto.hybrid_crypto import (
    ECCProvider,
    PQCProvider,
    HybridKEM,
    HybridKeyBundle,
    KeyManager,
    SessionKeyStore,
    SUPPORTED_ALGORITHMS,
    KYBER_PARAMS,
    PQCUnavailableError,
    get_crypto_status,
    ALLOW_MOCK_PQC,
)

__all__ = [
    "ECCProvider",
    "PQCProvider",
    "HybridKEM",
    "HybridKeyBundle",
    "KeyManager",
    "SessionKeyStore",
    "SUPPORTED_ALGORITHMS",
    "KYBER_PARAMS",
    "PQCUnavailableError",
    "get_crypto_status",
    "ALLOW_MOCK_PQC",
]
