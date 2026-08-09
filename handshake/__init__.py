"""
Signature-Free Handshake Protocol Package (KEMTLS-Inspired).
Manages packet serialization, state machines, and session key establishment without digital signatures.

All components are consolidated in the unified ``kemtls`` module.
"""

from handshake.kemtls import (
    # Wire protocol constants
    MAGIC,
    PROTOCOL_VERSION,
    HEADER_SIZE,
    MessageType,
    HandshakeError,

    # Message data classes
    ClientHello,
    ServerHello,
    ClientKeyExchange,
    ServerFinished,

    # Transcript integrity
    TranscriptHasher,

    # Session context
    HandshakeState,
    HandshakeSession,

    # State machines
    KEMTLSClient,
    KEMTLSServer,
)

__all__ = [
    "MAGIC",
    "PROTOCOL_VERSION",
    "HEADER_SIZE",
    "MessageType",
    "HandshakeError",
    "ClientHello",
    "ServerHello",
    "ClientKeyExchange",
    "ServerFinished",
    "TranscriptHasher",
    "HandshakeState",
    "HandshakeSession",
    "KEMTLSClient",
    "KEMTLSServer",
]
