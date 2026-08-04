# System Architecture & Protocol Specification

## 1. Overview
This document specifies the system architecture for the Hybrid Classical and Post-Quantum Cryptography VPN Application.

## 2. Hybrid Key Exchange Protocol (ECC + ML-KEM)
- **Classical ECC**: X25519 Curve (Curve25519)
- **Post-Quantum KEM**: ML-KEM-768 (Kyber768 NIST Standard)
- **Key Derivation**: HKDF-SHA256

## 3. Signature-Free Handshake (KEMTLS-Inspired)
Protocol sequence avoiding digital signatures:
1. `ClientHello` -> Sends client ephemeral public key
2. `ServerHello` -> Sends static/ephemeral server KEM public key & ciphertext
3. `ClientKeyExchange` -> Encapsulates shared secret to server static key
4. `Finished` -> Derives master session key & validates MAC
