# Team Roles & Responsibilities

## 👤 Gowtham supported by Shadow – Networking & VPN

### Responsibilities
- Set up OpenVPN or strongSwan
- Study VPN architecture
- Implement Dynamic Network Agility
- Measure latency, MTU, and packet fragmentation
- Perform network performance testing

### Learn
- TCP/IP
- VPN
- Linux Networking
- Wireshark
- Bash
- OpenVPN

---

## 👤 Karthik supported by Shadow – Cryptography

### Responsibilities
- Implement Hybrid Cryptography
- Integrate ML-KEM
- Develop Classical + Post-Quantum (PQC) Key Exchange
- Manage cryptographic keys

### Learn
- AES
- RSA
- ECC
- ML-KEM (Kyber)
- OpenSSL
- liboqs

---

## 👤 Nandha supported by Shadow – Secure Handshake & Performance

### Responsibilities
- Implement Signature-Free Handshake (KEMTLS-inspired)
- Analyze TLS handshake
- Benchmark handshake size
- Measure connection setup time

### Learn
- TLS
- KEMTLS Concepts
- Packet Capture
- Performance Benchmarking
- Python Scripting

---

## 👤 Shadow – Integration, Testing & Documentation

### Responsibilities
- Integrate all project components
- Docker/Linux deployment
- Testing and validation
- GitHub repository management
- Final report preparation
- Presentation development

### Learn
- Git
- Docker
- Linux
- Documentation
- System Architecture
- Performance Analysis

---

# Revised Project Architecture & Application Flow

```text
 ┌─────────────────────────────────────────────────────────────┐
 │                  Desktop GUI / Web App UI                  │
 │  (Connection Toggle, Real-Time MTU/Latency Graphs, Logs)   │
 └──────────────────────────────┬──────────────────────────────┘
                                │ API / IPC Socket
 ┌──────────────────────────────▼──────────────────────────────┐
 │                    VPN Controller Daemon                    │
 │                                                             │
 │  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐  │
 │  │ Hybrid Key Exch. │  │ Signature-Free   │  │  Dynamic  │  │
 │  │  (ECC + ML-KEM)  │  │ Handshake Engine │  │ Network   │  │
 │  └─────────┬────────┘  └─────────┬────────┘  │  Agility  │  │
 │            └─────────────────────┤           └─────┬─────┘  │
 └──────────────────────────────────┼─────────────────┼────────┘
                                    │ Derived Keys    │ MTU/Route
 ┌──────────────────────────────────▼─────────────────▼────────┐
 │                      VPN Tunnel Layer                       │
 │    Option A: Modified OpenVPN Engine (via Plugin/Mgmt)      │
 │    Option B: Native Standalone Hybrid TUN/TAP Engine        │
 └─────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **User / Client** interacts with the Desktop GUI / Web Application interface.
2. **GUI Application** sends control commands (Connect/Disconnect/Benchmark) via REST/WebSocket API to the **VPN Controller Daemon**.
3. **Hybrid Key Exchange** combines classical ECC (X25519) and Post-Quantum Cryptography (ML-KEM / Kyber-768 via `liboqs`) for quantum-safe key establishment.
4. **Signature-Free Handshake** establishes an authenticated secure session using a zero-signature KEMTLS-inspired protocol.
5. **Dynamic Network Agility** continuously monitors PMTU, fragmentation, RTT latency, and jitter to adjust network parameters on the fly.
6. **VPN Tunnel Layer** encrypts and routes data traffic through a native TUN/TAP interface or modified OpenVPN tunnel.
7. **Server Node** processes the secure communication and routes decrypted traffic.

---

## 🔐 Cryptographic Specifications & Key Architecture

The system uses a hybrid classical and post-quantum key encapsulation mechanism (`crypto/hybrid_crypto.py`).

### 1. Classical Cryptography (ECC)
* **Algorithm**: **X25519** (Elliptic Curve Diffie-Hellman over Curve25519)
* **Classical Security**: 128-bit security level
* **Private Key**: 32 bytes (`X25519PrivateKey`)
* **Public Key**: 32 bytes (Raw uncompressed bytes for wire transport)
* **Shared Secret**: 32 bytes

### 2. Post-Quantum Cryptography (PQC)
* **Algorithm**: **ML-KEM** (NIST FIPS 203 standardized Module-Lattice-Based KEM, formerly *CRYSTALS-Kyber*)
* **Default Variant**: **Kyber768** (NIST Security Category 3 $\approx$ AES-192 equivalent)
* **Supported Variants**:

| Variant | NIST Level | Public Key | Secret Key | Ciphertext | PQ Shared Secret |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Kyber512** | Level 1 | 800 B | 1,632 B | 768 B | 32 bytes |
| **Kyber768** *(Default)* | Level 3 | **1,184 B** | **2,400 B** | **1,088 B** | **32 bytes** |
| **Kyber1024** | Level 5 | 1,568 B | 3,168 B | 1,568 B | 32 bytes |

### 3. Hybrid Combination & Key Derivation (KDF)
```text
  [ ECC Shared Secret (32B) ] + [ PQC Shared Secret (32B) ]
                              │
                              ▼
                 [ Combined Secret (64 Bytes) ]
                              │
                              ▼
                        HKDF-SHA256
                              │
         ┌────────────────────┴────────────────────┐
         ▼                                         ▼
[ Encryption Key (32B) ]                 [ MAC Key (32B) ]
(b"hybrid-vpn-encryption-key")         (b"hybrid-vpn-mac-key")
```
* **Master Secret**: Concatenation of ECC (32B) + PQC (32B) = **64 bytes**.
* **KDF Algorithm**: **HKDF-SHA256** (RFC 5869).
* **Salt**: **32-byte** cryptographically secure random salt (`os.urandom(32)`).
* **Derived Session Keys**:
  * **Encryption Key**: 32 bytes (256-bit AES-GCM key) derived with info `b"hybrid-vpn-encryption-key"`.
  * **MAC / Integrity Key**: 32 bytes (256-bit HMAC key) derived with info `b"hybrid-vpn-mac-key"`.

### 4. Memory Security & Key Revocation
* **Storage**: In-memory `SessionKeyStore` using mutable `bytearray` buffers.
* **Zeroization**: Instant secure overwrite of memory via `ctypes.memset` zero-fill on session revocation to eliminate RAM residue.

---

## 🤝 Signature-Free Handshake Architecture (KEMTLS-Inspired)

The system implements a signature-free post-quantum hybrid handshake (`handshake/kemtls.py`) based on KEMTLS principles, replacing expensive post-quantum digital signatures with key encapsulation mechanisms.

### 1. Wire Protocol Specification
All wire messages start with a fixed 6-byte header formatted in big-endian network byte order:
* **Header Format**: `Magic (2B: 0x4856 "HV") | Version (1B: 0x10) | Type (1B) | PayloadLength (2B)`

| Message Type | Type Code | Payload Components & Exact Sizes | Total Wire Size |
| :--- | :---: | :--- | :---: |
| **ClientHello** | `0x01` | Client Random (32B) + Session ID (32B) + Client ECC Public Key (32B) + Client Kyber768 Public Key (1,184B) | **1,286 B** |
| **ServerHello** | `0x02` | Server Random (32B) + Session ID (32B) + Server ECC Public Key (32B) + Server Kyber768 Public Key (1,184B) + Kyber768 Ciphertext to Client (1,088B) | **2,374 B** |
| **ClientKeyExchange** | `0x03` | Kyber768 Ciphertext to Server (1,088B) + Client Finished MAC (32B) | **1,126 B** |
| **ServerFinished** | `0x04` | Server Finished MAC (32B) | **38 B** |
| **HandshakeError** | `0xFF` | Error Code + UTF-8 Description | Variable |

### 2. Handshake Protocol Sequence & Data Flow

```text
 Client (Initiator)                                                Server (Responder)
   │                                                                    │
   │ ─── 1. ClientHello (1,286 Bytes) ───────────────────────────────> │
   │       (Ephemeral X25519 PK + Ephemeral Kyber768 PK)                │
   │                                                                    │
   │ <── 2. ServerHello (2,374 Bytes) ─────────────────────────────── │
   │       (Ephemeral X25519 PK + Kyber768 PK + Kyber768 CT to Client)   │
   │                                                                    │
   │ ─── 3. ClientKeyExchange (1,126 Bytes) ─────────────────────────> │
   │       (Kyber768 CT to Server + Client Finished HMAC over Transcript)│
   │                                                                    │
   │ <── 4. ServerFinished (38 Bytes) ───────────────────────────────── │
   │       (Server Finished HMAC over Transcript)                       │
   │                                                                    │
   │ ================================================================== │
   │                AES-256-GCM Secure Data Channel                     │
```

### 3. Transcript Integrity & Security Guarantees
* **Transcript Binding**: `TranscriptHasher` maintains an incremental SHA-256 digest of all handshake bytes exchanged.
* **Handshake Authentication**: Finished MACs (`HMAC-SHA256`) bind derived keys to the complete, un-tampered transcript, eliminating signature generation/verification overhead while guaranteeing anti-tampering and key authentication.
* **Transport Encryption**: Successful handshake establishes a `HandshakeSession` using **AES-256-GCM** authenticated encryption with 12-byte nonces (`8-byte sequence counter + 4-byte random salt`) for data tunnel frames.

---

## Technology Stack

| Component | Technologies |
|-----------|--------------|
| VPN | OpenVPN / strongSwan |
| Cryptography | AES, ECC, ML-KEM (Kyber), OpenSSL, liboqs |
| Networking | TCP/IP, Linux Networking, Wireshark |
| Handshake | TLS, KEMTLS-inspired Protocol |
| Development | Bash, Python |
| Deployment | Docker, Linux |
| Version Control | Git, GitHub |
| Documentation | Markdown, Reports, Presentations |

---

## Project Deliverables

- Secure VPN with Hybrid Cryptography
- Signature-Free Handshake Implementation
- Dynamic Network Agility Module
- Performance Benchmark Report
- Dockerized Deployment
- GitHub Repository
- Final Project Report
- Project Presentation
