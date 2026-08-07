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
