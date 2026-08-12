# Hybrid Classical & Post-Quantum Cryptography VPN

> **Project Status**: ✅ **100% FULLY IMPLEMENTED** (Phases 0, 1, 2, 3, 4, 5 Complete)  
> **Automated Test Suite**: ✅ **161 / 161 Tests Passing (100% Pass Rate)**  
> **Cipher Suite**: **AES-256-GCM + Hybrid X25519 (ECDH) & ML-KEM-768 (Kyber768) + Signature-Free KEMTLS**

---

## 📌 Project Overview

This repository implements a production-grade **Hybrid Classical and Post-Quantum Cryptography VPN (PQ-VPN)** application. It combines **ECDH (X25519)** with **NIST ML-KEM (Kyber-768)** for quantum-safe key exchange, uses a **Signature-Free KEMTLS Handshake** for fast 1.5-RTT connection setup, features **Dynamic Network Agility** (PMTU discovery and RFC 3550 jitter/RTT quality monitoring), and provides a modern **Cross-Platform Desktop Application (PyWebView / FastAPI)** with live telemetry graphs.

---

## 👥 Team Roles & Responsibilities

### 👤 Gowtham supported by Shadow – Networking & VPN Engine (`vpn/`)
- Implemented native `/dev/net/tun` interface with cross-platform TCP loopback socket fallback for Windows/macOS.
- Implemented asynchronous `VPNTunnelDaemon` event loop for packet encapsulation and UDP transport.
- Implemented `MTUMonitor` for dynamic PMTU discovery (DF-bit probing), TCP MSS clamping, and overhead math (58B IPv4 / 78B IPv6).
- Implemented `NetworkQualityMonitor` for RFC 3550 exponential moving average jitter, RTT rolling window, and packet loss tracking.
- Implemented `OpenVPNManager` for runtime control sockets and dynamic `.ovpn` configuration generation.

### 👤 Karthik supported by Shadow – Hybrid Cryptography (`crypto/`)
- Implemented `ECCProvider` for X25519 ECDH keypair generation and raw 32-byte public key serialization.
- Implemented `PQCProvider` wrapping `liboqs` for ML-KEM (Kyber-512, Kyber-768, Kyber-1024) with graceful software fallback.
- Implemented `KeyManager` with HKDF-SHA256 (RFC 5869) key derivation for separate encryption (`b"hybrid-vpn-encryption-key"`) and MAC (`b"hybrid-vpn-mac-key"`) keys.
- Implemented `SessionKeyStore` with in-memory CRUD and instant zero-wipe (`ctypes.memset`) for secure key revocation.
- Implemented `HybridKEM` orchestrator combining classical + post-quantum key exchange into 64-byte master secrets.

### 👤 Nandha supported by Shadow – Signature-Free KEMTLS Handshake & Benchmarks (`handshake/`, `benchmarks/`)
- Implemented binary wire protocol with 6-byte header (`0x4856` magic, `ClientHello`, `ServerHello`, `ClientKeyExchange`, `ServerFinished`).
- Implemented `TranscriptHasher` SHA-256 cumulative transcript binding and `HMAC-SHA256` Finished MAC verification.
- Implemented `KEMTLSClient` and `KEMTLSServer` state machines driving full 1.5-RTT handshake lifecycle.
- Implemented benchmark suite (`benchmarks/`) for handshake setup timing (ms), throughput payload scaling (Mbps), and Scapy packet overhead analysis.
- Built Matplotlib chart generator producing 4 publication-quality 300 DPI chart PNGs (`benchmarks/results/`).

### 👤 Shadow – Integration, GUI Application, Testing & Documentation (`app/`, `tests/`, `docs/`)
- Built cross-platform desktop application launcher (`app/main.py`) with PyWebView native window, `--web` browser mode, and `--cli` headless mode.
- Developed FastAPI REST API & real-time WebSocket telemetry broadcaster (`/ws/telemetry`, 500ms push interval).
- Built dark glassmorphic HTML/CSS/JS dashboard UI with live Chart.js bandwidth graphs, security badges, and cryptographic stack visual.
- Created complete 161-test automated integration test suite across all 6 modules.
- Docker multi-container setup (`docker-compose.yml`, `Dockerfile.server`, `Dockerfile.client`) and full project documentation.

---

## 🏗 Architecture & System Flow

```text
 ┌─────────────────────────────────────────────────────────────┐
 │                  Desktop GUI / Web App UI                  │
 │  (Connection Toggle, Real-Time MTU/Latency Graphs, Logs)   │
 └──────────────────────────────┬──────────────────────────────┘
                                │ REST API / WebSocket (/ws/telemetry)
 ┌──────────────────────────────▼──────────────────────────────┐
 │                    VPN Controller Daemon                    │
 │                                                             │
 │  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐  │
 │  │ Hybrid Key Exch. │  │ Signature-Free   │  │  Dynamic  │  │
 │  │ (X25519+Kyber768)│  │ Handshake Engine │  │ Network   │  │
 │  └─────────┬────────┘  └─────────┬────────┘  │  Agility  │  │
 │            └─────────────────────┤           └─────┬─────┘  │
 │                                  │ Derived Keys    │ MTU/Route
 ┌──────────────────────────────────▼─────────────────▼────────┐
 │                      VPN Tunnel Layer                       │
 │    Option A: Native Standalone Hybrid TUN Daemon            │
 │    Option B: Modified OpenVPN Engine (via Management API)   │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Getting Started & Execution Modes

### 1. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git
cd Hybrid-Classical-and-Post-Quantum-VPN-
pip install -r requirements.txt
```

### 2. Launching the Desktop Application
```bash
# Mode 1: Native Desktop Window (PyWebView - Edge Webview2 / WebKitGTK)
python app/main.py

# Mode 2: Web Browser Mode (opens http://127.0.0.1:8000 in your browser)
python app/main.py --web

# Mode 3: Headless CLI Mode (Docker / CI automation)
python app/main.py --cli
```

### 3. Running the Performance Benchmark Suite
```bash
python -m benchmarks --iterations 50
```
This runs handshake timing, throughput payload scaling (64B–8192B), wire overhead analysis, and automatically generates 4 high-resolution chart PNG figures in `benchmarks/results/`.

### 4. Running the Test Suite
```bash
python -m pytest tests/ -v
```

---

## 🔐 Cryptographic Specifications & Key Architecture

The system uses a hybrid key encapsulation mechanism (`crypto/hybrid_crypto.py`).

### 1. Classical Cryptography (ECC)
* **Algorithm**: **X25519** (Elliptic Curve Diffie-Hellman over Curve25519)
* **Classical Security**: 128-bit security level
* **Private Key**: 32 bytes (`X25519PrivateKey`)
* **Public Key**: 32 bytes (Raw uncompressed bytes for wire transport)

### 2. Post-Quantum Cryptography (PQC)
* **Algorithm**: **ML-KEM** (NIST FIPS 203 standardized Module-Lattice-Based KEM, formerly *CRYSTALS-Kyber*)
* **Default Variant**: **Kyber768** (NIST Security Category 3 $\approx$ AES-192 equivalent)

| Variant | NIST Level | Public Key | Secret Key | Ciphertext | PQ Shared Secret |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Kyber512** | Level 1 | 800 B | 1,632 B | 768 B | 32 bytes |
| **Kyber768** *(Default)* | Level 3 | **1,184 B** | **2,400 B** | **1,088 B** | **32 bytes** |
| **Kyber1024** | Level 5 | 1,568 B | 3,168 B | 1,568 B | 32 bytes |

### 3. Hybrid Combination & Key Derivation (HKDF-SHA256)
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

---

## 🤝 Signature-Free Handshake Protocol (KEMTLS)

Fixed 6-byte network header: `Magic (2B: 0x4856 "HV") | Version (1B: 0x10) | Type (1B) | PayloadLength (2B)`

| Message Type | Type Code | Payload Components & Exact Sizes | Total Wire Size |
| :--- | :---: | :--- | :---: |
| **ClientHello** | `0x01` | Client Random (32B) + Session ID (32B) + Client ECC Public Key (32B) + Client Kyber768 Public Key (1,184B) | **1,286 B** |
| **ServerHello** | `0x02` | Server Random (32B) + Session ID (32B) + Server ECC Public Key (32B) + Server Kyber768 Public Key (1,184B) + Kyber768 Ciphertext to Client (1,088B) | **2,374 B** |
| **ClientKeyExchange** | `0x03` | Kyber768 Ciphertext to Server (1,088B) + Client Finished MAC (32B) | **1,126 B** |
| **ServerFinished** | `0x04` | Server Finished MAC (32B) | **38 B** |
| **HandshakeError** | `0xFF` | Error Code + UTF-8 Description | Variable |

### Handshake Sequence
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

---

## 🧪 Test Suite & Code Metrics

| Component | Path | Test File | Test Count | Status |
| :--- | :--- | :--- | :---: | :---: |
| **Hybrid Crypto** | [`crypto/hybrid_crypto.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/crypto/hybrid_crypto.py) | [`tests/test_crypto.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/tests/test_crypto.py) | **37** | ✅ 100% Passed |
| **KEMTLS Handshake** | [`handshake/kemtls.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/handshake/kemtls.py) | [`tests/test_handshake.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/tests/test_handshake.py) | **43** | ✅ 100% Passed |
| **VPN Engine** | [`vpn/engine.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/vpn/engine.py) | [`tests/test_vpn.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/tests/test_vpn.py) | **71** | ✅ 100% Passed |
| **Benchmarks Suite** | [`benchmarks/`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/benchmarks/) | [`tests/test_benchmarks.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/tests/test_benchmarks.py) | **10** | ✅ 100% Passed |
| **TOTAL** | — | — | **161** | ✅ **100% Passed** |

---

## 📄 License & Team
Developed for Final Year Project (2026) — **Hybrid Classical & Post-Quantum VPN**.
