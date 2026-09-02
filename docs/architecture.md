# System Architecture & Deployment Guide

## 1. System Overview
This document specifies the system architecture and deployment guidelines for the Hybrid Classical and Post-Quantum Cryptography VPN Application.

The system combines:
- **Classical Elliptic Curve Cryptography**: X25519 ECDH for classical forward secrecy.
- **Post-Quantum Cryptography**: ML-KEM-768 (Kyber768 NIST FIPS 203 Standard) for quantum resistance.
- **Signature-Free Handshake**: KEMTLS-inspired exchange eliminating digital signature overhead.
- **Data Plane Encryption**: Authenticated AES-256-GCM symmetric tunnel framing with forward-secret HKDF-SHA256 rekeying.
- **Unified Engine**: Direct Linux TUN device packet processing with dynamic MTU probing and jitter/loss monitoring.

---

## 2. Cryptographic Protocol Specification

### 2.1 Hybrid Key Encapsulation (ECC + ML-KEM)
- **Classical Component**: X25519 (RFC 7748) generating a 32-byte shared secret `ss_classical`.
- **Post-Quantum Component**: ML-KEM-768 / Kyber768 generating a 32-byte shared secret `ss_pqc`.
- **Key Derivation Function**: HKDF-SHA256 (RFC 5869) combining both secrets:
  $$\text{PRK} = \text{HKDF-Extract}(\text{salt}, \text{ss}_{\text{classical}} \parallel \text{ss}_{\text{pqc}})$$
  Deriving separated AES-256-GCM encryption and HMAC-SHA256 integrity keys.

### 2.2 Signature-Free KEMTLS-Inspired Handshake
1. **ClientHello** (1,286 B): Client ephemeral X25519 public key (32 B) + Kyber768 public key (1,184 B) + Client Random + Session ID.
2. **ServerHello** (2,374 B): Server ephemeral X25519 public key (32 B) + Kyber768 public key (1,184 B) + Kyber768 ciphertext (1,088 B) + Server Random.
3. **ClientKeyExchange** (1,126 B): Client Kyber768 ciphertext (1,088 B) encapsulating server key + Client Finished HMAC (32 B).
4. **ServerFinished** (38 B): Server Finished HMAC (32 B).

### 2.3 Wire Framing & Encapsulation Overhead
Tunnel packets are encapsulated over UDP:
- IPv4 Header (20 B) / IPv6 Header (40 B)
- UDP Header (8 B)
- AES-256-GCM Nonce (12 B: 8B sequence counter + 4B random salt)
- AES-256-GCM Auth Tag (16 B)
- Packet Length Prefix (2 B)
- **Total Overhead**: 58 Bytes (IPv4) / 78 Bytes (IPv6)

---

## 3. Deployment & Execution Guide

### 3.1 Prerequisites
- Linux OS with `CAP_NET_ADMIN` privileges (or WSL2 / Docker with `/dev/net/tun` mapped).
- Python 3.10+
- OpenSSL & `liboqs` (or set `ALLOW_MOCK_PQC=1` for testing environments).

### 3.2 Running with Docker Compose
To run both server and client in isolated containers with full network agility:
```bash
docker compose up --build
```

### 3.3 Running Standalone via Unified CLI

#### Server Node:
```bash
# Start server daemon on default port 51820 with dashboard on 8000
python3 -m vpn.cli server --bind 0.0.0.0 --port 51820 --dashboard --api-port 8000

# Server with specific PQC algorithm variant
python3 -m vpn.cli server --pqc Kyber1024 -v
```

#### Client Node:
```bash
# Connect to local test server
python3 -m vpn.cli client --server 127.0.0.1 --port 51820

# Connect to remote server with custom VPN IP
python3 -m vpn.cli client --server fra-01.pq-vpn.net --port 51820 --vpn-ip 10.8.0.2 -v
```

### 3.4 Running Desktop & Web Application
```bash
# Desktop PyWebView GUI
python3 app/main.py

# Headless / Web browser mode
python3 app/main.py --web --port 8000

# Direct Uvicorn server
uvicorn app.backend.api:app --reload --port 8000
```
Open `http://localhost:8000` to access the live glassmorphic dashboard with real-time WebSocket telemetry streaming.

### 3.5 Benchmarks
Execute performance benchmarks across handshake latency, tunnel throughput, and wire overhead:
```bash
ALLOW_MOCK_PQC=1 python3 -m benchmarks --iterations 50
```
Results and publication charts will be generated in `benchmarks/results/`.
