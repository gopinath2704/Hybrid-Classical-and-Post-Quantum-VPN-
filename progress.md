# Hybrid Classical and Post-Quantum VPN - Project Progress & Changelog

> [!IMPORTANT]
> **🤖 AI AGENT MANDATE & MEMORY PROMPT**:
> Whenever any modification, feature implementation, refactoring, or file creation is performed in this codebase, you MUST automatically:
> 1. Log the exact modifications under **📝 Modification Log & Project Progress** with a timestamp and clear summary of changes.
> 2. Update the **🚦 Current Status & Next Steps** progress table to reflect completed (`✅`), in-progress (`🔄`), or pending (`⏳`) tasks.
> 3. Update the **🏗 Directory Structure Diagram** if any new files or subdirectories are created or altered.

---

## 📌 Project Overview
Building a **Hybrid Classical & Post-Quantum Cryptography VPN Application** combining **ECC (X25519) + ML-KEM (Kyber-768)** with a **Signature-Free Handshake (KEMTLS)**, **Dynamic Network Agility (MTU/Latency Tracking)**, and a **Desktop GUI / Web Dashboard Application**.

---

## 🏗 Proposed Directory Structure

```text
Hybrid-Classical-and-Post-Quantum-VPN/
│
├── .gitignore                         # Git ignore rules (__pycache__, liboqs, caches)
├── README.md                          # Main project architecture & team specifications
├── phase.md                           # Project phase roadmap & module analysis
├── progress.md                        # Project progress tracking & modification log
├── requirements.txt                   # Dependencies (oqs, cryptography, scapy, fastapi, uvicorn)
├── docker-compose.yml                 # Client-Server multi-container environment
├── Dockerfile.server                  # Docker setup for Server (OpenVPN + TUN + liboqs)
├── Dockerfile.client                  # Docker setup for Client (OpenVPN + TUN + liboqs)
│
├── app/                               # 🖥 Application GUI & Backend API
│   ├── main.py                        # Desktop launcher (PyWebView + Uvicorn, --web, --cli)
│   ├── backend/
│   │   ├── __init__.py                # Package exports (app, vpn_state, ws_manager)
│   │   ├── api.py                     # FastAPI REST endpoints (connect, disconnect, status, servers, config, logs)
│   │   └── websocket.py               # WebSocket telemetry broadcaster (/ws/telemetry, 500ms interval)
│   └── frontend/
│       ├── index.html                 # PQ-VPN Dashboard (sidebar, hero button, telemetry, security, crypto stack)
│       ├── css/
│       │   └── style.css              # Dark glassmorphic theme (Inter + JetBrains Mono, neon accents)
│       └── js/
│           └── app.js                 # UI controller (Chart.js, WebSocket client, REST client, state machine)
│
├── crypto/                            # 🔐 Hybrid Cryptography Module
│   ├── __init__.py                    # Public API re-exports
│   └── hybrid_crypto.py              # Unified module: ECC + PQC + KeyManager + HybridKEM
│
├── handshake/                         # 🤝 Signature-Free Handshake (KEMTLS-Inspired)
│   ├── __init__.py                    # Public API re-exports
│   └── kemtls.py                      # Unified module: protocol, transcript, session, client/server state machines
│
├── vpn/                               # 🌐 VPN Engine & Network Integration
│   ├── __init__.py                    # Public API re-exports (15 symbols)
│   └── engine.py                      # Unified module: TUN Interface + Tunnel Daemon + MTU Monitor + Network Quality + OpenVPN Manager
│
├── benchmarks/                        # 📊 Performance Suite
│   ├── __init__.py                    # Package exports & unified runner CLI
│   ├── __main__.py                    # CLI entry point (python -m benchmarks)
│   ├── handshake_bench.py             # Handshake benchmark (Timing & Size)
│   ├── throughput_bench.py            # Encrypted tunnel throughput & payload scaling
│   ├── packet_capture.py              # Scapy wire packet overhead analyzer
│   ├── generate_charts.py             # Matplotlib chart generator (PNG figures)
│   └── results/                       # JSON metric reports & exported PNG figures
│       ├── handshake_results.json
│       ├── throughput_results.json
│       ├── packet_capture_results.json
│       ├── handshake_latency_comparison.png
│       ├── handshake_size_comparison.png
│       ├── throughput_payload_scaling.png
│       └── packet_overhead_breakdown.png
│
├── tests/                             # 🧪 Automated Test Suite
│   ├── test_crypto.py                 # Hybrid ECC + ML-KEM unit tests (37 tests)
│   ├── test_handshake.py              # End-to-end KEMTLS handshake integration test (43 tests)
│   ├── test_vpn.py                    # VPN engine & network agility tests (71 tests)
│   └── test_benchmarks.py             # Benchmark suite integration tests (10 tests)
│
└── docs/                              # 📚 Documentation
    ├── architecture.md                # System design specification
    └── deployment_guide.md            # Setup guide (Docker/Linux)
```

---

## 📝 Modification Log & Project Progress

### 📅 Date: 2026-08-12 (Performance Benchmarks & Validation Implementation)
- **Benchmarking Module (`benchmarks/`) — FULLY IMPLEMENTED**:
  - **Implemented [`benchmarks/handshake_bench.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/benchmarks/handshake_bench.py)** (~260 lines): Quantifies handshake setup latency (ms), message payload sizes (ClientHello, ServerHello, CKE, ServerFinished), and CPU processing overhead across Kyber768 and Hybrid KEMTLS suites. Exports `handshake_results.json`.
  - **Implemented [`benchmarks/throughput_bench.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/benchmarks/throughput_bench.py)** (~200 lines): Quantifies AES-256-GCM data-plane encryption/decryption latency (microseconds), throughput (Mbps), pps rate, and framing overhead across payload sizes 64B to 8192B. Exports `throughput_results.json`.
  - **Implemented [`benchmarks/packet_capture.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/benchmarks/packet_capture.py)** (~160 lines): Scapy wire header breakdown (20B IP + 8B UDP + 28B crypto + 2B length framing = 58B IPv4 / 78B IPv6) and wire payload efficiency calculations. Exports `packet_capture_results.json`.
  - **Created [`benchmarks/generate_charts.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/benchmarks/generate_charts.py)** (~230 lines): Matplotlib automated chart generator producing 4 publication-quality 300 DPI PNG figures:
    - `handshake_latency_comparison.png`
    - `handshake_size_comparison.png`
    - `throughput_payload_scaling.png`
    - `packet_overhead_breakdown.png`
  - **Created [`benchmarks/__main__.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/benchmarks/__main__.py)** and updated [`benchmarks/__init__.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/benchmarks/__init__.py): Unified CLI runner (`python -m benchmarks --iterations 20`).
  - **Created [`tests/test_benchmarks.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/tests/test_benchmarks.py)**: 10 automated integration tests covering all benchmark modules and chart generation.
  - **Verification Results**:
    - All **161/161 tests passed cleanly (`100% pass rate`)** (10 benchmark + 71 VPN + 43 handshake + 37 crypto, 8.66s, zero warnings).
    - Executed `python -m benchmarks --iterations 20` generating all 4 JSON reports and 4 PNG chart figures in `benchmarks/results/`.

### 📅 Date: 2026-08-12 (Desktop Application & Dashboard Implementation)
- **Application Module (`app/`) — FULLY IMPLEMENTED**:
  - **Created [`app/main.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/app/main.py)**: Cross-platform desktop application launcher with 3 modes: PyWebView native window (default, using Edge Webview2 on Windows / WebKitGTK on Linux), `--web` browser mode, and `--cli` headless mode. Spawns Uvicorn server on background daemon thread.
  - **Implemented [`app/backend/api.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/app/backend/api.py)** (~360 lines): FastAPI REST controller with endpoints:
    - `POST /api/v1/vpn/connect`: Initiates KEMTLS handshake simulation and starts tunnel daemon.
    - `POST /api/v1/vpn/disconnect`: Gracefully terminates tunnel and securely wipes session keys.
    - `GET /api/v1/vpn/status`: Returns connection state, uptime, cipher suite (AES-256-GCM + X25519 + Kyber768), VPN IP, MTU, RTT, and key rotation timer.
    - `GET /api/v1/vpn/servers`: Returns 6 global VPN server profiles (Frankfurt, London, NYC, Tokyo, Singapore, Sydney).
    - `GET /api/v1/vpn/config`: Active tunnel configuration parameters.
    - `GET /api/v1/logs`: Recent activity log event stream.
    - Background telemetry simulation thread generating realistic bandwidth/latency/jitter data.
  - **Implemented [`app/backend/websocket.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/app/backend/websocket.py)** (~230 lines): Real-time WebSocket telemetry broadcaster at `/ws/telemetry`:
    - 500ms push interval with 120-point rolling history buffers (60s window).
    - Streams download/upload speed, latency, jitter, packet loss, MTU, data transferred, and key rotation countdown.
    - Multi-client ConnectionManager with automatic cleanup.
  - **Created [`app/frontend/css/style.css`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/app/frontend/css/style.css)** (~900 lines): Deep dark glassmorphic theme matching reference UI:
    - Color palette: `#0B0F19` bg, `#131A2B` cards, `#00E676` emerald, `#00F0FF` cyan, `#A855F7` purple accents.
    - Inter + JetBrains Mono fonts, CSS custom properties design system, glassmorphic `backdrop-filter` cards.
    - Animated power ring with rotating glow, pulsing status dots, smooth transitions, responsive layout.
  - **Created [`app/frontend/js/app.js`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/app/frontend/js/app.js)** (~430 lines): Desktop UI controller:
    - REST client for connect/disconnect/status lifecycle management.
    - Auto-reconnecting WebSocket client feeding live telemetry updates.
    - Chart.js integration: dual-line bandwidth graph (download green, upload blue), latency mini-chart, packet loss mini-chart — all updating in real time.
    - Navigation, server selector, activity log renderer, and connection state machine (DISCONNECTED → CONNECTING → CONNECTED → DISCONNECTING).
  - **Rebuilt [`app/frontend/index.html`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/app/frontend/index.html)** (~300 lines): Complete dashboard layout matching the PQ-VPN design reference:
    - Sidebar navigation (Dashboard, Connections, Servers, Telemetry, Security, Settings, Logs, About) with system status indicator.
    - Top bar with server location selector dropdown.
    - Connection status card with duration, VPN IP, server location, protocol, key rotation details.
    - Central glowing power ring button with animated state transitions.
    - Live telemetry panel with Chart.js bandwidth graph and latency/packet loss mini-charts.
    - Security overview listing AES-256-GCM, Hybrid Key Exchange, KEMTLS, HMAC-SHA256 with ACTIVE badges.
    - Cryptographic stack visual showing Classical (X25519) + Post-Quantum (Kyber768) with MAXIMUM security level bar.
    - Recent activity timeline log.
    - Footer status bar with PQ Protection, Key Rotation, Protocol, Uptime, and Data Transferred counters.
  - **Updated [`app/backend/__init__.py`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/app/backend/__init__.py)**: Re-exports FastAPI app instance and WebSocket manager.
  - **Updated [`requirements.txt`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/requirements.txt)**: Added `pywebview>=4.0` dependency.
  - **Verification Results**:
    - All **151/151 existing tests passed** (71 VPN + 43 handshake + 37 crypto, `100% pass rate`, 7.29s). Zero regressions.
    - FastAPI server launched successfully on `http://127.0.0.1:8000`.
    - All REST endpoints verified: `/api/v1/vpn/status`, `/api/v1/vpn/servers`, `/api/v1/vpn/config`, `/api/v1/logs`.
    - WebSocket telemetry stream connected and broadcasting at 500ms intervals.
    - Dashboard HTML served correctly with full layout rendering.

### 📅 Date: 2026-08-12 (VPN Engine & Network Agility Implementation)
- **VPN Engine Module (`vpn/`) — FULLY IMPLEMENTED**:
  - **Created `vpn/engine.py`** (~700 lines): Unified single-file VPN engine module consolidating all 3 former subdirectories (`engine/`, `agility/`, `openvpn_mod/`).
  - **§1 TUNInterface**: Native Linux `/dev/net/tun` device allocator (`ioctl IFF_TUN | IFF_NO_PI`) with cross-platform TCP socket pipe fallback for Windows/macOS. Context manager support, inject/drain test helpers.
  - **§2 VPNTunnelDaemon**: Asynchronous `select()`-based event loop daemon reading raw IP packets from TUN, encrypting via `HandshakeSession` AES-256-GCM, and forwarding over UDP socket. Background thread with stats tracking.
  - **§3 MTUMonitor**: Dynamic PMTU discovery (binary search UDP probing with DF bit), VPN overhead calculation (58B IPv4 / 78B IPv6), TCP MSS clamping, and timestamped MTU change history.
  - **§4 NetworkQualityMonitor**: RFC 3550 exponential moving average jitter tracking, rolling-window RTT statistics (avg/min/max), UDP echo probing, and packet loss rate calculation with `QualitySnapshot` dataclass.
  - **§5 OpenVPNManager**: TCP management socket interface (`send_command()`) for runtime commands, and dynamic `generate_server_config()` / `generate_client_config()` configuration generation.
  - **Created `vpn/__init__.py`**: Re-exports all 15 public symbols from `vpn.engine`.
  - **Deleted** 9 skeleton files across 3 subdirectories: `vpn/engine/` (3 files), `vpn/agility/` (3 files), `vpn/openvpn_mod/` (3 files) — consolidated into single `vpn/engine.py`.
  - **Deleted** `tests/test_agility.py` placeholder — replaced by comprehensive `tests/test_vpn.py`.
  - **Created `tests/test_vpn.py`**: 71 tests across 8 test classes (`TestTUNInterface`, `TestTunnelStats`, `TestVPNTunnelDaemon`, `TestMTUMonitor`, `TestNetworkQualityMonitor`, `TestOpenVPNManager`, `TestE2EIntegration`).
  - **Test Execution Results**: All **151/151 tests passed** (71 VPN + 43 handshake + 37 crypto, `100% pass rate`, 7.66s). Zero regressions.
  - **Platform Fix**: Windows `socket.AF_UNIX` unavailable — implemented TCP loopback socket pair fallback via `AF_INET` listener pattern.
  - **Rationale**: Single-file consolidation mirrors `crypto/hybrid_crypto.py` (Phase 1) and `handshake/kemtls.py` (Phase 2) patterns, reduces file count from 9 → 2, and keeps the VPN layer auditable as one cohesive unit.

### 📅 Date: 2026-08-09 (Project Phase Roadmap Created)
- **Created [`phase.md`](file:///d:/Documents/Final%20Year%20Project/Hybrid-Classical-and-Post-Quantum-VPN-/phase.md)**:
  - Comprehensive project analysis documenting current status (**Phase 2 Completed → Preparing for Phase 3**).
  - Detailed matrix & breakdown for Phase 0 (Setup), Phase 1 (Hybrid Crypto), Phase 2 (KEMTLS Handshake), Phase 3 (VPN Engine & Agility), Phase 4 (Application UI & API), and Phase 5 (Performance Benchmarking).
  - Documented 100% pass rate across total test suite (80/80 tests passing: 43 handshake + 37 crypto).

### 📅 Date: 2026-08-09 (Handshake Documentation Update)
- **Updated `README.md` with Signature-Free Handshake Architecture**:
  - Added technical specification section detailing the KEMTLS-inspired handshake wire protocol (6-byte header, `ClientHello`, `ServerHello`, `ClientKeyExchange`, `ServerFinished`, `HandshakeError`), exact payload byte sizes, complete ASCII message sequence diagram, `TranscriptHasher` SHA-256 transcript binding, and AES-256-GCM data frame encryption.

### 📅 Date: 2026-08-09 (KEMTLS Handshake Implementation)
- **Handshake Module (`handshake/`) — FULLY IMPLEMENTED**:
  - **Created `handshake/kemtls.py`** (~550 lines): Unified single-file signature-free KEMTLS-inspired handshake module.
  - **§1 Wire Protocol**: Binary header format (`Magic 0x4856`, `Version 1.0`, `Type`, `Length`), 5 message types (`ClientHello`, `ServerHello`, `ClientKeyExchange`, `ServerFinished`, `HandshakeError`).
  - **§2 Transcript Hasher**: SHA-256 cumulative transcript binding with `TranscriptHasher` class.
  - **§3 Session Context**: `HandshakeSession` with AES-256-GCM frame encryption/decryption (`encrypt_frame()` / `decrypt_frame()`) using derived session keys.
  - **§4 Client State Machine**: `KEMTLSClient` driving initiator through `initiate_handshake()` → `process_server_hello()` → `process_server_finished()`.
  - **§5 Server State Machine**: `KEMTLSServer` driving responder through `process_client_hello()` → `process_client_key_exchange()`.
  - **Deleted** 4 skeleton placeholder files (`protocol.py`, `session.py`, `kemtls_client.py`, `kemtls_server.py`) — consolidated into `kemtls.py`.
  - **Updated** `handshake/__init__.py` to re-export all 14 public symbols from `handshake.kemtls`.
  - **Created `tests/test_handshake.py`**: 43 tests across 8 test classes (`TestHeader`, `TestClientHello`, `TestServerHello`, `TestClientKeyExchange`, `TestServerFinished`, `TestTranscriptHasher`, `TestFinishedMAC`, `TestHandshakeSession`, `TestFullHandshake`, `TestStateValidation`).
  - **Test Execution Results**: All **80/80 tests passed** (43 handshake + 37 crypto, `100% pass rate`, 5.70s). Zero regressions.
  - **Rationale**: Single-file consolidation mirrors `crypto/hybrid_crypto.py` pattern, reduces cognitive overhead, and keeps the handshake layer auditable as one cohesive unit.

### 📅 Date: 2026-08-07 (Cryptographic Documentation Update)
- **Updated README.md with Cryptographic Specifications & Key Architecture**:
  - Added comprehensive technical reference section detailing X25519 (ECC), ML-KEM / Kyber768 (PQC), HKDF-SHA256 hybrid key derivation scheme, salt size, derived key specs (encryption & MAC), and in-memory zeroization security.

### 📅 Date: 2026-08-07 (Evening — Module Consolidation)
- **Crypto Module Merged into Single Unified File**:
  - **Merged** `ecc_provider.py`, `pqc_provider.py`, `key_manager.py`, `hybrid_kem.py` → **`crypto/hybrid_crypto.py`** (~600 lines).
  - **Deleted** the 4 individual provider files to reduce file count and simplify imports.
  - **Updated** `crypto/__init__.py` to re-export all public symbols from `hybrid_crypto.py` (backward-compatible: `from crypto import HybridKEM` still works).
  - **Updated** `tests/test_crypto.py` — all imports now reference `crypto.hybrid_crypto` directly.
  - **Test Execution Results**: All **37/37 tests passed** (`100% pass rate`, 6.46s). Zero regressions.
  - **Rationale**: Consolidation reduces cognitive overhead (4 files → 1), simplifies dependency tracking, and makes the crypto layer easier to audit as a single cohesive unit.

### 📅 Date: 2026-08-07 (Initial Implementation)
- **Hybrid Cryptography Module (`crypto/`) — FULLY IMPLEMENTED**:
  - **`crypto/ecc_provider.py`**: Implemented `ECCProvider` class with X25519 ECDH keypair generation, shared secret derivation, and public key serialize/deserialize helpers. All public keys use 32-byte Raw encoding for wire transport.
  - **`crypto/pqc_provider.py`**: Implemented `PQCProvider` class wrapping `liboqs` for ML-KEM (Kyber512/768/1024). Includes `generate_keypair()`, `encapsulate()`, `decapsulate()`, and `get_algorithm_details()`. Graceful `ImportError` fallback with installation instructions if `oqs` is missing.
  - **`crypto/key_manager.py`**: Implemented `KeyManager` with HKDF-SHA256 derivation (`derive_key()`, `derive_key_pair()` with separate info labels for encryption vs. MAC keys). Implemented `SessionKeyStore` with in-memory CRUD, secure revocation (zero-wipe via `ctypes.memset`), `revoke_all()`, and `count` property.
  - **`crypto/hybrid_kem.py`**: Implemented `HybridKEM` orchestrator combining `ECCProvider` + `PQCProvider` + `KeyManager`. Includes `generate_keypairs()` → `HybridKeyBundle` dataclass, `encapsulate()` / `decapsulate()` for two-party exchange, `combine_secrets()` and `combine_secrets_to_pair()` for HKDF finalization. Added `get_info()` for introspection.
  - **`crypto/__init__.py`**: Updated with clean public exports: `ECCProvider`, `PQCProvider`, `HybridKEM`, `HybridKeyBundle`, `KeyManager`, `SessionKeyStore`.
  - **`tests/test_crypto.py`**: Wrote comprehensive pytest suite with 37 tests across 5 test classes (`TestECCProvider`, `TestPQCProvider`, `TestKeyManager`, `TestSessionKeyStore`, `TestHybridKEM`). Covers keypair generation, ECDH agreement, KEM encap/decap, all 3 Kyber variants, HKDF determinism, salt/info variation, session store CRUD, secure wipe, and full end-to-end hybrid exchange simulation.
  - **Test Execution Results**: All **37 out of 37 unit tests passed cleanly (`100% pass rate`)**. Added seamless software fallback for `PQCProvider` on host OS (Windows) without native C compiler, while native `liboqs` automatically runs in Linux/Docker environment.

### 📅 Date: 2026-08-04
- **Agent Memory Mandate Added**:
  - Embedded mandatory rule at top of `progress.md` and in `.agents/AGENTS.md` ensuring all future implementation steps automatically update `progress.md`.
- **Architecture Overview Updated**:
  - Expanded `README.md` to document the application flow, frontend GUI, API backend daemon, and dual-mode VPN engine options (OpenVPN wrapper vs native hybrid TUN daemon).
- **Directory Structure & Files Created**:
  - Created 100% of all proposed folders (`app/`, `crypto/`, `handshake/`, `vpn/`, `benchmarks/`, `tests/`, `docs/`) and 25 initial skeleton files on disk.
- **Dependencies & Docker Configuration**:
  - Created `requirements.txt`, `docker-compose.yml`, `Dockerfile.server`, and `Dockerfile.client`.
- **Git Commit & Repository Push**:
  - Configured git identity (`gopinath2704`), staged all 41 modified/created files, committed (`2427175`), and successfully pushed changes to remote repository (`origin/main`).

---

## 🚦 Current Status & Next Steps

| Task / Module | Status | Description |
| :--- | :---: | :--- |
| **Directory Scaffolding** | ✅ Completed | Created complete directory tree and skeleton files |
| **Agent Memory Mandate** | ✅ Completed | Configured automatic progress logging instructions |
| **Hybrid Cryptography (`crypto/`)** | ✅ Completed | X25519 + Kyber768 hybrid KEM, HKDF key derivation, session store, 37 tests |
| **KEMTLS Handshake (`handshake/`)** | ✅ Completed | Signature-free KEMTLS handshake: wire protocol, transcript binding, AES-256-GCM session, client/server state machines, 43 tests |
| **VPN Engine (`vpn/`)** | ✅ Completed | TUN interface, tunnel daemon, MTU monitor, network quality, OpenVPN manager, 71 tests |
| **Application UI (`app/`)** | ✅ Completed | Cross-platform desktop app (PyWebView), FastAPI REST + WebSocket API, dark glassmorphic dashboard, Chart.js telemetry |
| **Benchmarks (`benchmarks/`)** | ✅ Completed | Handshake timing, throughput payload scaling, packet overhead analysis, 4 Matplotlib chart figures, 10 tests |
