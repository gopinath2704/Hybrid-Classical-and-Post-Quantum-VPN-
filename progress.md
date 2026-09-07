# Hybrid Classical and Post-Quantum VPN - Project Progress & Changelog

> [!IMPORTANT]
> **🤖 AI AGENT MANDATE & MEMORY PROMPT**:
> Whenever any modification, feature implementation, refactoring, or file creation is performed in this codebase, you MUST automatically:
> 1. Log the exact modifications under **📝 Modification Log & Project Progress** with a timestamp and clear summary of changes.
> 2. Update the **🚦 Current Status & Next Steps** progress table to reflect completed (`✅`), in-progress (`🔄`), or pending (`⏳`) tasks.
> 3. Update the **🏗 Directory Structure Diagram** if any new files or subdirectories are created or altered.

---

## 📌 Project Overview
Building a **Hybrid Classical & Post-Quantum Cryptography VPN Application** combining **ECC (X25519) + ML-KEM (Kyber-768)** with a **custom KEMTLS-inspired v2 handshake (classical Ed25519 client authentication)**, **Dynamic Network Agility (MTU/Latency Tracking)**, and a **Desktop GUI / Web Dashboard Application**.

---

## 🏗 Directory Structure

```text
Hybrid-Classical-and-Post-Quantum-VPN/
├── app/                    # Token-protected FastAPI/WebSocket dashboard
├── crypto/                 # X25519, runtime-discovered ML-KEM-768, HKDF
├── handshake/              # Authenticated strict v2 protocol and record layer
├── vpn/
│   ├── cli.py             # Provisioning, authorization, server, client
│   ├── config.py          # Strict TOML models
│   ├── doctor.py          # Read-only deployment diagnostics
│   ├── firewall.py        # Scoped nftables policy renderer
│   ├── engine.py          # Linux TUN, exact MTU, quality primitives
│   ├── identity.py        # Static server/client identity lifecycle
│   └── runtime.py         # One-TUN/UDP server and transactional client
├── config/                 # Server/client TOML examples; private keys ignored
│   └── client.docker.toml  # Docker DNS hostname and provisioned pin
├── scripts/                # Isolated nftables setup and cleanup
├── deploy/                 # systemd service and tested versions
├── tests/                  # Unit, security, native-PQC, root integration markers
│   ├── test_session_activity.py # Quiet keepalive, idle cleanup, rejected activity
│   └── test_runtime_fixes.py # Shutdown, liveness, delayed rekey, deployment regressions
├── benchmarks/             # Historical benchmark code/results (not security proof)
├── docs/                   # Architecture, protocol, audit, threat/deployment/setup
│   └── management-api.md  # Shared dashboard/telemetry contract
├── requirements*.txt       # Server/client/management/dev roles
├── constraints-tested.txt  # Pinned tested Python dependencies
├── pytest.ini
├── Dockerfile.server
├── Dockerfile.client
└── docker-compose.yml
```

---

## 📝 Modification Log & Project Progress

### 2026-09-07 — Final handoff validation and documentation consistency

- Inspected the existing dirty working tree, diffs, current implementation, tests and deployment documents before edits. Preserved all previous work and the v2 1,318 / 1,222 / 1,190 / 38-byte handshake, key schedule, separate DATA/CONTROL domains and synchronized rekey.
- Initial handoff reruns in a fresh `/tmp/pqvpn-final-venv`: `pytest -q` **206 passed, 2 skipped in 36.32s**; `python -m pytest -q` **206 passed, 2 skipped in 36.40s**. System Python originally lacked pytest; installed the unchanged pinned `requirements-dev.txt` baseline outside the repository. All constrained versions match and `pip check` passes. Network/socket tests require execution outside the sandbox as UID 1000; a restricted ASGI-only run stalled and was terminated.
- Fixed one verified configuration defect in `vpn/config.py`: omitted identity/database path fields now use standard filenames beside the TOML instead of resolving from the process CWD. Added its regression in `tests/test_network_transactions.py`. Added actual ASGI HTTP ticket-authentication and random-ticket rejection coverage in `tests/test_doctor_management.py`; existing atomic single-use ticket implementation preserved.
- Removed unused third-party Chart.js from the dashboard and corrected record integrity to AES-GCM. Corrected crypto docstrings for the single supported ML-KEM-768 suite, explicit native installation and key evolution limitations; no crypto behavior changes.
- **Final complete regressions (210 collected each):** `pytest -q`: **208 passed, 0 failed, 2 skipped, 37.19s**; `python -m pytest -q`: **208 passed, 0 failed, 2 skipped, 36.17s**. Both ran sequentially from repository root with the environment activated and 120-second outer timeouts. Skips: root namespace and mock-only fallback with native provider present.
- **Static checks:** Python compileall over crypto/handshake/vpn/app/benchmarks/tests PASS; setup, cleanup, namespace and native installer bash syntax each PASS; Node JS syntax PASS; Docker Compose plus development-client profile configuration PASS; `git diff --check` PASS. Compose is syntax-only, not image/runtime validation.
- **Doctors:** valid temporary native profiles in `/tmp/pqvpn-final-doctor`; server **WARN, exit 0**, only external provider/host firewall verification outstanding, no profile-blocking findings; client **PASS, exit 0**. Server used service_user shadow and the visible WAN; client used a loopback address for diagnostics only. File hashes/modes/mtimes, links, routes, resolver state and forwarding snapshots were identical before/after. No routes/DNS/firewall/TUN mutations were performed by doctor.
- **Native ML-KEM-768: PASS**, separately with `ALLOW_MOCK_PQC=0 python -m pytest -q -m native_pqc`: **2 passed, 208 deselected in 0.56s**. Actual baseline: Python **3.14.7**, liboqs-python **0.16.0**, native liboqs **0.16.0**. Native keypair self-test and authenticated session records both validated; mock results are not represented as native.
- **Firewall/dead-peer/DNS/forwarding/identities/database/tickets/rate bounds:** static and existing unit/loopback regressions PASS; nft/sysctl/DNS command tests are simulated, not privileged integration evidence. Healthy DATA without PONG survives; UDP blackhole fails and cleans up; static leases are reserved; expired source entries are pruned and capped.
- **ROOT NAMESPACE: SKIPPED.** Actual host is UID **1000**; `/dev/net/tun` exists outside the sandbox but root execution is unavailable to the current invocation. The root marker returned SKIP. Earlier sandbox-only TUN absence is not the host result. **Real VPS: NOT PERFORMED.**
- Updated README, protocol, threat model, deployment/client setup, architecture, management contract and security audit to match current code and commands. Historical progress entries/counts retained. Full [validation matrix](docs/security_audit.md#final-validation--2026-09-07) records evidence and limits. Native installation precedes Python imports, native validation and doctor precede service startup; no daemon-time native download/build.
- Status: **Deployable research/prototype PQ-VPN. Root/TUN integration pending. Real VPS/client validation pending.** Next end-to-end milestone: **REAL VPS + REAL LINUX CLIENT VALIDATION**, with the documented disposable root namespace/systemd/DNS gates first. Custom protocol review, classical client auth, key evolution without post-compromise recovery, routed IPv6, dynamic PMTU and kill switch limitations remain. No remote deployment or architecture redesign attempted.

### 2026-09-06 22:08 IST — Edit-3 idle activity and source packaging

- `vpn/runtime.py`: centralized `ServerSession.touch`, count authenticated eight-byte PING and accepted DATA only, validate CONTROL before activity, serialize expiry/UDP/rekey authorization, retain endpoint binding, clear endpoint on cleanup, log idle/absolute expiry reason. Added overridable client ping timing constants with unchanged deployment defaults. No cryptographic architecture or handshake changes.
- `tests/test_session_activity.py`: live loopback quiet keepalive and real idle expiry/cleanup regressions, plus authenticated-record rejection cases (replay/session/endpoint/epoch/tag/domain/payload/source).
- `.gitignore`: explicit environment and coverage exclusions. Removed the untracked bundled `.venv/` from the source folder; no dependency or lock files removed. Validation environment lives outside the repository.
- `deploy/pqvpn-server.service`: recreate runtime directory on boot. README and deployment/client guides specify freshly created environments; native installation excludes environments/caches and consistently uses `/opt/pqvpn/.venv` and `/etc/pqvpn/server.toml`, with no EnvironmentFile.
- README, protocol, security audit, deployment, client setup, and threat model document authenticated liveness, rejection rules and genuine expiry cleanup. Status remains **deployable research/prototype PQ-VPN**; privileged networking and real VPS/client validation are the next milestone.
- `tests/namespace_vpn.sh`: additionally runs quiet keepalive and genuine idle cleanup tests with real TUN in the isolated namespace; compares routes before/after. Namespace DNS mutation is disabled; unprivileged idle cleanup verifies route/DNS undo commands with mocked OS calls.
- Validation in fresh `/tmp/pqvpn-edit3-venv` (Python 3.14.7; freshly installed test dependencies, not the old bundled environment): `python -m pytest -q`: **139 passed, 2 skipped in 16.65s**; `pytest -q`: **139 passed, 2 skipped in 16.53s**. Native ML-KEM-768 separately: **1 passed, 140 deselected**. Root namespace: **1 skipped, 140 deselected** (UID 1000; `/dev/net/tun` absent). Compileall, all three shell syntax checks, JS syntax, Compose config and diff whitespace check passed. Local socket tests require execution outside the socket-restricting sandbox.
- Limitations: fresh installation used Python-3.14-compatible test dependencies (cryptography 50.0.1, pytest 9.1.1, FastAPI 0.141.1); installation of the older exact `requirements.txt` pins was not validated on this host. Native systemd activation, privileged namespace networking/DNS and real VPS/client end-to-end validation remain pending. No production-readiness claim.


### 2026-09-06 — Edit-2 runtime and deployment repairs

Preserved v2 handshake algorithms, wire format, and existing security tests.
Client SIGTERM wakes an event-driven main loop and performs cleanup before exit.
Namespace shutdown waits fail after ten seconds rather than hanging. One resolved
IPv4 address serves TCP, the bypass route, and UDP. A dedicated authenticated
control reader detects EOF/CLOSE/ERROR/protocol failure and server expiry, exposes
FAILED through management status, and tears down networking. A separate scheduler
keeps data forwarding active during rekey waits. Teardown serializes with all
record/epoch locks, and closed records fail explicitly.

Compose identity mounts now match TOML-relative paths; client.docker.toml sets
vpn-server explicitly. Docker bases support tomllib and use a virtualenv.
Systemd firewall setup reads the actual server TOML, including non-default subnet,
TUN and outbound interface. The dashboard uses the configured profile and a
single documented real telemetry schema; unsupported custom-server/log controls,
unmeasured bandwidth/byte displays, and obsolete launcher behavior were removed.
Documentation distinguishes ML-KEM server authentication and hybrid establishment
from classical Ed25519 client authentication. Rate-limiter sources expire and
have a hard cardinality cap. Root pytest imports are configured explicitly.

Validation in the existing .venv with local sockets permitted: both
`python -m pytest -q` and `pytest -q`: **121 passed, 2 skipped**. Native ML-KEM
separately: **1 passed**. Root namespace marker: **1 skipped** (non-root, no TUN);
no successful namespace or real VPS/client deployment is claimed. Compileall,
all three requested bash syntax checks, JavaScript syntax, Compose config, and
`git diff --check` passed. Status: **deployable research/prototype PQ-VPN**.


### 📅 Date: 2026-09-05 — Concurrency, Transaction, and Handshake Follow-up

- **[MODIFIED] `handshake/kemtls.py` / `handshake/__init__.py`** — added independent DATA/CONTROL HKDF domains, keys, nonce bases, counters and receive policies; serialized complete encrypt operations; serialized DATA authenticate/commit replay handling; enforced exact-next CONTROL records; reduced the handshake to one ephemeral ML-KEM session exchange plus the separate static ML-KEM authentication exchange.
- **[MODIFIED] `vpn/runtime.py`, `vpn/config.py`, `vpn/cli.py`** — added strict inner IPv4 source validation, host-safe IP allocation, full connection rollback, exact prior-route restoration, partial-DNS rollback, structured server failures, graceful accept shutdown, one-owner automatic rekey state, per-source limits, config-relative secret paths, and an explicit mock-PQC runtime flag independent of emulated TUN.
- **[RESTORED/NEW] tests** — restored relevant handshake, VPN, MTU, telemetry, and benchmark coverage from history; added concurrency nonce/replay stress, channel separation, spoof/IP-pool, network failure transaction, server lifecycle/rekey, API ownership, and CWD-independent config tests. Expanded `tests/namespace_vpn.sh` to two clients with TCP/UDP traffic, spoof rejection, automatic rekey under traffic, disconnect, route restoration, and reconnect.
- **[MODIFIED] deployment/docs/benchmarks** — made nftables setup idempotent by rule comment, corrected stale Docker/dependency claims, documented API-owned versus CLI-owned operation and hash-only rekey limitations, updated exact 1,318/1,222/1,190/38-byte flights, and regenerated native benchmark artifacts (3,768 bytes total; 42-byte encrypted-record overhead).
- Validation: full available suite `103 passed, 3 skipped`; isolated native ML-KEM marker `1 passed`; privileged namespace marker skipped because this workspace is non-root and lacks `/dev/net/tun`. Python compilation, all three requested shell syntax checks, and `git diff --check` passed.

### 📅 Date: 2026-09-05 — Security and Functional Audit

- **[NEW] `docs/security_audit.md`** — audited the complete current implementation and recorded 19 confirmed cryptographic, protocol, networking, management, deployment, and assurance issues using severity/component/location/impact/scenario/fix/verification/status fields.
- Corrected the active project status from prior unverified production-ready claims to remediation in progress. Historical entries below are retained as originally recorded.

### 📅 Date: 2026-09-05 — Authenticated Protocol and Routed Linux Runtime

- **[MODIFIED] `crypto/hybrid_crypto.py` / `crypto/__init__.py`** — production now supports only standardized `ML-KEM-768`, discovers enabled liboqs mechanisms, performs a native startup KEM self-test, and retains explicitly labelled mock-only development behavior.
- **[REPLACED] `handshake/kemtls.py`** — strict exact-length v2 handshake; pinned static ML-KEM server proof; authorized Ed25519 client proof; transcript/context-bound directional key schedule; deterministic per-direction nonces; authenticated headers; 128-packet replay window; monotonic epochs and best-effort mutable-buffer wiping. Superseded in part by the concurrency/channel update above.
- **[NEW] `vpn/identity.py`, `vpn/config.py`, `vpn/runtime.py`** — restrictive identity generation, authorized-client database, TOML configuration, one-TUN/one-UDP multi-client server, VPN IP pool, authenticated UDP endpoint binding, client/server TUN forwarding, transactional client routes/DNS, real encrypted PING/PONG telemetry, resource limits, and synchronized TCP control-channel rekey.
- **[REPLACED] `vpn/cli.py`, `vpn/engine.py`, `vpn/__init__.py`** — provisioning/admin commands and fail-closed Linux runtime; removed legacy unsafe service/server and misleading OpenVPN compatibility surface.
- **[REPLACED] `app/backend/api.py`** and **[MODIFIED] frontend** — bearer-protected management actions/telemetry, token-protected WebSocket, explicit CORS origins, local/custom profiles only, and browser token handling.
- **[NEW] `scripts/server-setup.sh`, `scripts/server-cleanup.sh`, `deploy/pqvpn-server.service`** — isolated nftables forwarding/NAT/MSS rules, safe cleanup, outbound-interface detection, and a capability-limited native systemd example.
- **[MODIFIED] Docker artifacts** — removed public management publication, corrected v2 CLI entrypoints, documented secret/config mounts, and made the bundled client an explicit development profile.
- Docker Compose schema validation passed with `docker compose config`.
- **[NEW/REPLACED] tests and `pytest.ini`** — security/authentication/directional-key/nonce/replay/rekey/IP-pool/MTU/API tests plus separate mock/native/integration markers. Validation: 55 unit/mock-capable tests passed (one native-precedence skip); native ML-KEM marker passed 1/1; privileged integration marker remains unexecuted in this restricted workspace.
- Final rerun after all edits: `59 passed, 2 skipped`; native marker: `1 passed`; namespace marker: skipped as non-root, and passwordless escalation was unavailable (`sudo: a password is required`). Shell syntax, Python compilation, Compose schema, and `git diff --check` passed.
- **[REPLACED/NEW] documentation** — honest README/architecture plus protocol, threat model, deployment, and client setup guides. No formal KEMTLS, guaranteed zeroization, or completed root-integration claim is made.

### 📅 Date: 2026-09-01 — Historical Transition Phase: Simulation → Production-Ready VPN

**Objective:** Transform the prototype (mocked crypto, fake telemetry, no TUN integration) into a
transparent, honest, production-ready VPN implementation as audited and approved by the project team.

---

#### Phase 1 — Cryptographic Integrity & Fail-Closed Enforcement

**[MODIFIED] `crypto/hybrid_crypto.py`** (major security rewrite):
- Removed `BaseException` catch on liboqs load; replaced with specific `ImportError`, `AttributeError`, `Exception` handlers with meaningful log messages.
- Added `PQCUnavailableError` — raised by default when native liboqs is absent.
- Added `ALLOW_MOCK_PQC` module flag — reads `os.environ.get("ALLOW_MOCK_PQC", "0")`. Default is fail-closed.
- Renamed `_SoftwarePQCProvider` → `_MockInsecurePQCProvider` — logs WARNING on instantiation; returns `is_quantum_safe=False` and `security_warning` from `get_algorithm_details()`.
- Added `PQCProvider.is_quantum_safe` property.
- Added `PQCProvider(allow_mock=False)` explicit parameter.
- Added `KeyManager.derive_rekey_material()` and `KeyManager.derive_rekey_pair()` — HKDF ratchet for forward-secret in-session key rotation.
- Updated `HybridKEM(allow_mock_pqc=False)` — forwards to `PQCProvider`.
- Added `get_crypto_status()` — runtime availability dict for API/UI transparency.

**[MODIFIED] `crypto/__init__.py`** — Exported: `PQCUnavailableError`, `get_crypto_status`, `ALLOW_MOCK_PQC`, `_OQS_AVAILABLE`.

---

#### Phase 2 — KEMTLS Rekey Protocol Extension

**[MODIFIED] `handshake/kemtls.py`**:
- Added `MessageType.REKEY_REQUEST = 0x05` and `REKEY_RESPONSE = 0x06` to wire protocol.
- Added `HandshakeSession.rekey()` — derives successor enc+mac keys via HKDF ratchet, zeroes old keys using `ctypes.memset`, resets seq counter.
- Added `HandshakeSession.secure_wipe()` — zeroes all session key material for use on disconnect.
- Added `HandshakeSession.get_info()` — restored after insertion of rekey/wipe methods.
- Updated `KEMTLSClient(allow_mock_pqc=False)` and `KEMTLSServer(allow_mock_pqc=False)`.

---

#### Phase 3 — VPN Service Orchestration Layer

**[NEW] `vpn/service.py`** (~430 lines):
- `VPNService.connect()` — real KEMTLS handshake over TCP, TUN allocation, `ip addr add`, `VPNTunnelDaemon` + `NetworkQualityMonitor` startup.
- `VPNService.disconnect()` — `session.secure_wipe()` before socket close, thread-safe.
- `VPNService.rotate_keys()` — calls `session.rekey()`, records timestamp.
- `VPNService.get_telemetry()` — reads live stats from tunnel daemon and quality monitor. Zero simulated values.
- `_allocate_tun()` — NATIVE → SOCKET_PIPE fallback with explicit warning (not silent).
- `perform_client_handshake()` / `perform_server_handshake()` — TCP transport for 4-message KEMTLS exchange.
- `ServiceState`, `VPNTelemetry` dataclass including `tun_mode`, `pqc_mode`, `is_quantum_safe`.

**[NEW] `vpn/server.py`** — Standalone VPN server daemon (`python -m vpn.server`).

**[NEW] `vpn/client.py`** — Standalone VPN client CLI (`python -m vpn.client --server HOST`).

**[MODIFIED] `vpn/__init__.py`** — Added `VPNService`, `ServiceState`, `VPNTelemetry`, transport helpers.

---

#### Phase 4 — API Rewrite (Simulation Elimination)

**[MODIFIED] `app/backend/api.py`** (complete rewrite):
- Removed `_simulate_telemetry` thread — eliminated all random/fake metric generation.
- Removed mock connect sleep (1.5s) — replaced with real `VPNService.connect()` in executor.
- Added HTTP 409 concurrency guard for concurrent connect/disconnect.
- Added `POST /api/v1/vpn/rekey` endpoint.
- Added `GET /api/v1/crypto/status` endpoint.
- All `/api/v1/vpn/status` values now sourced from live telemetry; `is_simulated: false`.
- Added `_VPNStateProxy` compatibility shim for websocket module.
- Added "Local Test Node" (127.0.0.1:51820) to server list for local testing.

**[MODIFIED] `app/backend/websocket.py`** (complete rewrite):
- Removed `random`, `math` — no more simulated telemetry generation.
- `_build_telemetry_frame()` reads `_vpn_service.get_telemetry()` directly.
- Frames now include `pqc_mode`, `tun_mode`, `is_quantum_safe`, `is_simulated: false`, `packets_dropped`.

---

#### Phase 5 — UI Transparency Badges

**[MODIFIED] `app/frontend/index.html`**:
- Topbar mode badge group: `#badge-tun-mode`, `#badge-pqc-mode` — live updates from crypto status API.
- `pq-badge-group` with three conditional badges: `🛡 Quantum-Safe LIVE`, `🔧 TUN EMULATED`, `⚠️ MOCK PQC — NOT SECURE`.
- Added `#detail-tun-mode` and `#detail-pqc-mode` rows in connection details panel.
- Custom server input group (host + port) with toggle button.

**[MODIFIED] `app/frontend/js/app.js`**:
- Added `fetchCryptoStatus()` — updates topbar badges from `/api/v1/crypto/status`.
- Updated `updateConnectionUI()` — null-safe, uses badge group, added `ERROR` state.
- Updated `updateTelemetryUI()` — reads `pqc_mode`, `tun_mode` from telemetry frames.
- Added `rekeyVPN()` — calls `POST /api/v1/vpn/rekey`.
- Added custom server toggle listener.
- `fetchCryptoStatus()` called on boot.

**[MODIFIED] `app/frontend/css/style.css`**:
- Added `.mode-badge--live/emulated/mock/error` styles.
- Added `.pq-badge-group`, `.pq-badge--live/emulated/mock` with pulsing warning animation.
- Added `.custom-server-group`, `.custom-input`, `.custom-port` styles.

---

#### Phase 6 — Docker, Entrypoints, Dependencies

**[MODIFIED] `Dockerfile.server`** — Fixed entrypoint: `python3 -m vpn.server --dashboard`; added cmake/ninja/libssl-dev for liboqs build; exposed 8000/51820.

**[MODIFIED] `Dockerfile.client`** — Fixed entrypoint: env-variable-driven `python3 -m vpn.client --server ${SERVER_HOST}`.

**[MODIFIED] `docker-compose.yml`** — Added vpn-net bridge network; `NET_ADMIN` + `/dev/net/tun` for both containers; `SERVER_HOST`/`SERVER_PORT`/`VPN_IP` env wired.

**[MODIFIED] `requirements.txt`** — Pinned all versions; added `liboqs-python>=0.10.0` with build note; added `pytest-asyncio`.

---

#### Verification Results

```
# Fail-closed enforcement (no env var):
.venv/bin/python -c "from crypto.hybrid_crypto import PQCProvider, PQCUnavailableError; PQCProvider()"
→ PASS: Fail-closed: Native liboqs is required but not available. Reason: liboqs-python not installed

# Full KEMTLS handshake + rekey (ALLOW_MOCK_PQC=1):
→ Handshake complete! Session IDs match: True
→ Frame encrypt/decrypt OK: True
→ Rekey nonce: 9fea514491722ba9...
→ Secure wipe OK
→ get_info: {session_id: ..., encryption_key_size: 32, mac_key_size: 32}

# KeyManager.derive_rekey_pair:
→ Rekey pair: enc_len=32 mac_len=32 | Keys differ from original: True | Derivation is deterministic: True
```

### 📅 Date: 2026-09-02 — GitHub Remote Repository Integration

**Objective:** Connect the local codebase to the remote GitHub repository (`https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git`).

- Initialized local Git repository on branch `main`.
- Verified `.gitignore` rules (excluding virtual environments, test caches, build artifacts).
- Added remote origin pointing to `https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git`.
- Configured commit author identity (`gopinath2704` <`gopihero713@gmail.com`>).
- Synchronized documentation in `README.md` and `progress.md`.
- Staged all project files and created initial root commit.

### 📅 Date: 2026-09-02 — Codebase Simplification & File Reduction (~44 → 18 Files)

**Objective:** Consolidate fragmented modules across benchmarks, application backend, VPN engine/CLI, and documentation into high-cohesion, maintainable files while preserving 100% functionality and test coverage.

- **Component 1 (Documentation)**:
  - Merged `phase.md` roadmap and milestone breakdowns into `progress.md`.
  - Merged `docs/deployment_guide.md` setup and container workflows into `docs/architecture.md`.
  - Deleted redundant `phase.md` and `docs/deployment_guide.md`.
- **Component 2 (Benchmarks)**:
  - Consolidated `handshake_bench.py`, `throughput_bench.py`, `packet_capture.py`, and `generate_charts.py` into a single high-performance `benchmarks/runner.py`.
  - Updated `benchmarks/__init__.py` and `tests/test_benchmarks.py` to import from `runner.py`.
  - Removed old fragmented benchmark scripts; results generated dynamically.
- **Component 3 (Application Backend)**:
  - Inlined `ConnectionManager`, rolling history buffers, `_build_telemetry_frame`, and `/ws/telemetry` endpoint directly into `app/backend/api.py`.
  - Updated `app/backend/__init__.py` and deleted `app/backend/websocket.py`.
- **Component 4 (VPN Engine & CLI)**:
  - Integrated `VPNService`, `ServiceState`, `VPNTelemetry`, and KEMTLS transport helpers from `vpn/service.py` directly into `vpn/engine.py`.
  - Created unified CLI `vpn/cli.py` with `server` and `client` subcommands (`python -m vpn.cli server|client`).
  - Updated `Dockerfile.server`, `Dockerfile.client`, `app/backend/api.py`, and `vpn/__init__.py`.
  - Deleted separate `vpn/service.py`, `vpn/server.py`, and `vpn/client.py`.
- **Remote Synchronization**:
  - Pushed consolidated commit `a88e911` to GitHub remote (`https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git`) on branch `main`.

---

## 🚦 Current Status & Next Steps

| Task / Module | Status | Description |
| :--- | :---: | :--- |
| **Final Handoff Validation** | ✅ Completed | 210 collected; both entrypoints 208 passed / 2 skipped; native 2 passed; doctors and static checks recorded |
| **Dependency / Deployment Hardening** | ✅ Completed | Pinned role dependencies; explicit native install; scoped firewall, forwarding restoration, UDP dead-peer/DNS safety, strict identities/database and telemetry tickets |
| **Edit-3 Idle Activity / Packaging** | ✅ Completed | Authenticated keepalive refresh; invalid activity rejected; fresh-environment deployment |
| **Directory Scaffolding** | ✅ Completed | Created complete directory tree and skeleton files |
| **Agent Memory Mandate** | ✅ Completed | Configured automatic progress logging instructions |
| **GitHub Integration** | ✅ Completed | Configured Git repo & remote `https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git` |
| **Hybrid Cryptography (`crypto/`)** | ✅ Completed | X25519 + standardized ML-KEM-768 hybrid inputs and HKDF-SHA256 |
| **KEMTLS-inspired Handshake (`handshake/`)** | ✅ Completed | Custom pinned-server/authorized-client protocol, transcript binding, channel-separated AES-256-GCM records |
| **VPN Engine (`vpn/engine.py`)** | ✅ Completed | TUN and measured quality primitives; routed client/server in vpn/runtime.py |
| **Unified VPN CLI (`vpn/cli.py`)** | ✅ Completed | Unified server and client entry points with subcommands (`vpn.cli server`, `vpn.cli client`) |
| **Application UI (`app/`)** | ✅ Completed | Browser management and consolidated REST/WebSocket backend; optional PyWebView shell outside tested dependency baseline |
| **Benchmarks (`benchmarks/runner.py`)** | ✅ Completed | Consolidated handshake, throughput, packet capture, and chart generation |
| **PQC Fail-Closed Enforcement** | ✅ Completed | `PQCUnavailableError` + `ALLOW_MOCK_PQC` env + `_MockInsecurePQCProvider` w/ security warnings |
| **In-Session Rekeying** | ✅ Completed | Dedicated control reader/rekey scheduler; existing epoch and record security preserved |
| **UI Transparency Badges** | ✅ Completed | Configured-profile UI; measured telemetry; classical client-auth boundary |
| **Docker Configuration** | ✅ Completed | Entrypoints updated to `vpn.cli`, `NET_ADMIN`, `/dev/net/tun`, bridge network |
| **Unified Documentation** | ✅ Completed | Consolidated architecture & deployment guide in `docs/architecture.md`, merged roadmap |
| **Automated Test Validation** | ✅ Completed | 208 passed / 2 skipped under both pytest entrypoints; current evidence in latest log |
| **Install Native liboqs** | ✅ Completed | Current environment exposes native ML-KEM-768 and passes the isolated self-test/integration marker |
| **2026 Security Remediation** | 🔄 In Progress | Confirmed code fixes are implemented; privileged end-to-end VPS/namespace proof remains pending |
| **Authenticated v2 Handshake/Records** | ✅ Completed | Pinned server identity, authorized clients, directional AEAD, replay/AAD/epoch controls |
| **Linux Routed Runtime** | 🔄 In Progress | Single TUN/UDP demux, IP pool, UDP bind, routes/DNS/NAT implemented; privileged namespace proof pending |
| **Management Security** | ✅ Completed | Loopback HTTP bearer, explicit CORS, bounded 30-second single-use telemetry tickets |
| **Native ML-KEM Validation** | ✅ Completed | Current environment: `2 passed` under `-m native_pqc`; liboqs/binding 0.16.0 |
| **Real VPS/client Deployment** | ⏳ Pending | Not executed; status remains deployable research/prototype PQ-VPN |
| **Privileged Namespace Validation** | ⏳ Pending | Host UID 1000, TUN present outside sandbox; no root execution; marker correctly skipped |

---

## 🚦 Historical Project Phase Roadmap Matrix

This retained matrix records earlier project claims and test counts. It is not the current validation report; the table above and the latest modification entry are authoritative.

| Phase | Phase Name | Status | Key Deliverables | Test Coverage |
| :---: | :--- | :---: | :--- | :---: |
| **Phase 0** | **Project Setup & Architecture** | ✅ **Completed** | Scaffolding, Docker environment, requirements, documentation | — |
| **Phase 1** | **Hybrid Cryptography Engine** | ✅ **Completed** | `crypto/hybrid_crypto.py` (X25519 + Kyber768 + HKDF-SHA256 + Session Store) | 37 / 37 Passed |
| **Phase 2** | **Signature-Free KEMTLS Handshake** | ✅ **Completed** | `handshake/kemtls.py` (Wire protocol, Transcript Hasher, AES-256-GCM session, Client/Server state machines) | 43 / 43 Passed |
| **Phase 3** | **VPN Engine & Network Agility** | ✅ **Completed** | `vpn/engine.py` (TUN Interface, Tunnel Daemon, MTU Monitor, Network Quality, OpenVPN Manager, VPNService) | 71 / 71 Passed |
| **Phase 4** | **Application GUI & Controller API** | ✅ **Completed** | `app/main.py` (Desktop launcher), `app/backend/api.py` (FastAPI REST + WS Telemetry), `app/frontend/` (Dashboard UI) | API verified |
| **Phase 5** | **Benchmarking & Final Validation** | ✅ **Completed** | `benchmarks/runner.py` (Handshake timing, throughput, packet capture, chart generator) | 10 / 10 Passed |
| **Phase 6** | **Codebase Simplification** | ✅ **Completed** | Streamlined file reduction (~44 → 18 files) with 100% backward compatibility & tests passing | 161 / 161 Passed |
