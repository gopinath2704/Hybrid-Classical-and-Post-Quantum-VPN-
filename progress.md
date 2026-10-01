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
├── app/                    # PySide6 desktop GUI, privileged client service, and Unix domain socket IPC
├── benchmarks/             # Ignored output directory created by benchmark runs
├── config/                 # Shared server/client TOML examples; secrets ignored
├── crypto/                 # X25519, native ML-KEM-768 and HKDF
├── deploy/                 # Server/client systemd units and consolidated version provenance
├── docs/                   # design, deployment, accounts, and historical security audit
├── handshake/              # Frozen authenticated v2 protocol and record layer
├── packaging/
│   ├── arch/               # Main PQ-VPN plus pinned native/Python liboqs Pacman packages
│   ├── common/             # Shared desktop, icon, and managed service assets
│   └── deb/                # Debian app plus pinned native/Python liboqs package recipes
├── scripts/                # Native liboqs installer and server network lifecycle
├── tests/                  # Responsibility suites plus shared fixtures and root harness
├── vpn/                    # CLI/config/doctor/identity/profiles/enrollment/network/runtime boundaries
├── constraints-tested.txt  # Complete tested transitive version pins
├── pyproject.toml          # Core, desktop and development dependency groups
├── Dockerfile              # Shared server/development-client image
└── docker-compose.yml
```

---

## 📝 Modification Log & Project Progress

### 2026-10-01 — Milestone 4.6: Account-Aware Desktop UX

- `account_ux_state()` in `app/client.py` combines session, account-server reachability,
  device binding/review status, and the service-reported VPN state into one of the
  planned states (signed out, no device, pending, rejected, revoked, disabled,
  approved/disconnected, connecting, connected, session expired, server unavailable).
- New Home "Account & Device" card (state, account, this device, Open Account) and a
  "Session expires" row on the Account profile; the 60-second session check also
  refreshes device status, so an administrator approval appears without re-login.
- Account state never gates Connect; the VPN state always takes precedence.
- Fixed Account page horizontal clipping caused by an unwrapped notice label.

### 2026-10-01 — Milestone 4.5: Device Enrollment and Administrator Approval

- **Account schema version 2** (`vpn/accounts.py`): devices gain an administrator review
  `status` (`pending` / `approved` / `rejected` / `revoked`, SQLite `CHECK`-enforced).
  `initialize()` migrates a verified version 1 database in one transaction; existing
  bindings start `pending`. Status changes are compare-and-set.
- **Administrator CLI** (`python -m vpn.cli account devices|approve|reject|revoke`):
  the only path from an account device into `AuthorizedClients`. `approve` refuses
  disabled accounts/devices and rolls back the authorization if recording the status
  fails; `revoke` disables tunnel authorization before recording the status.
- The account API exposes `status` read-only and still cannot modify `AuthorizedClients`;
  the desktop binding row shows the review state.

### 2026-10-01 — Milestone 4.4: Account ↔ Managed Device Binding

- `vpn/account_api.py`: authenticated `GET /devices` and `POST /devices`. The server
  verifies `SHA-256(public key) == fingerprint`, returns public fields only, treats a
  repeat binding as idempotent, rejects identities owned by another account and any
  extra (e.g. private-key) field, and caps accounts at 20 devices.
- `app/client.py`: "This Device" card on the Account page. It reads the managed public
  identity via the existing `SETUP_STATUS` IPC, re-verifies it locally, and uploads only
  the public key, fingerprint, and a device name. Device list refreshes with the session check.
- Binding never edits `AuthorizedClients`; tests assert `authorized_clients.json` is unchanged.

### 2026-10-01 — Milestone 4.3: Desktop Client Login, Registration, and Session UX

- **Account API client in `app/client.py`** (no new module, no new runtime dependency):
  `AccountClient` uses standard-library `urllib`/`ssl`; HTTPS always verifies
  certificates (optional private CA file), cleartext HTTP is accepted only on loopback,
  URLs with credentials/query strings are refused, responses are size-bounded and
  validated, and every server error is mapped to a fixed user-safe message.
- **Memory-only `AccountSession`**: the bearer token lives only in GUI process memory,
  is redacted from `repr`/`str`, and is never logged, displayed, persisted, or sent over IPC.
- **Account page**: Login (username or email), Register (client-side length/confirm
  checks; server authoritative), profile view loaded through `/auth/me`, Sign Out,
  rate-limit countdown, and session-expired / API-unavailable states. A 60-second
  `/auth/me` check returns an expired, revoked, or disabled-account session to Login.
  Sign Out clears the local token first, so a failed remote logout cannot leave it behind.
- **Tests** (`tests/test_client_app.py`): real `pqvpn-account-api` on loopback for
  username/email login, wrong password / unknown / disabled account uniformity,
  rate limits, invalid and duplicate registration, revocation, malformed responses,
  API unavailable, plus headless GUI session-lifecycle and token-never-shown checks.
- Login never touches `authorized_clients.json`; the frozen VPN core diff is empty.

### 2026-09-19 — Project File Consolidation

- Merged the distribution packaging guide into canonical `docs/deployment.md` and
  updated its README/test references.
- Embedded the sole-use IPv6 route filter in the root namespace harness while
  preserving its isolated regression test, and removed the redundant GUI launch
  wrapper because `pqvpn-gui` and `python -m app.client` use `app.client:main`.
- Removed duplicate cryptographic test fixtures in favor of `tests/conftest.py`.
  No frozen crypto, handshake, runtime, network, onboarding, account, or account
  API implementation was changed.
- Validation passed: 429 tests with 2 privileged skips, native ML-KEM 2/2,
  account/API 86/86, lifecycle reuse rejection, compileall, shell syntax,
  systemd/sysusers, Arch metadata, Debian patch dry-runs, clean wheel entry points,
  dependency consistency, frozen-core diff, and whitespace checks.

### 2026-09-19 — Milestone 4.1: Secure Account and Device Store Implementation

- **Secure SQLite Account & Device Store (`vpn/accounts.py`)**:
  - Implemented standalone `AccountStore` and `DeviceStore` backed by SQLite with WAL journal mode, `foreign_keys=ON`, and isolated schema migrations.
  - Implemented Argon2id password hashing via `argon2-cffi` (memory cost 64 MB, time cost 3 iterations, parallelism 4, 16-byte secure random salt) with parameter verification and rehash detection.
  - Implemented strict RBAC (`user`, `admin`), active/inactive account flags, device public key tracking, device revocation, session token generation with SHA-256 hash storage, constant-time token validation, and expiry management.
  - Preserved strict security separation: accounts, sessions, and devices in SQLite do NOT automatically grant VPN tunnel authorization or mutate `authorized_clients.json`.
- **Packaging and Dependencies**:
  - Pinned `argon2-cffi==25.1.0` and `argon2-cffi-bindings==25.1.0` in `pyproject.toml` and `constraints-tested.txt`.
  - Added `python-argon2-cffi` to Arch `packaging/arch/PKGBUILD`.
  - Added `python3-argon2` to Debian/Ubuntu `packaging/deb/debian/control` and refreshed runtime dependencies patch.
  - Updated `README.md`, the packaging guide now in `docs/deployment.md`, and `packaging/deb/debian/install`.
- **Documentation & Testing**:
  - Created `docs/accounts.md` detailing database schema, password hashing specifications, session token security, and authorization boundaries.
  - Created comprehensive test suite `tests/test_accounts.py` with 42 unit/integration tests; full test suite passes (385 passed, 2 skipped).

### 2026-09-15 — Milestone 3 Live Acceptance and Ubuntu 26.04 Packaging

- **Minimal server enrollment update**: deployed only `vpn/cli.py` and
  `vpn/enrollment.py` to the Ubuntu server. Local/remote SHA-256 values matched
  (`b48ffa0812cdc55c8943dfe70c2094a5024be3d8f04b7e98c770a9eb23c94ccb`
  and `44cc80fc55f0b423c7c2a006d64f3b217aac7350ff86a8939b14b395cefeb594`),
  `authorize-request` appeared, and the daemon PID remained unchanged. Authorized
  `shadow-laptop.pqenroll` in the configured database with fingerprint
  `71a07a73d1b4acc332db2f6083cedf34bd0a67ed887d910fdb1c313cde614fb1`.
- **Real GUI connection lifecycle**: the normal-user GUI connected the managed
  `ubuntu-lab` profile through native `pqvpn0` at `10.8.0.2/24`, reached
  `10.8.0.1`, installed both full-tunnel `/1` routes and the endpoint bypass,
  attached working `1.1.1.1`/`9.9.9.9` routing DNS, blocked IPv6 in an owned nft
  table, loaded native liboqs 0.16.0, verified server fingerprint
  `caa34de32b573b511bde3f5a85b738ecc7cf7aa44b22fdc37e128d00016cf439`,
  and exposed changing real RTT/jitter/uptime metrics. GUI disconnect restored
  the baseline routes/DNS and removed the TUN and firewall table without residue.
  Reconnect preserved the client fingerprint and the exact identity-file inodes,
  sizes, modes, and timestamps, proving no identity regeneration.
- **Automatic rekey**: temporarily set the server interval to 60 seconds, observed
  epoch `0 → 1` with all **223/223** continuous gateway pings received, then
  disconnected, restored `3600`, restarted for the configuration change, and
  verified a short reconnect negotiated the restored interval. The final client
  teardown is clean and the server remains active at the normal policy.
- **Ubuntu 26.04 Debian packages**: replaced unavailable `python3-liboqs`/`liboqs0`
  dependencies with exact `python3-liboqs-pqvpn=0.16.0-1` and
  `liboqs-pqvpn=0.16.0-1` recipes pinned to the same commits/checksums as Arch.
  The wrapper shares the checksum-identical no-runtime-download patch. A
  Debian-only metadata patch delegates PyPI version requirements to explicit
  Ubuntu package dependencies, while the app build requires native PQC.
  `liboqs-pqvpn`, `python3-liboqs-pqvpn`, and `pqvpn` all built on Ubuntu 26.04;
  their binary SHA-256 values are respectively
  `a1cbbcf1291e330d8ce1b4389019d5f71d927c85c819f83db512937289e037d3`,
  `84d9ad981d01218e532986c268fb9b433b117684af79bee76418c40011375dbd`,
  and `050413c25a64de53cd83c901de332e6c5c7db8f7b03f27edae560370c890a736`.
  A clean Ubuntu 26.04 install resolved every dependency, imported the GUI,
  reported wrapper/native 0.16.0 with ML-KEM-768 and `native_liboqs`, mapped only
  `/usr/lib/x86_64-linux-gnu/liboqs.so.0.16.0`, exposed `authorize-request`, and
  passed packaged-unit verification. The regenerated allowlisted Arch application
  archive has SHA-256
  `c8042bb8d576c5ffca0c762b1972899bd05b82848fbdab52cbb80f382e9ad043`.
  Redistribution remains license-blocked.
- **Validation and hygiene**: removed the temporary VM SSH key, both temporary sudoers
  grants, the accidentally targeted alternate authorization database, enrollment
  transfer, deployment staging files, and GUI drivers after confirming the real
  configured authorization record remained enabled. The committed release
  candidate passed the full suite (**343 passed, 2 skipped in 39.30s**) and native
  no-mock marker (**2 passed, 343 deselected in 0.28s**). Compileall, every project
  Bash/PKGBUILD and Debian rules syntax check, Debian patch dry-run, identical
  wrapper-patch comparison, deterministic archive checksum, native backend/version,
  `pip check`, and Git whitespace/clean-tree checks passed.

### 2026-09-14 — Milestone 3 Privileged Client User-Site Isolation

- **Systemd launch hardening**: added Python's `-s` flag to both maintained
  privileged client units while preserving their interpreter paths, privileges,
  capabilities, sandboxing, IPC, and VPN behavior. Packaging regressions now
  assert the exact hardened command in each unit.
- **Deterministic source update**: regenerated the allowlisted committed-source
  archive after the packaged service change and recorded SHA-256
  `d791b49894214253bba52395e06b2745ce946bab80418f46148c13768d69ba1a`.
  Added narrow ignores for local makepkg archives and `src/`/`pkg/` trees so
  live-validation artifacts remain untracked and are never packaged.
- **Validation**: full suite **343 passed, 2 skipped in 39.01s** outside the
  local-socket sandbox; native marker **2 passed, 343 deselected in 0.16s**.
  The PKGBUILD syntax, deterministic archive checksum, and Git whitespace gates
  passed without installing or removing any package.

### 2026-09-14 — Milestone 3 Arch/Omarchy Packaging Reproducibility Fix

- **Package-managed PQC dependencies**: added `liboqs-pqvpn` and
  `python-liboqs-pqvpn` Arch package definitions at `0.16.0`. Native liboqs is
  pinned to validated commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`,
  builds a shared library with CMake/Ninja, installs the normal SONAME chain
  under `/usr/lib`, and declares its observed glibc/gcc-libs/OpenSSL runtime
  dependencies. The Python wrapper is pinned to tag commit
  `c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061`, installs system-wide through
  `python-installer`, and depends on the native Pacman package.
- **Fail-closed wrapper packaging**: added a checksum-verified downstream patch
  that removes liboqs-python's upstream runtime Git/CMake downloader, defaults
  discovery to `/usr`, and prioritizes the explicit `/usr/lib` path. It neither
  bundles liboqs nor uses pip, home-directory state, `/usr/local`, or mock PQC.
- **Main package/source**: replaced `python-pyside6`, `python-liboqs`, and
  `liboqs` with `pyside6`, `python-liboqs-pqvpn=0.16.0`, and
  `liboqs-pqvpn=0.16.0`; added the setuptools build backend dependency. Replaced
  the checksum placeholder with a real deterministic `git archive` hash. The
  documented allowlist contains only committed package inputs and excludes the
  deployment-specific client configuration, identities, state, caches, `.git`,
  untracked files, and the PKGBUILD itself.
- **Validation**: all three source sets passed makepkg SHA-256 verification and
  all PKGBUILDs passed syntax and `.SRCINFO` generation. `liboqs-pqvpn` completed
  a full makepkg build; its package contains `/usr/lib/liboqs.so.0.16.0` with
  SONAME `liboqs.so.9` and correct links. The patched wrapper imported against
  that staged library, reported wrapper/native `0.16.0`, enabled ML-KEM-768, and
  mapped the staged library rather than `/usr/local`. Full suite: **343 passed,
  2 skipped in 38.88s** outside the local-socket sandbox; native marker:
  **2 passed, 343 deselected in 0.16s**. No system package was installed or
  removed; final manual dependency/main installation validation remains pending.

### 2026-09-13 — Desktop Client Milestone 3: Secure Onboarding Foundation

- **Branch/pre-flight**: created `client/onboarding-milestone-3` from clean verified
  `main` commit `50b86e2a630cd28a3580b06bb4d1781b9b703519`; unchanged baseline
  passed **286 passed, 2 skipped** outside the environment's local-socket sandbox.
- **Public provisioning formats**: added strict, duplicate-property-rejecting,
  bounded JSON `.pqvpn` server profiles and `.pqenroll` client enrollment requests.
  Both verify key lengths and SHA-256 fingerprints and reject unknown fields; neither
  format accepts secrets, commands, URLs, interpolation, or private-key paths.
- **Managed identity/profile state**: added idempotent service-owned Ed25519 identity
  creation/validation without rotation, no-follow private reads, `0600` private and
  `0644` public modes, deterministic atomic profile storage, explicit replacement,
  exact-ID deletion, active selection, and a five-profile bound compatible with the
  unchanged 16 KiB IPC maximum.
- **Narrow IPC/GUI**: extended the existing service with setup, identity, profile, and
  public enrollment commands. Profile content crosses IPC as bounded JSON rather than
  a privileged file path; no generic file/TOML write or private-key response exists.
  The existing six-page GUI now has first-run setup, real imported profiles, offline
  enrollment copy/export, public identity display, and disconnect-before-profile-change
  policy. The normal-user GUI refuses root execution.
- **CLI/admin flow**: added `client enrollment-request` and `client authorize-request`;
  authorization continues through the existing locked/atomic `AuthorizedClients`
  abstraction and does not change revocation/session semantics.
- **Compatibility**: explicit `--config PATH` remains legacy TOML mode; omitting
  `--config` selects managed state. Sources never merge. The frozen protocol,
  cryptography, records, rekey, TUN, routing, firewall, DNS, IPv6, and server session
  semantics were not modified.
- **Packaging/docs/tests**: added conservative Arch/Omarchy and Debian foundations,
  desktop entry/icon, managed package service, safe state directories, README/design/
  deployment updates, exact live-validation instructions, and focused onboarding
  regressions.
- **Final validation**: `pytest -q` — **342 passed, 2 skipped in 39.05s**;
  `ALLOW_MOCK_PQC=0 pytest -q -m native_pqc` — **2 passed, 342 deselected in
  0.16s**. Compileall, all project Bash syntax plus PKGBUILD syntax, `git diff
  --check`, `pip check`, desktop-entry validation, package systemd-unit validation,
  and Arch `.SRCINFO` generation passed. The deploy unit parsed but its configured
  `/opt/pqvpn/.venv/bin/python` is not installed on this source host. Wheel build
  was unavailable because system Python lacks `setuptools.build_meta`; Debian
  package tools are absent. Package build/install and Milestone 3 Omarchy↔Ubuntu
  live validation remain unperformed.

### 2026-09-13 — GUI Milestone 2 Merged to Main & Published

- **Restored server config**: `rekey_interval` restored from `60` back to `3600` on Ubuntu VM (`192.168.8.43`), server restarted and verified `active (running)`.
- **Reconnected from Omarchy client**: Confirmed `State: CONNECTED`, `Epoch: 0`, `rekey_interval: 3600` via IPC before network change.
- **Branch `client/gui-milestone-2` merged into `main`** via `git merge --ff-only` (fast-forward, no merge commit):
  - Files changed: `app/client.py`, `tests/test_client_app.py`, `README.md`, `progress.md` (4 files, +1707/−704 lines).
- **Final regression**: `pytest -q` — **286 passed, 2 skipped** in 38.72s.
- **Pushed to GitHub**: `e70de38..c2638e8  main → main`.

### 2026-09-13 — Ubuntu VM Server Rekey Interval Accelerated for Testing

- **Updated Server Config (`/home/shadowuser/pqvpn/config/server.toml`) on Ubuntu VM (`192.168.8.43`)**:
  - Temporarily changed `rekey_interval` from `3600` to `60` seconds to enable observation of automated in-session rekeying within ~1 minute rather than waiting an hour.
  - Restarted systemd service: `sudo systemctl restart pqvpn-server`.
  - Verified daemon status: `active (running)`, listening on UDP and TCP `51820`, nftables/NAT rules reconciled.

### 2026-09-13 — VM Server Systemd Background Service Automation & Self-Healing

- **Hardened `/etc/systemd/system/pqvpn-server.service` on Ubuntu VM (`192.168.8.43`)**:
  - Integrated automated firewall & NAT setup directly into unit lifecycle:
    - `ExecStartPre=+/bin/bash /home/shadowuser/pqvpn/scripts/server-network.sh setup /home/shadowuser/pqvpn/config/server.toml` (ensures nftables rules and `net.ipv4.ip_forward = 1` are automatically reconciled across VM reboots).
    - `ExecStopPost=+/bin/bash /home/shadowuser/pqvpn/scripts/server-network.sh cleanup /home/shadowuser/pqvpn/config/server.toml` (ensures clean rule restoration upon stopping).
  - Configured network synchronization: `After=network-online.target Wants=network-online.target`.
  - Added self-healing restart policy: `Restart=always`, `RestartSec=3`.
  - Enabled service to start automatically on system boot (`systemctl enable pqvpn-server.service`).
  - Verified daemon status: `active (running)`, listening on TCP and UDP `51820`. Probed reachability from Omarchy host (`192.168.8.43:51820`).

### 2026-09-12 — Ubuntu VM Server Startup & Server Management Documentation

- Started and verified Ubuntu VM server instance (`192.168.8.43:51820`):
  - Setup and enabled persistent systemd service `pqvpn-server.service` in `/etc/systemd/system/` to ensure the server automatically resumes across VM reboots.
  - Reconciled firewall and NAT forwarding via `scripts/server-network.sh setup /home/shadowuser/pqvpn/config/server.toml`.
  - Verified server listening on TCP and UDP `51820` and tested probe from Omarchy host.
- Updated `README.md` with `Running the server` instructions:
  - Added systemd management commands (`start`, `stop`, `restart`, `status`, `journalctl`).
  - Added direct CLI execution commands (`server-network.sh setup` + `vpn.cli server`).
  - Added port verification command (`ss -tulpn | grep 51820`).

### 2026-09-12 — Desktop GUI Milestone 2

- Redesigned `app/client.py` as a premium dark desktop VPN interface with a large painted connection control, restrained state colors, live metric cards, responsive scrolling, and real Home, Servers, Security, Settings, Logs, and About navigation.
- Expanded the existing `STATUS` response with service-owned, read-only, non-secret profile metadata. Added only one command, `LOGS`, returning a sanitized 300-entry service event ring; framing, 16 KB bounds, `SO_PEERCRED`, socket permissions, and serialized Connect/Disconnect behavior are unchanged.
- Added a single serialized background IPC worker so one-second status polling and actions never block the Qt GUI thread or create unbounded threads. No navigation action can connect or disconnect the VPN.
- Security wording now distinguishes active sessions from configured capability and explicitly identifies ML-KEM-768 + X25519 server/session protection, classical Ed25519 client authentication, AES-256-GCM traffic protection, and the custom KEMTLS-inspired protocol boundary.
- No TX/RX counters were added because the runtime does not expose trustworthy VPN-only byte telemetry. No protocol, cryptography, runtime, routing, DNS, nftables, IPv6 guard, TUN, or server behavior changed.
- Validation: client suite **32 passed**; full suite **286 passed, 2 skipped**; native PQC marker **2 passed, 286 deselected**.
- Static compilation, shell syntax, and whitespace checks passed. The finished application opened in the live Hyprland session as native Wayland (`xwayland: false`); no real Connect or Disconnect action was triggered during this GUI-only launch check.

### 2026-09-12 — Live End-to-End VPN Connection, GUI Wayland Validation & Clean Teardown

- **Branch**: `client/home-gui`.
- **Live VM Connection Verified**:
  - Unprivileged PySide6 GUI launched natively under Hyprland / Wayland (`xwayland: 0`).
  - Connected from Omarchy host (`192.168.8.99`) to Ubuntu VM server (`192.168.8.43:51820`).
  - State transition observed: `DISCONNECTED → CONNECTING → CONNECTED`.
  - Tunnel interface `pqvpn0` created with IP `10.8.0.2/24`, MTU 1380.
  - Crypto parameters verified: Hybrid KEMTLS with native ML-KEM-768 (`native_liboqs`) + X25519, Epoch 0, rekey countdown active.
  - Traffic and quality metrics: Ping to gateway `10.8.0.1` succeeded with 0% loss, avg RTT `0.77 ms`. Transferred 18.8 MB TX / 3.0 MB RX.
  - Full-tunnel routing active (`0.0.0.0/1` and `128.0.0.0/1` via `pqvpn0`) with physical gateway route preserved.
  - `systemd-resolved` DNS managed on `pqvpn0` with servers `1.1.1.1`, `9.9.9.9` and routing domain `~.`.
- **Clean Disconnect & Restoration Verified**:
  - Triggered Disconnect from GUI.
  - TUN interface `pqvpn0` completely removed (`Device "pqvpn0" does not exist`).
  - Routing table cleanly restored: default route restored via physical gateway (`192.168.8.101 dev wlp46s0`).
  - DNS link on `pqvpn0` destroyed; physical DNS interface restored.
  - Client daemon remains healthy in `DISCONNECTED` state.
- **Dynamic Config Validation**:
  - Updated `app/client.py` (`_do_connect`) to re-validate config dynamically on connection attempt.
  - Corrected key paths in `config/client.toml` to resolve relative to the config directory.
- **Automated Tests**:
  - Full suite passed: **271 passed, 2 skipped in 38.43s**.

### 2026-09-12 — Omarchy Dependency Installation, IPC Socket Permission Fix & Ubuntu VM Deployment

- **Branch**: `client/home-gui`.
- **Omarchy Module Installation**:
  - Installed all required desktop and development dependency groups: `PySide6 6.11.2`, `liboqs-python 0.16.0`, `scapy 2.7.0`, `psutil 7.2.2`, `matplotlib 3.11.1`, `pandas 3.0.5`, `numpy 2.5.3`, `pillow 12.3.0`, and `paramiko 5.0.0`.
  - All packages verified against Python 3.14 on Arch/Omarchy.
- **Privilege & IPC Security Fixes (`app/client.py`)**:
  - Fixed IPC socket mode: changed from `0o660` to `0o666` at `/run/pqvpn/client.sock` so unprivileged desktop users (`shadow`, UID 1000) can connect when the service runs under systemd/root. Kernel-enforced `SO_PEERCRED` authenticates peer credentials upon connection.
  - Set default `QT_QPA_PLATFORM` to `wayland;xcb` for native Wayland execution under Hyprland.
  - Guarded `signal.signal(signal.SIGTERM)` against non-main thread execution.
- **Ubuntu VM PQ-VPN Server Setup**:
  - Bridged network between Omarchy (`10.83.129.99`) and Ubuntu VM (`10.83.129.43`) verified with `0.29 ms` RTT.
  - Deployed native `liboqs.so.0.16.0`, `python3.14-venv`, and repository codebase to `/home/shadowuser/pqvpn`.
  - Generated ML-KEM-768 server keypair (`server_identity_private.key`, `server_identity_public.key` fingerprint `caa34de3...`).
  - Authorized client identity `omarchy-client` (`client_identity_public.key` fingerprint `001b5845...`) in `authorized_clients.json`.
  - Configured firewall and IP forwarding via `scripts/server-network.sh setup`.
  - Started PQ-VPN server on VM via systemd (`pqvpn-server-test.service`), listening on TCP and UDP port 51820.
  - Configured `config/client.toml` on Omarchy with VM server endpoint and SHA-256 fingerprint.
- **Validation**:
  - Full test suite: **271 passed, 2 skipped** (273 collected).
  - Native PQC marker (`-m native_pqc`): **2 passed**.

### 2026-09-11 — Desktop Client Milestone 1, File Reduction & README Rewrite

- **Branch**: `client/home-gui` from latest `main`.
- **Desktop Client Milestone 1 (`app/client.py`)**:
  - Implemented a unified desktop client architecture providing:
    1. Unprivileged PySide6 GUI running as normal desktop user (`app.client --gui`).
    2. Privileged background service running with `CAP_NET_ADMIN` via systemd (`app.client --service`).
    3. Secure Unix domain socket IPC (`/run/pqvpn/client.sock`) using length-prefixed JSON framing (`<I`), peer credential authentication via `SO_PEERCRED` (limiting command access to the authorized user or root), strict message size bounds (16 KB max), concurrent command rejection, and error sanitization.
  - GUI Home Screen displays live connection state (DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, DISCONNECTING, FAILED), real VPN IP, endpoint, latency, TX/RX byte counters, protocol transparency pills (X25519, ML-KEM-768, AES-256-GCM, Ed25519 client auth), human-readable error messages, missing configuration notices with exact paths, and single-click Connect/Disconnect actions.
  - Privileged service manages `VPNClient` lifecycle (`vpn.runtime`), TUN allocation, route table configuration, and IPv6 leak prevention policies.
  - Added `deploy/pqvpn-client.service` systemd unit file with security sandbox and `RuntimeDirectory=pqvpn`.
- **Repository Simplification & File Reduction**:
  - Removed obsolete web stack: `app/main.py`, `app/backend/api.py`, `app/backend/__init__.py`, `app/frontend/index.html`, `app/frontend/css/style.css`, and `tests/test_management.py`.
  - Migrated non-FastAPI tests (doctor checks, native library verification) into `tests/test_deployment.py`.
  - Replaced API-dependent runtime schema test in `tests/test_runtime.py` with `test_client_status_serialization_and_real_schema`.
  - Added comprehensive test suite `tests/test_client_app.py` (12 test cases covering IPC framing, authorization, state transitions, missing config, and headless GUI widgets).
  - Updated `pyproject.toml` removing FastAPI, Uvicorn, and WebSockets dependencies; added `desktop` extra for `PySide6`.
  - Net file reduction: deleted 6 files and added the canonical client, service,
    and test files; the temporary package launcher was later removed in favor of
    the installed `pqvpn-gui` entry point and `python -m app.client`.
- **Documentation & README Rewrite**:
  - Rewrote `README.md` into a clean, accurate, single-source project landing page (~150 lines) detailing current capabilities, architecture, hybrid crypto primitives, quickstart, GUI usage, testing, and limitations.
  - Updated `docs/design.md` to reflect desktop client architecture and Unix domain socket IPC.
- **Validation**:
  - Full test suite: **270 passed, 3 skipped** (273 collected).
  - Native PQC marker (`-m native_pqc` with `ALLOW_MOCK_PQC=0`): **2 passed**.
  - Shell syntax verification: all shell scripts pass `bash -n`.
  - Python byte-compilation: all packages compile cleanly.

### 2026-09-08 — Minimal maintainable project layout

- Continued `refactor/minimal-layout` from clean `v2-pre-vps-2`. The handed-off working tree already contained 43 meaningful files; final count remains 43, versus 73 before the whole refactor: 30 files removed (41.10%). Removed seven reproducible benchmark outputs and ignored generated results/build metadata; added a Docker context exclusion list.
- Consolidated 19 Python test modules into six responsibility suites while retaining every prior test, markers, root namespace harness and native tests. Added one deterministic frozen-wire regression covering all four v2 handshake messages; collection is now 261 tests.
- Consolidated seven fragmented guides into `docs/design.md` and `docs/deployment.md`; retained `docs/security_audit.md`. Replaced five requirement entry points and pytest configuration with `pyproject.toml` core/management/dev groups and markers while keeping every tested version in `constraints-tested.txt`.
- Combined TUN/telemetry, IPv6 policy and firewall rendering into the 238-line `vpn/network.py`; kept crypto, handshake, runtime, identity, config and doctor separate. Combined setup/cleanup into `scripts/server-network.sh` with explicit subcommands and preserved privileged systemd execution. Merged version provenance, inlined the small dashboard JavaScript, retained the large CSS separately, consolidated benchmarks into `benchmarks.py` while preserving `python -m benchmarks`, and consolidated Docker/config duplication with an explicit validated client host override.
- Frozen handshake/cryptography and runtime security semantics were not changed. The only continuation correction makes the in-memory bearer dependency async so pinned AnyIO/Python 3.14 does not thread-offload a constant-time header check; its HTTP authentication assertions remain intact. Final validation: 261 collected; both test entry points 259 passed / 2 skipped; native 2 passed from pinned commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`; fresh constrained install, doctors, benchmark smoke, compile, shell, extracted JavaScript, both Compose profiles, links and diff checks pass. Root namespace is skipped at UID 1000 because passwordless sudo is unavailable; systemd/nftables/DNS/VPS runtime gates remain pending. Local tag `v2-minimal-layout`; no push.

### 2026-09-08 — Harden privileged systemd deployment ownership

- Continued clean validated `a09f65b948df985b97285b145faacb53ad292797` / `v2-pre-vps`. Root-owned source and production venv, administrative updates, and immutable-to-service privileged execution chain now documented in deployment, handoff and security audit. `/etc/pqvpn` is root:pqvpn 0750; config/public/policy files root:pqvpn 0640; private identity pqvpn:root 0400. Authorization/revocation run as root and restore DB ownership/mode after existing atomic replacement. Fixed optional absolute liboqs installer prefix wording.
- Doctor audits production code/venv ownership, group/world write bits, intermediate symlinks, targets and ancestors; development profiles are explicitly out of scope. Added 15 staged ownership/deployment regressions without requiring root. Only a comment changed in the systemd unit; daemon user/capabilities and privileged helper commands remain. No handshake, crypto, runtime, firewall/replay/IPv6/rekey/DNS or dependency-pin changes.
- Final validation: both pytest invocation styles **258 passed, 2 skipped, 260 collected**; native ML-KEM **2 passed** with mock disabled, Python **3.14.7**, binding/native **0.16.0**, clean source **5a1a854b0dc9f2141bdc771c555ee60c37950183**. Fresh temporary venv/native build and loaded-library digest recorded in security audit. Compileall, four Bash syntax checks, JavaScript syntax, both Compose profiles, pip check and diff checks PASS. Temporary server doctor exit 0 with provider-firewall WARN only; client doctor exit 0/all PASS.
- Root namespace **SKIPPED**: host UID 1000, no passwordless sudo; TUN present and unchanged. Actual systemd, nftables enforcement, resolved restoration and VPS/client validation remain pending. No production paths were provisioned. New local commit/tag `v2-pre-vps-2`; original tag retained; no push. No repository files/directories added or removed.

### 2026-09-07 — Source-review continuation and local validation release

- Resumed the existing 20-file staged change on `c50dee0`; inspected the complete staged diff, configs, client networking, server helpers/service, namespace tests, dependency pins, current documentation and secret/artifact exclusions before committing. No IPv6 enforcement or frozen v2 cryptographic regression found. Full-mode block/fail/allow, split defaults, atomic owned-table cleanup and read-only doctor semantics match source. Handshake, crypto, rekey and networking behavior unchanged during continuation.
- Corrected doctor wording: Python >=3.11 is a runtime minimum, not a tested support claim; 3.14.7 remains the tested baseline and other versions warn. Added one parametrized regression in `tests/test_management.py`. CLI revocation explicitly states that existing active sessions continue until disconnect/expiration/server restart; strengthened its existing `tests/test_networking.py` assertion. No session-kill implementation added.
- Prior temporary environments/builds were gone. Recreated `/tmp/pqvpn-continuation.PdFUxu/venv` from unchanged requirements; all 36 constrained versions match and pip check passes. Rebuilt native ML-KEM-only liboqs 0.16.0 from verified clean source commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`, using GCC 16.2.1, CMake 4.4.3 and Ninja 1.13.2. Verified the loaded library in `/proc/self/maps`; updated `deploy/versions.txt` with the current digest while retaining the prior digest.
- Validation: focused IPv6/doctor tests **41 passed**. Both `pytest -q` and `python -m pytest -q`: **243 passed, 2 skipped, 245 collected**. Native marker: **2 passed, 243 deselected**, mock disabled, Python **3.14.7**, binding/native **0.16.0**. Compileall, four shell scripts, JS syntax, both Compose profiles and diff checks PASS. Final available validation is rerun after the last file edits before commit/tag.
- Temporary provisioned server doctor: PASS/WARN only for external firewall, exit 0; client doctor: PASS including IPv6 block, exit 0. Before/after files, links, IPv4/IPv6 routes, IPv6 addresses, forwarding and resolver snapshots match. Shipped sample profiles correctly exit 1 for absent identities/database and absent pqvpn account; no deployment material was added to source. Host WAN is enp0s20f0u4; IPv6 snapshot sees 3 routes/addresses.
- **ROOT NAMESPACE: SKIPPED — non-root session**, UID 1000; TUN and required tools exist, but `sudo -n true` reports a password is required. Root marker: 1 skipped, 244 deselected. Docker runtime, systemd runtime and real systemd-resolved restoration: NOT VALIDATED. Real VPS/client: NOT PERFORMED.
- Added `docs/deployment.md`, linked from README and server deployment, with local bundle/tag transfer (no push), actual bounded namespace invocation, pinned provisioning/systemd commands and real-client gates. Updated the current audit/status counts only; historical progress entries are preserved. No tracked deployment secrets or local build artifacts found.
- Authorized local release: `Pre-VPS PQVPN v2 validation baseline`, annotated tag `v2-pre-vps`, annotation `Validated PQVPN v2 baseline before root namespace and VPS testing`; create only after final checks, inspect staged paths, then verify clean tree and tag target. The final report records the exact commit hash. No push or remote deployment is performed.
- Status: **Deployable research/prototype PQ-VPN. IPv4 full tunnel includes IPv6 leak prevention. Native ML-KEM validation passed. Root/TUN integration pending. Real VPS/client validation pending.** Next milestone: root namespace validation, then real VPS + real Linux client validation.

### 2026-09-07 — Pre-VPS IPv6 leak protection, revocation and source baseline

- Inspected current Edit-5 tree first: base `c50dee0`, only the existing GitHub push-history entry in this file was dirty; preserved it. Current v2 handshake and crypto source remain byte-for-byte unchanged.
- Added `vpn/network.py`: transactional IPv6 block/fail/allow policy. Full mode defaults to block, split mode defaults to leaving unrelated IPv6 alone. Exclusive random ip6 table blocks non-loopback OUTPUT/FORWARD before IPv4 tunnel routes; cleanup removes only the owned table. Added config fields/examples and read-only IPv6 diagnostics. No routed IPv6 or persistent sysctl changes.
- Added `tests/test_networking.py`: 34 cases cover policy/default validation, IPv6 route/address detection, atomic setup failure, disconnect/setup/dead-peer/control/rekey/SIGTERM cleanup, read-only doctor, new-handshake revocation and installer source mismatch. Related focused run: 95 passed. Extended root namespace script with a physical IPv6 default route, bounded ICMPv6/TCP leak checks, loopback, and IPv6 restoration after disconnect/SIGTERM/dead peer; real execution remains pending.
- CLI revoke help/output states future authentication only; existing sessions/already-authorized handshakes continue until expiry/disconnect/restart. Server restart terminates all clients; no live reload/active-identity termination was added.
- Pinned native liboqs 0.16.0 to source commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`, verified from upstream tag and checkout. Installer fails on mismatch before build. No dependency versions upgraded. Added `deploy/versions.txt` with explicit temporary ML-KEM-only build provenance, compiler and binary digest. Prior binary source provenance was unavailable, so validation used this freshly built library, verified via loaded process mappings.
- Native versions: Python **3.14.7**, liboqs-python **0.16.0**, liboqs **0.16.0**. Separate native marker with mock disabled: **2 passed, 242 deselected in 0.19s**. Both full suites used the verified source build: `pytest -q` **242 passed, 0 failed, 2 skipped, 38.35s**; `python -m pytest -q` **242 passed, 0 failed, 2 skipped, 38.30s**; **244 collected** each. Existing 2 skips remain root namespace and native-provider precedence over mock.
- Compileall PASS; setup/cleanup/install-liboqs/namespace shell syntax each PASS; Node JS syntax PASS; Docker Compose config PASS; pip check PASS; diff whitespace PASS. No Docker runtime claim.
- Server doctor **WARN, exit 0**, external firewall verification only; client doctor **PASS, exit 0**, including IPv6 block policy with 3 visible IPv6 routes/addresses. Temporary native profiles used; snapshots proved unchanged files, links, IPv4/IPv6 routes, IPv6 addresses, resolver state and forwarding. No doctor network mutations.
- **ROOT NAMESPACE: SKIPPED** — actual host UID 1000; TUN, ip and nft present. The root marker reported SKIP; privileged IPv6 enforcement remains unexecuted. **Docker/systemd/real systemd-resolved: NOT VALIDATED. Real VPS: NOT PERFORMED.**
- Upstream security policy/releases/advisories checked 2026-09-07: liboqs 0.16.0 remains supported/current; no published advisory requiring an upgrade was found. Sources and scope are recorded in the [pre-VPS report](docs/security_audit.md#pre-vps-hardening--2026-09-07). Python artifact hash locking was not added; existing version constraints retained.
- Release hygiene: no tracked private-key/authorized-client DB/.env paths; environment/cache/private-profile ignores verified. Prepare the local `Pre-VPS PQVPN v2 validation baseline` commit and annotated `v2-pre-vps` tag only after successful validation; no push. The tag resolves the exact validated commit without a self-referential hash in this file. All native build/identity/test outputs stay under /tmp.
- Documentation now defines full tunnel as supported IPv4 routing plus default IPv6 blocking, explicitly describes snapshot fail/unsafe allow modes and revocation boundaries, and retains Docker development-only, native systemd and real-client DNS gates. Status: **Deployable research/prototype PQ-VPN. IPv6 leak protection validated at unit level. Root/TUN integration pending. Real VPS/client validation pending.** Next milestone: **REAL VPS + SEPARATE REAL LINUX CLIENT**, following the privileged disposable-machine gates. No protocol redesign or optional feature expansion.

### 2026-09-07 10:17 IST — Push all pending changes to GitHub

- Staged all 72 changed files (31 modified, 40 new) and committed as `c50dee0` on `main`.
- Commit: `feat: add deployment configs, security hardening, management API, comprehensive tests, and documentation`.
- Pushed `8e6f125..c50dee0 main -> main` to `origin` (`https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git`).
- 5,157 insertions, 6,989 deletions across deployment configs, VPN modules (config, doctor, firewall, identity, runtime), documentation (protocol, threat model, security audit, setup guides), comprehensive test suite, and updated benchmarks/crypto/handshake/engine.

### 2026-09-07 — Final handoff validation and documentation consistency

- Inspected the existing dirty working tree, diffs, current implementation, tests and deployment documents before edits. Preserved all previous work and the v2 1,318 / 1,222 / 1,190 / 38-byte handshake, key schedule, separate DATA/CONTROL domains and synchronized rekey.
- Initial handoff reruns in a fresh `/tmp/pqvpn-final-venv`: `pytest -q` **206 passed, 2 skipped in 36.32s**; `python -m pytest -q` **206 passed, 2 skipped in 36.40s**. System Python originally lacked pytest; installed the unchanged pinned `pyproject.toml dev extras` baseline outside the repository. All constrained versions match and `pip check` passes. Network/socket tests require execution outside the sandbox as UID 1000; a restricted ASGI-only run stalled and was terminated.
- Fixed one verified configuration defect in `vpn/config.py`: omitted identity/database path fields now use standard filenames beside the TOML instead of resolving from the process CWD. Added its regression in `tests/test_networking.py`. Added actual ASGI HTTP ticket-authentication and random-ticket rejection coverage in `tests/test_management.py`; existing atomic single-use ticket implementation preserved.
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
- `tests/test_runtime.py`: live loopback quiet keepalive and real idle expiry/cleanup regressions, plus authenticated-record rejection cases (replay/session/endpoint/epoch/tag/domain/payload/source).
- `.gitignore`: explicit environment and coverage exclusions. Removed the untracked bundled `.venv/` from the source folder; no dependency or lock files removed. Validation environment lives outside the repository.
- `deploy/pqvpn-server.service`: recreate runtime directory on boot. README and deployment/client guides specify freshly created environments; native installation excludes environments/caches and consistently uses `/opt/pqvpn/.venv` and `/etc/pqvpn/server.toml`, with no EnvironmentFile.
- README, protocol, security audit, deployment, client setup, and threat model document authenticated liveness, rejection rules and genuine expiry cleanup. Status remains **deployable research/prototype PQ-VPN**; privileged networking and real VPS/client validation are the next milestone.
- `tests/namespace_vpn.sh`: additionally runs quiet keepalive and genuine idle cleanup tests with real TUN in the isolated namespace; compares routes before/after. Namespace DNS mutation is disabled; unprivileged idle cleanup verifies route/DNS undo commands with mocked OS calls.
- Validation in fresh `/tmp/pqvpn-edit3-venv` (Python 3.14.7; freshly installed test dependencies, not the old bundled environment): `python -m pytest -q`: **139 passed, 2 skipped in 16.65s**; `pytest -q`: **139 passed, 2 skipped in 16.53s**. Native ML-KEM-768 separately: **1 passed, 140 deselected**. Root namespace: **1 skipped, 140 deselected** (UID 1000; `/dev/net/tun` absent). Compileall, all three shell syntax checks, JS syntax, Compose config and diff whitespace check passed. Local socket tests require execution outside the socket-restricting sandbox.
- Limitations: fresh installation used Python-3.14-compatible test dependencies (cryptography 50.0.1, pytest 9.1.1, FastAPI 0.141.1); installation of the older exact `pyproject.toml` pins was not validated on this host. Native systemd activation, privileged namespace networking/DNS and real VPS/client end-to-end validation remain pending. No production-readiness claim.


### 2026-09-06 — Edit-2 runtime and deployment repairs

Preserved v2 handshake algorithms, wire format, and existing security tests.
Client SIGTERM wakes an event-driven main loop and performs cleanup before exit.
Namespace shutdown waits fail after ten seconds rather than hanging. One resolved
IPv4 address serves TCP, the bypass route, and UDP. A dedicated authenticated
control reader detects EOF/CLOSE/ERROR/protocol failure and server expiry, exposes
FAILED through management status, and tears down networking. A separate scheduler
keeps data forwarding active during rekey waits. Teardown serializes with all
record/epoch locks, and closed records fail explicitly.

Compose identity mounts now match TOML-relative paths; client.toml with an explicit Docker host override sets
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
- **[REPLACED] `vpn/cli.py`, `vpn/network.py`, `vpn/__init__.py`** — provisioning/admin commands and fail-closed Linux runtime; removed legacy unsafe service/server and misleading OpenVPN compatibility surface.
- **[REPLACED] `app/backend/api.py`** and **[MODIFIED] frontend** — bearer-protected management actions/telemetry, token-protected WebSocket, explicit CORS origins, local/custom profiles only, and browser token handling.
- **[NEW] `scripts/server-network.sh setup`, `scripts/server-network.sh cleanup`, `deploy/pqvpn-server.service`** — isolated nftables forwarding/NAT/MSS rules, safe cleanup, outbound-interface detection, and a capability-limited native systemd example.
- **[MODIFIED] Docker artifacts** — removed public management publication, corrected v2 CLI entrypoints, documented secret/config mounts, and made the bundled client an explicit development profile.
- Docker Compose schema validation passed with `docker compose config`.
- **[NEW/REPLACED] tests and pytest configuration** — security/authentication/directional-key/nonce/replay/rekey/IP-pool/MTU/API tests plus separate mock/native/integration markers. Validation: 55 unit/mock-capable tests passed (one native-precedence skip); native ML-KEM marker passed 1/1; privileged integration marker remains unexecuted in this restricted workspace.
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

**[MODIFIED] `app/frontend/index.html`**:
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

**[MODIFIED] `Dockerfile`** — Fixed entrypoint: `python3 -m vpn.server --dashboard`; added cmake/ninja/libssl-dev for liboqs build; exposed 8000/51820.

**[MODIFIED] `Dockerfile`** — Fixed entrypoint: env-variable-driven `python3 -m vpn.client --server ${SERVER_HOST}`.

**[MODIFIED] `docker-compose.yml`** — Added vpn-net bridge network; `NET_ADMIN` + `/dev/net/tun` for both containers; `SERVER_HOST`/`SERVER_PORT`/`VPN_IP` env wired.

**[MODIFIED] `pyproject.toml`** — Pinned all versions; added `liboqs-python>=0.10.0` with build note; added `pytest-asyncio`.

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
  - Merged `docs/deployment_guide.md` setup and container workflows into `docs/design.md`.
  - Deleted redundant `phase.md` and `docs/deployment_guide.md`.
- **Component 2 (Benchmarks)**:
  - Consolidated `handshake_bench.py`, `throughput_bench.py`, `packet_capture.py`, and `generate_charts.py` into a single high-performance `benchmarks.py`.
  - Updated the benchmark public API and `tests/test_deployment.py` around the unified runner.
  - Removed old fragmented benchmark scripts; results generated dynamically.
- **Component 3 (Application Backend)**:
  - Inlined `ConnectionManager`, rolling history buffers, `_build_telemetry_frame`, and `/ws/telemetry` endpoint directly into `app/backend/api.py`.
  - Updated `app/backend/__init__.py` and deleted `app/backend/websocket.py`.
- **Component 4 (VPN Engine & CLI)**:
  - Integrated `VPNService`, `ServiceState`, `VPNTelemetry`, and KEMTLS transport helpers from `vpn/service.py` directly into `vpn/network.py`.
  - Created unified CLI `vpn/cli.py` with `server` and `client` subcommands (`python -m vpn.cli server|client`).
  - Updated `Dockerfile`, `Dockerfile`, `app/backend/api.py`, and `vpn/__init__.py`.
  - Deleted separate `vpn/service.py`, `vpn/server.py`, and `vpn/client.py`.
- **Remote Synchronization**:
  - Pushed consolidated commit `a88e911` to GitHub remote (`https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git`) on branch `main`.

---

## 🚦 Current Status & Next Steps

| Task / Module | Status | Description |
| :--- | :---: | :--- |
| **Milestone 4.1 (Account/Device Store)** | ✅ Completed | SQLite AccountStore/DeviceStore with WAL mode, Argon2id hashing, strict RBAC, device management, session tokens; cleanly separated from VPN core (385 passed / 2 skipped) |
| **Milestone 4.2 (Register/Login HTTPS API)** | ✅ Completed | Standalone HTTPS API with register/login/me/logout, hashed session tokens, TLS enforcement, bounded rate limiting, and AccountStore integration (429 passed / 2 skipped baseline) |
| **Milestone 4.3 (Desktop Auth UX)** | ✅ Completed | PySide6 Login/Register/Logout UI, memory-only session, standard-library HTTPS account client in `app/client.py`, sanitized errors (472 passed / 2 skipped) |
| **Milestone 4.4 (Account-Device Binding)** | ✅ Completed | Authenticated `/devices` API and desktop "This Device" binding of the managed public Ed25519 identity; private keys remain local; no `AuthorizedClients` change |
| **Milestone 4.5 (Admin Enrollment Approval)** | ✅ Completed | Schema v2 device review status with v1 migration; root-only `vpn.cli account` approve/reject/revoke is the sole path into `AuthorizedClients` |
| **Milestone 4.6 (Account-Aware Desktop UX)** | ✅ Completed | Home "Account & Device" card driven by `account_ux_state()` across account, device review, and VPN states; never gates Connect |
| **Milestone 4.7 (E2E Multi-Node Validation)** | ⏳ Next | Full live system validation on Omarchy desktop ↔ Ubuntu server VM (KEMTLS v2, TUN, routes, DNS, rekeying, disconnect/logout) |
| **Desktop Client Milestone 3** | ✅ Completed | Managed identity/onboarding plus live GUI enrollment, connect, disconnect, identity persistence, rekey, cleanup, and native PQC validation passed against Ubuntu 26.04 |
| **Arch / Omarchy Packaging** | ✅ Completed | Pinned checksum-verified liboqs/Python packages, deterministic app archive, and Python `-s` isolation in both client units; manual Pacman install chain pending |
| **Debian / Ubuntu Packaging** | ✅ Completed | Exact pinned liboqs 0.16.0 native/Python packages and main app built, inspected, and clean-installed on Ubuntu 26.04 with native backend and GUI imports verified |
| **Milestone 3 Release Gate** | ✅ Completed | Full pytest 343 passed / 2 skipped; native no-mock 2 passed; compile/syntax, package patch/archive, dependency, whitespace, and clean-tree gates pass |
| **Systemd Ownership Boundary** | ✅ Completed | Root-owned deployment model; production doctor plus 15 regressions; both pytest styles 258 passed / 2 skipped; native 2 passed; runtime gates pending |
| **Pre-VPS Hardening Validation** | ✅ Completed | Source review complete; 245 collected; both entrypoints 243 passed / 2 skipped; native 2 passed at pinned source; provisioned doctors/static checks PASS (external firewall WARN) |
| **IPv6 Leak Prevention** | ✅ Completed | Unit/static policy and cleanup validated; real kernel namespace enforcement pending |
| **Minimal Layout Refactor** | ✅ Completed | 73 to 43 meaningful files; 261 tests retained/added; fresh install and full validation pass; protocol unchanged |
| **Local Release Baseline** | ✅ Completed | Structural baseline v2-minimal-layout; v2-pre-vps and v2-pre-vps-2 retained; exact hash and clean-tree verification in final report; no push |
| **Dependency / Deployment Hardening** | ✅ Completed | Pinned role dependencies; explicit native install; scoped firewall, forwarding restoration, UDP dead-peer/DNS safety, strict identities/database and telemetry tickets |
| **Edit-3 Idle Activity / Packaging** | ✅ Completed | Authenticated keepalive refresh; invalid activity rejected; fresh-environment deployment |
| **Directory Scaffolding** | ✅ Completed | Created complete directory tree and skeleton files |
| **Agent Memory Mandate** | ✅ Completed | Configured automatic progress logging instructions |
| **GitHub Integration** | ✅ Completed | Configured Git repo & remote `https://github.com/gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git` |
| **Hybrid Cryptography (`crypto/`)** | ✅ Completed | X25519 + standardized ML-KEM-768 hybrid inputs and HKDF-SHA256 |
| **KEMTLS-inspired Handshake (`handshake/`)** | ✅ Completed | Custom pinned-server/authorized-client protocol, transcript binding, channel-separated AES-256-GCM records |
| **VPN Engine (`vpn/network.py`)** | ✅ Completed | TUN and measured quality primitives; routed client/server in vpn/runtime.py |
| **Unified VPN CLI (`vpn/cli.py`)** | ✅ Completed | Unified server and client entry points with subcommands (`vpn.cli server`, `vpn.cli client`) |
| **Application UI (`app/`)** | ✅ Completed | Milestone 3 six-page PySide6 GUI; first-run setup, real profiles, offline enrollment, live state/metrics, read-only settings, bounded logs; privileged service retained |
| **Omarchy Desktop & Dev Modules** | ✅ Completed | PySide6 6.11.2, liboqs-python 0.16.0, scapy 2.7.0, psutil 7.2.2, matplotlib 3.11.1, pandas 3.0.5, paramiko 5.0.0 |
| **Ubuntu VM Server Deployment** | ✅ Completed | Pinned ML-KEM-768 server keys, client authorization, firewall/forwarding setup, listening on 192.168.8.43:51820 |
| **Benchmarks (`benchmarks.py`)** | ✅ Completed | Consolidated handshake, throughput, packet capture, and chart generation |
| **PQC Fail-Closed Enforcement** | ✅ Completed | `PQCUnavailableError` + `ALLOW_MOCK_PQC` env + `_MockInsecurePQCProvider` w/ security warnings |
| **In-Session Rekeying** | ✅ Completed | Dedicated control reader/rekey scheduler; existing epoch and record security preserved |
| **UI Transparency Badges** | ✅ Completed | Configured-profile UI; measured telemetry; classical client-auth boundary |
| **Docker Configuration** | ✅ Completed | Development/integration convenience; schema PASS, runtime routing NOT VALIDATED |
| **Unified Documentation** | ✅ Completed | Consolidated architecture & deployment guide in `docs/design.md`, merged roadmap |
| **Automated Test Validation** | ✅ Completed | 343 passed / 2 skipped; native PQC 2 passed / 343 deselected; deterministic Arch packaging regressions added |
| **Install Native liboqs** | ✅ Completed | Current environment exposes native ML-KEM-768 and passes the isolated self-test/integration marker |
| **2026 Security Remediation** | ✅ Completed | Code fixes implemented, privilege boundaries enforced via SO_PEERCRED, end-to-end VM/host validation verified |
| **Authenticated v2 Handshake/Records** | ✅ Completed | Pinned server identity, authorized clients, directional AEAD, replay/AAD/epoch controls |
| **Linux Routed Runtime** | ✅ Completed | Single TUN/UDP demux, IP pool, UDP bind, routes/DNS/NAT validated live end-to-end |
| **Management Security** | ✅ Completed | Loopback HTTP bearer, explicit CORS, bounded 30-second single-use telemetry tickets |
| **Native ML-KEM Validation** | ✅ Completed | Current environment: `2 passed` under `-m native_pqc`; liboqs/binding 0.16.0 |
| **Real VM / Host Deployment** | ✅ Completed | Live end-to-end connection between Omarchy host and Ubuntu VM server verified with clean teardown |

---

## 🚦 Historical Project Phase Roadmap Matrix

This retained matrix records earlier project claims and test counts. It is not the current validation report; the table above and the latest modification entry are authoritative.

| Phase | Phase Name | Status | Key Deliverables | Test Coverage |
| :---: | :--- | :---: | :--- | :---: |
| **Phase 0** | **Project Setup & Architecture** | ✅ **Completed** | Scaffolding, Docker environment, requirements, documentation | — |
| **Phase 1** | **Hybrid Cryptography Engine** | ✅ **Completed** | `crypto/hybrid_crypto.py` (X25519 + Kyber768 + HKDF-SHA256 + Session Store) | 37 / 37 Passed |
| **Phase 2** | **Signature-Free KEMTLS Handshake** | ✅ **Completed** | `handshake/kemtls.py` (Wire protocol, Transcript Hasher, AES-256-GCM session, Client/Server state machines) | 43 / 43 Passed |
| **Phase 3** | **VPN Engine & Network Agility** | ✅ **Completed** | `vpn/network.py` (TUN Interface, Tunnel Daemon, MTU Monitor, Network Quality, OpenVPN Manager, VPNService) | 71 / 71 Passed |
| **Phase 4** | **Application GUI & Controller API** | ✅ **Completed** | `app/main.py` (Desktop launcher), `app/backend/api.py` (FastAPI REST + WS Telemetry), `app/frontend/` (Dashboard UI) | API verified |
| **Phase 5** | **Benchmarking & Final Validation** | ✅ **Completed** | `benchmarks.py` (Handshake timing, throughput, packet capture, chart generator) | 10 / 10 Passed |
| **Phase 6** | **Codebase Simplification** | ✅ **Completed** | Streamlined file reduction (~44 → 18 files) with 100% backward compatibility & tests passing | 161 / 161 Passed |
