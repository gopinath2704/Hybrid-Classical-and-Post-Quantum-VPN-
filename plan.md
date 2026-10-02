# PQ-VPN Research Build Plan

**Goal:** Turn PQ-VPN from a deployable research prototype into a system with a clear, defensible research contribution. **Build and validate the project first; the paper is written afterwards (see the end).**

**Target contribution:** A *signature-free, fully post-quantum, mutually authenticated hybrid VPN with post-compromise recovery*. It has a machine-checked security model and is evaluated against existing VPNs.

---

## 0. Where we start (v2 baseline)

| Area | Current state (from repo) | Gap for publication |
|---|---|---|
| Server auth | Static ML-KEM-768, pinned SHA-256 fingerprint | ✅ already KEM-based |
| Session keys | X25519 + ephemeral ML-KEM-768, HKDF-SHA256 | ✅ hybrid |
| Client auth | Ed25519 signature | ❌ classical → not fully PQ |
| Rekey | Hash-based epoch evolution | ❌ no post-compromise security |
| Security argument | Written threat model only | ❌ no formal proof |
| DoS | Source rate limiting | ❌ ML-KEM work done before any cookie check |
| Evaluation | Own handshake/throughput benchmarks | ❌ no baselines, no network emulation |
| Data plane | Python TUN/UDP loop | ⚠ slow vs kernel/C VPNs |
| Handshake size | 1,318 + 1,222 + 1,190 + 38 = **3,768 B** | — |

### Ground rules for every phase

1. **v2 keeps working.** New work ships as protocol **v3** with its own version byte; v2 tests must still pass.
2. **No mock PQC in any measured result.** Fail-closed native liboqs only.
3. **Every phase ends with:** passing tests, an updated `docs/design.md`, a `progress.md` entry, and a git tag.
4. **Record every design decision** in `docs/decisions/` (one short file per decision: context → options → choice → why).

---

## Phase overview

```
Phase 0  Baseline freeze + measurement harness        ─┐
Phase 1  v3 protocol: KEM-based client authentication  │  core protocol
Phase 2  Formal model (Tamarin)  ◄── start in parallel ┤
Phase 3  Post-compromise security: hybrid re-handshake │
Phase 4  DoS resistance: stateless cookie             ─┘
Phase 5  Comparison suites (ML-DSA-44, Ed25519 legacy)  ─┐
Phase 6  Data-plane decision (scope or rewrite)          │  evaluation
Phase 7  Evaluation campaign vs. baselines               │
Phase 8  Reproducibility artifact                       ─┘
Phase 9  Paper (later)
Phase 10 Codebase reduction (zero feature loss)         ── independent
```

Dependencies: 1 → 3 → 4 → 5 → 7 → 8. Phase 2 starts alongside Phase 1 and is updated after Phases 3 and 4. Phase 6 must be decided before Phase 7. Phase 10 is independent and can be executed at any time.

---

## Phase 0: Baseline freeze and measurement harness

**Why:** Every later claim ("v3 costs X more bytes", "the cookie stops a flood") needs a fixed v2 reference measured the same way.

**Tasks**
- [x] Tag current `main` as `v2-research-baseline`.
- [x] Extend `benchmarks.py` so that every result row records:
  - suite name, protocol version, git commit, liboqs version, CPU model, and iteration count;
  - median, p95, p99 and standard deviation, not just the mean;
  - client and server CPU time separately.
- [x] Output raw CSV/JSON to `results/<date>-<commit>/` (charts are generated from the raw data, never hand-edited).
- [x] Add a namespace-based real-network harness: `tests/namespace_vpn.sh` + `tc netem` profiles:
  - RTT: 0 / 50 / 200 ms
  - Loss: 0 / 1 / 5 %
  - MTU: 1280 / 1400 / 1500
- [x] Measure and store the v2 baseline under all profiles.

**Done when:** `python -m benchmarks --all --profile <name>` reproduces v2 numbers in under 5% variance across two runs.

---

## Phase 1: Protocol v3 with KEM-based client authentication (core contribution)

**Why:** Replaces classical Ed25519 client authentication with ML-KEM. The system then becomes **fully post-quantum mutually authenticated without any signatures**.

### 1.1 Design (write before coding)

Both long-term public keys are known in advance:
- the client pins the server key from `.pqvpn`;
- the server stores the client key from `.pqenroll`.

That means each side can authenticate the other by *encapsulating* to the peer's static key. Only the true key owner can decapsulate and compute the Finished MAC.

**Decision D1 to make first:** where does the client's encapsulation to the server key go?

| Option | Flow | Pros | Cons |
|---|---|---|---|
| **A: Keep current shape** | `ct_S` stays in ClientKeyExchange; server adds `ct_C` to ServerHello | Minimal change from v2 | Client identity sent in clear; 1.5 RTT |
| **B: PDK-style (recommended to evaluate)** | `ct_S` moves into ClientHello. The client identity is encrypted under a key derived from `K_S`. | Client identity hidden from passive observers; server key confirmation one flight earlier | ClientHello grows; needs replay handling of ClientHello; more modelling work |

Sketch of **Option A**:

```
Client                                              Server
ClientHello:  r_c, sid, X25519_eph_pk, MLKEM_eph_pk, H(client_static_pk)
                                    ───────────────►
                        ServerHello: r_s, sid, X25519_eph_pk,
                                     ct_eph  (to client ephemeral key),
                                     H(server_static_pk),
                                     ct_C    (to client STATIC ML-KEM key)   ← new
                                    ◄───────────────
ClientKeyExchange: ct_S (to server STATIC key), Client Finished
   (Finished key depends on K_C ⇒ proves client owns its static key)
                                    ───────────────►
                        ServerFinished (key depends on K_S ⇒ proves server)
                                    ◄───────────────
```

**Key schedule (draft):**
- `ES = HKDF(X25519_ss ‖ K_eph)` gives the handshake secret.
- `AS = HKDF(ES, K_S ‖ K_C ‖ transcript)` gives the authenticated master secret.
- From the master secret, derive the Finished keys, data/control keys, the rekey secret and the confirmation key. Keep v2's labels and channel separation.

**Expected wire size (estimate, Option A):**

| Message | v2 | v3 (estimate) |
|---|---|---|
| ClientHello | 1,318 | ~1,318 (Ed25519 pk swapped for 32 B identity hash) |
| ServerHello | 1,222 | ~2,310 (+1,088 B `ct_C`) |
| ClientKeyExchange | 1,190 | ~1,126 (−64 B Ed25519 signature) |
| ServerFinished | 38 | 38 |
| **Total** | **3,768** | **~4,800** |

Measure the real numbers; the estimates are not results.

### 1.2 Implementation

| Component | File(s) | Change |
|---|---|---|
| Client static ML-KEM key generation | `vpn/identity.py` | Generate and store an ML-KEM-768 keypair in managed mode (`/var/lib/pqvpn/identity`, mode 0600/0644) |
| Enrollment format | `vpn/enrollment.py` | `.pqenroll` **version 2**: canonical Base64 of the 1,184 B ML-KEM public key plus its SHA-256 fingerprint. Version 1 stays readable. |
| Authorized-clients store | `vpn/identity.py` | Store the client ML-KEM public key; lookup by fingerprint; keep the locked, atomic write |
| Handshake messages | `handshake/kemtls.py` | New v3 message classes, strict length parsing, version byte |
| Key schedule | `crypto/hybrid_crypto.py` | v3 HKDF labels; mix `K_C` into the authenticated secret |
| State machines | `handshake/kemtls.py` | Client decapsulates `ct_C`; server verifies the client Finished with a `K_C`-dependent key |
| Config | `vpn/config.py`, `config/*.toml` | `protocol_version = 3` |
| GUI / service | `app/client.py` | Show "Client auth: ML-KEM-768 (post-quantum)"; export the v2 enroll file |
| CLI | `vpn/cli.py` | `client-key generate --kem`, `client authorize` accepts the v2 enroll file |

### 1.3 Tests
- [x] Round-trip v3 handshake (native liboqs).
- [x] Negative tests:
  - wrong client static key, so the client Finished fails;
  - wrong server key, so the server Finished fails;
  - swapped `ct_C` or `ct_S`;
  - truncated or extended messages;
  - wrong version.
- [x] Unknown, revoked, or disabled client is rejected before key derivation completes.
- [x] v2 and v3 suites both pass; there is no silent downgrade from v3 to v2.
- [ ] Live namespace end-to-end test on v3. *(requires root; deferred to VM validation)*

**Done when:** v3 connects end-to-end on the Ubuntu VM, all negative tests fail closed, and the docs state **"fully post-quantum mutual authentication (custom protocol, not formally verified until Phase 2)"**.

---

## Phase 2: Formal model in Tamarin (start in parallel with Phase 1)

**Why:** A custom protocol without a proof is the most common rejection reason. Modelling early often finds design bugs before they are coded.

**Tasks**
- [x] Install Tamarin Prover; create the `formal/` folder.
- [x] `formal/pqvpn_v3.spthy`: model ClientHello → ServerFinished.
  - Model KEMs as `encaps`/`decaps` with reveal rules.
  - Model X25519 and ML-KEM as **independently breakable** (a separate "break" rule for each).
- [x] Prove these lemmas:

| Lemma | Property |
|---|---|
| `session_key_secrecy` | Session keys stay secret unless both static keys are compromised before the session |
| `client_auth` / `server_auth` | Injective agreement on transcript and keys |
| `forward_secrecy` | Later compromise of static keys does not reveal past session keys |
| `kci_resistance` | Compromising the client's key does not let an attacker impersonate the server to that client, and vice versa |
| `hybrid_security` | Keys stay secret if **either** X25519 **or** ML-KEM is unbroken |
| `pcs_recovery` | *(added in Phase 3)* Secrecy is restored after a clean re-handshake |
| `cookie_no_state` | *(optional, Phase 4)* Server keeps no state before a valid cookie |

- [x] `formal/README.md`: how to run, the expected output, the model's assumptions and abstractions, and what is **not** modelled (timing, implementation bugs).
- [x] A CI job (or script) that re-runs all lemmas.

**Done when:** all lemmas verify automatically and the README states the assumptions honestly.

---

## Phase 3: Post-compromise security with a hybrid re-handshake

**Why:** v2's hash-based rekey cannot recover after a state compromise (stated in `docs/design.md`). Fresh ephemeral key material restores secrecy.

**Design**
- A new CONTROL frame pair: `REHANDSHAKE_REQUEST` / `REHANDSHAKE_RESPONSE`, carried over the existing encrypted control channel.
- Each side contributes a fresh X25519 key and a fresh ML-KEM encapsulation.
- The new secret is computed as `HKDF(old_rekey_secret ‖ new_X25519_ss ‖ new_K_mlkem ‖ epoch)`.
- Trigger: every N minutes **or** N GB, whichever comes first. Both values are configurable; defaults are chosen in Phase 7.
- Reuse v2's confirmed-epoch switch logic so there is no packet-loss window.

**Tasks**
- [x] Frames and state machine in `vpn/runtime.py` and `handshake/kemtls.py`.
- [x] Scheduler hooks next to the existing rekey scheduler.
- [x] Tests:
  - the re-handshake under traffic;
  - concurrent rekey and re-handshake;
  - replayed or old-epoch re-handshake frames are rejected;
  - a simulated "state leak" test: give the attacker the old keys and check that it cannot derive the new epoch keys.
- [x] Add the `pcs_recovery` lemma to the Tamarin model.
- [ ] Measure cost: CPU, bytes, and any throughput dip during the switch. *(deferred to Phase 7 evaluation)*

**Done when:** a long-lived session survives repeated re-handshakes under iperf load with no drops, and the lemma verifies.

---

## Phase 4: DoS resistance with a stateless cookie

**Why:** ML-KEM decapsulation and keygen on unauthenticated input lets an attacker burn server CPU.

**Design (like the WireGuard/DTLS pattern)**
- Under load, or always, the server answers the first ClientHello with `COOKIE_CHALLENGE`.
  - The cookie is `MAC(server_cookie_secret_rotating, client_ip ‖ port ‖ time_bucket)`.
- The client resends ClientHello with the cookie.
- The server does **no ML-KEM work and keeps no state** until the cookie is valid.
- The cookie secret rotates every few minutes.

**Tasks**
- [x] Cookie generation and verification in the server accept path (`handshake/kemtls.py`, `vpn/runtime.py`).
- [x] A `cookie_mode` config option: `off` / `under_load` / `always`.
- [x] Load-detection threshold (pending handshakes counter).
- [ ] Flood test tool: a spoofed-source ClientHello generator inside a namespace. *(deferred to Phase 7 evaluation)*
- [ ] Measure server handshakes/sec and CPU **with vs. without** cookies under flood. *(deferred to Phase 7 evaluation)*

**Done when:** under a flood, legitimate clients still connect, and the server CPU stays bounded (show this with a graph).

---

## Phase 5: Comparison suites

**Why:** The paper's central claim is that a signature-free design is smaller and faster. That needs a fair, same-codebase comparison.

| Suite ID | Server auth | Client auth | Purpose |
|---|---|---|---|
| `v2-ed25519` | ML-KEM static | Ed25519 | Existing baseline (classical client auth) |
| `v3-kem` | ML-KEM static | ML-KEM static | **Proposed design** |
| `v3-mldsa` | ML-KEM static | ML-DSA-44 signature | Fully PQ, signature-based alternative |
| `v3-mldsa-both` *(optional)* | ML-DSA-44 | ML-DSA-44 | "Classic" PQ-TLS-style signed handshake |

**Tasks**
- [x] Implement `v3-mldsa` using liboqs ML-DSA-44. Pin the client signature key at the server, so the public key is not sent.
- [x] Make suites **selectable for experiments only** (`--suite` in benchmarks, `experimental_suite` in config). Production defaults to `v3-kem`.
- [x] Same tests as Phase 1 for each suite.

**Done when:** all suites handshake successfully under the same harness, and the bytes and CPU table is generated automatically.

---

## Phase 6: Data-plane decision

**Why:** The Python packet loop will lose to WireGuard (kernel) and OpenVPN (C) on throughput. Reviewers will notice, so decide this explicitly.

| Option | Effort | Paper framing |
|---|---|---|
| **A: Scope it** (fastest) | Low | The contribution is the *handshake and control plane*. Throughput is reported only as a functional check, with the limitation stated openly. |
| **B: Native data plane** | High | Move TUN ↔ UDP AES-GCM framing to Rust (PyO3) or C. Keep the handshake in Python and keep the wire format identical. |

**Tasks**
- [x] Profile the current data plane (cProfile) and record where the time goes.
- [x] Write decision record `docs/decisions/D6-data-plane.md`.
- [x] Decision: Option A (scope it). Native data plane not needed for research contribution.

**Done when:** the decision is recorded, and (if B) throughput is within an explainable distance of the baselines.

---

## Phase 7: Evaluation campaign

**Why:** IEEE reviewers expect comparisons under realistic conditions.

**Baselines to install in identical namespaces/VMs**
- WireGuard (classical)
- WireGuard + Rosenpass (fully PQ, Classic McEliece + Kyber)
- strongSwan IKEv2 with ML-KEM (RFC 9370 additional key exchange)
- OpenVPN (classical; plus a PQ-enabled build if available)

**Matrix**
- **Systems:** our four suites + the baselines.
- **Networks:** the Phase 0 `netem` profiles (RTT × loss × MTU).
- **Hardware:** x86 laptop/VM + one constrained device (Raspberry Pi 4/5).
- **Repetitions:** at least 30 per cell; report median and 95% CI.

**Metrics**

| Metric | Tool |
|---|---|
| Handshake latency (time to first data byte) | Our harness / timestamps |
| Bytes on the wire per handshake, and packet/fragment count | tcpdump + scapy |
| Server and client CPU per handshake | perf / psutil |
| Max handshakes/sec (server) | Flood tool |
| Throughput and latency through the tunnel | iperf3, ping |
| Re-handshake cost (Phase 3) | Harness |
| Cookie effectiveness under flood (Phase 4) | Flood tool |
| Memory footprint | psutil |
| *(optional)* Energy on Pi | USB power meter |

**Tasks**
- [x] One script per system to bring up, measure, and tear down: `eval/run_pqvpn.py`, `eval/run_wireguard.sh`, `eval/run_openvpn.sh`, `eval/run_rosenpass.sh`, `eval/run_strongswan.sh`.
- [x] One orchestrator: `eval/run_all.py` → `results/eval-<date>/raw/*.csv`.
- [x] One chart/table generator from raw data → `results/eval-<date>/figures/` (text tables + matplotlib PNGs).
- [x] A sanity log for every run: `sanity.json` with versions, kernel, CPU governor, tool availability.

**Done when:** the full matrix runs unattended from one command, and the repeated runs agree.

---

## Phase 8: Reproducibility artifact

**Tasks**
- [x] `ARTIFACT.md`: hardware and OS requirements, one-command setup (Docker + native), expected runtime, expected outputs, and troubleshooting.
- [x] `Dockerfile.artifact`: builds pinned liboqs 0.16.0, installs `.[dev]` deps, runs tests + evaluation + figure generation.
- [x] `reproduce.sh`: top-level script that runs tests, evaluation campaign, and regenerates all figures/tables from raw data.
- [x] The Tamarin model runs with one command: `./scripts/verify_formal.sh`.
- [ ] Freeze a release tag (`v3-paper-artifact`) and archive it with a DOI (Zenodo).

**Done when:** a fresh machine following `ARTIFACT.md` reproduces the main figures.

---

## Phase 9: Paper (later, after Phases 0–8)

Outline to fill once the results exist:
1. Introduction and contributions
2. Background: ML-KEM, hybrid key exchange, KEMTLS / KEMTLS-PDK
3. Threat model
4. Protocol design (v3, re-handshake, cookie)
5. Formal analysis (Tamarin)
6. Implementation
7. Evaluation
8. Related work:
   - KEMTLS (CCS 2020) and KEMTLS-PDK (ESORICS 2021)
   - Post-Quantum WireGuard (IEEE S&P 2021) and Rosenpass
   - RFC 9370 / IKEv2, and FIPS 203
9. Limitations
10. Conclusion

**Venues to consider:** IEEE Access (first realistic target); IEEE CNS, IEEE TrustCom, and the ICC/GLOBECOM security tracks.

---

## Phase 10: File and codebase reduction (zero feature loss)

**Why:** The repository has **212 files** across heavily nested directories with significant structural waste: 3× duplicated source trees in packaging build artifacts, single-file packages that don't need to be packages, small modules that share a single concern, and duplicated systemd units. Additionally, the ~11,400 lines of source code contain verbose docstrings, copy-pasted protocol variant helpers, and repeated GUI boilerplate. Reducing **both** file count and line count improves maintainability without removing any feature, wire format, or public API.

---

### Part A — File reduction (212 → ~88 files)

#### Current file census

| Category | Files | Action |
|----------|------:|--------|
| Source code (app/, crypto/, handshake/, vpn/) | 18 | Merge to **10** |
| benchmarks.py | 1 | Keep |
| Tests (tests/) | 10 | Keep (never reduce tests) |
| Eval scripts (eval/) | 6 | Keep |
| Scripts (scripts/) | 4 | Keep |
| Config examples (config/) | 5 | Keep |
| Docs (docs/) | 7 | Keep |
| Formal model (formal/) | 2 | Keep |
| Packaging — common | 5 | Deduplicate service files with deploy/ → **3** |
| Packaging — arch PKGBUILD + patch | 3 | Keep |
| Packaging — deb | 13 | Keep |
| **Packaging — arch build artifacts** (src/ + pkg/) | **115** | **Delete all** (gitignore) |
| **Packaging — binary blobs** (.pkg.tar.zst, .tar.gz) | **4** | **Delete all** (gitignore) |
| Deploy (systemd + versions.txt) | 3 | Merge into packaging/common → **0** |
| Root files (pyproject.toml, README, etc.) | 10 | Keep |
| Results (output data) | 23 | gitignore (generated, not source) |
| .pytest_cache | 5 | gitignore |
| **Total** | **212** | **→ ~88** |

#### A1. Delete packaging build artifacts — eliminate **119 files**, save **~24 MB**

These are `makepkg` outputs that should never be in source control:

| Path | Files | Why delete |
|------|------:|-----------|
| `packaging/arch/src/pqvpn-2.0.0/` (incl. `build/lib/`) | 48 | Full source copy + second copy in `build/lib/`; regenerated by `makepkg` |
| `packaging/arch/pkg/pqvpn/` | 67 | Install tree; regenerated by `makepkg` |
| `packaging/arch/pqvpn-2.0.0-1-x86_64.pkg.tar.zst` | 1 | Binary package |
| `packaging/arch/pqvpn-2.0.0.tar.gz` | 1 | Source tarball |
| `packaging/arch/liboqs-pqvpn/*.tar.gz`, `*.pkg.tar.zst` | 2 | Binary + source blobs |
| `packaging/arch/python-liboqs-pqvpn/*.tar.gz`, `*.pkg.tar.zst` | 2 | Binary + source blobs |

**Action:** `rm -rf packaging/arch/src packaging/arch/pkg` + delete blobs. Add to `.gitignore`:
```
packaging/arch/src/
packaging/arch/pkg/
packaging/arch/*.pkg.tar.zst
packaging/arch/*.tar.gz
packaging/arch/liboqs-pqvpn/*.tar.gz
packaging/arch/liboqs-pqvpn/*.pkg.tar.zst
packaging/arch/python-liboqs-pqvpn/*.tar.gz
packaging/arch/python-liboqs-pqvpn/*.pkg.tar.zst
```

#### A2. Gitignore generated outputs — eliminate **28 files**

| Path | Files | Why |
|------|------:|-----|
| `results/` | 23 | Generated by benchmarks/evaluation; not source code |
| `.pytest_cache/` | 5 | Test runner cache |

**Action:** Add `results/` and `.pytest_cache/` to `.gitignore`. Remove from tracking with `git rm -r --cached`.

#### A3. Merge `deploy/` into `packaging/common/` — eliminate **3 files**, **1 directory**

| File | Duplicate of | Difference |
|------|-------------|------------|
| `deploy/pqvpn-client.service` | `packaging/common/pqvpn-client.service` | 2 lines differ (Description + ExecStart path) |
| `deploy/pqvpn-server.service` | No exact dup, but belongs with packaging | Should live in `packaging/common/` |
| `deploy/versions.txt` | Unique | Move to root or `docs/` |

**Action:** Move `deploy/pqvpn-server.service` → `packaging/common/`. Delete `deploy/pqvpn-client.service` (duplicate). Move `deploy/versions.txt` → root `VERSIONS.txt`. Remove `deploy/` directory.

#### A4. Eliminate single-file packages — eliminate **3 `__init__.py`** files, **2 directories**

Three packages contain only a single source module plus an `__init__.py` that re-exports everything:

| Package | Files | Proposed change |
|---------|-------|-----------------|
| `crypto/` | `hybrid_crypto.py` + `__init__.py` (50 lines of re-exports) | Flatten: rename `crypto/hybrid_crypto.py` → `crypto.py` at project root. Delete `crypto/__init__.py` and `crypto/` dir. |
| `handshake/` | `kemtls.py` + `__init__.py` (50 lines of re-exports) | Flatten: rename `handshake/kemtls.py` → `handshake.py` at project root. Delete `handshake/__init__.py` and `handshake/` dir. |
| `app/` | `client.py` + `__init__.py` (empty) | Keep as package (needed for `python -m app.client`) |

**Import update required:**
- `from crypto.hybrid_crypto import X` → `from crypto import X` (simpler — but wait, `crypto.py` at root means `import crypto` loads the whole module)
- Alternative: keep as packages but delete the `__init__.py` re-export boilerplate (replace with empty `__init__.py`) — saves 100 lines but not files.

**Recommended approach:** Keep `crypto/` and `handshake/` as packages but **empty their `__init__.py`** files (1 line each). All callers already import from the actual module (`from crypto.hybrid_crypto import ...`, `from handshake.kemtls import ...`), so the re-exports are dead code. This saves **~100 lines** and removes the maintenance burden of keeping re-export lists synchronized.

#### A5. Merge small related VPN modules — eliminate **4 files**

| Merge | Rationale | Import changes |
|-------|-----------|----------------|
| `vpn/enrollment.py` (201 lines) → `vpn/identity.py` (299 lines) | Both manage client/server identity key material. `enrollment` is just identity provisioning. | 3 importers: `app/client.py`, `vpn/cli.py`, `tests/test_onboarding.py` → change `from vpn.enrollment` to `from vpn.identity` |
| `vpn/doctor.py` (244 lines) → `vpn/cli.py` (288 lines) | Doctor is only invoked via CLI (`vpn/cli.py:191: from vpn.doctor import run`). | 2 test importers: `tests/test_networking.py`, `tests/test_deployment.py` → change to `from vpn.cli import ...` |
| `vpn/config.py` (138 lines) → `vpn/runtime.py` (945 lines) | Config defines only `ClientConfig`/`ServerConfig` dataclasses + loaders, exclusively consumed by runtime and its dependents. | 8 importers → `from vpn.runtime import ClientConfig, ...` |
| `vpn/profiles.py` (361 lines) → `vpn/identity.py` | Profiles manage server identity configurations (fingerprint, endpoint). Closely related to identity. | 2 importers: `app/client.py`, `tests/test_onboarding.py` → `from vpn.identity import ...` |

**After merges, `vpn/` contains 6 files (down from 10):**

| File | Approx lines | Contents |
|------|------------:|---------|
| `vpn/identity.py` | ~860 | Identity keys + enrollment + profiles |
| `vpn/runtime.py` | ~1,080 | Config + client/server runtime |
| `vpn/accounts.py` | ~1,085 | Server-side account store |
| `vpn/account_api.py` | ~621 | FastAPI account endpoints |
| `vpn/cli.py` | ~530 | CLI + doctor checks |
| `vpn/network.py` | ~238 | TUN, IPv6, MTU |

#### Part A summary

| Action | Files eliminated | Disk saved |
|--------|----------------:|----------:|
| A1. Delete packaging build artifacts | 119 | ~24 MB |
| A2. Gitignore generated outputs | 28 | ~2 MB |
| A3. Merge deploy/ into packaging/common | 3 + 1 dir | — |
| A4. Empty single-file package `__init__.py` | 0 (but −100 LOC) | — |
| A5. Merge small VPN modules | 4 | — |
| **Total** | **~154 files** | **~26 MB** |
| **212 → ~88 files** | | |

---

### Part B — Codebase line reduction (11,404 → ~8,255 lines)

**Current inventory (14 core source files → 10 after Part A merges):**

| File | Lines | Reduced | Save | Priority |
|---|---:|---:|---:|:---:|
| `app/client.py` | 3,613 | ~2,350 | **1,260** | 🔴 |
| `handshake/kemtls.py` | 1,359 | ~750 | **610** | 🔴 |
| `vpn/accounts.py` | 1,085 | ~850 | **235** | 🟡 |
| `crypto/hybrid_crypto.py` | 1,070 | ~700 | **370** | 🟡 |
| `vpn/runtime.py` (+ config.py) | 1,083 | ~900 | **183** | 🟡 |
| `benchmarks.py` | 945 | ~700 | **245** | 🟡 |
| `vpn/identity.py` (+ enrollment + profiles) | 860 | ~680 | **180** | 🟡 |
| `vpn/account_api.py` | 621 | ~500 | **121** | 🟢 |
| `vpn/cli.py` (+ doctor) | 532 | ~440 | **92** | 🟢 |
| `vpn/network.py` | 238 | ~220 | **18** | 🟢 |
| `__init__.py` re-exports (crypto + handshake) | 100 | ~2 | **98** | 🟢 |
| **Total** | **11,506** | **~8,092** | **~3,414** | |

#### B1. `app/client.py` — 3,613 → ~2,350 lines (save ~1,260)

| # | Technique | Lines saved | Details |
|---|-----------|---:|---------|
| A | Extract inline stylesheets → constants | ~120 | 31 `setStyleSheet()` calls with repeated color strings; 8 multi-line `QPushButton:hover` blocks → `_PRIMARY_BTN_STYLE`, `_DANGER_BTN_STYLE`, `_BADGE_STYLE_TEMPLATE` constants |
| B | Unify Login / Register form builders | ~110 | Near-identical field+label+button boilerplate → single `_build_auth_form(title, fields, on_submit, ...)` helper |
| C | Reduce `_render_*` method verbosity | ~150 | 6 render methods repeat `if connected and X / elif connected / else` patterns → `_render_status_row(row, labels, connected, condition)` helper |
| D | Collapse `_set_visual_state` button table | ~40 | 6-branch if/elif chain for (text, bg, fg, border) → `_BUTTON_STATES` lookup dict |
| E | Trim `ClientStatus` / IPC docstrings | ~60 | 40+ inline field comments → class-level docstring; 10 one-line `IPCClient` methods → generic dispatch |
| F | Compact `_dispatch` command router | ~30 | 12 separate `if command ==` blocks → `_COMMAND_MAP` dict |
| G | Condense `_account_*_finished` handlers | ~30 | Repeated `_set_account_inputs_enabled(True); button.setText(original)` → decorator/wrapper |
| H | Extract profile-mutation lock pattern | ~10 | 4 methods repeat `if not self._lock.acquire` + `_require_profile_mutation_state` → context manager |
| | **Subtotal** | **~550** | (remaining ~710 from verbose docstring trimming and GUI widget construction compaction) |

#### B2. `handshake/kemtls.py` — 1,359 → ~750 lines (save ~610)

| # | Technique | Lines saved | Details |
|---|-----------|---:|---------|
| A | Parameterize protocol version helpers | ~90 | 3× `_pack_header`, `_unpack_header`, `_fixed` (v2/v3/mldsa) differ ONLY in version constant → make version a parameter; delete 6 redundant functions |
| B | Unify Client/ServerHello dataclasses | ~120 | `ClientHello` / `ClientHelloV3` / `ClientHelloMLDSA` are structurally identical; `ServerHello` / `ServerHelloV3` / `ServerHelloMLDSA` similarly → version-parameterized single classes |
| C | Consolidate 6 handshake classes | ~300 | `KEMTLSClient`, `KEMTLSClientV3`, `KEMTLSClientMLDSA`, `KEMTLSServer`, `KEMTLSServerV3`, `KEMTLSServerMLDSA` share >70% identical logic → base class + template-method hooks |
| D | Merge 3 `derive_schedule` functions | ~30 | Nearly identical; differ only in protocol label → single function with keyword args |
| E | Trim inline comments / docstrings | ~40 | `# 32`, `# 1088` size annotations on frozen dataclass fields |

#### B3. `crypto/hybrid_crypto.py` — 1,070 → ~700 lines (save ~370)

| # | Technique | Lines saved | Details |
|---|-----------|---:|---------|
| A | Trim verbose docstrings | ~200 | ~309 lines are blank/comment/docstring (~29%); collapse to 1-3 line summaries; keep security warnings |
| B | Compact mock providers | ~40 | `_MockInsecurePQCProvider` + `_MockInsecureSigProvider` have formulaic hash bodies |
| C | Reduce `HybridKEM` delegation verbosity | ~60 | `encapsulate()` / `decapsulate()` are 2 lines of work wrapped in ~30 lines of docstring each |
| D | Remove unused `KYBER_PARAMS` alias | ~2 | Verify no external imports |

#### B4. `benchmarks.py` — 945 → ~700 lines (save ~245)

| # | Technique | Lines saved |
|---|-----------|---:|
| A | Extract common benchmark runner pattern | ~100 |
| B | Extract chart setup/save boilerplate | ~60 |
| C | Compact CLI + module docstrings | ~85 |

#### B5. `vpn/accounts.py` — 1,085 → ~850 lines (save ~235)

| # | Technique | Lines saved |
|---|-----------|---:|
| A | Compact SQL schema strings | ~80 |
| B | Generic field validator | ~60 |
| C | Consolidate `_with_db` context patterns | ~40 |
| D | Trim docstrings | ~55 |

#### B6. `vpn/runtime.py` (+ merged config) — 1,083 → ~900 lines (save ~183)

| # | Technique | Lines saved |
|---|-----------|---:|
| A | Compact rekey/rehandshake control flow | ~60 |
| B | Reduce inline comments and error handling | ~45 |
| C | Trim send/recv docstrings | ~40 |
| D | Config integration cleanup | ~38 |

#### B7. `vpn/identity.py` (+ merged enrollment + profiles) — 860 → ~680 lines (save ~180)

| # | Technique | Lines saved |
|---|-----------|---:|
| A | Remove duplicate imports after merge | ~20 |
| B | Consolidate duplicate `fingerprint()` calls | ~15 |
| C | Trim docstrings across merged modules | ~80 |
| D | Compact enrollment/profile parsing boilerplate | ~65 |

#### B8. `vpn/account_api.py` — 621 → ~500 lines (save ~121)

| # | Technique | Lines saved |
|---|-----------|---:|
| A | Extract endpoint boilerplate → `_handle_account_op` | ~60 |
| B | Compact middleware implementations | ~30 |
| C | Trim docstrings | ~31 |

#### B9. `vpn/cli.py` (+ merged doctor) — 532 → ~440 lines (save ~92)

| # | Technique | Lines saved |
|---|-----------|---:|
| A | Remove duplicate imports after merge | ~10 |
| B | Compact doctor check patterns | ~40 |
| C | Trim subcommand definitions | ~25 |
| D | Compact help text | ~17 |

#### B10. `__init__.py` cleanup — save ~98 lines

| File | Lines saved | Action |
|------|---:|--------|
| `crypto/__init__.py` | ~50 | Replace 50-line re-export with empty `__init__.py` |
| `handshake/__init__.py` | ~48 | Replace 48-line re-export with empty `__init__.py` |

---

### Constraints

- **No feature removal:** every IPC command, GUI page, protocol variant (v2/v3/v3-mldsa), benchmark, and account API endpoint remains functional.
- **No behavioral changes:** wire formats, key derivation, and security properties are untouched.
- **Docstrings trimmed, not removed:** every public class/function keeps at least a 1-line summary.
- **Tests are not reduced:** test files are excluded from this plan. Import paths in tests are updated for file merges.
- **Security comments preserved:** e.g., "mock provides NO quantum security" warnings stay.
- **All existing tests must pass** after every sub-phase.

### Execution order

```
Phase A (file reduction):
  A1 → A2 (artifact + cache cleanup)     — risk-free, immediate wins
  A3 (deploy/ merge)                       — trivial
  A4 (__init__.py cleanup)                 — trivial
  A5 (VPN module merges)                   — import path updates needed, run tests
  
Phase B (line reduction):
  B10 (__init__.py)  →  B2 (kemtls.py)    — highest architectural impact
  B1 (client.py)     →  B3 (hybrid_crypto.py)
  B4 (benchmarks.py) →  B5–B9 (remaining)
  
Run full test suite after each step.
```

### Expected results

| Dimension | Before | After | Δ |
|-----------|-------:|------:|--:|
| **Total files** | 212 | ~88 | **−124 files (−59%)** |
| **Source code lines** | 11,404 | ~8,092 | **−3,312 lines (−29%)** |
| **Disk (packaging)** | ~24 MB artifacts | ~300 KB | **−24 MB** |
| **Source directories** | 13 | 11 | **−2 dirs** |
| **VPN source files** | 10 | 6 | **−4 files** |



---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| The design overlaps with KEMTLS-PDK / Rosenpass | Do a related-work check **before** Phase 1 coding. Position the novelty as a hybrid ML-KEM-only full VPN with post-compromise security, a formal model, and a deployed evaluation. |
| Tamarin model doesn't terminate | Keep the model abstract; split the lemmas; use helper lemmas and oracles. |
| Rosenpass/strongSwan PQ builds are hard to set up | Start the baseline setup early (during Phase 3), and pin their versions. |
| Python data plane looks weak | Phase 6 decision; state the limitation openly. |
| The ClientHello with Option B exceeds the 1,280 B IPv6 minimum MTU | Measure the fragmentation behaviour and report it, since this is part of the evaluation. |
| Scope creep (GUI, packaging) | Freeze GUI and packaging work, apart from the v3 changes needed, until Phase 8. |
| Reduction introduces regressions | Run full 555-test suite after every sub-phase; no merge without green CI. |
| Over-aggressive docstring trimming hurts readability | Keep at least 1-line summaries; preserve all security-critical warnings. |

---

## Progress tracker

| Phase | Status | Tag | Notes |
|---|---|---|---|
| 0 Baseline + harness | ☑ | `v2-research-baseline` | lan profile baseline measured; netem profiles require root |
| 1 v3 KEM client auth | ☑ | `v3-alpha` | 4,792 B total; 527 tests |
| 2 Tamarin model | ☑ | — | 7 lemmas + pcs_recovery; Tamarin not installed |
| 3 Hybrid re-handshake (PCS) | ☑ | `v3-pcs` | 534 tests; cost measurement deferred to Phase 7 |
| 4 Stateless cookie | ☑ | `v3-dos` | 545 tests; flood tool deferred to Phase 7 |
| 5 Comparison suites | ☑ | `v3-suites` | 555 tests; v3-mldsa (0x31) 6,124 B |
| 6 Data-plane decision | ☑ | — | Option A (scope it); profiled ~10 µs/pkt |
| 7 Evaluation | ☑ | `v3-eval` | eval/ framework; PQVPN + 4 baseline scaffolds |
| 8 Artifact | ☑ | `v3-paper-artifact` | ARTIFACT.md, Dockerfile.artifact, reproduce.sh |
| 9 Paper | ☐ | — | Later |
| 10 Codebase reduction | ☐ | — | 212→~88 files (−59%); 11,404→~8,092 lines (−29%); zero feature loss |

