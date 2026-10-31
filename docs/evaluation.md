# Evaluation and Reproducibility

This document describes how to reproduce the evaluation results for the
**Hybrid Classical and Post-Quantum VPN** (PQVPN) research prototype.

---

## Hardware requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU | x86_64, 2 cores | x86_64, 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 2 GB free | 5 GB free |
| OS | Ubuntu 22.04+ / Arch Linux | Ubuntu 24.04 LTS |
| Python | 3.11+ | 3.14+ |

Optional for constrained-device evaluation: Raspberry Pi 4/5 (aarch64).

---

## One-command setup

### Option A: Docker (recommended)

```bash
docker build --target artifact -t pqvpn-artifact .
docker run --rm -v $(pwd)/results:/app/results pqvpn-artifact
```

This builds liboqs 0.16.0 from pinned source, installs all Python
dependencies, runs the test suite, runs the evaluation campaign, and
generates all figures and tables.

### Option B: Native

```bash
# 1. Build and install liboqs 0.16.0 (requires cmake, ninja, gcc/g++)
sudo bash scripts/install-liboqs.sh /usr/local

# 2. Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -c constraints-tested.txt '.[dev]'

# 3. Run the test suite (740 tests collected)
python -m pytest tests/ -q

# 4. Run the evaluation campaign
python eval/run_all.py --iterations 50

# 5. Figures are written to results/eval-<timestamp>/figures/
```

---

## Expected runtime

| Step | Time (4-core laptop) |
|---|---|
| Docker build (first time) | ~5 min |
| Test suite (740 tests) | ~95 s |
| Evaluation (50 iterations) | ~30 s |
| Table/chart generation | ~2 s |
| **Total** | **~6 min** |

---

## Expected outputs

### Test suite

```
737 passed, 3 skipped
```

Recorded 2026-10-28 with native liboqs as a normal user. The 3 skips depend on the
host: one root namespace test (needs root, TUN, iproute2 and nftables), one mock-PQC
test that is skipped when native liboqs is present, and one missing-WireGuard test that
is skipped when `wg` is installed. The 2026-10-10 evaluation run below
predates later tests and recorded 594 passed, 2 skipped.

### Evaluation results

Output directory: `results/eval-<timestamp>/`

```
results/eval-<timestamp>/
├── raw/
│   └── pqvpn.csv              # Raw metrics for all three suites
├── figures/
│   ├── handshake_comparison.txt   # Text table (terminal/paper)
│   ├── handshake_comparison.csv   # Machine-readable comparison
│   ├── wire_sizes.txt             # Per-message byte breakdown
│   ├── handshake_comparison.png   # Bar charts (latency, wire, throughput)
│   └── wire_breakdown.png         # Stacked wire size chart
└── sanity.json                    # Environment log
```

### Expected wire sizes (deterministic)

| Suite | ClientHello | ServerHello | ClientKeyExchange | ServerFinished | Total |
|---|---|---|---|---|---|
| v2-ed25519 | 1,318 B | 1,222 B | 1,190 B | 38 B | **3,768 B** |
| v3-kem | 1,318 B | 2,310 B | 1,126 B | 38 B | **4,792 B** |
| v3-mldsa | 1,318 B | 1,222 B | 3,546 B | 38 B | **6,124 B** |

Wire sizes are protocol-determined and must match exactly on every run.
Latency and throughput numbers vary with hardware.

---

## Formal verification

The Tamarin Prover models verify 13 security lemmas for the v3 protocol across
two theories: `formal/pqvpn_v3.spthy` (handshake, 7 lemmas) and
`formal/pqvpn_v3_pcs.spthy` (post-compromise security, 6 lemmas). Splitting the
model avoids Tamarin state-space explosion while keeping the composition sound:
the handshake theory proves key establishment; the PCS theory proves re-handshake
recovery given an established session.

### Prerequisites

Install [Tamarin Prover](https://tamarin-prover.com/):

```bash
# Arch Linux
sudo pacman -S tamarin-prover

# macOS (Homebrew)
brew install tamarin-prover
```

### Running

```bash
# Verify all lemmas automatically (both models):
./scripts/verify_formal.sh

# Or directly:
tamarin-prover --prove formal/pqvpn_v3.spthy          # handshake (7 lemmas)
tamarin-prover --heuristic=S --prove formal/pqvpn_v3_pcs.spthy  # PCS (6 lemmas)

# Interactive exploration (opens a web UI):
tamarin-prover interactive formal/pqvpn_v3.spthy
```

### Expected output

All lemmas should report `verified`. The exists-trace lemmas (`protocol_completes`,
`rehandshake_completes`, `passive_rehandshake_completes`,
`attack_active_after_epoch_compromise`) verify that witness traces exist; "verified"
for the attack lemma means the attack is confirmed, documenting the protocol's stated
limitation.

**Handshake model** (`formal/pqvpn_v3.spthy`):

| Lemma | Kind | Property | Expected |
|---|---|---|---|
| `protocol_completes` | exists-trace | Sanity: a full handshake trace exists | verified |
| `session_key_secrecy` | all-traces | Keys secret unless both LTKs compromised | verified |
| `forward_secrecy` | all-traces | Post-session LTK compromise doesn't reveal keys | verified |
| `server_auth` | all-traces | Injective agreement: client authenticates server | verified |
| `client_auth` | all-traces | Injective agreement: server authenticates client | verified |
| `kci_resistance_client` | all-traces | Client key compromise doesn't allow server impersonation | verified |
| `kci_resistance_server` | all-traces | Server key compromise doesn't allow client impersonation | verified |

**PCS model** (`formal/pqvpn_v3_pcs.spthy`):

| Lemma | Kind | Property | Expected |
|---|---|---|---|
| `rehandshake_completes` | exists-trace | Sanity: an active re-handshake trace exists | verified |
| `passive_rehandshake_completes` | exists-trace | Sanity: a passive re-handshake trace exists | verified |
| `rh_client_agrees` | all-traces | Key confirmation: client agrees with server on new keys (no epoch leak) | verified |
| `pcs_control_keys_only` | all-traces | Control-key-only compromise: new keys stay secret | verified |
| `pcs_passive_after_epoch_compromise` | all-traces | Full epoch compromise + passive adversary: new keys stay secret | verified |
| `attack_active_after_epoch_compromise` | exists-trace | Active adversary with full epoch state can complete re-handshake (known limitation) | verified |

### Recorded run

| Theory | Date | Tamarin | Maude | Heuristic | Time | Result |
|---|---|---|---|---|---|---|
| `pqvpn_v3.spthy` | 2026-10-02 | 1.12.0 | 3.5.1 | default | 20.9 s | 7/7 verified |
| `pqvpn_v3_pcs.spthy` | 2026-10-02 | 1.12.0 | 3.5.1 | `S` | 3.5 s | 6/6 verified |

Raw output: `formal/results/verify-2026-10-02.txt` (combined),
`formal/results/handshake-verify.txt`, `formal/results/pcs-verify.txt`.
`formal/results/baseline-2026-10-02.txt` preserves the pre-fix model output
(with `pcs_recovery` incomplete) for comparison.

Results are in `formal/results/`. Run `./scripts/verify_formal.sh` to
reproduce; the script fails if any lemma is not verified or any expected
lemma is missing.

### Model structure

**Handshake theory** (`formal/pqvpn_v3.spthy`):

- **X25519:** Tamarin's built-in Diffie-Hellman
- **ML-KEM-768:** Modelled as public-key encryption with CCA security
- **HKDF:** Modelled as a keyed derivation function (`kdf`/`kdf3`)
- **Finished MAC:** Modelled as a MAC with equational verification
- **Compromise:** `Reveal_LTK` (long-term keys only)

Key schedule:

```
hs     = kdf(<dhss, k_eph>, 'hs')           -- ephemeral handshake secret
master = kdf3(hs, <k_s, k_c>, transcript)   -- authenticated master secret
```

**PCS theory** (`formal/pqvpn_v3_pcs.spthy`):

- **KEM-only re-handshake:** Sound abstraction — DH adds an independent shared
  secret, so KEM-only gives the adversary strictly more power
- **Bootstrapped session state:** Two rules (`Bootstrap_Control`, `Bootstrap_Epoch`)
  create session facts with a fresh master; the adversary receives old data keys
  (and optionally the rekey secret) via `Out()`
- **Direct channel facts:** `Ch_C2S`/`Ch_S2C` structurally enforce passive delivery
  for the passive-adversary lemma, avoiding case-split explosion
- **Single re-handshake:** `PostSession` facts (not consumed by any rule) replace
  `Session` facts after re-handshake, preventing unbounded term nesting
- **Transcript binding:** KDF context includes `h(<sid, 'rehandshake', epoch, req, resp_body>)`
- **Key confirmation:** Server sends `mac(cck(new_master), <'rehandshake confirm', req, resp_body>)`;
  client pattern-matches it before activating

Re-handshake key derivation (matches `kemtls.py`):

```
new_master = kdf(h(<old_master, 'rk'>), <k_rh, h(<sid, 'rehandshake', epoch, req, resp_body>)>)
confirm    = mac(cck(new_master), <'rehandshake confirm', req, resp_body>)
```

### Assumptions

1. **Perfect cryptography.** DH is CDH-hard; KEM is IND-CCA2 secure; HKDF is a PRF; MACs are unforgeable.
2. **Dolev-Yao adversary.** The attacker controls the network.
3. **Pre-shared public keys.** Both sides have the peer's long-term public key before the handshake.
4. **Fresh randomness.** All nonces, session IDs, and ephemeral keys are generated freshly.

### What is NOT modelled

Timing/side channels, transport details, rate limiting/DoS, the data-plane record
layer, hash-based rekey, the stateless cookie, enrollment/key distribution, and
multi-session composition beyond Tamarin's built-in semantics.

### Hybrid security argument

The key schedule mixes independent DH and KEM contributions. If DH is broken but KEM
holds, the master still depends on KEM-protected inputs. If KEM is broken but DH holds,
`dhss` is CDH-protected. The `session_key_secrecy` lemma verifies this in the
both-sound setting.

---

## Regenerating figures from raw data

If you have existing raw CSV data and want to regenerate figures:

```bash
python eval/generate_tables.py \
    --input results/eval-<timestamp>/raw \
    --output results/eval-<timestamp>/figures
```

---

## Additional evaluation scripts

Beyond the core campaign, dedicated scripts measure:

- **Throughput** (`eval/measure_throughput.py`) — iperf3-through-tunnel with namespace isolation
- **Memory** (`eval/measure_memory.py`) — RSS tracking during handshake and data transfer
- **DoS resistance** (`eval/flood_clienthello.py`) — ClientHello flood with cookie-mode measurement
- **Re-handshake** (`eval/run_rehandshake.py`) — PCS epoch rotation latency
- **Session resumption** (`eval/run_resumption_net.sh`) — 1-RTT resumption handshake timing

## Baseline VPN comparison (optional)

The evaluation framework includes a harness for comparing against
**WireGuard** (classical) — requires `wg` and root.

Rosenpass and strongSwan baseline runners exist (`eval/run_rosenpass.sh`,
`eval/run_strongswan.sh`) but require their respective tools installed.

```bash
sudo python eval/run_all.py --iterations 30 --systems pqvpn,wireguard
```

---

## Pinned versions

| Component | Version | Pin mechanism |
|---|---|---|
| liboqs | 0.16.0 | Git tag + commit SHA in `scripts/install-liboqs.sh` |
| liboqs-python | 0.16.0 | `pyproject.toml` + `constraints-tested.txt` |
| cryptography | 50.0.1 | `pyproject.toml` + `constraints-tested.txt` |
| Python | ≥3.11 | `pyproject.toml` `requires-python` |
| All transitive deps | — | `constraints-tested.txt` (full pin file) |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `liboqs-python` import fails | Ensure native liboqs 0.16.0 is installed: `sudo bash scripts/install-liboqs.sh /usr/local` |
| Tests show >3 skips | Check `pytest -rs`: namespace tests need `sudo`; native-PQC tests skip without liboqs |
| matplotlib charts missing | Install `matplotlib` via `pip install '.[dev]'` |
| Tamarin not found | Install: `pacman -S tamarin-prover` or `brew install tamarin-prover` |
| Docker build OOM | Increase Docker memory limit to ≥4 GB |

---

## Recorded evaluation run

| Field | Value |
|---|---|
| Date | 2026-10-10 |
| CPU | Intel i7-11800H @ 2.30 GHz |
| Governor | `performance` |
| Kernel | 7.2.3-arch1-3 (Arch Linux) |
| liboqs | 0.16.0 (native) |
| Python | 3.14 |
| Commit | `6d9cac1` |
| Metrics | M1 (n=30), M2 (n=50), M3, M5, M6 (n=30+12), M7, M8 |
| Baselines | WireGuard (M1 only) |

Summary CSV: `eval/results-summary/summary.csv`
Full write-up: `eval/results-summary/EVALUATION.md`

---

## Release tag

This artifact is tagged as `v3-paper-artifact` in the repository.

## Validity report
**Date:** 2026-10-03
**Reviewer environment:** cloud container, git `claude/adoring-gauss-1twmyl`
**Scope:** validate the committed M1–M8 campaign results before any of them are
used in the paper.

> **One-line verdict:** No networked campaign results (CSVs, figures, or summary
> tables) are committed anywhere in the repository or present on disk, so **zero
> data-plane / connect-time cells are paper-ready today.** The only
> trustworthy, committed quantitative evidence is (a) the **formal verification**
> (13/13 lemmas) and (b) the **deterministic handshake wire sizes**. Two of the
> three baselines (Rosenpass, strongSwan) had no runner at all. The harness
> gaps that caused this are now fixed (see [Re-run commands](#re-run-commands)); the cells
> themselves must be produced by a run on a capable host.

---

### 1. How the results were located

| Where I looked | Result |
|---|---|
| Tracked files on `claude/adoring-gauss-1twmyl` | `eval/*.py`, `eval/*.sh` only — **no CSVs** |
| All remote branches (`main`, `eval/harness-v2`, `fix/code-review-round3`, `claude/keen-mccarthy-gfait3`) | no result CSVs in any ref |
| `git log --all --diff-filter=A` for `*.csv`/`result`/figures | only old `benchmarks/results/*.json|png` (superseded, now git-ignored) + `formal/results/*.txt` |
| `results/` on disk | **does not exist** (git-ignored; nothing generated here) |
| `benchmarks/` on disk | **does not exist** |

`results/` is listed in `.gitignore`, so even if a campaign had been run on the
real host, its output would **not** have been committed. The intended tracked
home for the summary (`eval/results-summary/`) was empty. **This is the root
cause of the missing data: the campaign output path is git-ignored and was
never exported to a tracked location.**

---

### 2. Per-check findings (Step 1 checklist)

| Check | Status | Finding / root cause |
|---|---|---|
| **Native crypto only** (`pqc_mode == native_liboqs`, real `liboqs_version`) | ⚠️ Cannot confirm from data | No rows exist to inspect. The guard itself is correct: `run_pqvpn.py:require_native_pqc`, `run_all.py:_require_native_pqc`, and `run_pqvpn_net.sh` all `sys.exit(1)`/`exit 1` on non-native mode (verified by `tests/test_eval_harness.py::test_pqc_guard_rejects_mock/_unavailable`). **Per-row** liboqs provenance did **not** exist in the schema; now added to the networked runners. |
| **Sample size + CI ≥ 30 runs, median + 95% bootstrap CI** | ⚠️ Cannot confirm from data | No cells. The aggregation path is sound: `generate_tables.bootstrap_ci` (10 000 resamples, seed 42) is deterministic and tested. Default `--net-iterations` is 30 (meets the floor); in-process default is 50. |
| **Profiles actually applied** (connect time scales with profile; `continent` ≫ `lan`) | ❌ Could not have been satisfied for baselines | `run_pqvpn_net.sh` applies netem per profile correctly. **But `run_wireguard.sh` hard-coded `profile=lan` and applied *no* netem at all** — WireGuard could only ever produce a single flat `lan` cell. Fixed: WG now takes a profile and applies the shared netem table. |
| **Same topology/schema for every system** | ❌ Not satisfied | PQ-VPN-net used netns+veth+netem; WireGuard used netns+veth but **no netem** and only `lan`; Rosenpass/strongSwan **did not exist**. Fixed: all baselines now source `eval/netem_profiles.sh` (identical RTT/loss/MTU table) and share the M1 definition. |
| **A baseline that silently "completed" with no data is a hole** | ❌ Latent bug | `run_all.py` appended failures to `skipped`, never to `failed` (the `failed` list was dead), so a broken baseline reported as "Skipped", not "Failed". Fixed: failures are tracked and the orchestrator now exits non-zero on any failed unit. New baseline runners fail fast (exit 1) when their tool is missing — never exit 0 with an empty CSV. |
| **Baselines present** (WireGuard, Rosenpass, strongSwan) | ❌ 2 of 3 missing | this document states verbatim: *"OpenVPN, Rosenpass, and strongSwan baselines are not implemented; the scaffold stubs that previously existed have been removed."* Only WireGuard had a runner (and it was lan-only). Fixed: `eval/run_rosenpass.sh` and `eval/run_strongswan.sh` added (require host validation — see below). |
| **Metadata per row** (git commit, liboqs version, CPU, governor, kernel) | ❌ Not in schema | The unified schema was 6 columns (`system,profile,metric,run,value,unit`) with no provenance; metadata lived only in a separate `sanity.json`. Fixed: the networked runners now append `git_commit,liboqs_version,cpu_model,governor,kernel` to every row (`generate_tables` tolerates the extra columns). In-process `run_pqvpn.py` keeps the 6-column schema (its test asserts exactly 6 columns); its provenance is in `sanity.json`. |

---

### 3. Additional harness findings (beyond the checklist)

1. **The real networked connect-time runner was never orchestrated.**
   `run_pqvpn_net.sh` (the genuine M1 benchmark) existed but `run_all.py` only
   ran `run_pqvpn.py` (in-process) and `run_wireguard.sh` (lan-only). A campaign
   driven by `run_all.py` would therefore have produced **in-process PQ-VPN
   numbers and a single lan WireGuard number** — and if the in-process
   `latency_ms` were presented as "connect time", that would be exactly the
   mock/in-process-as-networked error the brief forbids. Fixed: `pqvpn-net` and
   the three baselines are now first-class networked systems in the orchestrator,
   swept across all six profiles.

2. **Networked data-plane throughput (M2) runner now exists.**
   `eval/measure_throughput.py` runs iperf3 through the tunnel on namespace-isolated
   topology. `eval/measure_memory.py` profiles RSS during handshake and data transfer.
   Both need a capable-host run to produce committed results. `run_pqvpn.py`'s
   in-process `encrypt_pps`/`encrypt_mbps` remain a crypto-core ceiling and must
   not be reported as data-plane throughput.

3. **In-process labelling is honest.** `run_pqvpn.py` correctly stamps its rows
   `profile=in-process`, so they cannot be silently mistaken for a netem profile.
   Its **wire-byte** and **CPU** rows are network-independent and legitimate; its
   `latency_ms`/`encrypt_*` rows are crypto-only and must be labelled as such.

---

### 4. Cell-by-cell status matrix

Legend: ✅ trustworthy & committed · 🟡 reproducible-but-not-committed ·
❌ absent (needs host run) · n/a not defined.

#### Security / correctness
| Cell | Status | Evidence |
|---|---|---|
| Handshake model, 7 lemmas | ✅ | `formal/results/handshake-verify.txt` — all `verified` |
| PCS model, 6 lemmas | ✅ | `formal/results/pcs-verify.txt` — all `verified` |

#### Handshake cost — bytes
| System | Status | Evidence |
|---|---|---|
| PQ-VPN v2-ed25519 / v3-kem / v3-mldsa wire bytes | 🟡 | Deterministic, in this document; reproduce with `python eval/run_pqvpn.py`. Not committed as a CSV. |
| WireGuard / Rosenpass / strongSwan handshake bytes | ❌ | No capture committed; no byte-capture step in any runner. |

#### Handshake cost — time (M1 connect) & CPU
| System × {lan,metro,continent,lossy-1,lossy-5,mtu-1280} | Status |
|---|---|
| pqvpn-net | ❌ absent (runner exists; never orchestrated/committed) |
| wireguard | ❌ absent (runner was lan-only, no netem — now fixed) |
| rosenpass | ❌ absent (**no runner existed** — now added, needs host validation) |
| strongswan | ❌ absent (**no runner existed** — now added, needs host validation) |
| PQ-VPN client/server CPU (in-process) | 🟡 reproducible via `run_pqvpn.py`; not committed |

#### Data-plane throughput / latency (M2)
| Cell | Status |
|---|---|
| Networked throughput through tunnel (PQ-VPN) | ❌ absent (runner exists: `eval/measure_throughput.py`; needs capable-host run) |
| Memory profiling | ❌ absent (runner exists: `eval/measure_memory.py`; needs capable-host run) |

---

### 5. What this means for the paper

- **Defensible today:** PQ confidentiality, formally verified handshake, and PCS
  (13/13 lemmas); PQ-VPN handshake **wire sizes** (3 768 / 4 792 / 6 124 B).
- **Not defensible today (must be produced on a capable host, never estimated):**
  connect-time (M1) for any system/profile, CPU cost vs baselines, baseline wire
  bytes, and all data-plane throughput/latency numbers.
- **Fairness note that must survive to the paper:** PQ-VPN is Python user-space
  TUN; WireGuard/strongSwan are in-kernel; Rosenpass is a userspace PQ control
  plane feeding kernel WireGuard. The handshake-cost comparison is apples-to-apples
  (all measured by the same M1 over the same netem), but any data-plane throughput
  comparison is Python-vs-kernel and must be framed as context, not a win.


## Re-run commands
This evaluation was prepared in a container that is **not** netem/WireGuard/
liboqs-capable, so the connect-time, CPU, and data-plane cells were deliberately
left PENDING rather than estimated. Run the commands below on a proper host to
fill them. **Do not commit fabricated or hand-edited numbers — only
harness output.**

---

### 1. Host capability gate (run first)

All of these must pass before any cell is trustworthy:

```bash
# root / CAP_NET_ADMIN
[ "$(id -u)" = 0 ] && echo "root OK"

# netns + netem
ip -V && tc -V && echo "iproute2 OK"

# baselines
wg --version && echo "wireguard OK"
rp --help    >/dev/null 2>&1 && echo "rosenpass OK"
swanctl --version && ls /usr/lib*/ipsec/charon 2>/dev/null && echo "strongswan OK"

# native post-quantum crypto (THE hard gate)
python -c "from crypto.hybrid_crypto import get_crypto_status as s; \
import sys; m=s()['pqc_mode']; print('pqc_mode =', m); \
sys.exit(0 if m=='native_liboqs' else 1)"
python -c "import oqs; print('liboqs', oqs.oqs_version())"
```

If `pqc_mode` is anything other than `native_liboqs`, stop: install native
liboqs 0.16.0 (`sudo bash scripts/install-liboqs.sh /usr/local`). Mock mode is
rejected by every runner by design.

Set a stable governor to keep CI tight:
```bash
sudo cpupower frequency-set -g performance   # or: for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance | sudo tee $f; done
```

---

### 2. One command for the whole campaign

```bash
sudo python eval/run_all.py --iterations 50 --net-iterations 30
# writes results/eval-<timestamp>/{raw,figures,sanity.json}
```

This now runs **all five systems** over **all six profiles**:
`pqvpn` (in-process crypto), `pqvpn-net`, `wireguard`, `rosenpass`, `strongswan`
× {lan, metro, continent, lossy-1, lossy-5, mtu-1280}. The orchestrator exits
non-zero if any unit fails, so a partial campaign is never silently reported as
complete.

---

### 3. Per-cell commands (if you want to run cells individually)

```bash
PROFILES="lan metro continent lossy-1 lossy-5 mtu-1280"
OUT=results/manual/raw; mkdir -p "$OUT"

# PQ-VPN networked connect time (M1)
for p in $PROFILES; do
  sudo eval/run_pqvpn_net.sh "$p" --iterations 30 --out "$OUT/pqvpn-net-$p.csv"
done

# WireGuard (classical baseline) — now profile-aware + netem-matched
for p in $PROFILES; do
  sudo eval/run_wireguard.sh 30 "$OUT/wireguard-$p.csv" "$p"
done

# Rosenpass (PQ control plane + kernel WireGuard) — VALIDATE FIRST (step 4)
for p in $PROFILES; do
  sudo eval/run_rosenpass.sh 30 "$OUT/rosenpass-$p.csv" "$p"
done

# strongSwan (classical IKEv2/IPsec) — VALIDATE FIRST (step 4)
for p in $PROFILES; do
  sudo eval/run_strongswan.sh 30 "$OUT/strongswan-$p.csv" "$p"
done

# PQ-VPN in-process crypto cost (wire bytes + CPU; network-independent)
python eval/run_pqvpn.py --iterations 50 --out "$OUT/pqvpn.csv"

# Aggregate -> tables + figures (median + 95% CI)
python eval/generate_tables.py --input "$OUT" --output results/manual/figures
```

---

### 4. Validate the two new baselines before trusting them

`run_rosenpass.sh` and `run_strongswan.sh` were written to the shared
topology/M1/schema contract but could not be executed in the prep environment.
Do a 1-iteration dry run on the host and confirm a real tunnel, not a timeout:

```bash
sudo eval/run_rosenpass.sh  1 /dev/stdout lan   # expect a connect_time_ms row with value > 0 (not -1)
sudo eval/run_strongswan.sh 1 /dev/stdout lan   # expect a connect_time_ms row with value > 0 (not -1)
```

A `-1` value or a `FAILED (timeout)` line means the tunnel did not come up — fix
the config (tool version / CLI surface / kernel XFRM for strongSwan) **before**
running the full sweep. The CLI of both tools varies across releases; the runners
target Rosenpass's `rp` wrapper (≥ 0.2) and strongSwan ≥ 5.9 (vici/swanctl).

---

### 5. Networked data-plane throughput (M2)

The throughput runner now exists as `eval/measure_throughput.py`. It uses
iperf3-through-the-tunnel on namespace-isolated topology:

```bash
# Throughput measurement (requires root, iperf3, netns)
sudo python eval/measure_throughput.py --duration 10

# Memory profiling
sudo python eval/measure_memory.py

# DoS resistance / cookie effectiveness
sudo python eval/flood_clienthello.py

# Re-handshake latency (PCS epoch rotation)
sudo python eval/run_rehandshake.py --iterations 30

# Resumption handshake timing
sudo eval/run_resumption_net.sh lan 30
```

---

### 6. Publish the results so they survive

`results/` is **git-ignored**, so a host run does not commit anything on its own.
After a clean run, copy the summary into the tracked folder and commit:

```bash
TS=<timestamp>
cp results/eval-$TS/figures/summary.csv       eval/results-summary/summary.csv
cp results/eval-$TS/figures/summary.txt       eval/results-summary/summary.txt
cp results/eval-$TS/figures/*.png             eval/results-summary/figures/
cp results/eval-$TS/sanity.json               eval/results-summary/sanity.json
# then fill Tables A/B/D in EVALUATION.md from summary.csv (median + CI) and commit
```


## Remaining steps
What is still outstanding after this evaluation pass, in **recommended order**.
Items 1–2 are blocking for any quantitative claim; 3–5 are artifact packaging;
6 is optional.

#### 1. ~~Run the campaign on a capable host and commit the numbers~~ — **done**
Tables A/B/C/D filled from real harness output on i7-11800H with native liboqs.
All PQ-VPN cells measured with `pqc_mode == native_liboqs`. M1 connect time
(n=30), M2 CPU (n=50), M3 wire bytes (n=10), M5 throughput, M6–M8 all committed.
Session resumption (n=20, v3-kem) added: −20% metro, −18% continent.
v3-kem on-wire bytes (17 packets, 5 745 B) and throughput added.
Rosenpass and strongSwan baselines still not run.

#### 2. ~~Run the data-plane throughput/latency benchmark~~ — **done**
`eval/measure_throughput.py` with `--protocol {v2-ed25519, v3-kem}`.
Measured on i7-11800H for both v2 and v3-kem across all 6 profiles.
v2: 613 Mbps LAN; v3-kem: 335 Mbps LAN (same AES-256-GCM cipher; variance
is run-to-run, not protocol). RTT overhead 0.3–1.2 ms.

#### 3. Create the `v3-paper-artifact` tag — **not yet done**
this document claims *"This artifact is tagged as `v3-paper-artifact`"*, but the
only tag in the repo is `v2-minimal-layout`. Tag the commit that contains the
committed campaign results (do this **after** step 1 so the tag captures real
numbers), then update this document's "Release tag" section if anything moved.

#### 4. Record the this document "recorded-run" table
this document has a recorded-run table for the **formal** proofs but not for the
**evaluation campaign**. Add a recorded-run table for the campaign (host CPU,
governor, kernel, liboqs version, git commit, date, per-cell `n`) sourced from
`sanity.json` — the per-row provenance now carried in the CSVs makes this exact.

#### 5. Mint the Zenodo DOI
After the `v3-paper-artifact` tag exists and the results are committed, archive
the tagged release to Zenodo and record the DOI in `README.md` and this document.
Do this last among packaging steps so the DOI points at the final artifact.

#### 6. Optional: live VPS check
A single real-Internet client↔VPS connect-time + short iperf3 run, reported
separately as a sanity cross-check of the netns/netem numbers (clearly labelled
"single run, not part of the CI'd campaign"). Nice-to-have, not required for the
core claim.

#### 7. Write the paper draft
With steps 1–4 committed, draft the paper: lead with the security contribution
(PQ + verified handshake + PCS, 13/13 lemmas), then handshake cost (bytes final;
time/CPU from step 1), then the honest throughput trade-off (step 2). Reuse
[`EVALUATION.md`](../eval/results-summary/EVALUATION.md) §1/§3/§4 as the skeleton for Results / Discussion / Threats.

---

### Recommended order (summary)

```
1. Host campaign run + commit numbers      (blocking)
2. Data-plane throughput runner + run      (blocking for trade-off)
3. Tag v3-paper-artifact                    (after 1)
4. this document campaign recorded-run table  (after 1)
5. Zenodo DOI                               (after 3)
6. Live VPS cross-check                      (optional)
7. Paper draft                               (after 1–4)
```

> Do not reorder 3/5 before 1: tagging or minting a DOI before real numbers are
> committed would archive an artifact with empty result tables.
