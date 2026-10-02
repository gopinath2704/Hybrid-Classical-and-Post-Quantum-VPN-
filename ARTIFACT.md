# Reproducibility Artifact

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
| Python | 3.11+ | 3.12+ |

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

# 3. Run the test suite (555 tests expected)
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
| Test suite (555 tests) | ~20 s |
| Evaluation (50 iterations) | ~30 s |
| Table/chart generation | ~2 s |
| **Total** | **~6 min** |

---

## Expected outputs

### Test suite

```
555 passed, 2 skipped
```

The 2 skips are namespace tests requiring root (`CAP_NET_ADMIN`).

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

## Baseline VPN comparison (optional)

The evaluation framework includes a harness for comparing against
**WireGuard** (classical) — requires `wg` and root.

OpenVPN, Rosenpass, and strongSwan baselines are not implemented; the
scaffold stubs that previously existed have been removed. Implementing
these comparisons requires the respective tools and manual configuration.

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
| Tests show >2 skips | Some tests require `CAP_NET_ADMIN`; run with `sudo` for namespace tests |
| matplotlib charts missing | Install `matplotlib` via `pip install '.[dev]'` |
| Tamarin not found | Install: `pacman -S tamarin-prover` or `brew install tamarin-prover` |
| Docker build OOM | Increase Docker memory limit to ≥4 GB |

---

## Release tag

This artifact is tagged as `v3-paper-artifact` in the repository.
