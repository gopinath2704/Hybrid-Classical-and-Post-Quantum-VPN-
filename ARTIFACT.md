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
docker build -t pqvpn-artifact -f Dockerfile.artifact .
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

The Tamarin Prover model verifies 7 security lemmas for the v3 protocol.

```bash
# Requires: tamarin-prover (Arch: pacman -S tamarin-prover)
./scripts/verify_formal.sh
```

All lemmas should report `verified`. See `formal/README.md` for the full
list and the model's assumptions.

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

The evaluation framework includes scaffold scripts for comparing against:

- **WireGuard** (classical) — requires `wg`, root
- **WireGuard + Rosenpass** (PQ) — requires `rosenpass`, `wg`, root
- **strongSwan IKEv2 + ML-KEM** — requires PQ-enabled `swanctl`, root
- **OpenVPN** (classical) — requires `openvpn`, root

These require the respective tools to be installed and root access for
network namespace setup. When a tool is not available, the scaffold script
exits cleanly with a skip message.

```bash
sudo python eval/run_all.py --iterations 30 --systems pqvpn,wireguard,rosenpass
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
