# Evaluation and Reproducibility

How to reproduce the PQ-VPN evaluation, and where each set of numbers lives. Only
harness output is committed; no number here is estimated or hand-edited.

## Where the results are

| Results | Commit / tag | Location |
|---|---|---|
| Paper campaign, Python stack (M1–M8, WireGuard baseline for M1) | tag `v3-paper-artifact` (e719c4c) | `eval/results-summary/EVALUATION.md`, `summary.csv`, `figures/` |
| Phase 0 baseline before the Rust migration | tag `v3.1-baseline` | `eval/results-summary/phase0-2026-10-28/` |
| Paper freeze with the Rust data plane, Phases 0–3 | tag `v3.1-paper-dataplane` | `phase1-nodelay-2026-10-29/`, `phase3-2026-10-29/` |
| Rust-core migration, Phases 0–4 gate runs | per-phase commit, recorded in each `environment.txt` | `eval/results-summary/phase*-<date>/` (`summary.txt` + raw CSVs) |
| Phase 5 / v4.0.0 gate run | **not run yet** | will land in `eval/results-summary/phase5-<date>/` |
| Formal verification (13/13 lemmas) | 2026-10-02 | `formal/results/` |

The migration plan, [docs/rust-core-migration-plan.md](rust-core-migration-plan.md),
reads each phase's numbers against its gates. Latest gate run (Phase 4, 6822d09):
M5 LAN rust 6665 / 6783 Mbps (v2 / v3-kem) against 680 / 677 Mbps for Python; M8
24.5 kB per session for rust-rust; M7 5/5 connects at 10,000 ClientHello/s on every
backend. Missed and reported: M2 v3-kem 0.205 ms (gate 0.2) and native `pqvpnd` cold
connect 42 ms (gate 30). Phase 5 traced both misses to aws-lc's jitter-entropy seeding
([deployment.md](deployment.md#components-and-tested-versions)). The no-jitter numbers
so far are unprivileged probes (M2 0.184–0.199 ms, native connect 6.5 ms on a shorter
clock), not gate results.

## Setup

Hardware: x86_64 with at least 2 cores and 4 GB RAM. All recorded runs used an
i7-11800H with Arch Linux and native liboqs 0.16.0.

**Native.**

```bash
sudo bash scripts/install-liboqs.sh /usr/local
python3 -m venv .venv && .venv/bin/python -m pip install -c constraints-tested.txt '.[dev]'
.venv/bin/python -m pytest tests/ -q
```

The suite collects 858 tests. On 2026-10-31 at df2aca6 it gave 855 passed and 3
skipped as a normal user with native liboqs. The skips depend on the host: the root
namespace test, a mock-PQC test skipped when liboqs is present, and a missing-WireGuard
test skipped when `wg` is installed. Rust-backend tests need `pqvpn_core` built into the
venv (`maturin develop -m core/pqvpn_core/Cargo.toml`, run from the repo root so the
no-jitter cargo config applies).

**Docker.**

```bash
docker build --target artifact -t pqvpn-artifact .
docker run --rm -v "$PWD/results:/app/results" pqvpn-artifact
```

The image builds liboqs from the pinned commit and runs the test suite plus
`eval/run_all.py --systems pqvpn` (in-process crypto only). It has no Rust toolchain,
so Rust-backend tests skip. That the image still builds and passes is UNVERIFIED for
the current tree.

## Campaign (Python paper metrics)

Gate the host first: root, iproute2 with netem, and native PQC
(`python -c "from crypto.hybrid_crypto import get_crypto_status as s; print(s()['pqc_mode'])"`
must print `native_liboqs`; every runner refuses mock mode). Pin the governor
(`sudo cpupower frequency-set -g performance`), because standalone runs do not do it.

```bash
sudo python eval/run_all.py --iterations 50 --net-iterations 30   # all systems x {lan, metro, continent, lossy-1, lossy-5, mtu-1280}
# writes results/eval-<timestamp>/{raw,figures,sanity.json}; exits non-zero if any unit failed
python eval/generate_tables.py --input results/eval-<ts>/raw --output results/eval-<ts>/figures
```

Per-cell runners: `eval/run_pqvpn_net.sh <profile>` (networked M1),
`eval/run_wireguard.sh`, `eval/run_rosenpass.sh`, `eval/run_strongswan.sh`,
`eval/run_pqvpn.py` (in-process wire bytes and CPU), `eval/measure_throughput.py`
(iperf3 through the tunnel), `eval/measure_memory.py`, `eval/flood_clienthello.py`,
`eval/run_rehandshake.py` and `eval/run_resumption_net.sh`. All networked baselines
share `eval/netem_profiles.sh`, and every networked row carries the git commit, liboqs
version, CPU, governor and kernel. In-process `latency_ms` / `encrypt_*` rows are
crypto-only ceilings, never connect time or data-plane throughput.

`results/` is git-ignored. To keep a run, copy `figures/summary.*`, the PNGs and
`sanity.json` into `eval/results-summary/` and commit them.

## Rust-core gate runs

```bash
sudo env PHASE=5 bash scripts/bench_dataplane.sh   # output: eval/results-summary/phase5-<date>/
```

One run, one committed tree. The runner pins every CPU governor to `performance` and
restores it on exit. It builds `pqvpn_core` in release mode, records the environment,
including the `jent_` symbol count of the installed extension (must be 0 for the
no-jitter build), and refuses a dirty tree unless `ALLOW_DIRTY=1`, which labels the
output DIRTY. Gate rows are the median of 5 runs (M5) or n = 30 / 50 (M1 / M2). A
miss is reported as a miss, not tuned away.

## Deterministic wire sizes

| Suite | ClientHello | ServerHello | ClientKeyExchange | ServerFinished | Total |
|---|---|---|---|---|---|
| v2-ed25519 | 1,318 B | 1,222 B | 1,190 B | 38 B | **3,768 B** |
| v3-kem | 1,318 B | 2,310 B | 1,126 B | 38 B | **4,792 B** |
| v3-mldsa | 1,318 B | 1,222 B | 3,546 B | 38 B | **6,124 B** |

These come from the protocol and must match on every run. The Rust handshake must
match too: its `cargo test` replays the recorded draws in `tests/vectors/handshake.json`
and must reproduce every message byte for byte.

## Formal verification

Tamarin proves 13 lemmas for the v3 protocol in two theories. The split keeps the
state space small; the PCS theory starts from an established session.

```bash
./scripts/verify_formal.sh   # fails if any lemma is not verified or any expected lemma is missing
tamarin-prover --prove formal/pqvpn_v3.spthy
tamarin-prover --heuristic=S --prove formal/pqvpn_v3_pcs.spthy
```

| Theory | Lemmas | Recorded run (2026-10-02, Tamarin 1.12.0, Maude 3.5.1) |
|---|---|---|
| `pqvpn_v3.spthy` (handshake) | `protocol_completes`, `session_key_secrecy`, `forward_secrecy`, `server_auth`, `client_auth`, `kci_resistance_client`, `kci_resistance_server` | 7/7 verified, 20.9 s |
| `pqvpn_v3_pcs.spthy` (post-compromise) | `rehandshake_completes`, `passive_rehandshake_completes`, `rh_client_agrees`, `pcs_control_keys_only`, `pcs_passive_after_epoch_compromise`, `attack_active_after_epoch_compromise` | 6/6 verified, 3.5 s (heuristic `S`) |

The exists-trace lemmas show that witness traces exist. For
`attack_active_after_epoch_compromise`, "verified" means the attack is confirmed: an
active adversary holding the full epoch state can complete a rehandshake. That is a
stated limitation of the protocol.

The model treats X25519 as Tamarin DH, ML-KEM-768 as IND-CCA public-key encryption,
HKDF as a keyed KDF and Finished as a MAC, with `Reveal_LTK` compromise. It assumes
perfect cryptography, a Dolev-Yao network, pre-shared public keys and fresh
randomness. It does **not** model timing or side channels, transport, DoS and cookies,
the data-plane record layer, hash-based rekey, enrollment, or composition across
sessions. The hybrid argument: the master secret mixes independent DH and KEM inputs,
so breaking only one of them does not reveal it. Raw output is in
`formal/results/*.txt`.

## Validity report

A 2026-10-03 audit found that no campaign output had ever been committed (`results/`
is git-ignored). It also found that WireGuard ran on `lan` only without netem, that
Rosenpass and strongSwan had no runners, and that failed baselines were reported as
"skipped". All four were fixed. Every networked system now shares one netem table and
one M1 definition, carries per-row provenance, and the orchestrator exits non-zero on
any failed unit. The campaign was then run and committed (`v3-paper-artifact`).

What still holds for any claim:

- **Committed and final:** formal verification, wire sizes, the Python campaign, and
  the Phase 0–4 gate runs.
- **Never run:** the Rosenpass and strongSwan baselines. Their runners are written to
  the shared contract, but they must pass a 1-iteration dry run
  (`sudo eval/run_rosenpass.sh 1 /dev/stdout lan`, connect time > 0, not -1) before a sweep.
- **Fairness:** WireGuard and strongSwan run in the kernel, and Rosenpass feeds kernel
  WireGuard. PQ-VPN is a userspace TUN VPN, with its data plane in Python or Rust.
  Handshake cost is like-for-like (same M1, same netem). Data-plane comparisons are
  context, not a win.

## Re-run commands

| Goal | Command |
|---|---|
| Unit and integration tests | `.venv/bin/python -m pytest tests/ -q` |
| Root namespace suite | `sudo env PATH=".venv/bin:$PATH" ALLOW_MOCK_PQC=0 .venv/bin/python -m pytest -q -m 'integration and requires_root'` |
| Python campaign | `sudo python eval/run_all.py --iterations 50 --net-iterations 30` |
| Rust-core gate | `sudo env PHASE=5 bash scripts/bench_dataplane.sh` |
| Formal proofs | `./scripts/verify_formal.sh` |
| Pentest harnesses | each script in `pentesting/attacks/` (see [pentest.md](../pentesting/pentest.md)) |
| Rust deps | `cargo deny check` and `cargo audit` in `core/` (both clean on 2026-10-31) |

## Remaining steps

1. **24 h fuzz run** of the 5 `core/fuzz` targets with 0 crashes. Earlier attempts were
   stopped early and do not count. It is valid for v4.0.0 only if `core/pqvpn_core`,
   `core/fuzz` and `core/Cargo.lock` are unchanged at the tag.
2. **Phase 5 gate run** (`PHASE=5`) on a clean tree with `jent_` = 0. M1 native ≤ 30 ms
   and M2 ≤ 0.2 ms are decided here, and misses are reported.
3. **Real-host kill-switch check:** with `kill_switch` on, `sudo kill -9` the client;
   curl and dig must fail, and GUI Disconnect must restore traffic (so far verified in a
   network namespace only).
4. Tag **v4.0.0** after rows 1–3 are met or reported.
5. Optional: Rosenpass and strongSwan baselines, a live VPS cross-check labelled as a
   single run, and a Zenodo DOI for the tagged release (none minted yet).

## Pinned versions

| Component | Version | Pin |
|---|---|---|
| liboqs | 0.16.0 | tag + commit in `scripts/install-liboqs.sh` |
| liboqs-python, cryptography (50.0.1), all Python deps | — | `constraints-tested.txt` |
| Python | ≥ 3.11 (baseline 3.14.7) | `pyproject.toml` |
| Rust crates | — | `core/Cargo.lock` |
| Rust toolchain | 1.99.1 (MSRV 1.85, checked on Debian trixie) | `core/rust-toolchain.toml` |

## Troubleshooting

| Problem | Fix |
|---|---|
| `PQCUnavailableError` / binding import fails | install native liboqs 0.16.0 with `scripts/install-liboqs.sh` |
| More than 3 skips | `pytest -rs`: root namespace tests need sudo, rust tests need `pqvpn_core` |
| `jent_` count is not 0 | rebuild `pqvpn_core` from the repo root so `.cargo/config.toml` applies |
| Bench refuses to start | commit or stash first, or set `ALLOW_DIRTY=1` for a labelled DIRTY run |
| Tamarin missing | `pacman -S tamarin-prover` or `brew install tamarin-prover` |
