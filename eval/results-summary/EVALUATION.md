# PQ-VPN Evaluation Write-Up

**Project:** Hybrid Classical + Post-Quantum VPN (PQ-VPN)
**Date:** 2026-10-03
**Status:** *defensible baseline* — security and handshake-byte results are final
and committed; connect-time, CPU, and data-plane cells are **marked PENDING** and
must be produced by a run on a capable host (see `RERUN_COMMANDS.md`). No number
in this document is estimated or synthesized.

---

## 0. The claim this evaluation defends

> PQ-VPN's contribution is **post-quantum confidentiality** with a **formally
> verified handshake** and **post-compromise security (PCS)**, at a **competitive
> handshake cost** (time, bytes, CPU). It is **not** claimed to beat kernel VPNs
> on data-plane throughput — it is Python user-space TUN, so it is expected to be
> slower there. Throughput and latency are reported as honest context, not a win.

Everything below is organized around that claim. Where the data cannot yet
support a quantitative statement, the statement is withheld (marked **PENDING**),
not weakened into something misleading and not inflated.

---

## 1. Headline findings

### 1.1 Security position — **supported, final**

PQ-VPN's v3 handshake and its post-compromise re-handshake are **formally
verified in Tamarin**: 13 lemmas across two theories, **all `verified`**.

| Theory | Lemmas | Result | Tooling |
|---|---|---|---|
| `formal/pqvpn_v3.spthy` (handshake) | 7 | 7/7 verified | Tamarin 1.12.0 / Maude 3.5.1, default heuristic, 20.9 s |
| `formal/pqvpn_v3_pcs.spthy` (PCS) | 6 | 6/6 verified | Tamarin 1.12.0 / Maude 3.5.1, `S` heuristic, 3.5 s |

Properties proved include session-key secrecy (secret unless **both** long-term
keys are compromised — the hybrid guarantee), forward secrecy, mutual injective
authentication, KCI resistance on both sides, and PCS recovery of a fresh epoch
after control-key-only and full-epoch passive compromise. The one exists-trace
"attack" lemma documents the **stated limitation** (an active adversary holding
full epoch state can complete a re-handshake). See
`figures/formal_verification.svg` and `formal/results/verify-2026-10-02.txt`.

**This is PQ-VPN's strongest, fully reproducible result and directly supports the
"PQ + verified-handshake + PCS" half of the claim.** No baseline in this study
(WireGuard, Rosenpass, strongSwan) ships a machine-checked proof of its handshake.

### 1.2 Handshake cost — **bytes supported; time & CPU PENDING**

Handshake **wire sizes** are protocol-determined and therefore deterministic and
network-independent (reproducible with `python eval/run_pqvpn.py`):

| Suite | ClientHello | ServerHello | ClientKeyExchange | ServerFinished | **Total** |
|---|---:|---:|---:|---:|---:|
| v2-ed25519 (X25519 + ML-KEM-768, Ed25519 client auth) | 1 318 B | 1 222 B | 1 190 B | 38 B | **3 768 B** |
| v3-kem (KEM client auth) | 1 318 B | 2 310 B | 1 126 B | 38 B | **4 792 B** |
| v3-mldsa (ML-DSA client auth) | 1 318 B | 1 222 B | 3 546 B | 38 B | **6 124 B** |

See `figures/handshake_wire_sizes.svg`. These are a few kilobytes — the expected
magnitude for a hybrid ML-KEM-768 handshake, dominated by PQ public keys /
ciphertexts / signatures — and are a one-time cost per session establishment.

Handshake **time (connect, M1)** and **CPU** vs the three baselines are **PENDING
a host run** — no committed cells exist (see §2 and the Validity Report).

### 1.3 Data-plane throughput / latency — **PENDING, and framed as context**

No networked data-plane throughput benchmark is implemented yet (only an
in-process crypto-core throughput ceiling exists, which is not comparable to a
kernel VPN and is not reported here as throughput). When measured, PQ-VPN's
Python user-space TUN data plane is **expected to be slower than in-kernel
WireGuard/strongSwan**; that is an accepted consequence of the design, reported
as context, never as a win. **No sentence in this write-up claims PQ-VPN is faster
than kernel WireGuard on the data plane.**

---

## 2. Results tables (median + 95% CI)

All connect-time cells use the shared netns+veth+tc-netem topology and the M1
definition (wall-clock from bringing the client up to the first successful ping
through the tunnel), `n ≥ 30` runs per cell, median with 95 % bootstrap CI
(10 000 resamples, seed 42) via `eval/generate_tables.py`.

**These tables are intentionally unfilled.** They are the exact shape the host
run must populate; filling them with anything other than measured values would
violate the project's guardrails.

### Table A — Connect time M1 (ms), by system × profile

| System | lan | metro (50 ms) | continent (200 ms) | lossy-1 (1 %) | lossy-5 (5 %) | mtu-1280 |
|---|---|---|---|---|---|---|
| pqvpn-net | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| wireguard | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| rosenpass | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |
| strongswan | PENDING | PENDING | PENDING | PENDING | PENDING | PENDING |

*Expected qualitative shape (a validity check, not a result): each system's
connect time should rise from `lan` → `metro` → `continent` roughly in step with
added RTT, and degrade further under `lossy-5`. A cell flat across profiles means
netem was not on that path — treat it as suspect.*

### Table B — Handshake CPU (ms), PQ-VPN suites (client / server split)

| Suite | client_cpu_ms | server_cpu_ms |
|---|---|---|
| v2-ed25519 | PENDING | PENDING |
| v3-kem | PENDING | PENDING |
| v3-mldsa | PENDING | PENDING |

*Reproducible now via `run_pqvpn.py` (in-process, `profile=in-process`); report
as crypto CPU cost, not connect time.*

### Table C — Handshake wire bytes — **FINAL** (see §1.2)

Filled above; these do not need a host run.

### Table D — Data-plane throughput (Mbps) / latency (ms) — benchmark not implemented

| System | throughput | p50 latency |
|---|---|---|
| (all) | NOT MEASURED — runner outstanding | NOT MEASURED |

---

## 3. Interpretation

**Where PQ-VPN wins.**
- *Quantum-resistant confidentiality today.* The handshake mixes X25519 and
  ML-KEM-768; session keys stay secret unless **both** are broken
  (`session_key_secrecy`, verified). A harvest-now-decrypt-later adversary who
  later breaks X25519 still faces ML-KEM-768.
- *Machine-checked handshake + PCS.* 13/13 Tamarin lemmas, including re-handshake
  recovery after compromise. This is a qualitative capability none of the
  baselines provide, and it is fully reproducible from the committed models.
- *Competitive handshake bytes.* A 3.8–6.1 KB hybrid handshake is in the expected
  band for ML-KEM-768-class protocols and is a one-time per-session cost.

**Where PQ-VPN trades off (honestly).**
- *Data-plane throughput.* Python user-space TUN cannot match an in-kernel data
  path. This is expected and acceptable **for the stated threat model**: the
  contribution is confidentiality and a verified handshake against a future
  quantum adversary, not line-rate forwarding. Deployments that need kernel
  throughput can pair the PQ control plane with a kernel data plane (the Rosenpass
  model) — a direction, not a current claim.

**Why the trade-off is acceptable.** The threat being addressed is *store-now,
decrypt-later* harvesting of long-lived secrets. The cost that matters there is
the confidentiality guarantee and the soundness of the handshake, both of which
PQ-VPN pays for in a few kilobytes and a formally verified exchange. Throughput
is a deployment-engineering concern orthogonal to that guarantee.

---

## 4. Threats to validity

1. **Python vs kernel fairness.** PQ-VPN is user-space Python + TUN; WireGuard and
   strongSwan are in-kernel; Rosenpass is user-space PQ control plane + kernel
   WireGuard data plane. Handshake-cost comparisons are fair (same M1, same netem,
   same topology). **Data-plane throughput comparisons are inherently
   Python-vs-kernel** and must be presented as context only.
2. **Sample sizes.** Connect-time cells target `n ≥ 30`; the in-process crypto
   microbenchmarks default to `n = 50`. Single-shot aggregates (`handshakes_per_sec`,
   `encrypt_*`, memory) are point estimates without a CI and are secondary.
3. **Excluded / absent cells.** Everything in Tables A, B (as committed), and D is
   absent pending a host run; nothing was back-filled. In-process latency and
   crypto throughput are **excluded** from any networked comparison by
   construction (labelled `profile=in-process`).
4. **New baseline runners need host validation.** `run_rosenpass.sh` and
   `run_strongswan.sh` are written to the shared topology/M1 contract but have
   **not** been executed here (no `rp`/`swanctl`/netem in this environment). They
   fail fast rather than emit empty data, but a dry run on the host must confirm
   the tunnel actually comes up before their numbers are trusted. The CLI surface
   of both tools varies by version — verify against the installed versions.
5. **Environment specifics.** CPU model, governor (should be `performance`),
   kernel, liboqs version, and git commit must be recorded; the orchestrator
   writes `sanity.json` and every networked row now carries per-row provenance.
   Pin the governor and avoid a noisy host.
6. **Native crypto gate.** Every PQ-VPN path aborts unless
   `pqc_mode == native_liboqs`; mock mode (`ALLOW_MOCK_PQC=1`) is rejected. No
   mock or in-process number is to be presented as a networked result.

---

## 5. Reproducibility pointer

**Host prerequisites (hard gate):** Linux with `CAP_NET_ADMIN` (root),
`iproute2` (`ip`, `tc`/netem), WireGuard (`wg`, `wg-quick`), Rosenpass (`rp`),
strongSwan (`swanctl` + `charon`), and **native liboqs 0.16.0** with the `oqs`
Python binding so that `pqc_mode == native_liboqs`.

```bash
# 0. Confirm the native-crypto gate
python -c "from crypto.hybrid_crypto import get_crypto_status as s; print(s()['pqc_mode'])"
#   -> must print: native_liboqs

# 1. Full campaign, all systems, all six profiles
sudo python eval/run_all.py --iterations 50 --net-iterations 30

# 2. Regenerate tables/figures from the raw CSVs
python eval/generate_tables.py \
    --input  results/eval-<timestamp>/raw \
    --output results/eval-<timestamp>/figures

# 3. Formal verification (already committed; re-check if desired)
./scripts/verify_formal.sh    # expects 13/13 verified
```

Exact per-cell commands, the capable-host checklist, and a dry-run validation
step for the new baselines are in **`RERUN_COMMANDS.md`**. The committed evidence
lives at: `formal/results/` (proofs), `eval/results-summary/figures/` (final
figures), and — after the host run — `results/eval-<timestamp>/` locally plus a
copied summary under `eval/results-summary/` (because `results/` is git-ignored).

---

## 6. Figures

| File | What it shows | Source |
|---|---|---|
| `figures/handshake_wire_sizes.svg` | PQ-VPN handshake wire size by suite (final) | deterministic; `run_pqvpn.py` / ARTIFACT.md |
| `figures/formal_verification.svg` | 13/13 lemma verification status (final) | `formal/results/verify-2026-10-02.txt` |
| `figures/connect_time_comparison.png` *(after host run)* | M1 connect time, median + 95 % CI | `generate_tables.py` |
| `figures/latency_comparison.png` *(after host run)* | per-system latency, median + 95 % CI | `generate_tables.py` |
