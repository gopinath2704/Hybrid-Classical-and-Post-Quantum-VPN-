# PQ-VPN Evaluation — Results Summary

Tracked home for the PQ-VPN evaluation deliverable. `results/` is git-ignored, so
the paper-facing summary and figures live here instead.

## Contents

| File | What it is |
|---|---|
| [`EVALUATION.md`](EVALUATION.md) | The evaluation write-up: claim, headline findings, tables (median + 95 % CI), interpretation, threats to validity, reproducibility pointer. |
| [Validity report](../../docs/evaluation.md#validity-report) | Per-cell validation of the campaign: what is trustworthy, missing, or suspect, with the concrete root cause for each. |
| [Re-run commands](../../docs/evaluation.md#re-run-commands) | Exact commands + host prerequisites to produce the PENDING cells on a capable host; dry-run validation for the new baselines. |
| [Remaining steps](../../docs/evaluation.md#remaining-steps) | What is still outstanding for the paper/artifact, in recommended order. |
| `figures/handshake_wire_sizes.svg` | **Final** — PQ-VPN handshake wire size by suite (deterministic). |
| `figures/formal_verification.svg` | **Final** — 13/13 Tamarin lemmas verified. |

## Status at a glance

- ✅ **Final & committed:** formal verification (13/13 lemmas); PQ-VPN handshake
  wire sizes (3 768 / 4 792 / 6 124 B).
- ⏳ **PENDING a capable-host run (never estimated):** connect time (M1) per
  system × profile; handshake CPU vs baselines; baseline wire bytes.
- 🔧 **Implemented, awaiting capable-host run:** networked data-plane throughput/latency (M2) via `eval/measure_throughput.py`; memory profiling via `eval/measure_memory.py`.

## Why cells are PENDING

The campaign described in the project plan was **not committed** (the `results/`
output path is git-ignored and nothing was exported to a tracked location), and
this preparation environment is not netem/WireGuard/liboqs-capable, so results
could not be regenerated here. Rather than fabricate numbers, the trustworthy
committed evidence is reported as final, the rest is marked PENDING, the harness
gaps that would have corrupted a future run are fixed, and exact re-run commands
are provided. See the [validity report](../../docs/evaluation.md#validity-report) for the full account.

## Harness changes made in this pass (eval files only)

- `eval/netem_profiles.sh` *(new)* — shared RTT/loss/MTU table + netem helpers so
  every system uses identical topology; per-row provenance helper.
- `eval/run_wireguard.sh` — now profile-aware and netem-matched (was lan-only,
  no netem); emits per-row provenance; still fails fast when `wg` is missing.
- `eval/run_rosenpass.sh`, `eval/run_strongswan.sh` *(new)* — the two missing
  baselines, on the shared topology/M1/schema contract; fail fast (never empty).
- `eval/run_all.py` — orchestrates the networked connect-time systems across all
  six profiles (previously only in-process PQ-VPN + lan-only WireGuard); fixes the
  dead `failed` list so failures are reported, not mislabelled "skipped"; exits
  non-zero on any failed unit; records CPU model/kernel/governor in `sanity.json`.

No `handshake/`, `crypto/`, `vpn/`, or `formal/` files were changed.

## Gate-run archives

Each `scripts/bench_dataplane.sh` gate run is packed into one archive (raw CSVs, `environment.txt`,
per-run logs). Open one with `tar -xzf <archive>`. Pack a new run the same way before committing:
`tar --sort=name --owner=0 --group=0 -C eval/results-summary -cf - phaseN-<date> | gzip -9n > eval/results-summary/phaseN-<date>.tar.gz`.

| Archive |
|---|
| `phase0-2026-10-28.tar.gz` |
| `phase1-nodelay-2026-10-29.tar.gz` |
| `phase1-warm-2026-10-29.tar.gz` |
| `phase2-2026-10-29.tar.gz` |
| `phase3-2026-10-29.tar.gz` |
| `phase4-2026-10-30.tar.gz` |

### Phase 0 caveat

The `pqvpn-net` M1 rows for metro, continent, lossy and mtu-1280 are resumed connects: `run_pqvpn_net.sh` never removed the resumption ticket, so runs 1-29 reused the ticket saved by run 0.
True cold connect is run 0 in the raw CSVs (metro 462 ms, continent 1364 ms) or `full_connect_ms` in `resumption-*.csv`. LAN is unaffected (RTT ≈ 0).
Fixed in Phase 1, which also changed the poll interval, so Phase 1 M1 numbers are not directly comparable with these rows.
