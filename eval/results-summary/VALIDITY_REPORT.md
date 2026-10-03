# PQ-VPN Evaluation — Validity Report

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
> gaps that caused this are now fixed (see `RERUN_COMMANDS.md`); the cells
> themselves must be produced by a run on a capable host.

---

## 1. How the results were located

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

## 2. Per-check findings (Step 1 checklist)

| Check | Status | Finding / root cause |
|---|---|---|
| **Native crypto only** (`pqc_mode == native_liboqs`, real `liboqs_version`) | ⚠️ Cannot confirm from data | No rows exist to inspect. The guard itself is correct: `run_pqvpn.py:require_native_pqc`, `run_all.py:_require_native_pqc`, and `run_pqvpn_net.sh` all `sys.exit(1)`/`exit 1` on non-native mode (verified by `tests/test_eval_harness.py::test_pqc_guard_rejects_mock/_unavailable`). **Per-row** liboqs provenance did **not** exist in the schema; now added to the networked runners. |
| **Sample size + CI ≥ 30 runs, median + 95% bootstrap CI** | ⚠️ Cannot confirm from data | No cells. The aggregation path is sound: `generate_tables.bootstrap_ci` (10 000 resamples, seed 42) is deterministic and tested. Default `--net-iterations` is 30 (meets the floor); in-process default is 50. |
| **Profiles actually applied** (connect time scales with profile; `continent` ≫ `lan`) | ❌ Could not have been satisfied for baselines | `run_pqvpn_net.sh` applies netem per profile correctly. **But `run_wireguard.sh` hard-coded `profile=lan` and applied *no* netem at all** — WireGuard could only ever produce a single flat `lan` cell. Fixed: WG now takes a profile and applies the shared netem table. |
| **Same topology/schema for every system** | ❌ Not satisfied | PQ-VPN-net used netns+veth+netem; WireGuard used netns+veth but **no netem** and only `lan`; Rosenpass/strongSwan **did not exist**. Fixed: all baselines now source `eval/netem_profiles.sh` (identical RTT/loss/MTU table) and share the M1 definition. |
| **A baseline that silently "completed" with no data is a hole** | ❌ Latent bug | `run_all.py` appended failures to `skipped`, never to `failed` (the `failed` list was dead), so a broken baseline reported as "Skipped", not "Failed". Fixed: failures are tracked and the orchestrator now exits non-zero on any failed unit. New baseline runners fail fast (exit 1) when their tool is missing — never exit 0 with an empty CSV. |
| **Baselines present** (WireGuard, Rosenpass, strongSwan) | ❌ 2 of 3 missing | `ARTIFACT.md` states verbatim: *"OpenVPN, Rosenpass, and strongSwan baselines are not implemented; the scaffold stubs that previously existed have been removed."* Only WireGuard had a runner (and it was lan-only). Fixed: `eval/run_rosenpass.sh` and `eval/run_strongswan.sh` added (require host validation — see below). |
| **Metadata per row** (git commit, liboqs version, CPU, governor, kernel) | ❌ Not in schema | The unified schema was 6 columns (`system,profile,metric,run,value,unit`) with no provenance; metadata lived only in a separate `sanity.json`. Fixed: the networked runners now append `git_commit,liboqs_version,cpu_model,governor,kernel` to every row (`generate_tables` tolerates the extra columns). In-process `run_pqvpn.py` keeps the 6-column schema (its test asserts exactly 6 columns); its provenance is in `sanity.json`. |

---

## 3. Additional harness findings (beyond the checklist)

1. **The real networked connect-time runner was never orchestrated.**
   `run_pqvpn_net.sh` (the genuine M1 benchmark) existed but `run_all.py` only
   ran `run_pqvpn.py` (in-process) and `run_wireguard.sh` (lan-only). A campaign
   driven by `run_all.py` would therefore have produced **in-process PQ-VPN
   numbers and a single lan WireGuard number** — and if the in-process
   `latency_ms` were presented as "connect time", that would be exactly the
   mock/in-process-as-networked error the brief forbids. Fixed: `pqvpn-net` and
   the three baselines are now first-class networked systems in the orchestrator,
   swept across all six profiles.

2. **No networked data-plane throughput (M2) benchmark exists.** `run_pqvpn.py`
   measures `encrypt_pps`/`encrypt_mbps` **in-process** (one process calling
   `encrypt_frame` in a loop). That is a crypto-core ceiling, **not** throughput
   through a TUN tunnel over the link, and it has no baseline counterpart. It
   must not be reported as data-plane throughput. A networked throughput runner
   (iperf3 through the tunnel) is **not implemented** — listed as outstanding in
   `RERUN_COMMANDS.md` / `REMAINING_STEPS.md`.

3. **In-process labelling is honest.** `run_pqvpn.py` correctly stamps its rows
   `profile=in-process`, so they cannot be silently mistaken for a netem profile.
   Its **wire-byte** and **CPU** rows are network-independent and legitimate; its
   `latency_ms`/`encrypt_*` rows are crypto-only and must be labelled as such.

---

## 4. Cell-by-cell status matrix

Legend: ✅ trustworthy & committed · 🟡 reproducible-but-not-committed ·
❌ absent (needs host run) · n/a not defined.

### Security / correctness
| Cell | Status | Evidence |
|---|---|---|
| Handshake model, 7 lemmas | ✅ | `formal/results/handshake-verify.txt` — all `verified` |
| PCS model, 6 lemmas | ✅ | `formal/results/pcs-verify.txt` — all `verified` |

### Handshake cost — bytes
| System | Status | Evidence |
|---|---|---|
| PQ-VPN v2-ed25519 / v3-kem / v3-mldsa wire bytes | 🟡 | Deterministic, in `ARTIFACT.md`; reproduce with `python eval/run_pqvpn.py`. Not committed as a CSV. |
| WireGuard / Rosenpass / strongSwan handshake bytes | ❌ | No capture committed; no byte-capture step in any runner. |

### Handshake cost — time (M1 connect) & CPU
| System × {lan,metro,continent,lossy-1,lossy-5,mtu-1280} | Status |
|---|---|
| pqvpn-net | ❌ absent (runner exists; never orchestrated/committed) |
| wireguard | ❌ absent (runner was lan-only, no netem — now fixed) |
| rosenpass | ❌ absent (**no runner existed** — now added, needs host validation) |
| strongswan | ❌ absent (**no runner existed** — now added, needs host validation) |
| PQ-VPN client/server CPU (in-process) | 🟡 reproducible via `run_pqvpn.py`; not committed |

### Data-plane throughput / latency (M2)
| Cell | Status |
|---|---|
| Networked throughput through tunnel, any system | ❌ **no benchmark implemented** (only in-process crypto throughput exists) |

---

## 5. What this means for the paper

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
