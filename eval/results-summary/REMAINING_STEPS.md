# Remaining Steps for the Paper / Artifact

What is still outstanding after this evaluation pass, in **recommended order**.
Items 1–2 are blocking for any quantitative claim; 3–5 are artifact packaging;
6 is optional.

### 1. Run the campaign on a capable host and commit the numbers — **blocking**
Fill Tables A/B/D of `EVALUATION.md` from real harness output.
- Follow `RERUN_COMMANDS.md` §1–§3 on a netem + WireGuard + Rosenpass +
  strongSwan + native-liboqs host.
- First validate the two new baseline runners (`RERUN_COMMANDS.md` §4).
- Commit `summary.csv`/`summary.txt`/`*.png`/`sanity.json` into
  `eval/results-summary/` (because `results/` is git-ignored).
- **Gate:** every PQ-VPN cell `pqc_mode == native_liboqs`; every cell `n ≥ 30`
  with a 95 % CI; connect time scales with profile (not flat).

### 2. Implement + run the data-plane throughput/latency benchmark (M2) — **blocking for the trade-off claim**
No networked throughput runner exists (see `RERUN_COMMANDS.md` §5). Add an
`iperf3`-through-the-tunnel runner on the shared topology, run it for PQ-VPN and
the baselines, and report the trade-off honestly. Until this exists, the paper
can only state the throughput trade-off qualitatively.

### 3. Create the `v3-paper-artifact` tag — **not yet done**
`ARTIFACT.md` claims *"This artifact is tagged as `v3-paper-artifact`"*, but the
only tag in the repo is `v2-minimal-layout`. Tag the commit that contains the
committed campaign results (do this **after** step 1 so the tag captures real
numbers), then update `ARTIFACT.md`'s "Release tag" section if anything moved.

### 4. Record the ARTIFACT.md "recorded-run" table
`ARTIFACT.md` has a recorded-run table for the **formal** proofs but not for the
**evaluation campaign**. Add a recorded-run table for the campaign (host CPU,
governor, kernel, liboqs version, git commit, date, per-cell `n`) sourced from
`sanity.json` — the per-row provenance now carried in the CSVs makes this exact.

### 5. Mint the Zenodo DOI
After the `v3-paper-artifact` tag exists and the results are committed, archive
the tagged release to Zenodo and record the DOI in `README.md` and `ARTIFACT.md`.
Do this last among packaging steps so the DOI points at the final artifact.

### 6. Optional: live VPS check
A single real-Internet client↔VPS connect-time + short iperf3 run, reported
separately as a sanity cross-check of the netns/netem numbers (clearly labelled
"single run, not part of the CI'd campaign"). Nice-to-have, not required for the
core claim.

### 7. Write the paper draft
With steps 1–4 committed, draft the paper: lead with the security contribution
(PQ + verified handshake + PCS, 13/13 lemmas), then handshake cost (bytes final;
time/CPU from step 1), then the honest throughput trade-off (step 2). Reuse
`EVALUATION.md` §1/§3/§4 as the skeleton for Results / Discussion / Threats.

---

## Recommended order (summary)

```
1. Host campaign run + commit numbers      (blocking)
2. Data-plane throughput runner + run      (blocking for trade-off)
3. Tag v3-paper-artifact                    (after 1)
4. ARTIFACT.md campaign recorded-run table  (after 1)
5. Zenodo DOI                               (after 3)
6. Live VPS cross-check                      (optional)
7. Paper draft                               (after 1–4)
```

> Do not reorder 3/5 before 1: tagging or minting a DOI before real numbers are
> committed would archive an artifact with empty result tables.
