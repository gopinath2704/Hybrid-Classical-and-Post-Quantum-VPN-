# Remaining Steps for the Paper / Artifact

What is still outstanding after this evaluation pass, in **recommended order**.
Items 1–2 are blocking for any quantitative claim; 3–5 are artifact packaging;
6 is optional.

### 1. ~~Run the campaign on a capable host and commit the numbers~~ — **done**
Tables A/B/C/D filled from real harness output on i7-11800H with native liboqs.
All PQ-VPN cells measured with `pqc_mode == native_liboqs`. M1 connect time
(n=30), M2 CPU (n=50), M3 wire bytes (n=10), M5 throughput, M6–M8 all committed.
Session resumption (n=20, v3-kem) added: −20% metro, −18% continent.
v3-kem on-wire bytes (17 packets, 5 745 B) and throughput added.
Rosenpass and strongSwan baselines still not run.

### 2. ~~Run the data-plane throughput/latency benchmark~~ — **done**
`eval/measure_throughput.py` with `--protocol {v2-ed25519, v3-kem}`.
Measured on i7-11800H for both v2 and v3-kem across all 6 profiles.
v2: 613 Mbps LAN; v3-kem: 335 Mbps LAN (same AES-256-GCM cipher; variance
is run-to-run, not protocol). RTT overhead 0.3–1.2 ms.

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
