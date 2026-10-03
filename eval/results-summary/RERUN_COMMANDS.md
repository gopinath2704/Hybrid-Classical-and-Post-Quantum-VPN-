# Re-run Commands — producing the PENDING cells on a capable host

This evaluation was prepared in a container that is **not** netem/WireGuard/
liboqs-capable, so the connect-time, CPU, and data-plane cells were deliberately
left PENDING rather than estimated. Run the commands below on a proper host to
fill them. **Do not commit fabricated or hand-edited numbers — only
harness output.**

---

## 1. Host capability gate (run first)

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

## 2. One command for the whole campaign

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

## 3. Per-cell commands (if you want to run cells individually)

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

## 4. Validate the two new baselines before trusting them

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

## 5. Still outstanding: networked data-plane throughput (M2)

There is **no** networked throughput/latency-under-load runner yet (the existing
`encrypt_pps`/`encrypt_mbps` are in-process crypto-core numbers, not through the
tunnel, and have no baseline). To report the data-plane trade-off honestly it
must be added, e.g. an `iperf3`-through-the-tunnel runner on the same
netns+veth+netem topology, emitting `*,<profile>,throughput_mbps,<run>,<v>,Mbps`
and a steady-state `rtt_ms`. Until then, the throughput/latency trade-off is
stated qualitatively only (see `EVALUATION.md` §1.3).

---

## 6. Publish the results so they survive

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
