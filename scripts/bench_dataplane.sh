#!/usr/bin/env bash
# Data-plane benchmark for the Rust-core migration gates (Phase 2: M5 LAN >= 1500 Mbps and tunnel
# RTT overhead <= 0.2 ms, each the median of 5 runs). Everything runs on ONE commit:
#   - M5 LAN, v2-ed25519 and v3-kem, 5 runs each, python vs rust (interleaved per run)
#   - M1 LAN cold + warm connect, rust data plane
#   - M7 ClientHello flood, rust data plane
# Pins every CPU's governor to performance and restores it on exit. Builds pqvpn_core in
# release mode as the invoking user, and runs all Python through .venv/bin/python.
#
# Usage: sudo scripts/bench_dataplane.sh [OUT_DIR]   (default eval/results-summary/phase2-<date>)
#
# PHASE=3 (sudo env PHASE=3 scripts/bench_dataplane.sh) gates Phase 3 instead: M5 LAN rust
# >= 3000 Mbps TCP, a fixed-rate UDP goodput sweep on rust (UDP_RATES, max rate with <1% loss
# reported) and M7 at 0,1000,10000/s with every legitimate connect succeeding at 10000/s.
# Output goes to eval/results-summary/phase3-<date>.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PHASE=${PHASE:-2}
[[ $PHASE == 2 || $PHASE == 3 ]] || { echo "PHASE must be 2 or 3" >&2; exit 1; }
UDP_RATES=${UDP_RATES:-100M,500M,1G,2G,3G,4G}
OUT=${1:-$ROOT/eval/results-summary/phase$PHASE-$(date +%F)}
PY=$ROOT/.venv/bin/python
RUNS=5
# Root must not leave root-owned .pyc files in the user's tree.
export PYTHONDONTWRITEBYTECODE=1
cd "$ROOT"
[[ $EUID -eq 0 && -n ${SUDO_USER:-} ]] || { echo "run with sudo from your user account" >&2; exit 1; }
as_user() { sudo -u "$SUDO_USER" -H env "PATH=$PATH" "$@"; }
[[ -x $PY ]] || { echo "missing $PY (create the venv first)" >&2; exit 1; }
command -v iperf3 >/dev/null || { echo "iperf3 not found" >&2; exit 1; }

# --- Pin the governor; restore each CPU's own value however the script ends ---
declare -A GOVERNOR
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do GOVERNOR[$g]=$(<"$g"); done
restore() { for g in "${!GOVERNOR[@]}"; do echo "${GOVERNOR[$g]}" >"$g" 2>/dev/null || true; done; }
trap restore EXIT
for g in "${!GOVERNOR[@]}"; do echo performance >"$g"; done

# --- Release build of the Rust core into the venv (as the user: their rustup toolchain) ---
as_user env VIRTUAL_ENV="$ROOT/.venv" maturin develop --release -m "$ROOT/core/pqvpn_core/Cargo.toml"
"$PY" -c "import pqvpn_core; pqvpn_core.DataPlane"

# --- Environment ---
as_user mkdir -p "$OUT"
COMMIT=$(as_user git -C "$ROOT" rev-parse HEAD)
DIRTY=$(as_user git -C "$ROOT" status --porcelain | wc -l)
{
  echo "commit: $COMMIT ($([[ $DIRTY -eq 0 ]] && echo clean || echo "DIRTY: $DIRTY paths modified or untracked"))"
  echo "date: $(date -Iseconds)"
  echo "kernel: $(uname -r)"
  echo "governor: performance (was $(printf '%s\n' "${GOVERNOR[@]}" | sort -u | paste -sd,))"
  grep -m1 'model name' /proc/cpuinfo
  grep -m1 -o -w -E 'aes|avx2|vaes' /proc/cpuinfo | sort -u | paste -sd' '
  echo "on_ac: $(cat /sys/class/power_supply/A*/online 2>/dev/null | head -n1)"
  "$PY" --version
  "$PY" -c "from crypto.hybrid_crypto import get_crypto_status as s; print('pqc_mode', s()['pqc_mode'])"
  echo "rustc: $(cd "$ROOT/core" && as_user rustc --version)"
  echo "pqvpn_core: maturin develop --release"
} | tee "$OUT/environment.txt"

FAILED=()
run() { local name=$1; shift; echo "=== $name"; "$@" || { echo "FAILED: $name" >&2; FAILED+=("$name"); }; }

# --- M5 LAN: python vs rust, interleaved so drift hits both equally ---
for run in $(seq 1 $RUNS); do
  for protocol in v2-ed25519 v3-kem; do
    for plane in python rust; do
      UDP=(); [[ $PHASE == 3 && $plane == rust ]] && UDP=(--udp-rates "$UDP_RATES")
      run "m5 $protocol $plane $run" "$PY" eval/measure_throughput.py --profiles lan --duration 20 \
        --protocol "$protocol" --data-plane "$plane" "${UDP[@]}" --out "$OUT/m5-$protocol-$plane-run$run.csv"
    done
  done
done

# --- M1 cold + warm, and M7, on the rust data plane ---
run "m1 rust lan" env PYTHON="$PY" bash eval/run_pqvpn_net.sh lan --iterations 30 --data-plane rust \
  --out "$OUT/pqvpn-net-lan-rust.csv"
M7_RATES=0,100,1000; [[ $PHASE == 3 ]] && M7_RATES=0,1000,10000
run "m7 rust" "$PY" eval/flood_clienthello.py --rates "$M7_RATES" --data-plane rust --out "$OUT/m7-flood-rust.csv"
chown -R "$SUDO_USER": "$OUT"

[[ $(as_user git -C "$ROOT" rev-parse HEAD) == "$COMMIT" ]] || { echo "HEAD moved during the run" >&2; exit 1; }

# --- Medians and gates ---
"$PY" - "$OUT" "$PHASE" <<'PYEOF' | tee "$OUT/summary.txt"
import csv, glob, os, statistics, sys
out, phase = sys.argv[1], int(sys.argv[2])
print("M5 LAN, median of runs: tcp_received_mbps, tunnel_rtt_ms - bare_rtt_ms")
verdict = True
for protocol in ("v2-ed25519", "v3-kem"):
    for plane in ("python", "rust"):
        tcp, overhead = [], []
        for path in sorted(glob.glob(f"{out}/m5-{protocol}-{plane}-run*.csv")):
            rows = {r["metric"]: float(r["value"]) for r in csv.DictReader(open(path)) if r["profile"] == "lan"}
            if "tcp_received_mbps" in rows:
                tcp.append(rows["tcp_received_mbps"])
            if "tunnel_rtt_ms" in rows and "bare_rtt_ms" in rows:
                overhead.append(rows["tunnel_rtt_ms"] - rows["bare_rtt_ms"])
        if not tcp or not overhead:
            print(f"  {protocol:10} {plane:6} NO DATA"); verdict = False; continue
        mbps, ms = statistics.median(tcp), statistics.median(overhead)
        gate = ""
        if plane == "rust" and phase == 2:
            ok = mbps >= 1500 and ms <= 0.2 and len(tcp) == len(overhead) == 5
            verdict &= ok
            gate = f"  gate(>=1500 Mbps, <=0.2 ms, 5 runs): {'PASS' if ok else 'FAIL'}"
        elif plane == "rust":
            ok = mbps >= 3000 and len(tcp) == 5
            verdict &= ok
            gate = f"  gate(>=3000 Mbps, 5 runs): {'PASS' if ok else 'FAIL'}"
        print(f"  {protocol:10} {plane:6} n={len(tcp)} {mbps:8.1f} Mbps  {ms:.3f} ms{gate}")
if phase == 3:
    print("M5 LAN UDP sweep, rust, median of runs: goodput Mbps (loss %) per offered rate")
    for protocol in ("v2-ed25519", "v3-kem"):
        runs = [{r["metric"]: float(r["value"]) for r in csv.DictReader(open(path)) if r["profile"] == "lan"}
                for path in sorted(glob.glob(f"{out}/m5-{protocol}-rust-run*.csv"))]
        best = [r["udp_max_rate_under_1pct_loss_mbps"] for r in runs if "udp_max_rate_under_1pct_loss_mbps" in r]
        rates = sorted({int(m.split("@")[1]) for r in runs for m in r if m.startswith("udp_goodput_mbps@")})
        for rate in rates:
            good = [r[f"udp_goodput_mbps@{rate}"] for r in runs if f"udp_goodput_mbps@{rate}" in r]
            lost = [r[f"udp_lost_pct@{rate}"] for r in runs if f"udp_lost_pct@{rate}" in r]
            print(f"  {protocol:10} @{rate:>5} n={len(good)} {statistics.median(good):8.1f} Mbps"
                  f" ({statistics.median(lost):.3f}%)")
        ok = len(best) == 5
        verdict &= ok
        median = f"{statistics.median(best):.0f} Mbps" if best else "NO DATA"
        print(f"  {protocol:10} max rate with <1% loss, n={len(best)}: {median}"
              f"  gate(reported, 5 runs): {'PASS' if ok else 'FAIL'}")
    print("M7 ClientHello flood at 10000/s, rust: legitimate connects, offered flood rate")
    m7 = {}
    m7_path = f"{out}/m7-flood-rust.csv"
    for r in csv.DictReader(open(m7_path)) if os.path.exists(m7_path) else []:
        if r["profile"] == "flood-10000":
            m7.setdefault(r["system"], {})[r["metric"]] = float(r["value"])
    for system in ("pqvpn-cookie-off", "pqvpn-cookie-always"):
        m = m7.get(system, {})
        ok = (m.get("connects_attempted", 0) > 0 and m["connects_succeeded"] == m["connects_attempted"]
              and m.get("flood_rate_per_s", 0) >= 9500)
        verdict &= ok
        print(f"  {system:20} {m.get('connects_succeeded', 0):.0f}/{m.get('connects_attempted', 0):.0f} connects"
              f"  offered {m.get('flood_rate_per_s', 0):.0f}/s  delivered {m.get('flood_delivered_per_s', 0):.0f}/s"
              f"  median {m.get('median_connect_time_ms', -1):.0f} ms"
              f"  gate(all connects, offered >=9500/s): {'PASS' if ok else 'FAIL'}")
print(f"PHASE {phase} GATES:", "PASS" if verdict else "FAIL")
PYEOF

if (( ${#FAILED[@]} )); then
  printf 'failed steps: %s\n' "${FAILED[@]}" | tee -a "$OUT/summary.txt" >&2
  exit 1
fi
echo "Results: $OUT"
