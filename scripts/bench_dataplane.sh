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
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT=${1:-$ROOT/eval/results-summary/phase2-$(date +%F)}
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
      run "m5 $protocol $plane $run" "$PY" eval/measure_throughput.py --profiles lan --duration 20 \
        --protocol "$protocol" --data-plane "$plane" --out "$OUT/m5-$protocol-$plane-run$run.csv"
    done
  done
done

# --- M1 cold + warm, and M7, on the rust data plane ---
run "m1 rust lan" env PYTHON="$PY" bash eval/run_pqvpn_net.sh lan --iterations 30 --data-plane rust \
  --out "$OUT/pqvpn-net-lan-rust.csv"
run "m7 rust" "$PY" eval/flood_clienthello.py --rates 0,100,1000 --data-plane rust --out "$OUT/m7-flood-rust.csv"
chown -R "$SUDO_USER": "$OUT"

[[ $(as_user git -C "$ROOT" rev-parse HEAD) == "$COMMIT" ]] || { echo "HEAD moved during the run" >&2; exit 1; }

# --- Medians and gates ---
"$PY" - "$OUT" <<'PYEOF' | tee "$OUT/summary.txt"
import csv, glob, statistics, sys
out = sys.argv[1]
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
        if plane == "rust":
            ok = mbps >= 1500 and ms <= 0.2 and len(tcp) == len(overhead) == 5
            verdict &= ok
            gate = f"  gate(>=1500 Mbps, <=0.2 ms, 5 runs): {'PASS' if ok else 'FAIL'}"
        print(f"  {protocol:10} {plane:6} n={len(tcp)} {mbps:8.1f} Mbps  {ms:.3f} ms{gate}")
print("PHASE 2 GATES:", "PASS" if verdict else "FAIL")
PYEOF

if (( ${#FAILED[@]} )); then
  printf 'failed steps: %s\n' "${FAILED[@]}" | tee -a "$OUT/summary.txt" >&2
  exit 1
fi
echo "Results: $OUT"
