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
#
# PHASE=4 gates Phase 4 (docs/rust-core-migration-plan.md, Appendix A section 3), definitions unchanged from Phases 0-3:
#   - M1 LAN cold, v2, n=30, per data-plane/handshake backend, plus the pqvpnd native row
#     (gate: native cold median <= 30 ms, all 30 connected)
#   - M2 in-process, both roles, n=50, python and rust handshake (gate: v3-kem rust total <= 0.2 ms)
#   - M8 N=50, v2, cookies off, per backend (gate: <= 64 kB per session, all 50 connected)
#   - no regression: M5 (rust >= 3000 Mbps TCP), M6 hitless rekey/rehandshake (0% ping loss),
#     M7 at 0,1000,10000/s (every legitimate connect succeeds at 10000/s)
# PHASE=5 is the final M1-M8 rerun with the Phase 4 definitions and gates (output phase5-<date>).
# Backends are data_plane/handshake: python/python, rust/python, rust/rust. The pqvpnd binary is
# built from core/ when that crate exists (slice d); NATIVE=<path> overrides it.
#
# DRY_RUN=1 (no sudo needed) prints the plan and the commands without running anything.
# A dirty tree stops the run; ALLOW_DIRTY=1 runs it anyway into OUT-DIRTY with dirty.txt.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PHASE=${PHASE:-2}
DRY_RUN=${DRY_RUN:-0}
[[ $PHASE == 2 || $PHASE == 3 || $PHASE == 4 || $PHASE == 5 ]] || { echo "PHASE must be 2, 3, 4 or 5" >&2; exit 1; }
UDP_RATES=${UDP_RATES:-100M,500M,1G,2G,3G,4G,5G,6G,8G}
OUT=${1:-$ROOT/eval/results-summary/phase$PHASE-$(date +%F)}
PY=$ROOT/.venv/bin/python
RUNS=5
# Root must not leave root-owned .pyc files in the user's tree.
export PYTHONDONTWRITEBYTECODE=1
cd "$ROOT"
BACKENDS=("python python" "rust python" "rust rust")  # PHASE=4: data_plane handshake
NATIVE_GIVEN=${NATIVE:+1}
NATIVE=${NATIVE:-$ROOT/core/target/release/pqvpnd}

FAILED=()
run() {
  local name=$1; shift
  if (( DRY_RUN )); then printf '=== %s\n   %s\n' "$name" "$*"; return; fi
  echo "=== $name"; "$@" || { echo "FAILED: $name" >&2; FAILED+=("$name"); }
}

if (( DRY_RUN )); then
  echo "DRY RUN: PHASE=$PHASE OUT=$OUT (nothing runs; needs sudo for real)"
  echo "  pins every CPU governor to performance, restores on exit"
  echo "  builds pqvpn_core (maturin develop --release)$( (( PHASE >= 4 )) && echo " and pqvpnd if core/pqvpnd exists (a failed build stops the run)" )"
  echo "  writes \$OUT/environment.txt (commit, kernel, governor, CPU, python, pqc_mode, rustc, pqvpnd sha256, jitter symbols)"
fi
(( DRY_RUN )) || [[ $EUID -eq 0 && -n ${SUDO_USER:-} ]] || { echo "run with sudo from your user account" >&2; exit 1; }
# Without SUDO_USER (DRY_RUN only) commands already run as the user.
as_user() { if [[ -n ${SUDO_USER:-} ]]; then sudo -u "$SUDO_USER" -H env "PATH=$PATH" "$@"; else "$@"; fi; }
[[ -x $PY ]] || { echo "missing $PY (create the venv first)" >&2; exit 1; }

# --- A gate run must be one committed tree; ALLOW_DIRTY=1 runs anyway, labelled DIRTY everywhere ---
DIRTY_PATHS=$(as_user git -C "$ROOT" status --porcelain)
if [[ -n $DIRTY_PATHS ]]; then
  [[ ${ALLOW_DIRTY:-0} == 1 ]] || { printf 'tree is dirty (ALLOW_DIRTY=1 to run anyway):\n%s\n' "$DIRTY_PATHS" >&2; exit 1; }
  OUT+=-DIRTY
fi
(( DRY_RUN )) && echo "  OUT=$OUT$([[ -n $DIRTY_PATHS ]] && echo " (DIRTY: $(wc -l <<<"$DIRTY_PATHS") paths, listed in dirty.txt)")"
if (( ! DRY_RUN )); then
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
if (( PHASE >= 4 )) && [[ -z $NATIVE_GIVEN && -d $ROOT/core/pqvpnd ]]; then
  as_user cargo build --release --manifest-path "$ROOT/core/Cargo.toml" -p pqvpnd || { echo "pqvpnd build failed" >&2; exit 1; }
fi

# --- Environment (after every build, so it describes the binaries that run) ---
as_user mkdir -p "$OUT"
COMMIT=$(as_user git -C "$ROOT" rev-parse HEAD)
[[ -z $DIRTY_PATHS ]] || as_user tee "$OUT/dirty.txt" <<<"$DIRTY_PATHS" >/dev/null
{
  [[ -z $DIRTY_PATHS ]] || echo "DIRTY: $(wc -l <<<"$DIRTY_PATHS") paths modified or untracked (dirty.txt); not a gate run"
  echo "commit: $COMMIT ($([[ -z $DIRTY_PATHS ]] && echo clean || echo DIRTY))"
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
  # aws-lc's CPU Jitter Entropy is linked in only when the no-jitter build setting was missed: expect 0.
  jitter() { nm "$1" >/dev/null 2>&1 || { echo "unknown (nm failed)"; return; }; nm "$1" | grep -c jent_ || true; }
  echo "pqvpn_core jitter symbols: $(jitter "$("$PY" -c 'import pqvpn_core.pqvpn_core as m; print(m.__file__)')")"
  if (( PHASE >= 4 )); then
    "$PY" -c "import dataclasses; from vpn.config import ServerConfig
print('handshake switch:', 'present' if 'handshake' in {f.name for f in dataclasses.fields(ServerConfig)} else 'MISSING (slice b)')"
    echo "pqvpnd: $([[ -x $NATIVE ]] && echo "$NATIVE sha256=$(sha256sum <"$NATIVE" | cut -d' ' -f1) jitter symbols: $(jitter "$NATIVE")" || echo MISSING)"
  fi
} | tee "$OUT/environment.txt"
fi

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

if (( PHASE < 4 )); then
# --- M1 cold + warm, and M7, on the rust data plane ---
run "m1 rust lan" env PYTHON="$PY" bash eval/run_pqvpn_net.sh lan --iterations 30 --data-plane rust \
  --out "$OUT/pqvpn-net-lan-rust.csv"
M7_RATES=0,100,1000; [[ $PHASE == 3 ]] && M7_RATES=0,1000,10000
run "m7 rust" "$PY" eval/flood_clienthello.py --rates "$M7_RATES" --data-plane rust --out "$OUT/m7-flood-rust.csv"
else
# --- Phase 4 and 5: M1, M8, M6 and M7 per backend; M2 per handshake; the native row on rust/rust ---
for backend in "${BACKENDS[@]}"; do
  read -r plane handshake <<<"$backend"
  tag=$plane-$handshake
  native=(); [[ $tag == rust-rust ]] && native=(--native-client "$NATIVE")
  run "m1 $tag lan" env PYTHON="$PY" bash eval/run_pqvpn_net.sh lan --iterations 30 --data-plane "$plane" \
    --handshake "$handshake" "${native[@]}" --out "$OUT/m1-lan-$tag.csv"
  run "m8 $tag" "$PY" eval/measure_memory.py --clients 50 --data-plane "$plane" --handshake "$handshake" \
    --out "$OUT/m8-$tag.csv"
  run "m6 $tag" env PYTHON="$PY" bash eval/run_rehandshake_net.sh --data-plane "$plane" --handshake "$handshake" \
    --out "$OUT/m6-net-$tag.csv"
  run "m7 $tag" "$PY" eval/flood_clienthello.py --rates 0,1000,10000 --data-plane "$plane" --handshake "$handshake" \
    --out "$OUT/m7-flood-$tag.csv"
done
for handshake in python rust; do
  run "m2 $handshake" "$PY" eval/run_pqvpn.py --iterations 50 --suites v2-ed25519,v3-kem,v3-mldsa \
    --handshake "$handshake" --out "$OUT/m2-$handshake.csv"
done
fi
if (( DRY_RUN )); then
  echo "then: summary.txt with medians and gates, and a HEAD-unchanged check"
  exit 0
fi
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
if phase >= 3:
    TAGS = ["rust"] if phase == 3 else ["python-python", "rust-python", "rust-rust"]
    print("M7 ClientHello flood at 10000/s" + (", rust" if phase == 3 else "") + ": legitimate connects, offered flood rate")
    for tag in TAGS:
        m7 = {}
        m7_path = f"{out}/m7-flood-{tag}.csv"
        for r in csv.DictReader(open(m7_path)) if os.path.exists(m7_path) else []:
            if r["profile"] == "flood-10000":
                m7.setdefault(r["system"], {})[r["metric"]] = float(r["value"])
        for system in ("pqvpn-cookie-off", "pqvpn-cookie-always"):
            m = m7.get(system, {})
            ok = (m.get("connects_attempted", 0) > 0 and m["connects_succeeded"] == m["connects_attempted"]
                  and m.get("flood_rate_per_s", 0) >= 9500)
            verdict &= ok
            label = "" if phase == 3 else f"{tag:13} "
            print(f"  {label}{system:20} {m.get('connects_succeeded', 0):.0f}/{m.get('connects_attempted', 0):.0f}"
                  f" connects  offered {m.get('flood_rate_per_s', 0):.0f}/s"
                  f"  delivered {m.get('flood_delivered_per_s', 0):.0f}/s"
                  f"  median {m.get('median_connect_time_ms', -1):.0f} ms"
                  f"  gate(all connects, offered >=9500/s): {'PASS' if ok else 'FAIL'}")
if phase >= 4:
    def rows(path):
        return list(csv.DictReader(open(path))) if os.path.exists(path) else []
    def med(values):
        return statistics.median(values) if values else None
    print("M1 LAN connect, median ms (cold = new process, no ticket, spawn to first tunnel ping; -1 = no tunnel)")
    for tag in TAGS:
        for system in ("pqvpn-net", "pqvpn-net-warm", "pqvpn-net-native"):
            vals = [float(r["value"]) for r in rows(f"{out}/m1-lan-{tag}.csv") if r["system"] == system]
            if not vals:
                continue
            good = [v for v in vals if v >= 0]
            gate = ""
            if system == "pqvpn-net-native":
                ok = len(good) == len(vals) == 30 and med(good) <= 30
                verdict &= ok
                gate = f"  gate(native cold <=30 ms, 30/30): {'PASS' if ok else 'FAIL'}"
            print(f"  {tag:13} {system:17} n={len(vals)} connected={len(good)} "
                  f"median {med(good) if good else float('nan'):.1f} ms{gate}")
    if not any(r["system"] == "pqvpn-net-native" for r in rows(f"{out}/m1-lan-rust-rust.csv")):
        print("  pqvpn-net-native: NO DATA  gate(native cold <=30 ms): FAIL"); verdict = False
    print("M2 handshake CPU, both roles in one process: median client + median server cpu ms")
    for handshake, suffix in (("python", ""), ("rust", "-hs-rust")):
        data = rows(f"{out}/m2-{handshake}.csv")
        for suite in ("v2-ed25519", "v3-kem", "v3-mldsa"):
            cpu = {m: [float(r["value"]) for r in data if r["system"] == f"pqvpn-{suite}{suffix}" and r["metric"] == m]
                   for m in ("client_cpu_ms", "server_cpu_ms")}
            if not all(cpu.values()):
                if handshake == "rust" and suite == "v3-kem":
                    print(f"  {handshake:6} {suite:10} NO DATA  gate(<=0.2 ms): FAIL"); verdict = False
                continue
            total = med(cpu["client_cpu_ms"]) + med(cpu["server_cpu_ms"])
            gate = ""
            if handshake == "rust" and suite == "v3-kem":
                ok = total <= 0.2 and len(cpu["client_cpu_ms"]) == 50
                verdict &= ok
                gate = f"  gate(<=0.2 ms, n=50): {'PASS' if ok else 'FAIL'}"
            print(f"  {handshake:6} {suite:10} client {med(cpu['client_cpu_ms']):.3f} + server "
                  f"{med(cpu['server_cpu_ms']):.3f} = {total:.3f} ms{gate}")
    print("M8 server VmRSS per session, N=50, v2, cookies off")
    for tag in TAGS:
        m = {r["metric"]: float(r["value"]) for r in rows(f"{out}/m8-{tag}.csv") if r["profile"] == "n=50"}
        ok = m.get("connected_clients") == 50 and m.get("per_session_kb", 1e9) <= 64
        verdict &= ok
        print(f"  {tag:13} connected {m.get('connected_clients', 0):.0f}/50  "
              f"{m.get('per_session_kb', float('nan')):.1f} kB  gate(<=64 kB, 50/50): {'PASS' if ok else 'FAIL'}")
    print("M6 hitless rekey and rehandshake on the netns path: ping loss across epoch switches")
    for tag in TAGS:
        m = {(r["system"], r["metric"]): float(r["value"]) for r in rows(f"{out}/m6-net-{tag}.csv")}
        for kind in ("rekey", "rehandshake"):
            loss = m.get((f"pqvpn-{kind}", f"{kind}_ping_loss_pct"))
            switches = m.get((f"pqvpn-{kind}", f"{kind}_epoch_transitions"), 0)
            ok = loss == 0 and switches > 0
            verdict &= ok
            print(f"  {tag:13} {kind:11} loss {loss if loss is not None else float('nan'):.2f}%  "
                  f"epochs {switches:.0f}  gate(0% loss, >0 epochs): {'PASS' if ok else 'FAIL'}")
print(f"PHASE {phase} GATES:", "PASS" if verdict else "FAIL")
PYEOF

if (( ${#FAILED[@]} )); then
  printf 'failed steps: %s\n' "${FAILED[@]}" | tee -a "$OUT/summary.txt" >&2
  exit 1
fi
echo "Results: $OUT"
