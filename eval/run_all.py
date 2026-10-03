#!/usr/bin/env python3
"""Orchestrate the full evaluation campaign.

Runs every available system over a shared netns+veth+tc-netem topology and
collects results under the unified CSV schema, then generates tables/figures.

Two kinds of system are run:

  * in-process crypto microbenchmarks (``pqvpn``) — handshake wire bytes, CPU,
    and crypto-only latency/throughput. These are labelled ``profile=in-process``
    and are NOT networked numbers. They are honest crypto costs, not M1/M2.

  * networked connect-time systems (``pqvpn-net``, ``wireguard``, ``rosenpass``,
    ``strongswan``) — the real M1 (time to first ping through the tunnel) over
    each profile, so every system shares topology, netem, and the M1 definition.

Usage:
    sudo python eval/run_all.py                              # everything, all profiles
    python eval/run_all.py --systems pqvpn                   # in-process crypto only (no root)
    sudo python eval/run_all.py --systems pqvpn-net,wireguard --profiles lan,continent
    sudo python eval/run_all.py --net-iterations 30 --iterations 50
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_EVAL = _ROOT / "eval"

if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

ALL_PROFILES = ["lan", "metro", "continent", "lossy-1", "lossy-5", "mtu-1280"]


def _require_native_pqc():
    from crypto.hybrid_crypto import get_crypto_status
    status = get_crypto_status()
    if status["pqc_mode"] != "native_liboqs":
        print(f"FATAL: pqc_mode={status['pqc_mode']}; native liboqs required.",
              file=sys.stderr)
        sys.exit(1)
    return status


def results_dir() -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    d = _ROOT / "results" / f"eval-{ts}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "raw").mkdir(exist_ok=True)
    (d / "figures").mkdir(exist_ok=True)
    return d


def collect_sanity() -> dict:
    from crypto.hybrid_crypto import get_crypto_status
    status = get_crypto_status()

    info = {
        "timestamp": datetime.now().isoformat(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "cpu": platform.processor() or "unknown",
        "arch": platform.machine(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "pqc_mode": status["pqc_mode"],
    }
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    info["cpu_model"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        info["cpu_model"] = info["cpu"]
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            info["cpu_governor"] = f.read().strip()
    except (FileNotFoundError, PermissionError):
        info["cpu_governor"] = "unknown"
    try:
        r = subprocess.run(["git", "-C", str(_ROOT), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=5)
        info["git_commit"] = r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:
        info["git_commit"] = "unknown"
    try:
        import oqs
        info["liboqs_version"] = oqs.oqs_version() if hasattr(oqs, "oqs_version") else getattr(oqs, "__version__", "available")
    except ImportError:
        info["liboqs_version"] = "unavailable"
    for tool in ("wg", "openvpn", "swanctl", "rp", "rosenpass", "iperf3", "ip", "tc"):
        info[f"has_{tool}"] = shutil.which(tool) is not None
    return info


# Each system is either an in-process microbenchmark (one CSV, no profile
# sweep) or a networked connect-time system (one CSV per profile). Networked
# runners share eval/netem_profiles.sh so topology and netem are identical.
SYSTEMS = {
    "pqvpn": {
        "kind": "in_process",
        "cmd": lambda iters, out: [
            sys.executable, str(_EVAL / "run_pqvpn.py"),
            "--iterations", str(iters), "--out", str(out),
        ],
        "output": "pqvpn.csv",
    },
    "pqvpn-net": {
        "kind": "networked",
        "cmd": lambda iters, out, profile: [
            "bash", str(_EVAL / "run_pqvpn_net.sh"), profile,
            "--iterations", str(iters), "--out", str(out),
        ],
        "requires_root": True,
    },
    "wireguard": {
        "kind": "networked",
        "cmd": lambda iters, out, profile: [
            "bash", str(_EVAL / "run_wireguard.sh"), str(iters), str(out), profile,
        ],
        "requires_root": True,
    },
    "rosenpass": {
        "kind": "networked",
        "cmd": lambda iters, out, profile: [
            "bash", str(_EVAL / "run_rosenpass.sh"), str(iters), str(out), profile,
        ],
        "requires_root": True,
    },
    "strongswan": {
        "kind": "networked",
        "cmd": lambda iters, out, profile: [
            "bash", str(_EVAL / "run_strongswan.sh"), str(iters), str(out), profile,
        ],
        "requires_root": True,
    },
}


def _run(cmd, label) -> bool:
    print(f"  [{label}] Running...", end=" ", flush=True)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if result.returncode != 0:
            print(f"FAILED (exit {result.returncode})")
            tail = (result.stderr or result.stdout or "").strip().split("\n")[-3:]
            for line in tail:
                print(f"    {line}")
            return False
        last = (result.stdout or result.stderr or "").strip().split("\n")
        print(last[-1] if last and last[-1] else "done")
        return True
    except subprocess.TimeoutExpired:
        print("TIMEOUT (1800s)")
        return False
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}")
        return False


def run_system(name, spec, iterations, net_iterations, profiles, out_dir):
    """Returns (completed_units, failed_units) where a unit is a profile cell
    for networked systems, or the whole system for in-process ones."""
    is_root = os.geteuid() == 0
    if spec.get("requires_root") and not is_root:
        print(f"  [{name}] SKIP: requires root")
        return [], []

    completed, failed = [], []
    if spec["kind"] == "in_process":
        out_file = out_dir / "raw" / spec["output"]
        ok = _run(spec["cmd"](iterations, out_file), name)
        (completed if ok else failed).append(name)
        return completed, failed

    # networked: one CSV per profile
    for profile in profiles:
        out_file = out_dir / "raw" / f"{name}-{profile}.csv"
        label = f"{name}/{profile}"
        ok = _run(spec["cmd"](net_iterations, out_file, profile), label)
        (completed if ok else failed).append(label)
    return completed, failed


def main():
    parser = argparse.ArgumentParser(description="PQVPN evaluation campaign orchestrator")
    parser.add_argument("--iterations", type=int, default=50,
                        help="in-process crypto microbenchmark iterations")
    parser.add_argument("--net-iterations", type=int, default=30,
                        help="networked connect-time iterations per profile")
    parser.add_argument("--systems", type=str, default=None,
                        help="Comma-separated system names (default: all available)")
    parser.add_argument("--profiles", type=str, default=None,
                        help=f"Comma-separated profiles (default: {','.join(ALL_PROFILES)})")
    args = parser.parse_args()

    _require_native_pqc()

    out_dir = results_dir()
    profiles = ([p.strip() for p in args.profiles.split(",")]
                if args.profiles else list(ALL_PROFILES))

    print("=" * 65)
    print("  PQVPN EVALUATION CAMPAIGN")
    print(f"  In-process iters: {args.iterations}  |  Net iters/profile: {args.net_iterations}")
    print(f"  Profiles: {', '.join(profiles)}")
    print(f"  Output: {out_dir}")
    print("=" * 65)

    sanity = collect_sanity()
    sanity_file = out_dir / "sanity.json"
    with open(sanity_file, "w") as f:
        json.dump(sanity, f, indent=2)
    print(f"\n  Sanity log: {sanity_file}")
    print(f"  CPU: {sanity.get('cpu_model', sanity['cpu'])} | Governor: {sanity['cpu_governor']}")
    print(f"  Kernel: {sanity['kernel']} | git: {sanity['git_commit']}")
    print(f"  pqc_mode: {sanity['pqc_mode']} | liboqs: {sanity['liboqs_version']}")
    print("  Tools: " + ", ".join(
        f"{t}={'yes' if sanity[f'has_{t}'] else 'no'}"
        for t in ("wg", "rp", "swanctl", "ip", "tc", "iperf3")
    ))
    print()

    if args.systems:
        system_names = [s.strip() for s in args.systems.split(",")]
    else:
        system_names = list(SYSTEMS.keys())

    completed, skipped, failed = [], [], []
    for name in system_names:
        if name not in SYSTEMS:
            print(f"  [{name}] UNKNOWN — skipping")
            skipped.append(name)
            continue
        c, f = run_system(name, SYSTEMS[name], args.iterations,
                          args.net_iterations, profiles, out_dir)
        completed.extend(c)
        failed.extend(f)
        if not c and not f:
            skipped.append(name)

    print()
    print("=" * 65)
    print(f"  Completed: {', '.join(completed) or 'none'}")
    if skipped:
        print(f"  Skipped:   {', '.join(skipped)}")
    if failed:
        print(f"  Failed:    {', '.join(failed)}")
    print(f"  Results:   {out_dir / 'raw'}")
    print("=" * 65)

    gen_tables = _EVAL / "generate_tables.py"
    if gen_tables.exists() and completed:
        print("\n  Generating tables...")
        subprocess.run([sys.executable, str(gen_tables), "--input", str(out_dir / "raw"),
                        "--output", str(out_dir / "figures")],
                       capture_output=True, text=True)
        print(f"  Figures:   {out_dir / 'figures'}")

    # A non-zero exit when any requested unit failed, so CI and callers can
    # tell a partial campaign from a clean one (failures are never silent).
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
