#!/usr/bin/env python3
"""Orchestrate the full evaluation campaign.

Runs all available systems, collects results, and writes a sanity log.

Usage:
    python eval/run_all.py                          # default 50 iterations
    python eval/run_all.py --iterations 100
    python eval/run_all.py --systems pqvpn          # our suites only
    python eval/run_all.py --systems pqvpn,wireguard
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
    for tool in ("wg", "openvpn", "swanctl", "rosenpass", "iperf3"):
        info[f"has_{tool}"] = shutil.which(tool) is not None
    return info


SYSTEMS = {
    "pqvpn": {
        "cmd": lambda iters, out: [
            sys.executable, str(_EVAL / "run_pqvpn.py"),
            "--iterations", str(iters), "--out", str(out),
        ],
        "output": "pqvpn.csv",
    },
    "wireguard": {
        "cmd": lambda iters, out: ["bash", str(_EVAL / "run_wireguard.sh"), str(iters), str(out)],
        "output": "wireguard.csv",
        "requires_root": True,
    },
}


def run_system(name: str, spec: dict, iterations: int, out_dir: Path) -> bool:
    out_file = out_dir / "raw" / spec["output"]
    cmd = spec["cmd"](iterations, out_file)
    is_root = os.geteuid() == 0

    if spec.get("requires_root") and not is_root:
        print(f"  [{name}] SKIP: requires root")
        return False

    print(f"  [{name}] Running...", end=" ", flush=True)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"FAILED (exit {result.returncode})")
            if result.stderr:
                for line in result.stderr.strip().split("\n")[-3:]:
                    print(f"    {line}")
            return False
        if result.stdout:
            print(result.stdout.strip().split("\n")[-1])
        else:
            print("done")
        return True
    except subprocess.TimeoutExpired:
        print("TIMEOUT (600s)")
        return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="PQVPN evaluation campaign orchestrator")
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--systems", type=str, default=None,
                        help="Comma-separated system names (default: all available)")
    args = parser.parse_args()

    _require_native_pqc()

    out_dir = results_dir()

    print("=" * 65)
    print("  PQVPN EVALUATION CAMPAIGN")
    print(f"  Iterations: {args.iterations}  |  Output: {out_dir}")
    print("=" * 65)

    sanity = collect_sanity()
    sanity_file = out_dir / "sanity.json"
    with open(sanity_file, "w") as f:
        json.dump(sanity, f, indent=2)
    print(f"\n  Sanity log: {sanity_file}")
    print(f"  CPU: {sanity['cpu']} | Governor: {sanity['cpu_governor']}")
    print(f"  pqc_mode: {sanity['pqc_mode']}")
    print(f"  liboqs: {sanity['liboqs_version']}")
    print("  Tools: " + ", ".join(
        f"{t}={'yes' if sanity[f'has_{t}'] else 'no'}"
        for t in ("wg", "openvpn", "swanctl", "rosenpass", "iperf3")
    ))
    print()

    if args.systems:
        system_names = [s.strip() for s in args.systems.split(",")]
    else:
        system_names = list(SYSTEMS.keys())

    completed = []
    skipped = []
    failed = []
    for name in system_names:
        if name not in SYSTEMS:
            print(f"  [{name}] UNKNOWN — skipping")
            skipped.append(name)
            continue
        ok = run_system(name, SYSTEMS[name], args.iterations, out_dir)
        (completed if ok else skipped).append(name)

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


if __name__ == "__main__":
    main()
