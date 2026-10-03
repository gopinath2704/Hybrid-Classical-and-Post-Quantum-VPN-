#!/usr/bin/env python3
"""Generate comparison tables and figures from raw evaluation CSV data.

Reads every *.csv in the input directory (unified schema:
system,profile,metric,run,value,unit), groups by system/profile/metric,
and reports median with 95% bootstrap CI (10,000 resamples, seed=42).

Outputs:
    - summary.csv       — aggregated stats
    - summary.txt       — text table
    - figures/*.png     — bar charts with error bars
"""
from __future__ import annotations

import argparse
import csv
import math
import random
import sys
from pathlib import Path


def load_all_csv(raw_dir: Path) -> list[dict]:
    rows = []
    for csv_path in sorted(raw_dir.glob("*.csv")):
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            if reader.fieldnames and set(reader.fieldnames) >= {"system", "profile", "metric", "run", "value", "unit"}:
                for row in reader:
                    try:
                        row["value"] = float(row["value"])
                        row["run"] = int(row["run"])
                    except (ValueError, TypeError):
                        continue
                    rows.append(row)
    return rows


def bootstrap_ci(values: list[float], n_resamples: int = 10000,
                 ci: float = 0.95, seed: int = 42) -> tuple[float, float, float]:
    rng = random.Random(seed)
    n = len(values)
    if n == 0:
        return 0.0, 0.0, 0.0
    if n == 1:
        return values[0], values[0], values[0]

    medians = []
    for _ in range(n_resamples):
        sample = [values[rng.randint(0, n - 1)] for _ in range(n)]
        sample.sort()
        medians.append(sample[len(sample) // 2])
    medians.sort()

    alpha = (1 - ci) / 2
    lo_idx = max(0, int(math.floor(alpha * n_resamples)))
    hi_idx = min(n_resamples - 1, int(math.ceil((1 - alpha) * n_resamples)) - 1)

    sample_median = sorted(values)[len(values) // 2]
    return sample_median, medians[lo_idx], medians[hi_idx]


def group_data(rows: list[dict]) -> dict[tuple[str, str, str], list[float]]:
    groups: dict[tuple[str, str, str], list[float]] = {}
    for row in rows:
        key = (row["system"], row["profile"], row["metric"])
        groups.setdefault(key, []).append(row["value"])
    return groups


def generate_summary(groups: dict) -> list[dict]:
    summary = []
    for (system, profile, metric), values in sorted(groups.items()):
        if not values:
            continue
        median, ci_lo, ci_hi = bootstrap_ci(values)
        summary.append({
            "system": system,
            "profile": profile,
            "metric": metric,
            "n": len(values),
            "median": round(median, 4),
            "ci_lo": round(ci_lo, 4),
            "ci_hi": round(ci_hi, 4),
        })
    return summary


def text_table(summary: list[dict]) -> str:
    columns = [
        ("System", "system", "s", 20),
        ("Profile", "profile", "s", 12),
        ("Metric", "metric", "s", 28),
        ("N", "n", "d", 5),
        ("Median", "median", ".4f", 12),
        ("CI Low", "ci_lo", ".4f", 12),
        ("CI High", "ci_hi", ".4f", 12),
    ]
    header = "  ".join(h.ljust(w) for h, _, _, w in columns)
    sep = "  ".join("-" * w for _, _, _, w in columns)
    lines = [header, sep]
    for row in summary:
        cells = []
        for _, key, fmt, w in columns:
            val = row[key]
            cells.append(format(val, fmt).ljust(w))
        lines.append("  ".join(cells))
    return "\n".join(lines)


def generate_figures(summary: list[dict], out_dir: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not available — skipping charts", file=sys.stderr)
        return

    latency_rows = [r for r in summary if r["metric"] == "latency_ms"]
    if latency_rows:
        fig, ax = plt.subplots(figsize=(10, 5))
        labels = [f"{r['system']}\n{r['profile']}" for r in latency_rows]
        medians = [r["median"] for r in latency_rows]
        lo_err = [r["median"] - r["ci_lo"] for r in latency_rows]
        hi_err = [r["ci_hi"] - r["median"] for r in latency_rows]
        ax.bar(range(len(labels)), medians, yerr=[lo_err, hi_err],
               capsize=4, color="#2196F3", edgecolor="#1565C0")
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, fontsize=8)
        ax.set_ylabel("Latency (ms)")
        ax.set_title("Handshake Latency — Median with 95% Bootstrap CI")
        fig.tight_layout()
        fig.savefig(out_dir / "latency_comparison.png", dpi=300)
        plt.close()

    connect_rows = [r for r in summary if r["metric"] == "connect_time_ms"]
    if connect_rows:
        fig, ax = plt.subplots(figsize=(10, 5))
        labels = [f"{r['system']}\n{r['profile']}" for r in connect_rows]
        medians = [r["median"] for r in connect_rows]
        lo_err = [r["median"] - r["ci_lo"] for r in connect_rows]
        hi_err = [r["ci_hi"] - r["median"] for r in connect_rows]
        ax.bar(range(len(labels)), medians, yerr=[lo_err, hi_err],
               capsize=4, color="#4CAF50", edgecolor="#2E7D32")
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, fontsize=8)
        ax.set_ylabel("Connect Time (ms)")
        ax.set_title("VPN Connect Time — Median with 95% Bootstrap CI")
        fig.tight_layout()
        fig.savefig(out_dir / "connect_time_comparison.png", dpi=300)
        plt.close()

    wire_rows = [r for r in summary if r["metric"] == "total_wire_bytes"]
    if wire_rows:
        fig, ax = plt.subplots(figsize=(8, 5))
        labels = [r["system"] for r in wire_rows]
        medians = [r["median"] for r in wire_rows]
        ax.bar(labels, medians, color="#FF9800", edgecolor="#E65100")
        ax.set_ylabel("Bytes")
        ax.set_title("Handshake Wire Size")
        fig.tight_layout()
        fig.savefig(out_dir / "wire_sizes.png", dpi=300)
        plt.close()


def generate(raw_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = load_all_csv(raw_dir)
    if not rows:
        print("No CSV files with unified schema found — nothing to generate",
              file=sys.stderr)
        return

    groups = group_data(rows)
    summary = generate_summary(groups)

    table = text_table(summary)
    (out_dir / "summary.txt").write_text(table + "\n")
    print(table)

    with open(out_dir / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["system", "profile", "metric", "n",
                                          "median", "ci_lo", "ci_hi"])
        w.writeheader()
        w.writerows(summary)

    generate_figures(summary, out_dir)
    print(f"\nOutput written to {out_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate evaluation tables and figures from raw CSV data")
    parser.add_argument("--input", type=str, required=True,
                        help="Path to raw/ directory with *.csv files")
    parser.add_argument("--output", type=str, required=True,
                        help="Path to output directory for tables and figures")
    args = parser.parse_args()
    generate(Path(args.input), Path(args.output))


if __name__ == "__main__":
    main()
