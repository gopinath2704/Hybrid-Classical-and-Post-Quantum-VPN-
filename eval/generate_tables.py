#!/usr/bin/env python3
"""Generate comparison tables and figures from raw evaluation CSV data.

Usage:
    python eval/generate_tables.py --input results/eval-<date>/raw --output results/eval-<date>/figures

Reads pqvpn.csv (and baseline CSVs when present) and produces:
    - handshake_comparison.csv   — side-by-side latency/bytes/CPU table
    - wire_sizes.csv             — per-message byte breakdown
    - handshake_comparison.txt   — text table for terminal/paper
    - figures/*.png              — bar charts (if matplotlib available)
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def load_pqvpn(raw_dir: Path) -> list[dict]:
    path = raw_dir / "pqvpn.csv"
    if not path.exists():
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def text_table(rows: list[dict], columns: list[tuple[str, str, str]]) -> str:
    """Render a fixed-width text table.

    columns: list of (header, dict_key, format_spec)
    """
    def _fmt(val: str, fmt: str) -> str:
        if not val or val in ("-1", "-1.0"):
            return "n/a"
        if fmt == "s":
            return val
        try:
            return format(float(val), fmt)
        except (ValueError, TypeError):
            return str(val)

    widths = [max(len(h), 8) for h, _, _ in columns]
    for row in rows:
        for i, (_, key, fmt) in enumerate(columns):
            widths[i] = max(widths[i], len(_fmt(row.get(key, ""), fmt)))

    header = "  ".join(h.ljust(w) for (h, _, _), w in zip(columns, widths))
    sep = "  ".join("─" * w for w in widths)
    lines = [header, sep]
    for row in rows:
        cells = []
        for (_, key, fmt), w in zip(columns, widths):
            cells.append(_fmt(row.get(key, ""), fmt).ljust(w))
        lines.append("  ".join(cells))
    return "\n".join(lines)


def generate(raw_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = load_pqvpn(raw_dir)
    if not rows:
        print("No pqvpn.csv found — nothing to generate", file=sys.stderr)
        return

    # --- Handshake comparison table ---
    columns = [
        ("Suite", "suite", "s"),
        ("Median (ms)", "median_latency_ms", ".3f"),
        ("p95 (ms)", "p95_latency_ms", ".3f"),
        ("σ (ms)", "stddev_latency_ms", ".3f"),
        ("Client CPU", "median_client_cpu_ms", ".3f"),
        ("Server CPU", "median_server_cpu_ms", ".3f"),
        ("Wire (B)", "total_wire_bytes", ".0f"),
        ("HS/s", "handshakes_per_sec", ".0f"),
        ("Enc pps", "encrypt_pps", ".0f"),
        ("Enc Mbps", "encrypt_mbps", ".1f"),
    ]
    table = text_table(rows, columns)
    (out_dir / "handshake_comparison.txt").write_text(table + "\n")
    print(table)

    # --- Wire size breakdown ---
    wire_cols = [
        ("Suite", "suite", "s"),
        ("CH (B)", "client_hello_bytes", ".0f"),
        ("SH (B)", "server_hello_bytes", ".0f"),
        ("CKE (B)", "client_key_exchange_bytes", ".0f"),
        ("SF (B)", "server_finished_bytes", ".0f"),
        ("Total (B)", "total_wire_bytes", ".0f"),
    ]
    wire_table = text_table(rows, wire_cols)
    (out_dir / "wire_sizes.txt").write_text(wire_table + "\n")
    print()
    print(wire_table)

    # --- CSV copies ---
    with open(out_dir / "handshake_comparison.csv", "w", newline="") as f:
        if rows:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    # --- Bar charts (optional) ---
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        suites = [r["suite"] for r in rows]
        latencies = [float(r["median_latency_ms"]) for r in rows]
        wire = [int(float(r["total_wire_bytes"])) for r in rows]
        hs_sec = [float(r["handshakes_per_sec"]) for r in rows]

        fig, axes = plt.subplots(1, 3, figsize=(14, 4))

        axes[0].bar(suites, latencies, color=["#2196F3", "#4CAF50", "#FF9800"])
        axes[0].set_ylabel("Median latency (ms)")
        axes[0].set_title("Handshake Latency")

        axes[1].bar(suites, wire, color=["#2196F3", "#4CAF50", "#FF9800"])
        axes[1].set_ylabel("Bytes on wire")
        axes[1].set_title("Wire Size")

        axes[2].bar(suites, hs_sec, color=["#2196F3", "#4CAF50", "#FF9800"])
        axes[2].set_ylabel("Handshakes/sec")
        axes[2].set_title("Server Throughput")

        plt.tight_layout()
        fig.savefig(out_dir / "handshake_comparison.png", dpi=300)
        plt.close()
        print(f"\n  Chart saved to {out_dir / 'handshake_comparison.png'}")

        # Stacked wire size chart
        fig2, ax2 = plt.subplots(figsize=(8, 5))
        ch_vals = [int(float(r["client_hello_bytes"])) for r in rows]
        sh_vals = [int(float(r["server_hello_bytes"])) for r in rows]
        cke_vals = [int(float(r["client_key_exchange_bytes"])) for r in rows]
        sf_vals = [int(float(r["server_finished_bytes"])) for r in rows]

        ax2.bar(suites, ch_vals, label="ClientHello", color="#2196F3")
        ax2.bar(suites, sh_vals, bottom=ch_vals, label="ServerHello", color="#4CAF50")
        ax2.bar(suites, cke_vals, bottom=[a + b for a, b in zip(ch_vals, sh_vals)],
                label="ClientKeyExchange", color="#FF9800")
        ax2.bar(suites, sf_vals,
                bottom=[a + b + c for a, b, c in zip(ch_vals, sh_vals, cke_vals)],
                label="ServerFinished", color="#F44336")
        ax2.set_ylabel("Bytes")
        ax2.set_title("Handshake Wire Size Breakdown")
        ax2.legend()
        plt.tight_layout()
        fig2.savefig(out_dir / "wire_breakdown.png", dpi=300)
        plt.close()
        print(f"  Chart saved to {out_dir / 'wire_breakdown.png'}")

    except ImportError:
        print("\n  matplotlib not available — skipping charts", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Generate evaluation tables and figures")
    parser.add_argument("--input", type=str, required=True, help="Path to raw/ directory")
    parser.add_argument("--output", type=str, required=True, help="Path to figures/ directory")
    args = parser.parse_args()
    generate(Path(args.input), Path(args.output))


if __name__ == "__main__":
    main()
