"""
Automated Chart Figure Generator Module.

Reads benchmark metrics JSON files from `benchmarks/results/` and generates
4 publication-ready comparative chart figures (PNG, 300 DPI):

    1. `handshake_latency_comparison.png`  — Latency (ms) across KEM & Hybrid suites
    2. `handshake_size_comparison.png`     — Message wire payload breakdown (bytes)
    3. `throughput_payload_scaling.png`    — Throughput (Mbps) vs payload size (64B–8192B)
    4. `packet_overhead_breakdown.png`     — Protocol header overhead donut chart (58B)
"""

from __future__ import annotations

import sys
import json
import logging
from pathlib import Path
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt

# Ensure root is on path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

logger = logging.getLogger("pqvpn.benchmarks.generate_charts")


class ChartGenerator:
    """
    Matplotlib figure generator for post-quantum VPN benchmark results.

    Attributes:
        results_dir: Directory containing JSON metric files and output PNGs.
    """

    def __init__(self, results_dir: Optional[Path] = None) -> None:
        self.results_dir = results_dir or (_PROJECT_ROOT / "benchmarks" / "results")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self._apply_style()

    def _apply_style(self) -> None:
        """Apply dark cyber aesthetic matching the application design system."""
        plt.style.use("dark_background")
        plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "sans-serif"]
        plt.rcParams["font.size"] = 10
        plt.rcParams["axes.edgecolor"] = "#1C2640"
        plt.rcParams["axes.facecolor"] = "#131A2B"
        plt.rcParams["figure.facecolor"] = "#0B0F19"
        plt.rcParams["grid.color"] = "#1C2640"
        plt.rcParams["grid.linestyle"] = "--"
        plt.rcParams["grid.alpha"] = 0.5

    def generate_handshake_latency_chart(self) -> Path:
        """Generate bar chart comparing handshake latency (ms) across suites."""
        json_file = self.results_dir / "handshake_results.json"
        if not json_file.exists():
            raise FileNotFoundError(f"Missing {json_file}")

        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        suites = list(data.keys())
        avg_latencies = [data[s]["avg_latency_ms"] for s in suites]
        p95_latencies = [data[s]["p95_latency_ms"] for s in suites]

        x = range(len(suites))
        width = 0.35

        fig, ax = plt.subplots(figsize=(10, 6))

        rects1 = ax.bar([i - width / 2 for i in x], avg_latencies, width, label="Avg Latency (ms)", color="#00E676")
        rects2 = ax.bar([i + width / 2 for i in x], p95_latencies, width, label="p95 Latency (ms)", color="#00F0FF")

        ax.set_title("Handshake Setup Latency Comparison", fontsize=14, fontweight="bold", pad=15, color="#F0F4FC")
        ax.set_ylabel("Latency (milliseconds)", fontsize=11, color="#8B95A8")
        ax.set_xticks(list(x))
        ax.set_xticklabels(suites, rotation=15, ha="right", fontsize=9)
        ax.legend(frameon=True, facecolor="#131A2B", edgecolor="#1C2640")
        ax.grid(True, axis="y")

        # Value labels
        for rect in rects1:
            h = rect.get_height()
            ax.annotate(f"{h:.2f}ms", xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, color="#00E676")

        fig.tight_layout()
        out_path = self.results_dir / "handshake_latency_comparison.png"
        fig.savefig(out_path, dpi=300)
        plt.close(fig)
        logger.info("Saved chart: %s", out_path)
        return out_path

    def generate_handshake_size_chart(self) -> Path:
        """Generate stacked bar chart showing total wire size (bytes) by message type."""
        json_file = self.results_dir / "handshake_results.json"
        if not json_file.exists():
            raise FileNotFoundError(f"Missing {json_file}")

        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        suites = list(data.keys())
        ch_bytes = [data[s]["client_hello_bytes"] for s in suites]
        sh_bytes = [data[s]["server_hello_bytes"] for s in suites]
        cke_bytes = [data[s]["client_key_exchange_bytes"] for s in suites]
        sf_bytes = [data[s]["server_finished_bytes"] for s in suites]

        fig, ax = plt.subplots(figsize=(10, 6))

        p1 = ax.bar(suites, ch_bytes, label="ClientHello", color="#00E676")
        p2 = ax.bar(suites, sh_bytes, bottom=ch_bytes, label="ServerHello", color="#00F0FF")
        p3 = ax.bar(suites, cke_bytes, bottom=[ch + sh for ch, sh in zip(ch_bytes, sh_bytes)], label="ClientKeyExchange", color="#3B82F6")
        p4 = ax.bar(suites, sf_bytes, bottom=[ch + sh + cke for ch, sh, cke in zip(ch_bytes, sh_bytes, cke_bytes)], label="ServerFinished", color="#A855F7")

        ax.set_title("Handshake Wire Payload Size Breakdown", fontsize=14, fontweight="bold", pad=15, color="#F0F4FC")
        ax.set_ylabel("Total Bytes Transmitted", fontsize=11, color="#8B95A8")
        ax.set_xticks(range(len(suites)))
        ax.set_xticklabels(suites, rotation=15, ha="right", fontsize=9)
        ax.legend(frameon=True, facecolor="#131A2B", edgecolor="#1C2640")
        ax.grid(True, axis="y")

        # Total label on top of each bar
        for i, s in enumerate(suites):
            total = data[s]["avg_total_bytes"]
            ax.annotate(f"{total:,} B", xy=(i, total), xytext=(0, 4),
                        textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#F0F4FC")

        fig.tight_layout()
        out_path = self.results_dir / "handshake_size_comparison.png"
        fig.savefig(out_path, dpi=300)
        plt.close(fig)
        logger.info("Saved chart: %s", out_path)
        return out_path

    def generate_throughput_chart(self) -> Path:
        """Generate line plot showing throughput (Mbps) vs payload size."""
        json_file = self.results_dir / "throughput_results.json"
        if not json_file.exists():
            raise FileNotFoundError(f"Missing {json_file}")

        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        sizes = [data[k]["payload_size_bytes"] for k in data]
        throughputs = [data[k]["throughput_mbps"] for k in data]
        enc_latencies = [data[k]["avg_enc_time_us"] for k in data]

        fig, ax1 = plt.subplots(figsize=(10, 6))

        color1 = "#00E676"
        ax1.set_xlabel("Payload Size (Bytes)", fontsize=11, color="#8B95A8")
        ax1.set_ylabel("Throughput (Mbps)", color=color1, fontsize=11, fontweight="bold")
        line1 = ax1.plot(sizes, throughputs, color=color1, marker="o", linewidth=2.5, label="Throughput (Mbps)")
        ax1.tick_params(axis="y", labelcolor=color1)
        ax1.grid(True)

        ax2 = ax1.twinx()
        color2 = "#00F0FF"
        ax2.set_ylabel("Encryption Latency per Frame (µs)", color=color2, fontsize=11, fontweight="bold")
        line2 = ax2.plot(sizes, enc_latencies, color=color2, marker="s", linestyle="--", linewidth=2, label="Enc Latency (µs)")
        ax2.tick_params(axis="y", labelcolor=color2)

        plt.title("AES-256-GCM Tunnel Throughput & Processing Latency vs Payload Size", fontsize=13, fontweight="bold", pad=15, color="#F0F4FC")
        fig.tight_layout()

        out_path = self.results_dir / "throughput_payload_scaling.png"
        fig.savefig(out_path, dpi=300)
        plt.close(fig)
        logger.info("Saved chart: %s", out_path)
        return out_path

    def generate_packet_overhead_chart(self) -> Path:
        """Generate donut chart showing protocol header overhead proportions (58 bytes total)."""
        json_file = self.results_dir / "packet_capture_results.json"
        if not json_file.exists():
            raise FileNotFoundError(f"Missing {json_file}")

        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        v4 = data["layer_breakdown_ipv4"]

        labels = [
            f"IPv4 Header ({v4['ip_header_bytes']}B)",
            f"UDP Header ({v4['udp_header_bytes']}B)",
            f"GCM Nonce ({v4['crypto_nonce_bytes']}B)",
            f"GCM Tag ({v4['crypto_tag_bytes']}B)",
            f"Length Prefix ({v4['length_prefix_bytes']}B)",
        ]
        sizes = [
            v4["ip_header_bytes"],
            v4["udp_header_bytes"],
            v4["crypto_nonce_bytes"],
            v4["crypto_tag_bytes"],
            v4["length_prefix_bytes"],
        ]
        colors = ["#3B82F6", "#00F0FF", "#00E676", "#A855F7", "#F59E0B"]

        fig, ax = plt.subplots(figsize=(8, 6))

        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            autopct="%1.1f%%",
            pctdistance=0.75,
            colors=colors,
            startangle=140,
            textprops=dict(color="#F0F4FC", fontsize=9),
            wedgeprops=dict(width=0.4, edgecolor="#0B0F19", linewidth=2),
        )

        plt.setp(autotexts, size=9, weight="bold")
        ax.set_title(f"VPN Wire Framing Overhead Breakdown ({v4['total_overhead_bytes']} Bytes Total)", fontsize=13, fontweight="bold", pad=15, color="#F0F4FC")

        fig.tight_layout()
        out_path = self.results_dir / "packet_overhead_breakdown.png"
        fig.savefig(out_path, dpi=300)
        plt.close(fig)
        logger.info("Saved chart: %s", out_path)
        return out_path

    def generate_all(self) -> list[Path]:
        """Generate all 4 chart figures and return their file paths."""
        chart_paths = [
            self.generate_handshake_latency_chart(),
            self.generate_handshake_size_chart(),
            self.generate_throughput_chart(),
            self.generate_packet_overhead_chart(),
        ]
        logger.info("Generated all 4 chart figures in %s", self.results_dir)
        return chart_paths


def main():
    """CLI entry point for chart generation."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")
    gen = ChartGenerator()
    paths = gen.generate_all()
    print("\n" + "=" * 65)
    print("  GENERATED BENCHMARK CHART FIGURES")
    print("=" * 65)
    for p in paths:
        print(f"  - {p.name}")


if __name__ == "__main__":
    main()
