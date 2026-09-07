"""
Unified Performance Benchmarking Runner.

Consolidates all benchmark modules into a single file:
    - HandshakeBenchmark:    KEMTLS connection setup timing & wire payload sizes
    - ThroughputBenchmark:   AES-256-GCM tunnel encryption/decryption latency, Mbps, pps
    - PacketOverheadAnalyzer: Wire packet overhead layer-by-layer (IPv4/IPv6)
    - ChartGenerator:        Matplotlib publication-quality 300 DPI chart PNGs

Usage:
    python -m benchmarks --iterations 50
    python -m benchmarks --all
"""

from __future__ import annotations

import os
import sys
import time
import json
import logging
import statistics
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

# Ensure root is on path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from crypto.hybrid_crypto import ECCProvider, PQCProvider, HybridKEM, KeyManager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vpn.identity import fingerprint
from handshake.kemtls import (
    KEMTLSClient,
    KEMTLSServer,
    ClientHello,
    ServerHello,
    ClientKeyExchange,
    ServerFinished,
    HandshakeSession,
)
from vpn.engine import (
    FRAME_OVERHEAD_TOTAL,
    IPV4_HEADER_SIZE,
    IPV6_HEADER_SIZE,
    UDP_HEADER_SIZE,
    FRAME_OVERHEAD_NONCE,
    FRAME_OVERHEAD_TAG,
    VPN_LENGTH_PREFIX,
    VPN_TOTAL_OVERHEAD,
)

logger = logging.getLogger("pqvpn.benchmarks")


# ═══════════════════════════════════════════════════════════════════════════════
# Handshake Benchmark
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class HandshakeMetric:
    """Benchmark metrics for a single handshake execution."""
    suite_name: str
    total_latency_ms: float
    client_cpu_ms: float
    server_cpu_ms: float
    client_hello_bytes: int
    server_hello_bytes: int
    client_key_exchange_bytes: int
    server_finished_bytes: int

    @property
    def total_wire_bytes(self) -> int:
        """Total bytes transmitted across the 1.5 RTT exchange."""
        return (
            self.client_hello_bytes +
            self.server_hello_bytes +
            self.client_key_exchange_bytes +
            self.server_finished_bytes
        )


@dataclass
class SuiteSummary:
    """Aggregated statistical summary for a cryptographic suite."""
    suite_name: str
    iterations: int
    avg_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    stddev_latency_ms: float
    avg_total_bytes: float
    client_hello_bytes: int
    server_hello_bytes: int
    client_key_exchange_bytes: int
    server_finished_bytes: int


class HandshakeBenchmark:
    """
    Performance benchmark runner for KEMTLS & hybrid key exchanges.

    Attributes:
        iterations: Number of benchmark runs per suite.
        warmup_runs: Number of unmeasured warm-up iterations.
        results_dir: Output directory for JSON metric files.
    """

    def __init__(
        self,
        iterations: int = 50,
        warmup_runs: int = 5,
        results_dir: Optional[Path] = None,
    ) -> None:
        self.iterations = iterations
        self.warmup_runs = warmup_runs
        self.results_dir = results_dir or (_PROJECT_ROOT / "benchmarks" / "results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def run_suite(self, suite_name: str, kyber_variant: str = "ML-KEM-768") -> SuiteSummary:
        """
        Run handshake benchmark for a specific cryptographic suite.

        Args:
            suite_name: Display name for the suite.
            kyber_variant: ML-KEM variant ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024").

        Returns:
            SuiteSummary: Aggregated latency and payload metrics.
        """
        logger.info("Benchmarking suite: %s (%d iterations)...", suite_name, self.iterations)
        metrics: list[HandshakeMetric] = []

        # Warm-up runs
        for _ in range(self.warmup_runs):
            self._benchmark_single_handshake(suite_name, kyber_variant)

        # Measured runs
        for i in range(self.iterations):
            metric = self._benchmark_single_handshake(suite_name, kyber_variant)
            metrics.append(metric)

        # Aggregate statistics
        latencies = [m.total_latency_ms for m in metrics]
        sorted_latencies = sorted(latencies)
        p95_idx = int(len(sorted_latencies) * 0.95)

        first = metrics[0]

        summary = SuiteSummary(
            suite_name=suite_name,
            iterations=self.iterations,
            avg_latency_ms=round(statistics.mean(latencies), 3),
            median_latency_ms=round(statistics.median(latencies), 3),
            p95_latency_ms=round(sorted_latencies[min(p95_idx, len(sorted_latencies) - 1)], 3),
            min_latency_ms=round(min(latencies), 3),
            max_latency_ms=round(max(latencies), 3),
            stddev_latency_ms=round(statistics.stdev(latencies) if len(latencies) > 1 else 0.0, 3),
            avg_total_bytes=first.total_wire_bytes,
            client_hello_bytes=first.client_hello_bytes,
            server_hello_bytes=first.server_hello_bytes,
            client_key_exchange_bytes=first.client_key_exchange_bytes,
            server_finished_bytes=first.server_finished_bytes,
        )

        return summary

    def _benchmark_single_handshake(
        self,
        suite_name: str,
        kyber_variant: str,
    ) -> HandshakeMetric:
        """Execute a single full handshake and measure timing + byte sizes."""
        identity = PQCProvider("ML-KEM-768")
        server_secret, server_public = identity.generate_keypair()
        client_private = Ed25519PrivateKey.generate()
        client_public = client_private.public_key().public_bytes_raw()
        client = KEMTLSClient(server_public, fingerprint(server_public), client_private)
        server = KEMTLSServer(server_secret, server_public, lambda key: {"client_id": "benchmark"} if key == client_public else None)

        start_time = time.perf_counter()
        c_cpu_start = time.process_time()

        # Step 1: Client -> ClientHello
        ch_bytes = client.initiate_handshake()

        s_cpu_start = time.process_time()

        # Step 2: Server -> ServerHello
        sh_bytes = server.process_client_hello(ch_bytes)

        s_cpu_end = time.process_time()

        # Step 3: Client -> ClientKeyExchange
        cke_bytes = client.process_server_hello(sh_bytes)

        c_cpu_end = time.process_time()

        # Step 4: Server -> ServerFinished
        sf_bytes, server_session = server.process_client_key_exchange(cke_bytes)

        # Step 5: Client processes ServerFinished
        client_session = client.process_server_finished(sf_bytes)

        end_time = time.perf_counter()

        total_latency_ms = (end_time - start_time) * 1000.0
        client_cpu_ms = (c_cpu_end - c_cpu_start) * 1000.0
        server_cpu_ms = (s_cpu_end - s_cpu_start) * 1000.0

        return HandshakeMetric(
            suite_name=suite_name,
            total_latency_ms=total_latency_ms,
            client_cpu_ms=client_cpu_ms,
            server_cpu_ms=server_cpu_ms,
            client_hello_bytes=len(ch_bytes),
            server_hello_bytes=len(sh_bytes),
            client_key_exchange_bytes=len(cke_bytes),
            server_finished_bytes=len(sf_bytes),
        )

    def run_all(self) -> dict:
        """
        Run benchmarks across all cryptographic suites and save JSON results.

        Suites:
            - ML-KEM-768 (ML-KEM-768)
            - Hybrid (X25519 + ML-KEM-768 — Signature-Free KEMTLS)
        """
        suites = [
            ("ML-KEM-768", "ML-KEM-768"),
            ("Hybrid (X25519 + ML-KEM-768)", "ML-KEM-768"),
        ]

        results = {}
        for display_name, variant in suites:
            summary = self.run_suite(display_name, variant)
            results[display_name] = asdict(summary)

        # Output JSON
        out_file = self.results_dir / "handshake_results.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        logger.info("Handshake benchmark results saved to %s", out_file)
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# Throughput Benchmark
# ═══════════════════════════════════════════════════════════════════════════════

PAYLOAD_SIZES = [64, 128, 512, 1024, 1400, 8192]


@dataclass
class PayloadResult:
    """Benchmark results for a single payload size."""
    payload_size_bytes: int
    frame_size_bytes: int
    overhead_bytes: int
    overhead_percentage: float
    iterations: int
    avg_enc_time_us: float
    avg_dec_time_us: float
    total_time_seconds: float
    throughput_mbps: float
    packets_per_second: float


class ThroughputBenchmark:
    """
    Throughput and encryption performance benchmark runner.

    Attributes:
        iterations: Number of packet encryption cycles per payload size.
        results_dir: Output directory for JSON metric files.
    """

    def __init__(
        self,
        iterations: int = 1000,
        results_dir: Optional[Path] = None,
    ) -> None:
        self.iterations = iterations
        self.results_dir = results_dir or (_PROJECT_ROOT / "benchmarks" / "results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def _create_mock_session(self):
        identity=PQCProvider("ML-KEM-768");secret,public=identity.generate_keypair();private=Ed25519PrivateKey.generate();client_public=private.public_key().public_bytes_raw()
        client=KEMTLSClient(public,fingerprint(public),private);server=KEMTLSServer(secret,public,lambda key:{"client_id":"benchmark"} if key==client_public else None)
        ch=client.initiate_handshake();sh=server.process_client_hello(ch);cke=client.process_server_hello(sh);sf,server_session=server.process_client_key_exchange(cke)
        return client.process_server_finished(sf),server_session

    def benchmark_payload_size(self, size: int) -> PayloadResult:
        """
        Benchmark encryption, decryption, and throughput for a specific payload size.

        Args:
            size: Payload size in bytes.

        Returns:
            PayloadResult: Performance metrics for this payload size.
        """
        session, receiver = self._create_mock_session()
        payload = os.urandom(size)

        # Warmup
        for _ in range(10):
            frame = session.encrypt_frame(payload)
            receiver.decrypt_frame(frame)

        enc_times_us: list[float] = []
        dec_times_us: list[float] = []
        frames: list[bytes] = []

        # Measure Encryption
        start_total = time.perf_counter()
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            frame = session.encrypt_frame(payload)
            t1 = time.perf_counter()
            enc_times_us.append((t1 - t0) * 1_000_000.0)
            frames.append(frame)

        # Measure Decryption
        for frame in frames:
            t0 = time.perf_counter()
            receiver.decrypt_frame(frame)
            t1 = time.perf_counter()
            dec_times_us.append((t1 - t0) * 1_000_000.0)
        end_total = time.perf_counter()

        total_duration = end_total - start_total
        frame_size = len(frames[0])
        overhead_bytes = frame_size - size
        overhead_pct = (overhead_bytes / size) * 100.0

        # Calculate throughput (Mbits processed per second)
        total_bits = (size * self.iterations * 2) * 8  # Both enc + dec
        throughput_mbps = (total_bits / 1_000_000.0) / total_duration
        pps = (self.iterations * 2) / total_duration

        return PayloadResult(
            payload_size_bytes=size,
            frame_size_bytes=frame_size,
            overhead_bytes=overhead_bytes,
            overhead_percentage=round(overhead_pct, 2),
            iterations=self.iterations,
            avg_enc_time_us=round(statistics.mean(enc_times_us), 2),
            avg_dec_time_us=round(statistics.mean(dec_times_us), 2),
            total_time_seconds=round(total_duration, 4),
            throughput_mbps=round(throughput_mbps, 2),
            packets_per_second=round(pps, 1),
        )

    def run_all(self) -> dict:
        """
        Run throughput benchmark across all standard payload sizes.

        Payload sizes: 64B, 128B, 512B, 1024B, 1400B (MTU), 8192B (Jumbo).
        """
        results = {}
        for size in PAYLOAD_SIZES:
            logger.info("Benchmarking payload size: %d bytes...", size)
            res = self.benchmark_payload_size(size)
            results[f"{size}B"] = asdict(res)

        out_file = self.results_dir / "throughput_results.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        logger.info("Throughput benchmark results saved to %s", out_file)
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# Packet Overhead Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

OVERHEAD_PAYLOAD_SIZES = [64, 128, 256, 512, 1024, 1400, 1442, 8192]


@dataclass
class LayerOverhead:
    """Overhead breakdown by protocol layer."""
    ip_header_bytes: int
    udp_header_bytes: int
    crypto_nonce_bytes: int
    crypto_tag_bytes: int
    length_prefix_bytes: int
    total_overhead_bytes: int


@dataclass
class PacketEfficiencyResult:
    """Wire efficiency measurement for a specific payload size."""
    payload_size_bytes: int
    wire_bytes_ipv4: int
    wire_bytes_ipv6: int
    overhead_ipv4_bytes: int
    overhead_ipv6_bytes: int
    efficiency_ipv4_percent: float
    efficiency_ipv6_percent: float


class PacketOverheadAnalyzer:
    """
    Packet capture and wire overhead analyzer.

    Attributes:
        results_dir: Output directory for JSON metric files.
    """

    def __init__(self, results_dir: Optional[Path] = None) -> None:
        self.results_dir = results_dir or (_PROJECT_ROOT / "benchmarks" / "results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def get_layer_breakdown(self, ipv6: bool = False) -> LayerOverhead:
        """
        Return the exact protocol header breakdown in bytes.

        Args:
            ipv6: Whether to calculate for IPv6 (True) or IPv4 (False).
        """
        ip_size = IPV6_HEADER_SIZE if ipv6 else IPV4_HEADER_SIZE
        total = ip_size + UDP_HEADER_SIZE + FRAME_OVERHEAD_TOTAL
        return LayerOverhead(
            ip_header_bytes=ip_size,
            udp_header_bytes=UDP_HEADER_SIZE,
            crypto_nonce_bytes=FRAME_OVERHEAD_TOTAL - FRAME_OVERHEAD_TAG,
            crypto_tag_bytes=FRAME_OVERHEAD_TAG,
            length_prefix_bytes=VPN_LENGTH_PREFIX,
            total_overhead_bytes=total,
        )

    def analyze_payload_efficiency(self, size: int) -> PacketEfficiencyResult:
        """
        Calculate wire payload efficiency percentage for a given payload size.

        Efficiency = (Payload Size / Total Wire Bytes) * 100%
        """
        v4_overhead = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + VPN_TOTAL_OVERHEAD
        v6_overhead = IPV6_HEADER_SIZE + UDP_HEADER_SIZE + VPN_TOTAL_OVERHEAD

        wire_v4 = size + v4_overhead
        wire_v6 = size + v6_overhead

        eff_v4 = (size / wire_v4) * 100.0
        eff_v6 = (size / wire_v6) * 100.0

        return PacketEfficiencyResult(
            payload_size_bytes=size,
            wire_bytes_ipv4=wire_v4,
            wire_bytes_ipv6=wire_v6,
            overhead_ipv4_bytes=v4_overhead,
            overhead_ipv6_bytes=v6_overhead,
            efficiency_ipv4_percent=round(eff_v4, 2),
            efficiency_ipv6_percent=round(eff_v6, 2),
        )

    def run_all(self) -> dict:
        """
        Analyze wire overhead and efficiency across standard payload sizes.

        Saves metrics to `benchmarks/results/packet_capture_results.json`.
        """
        v4_breakdown = self.get_layer_breakdown(ipv6=False)
        v6_breakdown = self.get_layer_breakdown(ipv6=True)

        efficiencies = [
            asdict(self.analyze_payload_efficiency(size))
            for size in OVERHEAD_PAYLOAD_SIZES
        ]

        results = {
            "layer_breakdown_ipv4": asdict(v4_breakdown),
            "layer_breakdown_ipv6": asdict(v6_breakdown),
            "payload_efficiencies": efficiencies,
        }

        out_file = self.results_dir / "packet_capture_results.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        logger.info("Packet capture overhead analysis saved to %s", out_file)
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# Chart Generator
# ═══════════════════════════════════════════════════════════════════════════════

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
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt
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
        import matplotlib.pyplot as plt

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
        import matplotlib.pyplot as plt

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
        import matplotlib.pyplot as plt

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
        import matplotlib.pyplot as plt

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
"""
Unified Performance Benchmarking Runner.
Consolidates handshake, throughput, packet capture, and chart generation.
"""
