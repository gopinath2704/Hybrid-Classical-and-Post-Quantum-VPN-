"""Unified performance benchmarking runner — handshake, throughput, overhead, charts."""

from __future__ import annotations

import argparse
import csv
import os
import platform
import subprocess
import sys
import time
import json
import logging
import statistics
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from crypto.hybrid_crypto import ECCProvider, PQCProvider, HybridKEM, KeyManager, get_crypto_status
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
    KEMTLSClientV3,
    KEMTLSServerV3,
    KEMTLSClientMLDSA,
    KEMTLSServerMLDSA,
    PROTOCOL_VERSION_V3,
    PROTOCOL_VERSION_V3_MLDSA,
)
from crypto.hybrid_crypto import PQSignatureProvider
from vpn.network import (
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

PROTOCOL_VERSION = 2

_SUITE_VERSIONS = {
    "v2-ed25519": 2,
    "v3-kem": 3,
    "v3-mldsa": 0x31,
}

NETEM_PROFILES: dict[str, dict] = {
    "lan":        {"rtt_ms": 0,   "loss_pct": 0, "mtu": 1500},
    "metro":      {"rtt_ms": 50,  "loss_pct": 0, "mtu": 1500},
    "continent":  {"rtt_ms": 200, "loss_pct": 0, "mtu": 1500},
    "lossy-1":    {"rtt_ms": 50,  "loss_pct": 1, "mtu": 1500},
    "lossy-5":    {"rtt_ms": 50,  "loss_pct": 5, "mtu": 1500},
    "mtu-1280":   {"rtt_ms": 50,  "loss_pct": 0, "mtu": 1280},
    "mtu-1400":   {"rtt_ms": 50,  "loss_pct": 0, "mtu": 1400},
    "worst":      {"rtt_ms": 200, "loss_pct": 5, "mtu": 1280},
}


def _cpu_model() -> str:
    try:
        r = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "Model name" in line:
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine()


def _git_commit() -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
            cwd=_PROJECT_ROOT,
        )
        return r.stdout.strip()
    except Exception:
        return "unknown"


def require_native_pqc():
    status = get_crypto_status()
    if status["pqc_mode"] != "native_liboqs":
        print(f"FATAL: pqc_mode={status['pqc_mode']}; native liboqs required "
              f"for trustworthy benchmarks.", file=sys.stderr)
        sys.exit(1)
    return status


def _liboqs_version() -> str:
    try:
        import oqs
        if hasattr(oqs, "oqs_version"):
            return oqs.oqs_version()
    except Exception:
        pass
    return "unknown"


def collect_environment() -> dict:
    status = get_crypto_status()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "protocol_version": PROTOCOL_VERSION,
        "pqc_mode": status["pqc_mode"],
        "liboqs_version": _liboqs_version(),
        "cpu_model": _cpu_model(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }


def _results_dir_for_run() -> Path:
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    commit = _git_commit()
    d = _PROJECT_ROOT / "results" / f"{date_str}-{commit}"
    d.mkdir(parents=True, exist_ok=True)
    return d


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
    protocol_version: int
    iterations: int
    avg_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    stddev_latency_ms: float
    avg_client_cpu_ms: float
    median_client_cpu_ms: float
    stddev_client_cpu_ms: float
    avg_server_cpu_ms: float
    median_server_cpu_ms: float
    stddev_server_cpu_ms: float
    avg_total_bytes: float
    client_hello_bytes: int
    server_hello_bytes: int
    client_key_exchange_bytes: int
    server_finished_bytes: int


class HandshakeBenchmark:
    """Performance benchmark runner for KEMTLS & hybrid key exchanges."""

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
        """Run handshake benchmark for a specific cryptographic suite."""
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
        client_cpus = [m.client_cpu_ms for m in metrics]
        server_cpus = [m.server_cpu_ms for m in metrics]
        sorted_latencies = sorted(latencies)
        n = len(sorted_latencies)
        p95_idx = min(int(n * 0.95), n - 1)
        p99_idx = min(int(n * 0.99), n - 1)

        first = metrics[0]
        _sd = lambda xs: round(statistics.stdev(xs), 3) if len(xs) > 1 else 0.0

        summary = SuiteSummary(
            suite_name=suite_name,
            protocol_version=_SUITE_VERSIONS.get(suite_name, PROTOCOL_VERSION),
            iterations=self.iterations,
            avg_latency_ms=round(statistics.mean(latencies), 3),
            median_latency_ms=round(statistics.median(latencies), 3),
            p95_latency_ms=round(sorted_latencies[p95_idx], 3),
            p99_latency_ms=round(sorted_latencies[p99_idx], 3),
            min_latency_ms=round(min(latencies), 3),
            max_latency_ms=round(max(latencies), 3),
            stddev_latency_ms=_sd(latencies),
            avg_client_cpu_ms=round(statistics.mean(client_cpus), 3),
            median_client_cpu_ms=round(statistics.median(client_cpus), 3),
            stddev_client_cpu_ms=_sd(client_cpus),
            avg_server_cpu_ms=round(statistics.mean(server_cpus), 3),
            median_server_cpu_ms=round(statistics.median(server_cpus), 3),
            stddev_server_cpu_ms=_sd(server_cpus),
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
        if suite_name in ("v3-kem", "v3-mldsa"):
            return self._benchmark_handshake_suite(suite_name)
        identity = PQCProvider("ML-KEM-768")
        server_secret, server_public = identity.generate_keypair()
        client_private = Ed25519PrivateKey.generate()
        client_public = client_private.public_key().public_bytes_raw()
        client = KEMTLSClient(server_public, fingerprint(server_public), client_private)
        server = KEMTLSServer(server_secret, server_public, lambda key: {"client_id": "benchmark"} if key == client_public else None)
        return self._run_handshake(suite_name, client, server)

    def _benchmark_handshake_suite(self, suite_name: str) -> HandshakeMetric:
        """Benchmark v3-kem or v3-mldsa handshake."""
        kem = PQCProvider("ML-KEM-768")
        server_sk, server_pk = kem.generate_keypair()
        server_fp = fingerprint(server_pk)

        if suite_name == "v3-kem":
            client_sk, client_pk = kem.generate_keypair()
            client_fp = fingerprint(client_pk)
            client = KEMTLSClientV3(server_pk, server_fp, client_sk, client_pk)
            server = KEMTLSServerV3(server_sk, server_pk,
                lambda h, _cpk=client_pk, _cfp=client_fp: (_cpk, {"client_id": "bench"}) if h == _cfp else None)
        else:
            sig = PQSignatureProvider()
            client_sig_sk, client_sig_pk = sig.generate_keypair()
            client_fp = fingerprint(client_sig_pk)
            client = KEMTLSClientMLDSA(server_pk, server_fp, client_sig_sk, client_sig_pk)
            server = KEMTLSServerMLDSA(server_sk, server_pk,
                lambda h, _cpk=client_sig_pk, _cfp=client_fp: (_cpk, {"client_id": "bench"}) if h == _cfp else None)

        return self._run_handshake(suite_name, client, server)

    def _run_handshake(self, suite_name: str, client, server) -> HandshakeMetric:
        start_time = time.perf_counter()

        c_cpu0 = time.process_time()
        ch_bytes = client.initiate_handshake()
        c_cpu1 = time.process_time()

        s_cpu0 = time.process_time()
        sh_bytes = server.process_client_hello(ch_bytes)
        s_cpu1 = time.process_time()

        c_cpu2 = time.process_time()
        cke_bytes = client.process_server_hello(sh_bytes)
        c_cpu3 = time.process_time()

        s_cpu2 = time.process_time()
        sf_bytes, _ = server.process_client_key_exchange(cke_bytes)
        s_cpu3 = time.process_time()

        c_cpu4 = time.process_time()
        client.process_server_finished(sf_bytes)
        c_cpu5 = time.process_time()

        end_time = time.perf_counter()

        client_cpu = (c_cpu1 - c_cpu0) + (c_cpu3 - c_cpu2) + (c_cpu5 - c_cpu4)
        server_cpu = (s_cpu1 - s_cpu0) + (s_cpu3 - s_cpu2)

        return HandshakeMetric(
            suite_name=suite_name,
            total_latency_ms=(end_time - start_time) * 1000.0,
            client_cpu_ms=client_cpu * 1000.0,
            server_cpu_ms=server_cpu * 1000.0,
            client_hello_bytes=len(ch_bytes),
            server_hello_bytes=len(sh_bytes),
            client_key_exchange_bytes=len(cke_bytes),
            server_finished_bytes=len(sf_bytes),
        )

    def run_all(self, profile: str = "lan", suite_filter: list[str] | None = None) -> dict:
        """Run benchmarks across cryptographic suites and save JSON/CSV results."""
        all_suites = [
            ("v2-ed25519", "ML-KEM-768"),
            ("Hybrid (X25519 + ML-KEM-768)", "ML-KEM-768"),
            ("v3-kem", "ML-KEM-768"),
            ("v3-mldsa", "ML-KEM-768"),
        ]

        if suite_filter:
            suites = [(n, v) for n, v in all_suites if n in suite_filter]
        else:
            suites = all_suites[:2]

        env = collect_environment()
        results = {"environment": env, "profile": profile, "suites": {}}
        for display_name, variant in suites:
            summary = self.run_suite(display_name, variant)
            results["suites"][display_name] = asdict(summary)

        out_file = self.results_dir / "handshake_results.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        csv_file = self.results_dir / "handshake_results.csv"
        _write_suite_csv(csv_file, results)

        logger.info("Handshake benchmark results saved to %s", out_file)
        return results


def _write_suite_csv(path: Path, results: dict) -> None:
    env = results["environment"]
    profile = results.get("profile", "lan")
    suites = results["suites"]
    if not suites:
        return
    first_suite = next(iter(suites.values()))
    env_cols = ["git_commit", "liboqs_version", "cpu_model", "profile"]
    fieldnames = env_cols + list(first_suite.keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for suite_data in suites.values():
            row = {
                "git_commit": env["git_commit"],
                "liboqs_version": env["liboqs_version"],
                "cpu_model": env["cpu_model"],
                "profile": profile,
            }
            row.update(suite_data)
            w.writerow(row)


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
    """Throughput and encryption performance benchmark runner."""

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
        """Benchmark encryption, decryption, and throughput for a given payload size."""
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
        """Run throughput benchmark across all standard payload sizes."""
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
    """Packet wire overhead and efficiency analyzer."""

    def __init__(self, results_dir: Optional[Path] = None) -> None:
        self.results_dir = results_dir or (_PROJECT_ROOT / "benchmarks" / "results")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def get_layer_breakdown(self, ipv6: bool = False) -> LayerOverhead:
        """Return the exact protocol header breakdown in bytes."""
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
        """Calculate wire payload efficiency for a given payload size."""
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
        """Analyze wire overhead and efficiency across standard payload sizes."""
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


class ChartGenerator:
    """Matplotlib figure generator for post-quantum VPN benchmark results."""

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

    @staticmethod
    def _load_suites(path: Path) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return raw.get("suites", raw)

    def generate_handshake_latency_chart(self) -> Path:
        """Generate bar chart comparing handshake latency (ms) across suites."""
        import matplotlib.pyplot as plt

        json_file = self.results_dir / "handshake_results.json"
        if not json_file.exists():
            raise FileNotFoundError(f"Missing {json_file}")

        data = self._load_suites(json_file)

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

        data = self._load_suites(json_file)

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
def run_full_suite(iterations: int = 50, profile: str = "lan",
                   suite_filter: list[str] | None = None) -> None:
    """Run full benchmark suite and generate chart figures."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")

    results_dir = _results_dir_for_run()

    print("\n" + "=" * 70)
    print(f"  HYBRID PQC-VPN PERFORMANCE BENCHMARK SUITE ({iterations} iterations)")
    print(f"  Profile: {profile}  |  Output: {results_dir}")
    if suite_filter:
        print(f"  Suites: {', '.join(suite_filter)}")
    print("=" * 70 + "\n")

    env = collect_environment()
    with open(results_dir / "environment.json", "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)

    print("> [1/4] Running KEMTLS Handshake Latency & Size Benchmark...")
    hb = HandshakeBenchmark(iterations=iterations, results_dir=results_dir)
    hb.run_all(profile=profile, suite_filter=suite_filter)

    print("\n> [2/4] Running Encrypted Tunnel Throughput & Payload Scaling Benchmark...")
    tb = ThroughputBenchmark(iterations=iterations * 10, results_dir=results_dir)
    tb.run_all()

    print("\n> [3/4] Running Wire Packet Overhead Analysis...")
    pca = PacketOverheadAnalyzer(results_dir=results_dir)
    pca.run_all()

    print("\n> [4/4] Generating Publication Chart Figures...")
    cg = ChartGenerator(results_dir=results_dir)
    cg.generate_all()

    print("\n" + "=" * 70)
    print("  ALL BENCHMARKS COMPLETED SUCCESSFULLY!")
    print(f"  Results saved to {results_dir}")
    print("=" * 70 + "\n")


def main() -> None:
    """Parse CLI arguments and run benchmark suite."""
    require_native_pqc()
    parser = argparse.ArgumentParser(
        description="Hybrid PQC-VPN Benchmark Suite",
    )
    parser.add_argument(
        "--all", action="store_true", default=True,
        help="Run all benchmarks and generate chart figures (default)",
    )
    parser.add_argument(
        "--iterations", type=int, default=50,
        help="Number of iterations for handshake benchmark (default: 50)",
    )
    parser.add_argument(
        "--profile",
        choices=list(NETEM_PROFILES.keys()),
        default="lan",
        help="Network emulation profile (default: lan). "
             "Available: " + ", ".join(NETEM_PROFILES.keys()),
    )
    parser.add_argument(
        "--suite",
        type=str,
        default=None,
        help="Comma-separated suite names to benchmark "
             "(v2-ed25519, v3-kem, v3-mldsa). Default: v2 suites only.",
    )
    args = parser.parse_args()

    suite_filter = [s.strip() for s in args.suite.split(",")] if args.suite else None
    run_full_suite(iterations=args.iterations, profile=args.profile,
                   suite_filter=suite_filter)


if __name__ == "__main__":
    main()
