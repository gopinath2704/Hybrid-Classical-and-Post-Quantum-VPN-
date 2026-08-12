"""
Handshake Performance Benchmark Module.

Quantifies connection setup timing (latency in ms), wire payload message sizes
(bytes for ClientHello, ServerHello, ClientKeyExchange, ServerFinished), and
CPU processing overhead across 5 cryptographic suites:

    1. Classical X25519 (ECDH)
    2. ML-KEM-512 (Kyber512)
    3. ML-KEM-768 (Kyber768)
    4. ML-KEM-1024 (Kyber1024)
    5. Hybrid (X25519 + Kyber768 — Signature-Free KEMTLS)

Exports benchmark metrics to `benchmarks/results/handshake_results.json`.
"""

from __future__ import annotations

import sys
import time
import json
import logging
import statistics
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# Ensure root is on path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from crypto.hybrid_crypto import ECCProvider, PQCProvider, HybridKEM, KeyManager
from handshake.kemtls import (
    KEMTLSClient,
    KEMTLSServer,
    ClientHello,
    ServerHello,
    ClientKeyExchange,
    ServerFinished,
)

logger = logging.getLogger("pqvpn.benchmarks.handshake")


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

    def run_suite(self, suite_name: str, kyber_variant: str = "Kyber768") -> SuiteSummary:
        """
        Run handshake benchmark for a specific cryptographic suite.

        Args:
            suite_name: Display name for the suite.
            kyber_variant: Kyber variant ("Kyber512", "Kyber768", "Kyber1024").

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
        # Initialize client and server
        client = KEMTLSClient(pqc_algorithm=kyber_variant)
        server = KEMTLSServer(pqc_algorithm=kyber_variant)

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
            - Classical X25519 (ECDH)
            - ML-KEM-512 (Kyber512)
            - ML-KEM-768 (Kyber768)
            - ML-KEM-1024 (Kyber1024)
            - Hybrid (X25519 + Kyber768 — Signature-Free KEMTLS)
        """
        suites = [
            ("ML-KEM-768 (Kyber768)", "Kyber768"),
            ("Hybrid (X25519 + Kyber768)", "Kyber768"),
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


def main():
    """CLI entry point for running handshake benchmark directly."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")
    bench = HandshakeBenchmark(iterations=50)
    results = bench.run_all()
    print("\n" + "=" * 65)
    print("  HANDSHAKE BENCHMARK SUMMARY")
    print("=" * 65)
    for name, data in results.items():
        print(f"\nSuite: {name}")
        print(f"  Avg Latency:  {data['avg_latency_ms']:.3f} ms (p95: {data['p95_latency_ms']:.3f} ms)")
        print(f"  Total Bytes:  {data['avg_total_bytes']:,} B")
        print(f"  Message Breakdown:")
        print(f"    - ClientHello:       {data['client_hello_bytes']:,} B")
        print(f"    - ServerHello:       {data['server_hello_bytes']:,} B")
        print(f"    - ClientKeyExchange: {data['client_key_exchange_bytes']:,} B")
        print(f"    - ServerFinished:    {data['server_finished_bytes']:,} B")


if __name__ == "__main__":
    main()
"""
Handshake benchmark module placeholder.
"""
