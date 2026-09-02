"""
Performance Benchmarking Suite — Public API & Unified Runner.

Re-exports all benchmark components from the unified runner module
and provides a CLI entry point:

    python -m benchmarks --all
    python -m benchmarks --iterations 50
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from benchmarks.runner import (
    HandshakeBenchmark,
    HandshakeMetric,
    SuiteSummary,
    ThroughputBenchmark,
    PayloadResult,
    PAYLOAD_SIZES,
    PacketOverheadAnalyzer,
    LayerOverhead,
    PacketEfficiencyResult,
    ChartGenerator,
)

__all__ = [
    "HandshakeBenchmark",
    "HandshakeMetric",
    "SuiteSummary",
    "ThroughputBenchmark",
    "PayloadResult",
    "PAYLOAD_SIZES",
    "PacketOverheadAnalyzer",
    "LayerOverhead",
    "PacketEfficiencyResult",
    "ChartGenerator",
]


def run_full_suite(iterations: int = 50) -> None:
    """Run full benchmark suite and generate chart figures."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")

    print("\n" + "=" * 70)
    print(f"  HYBRID PQC-VPN PERFORMANCE BENCHMARK SUITE ({iterations} iterations)")
    print("=" * 70 + "\n")

    # Step 1: Handshake Benchmark
    print("> [1/4] Running KEMTLS Handshake Latency & Size Benchmark...")
    hb = HandshakeBenchmark(iterations=iterations)
    hb.run_all()

    # Step 2: Throughput Benchmark
    print("\n> [2/4] Running Encrypted Tunnel Throughput & Payload Scaling Benchmark...")
    tb = ThroughputBenchmark(iterations=iterations * 10)
    tb.run_all()

    # Step 3: Packet Capture Overhead Analysis
    print("\n> [3/4] Running Wire Packet Overhead Analysis...")
    pca = PacketOverheadAnalyzer()
    pca.run_all()

    # Step 4: Chart Figure Generation
    print("\n> [4/4] Generating Publication Chart Figures...")
    cg = ChartGenerator()
    cg.generate_all()

    print("\n" + "=" * 70)
    print("  ALL BENCHMARKS COMPLETED SUCCESSFULLY!")
    print("  Results saved to benchmarks/results/")
    print("=" * 70 + "\n")


def main() -> None:
    """Parse CLI arguments and run benchmark suite."""
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
    args = parser.parse_args()

    run_full_suite(iterations=args.iterations)


if __name__ == "__main__":
    main()
