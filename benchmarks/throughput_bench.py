"""
Encrypted Tunnel Throughput & Payload Scaling Benchmark Module.

Quantifies data-plane performance of the AES-256-GCM encrypted VPN tunnel across
varying payload sizes (64B, 128B, 512B, 1024B, 1400B, 8192B):

    - Encryption & decryption latency per frame (microseconds)
    - Throughput (Mbps / Gbps)
    - Packet processing rate (packets per second / pps)
    - Framing overhead ratio (%)

Exports benchmark metrics to `benchmarks/results/throughput_results.json`.
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

from crypto.hybrid_crypto import HybridKEM
from handshake.kemtls import HandshakeSession
from vpn.engine import FRAME_OVERHEAD_TOTAL

logger = logging.getLogger("pqvpn.benchmarks.throughput")

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

    def _create_mock_session(self) -> HandshakeSession:
        """Create a HandshakeSession initialized with random 32-byte AES-256-GCM key."""
        session_key = os.urandom(32)
        session_id = os.urandom(32)
        return HandshakeSession(
            session_id=session_id,
            client_random=os.urandom(32),
            server_random=os.urandom(32),
            encryption_key=session_key,
            mac_key=os.urandom(32),
        )

    def benchmark_payload_size(self, size: int) -> PayloadResult:
        """
        Benchmark encryption, decryption, and throughput for a specific payload size.

        Args:
            size: Payload size in bytes.

        Returns:
            PayloadResult: Performance metrics for this payload size.
        """
        session = self._create_mock_session()
        payload = os.urandom(size)

        # Warmup
        for _ in range(10):
            frame = session.encrypt_frame(payload)
            session.decrypt_frame(frame)

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
            session.decrypt_frame(frame)
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


def main():
    """CLI entry point for throughput benchmark."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)s │ %(message)s")
    bench = ThroughputBenchmark(iterations=1000)
    results = bench.run_all()
    print("\n" + "=" * 70)
    print("  TUNNEL THROUGHPUT BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"{'Payload':<10} {'Enc Latency':<14} {'Dec Latency':<14} {'Throughput':<16} {'PPS':<12}")
    print("-" * 70)
    for key, data in results.items():
        print(
            f"{key:<10} "
            f"{data['avg_enc_time_us']:>6.2f} us        "
            f"{data['avg_dec_time_us']:>6.2f} us        "
            f"{data['throughput_mbps']:>8.2f} Mbps    "
            f"{data['packets_per_second']:>10.0f} pps"
        )


if __name__ == "__main__":
    main()
"""
Throughput benchmark module placeholder.
"""
