"""
Automated Pytest Suite for Performance Benchmarks Module (`benchmarks/`).

Tests:
    - HandshakeBenchmark: execution, metric structure, JSON export
    - ThroughputBenchmark: payload scaling, latency calculation, JSON export
    - PacketOverheadAnalyzer: layer breakdown calculations, payload efficiency
    - ChartGenerator: PNG figure creation and verification
"""

import os
import json
import pytest
from pathlib import Path

from benchmarks.runner import HandshakeBenchmark, SuiteSummary
from benchmarks.runner import ThroughputBenchmark, PAYLOAD_SIZES
from benchmarks.runner import PacketOverheadAnalyzer
from benchmarks.runner import ChartGenerator


@pytest.fixture
def tmp_results_dir(tmp_path):
    """Temporary results directory for isolated test outputs."""
    d = tmp_path / "results"
    d.mkdir()
    return d


class TestHandshakeBenchmark:
    """Unit tests for HandshakeBenchmark."""

    def test_single_handshake_execution(self):
        bench = HandshakeBenchmark(iterations=2, warmup_runs=1)
        metric = bench._benchmark_single_handshake("TestSuite", "Kyber768")
        assert metric.total_latency_ms > 0.0
        assert metric.client_hello_bytes > 0
        assert metric.server_hello_bytes > 0
        assert metric.client_key_exchange_bytes > 0
        assert metric.server_finished_bytes > 0
        assert metric.total_wire_bytes > 0

    def test_run_suite(self, tmp_results_dir):
        bench = HandshakeBenchmark(iterations=3, warmup_runs=1, results_dir=tmp_results_dir)
        summary = bench.run_suite("TestSuite", "Kyber768")
        assert isinstance(summary, SuiteSummary)
        assert summary.iterations == 3
        assert summary.avg_latency_ms > 0.0
        assert summary.p95_latency_ms >= summary.min_latency_ms

    def test_run_all(self, tmp_results_dir):
        bench = HandshakeBenchmark(iterations=2, warmup_runs=1, results_dir=tmp_results_dir)
        results = bench.run_all()
        assert "Hybrid (X25519 + Kyber768)" in results
        assert (tmp_results_dir / "handshake_results.json").exists()


class TestThroughputBenchmark:
    """Unit tests for ThroughputBenchmark."""

    def test_benchmark_single_payload(self):
        bench = ThroughputBenchmark(iterations=10)
        res = bench.benchmark_payload_size(512)
        assert res.payload_size_bytes == 512
        assert res.frame_size_bytes == 512 + 28  # 28 bytes crypto overhead
        assert res.throughput_mbps > 0.0
        assert res.packets_per_second > 0.0

    def test_run_all(self, tmp_results_dir):
        bench = ThroughputBenchmark(iterations=5, results_dir=tmp_results_dir)
        results = bench.run_all()
        assert "1400B" in results
        assert (tmp_results_dir / "throughput_results.json").exists()


class TestPacketOverheadAnalyzer:
    """Unit tests for PacketOverheadAnalyzer."""

    def test_layer_breakdown_ipv4(self):
        analyzer = PacketOverheadAnalyzer()
        v4 = analyzer.get_layer_breakdown(ipv6=False)
        assert v4.ip_header_bytes == 20
        assert v4.udp_header_bytes == 8
        assert v4.crypto_nonce_bytes == 12
        assert v4.crypto_tag_bytes == 16
        assert v4.length_prefix_bytes == 2
        assert v4.total_overhead_bytes == 58

    def test_layer_breakdown_ipv6(self):
        analyzer = PacketOverheadAnalyzer()
        v6 = analyzer.get_layer_breakdown(ipv6=True)
        assert v6.ip_header_bytes == 40
        assert v6.total_overhead_bytes == 78

    def test_analyze_payload_efficiency(self):
        analyzer = PacketOverheadAnalyzer()
        eff = analyzer.analyze_payload_efficiency(1400)
        assert eff.payload_size_bytes == 1400
        assert eff.wire_bytes_ipv4 == 1458
        assert 95.0 < eff.efficiency_ipv4_percent < 97.0

    def test_run_all(self, tmp_results_dir):
        analyzer = PacketOverheadAnalyzer(results_dir=tmp_results_dir)
        results = analyzer.run_all()
        assert "layer_breakdown_ipv4" in results
        assert (tmp_results_dir / "packet_capture_results.json").exists()


class TestChartGenerator:
    """Unit tests for ChartGenerator."""

    def test_generate_all_charts(self, tmp_results_dir):
        # Create mock JSON result files first
        hb = HandshakeBenchmark(iterations=2, warmup_runs=1, results_dir=tmp_results_dir)
        hb.run_all()

        tb = ThroughputBenchmark(iterations=5, results_dir=tmp_results_dir)
        tb.run_all()

        pca = PacketOverheadAnalyzer(results_dir=tmp_results_dir)
        pca.run_all()

        # Generate charts
        cg = ChartGenerator(results_dir=tmp_results_dir)
        chart_paths = cg.generate_all()

        assert len(chart_paths) == 4
        for p in chart_paths:
            assert p.exists()
            assert p.stat().st_size > 0  # Non-empty PNG file
