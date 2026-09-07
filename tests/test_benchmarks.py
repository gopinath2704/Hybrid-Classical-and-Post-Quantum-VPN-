"""Benchmark output coverage restored with v2 sizes and overhead."""
from benchmarks.runner import HandshakeBenchmark,ThroughputBenchmark,PacketOverheadAnalyzer
def test_handshake_benchmark_output(tmp_path):
    result=HandshakeBenchmark(iterations=1,warmup_runs=0,results_dir=tmp_path).run_all();assert "Hybrid (X25519 + ML-KEM-768)" in result;assert (tmp_path/"handshake_results.json").exists()
def test_throughput_benchmark_frame_size(tmp_path):
    result=ThroughputBenchmark(iterations=2,results_dir=tmp_path).benchmark_payload_size(512);assert result.frame_size_bytes==512+42 and result.throughput_mbps>0
def test_packet_overhead_output(tmp_path):
    analyzer=PacketOverheadAnalyzer(results_dir=tmp_path);v4=analyzer.get_layer_breakdown(False);assert v4.total_overhead_bytes==70
    assert analyzer.analyze_payload_efficiency(1400).wire_bytes_ipv4==1470
    assert (tmp_path/"packet_capture_results.json").exists() is False
    analyzer.run_all();assert (tmp_path/"packet_capture_results.json").exists()
