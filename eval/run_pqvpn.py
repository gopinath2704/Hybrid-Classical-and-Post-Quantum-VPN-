#!/usr/bin/env python3
"""Evaluate PQVPN handshake suites: latency, wire bytes, CPU, throughput, memory.

Outputs one CSV row per (suite × metric) to stdout or a file.  Designed to be
called by eval/run_all.py but also works standalone:

    python eval/run_pqvpn.py --iterations 50 --out results/eval/raw/pqvpn.csv
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import statistics
import sys
import time
from dataclasses import dataclass, asdict, fields
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from crypto.hybrid_crypto import PQCProvider, PQSignatureProvider, HybridKEM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vpn.identity import fingerprint
from handshake.kemtls import (
    KEMTLSClient, KEMTLSServer,
    KEMTLSClientV3, KEMTLSServerV3,
    KEMTLSClientMLDSA, KEMTLSServerMLDSA,
    HandshakeSession, FrameType,
)


@dataclass
class HandshakeResult:
    suite: str
    latency_ms: float
    client_cpu_ms: float
    server_cpu_ms: float
    client_hello_bytes: int
    server_hello_bytes: int
    client_key_exchange_bytes: int
    server_finished_bytes: int
    total_wire_bytes: int


def _make_v2():
    kem = PQCProvider("ML-KEM-768")
    sk, pk = kem.generate_keypair()
    cpriv = Ed25519PrivateKey.generate()
    cpub = cpriv.public_key().public_bytes_raw()
    c = KEMTLSClient(pk, fingerprint(pk), cpriv)
    s = KEMTLSServer(sk, pk, lambda k: {"client_id": "eval"} if k == cpub else None)
    return c, s


def _make_v3():
    kem = PQCProvider("ML-KEM-768")
    sk, pk = kem.generate_keypair()
    csk, cpk = kem.generate_keypair()
    cfp = fingerprint(cpk)
    c = KEMTLSClientV3(pk, fingerprint(pk), csk, cpk)
    s = KEMTLSServerV3(sk, pk, lambda h: (cpk, {"client_id": "eval"}) if h == cfp else None)
    return c, s


def _make_mldsa():
    kem = PQCProvider("ML-KEM-768")
    sk, pk = kem.generate_keypair()
    sig = PQSignatureProvider()
    ssk, spk = sig.generate_keypair()
    cfp = fingerprint(spk)
    c = KEMTLSClientMLDSA(pk, fingerprint(pk), ssk, spk)
    s = KEMTLSServerMLDSA(sk, pk, lambda h: (spk, {"client_id": "eval"}) if h == cfp else None)
    return c, s


_SUITE_FACTORY = {
    "v2-ed25519": _make_v2,
    "v3-kem": _make_v3,
    "v3-mldsa": _make_mldsa,
}


def run_handshake(suite: str) -> HandshakeResult:
    c, s = _SUITE_FACTORY[suite]()
    t0 = time.perf_counter()
    c_cpu0 = time.process_time()
    ch = c.initiate_handshake()
    s_cpu0 = time.process_time()
    sh = s.process_client_hello(ch)
    s_cpu1 = time.process_time()
    cke = c.process_server_hello(sh)
    c_cpu1 = time.process_time()
    sf, ss = s.process_client_key_exchange(cke)
    cs = c.process_server_finished(sf)
    t1 = time.perf_counter()
    return HandshakeResult(
        suite=suite,
        latency_ms=(t1 - t0) * 1000,
        client_cpu_ms=(c_cpu1 - c_cpu0) * 1000,
        server_cpu_ms=(s_cpu1 - s_cpu0) * 1000,
        client_hello_bytes=len(ch),
        server_hello_bytes=len(sh),
        client_key_exchange_bytes=len(cke),
        server_finished_bytes=len(sf),
        total_wire_bytes=len(ch) + len(sh) + len(cke) + len(sf),
    )


def measure_handshakes_per_sec(suite: str, duration_s: float = 2.0) -> float:
    count = 0
    deadline = time.perf_counter() + duration_s
    while time.perf_counter() < deadline:
        run_handshake(suite)
        count += 1
    elapsed = duration_s
    return count / elapsed


def measure_encrypt_throughput(session: HandshakeSession, packet_size: int = 1400,
                                duration_s: float = 2.0) -> dict:
    packet = os.urandom(packet_size)
    count = 0
    deadline = time.perf_counter() + duration_s
    t0 = time.perf_counter()
    while time.perf_counter() < deadline:
        session.encrypt_frame(packet)
        count += 1
    elapsed = time.perf_counter() - t0
    return {
        "packets": count,
        "elapsed_s": elapsed,
        "pps": count / elapsed,
        "mbps": (count * packet_size * 8) / (elapsed * 1e6),
    }


def measure_memory_per_session(suite: str, n_sessions: int = 100) -> float:
    try:
        import psutil
        proc = psutil.Process()
        mem_before = proc.memory_info().rss
        sessions = []
        for _ in range(n_sessions):
            c, s = _SUITE_FACTORY[suite]()
            ch = c.initiate_handshake()
            sh = s.process_client_hello(ch)
            cke = c.process_server_hello(sh)
            sf, ss = s.process_client_key_exchange(cke)
            cs = c.process_server_finished(sf)
            sessions.append((cs, ss))
        mem_after = proc.memory_info().rss
        return (mem_after - mem_before) / n_sessions
    except ImportError:
        return -1.0


@dataclass
class SuiteEvaluation:
    suite: str
    iterations: int
    median_latency_ms: float
    p95_latency_ms: float
    stddev_latency_ms: float
    median_client_cpu_ms: float
    median_server_cpu_ms: float
    total_wire_bytes: int
    client_hello_bytes: int
    server_hello_bytes: int
    client_key_exchange_bytes: int
    server_finished_bytes: int
    handshakes_per_sec: float
    encrypt_pps: float
    encrypt_mbps: float
    memory_bytes_per_session: float


def evaluate_suite(suite: str, iterations: int = 50, warmup: int = 5) -> SuiteEvaluation:
    for _ in range(warmup):
        run_handshake(suite)

    results = [run_handshake(suite) for _ in range(iterations)]
    latencies = sorted(r.latency_ms for r in results)
    client_cpus = [r.client_cpu_ms for r in results]
    server_cpus = [r.server_cpu_ms for r in results]
    n = len(latencies)

    c, s = _SUITE_FACTORY[suite]()
    ch = c.initiate_handshake()
    sh = s.process_client_hello(ch)
    cke = c.process_server_hello(sh)
    sf, ss = s.process_client_key_exchange(cke)
    cs = c.process_server_finished(sf)
    tp = measure_encrypt_throughput(cs)

    return SuiteEvaluation(
        suite=suite,
        iterations=iterations,
        median_latency_ms=round(statistics.median(latencies), 3),
        p95_latency_ms=round(latencies[min(int(n * 0.95), n - 1)], 3),
        stddev_latency_ms=round(statistics.stdev(latencies), 3) if n > 1 else 0.0,
        median_client_cpu_ms=round(statistics.median(client_cpus), 3),
        median_server_cpu_ms=round(statistics.median(server_cpus), 3),
        total_wire_bytes=results[0].total_wire_bytes,
        client_hello_bytes=results[0].client_hello_bytes,
        server_hello_bytes=results[0].server_hello_bytes,
        client_key_exchange_bytes=results[0].client_key_exchange_bytes,
        server_finished_bytes=results[0].server_finished_bytes,
        handshakes_per_sec=round(measure_handshakes_per_sec(suite), 1),
        encrypt_pps=round(tp["pps"], 0),
        encrypt_mbps=round(tp["mbps"], 1),
        memory_bytes_per_session=round(measure_memory_per_session(suite), 0),
    )


def collect_sanity() -> dict:
    import platform
    info = {
        "hostname": platform.node(),
        "python": platform.python_version(),
        "cpu": platform.processor() or "unknown",
        "arch": platform.machine(),
        "os": platform.platform(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            info["cpu_governor"] = f.read().strip()
    except (FileNotFoundError, PermissionError):
        info["cpu_governor"] = "unknown"
    try:
        import oqs
        info["liboqs"] = getattr(oqs, "__version__", "available")
    except ImportError:
        info["liboqs"] = "unavailable"
    return info


def main():
    parser = argparse.ArgumentParser(description="PQVPN evaluation benchmark")
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--suites", type=str, default="v2-ed25519,v3-kem,v3-mldsa")
    parser.add_argument("--out", type=str, default=None)
    args = parser.parse_args()

    suites = [s.strip() for s in args.suites.split(",")]
    sanity = collect_sanity()

    print(f"PQVPN Evaluation — {args.iterations} iterations")
    print(f"  Suites: {', '.join(suites)}")
    print(f"  CPU: {sanity['cpu']} | Governor: {sanity['cpu_governor']}")
    print(f"  liboqs: {sanity['liboqs']}")
    print()

    evaluations = []
    for suite in suites:
        print(f"  Evaluating {suite}...", end=" ", flush=True)
        ev = evaluate_suite(suite, iterations=args.iterations)
        evaluations.append(ev)
        print(f"{ev.median_latency_ms:.3f}ms median, {ev.total_wire_bytes}B wire, "
              f"{ev.handshakes_per_sec:.0f} hs/s")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_path = None

    field_names = [f.name for f in fields(SuiteEvaluation)]
    buf = io.StringIO() if out_path is None else open(out_path, "w", newline="")
    w = csv.DictWriter(buf, fieldnames=field_names)
    w.writeheader()
    for ev in evaluations:
        w.writerow(asdict(ev))

    if out_path is None:
        print()
        print(buf.getvalue())
    else:
        buf.close()
        print(f"\n  Results saved to {out_path}")

    print("\n  Wire size comparison:")
    print(f"  {'Suite':<15} {'CH':>6} {'SH':>6} {'CKE':>6} {'SF':>4} {'Total':>7}")
    for ev in evaluations:
        print(f"  {ev.suite:<15} {ev.client_hello_bytes:>6} {ev.server_hello_bytes:>6} "
              f"{ev.client_key_exchange_bytes:>6} {ev.server_finished_bytes:>4} "
              f"{ev.total_wire_bytes:>7}")


if __name__ == "__main__":
    main()
