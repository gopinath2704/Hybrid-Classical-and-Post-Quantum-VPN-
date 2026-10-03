#!/usr/bin/env python3
"""Evaluate PQVPN handshake suites: latency, wire bytes, CPU, throughput, memory.

Outputs one CSV row per (suite x metric x run) to stdout or a file using the
unified schema: system,profile,metric,run,value,unit

    python eval/run_pqvpn.py --iterations 50 --out results/eval/raw/pqvpn.csv
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from crypto.hybrid_crypto import PQCProvider, PQSignatureProvider, get_crypto_status
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vpn.identity import fingerprint
from handshake.kemtls import (
    KEMTLSClient, KEMTLSServer,
    KEMTLSClientV3, KEMTLSServerV3,
    KEMTLSClientMLDSA, KEMTLSServerMLDSA,
    HandshakeSession,
)

CSV_COLUMNS = ["system", "profile", "metric", "run", "value", "unit"]


def require_native_pqc():
    status = get_crypto_status()
    if status["pqc_mode"] != "native_liboqs":
        print(f"FATAL: pqc_mode={status['pqc_mode']}; native liboqs required "
              f"for trustworthy benchmarks.", file=sys.stderr)
        sys.exit(1)
    return status


def _liboqs_version():
    try:
        import oqs
        if hasattr(oqs, "oqs_version"):
            return oqs.oqs_version()
        return getattr(oqs, "__version__", "available")
    except Exception:
        return "unknown"


def _make_v2_identities():
    kem = PQCProvider("ML-KEM-768")
    sk, pk = kem.generate_keypair()
    cpriv = Ed25519PrivateKey.generate()
    cpub = cpriv.public_key().public_bytes_raw()
    return sk, pk, cpriv, cpub


def _make_v3_identities():
    kem = PQCProvider("ML-KEM-768")
    sk, pk = kem.generate_keypair()
    csk, cpk = kem.generate_keypair()
    return sk, pk, csk, cpk


def _make_mldsa_identities():
    kem = PQCProvider("ML-KEM-768")
    sk, pk = kem.generate_keypair()
    sig = PQSignatureProvider()
    ssk, spk = sig.generate_keypair()
    return sk, pk, ssk, spk


def _make_v2_endpoints(sk, pk, cpriv, cpub):
    c = KEMTLSClient(pk, fingerprint(pk), cpriv)
    s = KEMTLSServer(sk, pk, lambda k: {"client_id": "eval"} if k == cpub else None)
    return c, s


def _make_v3_endpoints(sk, pk, csk, cpk):
    cfp = fingerprint(cpk)
    c = KEMTLSClientV3(pk, fingerprint(pk), csk, cpk)
    s = KEMTLSServerV3(sk, pk, lambda h: (cpk, {"client_id": "eval"}) if h == cfp else None)
    return c, s


def _make_mldsa_endpoints(sk, pk, ssk, spk):
    cfp = fingerprint(spk)
    c = KEMTLSClientMLDSA(pk, fingerprint(pk), ssk, spk)
    s = KEMTLSServerMLDSA(sk, pk, lambda h: (spk, {"client_id": "eval"}) if h == cfp else None)
    return c, s


_SUITE_IDENTITY = {
    "v2-ed25519": (_make_v2_identities, _make_v2_endpoints),
    "v3-kem": (_make_v3_identities, _make_v3_endpoints),
    "v3-mldsa": (_make_mldsa_identities, _make_mldsa_endpoints),
}


def run_handshake(suite: str, identities=None):
    id_factory, ep_factory = _SUITE_IDENTITY[suite]
    if identities is None:
        identities = id_factory()
    c, s = ep_factory(*identities)

    t0 = time.perf_counter()

    c_cpu0 = time.process_time()
    ch = c.initiate_handshake()
    c_cpu1 = time.process_time()

    s_cpu0 = time.process_time()
    sh = s.process_client_hello(ch)
    s_cpu1 = time.process_time()

    c_cpu2 = time.process_time()
    cke = c.process_server_hello(sh)
    c_cpu3 = time.process_time()

    s_cpu2 = time.process_time()
    sf, ss = s.process_client_key_exchange(cke)
    s_cpu3 = time.process_time()

    c_cpu4 = time.process_time()
    c.process_server_finished(sf)
    c_cpu5 = time.process_time()

    t1 = time.perf_counter()

    client_cpu = (c_cpu1 - c_cpu0) + (c_cpu3 - c_cpu2) + (c_cpu5 - c_cpu4)
    server_cpu = (s_cpu1 - s_cpu0) + (s_cpu3 - s_cpu2)

    return {
        "latency_ms": (t1 - t0) * 1000,
        "client_cpu_ms": client_cpu * 1000,
        "server_cpu_ms": server_cpu * 1000,
        "client_hello_bytes": len(ch),
        "server_hello_bytes": len(sh),
        "client_key_exchange_bytes": len(cke),
        "server_finished_bytes": len(sf),
        "total_wire_bytes": len(ch) + len(sh) + len(cke) + len(sf),
    }


def measure_handshakes_per_sec(suite: str, duration_s: float = 2.0) -> float:
    id_factory, _ = _SUITE_IDENTITY[suite]
    identities = id_factory()
    count = 0
    t0 = time.perf_counter()
    deadline = t0 + duration_s
    while time.perf_counter() < deadline:
        run_handshake(suite, identities=identities)
        count += 1
    elapsed = time.perf_counter() - t0
    return count / elapsed


def measure_encrypt_throughput(session: HandshakeSession, packet_size: int = 1400,
                                duration_s: float = 2.0) -> dict:
    packet = os.urandom(packet_size)
    count = 0
    t0 = time.perf_counter()
    deadline = t0 + duration_s
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
        id_factory, ep_factory = _SUITE_IDENTITY[suite]
        identities = id_factory()
        for _ in range(n_sessions):
            c, s = ep_factory(*identities)
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


def evaluate_suite(suite: str, iterations: int = 50, warmup: int = 5):
    id_factory, ep_factory = _SUITE_IDENTITY[suite]
    identities = id_factory()

    for _ in range(warmup):
        run_handshake(suite, identities=identities)

    rows = []
    for i in range(iterations):
        r = run_handshake(suite, identities=identities)
        for metric, value, unit in [
            ("latency_ms", r["latency_ms"], "ms"),
            ("client_cpu_ms", r["client_cpu_ms"], "ms"),
            ("server_cpu_ms", r["server_cpu_ms"], "ms"),
            ("client_hello_bytes", r["client_hello_bytes"], "bytes"),
            ("server_hello_bytes", r["server_hello_bytes"], "bytes"),
            ("client_key_exchange_bytes", r["client_key_exchange_bytes"], "bytes"),
            ("server_finished_bytes", r["server_finished_bytes"], "bytes"),
            ("total_wire_bytes", r["total_wire_bytes"], "bytes"),
        ]:
            rows.append({
                "system": f"pqvpn-{suite}",
                "profile": "in-process",
                "metric": metric,
                "run": i,
                "value": value,
                "unit": unit,
            })

    hs_sec = measure_handshakes_per_sec(suite)
    rows.append({
        "system": f"pqvpn-{suite}",
        "profile": "in-process",
        "metric": "handshakes_per_sec",
        "run": 0,
        "value": round(hs_sec, 2),
        "unit": "hs/s",
    })

    c, s = ep_factory(*identities)
    ch = c.initiate_handshake()
    sh = s.process_client_hello(ch)
    cke = c.process_server_hello(sh)
    sf, ss = s.process_client_key_exchange(cke)
    cs = c.process_server_finished(sf)
    tp = measure_encrypt_throughput(cs)
    rows.append({
        "system": f"pqvpn-{suite}",
        "profile": "in-process",
        "metric": "encrypt_pps",
        "run": 0,
        "value": round(tp["pps"], 0),
        "unit": "pps",
    })
    rows.append({
        "system": f"pqvpn-{suite}",
        "profile": "in-process",
        "metric": "encrypt_mbps",
        "run": 0,
        "value": round(tp["mbps"], 1),
        "unit": "Mbps",
    })

    mem = measure_memory_per_session(suite)
    if mem >= 0:
        rows.append({
            "system": f"pqvpn-{suite}",
            "profile": "in-process",
            "metric": "memory_bytes_per_session",
            "run": 0,
            "value": round(mem, 0),
            "unit": "bytes",
        })

    return rows


def main():
    parser = argparse.ArgumentParser(description="PQVPN evaluation benchmark")
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--suites", type=str, default="v2-ed25519,v3-kem,v3-mldsa")
    parser.add_argument("--out", type=str, default=None)
    args = parser.parse_args()

    status = require_native_pqc()
    pqc_mode = status["pqc_mode"]
    liboqs_ver = _liboqs_version()

    suites = [s.strip() for s in args.suites.split(",")]

    print(f"PQVPN Evaluation — {args.iterations} iterations")
    print(f"  Suites: {', '.join(suites)}")
    print(f"  pqc_mode: {pqc_mode}")
    print(f"  liboqs_version: {liboqs_ver}")
    print()

    all_rows = []
    for suite in suites:
        print(f"  Evaluating {suite}...", end=" ", flush=True)
        rows = evaluate_suite(suite, iterations=args.iterations)
        all_rows.extend(rows)
        lat_rows = [r for r in rows if r["metric"] == "latency_ms"]
        if lat_rows:
            vals = sorted(r["value"] for r in lat_rows)
            median = vals[len(vals) // 2]
            print(f"{median:.3f}ms median")
        else:
            print("done")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            w.writeheader()
            w.writerows(all_rows)
        print(f"\n  Results saved to {out_path}")
    else:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(all_rows)
        print()
        print(buf.getvalue())


if __name__ == "__main__":
    main()
