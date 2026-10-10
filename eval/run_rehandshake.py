#!/usr/bin/env python3
"""Evaluate rekey and re-handshake (PCS) cost: latency, CPU, wire bytes.

Measures both mechanisms in-process over a socket pair, avoiding the noise
of namespace/TUN setup.  Outputs the unified CSV schema:
    system,profile,metric,run,value,unit

Usage:
    python eval/run_rehandshake.py --iterations 30 --out results/m6/raw/rehandshake.csv
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac as hmac_mod
import io
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from crypto.hybrid_crypto import (
    HybridKEM, PQCProvider, get_crypto_status,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from handshake.kemtls import (
    KEMTLSClient, KEMTLSServer, HandshakeSession, FrameType,
    send_message, recv_message,
)
from vpn.identity import fingerprint

CSV_COLUMNS = ["system", "profile", "metric", "run", "value", "unit"]

REKEY_REQUEST_BYTES = 36     # epoch(4) + nonce(32)
REKEY_RESPONSE_BYTES = 36    # epoch(4) + HMAC(32)
REHANDSHAKE_REQUEST_BYTES = 1220   # epoch(4) + X25519_pub(32) + ML-KEM_pub(1184)
REHANDSHAKE_RESPONSE_BYTES = 1156  # epoch(4) + X25519_pub(32) + ct(1088) + confirm(32)


def require_native_pqc():
    status = get_crypto_status()
    if status["pqc_mode"] != "native_liboqs":
        print(f"FATAL: pqc_mode={status['pqc_mode']}; native liboqs required.",
              file=sys.stderr)
        sys.exit(1)
    return status


def _establish_session():
    """Complete a v2-ed25519 handshake over a socket pair, returning
    (client_session, server_session, client_sock, server_sock)."""
    kem = PQCProvider("ML-KEM-768")
    sk, pk = kem.generate_keypair()
    cpriv = Ed25519PrivateKey.generate()
    cpub = cpriv.public_key().public_bytes_raw()

    c = KEMTLSClient(pk, fingerprint(pk), cpriv)
    s = KEMTLSServer(sk, pk, lambda k: {"client_id": "eval"} if k == cpub else None)

    ch = c.initiate_handshake()
    sh = s.process_client_hello(ch)
    cke = c.process_server_hello(sh)
    sf, s_session = s.process_client_key_exchange(cke)
    c_session = c.process_server_finished(sf)

    cs, ss = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return c_session, s_session, cs, ss


def measure_rekey(c_session: HandshakeSession, s_session: HandshakeSession,
                  c_sock: socket.socket, s_sock: socket.socket,
                  epoch: int) -> dict:
    """Perform one rekey and return timing + byte metrics."""
    nonce = os.urandom(32)
    payload = struct.pack("!I", epoch) + nonce

    t0 = time.perf_counter()
    cpu0 = time.process_time()

    c_pending = c_session.derive_next_epoch(epoch, nonce)
    req_frame = c_session.encrypt_control(payload, FrameType.REKEY_REQUEST)
    send_message(c_sock, req_frame)

    raw = recv_message(s_sock)
    _, s_payload = s_session.decrypt_control(raw, FrameType.REKEY_REQUEST)
    s_epoch = struct.unpack("!I", s_payload[:4])[0]
    s_nonce = s_payload[4:]
    s_pending = s_session.derive_next_epoch(s_epoch, s_nonce)
    confirmation = hmac_mod.new(
        bytes(s_session.secrets.control_confirm_key),
        b"rekey response" + s_payload, hashlib.sha256).digest()
    resp_frame = s_session.encrypt_control(
        s_payload[:4] + confirmation, FrameType.REKEY_RESPONSE)
    send_message(s_sock, resp_frame)
    s_session.activate_epoch(s_epoch, s_pending)

    raw = recv_message(c_sock)
    _, response = c_session.decrypt_control(raw, FrameType.REKEY_RESPONSE)
    expected = hmac_mod.new(
        bytes(c_session.secrets.control_confirm_key),
        b"rekey response" + payload, hashlib.sha256).digest()
    assert response[:4] == payload[:4]
    assert hmac_mod.compare_digest(response[4:], expected)
    c_session.activate_epoch(epoch, c_pending)

    cpu1 = time.process_time()
    t1 = time.perf_counter()

    req_bytes = len(payload)
    resp_bytes = 4 + 32  # epoch + HMAC
    return {
        "latency_ms": (t1 - t0) * 1000,
        "cpu_ms": (cpu1 - cpu0) * 1000,
        "request_bytes": req_bytes,
        "response_bytes": resp_bytes,
        "total_bytes": req_bytes + resp_bytes,
    }


def measure_rehandshake(c_session: HandshakeSession, s_session: HandshakeSession,
                         c_sock: socket.socket, s_sock: socket.socket,
                         epoch: int) -> dict:
    """Perform one re-handshake (PCS) and return timing + byte metrics."""
    hybrid = HybridKEM("ML-KEM-768")

    t0 = time.perf_counter()
    cpu0 = time.process_time()

    dh_private, dh_public = hybrid.ecc.generate_keypair()
    kem_secret, kem_public = hybrid.pqc.generate_keypair()
    payload = struct.pack("!I", epoch) + dh_public + kem_public
    req_frame = c_session.encrypt_control(payload, FrameType.REHANDSHAKE_REQUEST)
    send_message(c_sock, req_frame)

    raw = recv_message(s_sock)
    _, s_payload = s_session.decrypt_control(raw, FrameType.REHANDSHAKE_REQUEST)
    s_epoch = struct.unpack("!I", s_payload[:4])[0]
    client_dh_pub = s_payload[4:36]
    client_kem_pub = s_payload[36:]
    s_hybrid = HybridKEM("ML-KEM-768")
    s_dh_private, s_dh_public = s_hybrid.ecc.generate_keypair()
    s_dh_ss = s_hybrid.ecc.derive_shared_secret(s_dh_private, client_dh_pub)
    s_ct, s_k_mlkem = s_hybrid.pqc.encapsulate(client_kem_pub)
    response_body = struct.pack("!I", s_epoch) + s_dh_public + s_ct
    s_transcript = s_payload + response_body
    s_pending = s_session.derive_rehandshake_epoch(s_epoch, s_dh_ss, s_k_mlkem, s_transcript)
    confirmation = hmac_mod.new(
        bytes(s_pending.control_confirm_key),
        b"rehandshake confirm" + s_transcript, hashlib.sha256).digest()
    resp_frame = s_session.encrypt_control(
        response_body + confirmation, FrameType.REHANDSHAKE_RESPONSE)
    send_message(s_sock, resp_frame)
    s_session.activate_epoch(s_epoch, s_pending)

    raw = recv_message(c_sock)
    _, response = c_session.decrypt_control(raw, FrameType.REHANDSHAKE_RESPONSE)
    assert len(response) == 4 + 32 + 1088 + 32
    resp_epoch = struct.unpack("!I", response[:4])[0]
    assert resp_epoch == epoch
    c_response_body = response[:4 + 32 + 1088]
    server_confirm = response[4 + 32 + 1088:]
    server_dh_public = response[4:36]
    ct = response[36:36 + 1088]
    c_dh_ss = hybrid.ecc.derive_shared_secret(dh_private, server_dh_public)
    c_k_mlkem = hybrid.pqc.decapsulate(kem_secret, ct)
    c_transcript = payload + c_response_body
    c_pending = c_session.derive_rehandshake_epoch(epoch, c_dh_ss, c_k_mlkem, c_transcript)
    expected_confirm = hmac_mod.new(
        bytes(c_pending.control_confirm_key),
        b"rehandshake confirm" + c_transcript, hashlib.sha256).digest()
    assert hmac_mod.compare_digest(server_confirm, expected_confirm)
    c_session.activate_epoch(epoch, c_pending)

    cpu1 = time.process_time()
    t1 = time.perf_counter()

    req_bytes = len(payload)
    resp_bytes = len(response)
    return {
        "latency_ms": (t1 - t0) * 1000,
        "cpu_ms": (cpu1 - cpu0) * 1000,
        "request_bytes": req_bytes,
        "response_bytes": resp_bytes,
        "total_bytes": req_bytes + resp_bytes,
    }


def run_benchmark(iterations: int = 30, warmup: int = 3):
    rows = []
    c_session, s_session, c_sock, s_sock = _establish_session()

    epoch = c_session.epoch

    for _ in range(warmup):
        epoch += 1
        measure_rekey(c_session, s_session, c_sock, s_sock, epoch)
        epoch += 1
        measure_rehandshake(c_session, s_session, c_sock, s_sock, epoch)

    for i in range(iterations):
        epoch += 1
        r = measure_rekey(c_session, s_session, c_sock, s_sock, epoch)
        for metric, value, unit in [
            ("rekey_latency_ms", r["latency_ms"], "ms"),
            ("rekey_cpu_ms", r["cpu_ms"], "ms"),
            ("rekey_request_bytes", r["request_bytes"], "bytes"),
            ("rekey_response_bytes", r["response_bytes"], "bytes"),
            ("rekey_total_bytes", r["total_bytes"], "bytes"),
        ]:
            rows.append({
                "system": "pqvpn-rekey",
                "profile": "in-process",
                "metric": metric,
                "run": i,
                "value": value,
                "unit": unit,
            })

    for i in range(iterations):
        epoch += 1
        r = measure_rehandshake(c_session, s_session, c_sock, s_sock, epoch)
        for metric, value, unit in [
            ("rehandshake_latency_ms", r["latency_ms"], "ms"),
            ("rehandshake_cpu_ms", r["cpu_ms"], "ms"),
            ("rehandshake_request_bytes", r["request_bytes"], "bytes"),
            ("rehandshake_response_bytes", r["response_bytes"], "bytes"),
            ("rehandshake_total_bytes", r["total_bytes"], "bytes"),
        ]:
            rows.append({
                "system": "pqvpn-rehandshake",
                "profile": "in-process",
                "metric": metric,
                "run": i,
                "value": value,
                "unit": unit,
            })

    c_sock.close()
    s_sock.close()
    c_session.secure_wipe()
    s_session.secure_wipe()
    return rows


def main():
    parser = argparse.ArgumentParser(description="Rekey & re-handshake benchmark (M6)")
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--out", type=str, default=None)
    args = parser.parse_args()

    status = require_native_pqc()
    print(f"M6 Rekey & Re-handshake Evaluation — {args.iterations} iterations")
    print(f"  pqc_mode: {status['pqc_mode']}")
    print()

    rows = run_benchmark(iterations=args.iterations)

    rk_lat = sorted(r["value"] for r in rows if r["metric"] == "rekey_latency_ms")
    rh_lat = sorted(r["value"] for r in rows if r["metric"] == "rehandshake_latency_ms")
    rk_bytes = sorted(r["value"] for r in rows if r["metric"] == "rekey_total_bytes")
    rh_bytes = sorted(r["value"] for r in rows if r["metric"] == "rehandshake_total_bytes")

    if rk_lat:
        print(f"  Rekey:        {rk_lat[len(rk_lat)//2]:.3f} ms median, "
              f"{int(rk_bytes[len(rk_bytes)//2])} bytes")
    if rh_lat:
        print(f"  Re-handshake: {rh_lat[len(rh_lat)//2]:.3f} ms median, "
              f"{int(rh_bytes[len(rh_bytes)//2])} bytes")

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            w.writeheader()
            w.writerows(rows)
        print(f"\n  Results saved to {out_path}")
    else:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)
        print()
        print(buf.getvalue())


if __name__ == "__main__":
    main()
