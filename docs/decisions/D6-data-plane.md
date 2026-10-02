# D6: Data-plane implementation scope

## Context

The Python packet loop (TUN read → AES-GCM encrypt → UDP send, and reverse) will
lose to WireGuard (kernel) and OpenVPN (C userspace) on throughput. IEEE reviewers
will notice. The question is whether to rewrite the data plane in a native language
or scope the contribution to the handshake and control plane.

## Profiling results (2026-10-01)

Measured on the project host with 10,000 × 1,400 B synthetic IPv4 packets:

| Component | µs/pkt | Notes |
|---|---|---|
| AES-256-GCM encrypt (raw openssl) | 0.90 | Via `cryptography` Rust binding |
| AES-256-GCM decrypt (raw openssl) | 0.91 | Same |
| Python `encrypt_frame` total | 3.2 | Nonce XOR, struct.pack, lock, list append |
| Python `decrypt_frame` total | 4.0 | + enum lookup, replay window, struct.unpack |
| Python nonce XOR (`_nonce`) | 1.38 | Generator expression dominates |
| `validate_client_packet` | 1.5 | `ipaddress.IPv4Address` + str compare |
| `select()` poll (empty) | 0.5 | Kernel round-trip |
| UDP loopback send+recv | 2.4 | Per packet pair |

**Per-packet budget (one direction):** ~8–12 µs → ~80k–125k pps theoretical.

**Breakdown:** Python overhead is ~2.3 µs for encrypt and ~3.1 µs for decrypt —
roughly 2–3× the raw AES-GCM cost. The `_nonce` method (generator-expression XOR)
alone takes 1.38 µs, more than the actual AES-GCM operation. The `select()` loop,
socket I/O, and TUN syscalls add another ~3–5 µs.

**Comparison:**
- WireGuard (kernel): ~0.3–0.5 µs/pkt, millions of pps
- OpenVPN (C userspace): ~5–15 µs/pkt, similar order to ours
- Our Python loop: ~10 µs/pkt, ~100k pps

## Options

**A: Scope it.** The contribution is the handshake and control plane — a
signature-free, fully post-quantum, mutually authenticated hybrid VPN with
post-compromise recovery and a formal model. Throughput is reported as a
functional check, with the limitation stated openly. Effort: zero.

**B: Native data plane.** Move TUN ↔ UDP AES-GCM framing to Rust (PyO3) or C.
Keep the handshake in Python. Wire format identical; v2/v3 interop tests against
the Python implementation. Effort: high (2–4 weeks, new language toolchain,
build system, CI, platform-specific TUN bindings).

## Choice

**Option A.**

## Why

1. **The research contribution is the handshake.** The paper claims a
   signature-free fully-PQ handshake with a formal model, not a new data plane.
   Throughput comparisons against kernel-based VPNs are irrelevant to the claim.

2. **Python throughput is adequate for functional validation.** At ~100k pps
   (~1.1 Gbps for 1,400 B packets), the data plane is not the bottleneck for
   the evaluation metrics that matter: handshake latency, wire sizes, CPU per
   handshake, and re-handshake cost.

3. **The bottleneck is Python overhead, not crypto.** AES-256-GCM via openssl
   runs at ~1.5 GB/s. The Python nonce computation, struct packing, and lock
   acquire/release add 2–3× overhead. Rewriting in Rust would recover most of
   this, but it is engineering work orthogonal to the research question.

4. **OpenVPN (C userspace) is in the same order of magnitude.** Our ~10 µs/pkt
   is comparable to OpenVPN's ~5–15 µs/pkt. The limitation is stated; it is
   not an anomaly.

5. **Effort/risk is not justified.** A native rewrite introduces build
   complexity, platform dependencies, and a new attack surface. For a research
   prototype with a clear scope statement, this is not worthwhile.

The paper will state: *"The data plane is a Python userspace implementation
using AES-256-GCM via the `cryptography` library. Throughput is reported as a
functional check; the contribution and evaluation focus on the handshake and
control plane. A native data plane is future work."*
