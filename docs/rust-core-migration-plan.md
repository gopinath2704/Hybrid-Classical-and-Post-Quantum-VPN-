# PQ-VPN Rust-core migration plan

Oct 28, 2026 · @Shadow

## Summary

Move the per-packet data path into a Rust core loaded by Python through PyO3, then the handshake, while Python keeps the GUI, accounts, CLI, packaging glue and the eval harness. The protocol and wire format do not change, so the 13 Tamarin lemmas still hold and the paper's claim gets sharper: the gap to WireGuard was the Python implementation, not post-quantum cryptography.

Headline targets, all on the same i7-11800H netns testbed as M1 and M5:

- **M5 throughput (LAN):** 613 Mbps today, 1.5 Gbps after the first Rust data plane, 3 Gbps or more after multi-core and offload.
- **M1 connect (LAN):** 163 ms today, 40 ms or less with a warm daemon, 30 ms or less with a native Rust client.
- **Nothing regresses:** M2 CPU, M6 hitless rekey, M7 flood resilience and M8 memory stay at or better than today.

The migration runs behind a `data_plane = "python" | "rust"` switch, so every phase ships, can be rolled back, and gives the paper a clean Python versus Rust ablation on identical crypto.

## Where we are

The published M1 and M5 numbers are from 2026-10-04 and 2026-10-10, before several Python fixes landed on main, so the first job is a fresh baseline. The bottlenecks below are read from main at `d6e45e6`.

| Area | What the code does today | Cost | Fix belongs in |
| --- | --- | --- | --- |
| Client startup | Fresh interpreter + liboqs CDLL load per connect; the ML-KEM self-test itself is sub-millisecond and already skippable via `_PQVPN_SELFTEST_PASSED` (`crypto/hybrid_crypto.py:111`) | About 100 to 140 ms of the 163 ms LAN connect | Warm daemon now, native client later |
| Route setup | Forks the `ip` binary per address, link and route (`run_ip` in `vpn/runtime.py`) | Several ms per fork | Netlink (pyroute2 now, `rtnetlink` crate later) |
| Round trips | KEMTLS full handshake over TCP, then a separate `UDP_BIND` exchange; 1-RTT resumption tickets exist and save 92 ms metro, 241 ms continent | About 3 extra RTTs on a cold connect | Fold the bind into the handshake |
| Data loop | One thread, `select()` then up to 64 packets per wakeup, but still one `recvfrom`, `os.read` or `sendto` syscall and one Python dispatch per packet (`vpn/runtime.py:601`) | The 613 Mbps ceiling | Rust core |
| Cipher | AES-256-GCM via `cryptography` (already AES-NI in C) | Small | Keep the algorithm, move the call |

Two things are worth knowing before any Rust is written. Python's standard library has no `recvmmsg` or `sendmmsg`, so true syscall batching needs native code, which makes it the natural first Rust piece. And the GIL means a second Python data thread cannot help, so multi-core scaling also needs native code.

## Quick wins first

Do these in Python before the Rust core, in this order. They are cheap, they move M1 most, and they give an honest "optimized Python" baseline for the paper's ablation.

1. **Measure warm connect through the existing daemon.** `ClientService` in `app/client.py` already keeps a privileged process alive behind local IPC. Teach the M1 harness to time connect through that socket, and report cold and warm connect as two rows. Target: M1 LAN warm 40 ms or less.
2. **Replace `ip` forks with netlink.** Use pyroute2 for address, link up and routes in `vpn/runtime.py`. Target: 10 to 30 ms off cold connect.
3. **Fold `UDP_BIND` into the last handshake message.** Saves one RTT on every cold and resumed connect, so about 50 ms on metro. This touches the protocol, so it needs a Tamarin model update and the version bump rules in `CLAUDE.md`.
4. **Make resumption the default reconnect path** in the GUI client (it already falls back to a full handshake on failure). Target: metro reconnect 365 ms down to about 315 ms once item 3 lands.
5. **Syscall batching is not a Python quick win.** Without `recvmmsg` and `sendmmsg` in the standard library it would mean ctypes in the hot path, which is slower and riskier than doing it properly in Rust. It becomes Phase 2's first deliverable instead.

## Target architecture

Rust owns everything that runs per packet or per handshake; Python owns everything a person or operator touches. The two meet at one narrow PyO3 module, `pqvpn_core`, so the attack surface of the boundary is a handful of calls.

&#91;embedded content: target architecture · Python shell, PyO3 boundary, Rust core\]

Keys cross the boundary once, downward; nothing secret ever comes back up to Python.

| Component | Today | After migration | Phase |
| --- | --- | --- | --- |
| UDP + TUN data loop, framing, AES-256-GCM, replay window | `vpn/runtime.py`, `handshake/kemtls.py` | Rust `core/dataplane` | 2 |
| Session table and lookup | `SessionTable` snapshot dict | Rust, lock-free (`arc-swap`) | 2 |
| Multi-core workers, GSO/GRO, multi-queue TUN | none | Rust | 3 |
| KEMTLS handshake, cookies, resumption, rekey state machine | `handshake/kemtls.py` | Rust `core/handshake` | 4 |
| Hybrid KEM, HKDF key schedule | `crypto/hybrid_crypto.py` | Rust `core/crypto` | 4 |
| Netlink route and address setup | `ip` subprocess | pyroute2 (Phase 1), then Rust | 1, 4 |
| Client daemon | Python `ClientService` | Rust `pqvpnd`, same IPC protocol | 4 |
| GUI, accounts API, CLI, identity files, config | Python | Python, unchanged | none |
| Eval harness, pentest suite, Tamarin models | Python, shell, spthy | Unchanged, gains a `--backend` flag | none |

The FFI boundary, once Phase 2 lands, is deliberately small:

- `DataPlane.start(udp_fd, tun_fd, mtu, workers)` takes ownership of the descriptors and runs its own threads with the GIL released.
- `add_session(session_id, vpn_ip, keys, nonce_bases, epoch)` hands over the four directional data secrets once; Rust copies them into `Zeroizing` buffers and Python wipes its copies with the existing `TrafficSecrets.wipe()`.
- `rekey(session_id, keys, epoch)`, `bind_endpoint(session_id, addr)`, `remove_session(session_id)`.
- `stats()` returns counters for the eval harness; no packets or keys ever cross back into Python.

Build it with maturin as an `abi3` wheel (one build covers Python 3.11 and newer), with the Rust workspace in `core/` and `Cargo.lock` committed.

## Crate choices

Use one primary provider, aws-lc-rs, for every primitive, and a second independent implementation only as a test oracle. One provider keeps the audit and FIPS story simple; the oracle catches a silent mismatch with liboqs.

| Need | Primary | Test oracle or fallback | Why |
| --- | --- | --- | --- |
| ML-KEM-768 | `aws-lc-rs` | `libcrux-ml-kem` (formally verified with hax/F\*), plus liboqs known-answer vectors | Same FIPS 203 math as liboqs today; libcrux proves secret-independence and panic freedom |
| X25519 | `aws-lc-rs` | `x25519-dalek` | Constant-time, assembly-backed |
| AES-256-GCM (data and control) | `aws-lc-rs` | `ring` | AES-NI and VAES assembly; the cipher stays exactly what `cryptography` uses now |
| HKDF-SHA256, HMAC | `aws-lc-rs` | `hkdf` + `hmac` (RustCrypto) | Must reproduce the 12 labelled secrets byte for byte |
| Ed25519 (v2) | `aws-lc-rs` | `ed25519-dalek` | Managed desktop clients still speak v2 |
| ML-DSA-44 (v3-mldsa) | `aws-lc-rs` | `libcrux-ml-dsa` | Keep v3-mldsa only if the paper still needs it; v3-kem is the default |
| Secret hygiene | `zeroize`, `subtle` | none | Wipe on drop, constant-time compares |
| UDP batching, GSO/GRO | `quinn-udp` or `nix` (`recvmmsg`, `sendmmsg`, `UDP_SEGMENT`) | none | `quinn-udp` already wraps GSO/GRO safely |
| TUN, multi-queue, offload | `tun-rs`, or a thin `libc` ioctl module | none | `IFF_MULTI_QUEUE` and `IFF_VNET_HDR` support |
| Netlink | `rtnetlink` | none | Replaces the `ip` forks |
| Python bindings | `pyo3` + `maturin` | none | `abi3` wheels, GIL released in the data loop |

Pin exact versions in `Cargo.lock`, check each crate's ML-KEM and ML-DSA feature status (some sit behind an `unstable` flag) at pin time, and gate every update through `cargo deny` and `cargo audit`. Crate status above is from memory, not checked today, so treat it as the starting shortlist. Prior art worth reading: Cloudflare's boringtun (WireGuard in Rust) and wireguard-go's GSO/GRO work, which both show userspace tunnels reaching multi-gigabit rates.

## Phased roadmap

Six phases, each ending in a gate that is a measurement, not a feeling. Every phase merges to main behind the backend switch, so stopping early still leaves a shippable VPN and paper-ready numbers.

&#91;embedded content: roadmap · 6 phases, one gate each, about 10 to 13 weeks\]

Phases 0 to 3 give the paper its numbers; Phase 4 and 5 turn the prototype into a native client.

1. **Phase 0, baseline and freeze (2 days).** Re-run M1 to M8 on current main (30 runs, median and 95% CI); capture py-spy and `perf` flame graphs of `_data_loop`; tag `v3-paper-artifact` for the Python results. Gate: fresh numbers committed to `eval/results-summary/`.
2. **Phase 1, Python quick wins (1 week).** The four items in Quick wins. Gate: M1 LAN warm 40 ms or less, cold 130 ms or less, all tests green, Tamarin re-verified for the folded bind.
3. **Phase 2, Rust data plane (2 to 3 weeks).** `core/` workspace, `pqvpn_core` module, one worker thread, `recvmmsg`/`sendmmsg` and TUN drain in batches of 64, AES-256-GCM, 128-entry replay window, lock-free session table. Gate: byte-identical interop with the Python backend in both directions, the full suite passes on both backends, M5 LAN 1.5 Gbps or more, tunnel RTT overhead 0.2 ms or less.
4. **Phase 3, scale out (2 weeks).** N workers on multi-queue TUN with `SO_REUSEPORT`, UDP GSO/GRO, TUN offload. Gate: M5 LAN 3 Gbps or more, a fixed-rate UDP goodput sweep replacing the `-b 0` flood numbers, M7 still 100% under a 10k/s flood.
5. **Phase 4, Rust handshake and native daemon (3 to 4 weeks).** Port KEMTLS, cookies, resumption, rekey and the key schedule; ship `pqvpnd` speaking the existing IPC so the GUI is untouched. Gate: Python and Rust produce identical transcripts and secrets on shared test vectors, M1 LAN cold 30 ms or less, M2 0.2 ms or less, M8 64 kB per session or less.
6. **Phase 5, hardening and release (1 to 2 weeks).** Fuzzing, `cargo deny`, unsafe review, packaging, full M1 to M8 rerun, tag `v4.0.0`. Gate: 24 hours of fuzzing without a crash, pentest suite re-run clean, Arch and Debian packages build from `git archive HEAD`.

Decision point after Phase 2 or 3: if the paper deadline is close, freeze there. The data plane alone already makes the ablation story, and Phase 4 can follow as v4.

| Metric | Today (published) | Phase 1 | Phase 2 | Phase 3 | Phase 4 | WireGuard |
| --- | --- | --- | --- | --- | --- | --- |
| M1 connect LAN (ms) | 163 | 40 warm, 130 cold | same | same | 30 cold | 21 |
| M1 connect metro (ms) | 464 | 410 | same | same | 360 | 172 |
| M5 TCP LAN (Mbps) | 613 | about 613 | 1,500 | 3,000 | same | 2,000 to 5,000 |
| Tunnel RTT overhead (ms) | 0.34 | same | 0.2 | 0.15 | same | not measured |
| M2 CPU per handshake (ms) | 0.39 | same | same | same | 0.2 | under 1 |
| M8 memory per session (kB) | 186 | same | same | same | 64 | lower |

All numbers right of "Today" are targets, not measurements. Phase 0 may move the starting point, since batching and resumption landed after the published runs.

### Phase 2 ablation: Python vs Rust data plane

Pre-slice-(d) run, to be replaced by the final bench: commit 0310a5c, governor pinned to performance, M5 LAN, median of 5 runs per cell, Python and Rust interleaved on the same commit (`scripts/bench_dataplane.sh`, raw data in `eval/results-summary/phase2-2026-10-29/`).

| Suite | Data plane | TCP (Mbps) | Tunnel RTT overhead (ms) |
| --- | --- | --- | --- |
| v2-ed25519 | Python | 632 | 0.416 |
| v2-ed25519 | Rust | 3,831 | 0.203 |
| v3-kem | Python | 633 | 0.452 |
| v3-kem | Rust | 3,782 | 0.155 |

**Moved to Rust** (`data_plane = "rust"`, both roles): the whole per-packet loop, meaning `recvmmsg`/`sendmmsg` and the TUN drain in batches of 64, AES-256-GCM seal and open, the 128-entry replay window, session lookup, endpoint binding, `UDP_BIND`/`ACK`, `PING`/`PONG` keepalive, the inner-packet source and destination checks, and the counters.

**Stayed in Python:** the TCP control channel (CONFIG, rekey, re-handshake and close frames), the KEMTLS handshake, cookies, resumption, the key schedule and rekey derivation, idle, session and dead-peer policy, revocation, the client's first `UDP_BIND` at connect, and TUN, route and DNS setup and teardown. Python derives each epoch's keys; Rust holds the only data-channel sealer.

**RTT overhead.** The loop's own work is about 30 µs per ping round trip. The rest is the host waking idle threads: three wakeups per round trip (client TUN, server UDP, client UDP). Spinning instead of sleeping drops the overhead to about 0.03 ms on the same machine, so the remaining gap is host wake-from-idle latency, not data-plane code.

Phase 2 gates (ticked only once the final bench passes):

- [ ] Byte-identical interop with the Python backend in both directions (`test_mixed_data_planes_interoperate_end_to_end`, v2 and v3, with rekey)
- [ ] Full suite passes on both backends
- [ ] M5 LAN TCP 1.5 Gbps or more, both suites
- [ ] Tunnel RTT overhead 0.2 ms or less, both suites

## Security invariants and tests

The rewrite must not weaken a single property in the security gap analysis. These are the invariants each Rust PR is checked against:

- **Hybrid only.** X25519 and ML-KEM-768 are both always in the key schedule; there is no code path that builds a classical-only session.
- **Same key schedule.** The 12 HKDF secrets, their labels, directional and channel separation, and nonce bases match Python byte for byte.
- **Authenticate, then commit.** The replay window advances only after the GCM tag verifies, exactly as `ReplayWindow.check` then `commit` does now.
- **Inner-packet validation stays.** Decrypted packets must pass the same source-IP check as `validate_client_packet` before reaching the TUN.
- **Revocation reaches the core.** `remove_session` and ticket-key rotation take effect in the Rust session table within one revocation-loop tick.
- **No unsafe outside one module.** `#![forbid(unsafe_code)]` on every crate except the small syscall and ioctl module, which gets a line-by-line review and Miri where it can run.
- **No secrets cross back.** The FFI returns only counters and status; keys are never readable from Python once handed over.

Test strategy, on top of the existing 560 tests and 70-attack pentest suite:

- [x] Run the whole Python suite against both backends via a `--backend` pytest option.
- [ ] Cross-implementation interop: Python client to Rust server and the reverse, for v2, v3-kem and v3-mldsa, including rekey and resumption.
- [ ] Known-answer vectors exported from the Python code for HKDF output, frame encryption and transcripts, checked in Rust unit tests.
- [ ] Differential fuzzing with `cargo-fuzz` on frame decryption, the replay window and handshake parsing, comparing Rust against Python where both exist.
- [ ] Property tests (`proptest`) for the replay window and sequence handling at the 64-bit edge.
- [ ] Re-run the Tamarin models only where the protocol changes (the folded `UDP_BIND` in Phase 1); a pure port changes no model.

## Keeping the IEEE evaluation reproducible

Treat the Python and Rust backends as two configurations of one artifact, not as a before and after. That turns the migration into the paper's strongest evidence: same protocol, same crypto, same testbed, only the implementation language changes.

- **Freeze first.** Tag `v3-paper-artifact` in Phase 0 and archive it on Zenodo, so the Python numbers stay reproducible even after main moves on.
- **One harness, a backend flag.** `eval/run_all.py --backend python|rust` and `reproduce.sh` run both; results land in `summary.csv` with a `backend` column, so the generated LaTeX tables show the ablation directly.
- **Offline, pinned builds.** Commit `Cargo.lock`, vendor crates with `cargo vendor` into the source tarball, and pin the toolchain in `rust-toolchain.toml`. The package is built from `git archive HEAD`, so the vendored tree is what ships.
- **Record the environment.** Every run writes rustc version, crate versions, liboqs version, CPU model and flags (AES-NI, AVX2), kernel and governor into its results header.
- **Same statistics.** 30 runs per cell, median with 95% bootstrap CI, as M1 does today, for every new number.
- **Packaging chores per release.** After each merge, refresh `packaging/arch/pqvpn-3.0.0.tar.gz`, the PKGBUILD `sha256sums` and the digest pin in `tests/test_onboarding.py`; add `cargo` and `maturin` to the Arch makedepends and the `debian:trixie` build container.

## Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Rust and Python drift apart on the wire (nonce, header or label mismatch) | Medium | High: silent interop failure or a nonce reuse | Known-answer vectors, two-way interop tests, differential fuzzing before any merge |
| A key handed over at the FFI boundary lingers in Python memory | Medium | High | Hand over once, wipe the `bytearray` immediately, never return keys; review the boundary in every PR |
| `unsafe` bugs in syscall or TUN code | Medium | High | One isolated module, `forbid(unsafe_code)` elsewhere, Miri and fuzzing, prefer `quinn-udp` and `tun-rs` over hand-written ioctls |
| ML-KEM crate behaviour differs from liboqs, or a feature is still `unstable` | Low | Medium | liboqs vectors as the oracle; keep the liboqs path for the handshake until Phase 4 passes |
| Packaging breaks (Rust toolchain on Arch and in the Debian container, offline build) | High | Medium | Vendored crates, pinned toolchain, abi3 wheel, CI job that builds both packages |
| Scope creep delays the paper | High | High | Hard decision point after Phase 2 or 3; the Python artifact is frozen first |
| Multi-core changes packet ordering and hurts TCP | Medium | Medium | Flow-hash workers per session (one session per queue), measure reordering in Phase 3 |
| Rewritten code drops a past fix (cookie `bid - 1`, rate limiter, revocation kill) | Medium | Medium | Port the regression tests first, then the code |

## Next steps

- [ ] Phase 0: re-run M1 to M8 on current main with flame graphs, then tag `v3-paper-artifact` (needs root on your machine).
- [ ] Phase 1: open one PR per quick win, starting with warm connect through `ClientService` and pyroute2.
- [x] Phase 2 spike: a `core/` skeleton with maturin, one known-answer test for frame encryption, and a `--backend` pytest option, to prove the build and packaging path before the real port.

Open question: which venue and deadline is the paper aiming for? That decides whether to freeze after Phase 2, Phase 3 or Phase 4.
