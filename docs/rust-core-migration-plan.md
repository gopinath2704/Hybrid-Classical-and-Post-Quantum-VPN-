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
5. **Phase 4, Rust handshake and native daemon (3 to 4 weeks).** Port KEMTLS, cookies, resumption, rekey and the key schedule; ship `pqvpnd` speaking the existing IPC so the GUI is untouched (scope cut 2026-10-30: Phase 4 ships `pqvpnd connect`, a native one-shot client; the IPC daemon moves to Phase 5, see [Appendix A](#appendix-a--phase-4-design)). Gate: Python and Rust produce identical transcripts and secrets on shared test vectors, M1 LAN cold 30 ms or less, M2 0.2 ms or less, M8 64 kB per session or less.
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

Final run: commit 17d4667 (clean), governor pinned to performance, M5 LAN, median of 5 runs per cell, Python and Rust interleaved on the same commit (`scripts/bench_dataplane.sh`, raw data and `environment.txt` in `eval/results-summary/phase2-2026-10-29/`).

| Suite | Data plane | TCP (Mbps) | Tunnel RTT overhead (ms) |
| --- | --- | --- | --- |
| v2-ed25519 | Python | 634 | 0.410 |
| v2-ed25519 | Rust | 3,821 | 0.177 |
| v3-kem | Python | 632 | 0.445 |
| v3-kem | Rust | 3,757 | 0.213 |

Same run, Rust data plane: M1 LAN cold connect 131 ms, warm 9.0 ms (30 each). M7 ClientHello flood at 0, 100 and 1000 per second: all legitimate connects succeed at about 157 ms, with server CPU at 22% (cookies off) and 18% (cookies always) at 1000 per second.

**Moved to Rust** (`data_plane = "rust"`, both roles): the whole per-packet loop, meaning `recvmmsg`/`sendmmsg` and the TUN drain in batches of 64, AES-256-GCM seal and open, the 128-entry replay window, session lookup, endpoint binding, `UDP_BIND`/`ACK`, `PING`/`PONG` keepalive, the inner-packet source and destination checks, and the counters.

**Stayed in Python:** the TCP control channel (CONFIG, rekey, re-handshake and close frames), the KEMTLS handshake, cookies, resumption, the key schedule and rekey derivation, idle, session and dead-peer policy, revocation, the client's first `UDP_BIND` at connect, and TUN, route and DNS setup and teardown. Python derives each epoch's keys; Rust holds the only data-channel sealer.

**RTT overhead.** The loop's own work is about 30 µs per ping round trip. The rest is the host waking idle threads: three wakeups per round trip (client TUN, server UDP, client UDP). Spinning instead of sleeping drops the overhead to about 0.03 ms on the same machine, so the remaining gap is host wake-from-idle latency, not data-plane code. Per-run overhead spans 0.14 to 0.23 ms on both suites, which share one data path, and the suite that misses 0.2 ms flips between runs: the pre-hardening run at 0310a5c measured v2 0.203 / v3-kem 0.155 ms, this one v2 0.177 / v3-kem 0.213 ms. Busy-polling or holding a PM QoS latency request would pass the gate here, but it burns a core on a laptop client and does nothing on a WAN path, so the gate is recorded as missed rather than tuned around.

Phase 2 gates (final bench above):

- [x] Byte-identical interop with the Python backend in both directions (`test_mixed_data_planes_interoperate_end_to_end`, v2 and v3, with rekey)
- [x] Full suite passes on both backends
- [x] M5 LAN TCP 1.5 Gbps or more, both suites
- [ ] Tunnel RTT overhead 0.2 ms or less, both suites. Missed: v3-kem 0.213 ms (v2 0.177 ms); host wake-up latency, see above.

### Phase 3 design

**Bottom line.** Phase 2 already clears the Phase 3 throughput gate: one worker does about 3.8 Gbps against a target of 3 Gbps or more. The other two gate items do not depend on the data plane. The fixed-rate UDP sweep is harness work, and M7 at 10k/s exercises the Python control plane. Every data-plane change below is therefore headroom or multi-client scaling, not gate work. Recommendation: (a) UDP GSO/GRO, then (b) a measured direction split. Defer multi-queue N workers and TUN offload.

Evidence: M5 TCP-only, 10 s, single stream, release build, unprivileged netns (`unshare -rnm`), powersave governor; 3.74 Gbps. This ran against sentinel-74's in-progress `measure_throughput.py`, TCP part only. A temporary build timed each loop phase in wall-clock time, so kernel work done inside a syscall counts towards that phase. Both workers were saturated: busy about 97% (client) and 90% (server) of the run.

| Phase, share of busy time | Client (data out) | Server (data in) |
| --- | --- | --- |
| UDP send (`sendmmsg`) | 42% | 18% (ACKs) |
| TUN write | 22% (ACKs) | 39% (0.99 µs per packet) |
| AES-GCM seal + open, including the per-packet copy | 16% | 18% |
| TUN read | 12% | 5% |
| UDP receive (`recvmmsg`) | 5% | 15% |

**1. Where the time goes.** About 80% of worker time is per-packet kernel work inside syscalls, and about 15% is crypto plus copies. The phases also include softirq work done for the peer: a veth send runs the receiver's stack, and a TUN write runs TCP receive. So the gains below are veth upper bounds; on EC2, ENA has no USO, so expect less there. The supervisor polls at 5 Hz and is off the packet path. Levers, by expected gain:

1. UDP GSO and GRO. A veth microbenchmark showed sending about 7× cheaper per byte and receiving about 9× cheaper. Estimated M5 gain: about 1.4×, after which the server is TUN-write-bound.
2. Direction split (one thread per direction). Estimated from summed phase times: about 1.4–1.8× on top of (1).
3. TUN offload. The TUN write is 39% of the server and the biggest remaining lever, but also the riskiest; see item 5.
4. N workers. No M5 gain at all: one stream is one session, one inner flow, one TUN queue and one socket.
5. Removing allocations. Bounded by the 15% crypto bucket; skip.

**2. Multi-queue TUN.** Feasible without new unsafe code. Python opens N fds with `TUNSETIFF` plus `IFF_MULTI_QUEUE` under the same name (verified unprivileged: 4 queues), `TUNSETQUEUE` with `IFF_DETACH_QUEUE`/`IFF_ATTACH_QUEUE` toggles a queue, and Rust adopts each one through the unchanged 10:200 `check`. Observed kernel behaviour:
- each inner flow stays on one queue (32 flows spread 8/12/5/7);
- automatic queue selection steers a flow's replies to the queue that last wrote that flow (16 of 16).

Emulated TUN has no kernel hashing, so N socketpairs stand in for it, and steering tests use a native TUN under `unshare -rn`. **Decision: defer** (see item 3).

**3. Workers and sockets** (for when multi-client scaling gets a gate):
- **Layout:** N workers, each with an `SO_REUSEPORT` UDP socket (set and bound by Python) and its own TUN queue.
- **Inbound affinity:** reuseport hashes the client's 4-tuple, so each session's inbound traffic lands on one worker. Its replay window stays single-threaded and in order.
- **Replies:** any reuseport socket has the same source address, so a reply leaves correctly from the worker that received the request.
- **Table:** the ArcSwap table is shared unchanged.
- **Stats:** per-worker counters, summed in `stats()`.
- **Nonces stay safe:** the counter is atomic in the shared `Session`, and `rekey_under_load_never_repeats_a_nonce` proves it.
- **Ordering does not:** a session's inner flows can land on different TUN queues, so several workers seal for one session. Their batches interleave sequence numbers past the 128-entry window, and the receiver (Python-plane receivers keep 128 too) drops valid frames as outside the window. Multi-worker therefore needs home-worker sealing: hand the packet to the worker that owns the session. That handoff is the real cost.
- **Default N = 1, with no knob in Phase 3.** On a 2-vCPU t3.small the direction split already uses both cores.

**4. UDP GSO and GRO** (nix =0.31.3, measured on this kernel):
- **API:** nix exposes `sockopt::UdpGsoSegment` / `UdpGroSegment`, `ControlMessage::UdpGsoSegments(&u16)` for sending and `ControlMessageOwned::UdpGroSegments` for receiving.
- **Send path:** use `sendmsg` with a per-call segment-size cmsg over a run of consecutive frames with the same destination and the same length; the last frame may be shorter. Not `sendmmsg`, because nix shares cmsgs across the whole batch. Not the socket-level `UDP_SEGMENT` option either, which would split every longer datagram.
- **Limits:** cap a run at 64 segments and 65,000 bytes. This kernel rejects more than 128 segments (EINVAL) or more than about 64 KB (EMSGSIZE).
- **Parity at mtu-1280:** GSO succeeds only when each segment fits the path MTU. Measured: 1,252 B works, 1,253 B fails with EMSGSIZE, and a plain datagram of the same size is sent and fragmented. So a frame larger than MTU − 28 always goes through plain `sendmmsg`, and `IP_MTU_DISCOVER` stays untouched. On EMSGSIZE, EINVAL or EIO from a GSO send, resend that run with `sendmmsg` and remember a per-peer GSO size limit. If the start-up probe `setsockopt` fails, GSO is off.
- **Receive path:** Rust sets `UDP_GRO` after adopting the socket (Python's last read happens at connect, before the data plane exists). It splits each coalesced buffer by its segment size and sends every segment through the existing `open`, so authenticate-then-commit is unchanged. Receive memory stays at today's 64 × 64 KB.
- **No quinn-udp:** current versions need rustc 1.88, and older ones force DF.

**5. TUN offload** (`IFF_VNET_HDR`, `TUNSETOFFLOAD`, `virtio_net_hdr`). **Defer to its own phase.** It needs userspace TCP segmentation and checksums on TUN → UDP, in-order coalescing on UDP → TUN, and parsing of `virtio_net_hdr` from the kernel. It is the largest remaining lever (the server's TUN write) and the riskiest, and the gate does not need it. The Python-side ioctls already work unprivileged (`vnet_hdr` with CSUM, TSO4 and TSO6), so a later phase can keep the unsafe inventory at 3.

**6. Python surface.** Phase 3 adds no config knob. The direction split stays internal to `DataPlane`, with the same API:
- `stop()` sets the flag and joins both threads;
- each thread is guarded, the first error wins and also sets the stop flag so its sibling exits;
- the supervisor and the teardown order are unchanged.

A later multi-worker phase would add one knob, `data_plane_workers` (an int or `auto`).

**7. Invariants that must not move:**
- **Authenticate, then commit, per session:** every GRO segment goes through `open` on its own, and the replay window is touched only by the receiving thread.
- **One sealer per key:** still the single shared `Session`; seals from other threads stay nonce-safe through the atomic counter.
- **New ordering rule:** frames sealed but not yet sent for one session, across all sealers, stay well under 128. A GSO run is at most 64 frames, and with the split the second sealer seals only rare control replies (PONG, BIND_ACK).
- **Inner-packet checks:** unchanged, applied per segment.
- **Revocation:** `remove_session` reaches every thread through the shared table within one loop cycle.
- **Bounded memory:** at most 64 receive buffers and 64 staged send frames, and no unbounded queues.
- **Unchanged:** unsafe stays at 3 blocks, MSRV stays 1.85, and the nix pin stays exact.

**8. Slices** (one commit each, every one shippable behind `data_plane`):
- **(a) UDP GSO send plus GRO receive, with fallback.**
  - Cargo tests: GSO run grouping (destination, length, caps); GRO split, where a tampered segment drops only itself; the EMSGSIZE fallback.
  - Python under `unshare -rn`: frames larger than MTU − 28 at mtu-1280 are still delivered.
  - Reordering: iperf3 JSON `retransmits` plus `nstat` TcpExt reorder and out-of-order counters in the client netns, compared across python, rust and rust+GSO.
  - Performance: an unprivileged M5 A/B.
- **(b) Direction split**, optional and kept only if the M5 A/B shows at least 1.3× over (a).
  - Race tests run with the split.
  - A receiver-side sequence-distance assertion (≤ 128) while control replies interleave with bulk data.
  - A crash in either thread surfaces in Python and stops both.
- **(c) Gate run** on sentinel-74's harness: M5, the fixed-rate UDP sweep, and M7 at 10k/s in rust mode.
- **Deferred:** multi-queue N workers (needs home-worker sealing and a multi-client gate first) and TUN offload (its own phase).

### Phase 3 results

Gate run: commit 2e0a5e5 (clean), governor pinned to performance, median of 5 runs per cell (`sudo env PHASE=3 scripts/bench_dataplane.sh`, raw data and `environment.txt` in `eval/results-summary/phase3-2026-10-29/`). Shipped: slice (a) UDP GSO/GRO with a 4 MB `SO_RCVBUF`, and the control accept backlog fixed at 64 (`CONTROL_LISTEN_BACKLOG`). Slice (b) was skipped: a profile put it at about 1.1 to 1.25x, below its 1.3x bar. Raising TUN `txqueuelen` to 4000 removed the TUN drops but did not add throughput, and it adds about 7 ms of standing queue, so it was not shipped either.

| Suite | Data plane | TCP (Mbps) | Tunnel RTT overhead (ms) | UDP, highest rate with <1% loss |
| --- | --- | --- | --- | --- |
| v2-ed25519 | Python | 684 | 0.452 | not measured |
| v2-ed25519 | Rust, Phase 2 (baseline run) | 4,057 | 0.213 | 4,000 Mbps (the top of that sweep) |
| v2-ed25519 | Rust, Phase 3 | 6,670 | 0.235 | 8,000 Mbps (0.10% loss) |
| v3-kem | Python | 686 | 0.455 | not measured |
| v3-kem | Rust, Phase 2 (baseline run) | 4,058 | 0.224 | 4,000 Mbps (the top of that sweep) |
| v3-kem | Rust, Phase 3 | 6,834 | 0.217 | 8,000 Mbps (0.67% loss) |

The Phase 2 baseline row comes from a run the same day on 4566b93 plus the uncommitted harness. It was not committed because its tree was dirty. 8,000 Mbps is the highest rate the sweep offers, so the UDP ceiling may be higher still.

M7 under a real 10k/s ClientHello flood (open-loop sender, offered 9,997 to 9,998 per second): 5 of 5 legitimate connects succeed in both cookie modes. With `cookie_mode = "always"` every connect takes 156 ms. With `cookie_mode = "off"` the connects take 156, 156, 1,186, 1,186 and 2,266 ms, so the median is 1,186 ms: the flood overflows the accept queue and drops the legitimate SYN, which costs one or two 1-second SYN retransmits. Cookies let the server shed flood connections faster (8,070 against 5,650 delivered per second), so the queue drains. `cookie_mode` defaults to `"off"`, which makes the default configuration the weaker one under a flood. An accept-backlog sweep at 10k/s found 64 better than 512 or 4096, because a deeper queue makes legitimate connects wait behind the flood.

M1 on LAN, rust data plane, 30 connects each: cold 126 ms, warm 15 ms.

Phase 3 gates:

- [x] M5 LAN TCP 3 Gbps or more: 6,670 and 6,834 Mbps.
- [x] A fixed-rate UDP goodput sweep replaces the `-b 0` flood numbers: under 1% loss at 8,000 Mbps on both suites.
- [x] M7 100% of legitimate connects under a 10k/s flood, in both cookie modes. The median latency is 156 ms with cookies always on and 1,186 ms with cookies off.

All numbers are from veth on one host. EC2's ENA has no UDP segmentation offload, so the gain from GSO/GRO will be smaller there.

### Phase 4 results

Gate run: commit 6822d09 (clean), governor pinned to performance, on AC power, one `sudo PHASE=4 bash scripts/bench_dataplane.sh` run. Raw data and `environment.txt` are in `eval/results-summary/phase4-2026-10-30/`. Each row is named by its server backends, data plane then handshake: `python-python`, `rust-python` or `rust-rust`. The native client is `pqvpnd connect`, a separate binary, not the Python CLI made faster.

| Metric | Python (published) | Phase 4 | Gate |
| --- | --- | --- | --- |
| M1 LAN cold, Python CLI (ms) | 127 | 126 (rust-python), 150 (rust-rust) | n/a |
| M1 LAN cold, native `pqvpnd` (ms) | n/a | 42 (30/30) | 30, **missed** |
| M1 LAN warm (ms) | 15 | 15 | n/a |
| M2 handshake CPU, v3-kem, both roles (ms) | 0.391 | 0.205 | 0.2, **missed** |
| M2 handshake CPU, v2 (ms) | 0.475 | 0.218 | reported |
| M8 server memory per session, N=50 (kB) | 174 before slice (c) | 56.7 (python-python), 61.6 (rust-python), 24.5 (rust-rust) | 64, met |
| M5 TCP LAN (Mbps) | 680 / 677 | 6,665 / 6,783 | 3,000, met |
| M7 connects under a 10k/s flood | 5/5 | 5/5 in all six rows, median 156 ms | met |
| M6 ping loss across 12 rekeys / rehandshakes | n/a | 0.00% on the Rust data plane; 0.04% / 0.01% on the Python data plane | 0%, met on Rust |

Phase 4 gates:

- [x] Python and Rust produce identical transcripts and secrets on shared vectors: v2, v3-kem, resumption, rekey and rehandshake, replayed through the real state machines.
- [ ] **M1 LAN cold 30 ms or less: missed at 42 ms.** The native client removes Python startup, but the Rust handshake also costs about 24 ms more cold than the Python one in the same CLI (150 vs 126 ms). That cost has not been profiled yet. Phase 5 profiles it first; any fix is reported as a separate, labelled run.
- [ ] **M2 0.2 ms or less: missed at 0.205 ms (v3-kem).** The primitive floor is about 0.167 ms. Nothing was trimmed to meet the gate.
- [x] M8 64 kB per session or less, on every backend. Most of the drop comes from the slice (c) selector thread, which also applies to the default Python path.
- [x] No regression in M5 or M7. The M6 netns gate is new in this run. On the Python data plane it lost 2 of 5,447 pings across 12 rekeys (0.04%) and 1 across 12 rehandshakes (0.01%). There is no earlier netns M6 baseline, so it is recorded here, not counted as a regression.

Caveat: `environment.txt` says `pqvpnd: MISSING`, because the environment is captured before the build step. The 30 native M1 rows show the binary was built and run. The runner will be fixed in Phase 5.

### Phase 5 results

Branch `rust-core/phase-5-hardening` from main a16ae2a. Every number here is from an unprivileged probe unless it says gate run. The gate run needs sudo and has not happened yet.

#### The Phase 4 misses: root cause

Both Phase 4 misses had the same cause: how aws-lc seeds its random number generator.

- **M1 cold.** aws-lc-sys 0.46.0 seeds its Tree DRBG from CPU Jitter Entropy on the first random draw in each process. That costs about 27 ms (a pure aws-lc-rs probe measured 26.6 ms for the first draw and 3 µs for the second).
  - Python and Rust handshakes were swapped between client and server (2x2), under `unshare -rn`. The cost is entirely on the client and does not depend on the server's backend.
  - The Python handshake never touches aws-lc's RNG, which is why rust-python was not slower.
  - The native `pqvpnd connect` paid it too: about 27 of its ~34 ms.
- **M2.** In the jitter build, aws-lc sets RDRAND as its prediction-resistance source, so every `RAND_bytes` call reads RDRAND. That is about 18 µs per v3-kem handshake, 9.9% of cycles.
  - PyO3 and the harness glue cost only a few µs: pure Rust measured 198 to 207 µs, through Python 205 to 211 µs. So trimming the glue could never have met the gate.

**Decision (user, 2026-10-30): build aws-lc without jitter entropy** (4425fa6, `AWS_LC_SYS_NO_JITTER_ENTROPY=1` in the repo-root `.cargo/config.toml`, so cargo, maturin, the PKGBUILD, debian/rules and the bench runner all pick it up).

- **What it changes:** the DRBG is seeded from `getrandom` (`CRYPTO_sysrand`), with RDRAND as extra entropy and personalization. Prediction resistance is off. See aws-lc `entropy_sources.c` and `rand_extra/vm_ube_fallback.c`.
- **What it costs:** aws-lc's second independent entropy source. In aws-lc's own words, randomness "might not use two independent entropy sources". The build is also incompatible with aws-lc FIPS, which this project does not use.
- **Why it is acceptable:** `getrandom` is the same source the Python path (liboqs, cryptography) uses today, so the RNG is no weaker than the published baseline.
- **EC2:** aws-lc already skips jitter on VMs that advertise VM UBE, so EC2 numbers may differ from the laptop either way.
- **Provable:** the runner records the `jent_` symbol count of the installed extension (382ee27). A no-jitter gate run must show 0.

Probe results with the no-jitter build. These are labelled probes, not gate numbers:

| Metric | Jitter (Phase 4 build) | No jitter | Gate |
| --- | --- | --- | --- |
| Native `pqvpnd connect` cold, spawn to connected line, no ping polling (ms) | 34.4 | 6.5 | n/a, different clock from M1 |
| M2 v3-kem, `eval/run_pqvpn.py --handshake rust`, 3 runs of n = 50 (ms) | 0.205 (gate run) | 0.184, 0.187, 0.199 | 0.2 |

The M2 margin is thin. If the pinned gate run lands above 0.2 ms, it is reported as missed. Transcript hashing, length checks and constant-time compares are not trimmed. SHA-256 (transcript, HKDF, fingerprints) is now the largest cost that is not a primitive, at about 12% of cycles.

#### Native client as a backend of the client service (Option T)

- **Decision (user): Option T.** The Python `ClientService` keeps the socket, all 11 IPC commands and `ClientStatus`, so the GUI is unchanged.
  - With `client_backend = "native"` it supervises `pqvpnd connect --status-json` (562b742).
  - Option F would have `pqvpnd` own the socket; it was not chosen. It would have meant porting profile import, enrollment and identity creation (the most audited client file handling) to Rust, for about 2 to 3 more weeks.
- **Prerequisite, done:** `pqvpnd` matches the Python client's network handling.
  - IPv6 guard: 45d3bfb.
  - Full and split tunnel routing with exact rollback: 7787c96.
  - systemd-resolved DNS, reverted first on teardown: 6f991ef.
- **Status pipe (6f8b129):** JSON lines, wire spec v1, at most 4096 bytes per line, flushed.
  - States: CONNECTING, CONNECTED (on up, every 1 s and on each epoch change), then exactly one final line after cleanup. That line is DISCONNECTED (exit 0), FAILED (exit 1, or exit 2 for a config refusal) or BLOCKED.
  - Probe counts are deltas.
  - The service treats every line as untrusted. An invalid stream stops the child and fails closed.
- **The GUI contract is tested (00bba49 and b32e645):** `ClientStatus(**status)` raises on an extra key but silently defaults a missing one. So every STATUS, in every state and on both backends, must have exactly the dataclass's keys, with values of the annotated types.
  - The real `pqvpnd` against the Python server is covered under `unshare -rn`, v2 and v3, with the kill switch on.

#### Kill switch

- **The gap:** the Python client never enforced `kill_switch`; the GUI said "not enforced".
- **Decision (user): a real kill switch now, for both clients.**
  - An nft table, `inet pqvpn_killswitch`, installed before the tunnel comes up and narrowed to a "connecting" phase while reconnecting. It fails closed on a crash: SIGKILL leaves the table blocking until `pqvpnd recover` or Disconnect.
  - Full tunnels that would leak DNS are refused.
  - Commits: c8f2bb0, 4e9dfed, 9f1b66f, 6c271fa, 600b219, 5e6e24b.
- **Only the user's Disconnect lifts it.** A lost session leaves traffic blocked and shows BLOCKED.

#### Fuzzing

- **New coverage (ad2aa52):** resume tickets that pass GCM with hostile hello fields (X25519 points, a malformed ML-KEM key, the wrong protocol version); control traffic on a resumed session; and the client ticket-file parser (JSON and base64), which must round-trip through the writer's format.
- **The 24 h run started 2026-10-30 23:19 IST** from 6f991ef. All 5 targets run side by side, one worker each, with ASan.
  - It counts for v4.0.0 only if these are unchanged at the tag: `pqvpn_core` tree `60df2ae`, `core/fuzz` tree `b624343`, `core/Cargo.lock` `537a016`. The governor was not pinned, which is fine because the gate is 0 artifacts, not a rate.
  - The run started with `core/pqvpnd/src` dirty. That crate is not a fuzz dependency, and the run's validity rests on the three tree hashes, not on a clean checkout.
- **10-minute preflight at 45d3bfb, 0 artifacts:**

| Target | exec/s | Coverage after cmin | Corpus after cmin (files) |
| --- | --- | --- | --- |
| dispatch | 22,771 | 536 | 19 |
| open | 97,463 | 143 | 8 |
| handshake_decode | 34,240 | 1862 | 1907 |
| handshake_machines | 6,034 | 3109 | 219 |
| established | 1,615 | 1966 | 34 |

#### Ticket hardening

- The ticket file stays plaintext with mode 0600; sentinel-10's S4 records the rationale.
- Both loaders refuse anything that is not a private regular file owned by the effective uid (b0e69eb, 87077bc).
- The Rust loader opens with `O_NONBLOCK`, so a FIFO planted at the path cannot hang it.
- A ticket the server rejects is deleted (de1bea7).

#### Phase 5 gates

| Gate | Status | How it is verified |
| --- | --- | --- |
| 24 h of fuzzing, no crash | **In progress** (started 2026-10-30 23:19 IST) | 0 files in `artifacts/*/` after 86,400 s per target, and the three tree hashes above unchanged at the tag |
| `cargo deny` and `cargo audit` clean | sentinel-10, S4 | Both run at the tag commit; output in the release notes |
| unsafe review | sentinel-10, S4 | `pqvpn_fd` is the only crate with unsafe; `own()` stays a safe fn so the single-crate invariant holds |
| Pentest suite re-run clean | **Partial** | The network-leak section (#33 to #40) re-ran with the kill-switch case: SECTION 4 OK, while #33, #37 and #39 stay PARTIAL in `report.md`. Pending: the full 70-attack re-run and the real-host (sudo) kill-switch check |
| Arch and Debian packages build from `git archive HEAD` | **Pending** (pqvpnd is in the PKGBUILD and debian/rules since 186f744; neither build has run) | `makepkg -fC` and the `debian:trixie` build, after the final digest re-pin, which comes last |
| Full M1 to M8 rerun | **Pending, needs sudo** | One `bench_dataplane.sh` run on a clean tree, governor pinned, `jent_` = 0 recorded; M1 native and M2 reported as separate labelled rows attributed to the jitter decision |
| M1 LAN cold 30 ms or less (carried from Phase 4) | **Pending** (probe: native 6.5 ms on a shorter clock) | The gate run's native M1 row |
| M2 0.2 ms or less (carried from Phase 4) | **Pending** (probe: 0.184 to 0.199 ms) | The gate run's M2 v3-kem row; reported as missed if above 0.2 |
| Tag `v4.0.0` | Pending | After every row above is met or reported |

## Security invariants and tests

The rewrite must not weaken a single property in the security gap analysis. These are the invariants each Rust PR is checked against:

- **Hybrid only.** X25519 and ML-KEM-768 are both always in the key schedule; there is no code path that builds a classical-only session.
- **Same key schedule.** The 12 HKDF secrets, their labels, directional and channel separation, and nonce bases match Python byte for byte.
- **Authenticate, then commit.** The replay window advances only after the GCM tag verifies, exactly as `ReplayWindow.check` then `commit` does now.
- **Inner-packet validation stays.** Decrypted packets must pass the same source-IP check as `validate_client_packet` before reaching the TUN.
- **Revocation reaches the core.** `remove_session` and ticket-key rotation take effect in the Rust session table within one revocation-loop tick.
- **No unsafe outside one module.** `#![forbid(unsafe_code)]` on every crate except the small syscall and ioctl module, which gets a line-by-line review and Miri where it can run.
  Phase 5 review (2026-10-30): `pqvpn_fd` holds the only four `unsafe` blocks (`fcntl(F_GETFD)`, `BorrowedFd::borrow_raw`, `OwnedFd::from_raw_fd` in `own`, and the `TUNSETIFF` ioctl), each with a SAFETY comment; the `ifreq` layout is a compile-time assert. `own()` stays a safe fn on purpose: its one caller is in `pqvpn_core`, and `forbid(unsafe_code)` cannot be relaxed for one block, so the ownership contract (a fresh `os.dup()` copy nothing else uses) is documented on `check` and `own` rather than in the signature. Miri cannot execute these FFI calls, so it adds no coverage here.
- **No secrets cross back.** The FFI returns only counters and status; keys are never readable from Python once handed over.

Test strategy, on top of the existing 560 tests and 70-attack pentest suite:

- [x] Run the whole Python suite against both backends via a `--backend` pytest option.
- [x] Cross-implementation interop: Python client to Rust server and the reverse, for v2, v3-kem and v3-mldsa, including rekey and resumption.
- [ ] Known-answer vectors exported from the Python code for HKDF output, frame encryption and transcripts, checked in Rust unit tests.
- [ ] Differential fuzzing with `cargo-fuzz` on frame decryption, the replay window and handshake parsing, comparing Rust against Python where both exist.
  cargo-fuzz smoke 2026-10-29: dispatch 1.63M runs, open 6.70M runs, 60 s each, no crashes; cargo deny + cargo audit clean.
  Re-run 2026-10-30: `cargo deny check` advisories, bans, licenses and sources ok (one harmless warning: the `libfuzzer-sys` NCSA exception is unmatched because `core/fuzz` is outside the workspace); `cargo audit` 71 crates against 1,395 advisories, none found.
- [x] Property tests (`proptest`) for the replay window and sequence handling at the 64-bit edge.
- [ ] Re-run the Tamarin models only where the protocol changes (the folded `UDP_BIND` in Phase 1); a pure port changes no model.

## Keeping the IEEE evaluation reproducible

Treat the Python and Rust backends as two configurations of one artifact, not as a before and after. That turns the migration into the paper's strongest evidence: same protocol, same crypto, same testbed, only the implementation language changes.

- **Freeze first.** Tag `v3-paper-artifact` in Phase 0 and archive it on Zenodo, so the Python numbers stay reproducible even after main moves on.
- **One harness, a backend flag.** `eval/run_all.py --backend python|rust` and `eval/reproduce.sh` run both; results land in `summary.csv` with a `backend` column, so the generated LaTeX tables show the ablation directly.
- **Offline, pinned builds.** Commit `Cargo.lock`, vendor crates with `cargo vendor` into the source tarball, and pin the toolchain in `rust-toolchain.toml`. The package is built from `git archive HEAD`, so the vendored tree is what ships.
- **Record the environment.** Every run writes rustc version, crate versions, liboqs version, CPU model and flags (AES-NI, AVX2), kernel and governor into its results header.
- **Same statistics.** 30 runs per cell, median with 95% bootstrap CI, as M1 does today, for every new number.
- **Packaging chores per release.** After each merge, refresh `packaging/arch/pqvpn-3.0.0.tar.gz`, the PKGBUILD `sha256sums` and the digest pin in `tests/test_onboarding.py`; add `cargo` and `maturin` to the Arch makedepends and the `debian:trixie` build container. Both packages also build and install `/usr/bin/pqvpnd`. Refresh the pins as the last commit before a package build: every commit under the tarball allowlist moves them.
- **MSRV 1.85 has no headroom.** `toml`, `toml_parser` and `zeroize` declare exactly 1.85, the `debian:trixie` rustc. Re-check the trixie build (`cargo +1.85.1 check -p pqvpnd --all-targets`) before bumping any of those pins.

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
| Rewritten code drops a past fix (cookie boot-time window, rate limiter, revocation kill) | Medium | Medium | Port the regression tests first, then the code. The old cookie `bid - 1` window was replaced by a current-plus-previous secret in 30e60fc; its regression test is `test_cookie_no_crash_at_boot_time` |

## Next steps

- [x] Phase 0: re-run M1 to M8 on current main with flame graphs, then tag `v3-paper-artifact` (needs root on your machine). Baseline b726b42 in `eval/results-summary/phase0-2026-10-28/`; the `v3-paper-artifact` tag already existed and is public, so it was not moved.
- [x] Phase 1: open one PR per quick win, starting with warm connect through `ClientService` and pyroute2. Merged: #28 warm connect, #29 TCP_NODELAY.
- [x] Phase 4: Rust handshake behind `handshake = "rust"`, `pqvpnd connect`, the server selector thread. Gate run 6822d09: transcripts, M8, M5 and M7 met; M1 cold (42 ms) and M2 (0.205 ms) missed and reported. The IPC daemon is deferred to Phase 5.
- [ ] Phase 5: hardening and release. Done: both Phase 4 misses root-caused (aws-lc jitter seeding; built without it, 4425fa6), pqvpnd network parity, a real kill switch on both clients, the native backend of the client service with the GUI contract tested, ticket loader hardening, and new resume and ticket-file fuzz coverage. In progress: the 24 h fuzz run (since 2026-10-30 23:19 IST). Pending: the full pentest re-run, Arch and Debian package builds, the sudo M1 to M8 gate run, then tag `v4.0.0`.
- [x] Phase 2 spike: a `core/` skeleton with maturin, one known-answer test for frame encryption, and a `--backend` pytest option, to prove the build and packaging path before the real port.

Open question: which venue and deadline is the paper aiming for? That decides whether to freeze after Phase 2, Phase 3 or Phase 4.

## Appendix A — Phase 4 design

Oct 30, 2026 · core coding session (Opus) · base `c038f53` · **design only, no code until the user approves**

This answers the Phase 4 brief above and is reconciled with [Appendix B](#appendix-b--phase-4-handshake-inventory) (cited below as "inventory §n"). Every number marked *measured* was taken today on this laptop (governor not pinned, so treat them as approximate); the probes are in its last subsection. Numbers marked *estimate* are not measurements.

### Bottom line

- **The crypto is ready.** aws-lc-rs `=1.18.2`, already in `core/Cargo.lock`, has stable ML-KEM-768, ML-DSA-44, X25519, Ed25519, HKDF, HMAC and SHA-256. It builds at MSRV 1.85.1 without the `unstable` feature, and it interoperates with liboqs 0.16.0 in both directions (*measured*, §2). The handshake needs no new crate.
- **Each of the three gates depends on a different component**, and only M2 depends on the language of the handshake:
  - **M2 ≤ 0.2 ms** (both roles in one process): a Rust handshake for both roles, called through PyO3. Primitive floor *measured* at 0.17 ms for v3-kem, so this is reachable but tight.
  - **M8 ≤ 64 kB** (server RSS per session at N = 50): this is set by the server's **thread per session**, not by Python crypto objects. A v2 session whose handshake thread exits after hand-off costs 15.4 kB; a session held by its own thread costs 77 to 87 kB (*measured*, §3). The lever is a small change to the Python server's concurrency, not a Rust server.
  - **M1 cold ≤ 30 ms** (a new client process, no ticket, spawn to first ping): this needs a **native one-shot client** (`pqvpnd connect`). The bare interpreter alone costs 18 ms and `import vpn.cli` costs 119 ms (*measured*).
- **Recommendation: option A, plus a server concurrency fix, plus a native one-shot client.** The Rust handshake covers both roles through PyO3. The Python server keeps accounts, authorization, the IP pool, cookies, the rate limiter and revocation. The IPC daemon is deferred.
- **One design rule decides the slice boundaries:** once the handshake runs in Rust, no secret may come back up to Python. That pulls control-channel seal/open, rekey and rehandshake derivation, their confirmation HMACs, and ticket issue/validate/persist into the same Rust session object (§5).

### 1. Determinism

**The problem.** ML-KEM encapsulation, ML-DSA-44 signing (liboqs 0.16 signs hedged: two signatures of the same message differ, *measured*), and every `os.urandom` draw make a run unreproducible. aws-lc-rs 1.18.2 has **no seeded or derandomized encapsulation** in its public API, so injecting an RNG is not possible. The seam must inject **outputs**.

**The seam.** A private trait inside `pqvpn_core`, with one production implementation and one test implementation:

```rust
// As built in slice (a), core/pqvpn_core/src/handshake.rs. Sealed, so no crate linking pqvpn_core can implement it.
pub trait Draws: sealed::Sealed {
    fn random(&mut self) -> Result<[u8; 32], Error>;                           // client_random, session_id, server_random, rekey nonce
    fn x25519(&mut self) -> Result<agreement::PrivateKey, Error>;              // ephemeral DH keys
    fn mlkem_keypair(&mut self) -> Result<(DecapsulationKey, Vec<u8>), Error>; // (dk, ek bytes)
    fn encapsulate(&mut self, ek: &[u8; 1184]) -> Result<([u8; 1088], Zeroizing<[u8; 32]>), Error>;
}
pub struct Os;                         // calls aws-lc-rs; zero-sized
#[cfg(test)] pub(crate) struct Replay; // pops one step's recorded draws, checking kind and order, and that all were used
```

Slice (a) checks each draw's **kind and order**, not a finer label. v3-mldsa is not ported, so there is no `mldsa_sign`. The ticket key and nonce draws come in slice (b) with tickets.

- The state machines are generic over `D: Draws`. The PyO3 classes and `pqvpnd` name only `Os`, so the shipped `.so` and binary contain only that instantiation.
- `Replay` is `#[cfg(test)]`, so it exists only in `cargo test` builds of the crate. There is no feature flag, no runtime flag and no Python-visible hook. The vector tests live in `src/` unit-test modules, because integration tests in `tests/` cannot see `cfg(test)` items.
- `Replay` checks the **label and order** of every draw. A port that draws in a different order fails loudly instead of producing different-but-valid bytes.
- Importing recorded values uses stable APIs: `agreement::PrivateKey::from_private_key(&X25519, ..)` and `kem::DecapsulationKey::new(&ML_KEM_768, 2400-byte sk)`. For `Replay::encapsulate`, the recorded `(ct, ss)` is returned as is.
- `mlkem_keypair` returns the public key bytes alongside the key, because aws-lc-rs cannot derive `encapsulation_key()` from a key imported with `DecapsulationKey::new`. `Os` takes them from `encapsulation_key()`; `Replay` returns the recorded ones.
- Ed25519 signing is deterministic, so v2 needs no signature injection.
- Clocks: ticket expiry (`time.time`) and cookie rotation are passed in as arguments (`now: u64`), not read inside the state machine.

**Vector export (sentinel-e2, `tests/vectors/`): record, don't derandomize.** The Python generator wraps the draw sites listed in inventory §1.8 and **records** what they return during a normal run:
- wrap `os.urandom` and `X25519PrivateKey.generate` (store `private_bytes_raw()`);
- wrap `PQCProvider.generate_keypair`, `.encapsulate` and `PQSignatureProvider.sign`;
- write the recorded draws in order with their labels, then the outputs: every wire message, the transcript digest after each message, the 12 secrets, both Finished MACs, the first CONFIG control frame, a rekey and a rehandshake epoch, and a resume run with its ticket.

This needs no ctypes shim for `encaps_derand` (inventory §1.8 point 3). Rust replays the recorded draws and must reproduce every output byte for byte.

**Cross-checks against liboqs, the oracle, in both directions:**
- **Rust decapsulates liboqs:** a KAT in `cargo test` over liboqs `(sk, ct, ss)` triples from the vectors. This also proves that liboqs's 2400-byte secret-key format loads in aws-lc-rs, which matters because v3 client identities on disk are liboqs keys.
- **liboqs decapsulates Rust:** the interop tests already do this with no extra hook. Python client against Rust server and Rust client against Python server, for every suite, means liboqs decapsulates aws-lc-rs ciphertexts and the reverse. Matching Finished MACs prove equal secrets.
- **ML-DSA-44:** Rust verifies liboqs signatures and liboqs verifies Rust signatures (interop for v3-mldsa).
- *Measured today* with a throwaway crate built at 1.85.1, offline, with the workspace's `Cargo.lock`. All of the following passed:
  - aws-lc-rs decapsulated a liboqs ciphertext with a liboqs secret key;
  - liboqs decapsulated an aws-lc-rs ciphertext;
  - aws-lc-rs imported liboqs's 2560-byte ML-DSA-44 secret key, derived the identical public key, and verified a liboqs signature;
  - liboqs verified an aws-lc-rs signature;
  - a 12-byte HKDF-Expand matched `cryptography`'s `HKDFExpand`.
  - The scratch code is in this session's scratchpad (`spike/src/main.rs`), not in the repo. Slice (a) turns it into real tests.

### 2. Crates

| Need | aws-lc-rs 1.18.2 API | Stable? | MSRV |
| --- | --- | --- | --- |
| ML-KEM-768 | `kem::{ML_KEM_768, DecapsulationKey, EncapsulationKey}` | yes: `kem` is not `cfg`-gated | crate 1.71, aws-lc-sys 0.46.0 1.71 |
| ML-DSA-44 | `signature::{ML_DSA_44, ML_DSA_44_SIGNING, PqdsaKeyPair::from_raw_private_key}` | yes: `unstable` only re-exports deprecated aliases of these | same |
| X25519 | `agreement::{X25519, PrivateKey::from_private_key, agree}` | yes | same |
| Ed25519 | `signature::{Ed25519KeyPair::from_seed_and_public_key, ED25519}` | yes | same |
| HKDF-SHA256 | `hkdf::{Salt::extract, Prk::new_less_safe, expand}` with a `KeyType` impl for 12- and 32-byte outputs | yes | same |
| HMAC, SHA-256, constant-time compare | `hmac::{sign, verify}`, `digest`, `constant_time` | yes | same |
| Wipe on drop | `zeroize =1.9.1` (already a dependency) | — | — |

- **The handshake adds no crate.** `subtle` is not needed: `hmac::verify` and `constant_time::verify_slices_are_equal` cover the compares.
- **liboqs stays the oracle and is never linked into Rust.** That answers inventory §6 item 6: the Rust core has no liboqs build to pick, because liboqs runs only in the Python vector generator and in the Python peer of interop tests.
- **Primitive cost, *measured*** (release build, 3,000 iterations, laptop, governor not pinned):

| Primitive | µs |
| --- | --- |
| ML-KEM-768 keygen | 15.3 |
| ML-KEM-768 encapsulate | 15.4 |
| ML-KEM-768 decapsulate | 15.6 |
| X25519 keygen and public key | 8.8 |
| X25519 keygen and agree | 29.5 |
| Ed25519 sign | 7.0 |
| Ed25519 verify | 30.6 |
| ML-DSA-44 sign | 83.4 |
| ML-DSA-44 verify | 22.3 |

- **New crates for `pqvpnd` only (slice d):**
  - `serde_json =1.0.154` moves from a dev-dependency to a dependency, for CONFIG and the ticket file.
  - `toml =1.1.2` (MIT OR Apache-2.0, MSRV exactly 1.85) and `serde`/`serde_derive =1.0.229` (MSRV 1.71) parse `client.toml`. Both are already in the local cargo cache and pass the deny licence list on paper.
  - `cargo deny check` and `cargo +1.85.1 build` run as part of slice (d) before anything merges.
- **Deliberately not used:**
  - `rtnetlink`, which pulls in tokio. Address and route setup forks `ip`, as Python does today. Netlink comes only if the M1 run shows the forks matter.
  - `signal-hook`. SIGTERM cleanup uses `nix::sys::signal`, which is already a dependency.

### 3. Gates mapped to components

The definitions below are exactly the Phase 0 to 3 ones (inventory §4). Nothing is redefined.

| Gate | Definition (unchanged) | Baseline | What has to change | Component |
| --- | --- | --- | --- | --- |
| **M2 ≤ 0.2 ms** | `eval/run_pqvpn.py`: `process_time` CPU for client plus server, one process, no network, n = 50; published row is v3-kem | 0.388 ms v3-kem (Table B); v2 0.470; mldsa 0.436 | Both roles' handshakes in Rust, called through PyO3 | slice (b) |
| **M8 ≤ 64 kB** | `eval/measure_memory.py`: server `VmRSS` (loaded − baseline) / N at N = 50, v2, cookies off; the baseline ran the Python data plane | 186 kB published; 170 kB at Phase 0 | The server's per-session thread; Rust objects help a little | slice (c), Python |
| **M1 cold ≤ 30 ms** | `eval/run_pqvpn_net.sh`, LAN: new client process, no ticket, full v2 handshake, bash clock from spawn to first `ping` through the tunnel, 10 ms poll, n = 30 | 126 ms (Phase 3) | The process launched must be native | slice (d) |

**M2.**
- It is both roles, not server-only. The published 0.39 ms is the v3-kem total. Server-only v3-kem is already 0.187 ms in Python today, so gating on server CPU would be a redefinition into a pass.
- The *measured* primitive floors for both roles are 167 µs for v3-kem, 174 µs for v2 and 242 µs for v3-mldsa. That leaves about 30 µs for HKDF (about 26 expands), the transcript hashing, PyO3 crossings and the harness's Python glue.
- **v3-kem and v2 are reachable but tight. v3-mldsa misses by construction**, because ML-DSA signing alone is 83 µs.
- The harness needs a `--handshake python|rust` flag (an `eval/` change, sentinel-e2).

**M8: the measurement that decides the server question.** The script is `m8probe.py` in this session's scratchpad. It runs in one process, unprivileged, with v3 sessions:

| What is held | kB per session (*measured*, N = 50 or 200) |
| --- | --- |
| a bare Python thread blocked on an Event | 22.5 |
| a thread that ran one handshake and holds the session (`KEMTLSServer` dropped) | 79.0 (76.5 with `MALLOC_ARENA_MAX=2`) |
| the same, with the `KEMTLSServer` object kept, as `_client` does today | 86.6 (85.0) |
| the session objects only, with no per-session thread | **13.1** |
| **slice (c) shape, v2:** each handshake on its own thread, which hands the session to a shared list and exits; threads started 10 ms apart | **15.4** (also 15.5 at N = 200) |
| the same, with all 50 threads started together | 23.3 |

- **Per-thread malloc arenas are not the cause:** only about 2 kB changes with `MALLOC_ARENA_MAX=2`.
- **The cause is a live thread per session, plus the memory the crypto touches on it, which stays resident** for the session's lifetime: about 65 kB on top of 13 kB of objects.
- Porting the crypto to Rust keeps the stack touched on that thread, so it would not move M8 by much.
- What does move it is letting the handshake thread **exit** once the session is established, and serving every established session's control socket from **one selector thread**. Once the thread exits, the cost drops to 15 to 23 kB.
- The M8 harness starts its clients 0.3 s apart (`measure_memory.py:239-242`), so the staggered 15.4 kB row is the faithful one.
- The probe does not include `ServerSession`, the control socket object, CONFIG or the selector's registration. *Estimate* for the real harness: 20 to 40 kB. This must be confirmed by the real M8 run, which needs sudo.
- **Backend for the gate:** run M8 under every data-plane and handshake combination, as the Phase 2 and 3 M1 rows did per data plane. Slice (c) alone, with no Rust at all, should pass M8 on python/python.
- **Honest attribution:** this is a Python concurrency fix, not a Rust result. The paper should report it as such: the M8 row comes from the server structure, and the Rust handshake contributes only the object-size share.

**M1 cold.**
- The interpreter plus imports cost about 119 ms *measured* (bare `python -c pass` is 18 ms), against a 30 ms gate. A Python launcher that `exec`s a native binary would still pay 18 ms plus the native work plus the 10 ms poll, so it is not a reliable path.
- The gate needs the harness to spawn **`pqvpnd connect --config client.toml`** in place of `$PY -m vpn.cli client connect`. Everything else stays the same: clock, ticket deletion, stop condition, v2, LAN, n = 30. Both rows are reported.
- WireGuard measures 21 ms on the same harness with its own forks, so 30 ms is plausible.
- **If the user holds that `vpn.cli client connect` itself is part of the definition, the gate is unreachable in Phase 4 and is recorded as missed.** It is not to be swapped for the warm number (warm is already 15 ms through the Python `ClientService`).

**Options for the server role (inventory §6 item 1):**

| Option | What it is | Effort (*estimate*) | M2 | M8 |
| --- | --- | --- | --- | --- |
| **A** (recommended) | Rust handshake for both roles through PyO3. The Python server shell keeps accounts, authorization, the IP pool, cookies, rate limiter and revocation. Plus a Python server concurrency fix: handshake threads exit, one selector serves established sessions | (a) + (b) + (c) ≈ 12 to 16 days | projected to meet it (v3-kem, v2); mldsa misses | probe 15 to 23 kB; must be confirmed by the M8 run |
| B | A native server daemon too: authorization DB and account API integration, IP pool, revocation, cookies, rate limiter and CONFIG all rewritten in Rust | A + 15 to 25 days | same as A | meets it with margin |
| C | Gates redefined, for example server-only M2 or a different N for M8 | 0 | v3-kem "passes" today in Python | no |

- **A is recommended.** B duplicates the account and authorization logic that the 70-attack pentest just audited, roughly doubles Phase 4, and buys nothing that a gate needs.
- **C is not recommended.** It is exactly the redefinition-into-a-pass the brief rules out.
- **Suites for the gates:** M1 and M8 have only ever been measured on v2, and M2 was published on v3-kem (inventory §6 item 3). The proposal is to keep the published suite per metric (M1 v2, M8 v2, M2 v3-kem) and report every suite alongside it.

### 4. The switch

- **New key:** `handshake = "python" | "rust"` in `ClientConfig` and `ServerConfig` (`vpn/config.py`). It defaults to `"python"`. Flipping the default is the user's call in Phase 5.
- **`handshake = "rust"` requires `data_plane = "rust"`** and is rejected at validation otherwise. A Rust session must own the data keys, or the data secrets would have to come back up to Python.
- `handshake = "rust"` refuses `allow_mock_pqc`, because aws-lc-rs has no mock. Mock-only tests run on the Python backend only.
- **Mixed peers must interoperate**, because the wire does not change. A Python-handshake client works against a Rust-handshake server and the reverse; that is what the interop tests prove.
- The pytest `--backend` option gains a handshake axis. The suite runs under `python/python`, `rust/python` (data plane / handshake) and `rust/rust`.
- **Two groups of tests stay python-handshake-only:**
  - tests that read `session.secrets` directly, such as the directional-key and rehandshake key-derivation tests, because a Rust `Session` has no getters;
  - tests that use mock PQC.
  - The replay vectors replace their coverage on the Rust side, and both groups are listed by name in the slice (b) PR.
- `pqvpnd connect` has no switch: it is the Rust handshake and the Rust data plane by construction.

### 5. Shape of the Rust code

**Sans-IO.** The state machines take bytes and return bytes. Python (and, in slice d, `pqvpnd`) owns sockets, timeouts, authorization lookups, the IP pool and CONFIG JSON.

```python
# client: same call order as KEMTLSClient / KEMTLSClientV3 today
me = pqvpn_core.Identity.from_path(suite, client_private_path)   # .from_bytes() for tests and the M2 harness
hs = pqvpn_core.ClientHandshake(suite, server_identity_public, server_fp, me)
wire = hs.hello()                       # also used as the cookie-response body
wire = hs.on_server_hello(server_hello)
session = hs.on_server_finished(server_finished)   # -> pqvpn_core.Session

# server: authorization stays a Python lookup between two Rust steps
server_id = pqvpn_core.Identity.from_path("server-kem", identity_private_path)   # loaded once at server start
hs = pqvpn_core.ServerHandshake(suite, server_id)
lookup = hs.client_identity(client_hello)          # Ed25519 public key (v2) or identity hash (v3, mldsa)
wire = hs.respond(authorized_public_key)           # Python passes the key it found, or aborts
finished, session = hs.on_key_exchange(cke)

# resumption
key = pqvpn_core.TicketKey()                       # rotate = replace the object; the old one zeroizes on drop
accept, session, client_id, assigned_ip = pqvpn_core.resume_server(key, hello, version, now)
```

**`Session` replaces the secret-bearing half of `HandshakeSession`.** It holds the 12 secrets in `Zeroizing` buffers and owns the existing `DataSession`. It exposes no getters:
- `seal_control(type, payload)` and `open_control(frame, expected)`;
- `rekey_request()` returns a sealed REKEY_REQUEST, and `on_rekey_request(frame)` returns a sealed REKEY_RESPONSE confirmed under the old key, then activates;
- `rehandshake_request()` and `on_rehandshake_request(frame)` return sealed frames, with the confirmation under the new key and the plain-SHA-256 seed (inventory §1.5);
- `issue_ticket(key, client_id, ip, lifetime, now)` and, on the client, `save_ticket(path, fp)` and `ClientHandshake.resume(path, fp)`. The resumption secret never reaches Python.
- `data` hands the `DataSession` to the `DataPlane`, as `item.crypto._data` does today.

`handshake/kemtls.py` keeps its classes and their call surface: with `handshake = "rust"` they delegate to these objects, so `vpn/runtime.py` changes only where it touches secrets today (`_rekey_server`, `_rehandshake_server` and their client twins, and ticket issue and save).

**Identity secrets.** An `Identity` object is loaded once and shared by every handshake, so a flood does not mean one file read per connection.
- `Identity.from_path` is the production constructor. It reads the private identity file with the same checks as `read_private` (`O_NOFOLLOW`, a regular file, mode 0600 or 0400). Today these secrets are Python `bytes` that cannot be wiped; in rust mode Python never holds them.
- `Identity.from_bytes` is for tests, the interop suite and the M2 harness, which build identities in memory.

**Files.** The workspace rule is to ask before creating files. Proposed new files, for approval:
- `core/pqvpn_core/src/handshake.rs`: messages, transcript, state machines, tickets, the `Draws` seam;
- `core/pqvpn_core/src/schedule.rs`: HKDF labels, the 12 secrets, rekey and rehandshake derivation;
- `core/pqvpnd/` in slice (d): a new workspace member, a binary.

The control channel goes into the existing `session.rs`.

### 6. Slices

They are reordered from the brief. The reasons follow the table.

| Slice | Content | Tests that gate it | Estimate |
| --- | --- | --- | --- |
| **(a) Key schedule, codecs, control channel** | `schedule.rs`; message pack/unpack for v2, v3-kem, v3-mldsa and resume; transcript; Finished MACs; rekey and rehandshake derivation and confirmation; control seal/open; `Draws` plus `Replay`. No PyO3 surface | Vector replay byte-for-byte on every suite; the liboqs decapsulation KAT; `test_frozen_v2_handshake_serialization` mirrored in Rust; rejection parity (below); proptest on the decoders | 4 to 5 days |
| **(b) State machines behind `handshake = "rust"`, Python does the I/O** | `ClientHandshake`, `ServerHandshake`, `Session`, `TicketKey`, resume, client ticket file; the `kemtls.py` delegation; config validation | The whole suite under both handshake backends; interop for every suite in both directions, with rekey, rehandshake and resume; the M2 dry run (unprivileged, in-process) | 6 to 8 days |
| **(c) Server concurrency (Python)** | `_client` does the handshake, then hands the session to one selector thread that runs today's control dispatch, idle and session timeouts; the handshake thread exits; the `max_clients` slot is still held until the session ends | Every runtime, revocation and rate-limiter test unchanged; the M8 probe; M7 flood unchanged | 2 to 3 days, independent of (a) and (b) |
| **(d) `pqvpnd connect`, the native one-shot client** | `client.toml` parsing (failing closed on options it does not support), identity files, ticket, client cookie response, TUN open, `ip` forks for address, link and routes, `UDP_BIND`, the existing `dataplane`, the control loop (keepalive, rekey and rehandshake timers, CLOSE), SIGTERM cleanup that restores routes and closes TUN | Conformance against the Python server under `unshare -rn` (v2 and v3, cookie always, resume, rekey); `cargo deny`; the 1.85.1 build | 7 to 10 days |
| **(e) Gate run** | Needs sudo: M1 cold with a native row, M2 for every suite, M8 at N = 50, plus M5, M6 and M7 no-regression | — | 1 to 2 days |

**Total:** about 20 to 28 working days, so 4 to 5.5 weeks against the plan's 3 to 4.

**Why this cut differs from the brief:**
- **Rekey, rehandshake and resumption move from (c) into (a) and (b).** Their inputs are `rekey_secret` and `control_confirm_key`. If they stayed in Python, a rust-mode session would have to export those secrets, or it could not rekey and M6 would break on the Rust backend.
- **Server-side cookies stay in Python.** The cookie secret is not a session secret, the gate already works, and the twelve successor tests of the `bid - 1` fix keep guarding it unchanged. Only the client's cookie response is needed in Rust, and it goes into (d).
- **The new (c) is the M8 lever and is pure Python.** It is independent, so it can land first.
- **(d) is the one-shot client, not the IPC daemon.** The warm path already does 15 ms through the Python `ClientService`, so no gate needs the IPC. Re-implementing the 11 commands means re-implementing profile import, enrollment export and identity creation in Rust. That is the most security-sensitive file handling in the client, and the GUI's strict `ClientStatus` breaks on any drift (inventory §3). The plan's "pqvpnd speaks the existing IPC" is therefore proposed for Phase 5, or as a thin daemon that serves only CONNECT, DISCONNECT and STATUS while Python keeps the rest. This is the user's call; see the open questions.
- **v3-mldsa:** port it in (a) and (b). It costs about 1 day, keeps the M2 table complete, and is cheap to drop. It stays unreachable from config, as today.

### 7. Tests first, invariants

**Port the regression tests first.**
- Cookie: the twelve `test_cookie_*` tests, including `test_cookie_no_crash_at_boot_time`, the successor of `bid - 1` (inventory §1.6). The `bid - 1` row in the migration plan's risk table is stale.
- Rate limiter: `test_rate_limiter_*` and `test_source_rate_limiter_window`.
- Revocation: `test_revoked_client_session_terminated`, `test_revocation_rotates_ticket_key`, `test_rekey_rejects_revoked_client`, `test_signed_out_client_cannot_resume_before_revocation_sweep`.

All of this code stays in Python under option A, so "port" means the tests run unchanged under `handshake = "rust"` from the first commit of (b). They are not rewritten in Rust. Slice (c) must keep them green, because it moves exactly the code they exercise.

**Wire-quirk parity.** Reproduce each of these exactly; fixing any of them is a protocol change (inventory §6 item 5):
- the v2 `PROTOCOL_NAME` in every HKDF info string;
- the `0x30` byte in the resume context;
- the resume transcript header that claims 1216 bytes over a 1184-byte body;
- the plain-SHA-256 rehandshake seed;
- rekey confirmed under the old key, rehandshake under the new key;
- `unpack_cookie_challenge` ignores the version byte;
- `unpack_cookie_response` does not check that the declared length equals the actual length;
- the ticket expiry is a signed i64 compared with `now > expiry`.

**Rejection parity.** These are differential tests in (a):
- malformed ML-KEM encapsulation keys (out-of-range coefficients), wrong lengths, trailing bytes;
- all-zero X25519 output, which `cryptography` raises on and aws-lc-rs rejects;
- non-canonical Ed25519 signatures.

**Policy:** Rust may reject *more* than Python, which still fails closed as a `HandshakeError`, but never less. Every stricter case is listed in the PR.

**Other invariants:**
- **Tamarin:** not re-run, because the wire bytes do not change. The vectors and interop tests are the proof of that. If any byte has to change, stop and ask; it would need a version bump.
- **unsafe:** `#![forbid(unsafe_code)]` stays on `pqvpn_core` and goes on `pqvpnd`. `pqvpnd` needs a TUN open (`TUNSETIFF`), which goes into `pqvpn_fd`. That takes the unsafe inventory from 3 blocks to 4, all in that one module, reviewed line by line.
- **Zeroize:** every secret, shared secret, PRK, master, the 12 traffic secrets, the ticket plaintext and the resumption secret lives in `Zeroizing` or a `ZeroizeOnDrop` struct. aws-lc-rs key objects are freed by aws-lc, which cleanses on free. No `Debug` on secret types, and no secret getters at the PyO3 boundary.

### 8. Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| M2 misses by tens of µs because of PyO3 and harness glue | Medium | Gate missed | Measure in (b) before (e); batch each role's step into one PyO3 call; report honestly if it misses |
| The M8 fix lands, but the real harness shows more per-session cost than the probe (sockets, the Rust `DataSession`, the CONFIG path) | Medium | Gate missed | The probe is in-process; the M8 run in (c) or (e) decides, and the result is recorded as measured |
| The selector rewrite in (c) changes control-plane behaviour (revocation close, idle timeout, M7) | Medium | High | Keep the dispatch code and only move where it runs; all revocation and timeout tests plus an M7 rerun |
| Rust and Python differ on a wire quirk or a rejection | Low after vectors | High | Draw-order-checked replay vectors, both-direction interop, the parity list above |
| A secret leaks back into Python through a convenience getter | Low | High | No getters by design; a boundary review checklist in every PR |
| `pqvpnd` scope creep (DNS modes, kill switch, split tunnel) | High | Schedule | It fails closed on unsupported config in Phase 4 and grows in Phase 5 |
| `toml` or `serde` fails `cargo deny`, or MSRV moves | Low | Low | Pin exact versions; checked in (d) before merge |
| The ticket file keeps the resumption secret in plaintext JSON on disk | Exists today | Medium | Unchanged in Phase 4 for compatibility; see the open questions |

### 9. Open questions for the user

1. **The server role:** option A (recommended), B or C (§3)?
2. **The M1 cold definition:** is spawning `pqvpnd connect` in place of `python -m vpn.cli client connect` the same definition, with the same clock, stop condition, ticket deletion, suite and n, reported as an extra row? If not, M1 cold is recorded as missed for Phase 4.
3. **The IPC daemon:** defer it to Phase 5, build a thin CONNECT, DISCONNECT and STATUS daemon, or build the full 11-command port as the original plan said?
4. **Gate suites:** keep the published suite per metric (M1 v2, M8 v2, M2 v3-kem) and report the rest? And should v3-mldsa be ported, knowing its M2 floor is 0.24 ms?
5. **Slice (c) touches `vpn/runtime.py`**, which is outside `core/`. Should this session own it, or someone else?
6. **The ticket file:** keep the plaintext resumption secret on disk (today's format, mode 0600), or change it later, for example to an OS keyring or a sealed blob? Phase 4 proposes no change.
7. **New files:** approve `handshake.rs`, `schedule.rs` and the `core/pqvpnd/` crate (§5)?

### Appendix: probes behind the measured numbers

These are throwaway probes, not repo code. Run them from the repo root with `.venv/bin/python`. The Rust ones go in a scratch crate with `Cargo.toml` depending on `aws-lc-rs = "=1.18.2"` and `serde_json = "=1.0.154"`, a copy of `core/Cargo.lock`, and `cargo +1.85.1 run --offline`.

**M8, slice (c) shape** (`python m8exit.py 50 sequential|concurrent`):

```python
# Slice (c) shape: a thread per connection runs the v2 handshake, hands the session off, and exits.
import os, sys, threading, gc, time
sys.path.insert(0, os.getcwd())
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crypto.hybrid_crypto import PQCProvider
from handshake.kemtls import KEMTLSClient, KEMTLSServer
from vpn.identity import fingerprint
def rss():
    for l in open("/proc/self/status"):
        if l.startswith("VmRSS"): return int(l.split()[1])
ssk, spk = PQCProvider().generate_keypair(); ck = Ed25519PrivateKey.generate()
held, lock = [], threading.Lock()
def one():
    srv = KEMTLSServer(ssk, spk, lambda pk: {"client_id": "x"})
    cli = KEMTLSClient(spk, fingerprint(spk), ck)
    sh = srv.process_client_hello(cli.initiate_handshake())
    fin, sess = srv.process_client_key_exchange(cli.process_server_hello(sh))
    cli.process_server_finished(fin)
    with lock: held.append(sess)
n, mode = int(sys.argv[1]), sys.argv[2]
t = threading.Thread(target=one); t.start(); t.join(); gc.collect(); time.sleep(0.2); base = rss()
ts = [threading.Thread(target=one) for _ in range(n)]
if mode == "sequential":
    for t in ts: t.start(); t.join(); time.sleep(0.01)
else:
    for t in ts: t.start()
    for t in ts: t.join()
gc.collect(); time.sleep(0.5)
print(f"v2 thread-exits {mode} n={n}: {(rss()-base)/n:.1f} kB/session")
```

**aws-lc-rs and liboqs cross-check** (`src/main.rs`; feed it the JSON of liboqs `pk, sk, ct, ss, dpk, dsk, sig` hex, then decapsulate and verify its output with liboqs):

```rust
use aws_lc_rs::{agreement, hkdf, kem, signature::{self, KeyPair}};
fn h(s: &serde_json::Value, k: &str) -> Vec<u8> {
    let t = s[k].as_str().unwrap();
    (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect()
}
struct Len(usize);
impl hkdf::KeyType for Len { fn len(&self) -> usize { self.0 } }
fn main() {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap()).unwrap();
    // Rust decapsulates a liboqs ciphertext with a liboqs-format secret key
    let dk = kem::DecapsulationKey::new(&kem::ML_KEM_768, &h(&v, "sk")).unwrap();
    let ss = dk.decapsulate(kem::Ciphertext::from(&h(&v, "ct")[..])).unwrap();
    assert_eq!(ss.as_ref(), &h(&v, "ss")[..]);
    // Rust encapsulates to a liboqs public key; print for liboqs to decap
    let ek = kem::EncapsulationKey::new(&kem::ML_KEM_768, &h(&v, "pk")).unwrap();
    let (ct, ss2) = ek.encapsulate().unwrap();
    // ML-DSA-44: verify liboqs sig, import liboqs expanded sk, sign
    let pk = signature::UnparsedPublicKey::new(&signature::ML_DSA_44, h(&v, "dpk"));
    pk.verify(b"msg", &h(&v, "dsk")[..0]).err();
    pk.verify(b"msg", &h(&v, "sig")).unwrap();
    let kp = signature::PqdsaKeyPair::from_raw_private_key(&signature::ML_DSA_44_SIGNING, &h(&v, "dsk")).unwrap();
    assert_eq!(kp.public_key().as_ref(), &h(&v, "dpk")[..]);
    let mut sig = vec![0u8; signature::ML_DSA_44_SIGNING.signature_len()];
    kp.sign(b"rust", &mut sig).unwrap();
    // X25519 import + Ed25519 seed + HKDF expand-only with raw PRK and 12-byte output
    let x = agreement::PrivateKey::from_private_key(&agreement::X25519, &[7u8; 32]).unwrap();
    let _ = x.compute_public_key().unwrap();
    let _ = signature::Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
    let mut out = [0u8; 12];
    hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &[1u8; 32]).expand(&[b"info"], Len(12)).unwrap().fill(&mut out).unwrap();
    let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("{{\"ct\":\"{}\",\"ss\":\"{}\",\"sig\":\"{}\",\"hkdf\":\"{}\"}}", hx(ct.as_ref()), hx(ss2.as_ref()), hx(&sig), hx(&out));
}
```

**Primitive costs** (`src/bin/bench.rs`, `cargo +1.85.1 run --release --offline --bin bench`):

```rust
use aws_lc_rs::{agreement, kem, rand::SystemRandom, signature::{self, KeyPair}};
use std::time::Instant;
fn t<F: FnMut()>(name: &str, mut f: F) -> f64 {
    for _ in 0..200 { f(); }
    let n = 3000; let s = Instant::now(); for _ in 0..n { f(); }
    let us = s.elapsed().as_secs_f64() * 1e6 / n as f64; println!("{name:>16}: {us:7.1} us"); us
}
fn main() {
    let rng = SystemRandom::new();
    let dk = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
    let ek = dk.encapsulation_key().unwrap();
    let (ct, _) = ek.encapsulate().unwrap(); let ctb = ct.as_ref().to_vec();
    let peer = agreement::PrivateKey::generate(&agreement::X25519).unwrap().compute_public_key().unwrap().as_ref().to_vec();
    let kg = t("mlkem keygen", || { kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap().encapsulation_key().unwrap(); });
    let en = t("mlkem encaps", || { ek.encapsulate().unwrap(); });
    let de = t("mlkem decaps", || { dk.decapsulate(kem::Ciphertext::from(&ctb[..])).unwrap(); });
    let xk = t("x25519 keygen+pub", || { agreement::PrivateKey::generate(&agreement::X25519).unwrap().compute_public_key().unwrap(); });
    let xd = t("x25519 dh", || { let k = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        agreement::agree(&k, agreement::UnparsedPublicKey::new(&agreement::X25519, &peer), (), |_| Ok(())).unwrap(); }) - xk;
    let ed = signature::Ed25519KeyPair::generate().unwrap();
    let es = t("ed25519 sign", || { ed.sign(b"m"); });
    let esig = ed.sign(b"m"); let epk = ed.public_key().as_ref().to_vec();
    let ev = t("ed25519 verify", || { signature::UnparsedPublicKey::new(&signature::ED25519, &epk).verify(b"m", esig.as_ref()).unwrap(); });
    let md = signature::PqdsaKeyPair::generate(&signature::ML_DSA_44_SIGNING).unwrap();
    let mut sig = vec![0u8; 2420];
    let ms = t("mldsa44 sign", || { md.sign(b"m", &mut sig).unwrap(); });
    let mpk = md.public_key().as_ref().to_vec();
    let mv = t("mldsa44 verify", || { signature::UnparsedPublicKey::new(&signature::ML_DSA_44, &mpk).verify(b"m", &sig).unwrap(); });
    let _ = rng;
    let base = 2.0 * (xk + xd);
    println!("v3-kem  both roles: {:.0} us", base + kg + 3.0 * en + 3.0 * de);
    println!("v2      both roles: {:.0} us", base + kg + 2.0 * en + 2.0 * de + es + ev);
    println!("v3-mldsa both roles: {:.0} us", base + kg + 2.0 * en + 2.0 * de + ms + mv);
}
```

### Decisions (2026-10-30)

The user approved every recommendation in §9:

1. **Server role:** option A, plus the slice (c) thread fix. Slice (c) goes first and stands alone, so the default Python path still gets the M8 drop if Phase 4 slips.
2. **M1 cold:** keeps the same definition, with `pqvpnd connect` spawned in place of the Python CLI. Both rows are reported, and the native row is labelled as a separate client binary.
3. **IPC daemon:** deferred to Phase 5. This is a scope cut, recorded in the migration plan.
4. **Gate suites:** the published suite per metric (M1 v2, M8 v2, M2 v3-kem). v3-mldsa is not ported, and the Rust backend refuses it.
5. **Slice (c) owner:** the harness session.
6. **Ticket format:** stays plaintext, mode 0600. Writers in both `pqvpnd` and Python create a temp file with `O_CREAT|O_EXCL|O_NOFOLLOW`, fsync it and rename it into place; readers open with `O_NOFOLLOW`. Sealing the file goes on the Phase 5 hardening list.
7. **New files:** `handshake.rs`, `schedule.rs` and `core/pqvpnd/` are approved.

Conditions:
- **M2:** if it lands over 0.2 ms, it is reported as missed. Transcript hashing, length validation and constant-time compares are never trimmed to make the number.
- **Authorization order:** no lease, CONFIG or data-plane session exists before Python authorization passes. A test covers a client that completes the handshake without authorization and must get nothing.

## Appendix B — Phase 4 handshake inventory

This is a read-only inventory of the Python handshake, key schedule, IPC and metrics that the Phase 4 Rust port (`core/handshake`, `core/crypto`, `pqvpnd`) must reproduce. It was taken on main at `c038f53` (2026-10-30). All line references are against that commit. Nothing here is a design decision.

Shorthand used below: `‖` means concatenation. `H()` is SHA-256. `HKDF()` is full RFC 5869 extract plus expand with SHA-256. `Expand()` is HKDF-Expand only. Integers are big-endian unless stated.

### 1. Key schedule, transcript, cookies, resumption, rekey

#### 1.1 Suites and wire constants

| Suite | Header version byte | Name constant | Client auth | Wired into runtime? |
| --- | --- | --- | --- | --- |
| v2-ed25519 | `0x20` (`kemtls.py:24`) | `PROTOCOL_NAME = b"PQVPN-KEMTLS-INSPIRED-v2"` (`:25`) | Ed25519 signature | yes, `protocol_version = 2`, the default (`config.py:22,39`) |
| v3-kem | `0x30` (`:822`) | `PROTOCOL_NAME_V3 = b"PQVPN-KEMTLS-v3"` (`:823`) | client static ML-KEM-768 (implicit) | yes, `protocol_version = 3` |
| v3-mldsa | `0x31` (`:1083`) | `PROTOCOL_NAME_V3_MLDSA = b"PQVPN-MLDSA-v3"` (`:1084`) | ML-DSA-44 signature | **no.** `config.py:113,151` allows only 2 or 3. It is used by tests and `eval/run_pqvpn.py` only. |

**Handshake header** (`kemtls.py:23,36,94-116`): the format is `!HBBH`, which is `MAGIC=0x4856 ‖ version u8 ‖ msg_type u8 ‖ payload_len u16`, 6 bytes in all.
- `payload_len` must satisfy 0 < len ≤ 8186, and the total must equal 6 + len exactly.
- Message types (`:41-50`): 1 CH, 2 SH, 3 CKE, 4 SF, 5 COOKIE_CHALLENGE, 6 COOKIE_RESPONSE, 7 RESUMPTION_HELLO, 8 RESUMPTION_ACCEPT, 0xFF error. 0xFF is never sent.

**TCP control framing** (`runtime.py:36,44-72`): each message goes on the wire as `!I` length plus the message, with a maximum of 16384 bytes. TCP_NODELAY is set at both ends (`:50`). The 4-byte length prefix is **not** part of any transcript.

**Record header** (`kemtls.py:395-400,533-534`): the format is `!2sBBBB8sIQ`, 26 bytes:
- `b"PV"`
- `version u8`
- `channel u8` (1 data, 2 control)
- `frame_type u8`
- `direction u8` (1 c2s, 2 s2c)
- `session_id[:8]`
- `epoch u32`
- `seq u64`

**Record encryption:**
- Cipher: AES-256-GCM, with the 26-byte header as AAD.
- Nonce: `nonce_base XOR (0x00000000 ‖ seq u64)` (`:518-521`).
- Sequences: control receive is strictly sequential (`:593`); data uses a 128-entry replay window (`:403-425`).
- Already in Rust for data: KATs `tests/vectors/frame_{encrypt,decrypt}.json`, made by `tests/test_rust_core.py:35`.

**Message layouts** (all fixed size, checked by `_fixed`):

| Message | v2 (`:134-210`) | v3-kem (`:828-905`) | v3-mldsa (`:1090-1168`) |
| --- | --- | --- | --- |
| CH payload | `client_random32 ‖ session_id32 ‖ x25519_pub32 ‖ mlkem_pub1184 ‖ ed25519_pub32` = 1312 | same, but the last field is `client_identity_hash32` = H(client ML-KEM pub) | same as v3, with H(client ML-DSA pub) |
| SH payload | `server_random32 ‖ session_id32 ‖ x25519_pub32 ‖ eph_ct1088 ‖ identity_id32` = 1216 | v2 layout plus `client_ct1088` = 2304 | same as v2 = 1216 |
| CKE payload | `identity_ct1088 ‖ ed25519_sig64 ‖ finished32` = 1184 | `server_ct1088 ‖ finished32` = 1120 | `server_ct1088 ‖ mldsa_sig2420 ‖ finished32` = 3540 |
| SF payload | `finished32` | same | same |

`identity_id` is H(server ML-KEM-768 identity public key). The fingerprint is `sha256(pub).hexdigest()` (`identity.py:27-28`). The server's 1184-byte identity public key is never sent: the client holds it out of band and pins it by fingerprint (`kemtls.py:691-695`).

#### 1.2 Transcript hash (exact byte order)

`TranscriptHasher` (`kemtls.py:292-312`) is a running SHA-256 over **whole handshake messages: the 6-byte header plus payload**. `digest()` hashes a copy of the running state, so the transcript continues afterwards.

For a full handshake (v2, v3 and mldsa use the same order):
1. CH wire (client `:712`, server `:781`). The server hashes the ClientHello as it comes out of the cookie gate. COOKIE_CHALLENGE, COOKIE_RESPONSE and the 32-byte cookie are **never** hashed.
2. SH wire (client `:724`, server `:788`).
3. Then `digest_sh = transcript.digest()`, which is both the key-schedule `transcript_hash` and the input to the client Finished MAC.
4. CKE wire (client `:738`, server `:812`).
5. The Server Finished MAC is over `transcript.digest()` after CKE (`:746,813`).
6. SF wire is appended last (`:750,815`); nothing reads it afterwards.

For resumption (`:1488,1493,1538,1547`), the transcript covers:
- the RESUMPTION_HELLO wire;
- then the RESUMPTION_ACCEPT **header with `payload_len = 1216`** followed by only the **first 1184 payload bytes** (`server_random ‖ session_id ‖ x25519_pub ‖ ct`), without the MAC.

So the hashed header claims a length of 1216, but only 1184 body bytes follow it. A Rust port must reproduce this exactly.

#### 1.3 Finished MACs and client proofs

- `finished(key, label, digest) = HMAC-SHA256(key, label ‖ digest)` (`kemtls.py:315-320`). The labels are `b"client finished"` and `b"server finished"` (`:323-324`), and `b"pqvpn resume finished"` for resumption (`:1468`).
- **Client Finished** = `finished(client_finished_key, "client finished", H(digest_sh ‖ partial))`, where `partial` is:
  - v2: `identity_ct ‖ ed25519_sig` (`:734-736`, server `:806-809`)
  - v3: `server_ct` (`:978-980`, server `:1064-1067`)
  - mldsa: `server_ct ‖ mldsa_sig` (`:1241-1244`, server `:1333-1337`)
- **Server Finished** = `finished(server_finished_key, "server finished", digest_after_CKE)` (`:813,1072,1342`).
- **Resume Finished** is server only: `finished(server_finished_key, "pqvpn resume finished", digest_after_accept_sans_mac)` (`:1503-1507,1555-1557`). There is no client Finished in resumption; the client is authenticated only by holding the ticket.
- **Signed message** for v2 (Ed25519) is `PROTOCOL_NAME ‖ b" client proof " ‖ digest_sh ‖ identity_ct` (`:732`, verified at `:801-803` through `identity.py:342`).
- **Signed message** for mldsa is `PROTOCOL_NAME_V3_MLDSA ‖ b" client proof " ‖ digest_sh ‖ server_ct` (`:1238,1328`).
- Server-side check order in v2: decapsulate, derive the schedule, verify the signature, then verify Finished (`:797-811`).

#### 1.4 Key schedule (all HKDF labels)

**`KeyManager.derive_key`** (`hybrid_crypto.py:423-440`) is full HKDF-SHA256 (extract plus expand) with 32 bytes of output.

**`_expand(prk, label, context, n)`** (`kemtls.py:327-329`) is `Expand(prk, info = PROTOCOL_NAME ‖ "|" ‖ label ‖ "|" ‖ context, n)`.

> **Quirk:** `PROTOCOL_NAME` here is always the **v2** name `PQVPN-KEMTLS-INSPIRED-v2`, for every suite, for resumption and for rekey. Only `context` carries the suite.

**Traffic secrets.** `_derive_secrets(seed, context)` (`:380-383`) produces 12 secrets, in this order (`:332-345`):

| Field | Label | Bytes |
| --- | --- | --- |
| client_finished_key | `client finished` | 32 |
| server_finished_key | `server finished` | 32 |
| data_c2s_key | `data c2s key` | 32 |
| data_s2c_key | `data s2c key` | 32 |
| data_c2s_nonce_base | `data c2s nonce` | 12 |
| data_s2c_nonce_base | `data s2c nonce` | 12 |
| control_c2s_key | `control c2s key` | 32 |
| control_s2c_key | `control s2c key` | 32 |
| control_c2s_nonce_base | `control c2s nonce` | 12 |
| control_s2c_nonce_base | `control s2c nonce` | 12 |
| rekey_secret | `rekey` | 32 |
| control_confirm_key | `control confirm` | 32 |

**Per-suite master derivation.** Let `cr`, `sr` and `sid` be client_random, server_random and session_id, and `th` the transcript hash `digest_sh`.

| Suite | Context (passed to `_derive_secrets`) | Salt | Master |
| --- | --- | --- | --- |
| v2 (`:386-392`) | `PROTOCOL_NAME ‖ 0x20 ‖ "\|X25519\|ML-KEM-768\|AES-256-GCM\|" ‖ sid ‖ cr ‖ sr ‖ th` | `H("pqvpn extract" ‖ cr ‖ sr ‖ sid)` | `HKDF(ikm = x25519_ss ‖ eph_kem_ss ‖ identity_kem_ss, salt, info "pqvpn master secret")` (ikm order from `:730,798`) |
| v3-kem (`:908-920`) | `PROTOCOL_NAME_V3 ‖ 0x30 ‖ same suite string ‖ sid ‖ cr ‖ sr ‖ th` | same | `hs = HKDF(x25519_ss ‖ k_eph, salt, "pqvpn v3 handshake secret")`; `auth_salt = H(hs ‖ th)`; `master = HKDF(hs ‖ k_s ‖ k_c, auth_salt, "pqvpn v3 authenticated master")`. Here `k_s` is the client→server-identity encaps and `k_c` the server→client-static encaps (`:975,1061`). |
| v3-mldsa (`:1171-1178`) | `PROTOCOL_NAME_V3_MLDSA ‖ 0x31 ‖ "\|X25519\|ML-KEM-768\|ML-DSA-44\|AES-256-GCM\|" ‖ sid ‖ cr ‖ sr ‖ th` | same | `HKDF(x25519_ss ‖ k_eph ‖ k_s, salt, "pqvpn mldsa master secret")` |
| resume (`:1402-1412`) | `b"PQVPN-RESUME" ‖ 0x30 ‖ "\|X25519\|ML-KEM-768\|AES-256-GCM\|" ‖ sid ‖ cr ‖ sr ‖ th_resume` | `H("pqvpn resume" ‖ cr ‖ sr ‖ sid)` | `HKDF(resumption_secret ‖ x25519_ss ‖ kem_ss, salt, "pqvpn resume master secret")` |

> **Quirk:** the resume context hard-codes `0x30` (`PROTOCOL_VERSION_V3`), **including for v2 resumptions**, whose header byte is `0x20` (`:1406`).

In resumption, `sid` is a **fresh** server-chosen session_id (`:1540`), not the original one.

#### 1.5 Rekey and rehandshake (control channel)

**Rekey**, which renews the symmetric keys:
- The client sends `REKEY_REQUEST` with payload `epoch u32 ‖ nonce32`, where `epoch = current + 1` and the nonce comes from `os.urandom(32)` (`runtime.py:1096-1101`).
- **Derivation** (`kemtls.py:627-635`):
  - `ctx = session_id ‖ epoch u32 ‖ nonce`
  - `seed = _expand(rekey_secret, "epoch", ctx, 32)`
  - then `_derive_secrets(seed, ctx)`
- **Confirmation:** the server replies with `REKEY_RESPONSE` = `payload[:4] ‖ HMAC(old control_confirm_key, "rekey response" ‖ payload)` (`runtime.py:583-585`; client check at `:1108-1111`). It is keyed with the **old** epoch's key and sent under the old epoch. The server then activates.
- The server checks authorization before deriving (`:577`), and the payload must be exactly 36 bytes (`:579`).

**Rehandshake**, which gives post-compromise security (PCS):
- **Request:** `REHANDSHAKE_REQUEST` = `epoch u32 ‖ x25519_pub32 ‖ mlkem_pub1184` (`runtime.py:1140-1147`). The server checks the length (1220 bytes) and authorization (`:590-595`).
- **Response:** `REHANDSHAKE_RESPONSE` = `epoch u32 ‖ server_x25519_pub32 ‖ ct1088 ‖ confirm32` (`:603-609`; client parses at `:1156-1172`); server keys and encapsulation at `:599-602`.
- **Derivation** (`kemtls.py:637-654`):
  - `transcript = request ‖ response_body`, where `response_body` is the response without the confirm.
  - `ctx = session_id ‖ epoch u32 ‖ H(transcript)`
  - `seed = H(rekey_secret ‖ dh_ss ‖ kem_ss ‖ epoch u32)`, which is **plain SHA-256, not HKDF**
  - then `_derive_secrets(seed, ctx)`
- **Confirmation:** `confirm = HMAC(**new** control_confirm_key, "rehandshake confirm" ‖ transcript)` (`runtime.py:606,1169`).
- The server builds its own `HybridKEM("ML-KEM-768")` without the mock flag (`:596`).

**Activation** (`kemtls.py:656-670`) sets `epoch += 1` exactly, resets all sequences and the replay window, and wipes the old secrets. With the Rust data plane, Python hands over the four data secrets and then zeroes them (`:505-516`).

#### 1.6 Cookies, and what happened to the `bid - 1` window

**Current scheme** (`kemtls.py:213-248`), the WireGuard pattern:
- There are two 32-byte secrets, current and previous, both from `os.urandom`.
- Rotation is lazy: every `generate` or `verify` checks whether `time.monotonic() - rotated_at >= 120`.
- `cookie = HMAC-SHA256(secret, client_ip.encode() ‖ port u16)`, where `client_ip` is the ASCII dotted string from `accept()`. The listener is IPv4-only (`runtime.py:399`, `socket.socket()` defaults to `AF_INET`).
- `verify` accepts a MAC under the current **or** the previous secret, so a cookie lives between 120 and 240 s.

**Cookie wire format:**
- `COOKIE_CHALLENGE` = header (type 5, len 32) ‖ cookie (`:251-268`).
- `COOKIE_RESPONSE` = header (type 6) ‖ cookie ‖ **the full CH wire, including its own header** (`:271-289`).

**Server gate** (`runtime.py:433-439,550-574`):
- `cookie_mode` is `off` (the default), `under_load` (when pending handshakes ≥ `cookie_threshold`, default 10) or `always`.
- A COOKIE_RESPONSE as the first message is accepted directly; otherwise the server challenges once.
- The client side is at `runtime.py:874-884`.

**`bid - 1` no longer exists on main.** It was removed in `30e60fc` (2026-10-03, "remove bucket_id from cookie MAC").
- The old scheme MACed `ip ‖ !HQ(port, bucket_id)` with `bucket_id = int(monotonic()) // 120`.
- It verified the previous secret against `bid` and `bid - 1`.
- It crashed with `struct.error` in the first 120 s after boot, because `bid - 1 = -1` cannot be packed as u64, and its buckets drifted out of step with secret rotation.

The successor regression tests are listed in §5. The risk row at `docs/rust-core-migration-plan.md:292` ("cookie `bid - 1`") is stale and should say "cookie current/previous-secret window and boot-time verify".

#### 1.7 Resumption ticket

**Issue** (`kemtls.py:1360-1399`, `runtime.py:491-496`):
- The server key is `AESGCM(os.urandom(32))`, held in memory only. A restart invalidates every ticket.
- The ticket is rotated whenever any client drops out of the enabled set (`runtime.py:624-626`).
- **Plaintext:** `resumption_secret32 ‖ !BqHH(protocol_version, expiry, len(cid), len(aip)) ‖ client_id utf8 ‖ assigned_ip utf8`. The expiry is a **signed i64** in wall-clock `time.time()` seconds, and the header is 13 bytes.
- **Ticket on the wire:** `nonce12 (os.urandom) ‖ AES-GCM(ct ‖ tag)`, with AAD `b"PQVPN-RESUME"`.
- `resumption_secret` is the epoch-0 `rekey_secret` of the session that issued the ticket (`runtime.py:494`).
- The ticket is sent as a `RESUMPTION_TICKET` control frame right after CONFIG.

**Lifetime:**
- `resumption_ticket_lifetime` defaults to 86400 s (`config.py:25`) and may be 0 to 604800 (`:117`); 0 disables resumption.
- Validate rejects a ticket when `now > expiry` (`kemtls.py:1395`).
- The version in the ticket must equal the server's version (`:1535`).
- Tickets are **not single-use**, and resumption **skips the cookie gate** (`runtime.py:449-453`, a ponytail note).
- Authorization is re-checked after validation (`:462-465`).

**Hello and accept:**
- `RESUMPTION_HELLO` payload = `client_random32 ‖ ticket_len u16 ‖ ticket ‖ x25519_pub32 ‖ mlkem_pub1184` (`:1415-1443`).
- `RESUMPTION_ACCEPT` payload = `server_random32 ‖ new_session_id32 ‖ x25519_pub32 ‖ ct1088 ‖ finished32` = 1216 (`:1446-1465`).
- The server detects resumption from `msg_type == 7` in the first message's header (`runtime.py:455-456`).

**Client storage** (`runtime.py:801-825`):
- The client keeps `<dir of client key>/.pqvpn_ticket.json`, mode 0600 and opened with `O_NOFOLLOW`.
- It holds `{fp, t: b64 ticket, s: b64 rekey_secret, v: protocol_version}`, so the resumption secret is stored in plaintext on disk.
- If resumption fails, the client reconnects over TCP and falls back to the full handshake (`:858-862`).

#### 1.8 Randomness and clock sources (all must be injectable for KATs)

| Source | Where | Primitive |
| --- | --- | --- |
| client_random, session_id | `kemtls.py:709` (v2), `:950` (v3), `:1211` (mldsa) | `os.urandom(32)` ×2 |
| client ephemeral X25519 and ML-KEM keypair | `:708,949,1210` via `HybridKEM.generate_keypairs` (`hybrid_crypto.py:574-584`) | `X25519PrivateKey.generate()`; liboqs `generate_keypair` |
| server_random | `:783,1042,1307` | `os.urandom(32)` |
| server ephemeral X25519 | `:782,1041,1306` | `X25519PrivateKey.generate()` |
| ML-KEM encaps, server→client ephemeral | v2 `:785`, v3 `:1044`, mldsa `:1309` | liboqs `encap_secret` |
| ML-KEM encaps, server→client static (`k_c`) | v3 `:1045` | liboqs `encap_secret` |
| ML-KEM encaps, client→server identity | v2 `:728`, v3 `:971`, mldsa `:1231` | liboqs `encap_secret` |
| ML-DSA-44 signing | mldsa `:1239` | liboqs `Signature.sign`, which is hedged/randomized by default |
| Ed25519 signing | v2 `:733` | deterministic, needs no injection |
| resumption client_random and keypairs | `:1484-1485` | `os.urandom(32)`, `generate_keypairs` |
| resumption server_random, **new session_id**, X25519, encaps | `:1539-1543` | `os.urandom(32)` ×2, `generate()`, `encap_secret` |
| ticket key, ticket nonce | `:1365,1377` | `os.urandom(32)`, `os.urandom(12)` |
| cookie secrets | `:222-223,230` | `os.urandom(32)` |
| rekey nonce | `runtime.py:1096` | `os.urandom(32)` |
| rehandshake keypairs and encaps | client `runtime.py:1141-1142`, server `:599-602` | `generate()`, `generate_keypair`, `encap_secret` |
| mock PQC (tests only) | `hybrid_crypto.py:195,208,343` | `os.urandom(32)` |
| clocks | cookie rotation `time.monotonic` (`kemtls.py:224,227`); ticket expiry `time.time` (`:1370,1395`); session `established_at` `time.time` (`:461`) | n/a |

**Feasibility for Task 2 vectors:**
- The loaded liboqs exports `OQS_KEM_ml_kem_768_keypair_derand` and `OQS_KEM_ml_kem_768_encaps_derand`, plus generic `OQS_KEM_{keypair,encaps}_derand`.
- liboqs-python 0.16.0 wraps only `generate_keypair_seed` (`length_keypair_seed = 64`), so deterministic **encapsulation** on the Python side needs a ctypes shim. A custom `OQS_randombytes` callback would also work.
- X25519 can be injected with `X25519PrivateKey.from_private_bytes`. The `os.urandom` call sites need a seam or a monkeypatch.

### 2. Crypto libraries per primitive

**Libraries in use:**
- `cryptography==50.0.1` and `liboqs-python==0.16.0` (`constraints-tested.txt`).
- The venv loads **`/usr/local/lib/liboqs.so.0.16.0`**, checked through `/proc/self/maps`.
- That build exports BIKE and Classic McEliece symbols (1937 exported functions), so it is **not** the `OQS_MINIMAL_BUILD=KEM_ml_kem_768` build that `constraints-tested.txt` records.
- A second copy, `/usr/lib/liboqs.so.9`, also exists.
- liboqs is located through `_require_installed_liboqs` (`hybrid_crypto.py:98-108`): first `find_library`, then `$OQS_INSTALL_PATH`.
- An ML-KEM-768 keygen/encaps/decaps self-test runs at import, skipped when `_PQVPN_SELFTEST_PASSED=1` (`:111-150`).
- `ALLOW_MOCK_PQC=1` switches to a SHA-based mock (`:35,175-244`).

| Primitive | Backing | Used by |
| --- | --- | --- |
| X25519 | `cryptography` (`hybrid_crypto.py:38-80`) | all suites, resume, rehandshake |
| ML-KEM-768 keygen/encaps/decaps | liboqs through liboqs-python; a new `KeyEncapsulation` object per call (`:277-303`) | all suites, resume, rehandshake, server and client identities |
| Ed25519 sign/verify | `cryptography` (`kemtls.py:16,733`, `identity.py:20,183-187,342-343`) | v2 client identity |
| ML-DSA-44 sign/verify | liboqs through liboqs-python (`hybrid_crypto.py:364-392`) | v3-mldsa only (not wired) |
| HKDF (extract plus expand) | `cryptography` `HKDF` (`hybrid_crypto.py:25,434-440`) | masters for all suites |
| HKDF-Expand | `cryptography` `HKDFExpand` (`kemtls.py:18,329`) | `_derive_secrets`, rekey seed |
| SHA-256, HMAC-SHA256 | Python `hashlib`, `hmac` | transcript, salts, Finished, cookies, confirmations, rehandshake seed |
| AES-256-GCM (control, tickets) | `cryptography` `AESGCM` (`kemtls.py:17,499,1365`) | control channel, resumption tickets |
| AES-256-GCM (data) | Python `AESGCM`, or Rust `pqvpn_core.DataSession` when `data_plane = "rust"` (`:447-450,501-516`) | data channel |

**Per suite:**
- **v2-ed25519:** X25519, ML-KEM-768 ×2 (ephemeral, server identity), Ed25519, HKDF, HMAC.
- **v3-kem:** X25519, ML-KEM-768 ×3 (ephemeral, server identity, client static), two-stage HKDF, HMAC. No signature.
- **v3-mldsa:** X25519, ML-KEM-768 ×2, ML-DSA-44, HKDF, HMAC.

### 3. GUI ↔ client-service IPC contract (what `pqvpnd` must speak)

**Endpoint** (`app/client.py:27-31,47-51`):
- The socket is `$PQVPN_RUNTIME_DIR/client.sock`, defaulting to `/run/pqvpn/client.sock`.
- If that directory is missing, the fallback is `/tmp/pqvpn-client.sock`.
- `/run/pqvpn` is created by `RuntimeDirectory=pqvpn` in `packaging/common/pqvpn-client.service`.
- The unit runs `ExecStart=/usr/bin/python3 -s -m app.client --service` as root, with `AmbientCapabilities=CAP_NET_ADMIN`, `ProtectSystem=strict`, `StateDirectory=pqvpn` (mode 0700) and `UMask=0077`.
- The socket type is `AF_UNIX`, `SOCK_STREAM`, bound and then `chmod 0666` (`:478-482`), with `listen(4)` and a 1 s accept timeout and one thread per connection (`:484-512`).
- A stale socket is probed and unlinked (`:464-475`).

**Authentication**, in both directions:
- **Server side:** `SO_PEERCRED` uid must be 0 or in `PQVPN_ALLOWED_UIDS`, a comma-separated list of digits. Anything malformed gives an empty set, which means root only (`:148-167,455-458`). Packaging adds a drop-in for this (`packaging/arch/pqvpn.install:3-6`).
- An unauthorized peer gets `{"error": "unauthorized"}`, and the connection is closed without reading the request (`:540-546`).
- **Client side:** `IPCClient` **refuses any service whose peer uid is not 0** (`:781-783`), so `pqvpnd` must run as root.

**Framing:**
- `!I` length, then UTF-8 JSON, with 0 < len ≤ `MAX_IPC_MESSAGE = 16384` (`:23,117-145`).
- **One request and one response per connection.**
- The receive timeout is 10 s by default (`:125`). The GUI and `IPCClient` use that default, and **CONNECT is synchronous**, so a connect slower than 10 s shows up as an error in the GUI.
- The M1 warm harness uses 60 s.

**Requests and dispatch** (`:412-453`):
- A request is `{"command": str, ...}`, matched case-insensitively (`.upper()`).
- `_require_fields` rejects unknown keys and a missing or empty command (`:271-280`).
- Errors come back as `{"error": sanitized_str}` (`:548-552`, `sanitize_error` `:35-44`).

| Command | Extra fields | Success response | Notes |
| --- | --- | --- | --- |
| `STATUS` | none | `{"status": ClientStatus}` | `_get_status` `:563-678` |
| `CONNECT` | none | `{"status": "connected", "info": <server CONFIG dict>}` | `:694-748`. Uses a non-blocking lock, otherwise `{"error": "operation in progress"}`; also `"already connected"`. Errors are rewritten in managed mode (`:734-741`). |
| `DISCONNECT` | none | `{"status": "disconnected"}` | `:750-771`; `"not connected"` |
| `LOGS` | none | `{"logs": [{timestamp, level, message}]}` | ring buffer of 300 (`:195,256-268`) |
| `SETUP_STATUS` | none | `{"setup": {...}}` | `:291-322`; the keys differ between managed and `--config` mode |
| `ENSURE_IDENTITY` | none | `{"identity": setup}` | managed only (`:333-347`) |
| `LIST_PROFILES` | none | `{"profiles": [...], "active_profile_id"}` | managed only |
| `IMPORT_PROFILE` | `profile` (str, required), `replace` (bool) | `{"profile": {...}}` | `:349-366` |
| `SELECT_PROFILE` | `profile_id` (str) | `{"selected_profile_id"}` | `:368-383` |
| `DELETE_PROFILE` | `profile_id` (str) | `{"removed_profile_id"}` | `:385-399` |
| `EXPORT_ENROLLMENT_REQUEST` | `client_id` (str) | `{"enrollment": {...}, "content": json_str}` | `:401-410` |

**`ClientStatus` schema is strict** (`:63-114`). `IPCClient.status()` builds it with `ClientStatus(**resp["status"])` (`:804-811`). An **extra or renamed key raises `TypeError`** in the GUI; a missing key falls back to its default.

The fields are:
- `state`, `error`, `uptime_seconds`
- `client_vpn_ip`, `server_host`, `server_vpn_ip`
- `tun_name`, `tun_mode`
- `epoch`, `pqc_mode`, `is_quantum_safe`, `rekey_countdown`
- `rtt_ms`, `jitter_ms`, `loss_rate`
- `ipv6_guard_active`, `dns_managed`, `kill_switch_active`, `mtu`
- `config_path`, `server_control_port`, `connected_endpoint`, `expected_vpn_subnet`, `server_fingerprint`
- `full_tunnel`, `split_tunnel`, `ipv6_policy`, `dns_mode`, `dns_servers`
- `configured_tun_name`, `rekey_interval`
- `managed_mode`, `setup_complete`, `identity_ready`, `identity_fingerprint`
- `active_profile_id`, `active_profile_name`, `connected_profile_id`, `connected_profile_name`
- `profile_store_path`, `identity_path`, `profiles`

`state` takes the `ConnectionState` values (`:54-60`): DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, FAILED, SETUP_REQUIRED. The schema is pinned by `test_client_status_serialization_and_real_schema` (`tests/test_runtime.py:296`).

**Consumers:**
- The GUI uses `IPCClient` from `app/ui/window.py:101`, through `_IPCWorker` (`app/client.py:1774-1872`), with commands lowercased into method calls.
- The M1 warm harness (`eval/run_pqvpn_net.sh:244-250`) opens the socket directly through `ipc_send`/`ipc_recv`.
- **Modes:** with no `--config` the service runs in managed mode, with a profile store and identity under `/var/lib/pqvpn`. `--config PATH` is the legacy mode, where the onboarding commands raise (`:324-326,1971-1997`).

### 4. What M1 cold, M2 and M8 measure today

#### M1, connect time: `eval/run_pqvpn_net.sh <profile> [--data-plane python|rust]`

The run needs root.

**Topology and suite:**
- netns, veth and netem.
- The server is a long-lived `python -m vpn.cli server` (`:170-175`).
- **The suite is v2-ed25519.** The configs set no `protocol_version` (`:136-164`) and `client-key generate` runs without `--kem` (`:129`).
- `cookie_mode` is off (the default), resumption is on (the server default), and `full_tunnel = false`.

**Cold** (`:208-230`):
- **Clock:** bash `date +%s%N` wall clock, taken *before* `ip link del pqbench0` and `rm -f .pqvpn_ticket.json`, so every run is a full handshake. Then a **new `python -m vpn.cli client connect` process** is spawned.
- **Stop:** the first successful `ping -c1 -W1 10.8.0.1` from the client netns, polled every 10 ms with one fork per poll (`:198-206`). Before Phase 1 the poll was every 50 ms.
- **What is included:**
  - interpreter start and imports
  - the liboqs load and the import-time ML-KEM self-test, which runs in a fresh process
  - TCP connect, the full handshake, CONFIG and receipt of the ticket
  - TUN open, then `ip addr` and `ip link` forks (`runtime.py:150-168`), then `ClientNetwork.apply` routes (`:200`)
  - the `UDP_BIND` round trip, and the first ping round trip
- 30 runs; the median and 95% CI are reported.

**Warm** (`:232-280`):
- `app.client --service` runs in a private mount namespace.
- The clock is `time.time_ns()`, printed just before `ipc_send(CONNECT)`, so it excludes Python startup. The stop condition is the same ping.
- There is one untimed warm-up CONNECT, and the ticket is still deleted each run.

**Cold numbers so far (LAN, v2):**

| Phase | Commit / date | Data plane | Cold (ms) | Warm (ms) |
| --- | --- | --- | --- | --- |
| Published | 2026-10-10 | Python | 163 | n/a |
| Phase 0 | b726b42 | Python | 163 | n/a |
| Phase 1 | 2026-10-29 | Python | 164 | 52 |
| Phase 2 | 17d4667 | Rust | 131 | 9.0 |
| Phase 3 | 2026-10-29 | Rust | 126 | 15 |

- The Phase 0 caveat (`eval/results-summary/phase0-2026-10-28/README.md`): metro and other non-LAN cold rows were really resumed connects, because the ticket was not deleted. This was fixed in Phase 1. LAN is unaffected.
- **The cold definition for Phases 0-3:** a new client process, no ticket, full v2 handshake, from spawn to the first tunnel ping.
- The ≤30 ms gate under this definition needs a **native one-shot client** (no Python interpreter or imports). `pqvpnd` alone would improve the warm row, not cold. Cold minus warm is about 110 ms, which is process start alone.

#### M2, handshake CPU: `eval/run_pqvpn.py` `run_handshake` (`:105-147`), `evaluate_suite` (`:203-277`)

**What it measures:**
- Both roles run **in one process, with no network**, calling each other's methods directly.
- The clock is `time.process_time()` (whole-process CPU) around each step:
  - client CPU = initiate + process_server_hello + process_server_finished
  - server CPU = process_client_hello + process_client_key_exchange
- `latency_ms` is the `perf_counter` wall time of the whole exchange.
- Identities and endpoint construction (`HybridKEM`, `TranscriptHasher`) fall **outside** the timed region.
- Included: ephemeral keygen, every encaps/decaps (each builds a new liboqs object), HKDF, signatures and record-session construction.
- 5 warm-ups, then n = 50 runs.
- Data plane `python`, no cookie, no transcript of the TCP framing.

**Baseline:**
- The published "0.39 ms" is the **v3-kem total** (Table B: 0.204 + 0.184).
- Phase 0: v3-kem 0.207 + 0.187; v2 0.221 + 0.255 = 0.48; mldsa 0.24 + 0.20.
- The gate (≤ 0.2 ms) needs **both roles** in Rust to be meaningful under this definition.

#### M8, memory per session: `eval/measure_memory.py`

**What it measures:**
- The **server** process's `VmRSS` from `/proc/<pid>/status`, read twice:
  - a baseline right after a 2 s settle (`:160-175,235`)
  - again 2 s after N clients ping through (`:253`)
- Per-session = (loaded − baseline) / connected, for N ∈ {1, 10, 50}. The headline is **N = 50**.

**Setup:**
- Python data plane, v2 (no `protocol_version`, no `--kem`), `cookie_mode = "off"`, server defaults otherwise, resumption on (`:100-151`).
- Each client is its own `vpn.cli client connect` process in its own netns.

**What it includes:** one server `_client` thread per session (stack plus objects), `ServerSession`, `HandshakeSession`, the AESGCM objects, the IP pool and the ticket-key state.

**Results:**
- 186 kB published (`EVALUATION.md` Table G); 170.3 kB at Phase 0 (`phase0-2026-10-28/m8-memory.csv`).
- Not to be confused with `eval/run_pqvpn.py:181` `measure_memory_per_session`: that is an in-process psutil RSS delta over 100 session pairs, both roles, a different metric.

### 5. Regression tests the port must keep

**Cookie** (the successors of `bid - 1`), in `tests/test_crypto_protocol.py`:
- `test_cookie_protector_round_trip` (995)
- `test_cookie_wrong_ip_rejected` (1002)
- `test_cookie_wrong_port_rejected` (1008)
- `test_cookie_bad_length_rejected` (1014)
- `test_cookie_challenge_pack_unpack` (1020)
- `test_cookie_challenge_v3_version` (1026)
- `test_cookie_response_pack_unpack` (1033)
- `test_cookie_response_invalid_too_short` (1043)
- `test_cookie_protector_rotation` (1049)
- `test_cookie_accepted_just_before_and_after_rotation` (1059)
- `test_cookie_rejected_after_two_rotations` (1068)
- `test_cookie_no_crash_at_boot_time` (1078, the `bid - 1` regression)

Runtime, in `tests/test_runtime.py`:
- `test_cookie_always_mode_handshake_completes` (809)
- `test_cookie_off_mode_no_challenge` (839)

**Rate limiter and admission:**
- `SourceRateLimiter` (`runtime.py:337-360`) allows 10 per source IP per 60 s, using a sliding deque.
- It caps distinct sources at 65536, rejecting new ones beyond that, and prunes once per window.
- It is applied at `accept()` before a thread is spawned (`:418-426`), alongside the `max_clients` semaphore and `CONTROL_LISTEN_BACKLOG = 64` (`:40`).
- Tests in `tests/test_runtime.py`: `test_rate_limiter_prunes_sources` (197), `test_rate_limiter_caps_unique_sources` (321), `test_source_rate_limiter_window` (369).

**Revocation:**
- Every 30 s (`runtime.py:635-640`), `_check_revocations` (`:620-633`) closes the control socket of any revoked session and rotates the ticket key if any client was removed.
- Authorization is also checked at resume (`:464`), rekey (`:577`) and rehandshake (`:590`).
- Tests:
  - `tests/test_runtime.py`: `test_revoked_client_session_terminated` (1082), `test_revocation_rotates_ticket_key` (1107), `test_rekey_rejects_revoked_client` (1128), `test_signed_out_client_cannot_resume_before_revocation_sweep` (1038)
  - `tests/test_networking.py`: `test_revoked_client_cannot_start_new_handshake` (261)
  - `tests/test_crypto_protocol.py`: `test_signed_out_client_fails_handshake_authorization` (432)
  - `tests/test_accounts.py`: `test_admin_revoke_disables_tunnel_authorization` (513)

**Resumption:**
- `tests/test_crypto_protocol.py`: `test_resumption_1rtt_roundtrip` (1252), `test_resumption_expired_ticket_rejected` (1294), `test_resumption_tampered_ticket_rejected` (1301), `test_resumption_wrong_key_rejected` (1310)
- `tests/test_runtime.py`: `test_resumption_ticket_file_permissions` (917), `test_v3_resumption_resumes_end_to_end_not_fallback` (933)
- `tests/test_rust_core.py`: `test_mixed_data_planes_interoperate_across_rekey` (264, parametrized `resumed`)

**Rekey:**
- `tests/test_crypto_protocol.py`: `test_synchronized_rekey_and_old_epoch_rejection` (465)
- `tests/test_runtime.py`:
  - `test_delayed_rekey_keeps_data_forwarding` (116)
  - `test_automatic_rekey_short_interval` (372)
  - `test_overlapping_rekey_rejected` (376)
  - `test_client_rekey_protocol_uses_control_domain` (382)
  - `test_rust_rekey_and_remove_under_load` (704)
  - `test_manual_and_automatic_rekey_during_authenticated_traffic` (797)
  - `test_mixed_data_planes_interoperate_end_to_end` (452)

**Rehandshake:**
- `tests/test_crypto_protocol.py`:
  - `test_rehandshake_epoch_derives_new_keys` (749)
  - `test_rehandshake_old_epoch_rejected` (771)
  - `test_rehandshake_wrong_epoch_rejected` (792)
  - `test_rehandshake_bad_secret_length_rejected` (799)
  - `test_rehandshake_multiple_epochs` (808)
  - `test_rehandshake_pcs_recovery` (829)
  - `test_rehandshake_after_rekey` (853)
  - `test_rehandshake_empty_transcript_rejected` (878)
  - `test_rehandshake_wrong_rekey_secret_yields_different_keys` (885)
  - `test_rehandshake_tampered_dh_public_key_yields_different_keys` (909)
  - `test_rehandshake_transcript_mismatch_yields_different_keys` (932)
  - `test_rehandshake_key_confirmation_rejects_flipped_byte` (954)
- `tests/test_runtime.py`: `test_rehandshake_succeeds_and_advances_epoch` (868), `test_rehandshake_tampered_confirmation_fails_client` (879), `test_rehandshake_after_rekey` (905)

**Handshake correctness and wire format**, in `tests/test_crypto_protocol.py`:
- v2:
  - `test_authenticated_handshake_and_directional_keys` (417)
  - `test_wrong_server_fingerprint_rejected` (422)
  - `test_mitm_identity_substitution_rejected` (425)
  - `test_unauthorized_client_rejected` (429)
  - `test_transcript_tampering_rejected` (439)
  - `test_trailing_and_header_mismatch_rejected` (446)
  - `test_exact_reduced_handshake_sizes` (478)
  - `test_message_fixed_sizes` (499)
  - **`test_frozen_v2_handshake_serialization` (503).** This pins the header hex and the SHA-256 of all four v2 messages built from fixed fields. It is a partial wire KAT, covering serialization only and no secrets; Task 2 should extend it.
  - `test_transcript_hash_copy_and_count` (522)
  - `test_finished_mac_labels_and_tampering` (525)
  - `test_handshake_state_transitions` (534)
  - `test_invalid_x25519_points_raise_handshake_error` (1316)
- v3-kem: `test_v3_*` (666-736)
- mldsa: `test_mldsa_*` (1115-1212), including `test_mldsa_key_schedule_differs_from_v3_kem`
- `test_native_mlkem_self_test` (1225)

**IPC** (keep these green against `pqvpnd`):
- `tests/test_client_app.py`: `TestIPCFraming` (39), `TestMalformedIPC` (245), `TestPeerAuthorization` (282) including `test_desktop_user_runs_commands_over_real_socket` (309), `TestIPCClient` (328)
- `tests/test_onboarding.py`: `test_managed_service_setup_and_narrow_ipc` (303), `test_maximum_profile_status_fits_unchanged_ipc_limit` (337), `test_ipc_rejects_unknown_fields_and_generic_file_writes` (390), `test_public_enrollment_roundtrip_over_real_ipc_frame` (398)

**Existing KATs:** `tests/test_rust_core.py:59-180` (record layer only). There is no handshake or key-schedule KAT yet; that gap is Task 2.

### 6. Points for the design review

1. **M8 measures the server process, but `pqvpnd` is the client daemon.** Reaching 64 kB per session needs the server's per-session handling (one Python thread per client plus its objects) moved or restructured, or the gate redefined.
2. **M2 is both roles in one process.** Porting only the client cannot pass 0.2 ms.
3. **M1 and M8 have only ever been measured on v2-ed25519,** while M2's baseline is v3-kem. Pick one suite for the Phase 4 gates.
4. **M1 cold ≤ 30 ms needs a native one-shot client.** About 110 ms of today's cold time is Python process start, and the `ip` forks are still present (the pyroute2 quick win has not landed).
5. **Byte-level quirks to reproduce exactly, not "fix" during the port:**
   - the v2 name in every HKDF `info`
   - the `0x30` byte in the resume context
   - the resume transcript header that claims 1216 bytes over 1184 hashed
   - the plain-SHA-256 rehandshake seed
   - rekey confirmed under the old key, rehandshake confirmed under the new key
6. **liboqs on this host is `/usr/local/lib/liboqs.so.0.16.0`, a full build,** not the minimal build in `constraints-tested.txt`. Decide which liboqs the Rust core links, or use a pure-Rust ML-KEM, before generating vectors.
7. **v3-mldsa is not reachable from config.** Decide whether Phase 4 ports it.
