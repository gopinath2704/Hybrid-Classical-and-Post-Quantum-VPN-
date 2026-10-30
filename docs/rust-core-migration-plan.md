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
5. **Phase 4, Rust handshake and native daemon (3 to 4 weeks).** Port KEMTLS, cookies, resumption, rekey and the key schedule; ship `pqvpnd` speaking the existing IPC so the GUI is untouched (scope cut 2026-10-30: Phase 4 ships `pqvpnd connect`, a native one-shot client; the IPC daemon moves to Phase 5, see `docs/phase4-design.md`). Gate: Python and Rust produce identical transcripts and secrets on shared test vectors, M1 LAN cold 30 ms or less, M2 0.2 ms or less, M8 64 kB per session or less.
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
- [x] Cross-implementation interop: Python client to Rust server and the reverse, for v2, v3-kem and v3-mldsa, including rekey and resumption.
- [ ] Known-answer vectors exported from the Python code for HKDF output, frame encryption and transcripts, checked in Rust unit tests.
- [ ] Differential fuzzing with `cargo-fuzz` on frame decryption, the replay window and handshake parsing, comparing Rust against Python where both exist.
  cargo-fuzz smoke 2026-10-29: dispatch 1.63M runs, open 6.70M runs, 60 s each, no crashes; cargo deny + cargo audit clean.
- [x] Property tests (`proptest`) for the replay window and sequence handling at the 64-bit edge.
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
| Rewritten code drops a past fix (cookie boot-time window, rate limiter, revocation kill) | Medium | Medium | Port the regression tests first, then the code. The old cookie `bid - 1` window was replaced by a current-plus-previous secret in 30e60fc; its regression test is `test_cookie_no_crash_at_boot_time` |

## Next steps

- [x] Phase 0: re-run M1 to M8 on current main with flame graphs, then tag `v3-paper-artifact` (needs root on your machine). Baseline b726b42 in `eval/results-summary/phase0-2026-10-28/`; the `v3-paper-artifact` tag already existed and is public, so it was not moved.
- [x] Phase 1: open one PR per quick win, starting with warm connect through `ClientService` and pyroute2. Merged: #28 warm connect, #29 TCP_NODELAY.
- [x] Phase 2 spike: a `core/` skeleton with maturin, one known-answer test for frame encryption, and a `--backend` pytest option, to prove the build and packaging path before the real port.

Open question: which venue and deadline is the paper aiming for? That decides whether to freeze after Phase 2, Phase 3 or Phase 4.
