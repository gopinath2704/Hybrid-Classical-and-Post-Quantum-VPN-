# Security Audit

This file records the security audit findings, what fixed each one, and the boundaries that still apply. The per-attack pentest is in [pentesting/report.md](../pentesting/report.md), and its status is in [pentesting/pentest.md](../pentesting/pentest.md). The protocol is KEMTLS-inspired, not KEMTLS. It has a symbolic Tamarin model but no computational proof and no independent review.

Validation counts from earlier passes are in git history (`git log -- docs/security_audit.md`). This file keeps only what is still true.

## Original audit — 2026-09-05

The audit covered the complete repository at the start of the 2026-09-05 remediation, with the code, not earlier status claims, as the source of truth. Every finding below is closed: fixed in code and covered by tests.

| ID | Severity | Finding | Fix (current code) |
|---|---|---|---|
| A-01 | Critical | Server not authenticated | Static ML-KEM-768 server identity, pinned by SHA-256 fingerprint; its KEM secret enters the key schedule and the transcript |
| A-02 | Critical | Clients not authenticated or authorized | Transcript-bound client proof (Ed25519 in v2, ML-KEM in v3), checked against the authorized-client database with optional fixed IP |
| A-03 | High | Legacy, ambiguous PQC selection | Only standardized ML-KEM-768; fails closed in production after a keygen/encaps/decaps self-test |
| A-04 | Critical | Non-directional key schedule | Separate Finished, directional traffic, nonce, rekey and control secrets from a master secret bound to the session and the transcript |
| A-05 | Critical | Unsafe GCM nonces, no replay protection | Header as AAD, nonce base XOR sequence, per-direction counters, epoch check, 128-packet replay window committed only after authentication |
| A-06 | High | Rekey could not synchronize | Authenticated REKEY_REQUEST/RESPONSE with monotonic epoch, nonce and confirmation |
| A-07 | Critical | UDP endpoint negotiation broken | One server UDP port; the endpoint is learned only from an authenticated `UDP_BIND` |
| A-08 | Critical | No multi-client routing | One `pqvpn0`, one UDP listener, session/IP/endpoint maps, server-side IP pool |
| A-09 | Critical | No host or client routing lifecycle | Transactional client routes and DNS, server nftables NAT/MSS helper, and a real kill switch (2026-10) |
| A-10 | High | Silent fallback to an emulated TUN | Native TUN is mandatory unless `--dev-emulated-tun` is set |
| A-11 | Medium | MTU accounting wrong and not applied | One 42-byte frame overhead; TUN MTU set; oversized inner packets rejected; MSS clamp applied. Dynamic PMTU discovery is still open |
| A-12 | Medium | Telemetry never sampled | Authenticated PING/PONG on the real UDP path |
| A-13 | High | Parsers accepted trailing or inconsistent data | Exact lengths, known types, bounded outer messages, strict state transitions; fuzzed in Rust (see below) |
| A-14 | Critical | Unauthenticated management API | The browser management API was removed; the GUI uses the local `SO_PEERCRED` IPC |
| A-15 | Medium | Fake public servers in the dashboard | Removed together with the dashboard |
| A-16 | Medium | Over-claimed key erasure | Python erasure is documented as best-effort; the Rust core holds keys in `Zeroizing` buffers |
| A-17 | High | Weak resource-exhaustion controls | Max clients, per-source rate limit, handshake deadline, idle and absolute expiry, stateless cookies |
| A-18 | High | Deployment produced no routed VPN | systemd deployment with the firewall/NAT helper (see [trust boundary](#privileged-systemd-execution-trust-boundary)); Docker remains a convenience only |
| A-19 | High | Tests covered only the happy path | Separate mock and native markers, negative security tests, root namespace tests, shared Python/Rust vectors |

**Follow-up findings, same day, all fixed:**

- **DATA and CONTROL shared state.** The two channels shared keys, counters and the replay window, and sequence allocation was unlocked. Each channel now has its own HKDF domain and state. Sequence allocation plus encryption is atomic, and so is authenticate-then-commit.
- **Inner-source spoofing.** Inner source spoofing by an authenticated client is blocked: the inner IPv4 source must equal the session's assigned address.
- **Partial setup failures.** A failure partway through connect could leave routes, DNS or sockets behind. Connect now rolls back as a whole and restores the exact routes that existed before.
- **Handshake overhead.** It was cut from 7,192 to 3,768 bytes, by not retransmitting the pinned static key and by dropping a duplicate ephemeral ML-KEM exchange. This construction still needs independent review.
- **Liveness (Edit-3).** Only authenticated, authorized traffic now refreshes a session. Healthy PING/PONG keeps a quiet session alive, and rejected DATA no longer does. See [design.md](design.md#session-liveness).

## Pre-VPS hardening — 2026-09-07

This pass added:

- **Client IPv6 policy:** `block`, `fail` or `allow`, with block as the default in full mode. Blocking uses an exclusively created `ip6 pqvpn_client6_<random>` table. See [design.md](design.md#ipv6).
- **Pinned native source:** liboqs 0.16.0 is pinned to commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`, and `scripts/install-liboqs.sh` aborts on a mismatch. See [deployment.md](deployment.md#native-liboqs).
- **Revocation:** it applied to new handshakes only at the time. It is extended to live sessions in the [2026-10 section](#rust-core-and-client-hardening--2026-10).

That baseline was tagged `v2-pre-vps` locally; the tag is no longer in the repository. Real-client validation of systemd, DNS and IPv6 against a VM followed, recorded in [deployment.md](deployment.md#validation-gates), and so did the [AWS EC2 deployment](deployment.md#aws-ec2-deployment).

## Privileged systemd execution trust boundary

`packaging/common/pqvpn-server.service` runs the daemon as `User=pqvpn`, `Group=pqvpn` with `CapabilityBoundingSet=CAP_NET_ADMIN`. The `+` prefix on `ExecStartPre=+` and `ExecStopPost=+` runs `/opt/pqvpn/scripts/server-network.sh setup` and `cleanup` as root. Those helpers need root for the nftables tables and to save and restore the forwarding sysctl.

**What must be root-owned:** everything those root steps execute or import, directly or indirectly, and the directories that contain it. None of it may be writable by `pqvpn`, its groups or other users. That covers:

- `/opt/pqvpn/scripts/server-network.sh` and `/opt/pqvpn/vpn/network.py`;
- all application packages;
- `/opt/pqvpn/.venv/bin/python` and the whole venv;
- symlink targets.

The system Python, liboqs and the OS tools they call fall under the same rule. Do not grant the service account write ACLs.

**`/opt/pqvpn` ownership and updates:**
- The tree is `root:root`. Directories and executables are 0755, and ordinary files are 0644 or stricter.
- Create the venv and install dependencies as an administrator, never as `pqvpn`.
- Update while the service is stopped, restore ownership and modes, then rerun the production doctor.
- If an installation was ever owned by the service account, rebuild it from trusted inputs: a `chown` cannot remove code that was already planted.

**`/etc/pqvpn` permissions:**
- The directory is `root:pqvpn 0750`.
- `server.toml` and the public identity are `root:pqvpn 0640`.
- The private identity is `pqvpn:root 0400`. Because the daemon owns this file, it could chmod it, so 0400 does not make it immutable against a compromised daemon.
- The privileged helpers import or execute no key or policy file.

**Authorized-clients database:**
- It lives in `/var/lib/pqvpn/authorized/` (see [deployment.md](deployment.md)). Never make `/etc/pqvpn` group-writable.
- Run authorize and revoke as root. Each atomic update leaves a root-owned 0600 file. Restore the documented owner and mode afterwards. Until then, the daemon's reads fail closed.

**Doctor check:** the server doctor audits the complete `/opt/pqvpn` tree, including symlink targets and ancestors, when it inspects `/etc/pqvpn` or runs from `/opt/pqvpn`. It fails on non-root owners, group or world write bits, a missing helper or interpreter, and unreadable entries. It is a read-only snapshot. It does not validate systemd at runtime and does not audit external system libraries.

## Rust core and client hardening — 2026-10

Phase 5 of the [Rust-core migration](rust-core-migration-plan.md#phase-5-results) is on branch `rust-core/phase-5-hardening`. It adds the controls below. The `v4.0.0` tag is not cut yet.

### Unsafe code and dependencies

- **Unsafe code:**
  - `pqvpn_core` and `pqvpnd` are `#![forbid(unsafe_code)]`.
  - `pqvpn_fd` holds the only `unsafe`: `fcntl`/`fstat`-checked fd adoption and the TUN `ioctl`.
  - `own()` stays a safe fn, which keeps the one-crate rule.
- **Dependencies:**
  - `aws-lc-rs` and `pyo3` are pinned exactly, and `core/Cargo.lock` is committed.
  - `cargo deny check` (advisories, bans, licenses, sources) and `cargo audit` were clean on 2026-10-31: 0 vulnerabilities in `core/Cargo.lock` and `core/fuzz/Cargo.lock`.
  - Package builds still fetch crates at build time; vendoring them is a follow-up.
- **Randomness:** aws-lc is built without jitter entropy, so it is seeded from `getrandom`. This loses aws-lc's second, independent entropy source and rules out aws-lc FIPS. It is the same OS source the Python path uses. See [design.md](design.md#randomness-in-the-rust-build).

### Fuzzing

There are five cargo-fuzz targets with ASan in `core/fuzz/fuzz_targets/`:

- `dispatch`
- `open`
- `handshake_decode`
- `handshake_machines`
- `established`

They cover record parsing, hostile handshake fields and resume tickets that pass GCM with hostile contents. They also cover control traffic on resumed sessions and the client ticket-file parser.

A 10-minute preflight found 0 crashes. **The 24 h run for the release gate is pending.** It counts only if the `core/pqvpn_core` and `core/fuzz` trees and `core/Cargo.lock` are unchanged at the tag.

### Client controls

- **Kill switch:**
  - A real kill switch replaces the earlier `kill_switch` flag, which the client never enforced. It is a fixed-name `inet pqvpn_killswitch` table, installed before the handshake.
  - A crash or SIGKILL leaves it blocking (fails closed) until a disconnect or `recover`.
  - Both clients render the same golden rules. Its limits are in [design.md](design.md#kill-switch).
- **DNS:** a full tunnel with managed DNS and no DNS servers is refused in both clients. The earlier behaviour left every lookup on the uplink's resolver.
- **Ticket file:**
  - It stays plaintext, next to the equally protected identity key.
  - Both loaders refuse anything that is not a regular file owned by the effective uid with no group or other access. They open it with `O_NOFOLLOW | O_NONBLOCK`.
  - A rejected ticket is deleted.
- **Native backend:** the client service runs `/usr/bin/pqvpnd` from a fixed path, never found through `PATH`. It treats `--status-json` output as untrusted, and an invalid line stops the child and fails closed. See [design.md](design.md#native-backend-pqvpnd---status-json).
- **Revocation:** every 30 s the server re-reads the authorized-clients database. When a client is disabled, it rotates the ticket key and ends that client's live sessions, so a revoked client no longer keeps an active tunnel until a restart.

## Open items

- **Pentest partials:** #32, #33, #37, #39, #48 and #62, plus #69 (supply-chain verification). The account API also serves `/openapi.json` unauthenticated (low). See [pentesting/pentest.md](../pentesting/pentest.md).
- **IPC socket:** it is `0666`, and authorization rests on `SO_PEERCRED` plus `PQVPN_ALLOWED_UIDS`. Moving to `0660` with a group is a follow-up.
- **Release gate:** the 24 h fuzz run and the real-host `sudo kill -9` kill-switch check are pending.
- **Protocol:**
  - There is no independent protocol review.
  - v2 client authentication is classical.
  - The re-handshake does not recover from an active adversary who holds the full epoch state.
  - Routed IPv6 and dynamic PMTU discovery are not implemented.
- **Key erasure:** it is best-effort on the Python path.
