# Phase 4 design: Rust handshake and native client

Oct 30, 2026 · core coding session (Opus) · base `c038f53` · **design only, no code until the user approves**

This answers the Phase 4 brief from `docs/rust-core-migration-plan.md` and is reconciled with `docs/phase4-handshake-inventory.md` (cited below as "inventory §n"). Every number marked *measured* was taken today on this laptop (governor not pinned, so treat them as approximate); the probes are in the appendix. Numbers marked *estimate* are not measurements.

## Bottom line

- **The crypto is ready.** aws-lc-rs `=1.18.2`, already in `core/Cargo.lock`, has stable ML-KEM-768, ML-DSA-44, X25519, Ed25519, HKDF, HMAC and SHA-256. It builds at MSRV 1.85.1 without the `unstable` feature, and it interoperates with liboqs 0.16.0 in both directions (*measured*, §2). The handshake needs no new crate.
- **Each of the three gates depends on a different component**, and only M2 depends on the language of the handshake:
  - **M2 ≤ 0.2 ms** (both roles in one process): a Rust handshake for both roles, called through PyO3. Primitive floor *measured* at 0.17 ms for v3-kem, so this is reachable but tight.
  - **M8 ≤ 64 kB** (server RSS per session at N = 50): this is set by the server's **thread per session**, not by Python crypto objects. A v2 session whose handshake thread exits after hand-off costs 15.4 kB; a session held by its own thread costs 77 to 87 kB (*measured*, §3). The lever is a small change to the Python server's concurrency, not a Rust server.
  - **M1 cold ≤ 30 ms** (a new client process, no ticket, spawn to first ping): this needs a **native one-shot client** (`pqvpnd connect`). The bare interpreter alone costs 18 ms and `import vpn.cli` costs 119 ms (*measured*).
- **Recommendation: option A, plus a server concurrency fix, plus a native one-shot client.** The Rust handshake covers both roles through PyO3. The Python server keeps accounts, authorization, the IP pool, cookies, the rate limiter and revocation. The IPC daemon is deferred.
- **One design rule decides the slice boundaries:** once the handshake runs in Rust, no secret may come back up to Python. That pulls control-channel seal/open, rekey and rehandshake derivation, their confirmation HMACs, and ticket issue/validate/persist into the same Rust session object (§5).

## 1. Determinism

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

## 2. Crates

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

## 3. Gates mapped to components

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

## 4. The switch

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

## 5. Shape of the Rust code

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

## 6. Slices

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

## 7. Tests first, invariants

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

## 8. Risks

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

## 9. Open questions for the user

1. **The server role:** option A (recommended), B or C (§3)?
2. **The M1 cold definition:** is spawning `pqvpnd connect` in place of `python -m vpn.cli client connect` the same definition, with the same clock, stop condition, ticket deletion, suite and n, reported as an extra row? If not, M1 cold is recorded as missed for Phase 4.
3. **The IPC daemon:** defer it to Phase 5, build a thin CONNECT, DISCONNECT and STATUS daemon, or build the full 11-command port as the original plan said?
4. **Gate suites:** keep the published suite per metric (M1 v2, M8 v2, M2 v3-kem) and report the rest? And should v3-mldsa be ported, knowing its M2 floor is 0.24 ms?
5. **Slice (c) touches `vpn/runtime.py`**, which is outside `core/`. Should this session own it, or someone else?
6. **The ticket file:** keep the plaintext resumption secret on disk (today's format, mode 0600), or change it later, for example to an OS keyring or a sealed blob? Phase 4 proposes no change.
7. **New files:** approve `handshake.rs`, `schedule.rs` and the `core/pqvpnd/` crate (§5)?

## Appendix: probes behind the measured numbers

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

## Decisions (2026-10-30)

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
