# PQVPN Design

## Architecture

PQVPN separates an authenticated TCP control plane from an encrypted UDP data plane.

1. The client checks the server's static ML-KEM-768 identity against a provisioned SHA-256 fingerprint.
2. A KEMTLS-inspired handshake combines three inputs: ephemeral X25519, one ephemeral ML-KEM session secret and a static ML-KEM authentication secret from the server identity. The client then proves its authorized identity: Ed25519 in v2, ML-KEM in v3.
3. HKDF derives separate secrets for Finished, DATA, CONTROL, nonces, rekey and confirmation. Each is separated by role and by channel. All are bound to the protocol, version, algorithms, session, randoms and transcript.
4. An encrypted CONFIG message assigns the VPN address, server address, prefix, MTU, UDP port, routes, DNS, epoch and the rekey and re-handshake intervals.
5. An authenticated UDP_BIND tells the server the client's real NAT endpoint. No TCP source port is reused or inferred.
6. One server TUN and one UDP listener serve all clients. Maps connect compact session IDs, client VPN addresses, endpoints and traffic-key state.
7. Client TUN packets become AES-GCM DATA frames. The server decrypts them into `pqvpn0`, and Linux forwarding plus the project's own nftables masquerade route them out. Return packets are matched to a session by inner destination, encrypted, and injected into the client's TUN.

Production never falls back to a socket-pipe TUN; emulation requires `--dev-emulated-tun`. Client host changes are transactional. The server firewall helper owns separate nftables tables and never flushes user rules.

### Two implementations, one protocol

| Component | Python | Rust (`core/`) | Switch |
|---|---|---|---|
| Data plane: TUN↔UDP loop, framing, AES-GCM, replay window | `vpn/runtime.py`, `handshake/kemtls.py` | `pqvpn_core::dataplane` (`recvmmsg`/`sendmmsg`, UDP GSO/GRO) | `data_plane = "python" \| "rust"` |
| Handshake state machines, key schedule, tickets | `handshake/kemtls.py` | `pqvpn_core::handshake`, `schedule` | `handshake = "python" \| "rust"` (needs `data_plane = "rust"`) |
| Client | `VPNClient` | `pqvpnd connect` | `client_backend = "python" \| "native"` |
| Server | `VPNServer` | none | n/a |
| Primitives | liboqs (ML-KEM), `cryptography` | aws-lc-rs 1.18.2 | follows the above |

Both switches default to `python`. When the server runs `handshake = "rust"`, Python still does authorization, the IP pool, cookies, the source rate limiter and revocation. They run between Rust handshake steps, so no lease, CONFIG or data-plane state exists before authorization succeeds. v3-mldsa has no Rust port.

Both implementations replay the same recorded vectors to identical transcripts and secrets: v2, v3-kem, resumption, rekey and re-handshake (`tests/test_handshake_vectors.py`). The wire format is unchanged, so the Tamarin models apply to both.

**Crossing into Rust:**
- Key material crosses into Rust once, downward. `pqvpn_core` copies it from a Python buffer into `Zeroizing` storage.
- When the Rust data plane is on, Python never builds a data AES-GCM key and sees only the control ciphers.
- The descriptors handed over are `dup`s, which Rust adopts after an `fstat` check.

**Unsafe code:**
- `pqvpn_core` and `pqvpnd` are `#![forbid(unsafe_code)]`.
- `pqvpn_fd` is the only crate with `unsafe`: fd adoption and the TUN `ioctl`.

### Randomness in the Rust build

Every Rust build sets `AWS_LC_SYS_NO_JITTER_ENTROPY=1` in the repository-root `.cargo/config.toml`. Cargo, maturin, the PKGBUILD, `debian/rules` and the bench runner all read it.

- **Changes:** aws-lc seeds its DRBG from `getrandom`, with RDRAND as additional input, instead of from CPU Jitter Entropy. Prediction resistance is off.
- **Why:** jitter seeding cost about 27 ms on the first random draw in each process, which dominated native cold connect. In the jitter build, every `RAND_bytes` call also read RDRAND (about 18 µs per v3-kem handshake).
- **Costs:** aws-lc's second, independent entropy source. The build is also not usable for aws-lc FIPS, which this project does not use.
- **Why it is acceptable:** `getrandom` is the source the Python path (liboqs, `cryptography`) already uses, so the RNG is no weaker than the Python baseline.
- **Check:** a correct build has no `jent_` symbols (`nm … | grep -c jent_` is 0). The bench runner records that count.

Measurements and sources: [Phase 5 results](rust-core-migration-plan.md#phase-5-results).

## Client service and IPC

The desktop client (`app/client.py`) is a normal-user PySide6 GUI. It talks to a privileged client service over a Unix domain socket. The service owns the connection: TUN, routes, DNS, the IPv6 guard and the kill switch.

### Two configuration sources

The two modes are separate, and no values are merged between them.

- **TOML mode:** `app.client --service --config PATH` loads only that file. This is the only mode where `kill_switch`, `data_plane`, `handshake`, `protocol_version` and `client_backend` can be set.
- **Managed mode:** `app.client --service` loads the selected public profile plus the service-owned device identity under `/var/lib/pqvpn`. Its `ClientConfig` holds only the profile fields (`vpn/identity.py` `client_config`). Everything else keeps its default: protocol v2, Python backend, Python data plane and handshake, no kill switch.

After sign-in the GUI binds the device and imports `GET /server/info` ([accounts.md](accounts.md)), so no `.pqvpn` file is handled by hand.

**Device identity:**
- The Ed25519 identity is created once under `/var/lib/pqvpn/identity`. The directory is mode `0700`, the private key `0600` and the public key `0644`.
- Existing identities are opened without following symlinks and checked for type, mode, length and keypair consistency. They are never rotated.

**Profiles:**
- They are stored atomically in `/var/lib/pqvpn/profiles/profiles.json`, mode `0600`. There are at most five, so the full list fits in one 16 KiB IPC frame.
- Duplicate IDs are rejected unless replacement is requested.
- Removing the active profile leaves none selected.
- Import, select and remove are refused while a connection is active or changing.

### `.pqvpn` schema

UTF-8 JSON, at most 8,192 bytes, duplicate properties rejected, exactly these fields:

| Field | Validation |
|---|---|
| `version` | integer `1` |
| `profile_id` | 1–64 ASCII letters/digits/`.`, `_`, `-`; starts alphanumeric; no `..` |
| `name` | 1–80 non-control characters |
| `server_host` | IPv4 address or strict ASCII hostname, not a URL/path |
| `server_control_port` | integer `1..65535` |
| `server_identity_public_key` | canonical Base64 of exactly 1,184 ML-KEM-768 public-key bytes |
| `server_identity_fingerprint` | lowercase SHA-256 hex matching those bytes |
| `expected_vpn_subnet` | canonical IPv4 network with usable client addresses |

Unknown fields are rejected. Parsing does no interpolation, command execution, URL fetch or trust-on-first-use.

### `.pqenroll` schema

UTF-8 JSON, at most 4,096 bytes, duplicate properties rejected. It contains exactly:

- `version` (`1`);
- a 1–64 character `client_id`;
- the canonical Base64 of the 32-byte Ed25519 public key, and its lowercase SHA-256 fingerprint;
- a UTC `created_at` timestamp (`YYYY-MM-DDTHH:MM:SSZ`).

It is public data only. The administrator validates it and adds the key to the locked, atomic `AuthorizedClients` store. Exporting a request does not mean it is approved.

### IPC boundary

**Framing:**
- Each message is a 4-byte length prefix plus JSON, at most 16 KiB.
- One service-owned client handles requests, and mutations are serialized.
- Errors are sanitized before they reach the GUI.
- IPC has no generic file write, TOML write, command execution, restart or private-key operation. Profile import sends bounded JSON, not a path.

**Who may connect:**
- `SO_PEERCRED` authorization fails closed. A peer is accepted only if its uid is 0 or is listed in `PQVPN_ALLOWED_UIDS`, which is set in a systemd drop-in.
- An unset list means root only. A malformed entry empties the list.
- The socket is `0666`, so any local user can connect and be refused. Moving to `0660` plus a group is a tracked follow-up.
- `IPCClient` in turn refuses a service whose peer uid is not 0, so a squatted socket cannot impersonate the service.

### Native backend (`pqvpnd --status-json`)

With `client_backend = "native"`, the service writes a `[client]` table to a private temporary file. It then runs `/usr/bin/pqvpnd connect --config <file> --status-json`, from a fixed path, never found through `PATH`. It builds the same `ClientStatus` from the child's status stream, so the GUI cannot tell the two backends apart.

**Status stream, wire spec v1:**
- One JSON object per line, newline-terminated, at most 4,096 bytes.
- Every line has `v = 1`, a `state` (`CONNECTING`, `CONNECTED`, `DISCONNECTED`, `FAILED`, `BLOCKED`), an `error` string and a `kill_switch` boolean.
- `CONNECTED` lines add:
  - the tunnel fields: addresses, prefix, endpoint, TUN, MTU;
  - `suite`, `ipv6_guard`, `dns_managed`, `epoch`;
  - the `rekey_in` and `rehandshake_in` timers;
  - `probes`, as deltas: `sent`, `lost` and up to 64 RTTs.
- A `CONNECTED` line is sent when the tunnel comes up, every second after that, and on each epoch change. Exactly one final line follows all cleanup.
- Exit codes: 0 for `DISCONNECTED`, 1 for a failure, 2 for a config refusal.

**The service treats the stream as untrusted:**
- An invalid line stops the child.
- If the kill switch is on, the service then reinstalls it and reports `BLOCKED`.
- An exit without a final line is reported as `FAILED`, or as `BLOCKED` if the kill switch table is present.
- The status shows `pqc_mode = "native_aws_lc"`. It is quantum-safe once a hybrid suite (`v2-ed25519` or `v3-kem`) is negotiated.

**What `pqvpnd` itself does:**
- It reads the same `[client]` table as the Python client and refuses any option it does not implement.
- It matches the Python client's network handling: the IPv6 guard before routes, full and split routing with exact rollback, and systemd-resolved DNS reverted first on teardown.
- It runs `ip`, `nft` and `resolvectl` from fixed system paths.
- It supports v2 and v3, resumption, cookies, rekey and re-handshake.

## Protocol

### Protocol v2

This is a KEMTLS-inspired research protocol, not formal KEMTLS. Its static KEM identity reduces post-quantum handshake size and fragmentation pressure; it does not eliminate fragmentation.

Suite: X25519, ML-KEM-768, HKDF-SHA256, Ed25519 client identities, AES-256-GCM. The client is provisioned with the SHA-256 fingerprint of the server's 1,184-byte static ML-KEM public key. The server is provisioned with the enabled Ed25519 client keys.

### Handshake (v2)

Every handshake message starts with `magic:u16 | version:u8 | type:u8 | payload_length:u16`. TCP adds a four-byte length prefix. Both lengths must match exactly, and the largest control message is 16,384 bytes.

- **ClientHello:** random(32), session ID(32), ephemeral X25519 public(32), ephemeral ML-KEM public(1184), Ed25519 client public(32).
- **ServerHello:** random(32), echoed session ID(32), ephemeral X25519 public(32), ML-KEM ciphertext to the client's ephemeral key(1088), SHA-256 identity identifier(32). The static key is not retransmitted.
- **ClientKeyExchange:** ciphertext to the static server identity key(1088), Ed25519 transcript proof(64), client Finished(32).
- **ServerFinished:** server Finished(32). Only the holder of the pinned static ML-KEM private key can derive the secret behind this MAC.

The hybrid input is three secrets: the ephemeral X25519 secret, one ML-KEM secret from the client's ephemeral key, and the authenticated secret from the server's static KEM. A server-ephemeral ML-KEM direction was removed, because it duplicated the ephemeral post-quantum role without adding authentication. This simplification has no proof and needs independent review.

Wire sizes: ClientHello 1,318 B, ServerHello 1,222 B, ClientKeyExchange 1,190 B and ServerFinished 38 B, so **3,768 B in total**. The full byte layout, including the transcript order and every HKDF label, is in [Appendix B](rust-core-migration-plan.md#appendix-b--phase-4-handshake-inventory) of the migration plan.

### Encrypted frame

All integers are in network byte order. The 26-byte clear header is the AES-GCM AAD:

| Field | Bytes |
|---|---:|
| Magic `PV` | 2 |
| Protocol version (`0x20` v2, `0x30` v3) | 1 |
| Channel: DATA or CONTROL | 1 |
| Frame type | 1 |
| Direction | 1 |
| Compact session ID | 8 |
| Key epoch | 4 |
| Sequence | 8 |
| Encrypted payload | variable |
| GCM tag | 16 |

The frame types are DATA, UDP_BIND, UDP_BIND_ACK, PING, PONG, CLOSE, CONFIG, REKEY_REQUEST, REKEY_RESPONSE and ERROR. Record overhead is exactly 42 bytes, before the outer IP and UDP headers.

**Per-channel state:**
- Each channel and each direction has its own HKDF key, nonce base, send counter and receive state, so a record cannot authenticate on the other channel.
- DATA uses a 128-packet replay window. Ordered TCP CONTROL requires exactly the next sequence number.
- Allocating a sequence number and encrypting happen as one atomic step. So do the replay check, authentication and commit.

**Endpoint binding:**
- After the handshake, the server sends CONFIG. The client sends an encrypted `UDP_BIND` (payload `bind`) to the configured UDP port.
- Only that authenticated frame can set the client's endpoint. Once it is bound, a different endpoint is rejected; the client must reconnect to change it.

**Rekey:**
- The request payload is `next_epoch:u32 || nonce:32`. The server returns `next_epoch || HMAC(control_key, label || request)`, encrypted under the current epoch.
- Both sides then switch to independently derived next-epoch material. Replayed or non-monotonic epochs are rejected.
- This hash-based rekey only rotates keys. It does not give post-compromise security.

### Protocol v3

v3 (`0x30`) replaces Ed25519 client authentication with mutual authentication by static ML-KEM-768 keys. Each side encapsulates to the other's pre-shared static key, and only the real owner can decapsulate and derive the Finished MAC. There are no signatures in the handshake. Design decision: [D1](#d1-client-authentication-flow-for-v3).

- **ClientHelloV3:** random(32), session ID(32), ephemeral X25519 public(32), ephemeral ML-KEM public(1184), SHA-256 of the client's static ML-KEM public key(32).
- **ServerHelloV3:** random(32), echoed session ID(32), ephemeral X25519 public(32), ML-KEM ciphertext to the client's ephemeral key(1088), identity identifier(32), ML-KEM ciphertext to the client's static key(1088).
- **ClientKeyExchangeV3:** ciphertext to the server's static key(1088), client Finished(32).
- **ServerFinishedV3:** server Finished(32).

Wire sizes: 1,318 + 2,310 + 1,126 + 38 = **4,792 B** (1,024 B more than v2). The key schedule has two stages: an ephemeral secret from X25519 and K_eph, then a master secret from that, K_S, K_C and the transcript.

`protocol_version` selects v2 or v3, and the code default is 2. Managed desktop clients speak v2, so a server that serves them must run v2.

### Hybrid re-handshake (post-compromise security)

Hash-based rekey derives each successor from the previous `rekey_secret` plus a public nonce. So compromising the current rekey secret exposes future epochs. The v3 re-handshake adds fresh ephemeral material from both sides over the encrypted control channel:

```
REHANDSHAKE_REQUEST:  epoch(4) || X25519_eph_pub(32) || ML-KEM_eph_pub(1184)    client → server
REHANDSHAKE_RESPONSE: epoch(4) || X25519_eph_pub(32) || ct(1088) || confirm(32)  server → client
```

**Derivation:**
- `seed = SHA-256(old_rekey_secret || dh_ss || k_mlkem || epoch)`.
- HKDF expansion over `session_id || epoch || SHA-256(request || response_body)`.
- `confirm = HMAC-SHA256(new_control_confirm_key, "rehandshake confirm" || request || response_body)`. The client checks it in constant time before it activates the new keys, and tears the session down on a mismatch.

**Security:**
- **Recovers from:**
  - a **passive** adversary after full compromise of the epoch state;
  - an **active** adversary who learned only the traffic or control keys.
- **Does not recover from:** an active adversary who holds the full epoch state, including the rekey secret.
- `formal/pqvpn_v3_pcs.spthy` proves the two recovery claims (`pcs_control_keys_only`, `pcs_passive_after_epoch_compromise`) and shows the limitation (`attack_active_after_epoch_compromise`).

`rehandshake_interval` (in seconds, default 0 = off) is sent in CONFIG. The switch uses the same epoch logic as rekey, so no packets are lost when the new keys take effect.

### 1-RTT session resumption

After a full handshake, the server sends a `RESUMPTION_TICKET` control frame.

**Ticket format:**
- The ticket is AES-256-GCM under an in-memory server key, with AAD `PQVPN-RESUME`.
- It holds the session's `resumption_secret`, the protocol version, an expiry, the client ID and the assigned IP.
- `resumption_ticket_lifetime` defaults to 86400 s; the range is 0–604800, and 0 disables resumption.

**When the server key changes:**
- A server restart invalidates every ticket.
- The key is rotated whenever a client leaves the enabled set (see [Revocation](#revocation)).

```
RESUMPTION_HELLO:  client_random(32) || ticket_len(2) || ticket || X25519_eph_pub(32) || ML-KEM_eph_pub(1184)
RESUMPTION_ACCEPT: server_random(32) || new_session_id(32) || X25519_eph_pub(32) || ct(1088) || Finished(32)
```

**Properties:**
- Every resume mixes fresh X25519 and ML-KEM secrets with the `resumption_secret` and the transcript.
- An expired, tampered or version-mismatched ticket falls back to a full handshake.
- Authorization is checked again after the ticket validates.
- Tickets are not single-use, and resumption skips the cookie gate.

**Client ticket file:** `.pqvpn_ticket.json` sits next to the client private key and holds the ticket, its secret, the server fingerprint and the version.

- **Plaintext on purpose:** the file is not encrypted at rest. Anyone who can read it can already read the identity private key beside it, which has the same `0600` protection. Sealing the ticket alone would add nothing.
- **Same loader rules in Python and `pqvpnd`:** the file is opened with `O_NOFOLLOW | O_NONBLOCK`, so a planted FIFO cannot hang connect. It must be a regular file owned by the effective uid, with no group or other access.
- **Writes:** the ticket goes to an `O_EXCL | O_NOFOLLOW` temporary file, is fsynced, then renamed into place.
- **Rejected tickets:** if the server rejects the ticket, the file is deleted, so it cannot outlive a revocation.
- **Fingerprint check:** a ticket stored for a different server fingerprint is not used.

### Stateless cookie (DoS resistance)

ML-KEM decapsulation of unauthenticated input lets an attacker burn server CPU. A stateless HMAC cookie, as in WireGuard, makes the client prove its source address before any KEM work:

```
ClientHello                         →
                                    ←  COOKIE_CHALLENGE: cookie(32)
COOKIE_RESPONSE: cookie(32) || ClientHello  →   (handshake proceeds)
```

**Construction:**
- `cookie = HMAC-SHA256(secret, client_ip || port)`, with two random secrets, current and previous.
- The secrets rotate lazily every 120 s, and verification accepts either one, so a cookie lives 120–240 s.
- The server does no KEM work and keeps no per-connection state until the cookie checks out.

**Configuration:** `cookie_mode` is `off` (the default), `under_load` (when in-progress handshakes reach `cookie_threshold`, default 10) or `always`. The client answers a challenge automatically. Cookies work with v2 and v3.

Under a measured 10k/s ClientHello flood, `always` kept the legitimate connect median at 156 ms; `off` let it rise to 1,186 ms ([Phase 3 results](rust-core-migration-plan.md#phase-3-results)). So the default `off` is the weaker setting under a flood.

### Protocol v3-mldsa (comparison suite)

v3-mldsa (`0x31`, `experimental_suite = "v3-mldsa"`) replaces the KEM-based client authentication with an ML-DSA-44 signature. The server still authenticates with its static ML-KEM key. It exists for a same-codebase comparison, it is Python only, and `handshake = "rust"` refuses it.

- **ClientHello:** 1,318 B.
- **ServerHello:** 1,222 B (no ciphertext to the client's static key).
- **ClientKeyExchange:** ciphertext to the server's static key(1088), signature(2420), Finished(32), so 3,546 B.
- **ServerFinished:** 38 B.
- **Total: 6,124 B**, which is 1,332 B more than v3-kem. The key schedule has a single stage.

### Authentication boundary

- **v2:** static ML-KEM-768 authenticates the server, and X25519 plus ML-KEM-768 set up the session keys. Ed25519 client authentication is classical, so v2 is not fully post-quantum mutual authentication.
- **v3:** both sides authenticate by proving possession of a static ML-KEM-768 key. The Tamarin models (`formal/pqvpn_v3.spthy`, `formal/pqvpn_v3_pcs.spthy`, 13 lemmas) cover:
  - session-key secrecy and forward secrecy;
  - injective authentication of both sides;
  - KCI resistance and post-compromise security, under a Dolev-Yao adversary.

## Session liveness

**What counts as activity:**
- Activity is refreshed only by authenticated traffic:
  - accepted inner IPv4 DATA whose source is the assigned IP;
  - valid endpoint binding;
  - authorized CONTROL, including rekey once it validates.
- Invalid, replayed, wrong-endpoint or unauthenticated traffic does not count.
- UDP PING and PONG are DATA-domain frames, with an eight-byte timestamp.

**Server expiry:**
- A quiet session with healthy PING/PONG survives `idle_timeout`. `session_timeout` is an absolute limit that keepalives do not extend.
- Expiry removes the session's maps, releases its lease, wipes its keys best-effort, closes the control socket, and logs the client ID and VPN IP (no key material).
- Both timers use monotonic clocks.

**Client dead-peer detection:**
- The client tracks the last authenticated UDP receive: the first `UDP_BIND_ACK`, a matching PONG, or IPv4 DATA addressed to it.
- Outgoing PING or rekey cannot hide a UDP blackhole.
- After `dead_peer_timeout`, the client enters FAILED and cleans up. With the kill switch on, it enters BLOCKED instead.

## Client network policy

### IPv6

The tunnel carries IPv4 only.

- **Full mode:** by default it installs an exclusively created, randomly named `ip6 pqvpn_client6_<random>` table before any route. The table blocks non-loopback OUTPUT and FORWARD. Disconnect and every failure path remove it; a SIGKILL leaves it behind.
- **Split mode:** IPv6 is left alone unless `ipv6_policy = "block"`.
- **`fail`:** rejects visible IPv6 connectivity at setup. It is a snapshot only, so use `block` for ongoing protection.
- **`allow`:** warns that IPv6 bypasses the VPN.

Operator details: [IPv6 policy](deployment.md#ipv6-policy).

### DNS

Managed DNS (`dns_mode = "systemd-resolved"`, the default) is transactional:

- A full tunnel installs `~.`. Split mode installs only the configured routing domains.
- Setup fails closed when the resolver manager is missing.
- A full tunnel with managed DNS but no DNS servers is refused, in both clients. "No DNS servers" means none configured and none advertised in CONFIG; otherwise every lookup would stay on the uplink's resolver.
- `dns_mode = "none"` explicitly accepts the DNS leak.

Operator details: [DNS policy](deployment.md#dns-policy).

### Kill switch

`kill_switch = true` installs one fixed-name nftables table, `inet pqvpn_killswitch`. It has an output chain with policy drop.

**Phases:**
- **`connecting`**, installed before the handshake: it lets out loopback, DHCPv4 (UDP 68→67) and the server's control TCP port.
- **`up`**, after routes and DNS: it also lets out the server's data UDP port and the TUN.
- Each install is one transaction (`destroy table`, then re-add), so a replace never opens a gap.
- Both clients render the same text, which is held byte for byte to `tests/golden/killswitch_*.nft`. Each renderer validates its inputs before interpolating them.

**Removal and failure:**
- Only an explicit disconnect, `pqvpn client recover` or `pqvpnd recover` removes the table.
- A lost session, a failed reconnect or a crash leaves it blocking. The table outlives the process, so even a SIGKILL fails closed. The client reports `BLOCKED`.

**Requirements:** it needs `full_tunnel = true`, an `ipv6_policy` other than `allow`, and an IPv4 address as `server_host`. In the blocked state, a hostname could only be resolved by letting DNS out.

**Limits:**
- No LAN access while it is on.
- There is no forward chain, so containers or VMs forwarded through the host are not covered after a crash.
- nftables state does not survive a reboot, so the host is unprotected at boot until the first connect.
- After a SIGKILL, the IPv6 guard table and the server bypass route stay behind until they are removed by hand.
- It is available only in TOML mode and to `pqvpnd`, not to managed profiles.

`destroy table` needs nftables 1.0.8 and Linux 6.3 or newer (UNVERIFIED in this repo).

## Revocation

- Authorization is checked on every new handshake, and again after a ticket validates.
- The server also re-reads the authorized-clients database every 30 s. If any client has left the enabled set, it:
  - rotates the resumption ticket key;
  - shuts down the control socket of every session whose client is no longer enabled, which ends that session.
- So a revoked client loses an active session within about 30 s. A server restart ends every session at once.

## Threat model and limitations

**What PQVPN protects:** IP packets between an authenticated client and a provisioned server. It protects them against:

- passive observers and active network attackers;
- replay and cross-session injection;
- unauthorized clients.

**Trusted inputs:** the server fingerprint and the authorized-client database.

**Out of scope:**
- server or endpoint compromise;
- traffic analysis and volumetric DoS;
- a malicious kernel or root;
- compromise of provisioning.

**Production requirements:**
- Production needs real ML-KEM-768 and a passing self-test. Mock PQC (`ALLOW_MOCK_PQC=1`) is insecure and limited to development and tests.
- There is no silent trust-on-first-use.

**Protocol limitations:**
- The protocol has a symbolic Tamarin model but no computational proof and no independent review.
- If the server's long-term identity is compromised, the attacker can impersonate the server, and recordings that relied on the static KEM input may be affected. The ephemeral X25519 and ML-KEM inputs stay independent.
- Hash-based rekey only rotates keys; recovery after compromise needs the v3 re-handshake.

**Key erasure:**
- The Rust core keeps keys in `Zeroizing` buffers, and aws-lc wipes its key objects when they are dropped.
- On the Python path, and for Python's copies before they are handed to Rust, erasure is best-effort. Interpreter, allocator, swap and core-dump copies may remain.

Further limits:
- The tunnel has no routed IPv6 and no dynamic authenticated PMTU discovery.
- Client isolation on the server depends on the nftables policy installed by `scripts/server-network.sh`. Starting the daemon alone installs no firewall or NAT rules.

The isolation rules allow no peer forwarding and no access to host services or private and metadata ranges, except configured destinations and optional ICMP echo to the server's VPN IP. See [Firewall policy](deployment.md#firewall-policy-and-subnet).

## Diagnostics

`python -m vpn.cli doctor server|client --config PATH` reads deployment state without creating a TUN, binding ports, or changing routes or DNS. A FAIL row returns 1; PASS or WARN alone returns 0. In production it also audits who owns the `/opt/pqvpn` tree and its permissions ([security_audit.md](security_audit.md#privileged-systemd-execution-trust-boundary)).

---

## Design decisions

### D1: Client authentication flow for v3

**Context:** v2's Ed25519 client signature was the last classical primitive in the handshake. Both long-term public keys are pre-shared: the client pins the server's key (from `.pqvpn`), and the server stores the client's key (from `.pqenroll`). So each side can authenticate the other by encapsulating to the peer's static key.

**Options:**
- **A: keep v2's message shape.** `ct_S` stays in ClientKeyExchange, and the server adds `ct_C` to ServerHello. The client's identity hash is sent in the clear, the same exposure as v2's Ed25519 key.
- **B: PDK style.** `ct_S` moves into ClientHello, and the client identity is encrypted. It hides the identity, but needs a larger ClientHello, replay handling and more modelling.

**Choice: A.** It is the smallest wire change from v2 and is easier to model in Tamarin. B can be revisited later.

| Message | v2 | v3 | Delta |
|---|---|---|---|
| ClientHello | 1,318 | 1,318 | 0 |
| ServerHello | 1,222 | 2,310 | +1,088 (ct_C) |
| ClientKeyExchange | 1,190 | 1,126 | −64 (no signature) |
| ServerFinished | 38 | 38 | 0 |
| **Total** | **3,768** | **4,792** | **+1,024** |

```
ES = HKDF-Extract(salt, X25519_ss ‖ K_eph)       — ephemeral handshake secret
AS = HKDF-Extract(ES,  K_S ‖ K_C ‖ transcript)   — authenticated master secret
```

### D6: Data-plane implementation scope (superseded)

The original choice (2026-10-01) kept the data plane in Python. It measured about 10 µs per packet, roughly 680 Mbps on a LAN. Phases 2–4 of the [Rust-core migration](rust-core-migration-plan.md) replaced that choice with an optional Rust data plane and handshake behind the `data_plane` and `handshake` switches.

**Phase 4 gate run** (one host, veth):
- TCP: 6,665–6,783 Mbps on Rust, against about 680 on Python.
- Server memory per session: 24.5 kB on rust-rust.

**Phase 4 misses**, both traced to aws-lc's jitter-entropy seeding (see [Randomness in the Rust build](#randomness-in-the-rust-build)):
- Native cold connect: 42 ms against a 30 ms gate.
- v3-kem handshake CPU: 0.205 ms against 0.2 ms.

The Phase 5 gate run and the `v4.0.0` tag are pending.
