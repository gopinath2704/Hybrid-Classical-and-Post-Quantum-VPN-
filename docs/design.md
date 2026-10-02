# PQVPN Design

## Project Architecture

PQVPN separates an authenticated TCP control plane from an encrypted UDP data plane.

1. The client verifies a provisioned SHA-256 fingerprint for the server's static ML-KEM-768 identity.
2. A strict KEMTLS-inspired handshake combines ephemeral X25519, one ephemeral ML-KEM session secret, and a static server-identity ML-KEM authentication secret. The client proves its authorized Ed25519 identity. The provisioned identity key is not retransmitted; its transcript-bound SHA-256 identifier selects and binds the pinned key.
3. HKDF derives role- and channel-separated Finished, DATA, CONTROL, nonce, rekey, and confirmation secrets bound to protocol/version/algorithms/session/randoms/transcript.
4. Encrypted CONFIG assigns the VPN address, server address, prefix, MTU, UDP port, routes, DNS, and epoch.
5. Authenticated UDP_BIND teaches the server the client's actual NAT endpoint. No TCP source port is reused or inferred.
6. One server TUN and UDP listener serve all clients. Maps connect compact session IDs, client VPN addresses, endpoints, and traffic-key state.
7. Client TUN packets become AES-GCM DATA frames. The server decrypts them into `pqvpn0`; Linux forwarding and the project-specific nftables masquerade route them to WAN. Return packets are selected by inner destination, encrypted, and injected into the client TUN.

Every record header is AAD, including its DATA/CONTROL channel. Each channel and direction has an independent key, nonce base, send counter, and receive state. Sequence allocation plus encryption is atomic. DATA uses a locked 128-packet replay window; ordered CONTROL requires exactly the next sequence. TCP control rekey and re-handshake use one-way explicit key confirmation: the server proves possession of the new keys to the client before the client activates. The client's possession is confirmed implicitly by its first valid frame under the new epoch. On a failed check the client closes the session.

Production never falls back to socket-pipe TUN. Emulation requires `--dev-emulated-tun`. Host changes are transactional on the client; server firewall helpers own isolated nftables tables and do not flush user rules.

Current limitations are tracked in the README: IPv4 routing is implemented; IPv6 forwarding/data-route coverage, optional kill switch, and dynamic PMTU discovery remain future work. Post-compromise security via hybrid re-handshake and stateless DoS-resistance cookies are implemented in v3. The root namespace integration marker requires a privileged Linux runner and is not evidence until executed there.

## Deployment and diagnostics

`vpn/config.py` validates TOML before networking. Relative paths and omitted identity
filenames resolve beside the TOML. `vpn/identity.py` checks private permissions,
server ML-KEM pair consistency and the authorized-client database; locked atomic
updates use file fsync, replace and directory fsync. Static leases are excluded from
dynamic allocation, and configured maximum clients cannot exceed usable subnet capacity.

`vpn/network.py` renders scoped client/host/private isolation and WAN NAT;
`scripts/server-network.sh setup` atomically replaces only PQVPN-owned tables and preserves
the original forwarding sysctl once. Cleanup restores that value. The systemd unit
runs these helpers around the daemon. Raw Python and current Docker entrypoints do
not invoke the helpers: Docker examples require explicit setup and remain runtime
unvalidated. Client Docker managed DNS also requires a resolver manager unavailable
in the base image; an explicit development `dns_mode="none"` accepts unmanaged DNS.
Compose configuration checks establish syntax only.

`vpn/doctor.py`, exposed as `python -m vpn.cli doctor server|client --config PATH`,
reads deployment state without creating TUN, binding ports or changing routes/DNS.
FAIL rows return 1; PASS/WARN-only results return 0. Temporary native test identities
allow validating its operation without provisioning a real deployment.

Server session expiry and client authenticated UDP receive deadlines use monotonic
clocks. A UDP blackhole causes FAILED and transactional cleanup; accepted DATA can
keep the client alive without PONG. Managed DNS setup is transactional and split DNS
only installs configured routing domains. Source rate-limit state is capped and stale
entries are pruned on subsequent traffic.

The desktop client (`app/client.py`) replaces the prior browser management API. A normal-user
PySide6 GUI communicates with a privileged client service over a Unix domain socket.
The service manages VPNClient lifecycle, TUN, routes, DNS, and IPv6 policy. The prior
FastAPI/PyWebView management stack was removed. See the
[validation matrix](security_audit.md#pre-vps-hardening--2026-09-07).

## Managed desktop onboarding

Desktop Milestone 3 has two deliberately separate configuration sources:

- `app.client --service --config PATH` is legacy/development mode and loads only
  that explicit TOML file.
- `app.client --service` is installed managed mode and loads only a selected public
  profile plus the service-owned device identity under `/var/lib/pqvpn`.

No values are merged and managed state never changes the explicit TOML workflow.
Managed mode creates the Ed25519 device identity once under
`/var/lib/pqvpn/identity`: the directory is mode `0700`, the private raw key is
`0600`, and the public raw key is `0644`. Existing identities are opened without
following symlinks, validated for type/mode/length/keypair consistency, and never
rotated by `ensure_client_identity()`.

Profiles are stored atomically and deterministically in
`/var/lib/pqvpn/profiles/profiles.json` mode `0600`; extracted server public keys
are mode `0644` below a mode-`0700` service directory. The store contains only
version, exact active profile ID, and up to five public profiles. Five keeps a full
profile list within the unchanged 16 KiB IPC frame. Duplicate IDs are rejected
unless replacement is explicitly requested. Removing the active profile selects
none. Import/select/remove are refused while a connection is active or changing,
so the live `VPNClient` is never silently retargeted.

### `.pqvpn` schema

JSON is UTF-8, at most 8,192 bytes, rejects duplicate properties, and contains
exactly these fields:

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

Unknown fields—including secret, command, token, and arbitrary-path fields—are
rejected. Parsing performs no interpolation, command execution, URL retrieval, or
trust-on-first-use.

### `.pqenroll` schema

JSON is UTF-8, at most 4,096 bytes, rejects duplicate properties, and contains
exactly `version` (`1`), a strict 1–64 character `client_id`, canonical Base64 of
the 32-byte raw Ed25519 public key, its matching lowercase SHA-256 fingerprint,
and a UTC `created_at` timestamp (`YYYY-MM-DDTHH:MM:SSZ`). It is public enrollment
data only. The administrator validates it and feeds the public key to the existing
locked, atomic `AuthorizedClients` store. Enrollment remains offline and
administrator-approved; generating/exporting a request does not assert approval.

### IPC boundary

Milestone 3 adds `SETUP_STATUS`, `ENSURE_IDENTITY`, `LIST_PROFILES`,
`IMPORT_PROFILE`, `SELECT_PROFILE`, `DELETE_PROFILE`, and
`EXPORT_ENROLLMENT_REQUEST`. The four-byte length prefix, 16 KiB maximum,
`SO_PEERCRED` authorization, one service-owned `VPNClient`, serialized mutations,
and error sanitization remain. Import sends bounded profile JSON rather than a
root-readable path. Enrollment export returns public JSON for the normal-user GUI
to save; IPC has no generic file-write, TOML-write, command-execution, restart, or
private-key operation.

## Unsupported IPv6 and revocation

`vpn/network.py` implements client-local IPv6 policy without altering the v2 protocol.
Full mode defaults to an atomic, randomly named, exclusively created `ip6` nftables
table blocking non-loopback OUTPUT and FORWARD. `ClientNetwork` owns its cleanup
alongside routes/DNS; disconnect and failure paths remove that exact table. Split
mode leaves IPv6 alone unless `block` is explicit. `fail` checks visible connectivity
before mutation; `allow` warns about bypass. This is IPv4 tunneling with IPv6 leak
prevention, not routed IPv6 support. See [client policy](deployment.md#ipv6-policy).

Authorized-client revocation affects future ClientHello authorization. Existing
sessions and already-authorized handshakes are not actively terminated. Server restart
terminates all sessions; no live reload/remote termination mechanism is implemented.
Native source provenance is pinned to the exact 0.16.0 commit in
`constraints-tested.txt`; cryptographic components and versions are unchanged.

## Cryptographic and Protocol Design
### Protocol v2

This is a KEMTLS-inspired research protocol, not formal KEMTLS. Its static KEM identity design reduces post-quantum handshake communication overhead and fragmentation/segmentation pressure; it does not eliminate fragmentation.

Production has one suite: X25519, ML-KEM-768, HKDF-SHA256, Ed25519 client identities, and AES-256-GCM. The client is provisioned with the SHA-256 fingerprint of the server's 1,184-byte static ML-KEM public key. The server is provisioned with enabled Ed25519 client public-key fingerprints.

## Handshake

Every handshake message has `magic:u16 | version:u8 | type:u8 | payload_length:u16`. TCP adds a four-byte length. Both lengths must exactly match; the maximum control message is 16,384 bytes.

- ClientHello: random(32), session ID(32), ephemeral X25519 public(32), ephemeral ML-KEM public(1184), Ed25519 client public(32).
- ServerHello: random(32), echoed session ID(32), ephemeral X25519 public(32), ML-KEM ciphertext to the client's ephemeral key(1088), SHA-256 identity identifier(32). The provisioned 1,184-byte static key is not retransmitted.
- ClientKeyExchange: ciphertext to the static server identity key(1088), Ed25519 transcript proof(64), client Finished(32).
- ServerFinished: server Finished(32). Only possession of the pinned static ML-KEM private key produces the authentication secret needed for this MAC.

The hybrid input is the ephemeral X25519 secret, one client-ephemeral ML-KEM session secret, and the static authenticated server-KEM secret. The removed server-ephemeral ML-KEM direction duplicated the ephemeral PQ role without providing a distinct authentication role. The retained client ML-KEM key is fresh for each handshake; the static KEM has the separate server-possession role. This unproven protocol simplification requires independent review.

Exact wire sizes are ClientHello 1,318 bytes, ServerHello 1,222 bytes, ClientKeyExchange 1,190 bytes, and ServerFinished 38 bytes: 3,768 bytes total including handshake headers.

HKDF context includes protocol/version, algorithms, session ID, randoms, role-specific labels, and transcript hash. Expansions yield independent data C2S/S2C keys and nonce bases, independent control C2S/S2C keys and nonce bases, Finished keys, a rekey secret, and a control-confirmation key.

## Encrypted frame

All integer fields are network byte order. The 26-byte clear header is authenticated as AES-GCM AAD:

| Field | Bytes |
|---|---:|
| Magic `PV` | 2 |
| Version `0x20` | 1 |
| Channel: DATA or CONTROL | 1 |
| Frame type | 1 |
| Direction | 1 |
| Compact session ID | 8 |
| Key epoch | 4 |
| Sequence | 8 |
| Encrypted payload | variable |
| GCM tag | 16 |

Frame types are DATA, UDP_BIND, UDP_BIND_ACK, PING, PONG, CLOSE, CONFIG, REKEY_REQUEST, REKEY_RESPONSE, and ERROR. Record overhead is exactly 42 bytes before outer IP/UDP headers. DATA and CONTROL have different HKDF keys, nonce bases, counters, and receive state. DATA uses a 128-packet replay window; ordered TCP CONTROL requires exactly the next authenticated sequence. Records cannot authenticate in the other channel. Sequence allocation through encryption/increment is serialized, as is replay eligibility through successful authentication/commit.

After the TCP handshake the server sends encrypted CONFIG. The client sends an encrypted UDP_BIND to the configured UDP port. Only an authenticated `UDP_BIND` with payload `bind` can establish its observed source endpoint. Once bound, a different endpoint is rejected; reconnect to change it. DATA is then accepted only from that endpoint.

Rekey request payload is `next_epoch:u32 || nonce:32`. The server returns `next_epoch || HMAC(control_key, label || request)`, encrypted under the current epoch, then both activate independently derived next-epoch directional material. Replayed/non-monotonic epochs are rejected. This hash-based rekey is key rotation, not post-compromise security.

### Protocol v3

v3 (`0x30`) replaces classical Ed25519 client authentication with ML-KEM-768
static key mutual authentication. Both sides authenticate by encapsulating to
the peer's pre-shared static ML-KEM key; only the true key owner can
decapsulate and derive the Finished MAC. Design decision: [D1](#d1-client-authentication-flow-for-v3).

Suite: X25519, ML-KEM-768, HKDF-SHA256, ML-KEM-768 client identities, AES-256-GCM.
No signatures in the handshake.

- ClientHelloV3: random(32), session ID(32), ephemeral X25519 public(32), ephemeral ML-KEM public(1184), SHA-256 of client static ML-KEM public(32).
- ServerHelloV3: random(32), echoed session ID(32), ephemeral X25519 public(32), ML-KEM ciphertext to client ephemeral(1088), SHA-256 identity identifier(32), ML-KEM ciphertext to client static key(1088).
- ClientKeyExchangeV3: ciphertext to server static identity key(1088), client Finished(32). No signature.
- ServerFinishedV3: server Finished(32).

Wire sizes: ClientHelloV3 1,318 B, ServerHelloV3 2,310 B, ClientKeyExchangeV3 1,126 B, ServerFinishedV3 38 B: **4,792 B total** (+1,024 B vs v2).

Key schedule: two-stage HKDF. Ephemeral handshake secret from X25519_ss + K_eph; authenticated master secret from K_S + K_C + transcript. Same label/channel separation as v2.

v2 remains fully functional; `protocol_version` in config selects v2 or v3.

### Hybrid re-handshake (post-compromise security)

v2's hash-based rekey derives successors from the prior `rekey_secret` plus a public
nonce. It provides key evolution, not post-compromise recovery: compromise of the
current rekey secret exposes future epochs.

v3 adds a hybrid re-handshake that restores secrecy by contributing fresh ephemeral
key material from both sides. The exchange uses `REHANDSHAKE_REQUEST` and
`REHANDSHAKE_RESPONSE` CONTROL frames over the existing encrypted control channel:

```
Client                                              Server
REHANDSHAKE_REQUEST: epoch(4) || X25519_eph_pub(32) || ML-KEM_eph_pub(1184)
                                ───────────────►
REHANDSHAKE_RESPONSE: epoch(4) || X25519_eph_pub(32) || ct(1088) || confirm(32)
                                ◄───────────────
```

Both sides compute: `dh_ss = X25519(local_priv, peer_pub)` and
`k_mlkem = KEM.Decaps(sk, ct)` or `ct, k_mlkem = KEM.Encaps(pk)`.

New epoch secrets: `seed = SHA-256(old_rekey_secret || dh_ss || k_mlkem || epoch)`,
then HKDF expansion with `session_id || epoch || SHA-256(request || response_body)`
as context. The server appends a key confirmation HMAC:
`confirm = HMAC-SHA256(new_control_confirm_key, "rehandshake confirm" || request || response_body)`.
The client verifies this in constant time before activating the new epoch; on
mismatch it tears the session down.

Fresh X25519 + ML-KEM material restores secrecy against a **passive** adversary
after full epoch-state compromise, and against an **active** adversary who learned
only traffic/control keys (not the rekey secret). An active adversary who obtained
the full epoch state (including the rekey secret) can forge the re-handshake
exchange and is **not** recovered from; this is a stated limitation.

The PCS Tamarin model (`formal/pqvpn_v3_pcs.spthy`) verifies these properties:
`pcs_control_keys_only` and `pcs_passive_after_epoch_compromise` prove the
recovery claims, while `attack_active_after_epoch_compromise` formally documents
the active-attacker limitation.

Re-handshake is configurable via `rehandshake_interval` (seconds, default 0 =
disabled). It uses the same locking and epoch-switch logic as rekey, so there is
no packet-loss window during activation.

**Breaking change:** the `REHANDSHAKE_RESPONSE` grew from 1,124 to 1,156 bytes
(32-byte confirmation HMAC appended). Re-handshake requires both peers to run
this version or later. Mismatched peers fail closed with "invalid rehandshake
response length". Re-handshake is off by default, so the impact is limited to
deployments that have explicitly enabled it.

### Stateless cookie (DoS resistance)

ML-KEM decapsulation on unauthenticated input lets an attacker burn server CPU.
A stateless HMAC cookie (WireGuard/DTLS pattern) gates expensive cryptographic
work behind a source-address verification round-trip.

```
Client                                              Server
ClientHello
                                ───────────────►
                      COOKIE_CHALLENGE: cookie(32)
                                ◄───────────────
COOKIE_RESPONSE: cookie(32) || original ClientHello
                                ───────────────►
                                    (normal handshake proceeds)
```

Cookie = `HMAC-SHA256(rotating_server_secret, client_ip || port || time_bucket)`.
The server secret rotates every 120 seconds; verification accepts both the current
and previous secret/bucket pair for graceful rotation. The server performs **no
KEM work and keeps no per-connection state** until the cookie is validated.

Configuration: `cookie_mode` = `off` (default) / `under_load` / `always`.
In `under_load` mode, challenges are issued when the number of pending handshakes
exceeds `cookie_threshold` (default 10). The cookie adds one round-trip to the
handshake but is transparent to the client — it automatically wraps and resends.

Works with both v2 and v3 protocols.

### Protocol v3-mldsa (comparison suite)

v3-mldsa (`0x31`) is an experimental comparison suite that replaces v3-kem's KEM-based
client authentication with ML-DSA-44 (Dilithium) signatures. Server authentication
remains ML-KEM-768 static key possession (same as v2/v3). This provides a fair
same-codebase comparison: both v3-kem and v3-mldsa are fully post-quantum, but
v3-mldsa uses the traditional signature approach while v3-kem is signature-free.

Suite: X25519, ML-KEM-768, ML-DSA-44, HKDF-SHA256, AES-256-GCM.

- ClientHelloMLDSA: random(32), session ID(32), ephemeral X25519 public(32), ephemeral ML-KEM public(1184), SHA-256 of client ML-DSA-44 public(32).
- ServerHelloMLDSA: random(32), session ID(32), ephemeral X25519 public(32), ML-KEM ciphertext to client ephemeral(1088), identity ID(32). No ct_C.
- ClientKeyExchangeMLDSA: ciphertext to server static key(1088), ML-DSA-44 signature(2420), Finished(32).
- ServerFinishedMLDSA: server Finished(32).

Wire sizes: ClientHello 1,318 B, ServerHello 1,222 B, ClientKeyExchange 3,546 B, ServerFinished 38 B: **6,124 B total** (+1,332 B vs v3-kem).

The larger wire total demonstrates the bandwidth cost of PQ signatures vs KEM-based
authentication. ML-DSA-44 signatures are 2,420 B vs ML-KEM-768 ciphertexts at 1,088 B,
and v3-mldsa also loses the server-to-client ct_C savings since the server no longer
needs to encapsulate to the client's static key.

Key schedule: single-stage. Mixes ephemeral DH + ephemeral KEM + static KEM to server.
No bidirectional static KEM secrets (unlike v3-kem which mixes K_S + K_C).

Selectable via `experimental_suite = "v3-mldsa"` in config or `--suite v3-mldsa` in benchmarks.

### Authentication boundary

**v2:** Static ML-KEM-768 authenticates the server; X25519 + ML-KEM-768 establish
hybrid session keys. Ed25519 authenticates clients and is classical, not
post-quantum. This is not fully post-quantum mutual authentication.

**v3:** Fully post-quantum mutual authentication. Both server and client
authenticate via ML-KEM-768 static key possession proofs. No classical
signatures remain in the handshake. A Tamarin Prover model
(`formal/pqvpn_v3.spthy`, `formal/pqvpn_v3_pcs.spthy`) verifies session key
secrecy, forward secrecy, injective server/client authentication, KCI
resistance, and post-compromise security under a Dolev-Yao adversary.

Status: deployable research/prototype PQ-VPN. Passing automated and live validation
does not revise the custom-protocol or assurance limitations.

## Session liveness

Authenticated keepalive traffic refreshes session liveness. Invalid, unauthenticated,
replayed, or wrong-endpoint traffic does not. UDP PING and PONG retain the existing
DATA-domain directional AES-256-GCM protection and replay/epoch checks; PING has
an eight-byte timestamp payload. Only accepted inner IPv4 DATA (including assigned
source-IP validation), valid endpoint binding, and authorized CONTROL activity
count. A bound endpoint cannot be replaced by traffic from another endpoint;
reconnect to establish a new binding. Rekey activity counts only after validation.

A quiet session with healthy PING/PONG survives `idle_timeout`; a genuinely inactive
session still expires. Expiry removes session/IP mappings and the endpoint, releases
the lease, wipes session keys best-effort, closes control, and logs the reason with
client ID and VPN IP, without key material. Client control-loss detection enters
FAILED and runs network cleanup. The absolute `session_timeout` remains independent
of keepalive. Python cannot guarantee complete key zeroization.

Server idle and absolute session expiry use monotonic clocks. Independently, the
client tracks `last_authenticated_udp_rx`: initial valid UDP_BIND_ACK, matching
PONG, or a complete IPv4 DATA packet addressed to its assigned IP refreshes the
receive deadline. Wrong endpoint/session/epoch, replay, bad tag and malformed data
do not. Outgoing PING and CONTROL rekey cannot mask a UDP blackhole. Exceeding
`dead_peer_timeout` enters FAILED and performs route/DNS/TUN/socket cleanup.
The wire format and 1,318 / 1,222 / 1,190 / 38-byte handshake remain unchanged by
the final validation pass.

IPv6 leak prevention is a local client network policy, not a v2 wire extension.
The tunnel remains IPv4-only; full mode blocks unsupported IPv6 by default. Client
revocation disables future ClientHello authorization and does not terminate sessions
already authenticated. Both boundaries are detailed in the deployment/client guides.

## Threat Model and Limitations
### Threat Model

PQVPN protects IP packets between an authenticated client and a provisioned server against passive observers, active network attackers, replay, cross-session injection, and unauthorized clients. The server public-key fingerprint and client authorization database are trusted provisioning inputs. Server compromise, endpoint compromise, traffic analysis, denial of service, malicious kernel/root, and compromise of provisioning are out of scope.

ML-KEM mock mode is explicitly insecure and is limited to development/test operation. Production startup requires runtime-enabled ML-KEM-768 and a successful self-test. No silent TOFU exists.

The custom protocol has not received independent cryptographic review or a formal proof. Ed25519 authenticates clients while the server uses a static ML-KEM possession proof. Long-term server identity compromise permits impersonation and may affect recordings involving that static KEM contribution; ephemeral X25519 and one client-ephemeral ML-KEM exchange remain separate inputs. A second bidirectional ephemeral ML-KEM exchange was removed because it duplicated the ephemeral PQ role rather than authentication; this judgment requires independent review.

Frequent epoch rekey derives successors from the prior `rekey_secret` plus a public nonce. It provides key evolution, not post-compromise recovery: compromise of the current rekey secret plus observation/decryption of the rekey records can expose future epochs. v3 adds a hybrid re-handshake that mixes fresh X25519 + ML-KEM ephemeral material to restore secrecy after state compromise (see *Hybrid re-handshake* above).

The data plane is a Python userspace packet loop (TUN ↔ UDP AES-256-GCM). Profiling shows ~10 µs per packet (~100k pps), with Python overhead (nonce XOR, struct, locks) accounting for 2–3× the raw AES-GCM cost (~0.9 µs). This is comparable to OpenVPN (C userspace, ~5–15 µs) but far slower than WireGuard (kernel, ~0.3 µs). The research contribution is the handshake and control plane; throughput is reported as a functional check with the limitation stated openly. Decision: [D6](#d6-data-plane-implementation-scope).

Python cannot guarantee erasure of all secret copies. Mutable long-lived buffers are overwritten on rekey/disconnect as best-effort in-process zeroization; interpreter, library, allocator, swap, and core-dump copies may remain.

### Authentication boundary

PQVPN KEMTLS-inspired v2 is a custom protocol, not standardized KEMTLS.
Static ML-KEM-768 authenticates the server; X25519 + ML-KEM-768 establish
hybrid session keys. Ed25519 authenticates clients and is classical, not
post-quantum. This is not fully post-quantum mutual authentication.
Status: deployable research/prototype PQ-VPN. Existing root and VM/client evidence
does not revise the custom-protocol or assurance limitations.

## Session liveness

Authenticated keepalive traffic refreshes session liveness. Invalid, unauthenticated,
replayed, or wrong-endpoint traffic does not. UDP PING and PONG retain the existing
DATA-domain directional AES-256-GCM protection and replay/epoch checks; PING has
an eight-byte timestamp payload. Only accepted inner IPv4 DATA (including assigned
source-IP validation), valid endpoint binding, and authorized CONTROL activity
count. A bound endpoint cannot be replaced by traffic from another endpoint;
reconnect to establish a new binding. Rekey activity counts only after validation.

A quiet session with healthy PING/PONG survives `idle_timeout`; a genuinely inactive
session still expires. Expiry removes session/IP mappings and the endpoint, releases
the lease, wipes session keys best-effort, closes control, and logs the reason with
client ID and VPN IP, without key material. Client control-loss detection enters
FAILED and runs network cleanup. The absolute `session_timeout` remains independent
of keepalive. Python cannot guarantee complete key zeroization.

## Deployment boundaries

Authenticated clients are isolated by the PQVPN-owned nftables policy: no peer
forwarding, no arbitrary VPS host services, and no metadata/private forwarding
without an explicit configured destination exception. Optional ICMP echo to the
server VPN IP is the only host-service exception. This policy needs the setup helper;
starting the Python daemon alone does not install firewall/NAT rules. Existing host
and provider policy remains an independent boundary.

Client UDP receive deadlines detect a blackholed data path even when TCP is alive.
Route/DNS restoration on detected failure restores ordinary connectivity; it is
not a kill switch. Managed full-tunnel DNS fails setup when its resolver manager is
unavailable; `dns_mode="none"` explicitly accepts DNS leakage risk. Routed IPv6 and
dynamic authenticated PMTU discovery remain unsupported/incomplete.

The removed browser management stack is not part of the current runtime. The desktop
GUI uses bounded local Unix-socket IPC with `SO_PEERCRED`; local configuration,
private identities, and the service's CAP_NET_ADMIN privilege are trusted. Private
keys require mode 0600/0400 and server
ML-KEM keypairs are tested for consistency. These checks and passing regression/native
and live tests do not substitute for independent protocol review or production assurance.

## IPv6 leakage and revocation boundaries

The IPv4-only tunnel previously left a functional physical IPv6 path available.
Full-tunnel default policy now blocks non-loopback IPv6 output and forwarding using
an owned temporary nftables table. Split mode does not implicitly block unrelated
IPv6. `allow` explicitly accepts exposure of the normal IPv6 source; `fail` rejects
visible IPv6 at setup but is only a snapshot. No IPv6 tunnel or protocol change was
introduced. Network changes after a `fail` preflight are not continuously monitored;
use `block`. SIGKILL/crash can leave the temporary block installed, and root can remove
or bypass the policy. Real kernel enforcement still requires namespace validation.

Revocation rejects new authentication; it does not retroactively invalidate active
sessions or in-progress handshakes already authorized. Restart the server to terminate
all sessions immediately. Ordinary idle/absolute expiry remains unchanged.

## Benchmarking and measurement harness

`python -m benchmarks --all --profile <name>` runs the full benchmark suite (handshake
latency, throughput, packet overhead, charts) and writes raw JSON/CSV to
`results/<date>-<commit>/`. Every result row includes the git commit, protocol version,
liboqs version, CPU model, and iteration count. Handshake statistics report median, p95,
p99, standard deviation, and separate client/server CPU time.

Eight network profiles are defined for `tc netem` emulation:

| Profile | RTT (ms) | Loss (%) | MTU |
|---|---|---|---|
| lan | 0 | 0 | 1500 |
| metro | 50 | 0 | 1500 |
| continent | 200 | 0 | 1500 |
| lossy-1 | 50 | 1 | 1500 |
| lossy-5 | 50 | 5 | 1500 |
| mtu-1280 | 50 | 0 | 1280 |
| mtu-1400 | 50 | 0 | 1400 |
| worst | 200 | 5 | 1280 |

The `lan` profile runs in-process without network namespaces. Other profiles require
root and use `scripts/bench_netem.sh` to create isolated namespaces with `tc netem`
rules applied to both ends of a veth pair. The v2 baseline is tagged as
`v2-research-baseline` and frozen for comparison with later protocol versions.

---

## Design decisions

### D1: Client authentication flow for v3

**Context.** v2 uses Ed25519 signatures for client authentication — the only classical
cryptographic primitive remaining in the handshake. Replacing it with ML-KEM
makes the system fully post-quantum mutually authenticated without any signatures.

Both long-term public keys are pre-shared: the client pins the server key
(from `.pqvpn`), and the server stores the client key (from `.pqenroll`).
Each side can authenticate the other by encapsulating to the peer's static
key — only the true key owner can decapsulate and derive the Finished MAC.

**Options.**
- A: Keep current message shape. `ct_S` stays in ClientKeyExchange; server adds
  `ct_C` to ServerHello. Minimal change from v2. Client identity hash is sent in the
  clear (same exposure as v2's Ed25519 public key). 1.5 RTT.
- B: PDK-style. `ct_S` moves into ClientHello; client identity is encrypted under a
  key derived from `K_S`. Hides client identity from passive observers. Larger
  ClientHello, replay handling needed, more modelling work.

**Choice: Option A.** Minimal wire-format delta from v2 — easier to verify correctness
and model in Tamarin. Client identity exposure is equivalent to v2. Option B can be
revisited after the Tamarin model is stable.

Wire sizes (Option A):

| Message | v2 | v3 | Delta |
|---|---|---|---|
| ClientHello | 1,318 | 1,318 | 0 |
| ServerHello | 1,222 | 2,310 | +1,088 (ct_C) |
| ClientKeyExchange | 1,190 | 1,126 | −64 (no signature) |
| ServerFinished | 38 | 38 | 0 |
| **Total** | **3,768** | **4,792** | **+1,024** |

Key schedule:

```
ES  = HKDF-Extract(salt, X25519_ss ‖ K_eph)     — ephemeral handshake secret
AS  = HKDF-Extract(ES,  K_S ‖ K_C ‖ transcript)  — authenticated master secret
```

From AS, derive Finished keys, data/control keys, rekey secret, and
confirmation key using the same HKDF-Expand labels as v2.

### D6: Data-plane implementation scope

**Context.** The Python packet loop (TUN read → AES-GCM encrypt → UDP send, and reverse)
will lose to WireGuard (kernel) and OpenVPN (C userspace) on throughput.

Profiling (2026-10-01) on the project host with 10,000 × 1,400 B synthetic IPv4 packets:

| Component | µs/pkt | Notes |
|---|---|---|
| AES-256-GCM encrypt (raw openssl) | 0.90 | Via `cryptography` Rust binding |
| AES-256-GCM decrypt (raw openssl) | 0.91 | Same |
| Python `encrypt_frame` total | 3.2 | Nonce XOR, struct.pack, lock, list append |
| Python `decrypt_frame` total | 4.0 | + enum lookup, replay window, struct.unpack |

Per-packet budget: ~8–12 µs → ~80k–125k pps theoretical.

**Options.**
- A: Scope it. Contribution is the handshake and control plane. Effort: zero.
- B: Native data plane. Move framing to Rust (PyO3) or C. Effort: 2–4 weeks.

**Choice: Option A.** The research contribution is the handshake. Python throughput
(~100k pps, ~1.1 Gbps for 1,400 B packets) is adequate for functional validation
and comparable to OpenVPN (~5–15 µs/pkt). The bottleneck is Python overhead, not
crypto. A native rewrite introduces build complexity orthogonal to the research
question. The paper states the limitation openly.
