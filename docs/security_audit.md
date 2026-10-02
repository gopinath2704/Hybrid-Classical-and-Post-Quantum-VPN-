# Security Audit — 2026-09-05

The A-01–A-19 findings below describe the original audit snapshot; their original
status lines are historical. The remediation updates and final validation matrix
below are authoritative for the current files.

Scope: complete repository at the start of the 2026-09-05 remediation. Code, not prior status claims, was treated as authoritative. This protocol is a KEMTLS-inspired research protocol; it is not formally compatible with KEMTLS and has no formal security proof. The design goal is to reduce post-quantum handshake communication overhead and fragmentation/segmentation pressure.

## A-01 — Server is not authenticated

Severity: Critical  
Component: Handshake authentication  
File/function: `handshake/kemtls.py`, `KEMTLSClient.process_server_hello`, `KEMTLSServer.process_client_key_exchange`  
Problem: Finished MACs use only attacker-negotiable ephemeral X25519 and ML-KEM secrets. No provisioned long-term server identity is checked.  
Impact: An active attacker can establish independent sessions with client and server.  
Attack/failure scenario: A network MITM replaces both handshake flights and produces valid Finished MACs for each leg.  
Fix: Add a static ML-KEM-768 server identity, client-side SHA-256 fingerprint pinning, an identity-key encapsulation whose secret enters the key schedule, and transcript binding of the identity public key and ciphertext.  
Verification: Wrong-pin and identity-substitution tests; valid pinned handshake test.  
Status: Confirmed; remediation in progress.

## A-02 — Clients are not authenticated or authorized

Severity: Critical  
Component: Access control  
File/function: `handshake/kemtls.py`; `vpn/runtime.py:VPNServer._client`
Problem: The server accepts any syntactically valid handshake.  
Impact: Any network user can obtain tunnel access and consume server resources.  
Attack/failure scenario: An unaffiliated client completes an ephemeral handshake and receives usable data-plane keys.  
Fix: Add client Ed25519 identity proof bound to the transcript and an enabled-client fingerprint database with optional fixed IP.  
Verification: Authorized-client success and unauthorized/revoked-client rejection tests.  
Status: Confirmed; remediation in progress.

## A-03 — Legacy/ambiguous PQC selection and unsafe wire choices

Severity: High  
Component: PQC provider and negotiation  
File/function: `crypto/hybrid_crypto.py` import probe and `PQCProvider`; `vpn/cli.py --pqc`  
Problem: Startup assumes `Kyber768`, never queries enabled mechanisms, offers three variants while the handshake parser is fixed to 1184/1088-byte ML-KEM-768 values, and labels legacy identifiers as standardized ML-KEM.  
Impact: Native deployments can fail with current liboqs identifiers; alternate CLI choices produce parser incompatibility and misleading security posture.  
Attack/failure scenario: A deployment selects Kyber512/1024 and peers disagree with fixed sizes, or current liboqs exposes only `ML-KEM-768`.  
Fix: Query `oqs.get_enabled_kem_mechanisms()`, select only standardized `ML-KEM-768`, fail closed in production, and self-test keygen/encap/decap.  
Verification: Provider-detection, mock-posture, and native-PQC marked tests.  
Status: Confirmed; remediation in progress.

## A-04 — Non-directional key schedule

Severity: Critical  
Component: Key derivation/data plane  
File/function: `handshake/kemtls.py:HandshakeSession` and both handshake state machines  
Problem: One encryption key, one MAC key, and one sequence counter are used for both directions; derivation context omits roles, protocol identifiers, session ID, and final transcript hash.  
Impact: Nonce/key domain separation is absent and reflection/cross-direction misuse is possible.  
Attack/failure scenario: Both peers encrypt sequence zero under the same AES-GCM key, immediately risking nonce reuse.  
Fix: Derive separate Finished keys, directional traffic keys, nonce bases, rekey/control/exporter secrets from a transcript- and session-bound master secret.  
Verification: Directional-key inequality and cross-direction rejection tests.  
Status: Confirmed; remediation in progress.

## A-05 — AES-GCM nonce construction and replay handling are unsafe

Severity: Critical  
Component: Encrypted record layer  
File/function: `handshake/kemtls.py:HandshakeSession.encrypt_frame/decrypt_frame`  
Problem: Nonces are `sequence || random32`, use the same key in both directions, AAD is `None`, receive sequence state is absent, and exact frames can be replayed indefinitely.  
Impact: Nonce collision/reuse can break GCM confidentiality/integrity; metadata is movable across sessions; replayed IP packets are accepted.  
Attack/failure scenario: Duplicate ciphertext injects duplicate inner traffic; birthday collisions in the 32-bit suffix occur under a reused directional key space.  
Fix: Clear authenticated header, deterministic nonce-base XOR sequence, independent directional keys/counters, epoch validation, and a 128-packet replay window committed only after successful authentication.  
Verification: Replay, out-of-order, nonce uniqueness, wrong-session/direction/epoch tests.  
Status: Confirmed; remediation in progress.

## A-06 — Rekey cannot synchronize

Severity: High  
Component: Control protocol  
File/function: `handshake/kemtls.py:HandshakeSession`; `vpn/runtime.py:VPNClient.rekey`, `VPNServer._rekey_server`
Problem: A locally random nonce derives and activates new keys without being transmitted. Declared rekey message constants are unused.  
Impact: The initiating peer immediately loses interoperability with its peer.  
Attack/failure scenario: Scheduled client rekey causes all subsequent packets to fail authentication.  
Fix: Authenticated counter-framed control messages with monotonic epoch, request nonce, response confirmation, and coordinated activation.  
Verification: Synchronized rekey, replayed-rekey rejection, post-rekey traffic, and old-epoch rejection tests.  
Status: Confirmed; remediation in progress.

## A-07 — UDP endpoint negotiation is functionally broken

Severity: Critical  
Component: UDP data-plane establishment  
File/function: `vpn/runtime.py:VPNClient.connect`, `VPNServer._client`, `VPNServer._handle_datagram`
Problem: Client sends UDP to the TCP destination port; server sends UDP to the client's TCP source address and binds an unrelated ephemeral UDP socket. TCP and UDP source ports are unrelated.  
Impact: Real data-plane traffic does not reliably reach either endpoint and NAT cannot work.  
Attack/failure scenario: A normal NAT assigns a distinct UDP mapping; server ciphertext is sent to the TCP source port and discarded.  
Fix: One known UDP server port and authenticated `UDP_BIND`/`UDP_BIND_ACK`; learn the client endpoint only from a valid encrypted bind frame.  
Verification: Different TCP/UDP source-port and endpoint-binding tests.  
Status: Confirmed; remediation in progress.

## A-08 — Server architecture cannot support real multi-client routing

Severity: Critical  
Component: Server tunnel architecture  
File/function: `vpn/runtime.py:VPNServer`, `SessionManager`, `IPPool`
Problem: Every connection opens the same TUN name and a separate UDP socket; no session demultiplexer, destination-IP routing map, endpoint map, or IP pool exists.  
Impact: The second native client conflicts; server return packets cannot be assigned to sessions; all clients default to 10.8.0.2.  
Attack/failure scenario: Concurrent users collide on device/IP resources and cannot receive routed responses.  
Fix: One `pqvpn0`, one UDP listener, session-ID/IP/endpoint maps, server-side IP pool allocation/release.  
Verification: Multi-session and allocation/release tests.  
Status: Confirmed; remediation in progress.

## A-09 — No real host/client routing lifecycle

Severity: Critical  
Component: Linux networking  
File/function: `vpn/runtime.py:ClientNetwork`, `VPNClient`, `VPNServer`; `vpn/network.py:render`; deployment files
Problem: Server forwarding/NAT is absent; client default/split routes, transport bypass, DNS setup/restoration, transactional rollback, kill switch, and applied MSS clamp are absent. TUN IP setup errors are ignored.  
Impact: A UI may say CONNECTED while Internet traffic does not traverse the server.  
Attack/failure scenario: Client traffic continues over its original default route; server cannot forward decrypted packets to WAN.  
Fix: Transactional Linux network configurator, server setup/cleanup scripts with project-specific nftables chains, route/DNS restoration, optional kill switch, and actual MSS rules.  
Verification: Namespace integration tests and setup-script validation.  
Status: Confirmed; remediation in progress.

## A-10 — Production silently falls back to an emulated TUN

Severity: High  
Component: TUN lifecycle  
File/function: `vpn/network.py:TUNInterface`; `vpn/runtime.py:open_tun`, `VPNServer.start`
Problem: Missing `/dev/net/tun` or permissions silently select a socket pair, yet connection state becomes CONNECTED.  
Impact: Operators can believe traffic is protected when no traffic can leave the host.  
Attack/failure scenario: A container missing `NET_ADMIN` appears connected but leaks traffic via the normal route.  
Fix: Native TUN is mandatory unless an explicit `--dev-emulated-tun` option is set.  
Verification: Fail-closed and explicit-emulation tests.  
Status: Confirmed; remediation in progress.

## A-11 — MTU accounting is incorrect and unapplied

Severity: Medium  
Component: MTU/fragmentation  
File/function: `vpn/network.py:MTUMonitor`; `benchmarks.py:PacketOverheadAnalyzer`
Problem: Calculations include a nonexistent two-byte UDP length prefix, omit the future authenticated header, do not set the chosen TUN MTU, and only calculate (not apply) MSS values.  
Impact: Inner packets can exceed PMTU and fragment/drop; published overhead is false.  
Attack/failure scenario: Full-size TCP packets exceed the outer path MTU and black-hole on DF paths.  
Fix: Define one frame header, derive exact overhead from it, set TUN MTU, reject oversized inner packets, and apply project-specific MSS clamp.  
Verification: 1500/1400/1280 MTU size tests and namespace traffic tests.  
Status: Confirmed; remediation in progress.

## A-12 — Telemetry is labelled real but never sampled on the tunnel

Severity: Medium  
Component: Quality telemetry  
File/function: `vpn/runtime.py:VPNClient`; `vpn/network.py:NetworkQualityMonitor`
Problem: The monitor is constructed but never fed. Its standalone probe targets arbitrary UDP/33434 and is not authenticated tunnel measurement.  
Impact: Latency, jitter, and loss remain zero and mislead operators.  
Attack/failure scenario: A degraded tunnel is reported as zero-latency/zero-loss.  
Fix: Authenticated encrypted PING/PONG frames on the actual UDP path with timeout accounting.  
Verification: Keepalive RTT/loss tests and API telemetry assertions.  
Status: Confirmed; remediation in progress.

## A-13 — Handshake parsers accept inconsistent/trailing data

Severity: High  
Component: Wire parsing  
File/function: `handshake/kemtls.py`, all `unpack` methods and `_unpack_header`; `vpn/runtime.py:recv_message`
Problem: Parsers check `len(payload) < expected`, ignore declared inner length, accept trailing bytes, and permit zero outer lengths.  
Impact: Transcript/parser differentials and resource abuse become possible.  
Attack/failure scenario: A peer appends ignored bytes that remain transcript-visible or sends malformed nested lengths.  
Fix: Exact total/declared/message-specific lengths, known types, nonzero bounded outer messages, and strict state transitions.  
Verification: Truncation, trailing-byte, mismatch, unexpected-type, and fuzz tests.  
Status: Confirmed; remediation in progress.

## A-14 — Management API and WebSocket are unauthenticated

Severity: Critical  
Component: Management plane  
File/function: `app/backend/api.py`; `vpn/cli.py:_run_server`; `docker-compose.yml`  
Problem: Wildcard CORS with credentials is configured; privileged endpoints and telemetry require no token; dashboard binds/publishes on all interfaces.  
Impact: Remote or browser-based attackers can connect/disconnect/rekey and read operational data.  
Attack/failure scenario: A website or Internet scanner invokes the public management API.  
Fix: Loopback binding by default, bearer-token dependency for APIs, token-authenticated WebSocket, explicit origins, and opt-in remote management.  
Verification: 401/403 API and WebSocket authentication tests.  
Status: Confirmed; remediation in progress.

## A-15 — Fake public infrastructure and measurements

Severity: Medium  
Component: Dashboard profiles  
File/function: `app/backend/api.py:SERVERS`  
Problem: Undeployed `pq-vpn.net` hosts and fabricated load/latency values are presented as available servers.  
Impact: Users are misled and connections fail or can be redirected if those names are controlled later.  
Attack/failure scenario: A user selects a fictitious endpoint believing it is operated by the project.  
Fix: Retain only local/custom/configured profiles and measurements obtained from authenticated sessions.  
Verification: API profile test.  
Status: Confirmed; remediation in progress.

## A-16 — Secret-erasure claims exceed Python guarantees

Severity: Medium  
Component: Key lifecycle  
File/function: `handshake/kemtls.py:HandshakeSession.secure_wipe`; documentation/UI logs  
Problem: Immutable `bytes` are copied into a temporary `bytearray` and only that copy is wiped; logs/docs claim keys are securely/instantly zeroed.  
Impact: Original secret objects may remain in process memory and operational claims are inaccurate.  
Attack/failure scenario: A memory disclosure or core dump recovers an immutable key after “wipe.”  
Fix: Keep long-lived material in mutable buffers where practical, minimize copies, rebuild cipher objects on rekey, wipe those buffers, and document best-effort in-process zeroization.  
Verification: Mutable-buffer wipe tests and documentation review.  
Status: Confirmed; remediation in progress.

## A-17 — Resource exhaustion controls are insufficient

Severity: High  
Component: Server availability  
File/function: `vpn/runtime.py:VPNServer.start`, `VPNServer._client`, `SourceRateLimiter`
Problem: No maximum clients, source rate limiting, session/idle timeout, bounded thread cleanup, or production startup self-test. Listener backlog is five but accepted connections spawn indefinitely.  
Impact: Remote clients can consume threads, sockets, ML-KEM work, and tunnel resources.  
Attack/failure scenario: Repeated slow handshakes or idle control sockets exhaust the server.  
Fix: Semaphores/session manager, handshake deadlines, strict message cap, per-source token bucket, idle/session expiry, and cleanup.  
Verification: Limit/timeout tests.  
Status: Confirmed; remediation in progress.

## A-18 — Deployment artifacts do not produce a routed VPN

Severity: High  
Component: Docker/VPS deployment  
File/function: `Dockerfile`, `docker-compose.yml`, `packaging/common/pqvpn-server.service`, `scripts/server-network.sh`
Problem: Host forwarding/NAT is not configured, management is publicly mapped, source is bind-mounted over the image, static client IP is injected, and no systemd/native deployment exists.  
Impact: `docker compose up` does not satisfy Internet-routing requirements and exposes an unsafe controller.  
Attack/failure scenario: Operator deploys advertised configuration and obtains neither safe routing nor a protected management plane.  
Fix: Native systemd deployment, explicit host networking prerequisites, TCP+UDP publication, secret mounts, and server setup/cleanup helpers.  
Verification: Namespace integration and documented deployment validation.  
Status: Confirmed; remediation in progress.

## A-19 — Existing tests validate happy-path simulation, not security/deployment

Severity: High  
Component: Test assurance  
File/function: `tests/`; `benchmarks/`  
Problem: Tests force mock PQC through environment-dependent collection, assert same bidirectional keys, accept replay, count a socket pipe as integration, and do not exercise identities, authorization, NAT endpoint learning, routing, API auth, native ML-KEM, or namespaces.  
Impact: A passing test count provides false confidence and cannot substantiate production claims.  
Attack/failure scenario: All unit tests pass while the real UDP data plane is unreachable and MITM-vulnerable.  
Fix: Split mock/native markers and add negative security, multi-session, networking, API, and root namespace integration coverage.  
Verification: Marker-separated unit/native/integration runs reported independently.  
Status: Confirmed; remediation in progress.

## Remediation status update

Code-level fixes and unit verification are complete for A-01 through A-08, A-10, A-13 through A-17, and the unit/native portions of A-19. A-09/A-11/A-12/A-18 have functional implementations (transactional IPv4 routes/DNS, isolated nftables NAT/MSS, applied static safe MTU, encrypted PING/PONG, and systemd/Docker documentation), but remain only partially verified until the privileged namespace suite is executed. Dynamic authenticated PMTU adjustment, IPv6 routed operation, the optional kill switch, a stateless pre-PQ cookie, and fresh-hybrid rekey remain known limitations rather than completed claims.

### 2026-09-05 focused follow-up findings

Severity: Critical  
Component: Concurrent record processing  
File/function: `handshake/kemtls.py:HandshakeSession`  
Problem: DATA and CONTROL shared keys/counters/windows, sequence allocation was unlocked, and replay check/decrypt/commit was not atomic.  
Impact: Concurrent encryption could reuse an AES-GCM nonce; concurrent duplicate decryption could accept one packet twice; heavy UDP could age valid TCP records out of the shared replay window.  
Attack/failure scenario: Two worker threads both emit sequence zero or both accept the same ciphertext before either replay commit.  
Fix: Independent DATA/CONTROL HKDF domains and state, locked atomic sequence allocation/encryption, locked authenticate-then-commit DATA replay handling, and exact-next CONTROL sequencing.  
Verification: Concurrent 4,000-record uniqueness/decryption, simultaneous duplicate replay, cross-channel rejection, and delayed-control regression tests.  
Status: Fixed and unit verified.

Severity: Critical  
Component: Inner-packet authorization  
File/function: `vpn/runtime.py:validate_client_packet`, server DATA path  
Problem: An authenticated client could inject an IPv4 packet bearing another source address.  
Impact: Client-to-client identity/IP spoofing and policy bypass.  
Attack/failure scenario: Client `10.8.0.2` submits an inner packet sourced from `10.8.0.3`.  
Fix: Strict IPv4 header/length parsing and equality with the session-assigned address; reject IPv6 until assigned IPv6 routing exists.  
Verification: Assigned, other-client, public-address, and malformed-packet tests plus namespace spoof attempt.  
Status: Fixed and unit verified; namespace verification requires root.

Severity: High  
Component: Client network transaction  
File/function: `vpn/runtime.py:VPNClient.connect`, `ClientNetwork`  
Problem: Failures after partial TUN/route/DNS/socket setup could leak resources or delete routes that existed before PQVPN.  
Impact: A failed connection could leave the host offline or misconfigured.  
Attack/failure scenario: UDP_BIND timeout after route and DNS changes leaves those changes active.  
Fix: Whole-connect rollback, idempotent partial cleanup, exact pre-existing route capture/restoration, and DNS undo registration before dependent operations.  
Verification: Injected UDP bind, route, and partial DNS failures and exact route restoration tests.  
Status: Fixed and unit verified.

Severity: High  
Component: Handshake overhead  
File/function: `handshake/kemtls.py:ServerHello/ClientKeyExchange`  
Problem: The pinned 1,184-byte static server key was retransmitted and a second ephemeral ML-KEM exchange duplicated the ephemeral PQ contribution.  
Impact: Avoidable TCP segmentation/packetization pressure increased total handshake wire size to 7,192 bytes.  
Attack/failure scenario: Constrained paths require more segments and amplify loss sensitivity during setup.  
Fix: Bind only the provisioned key's 32-byte identifier and use ephemeral X25519 + one ephemeral ML-KEM session secret + one static ML-KEM authentication secret.  
Verification: Identity-omission/fingerprint-binding and exact-size tests; regenerated native benchmark.  
Status: Fixed at 3,768 bytes; custom construction still requires independent review.

## Edit-3 session liveness

Severity: High  
Component: Server idle expiry / authenticated activity  
File/function: `vpn/runtime.py:VPNServer._handle_datagram`, `ServerSession.touch`  
Problem: PING/PONG continued but PING did not refresh last_seen; rejected DATA did.  
Impact: Healthy quiet sessions disconnected after the idle timeout, while invalid inner traffic could prolong a session.  
Fix: Update activity only after record authentication and message/endpoint/source authorization; serialize with expiry and rekey.  
Historical verification on 2026-09-06: 18 new test cases; full suite 139 passed, 2 skipped; native ML-KEM 1 passed. Two-second idle timeout with five seconds of healthy PING/PONG passes, and inactive expiry releases resources and triggers client restoration.  
Status: Fixed and loopback/unit verified; real TUN namespace and VPS validation pending.

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

## Final validation — 2026-09-07

Status: **Deployable research/prototype PQ-VPN. Root/TUN integration pending.
Real VPS/client validation pending.** This pass preserved the current v2 handshake,
directional DATA/CONTROL cryptography, replay locks and synchronized epoch rekey.

Validation used a newly created `/tmp/pqvpn-final-venv` with CPython **3.14.7** and
an unchanged `pyproject.toml` / `constraints-tested.txt` installation.
`pip check` passed; every installed constrained package matched its pin.
Native **liboqs-python 0.16.0** loaded the existing **liboqs 0.16.0** installation.
No dependency upgrades, native library build or remote deployment were performed.

| Check | Result | Evidence / limits |
|---|---|---|
| `pytest -q` | PASS | 210 collected; 208 passed, 0 failed, 2 skipped; 37.19s |
| `python -m pytest -q` | PASS | 210 collected; 208 passed, 0 failed, 2 skipped; 36.17s |
| Python compileall | PASS | `python -m compileall -q crypto handshake vpn app benchmarks tests` |
| Server setup shell syntax | PASS | `bash -n scripts/server-network.sh` |
| Server cleanup shell syntax | PASS | `bash -n scripts/server-network.sh` |
| Namespace shell syntax | PASS | `bash -n tests/namespace_vpn.sh` |
| Native installer shell syntax | PASS | `bash -n scripts/install-liboqs.sh` |
| JavaScript syntax | PASS | Extracted inline script parsed by Node's `Function` constructor |
| Docker Compose | PASS | `docker compose config`; development-client profile also validated; images/runtime not tested |
| `git diff --check` | PASS | No whitespace errors |
| Server doctor | WARN, exit 0 | No blocking findings for temporary native profile; external provider/host firewall requires operator verification |
| Client doctor | PASS, exit 0 | Temporary native profile, matching pin, managed resolver and loopback route diagnostic |
| Doctor read-only behavior | PASS | Config/key/database file hashes, modes and mtimes plus links/routes/resolver/forwarding snapshots unchanged; negative diagnostic unit tests retained |
| Native ML-KEM-768 | PASS | `ALLOW_MOCK_PQC=0 python -m pytest -q -m native_pqc`: 2 passed, 208 deselected; 0.56s; native self-test and authenticated session records |
| Native library installation design | PASS | Explicit pinned installer; absent-library regression prevents importing the auto-downloading binding; daemon never invokes installer |
| Dependencies | PASS | Fresh pinned installation, version comparison and `pip check`; server/client exclude GUI/API/test/benchmark dependencies |
| Firewall static validation | PASS | TUN-scoped peer/host/metadata/private filtering, ordered exceptions, WAN/return rules, only owned tables replaced; real nft enforcement pending |
| Reconciliation / ip_forward restoration | PASS (simulated commands) | Deterministic repeat/config changes; both original 0 and 1 restored; repeated setup preserves saved value; unmanaged-disabled setup rejected |
| Dead-peer regression | PASS (loopback) | Healthy PONG and DATA-only survive; blackhole/replay/bad tags fail and clean resources; no outgoing-PING liveness refresh |
| DNS fail-safe | PASS (simulated commands) | Missing manager and partial failure roll back; full `~.` / split policy and explicit unmanaged warning covered; real resolver mutation/restoration pending |
| Configuration / IP allocation | PASS | Strict ports/MTU/subnet/timeouts/rates/interfaces/DNS checks, routed IPv6 rejection, usable-capacity limit and static reservations; omitted identity filenames now TOML-relative |
| Identity consistency | PASS | Real ML-KEM pair check, mismatched pair rejection, strict private permissions and symlink rejection |
| Authorized-client DB validation | PASS | Malformed/duplicate/mismatched identities and unusable/duplicate leases rejected; concurrent locked atomic authorize/revoke covered |
| WebSocket tickets | PASS | Authenticated HTTP issuance, secure randomness, 30-second expiry, single-use pop, replay/random/expired/origin/bearer rejection, bounded/pruned storage |
| Rate-limiter memory bounds | PASS | 1,000 synthetic sources pruned after window expiry on subsequent traffic; unique-source cap enforced |
| Root namespace | SKIPPED | Host UID 1000; TUN is present outside sandbox but root is unavailable to this invocation. Root marker returned SKIP; no namespace or privileged networking executed |
| Real VPS | NOT PERFORMED | No remote VPS/client environment or credentials provided |

The two normal-suite skips are the root namespace test and the mock-only fallback
test when a native provider is present. Native validation used the real provider,
not the insecure mock. The original handoff reruns, before the small final fix/test
additions, also passed: 206 passed / 2 skipped in 36.32s and 36.40s.
System Python initially had no pytest; installation in the fresh pinned environment
resolved invocation availability. Socket-dependent validation ran outside the sandbox
as UID 1000. A focused ASGI test stalled in the restricted sandbox and was terminated;
both complete unrestricted final runs passed with 120-second outer timeouts.

Doctor commands were:

```bash
ALLOW_MOCK_PQC=0 /tmp/pqvpn-final-venv/bin/python -m vpn.cli doctor server --config /tmp/pqvpn-final-doctor/server.toml
ALLOW_MOCK_PQC=0 /tmp/pqvpn-final-venv/bin/python -m vpn.cli doctor client --config /tmp/pqvpn-final-doctor/client.toml
```

The server profile used `service_user="shadow"`, one authorized test client, ports
51820/TCP+UDP, subnet 10.8.0.0/24 and detected WAN `enp0s20f0u2`. Forwarding was 0
with management enabled, so doctor correctly reported its current value without
changing it. The client used native generated identities, a matching fingerprint,
`dns_mode="systemd-resolved"` and `server_host="127.0.0.1"`. That route check does not
validate remote reachability. Standard TOML examples remain unprovisioned templates;
run doctor again using actual `/etc/pqvpn` ownership, keys, network and hostname.

Final changes: repaired omitted TOML identity/database paths resolving from CWD;
added regression coverage for that case and real ASGI HTTP ticket authentication,
plus explicit random-ticket rejection; removed an unused external Chart.js import
and corrected the dashboard record-integrity label. Documentation now matches
native installation order, dependency roles, ticket authentication, firewall/DNS and
UDP dead-peer behavior. No handshake components or packet formats changed.

Remaining gates/limitations: root namespace execution; real systemd activation and
client DNS restoration; Docker runtime (raw entrypoints require explicit firewall
setup and client DNS provisioning); real VPS + real Linux client validation;
independent review of the custom KEMTLS-inspired protocol; classical Ed25519 client
authentication; re-handshake provides post-compromise recovery against passive
adversaries after full state compromise (active adversary with full epoch state
including rekey secret is a stated limitation); incomplete routed IPv6, dynamic
authenticated PMTU and kill switch. Python key wiping remains
best-effort. Passing these checks does not establish production suitability.

## Pre-VPS hardening — 2026-09-07

Status: **Deployable research/prototype PQ-VPN.
IPv4 full tunnel includes IPv6 leak prevention.
Native ML-KEM validation passed.
Root/TUN integration pending.
Real VPS/client validation pending.**
This record supersedes the Edit-5 validation counts above; historical evidence is
retained. No changes were made to `handshake/kemtls.py` or `crypto/hybrid_crypto.py`.

### Changes and boundaries

- Added `vpn/network.py` and the optional client `ipv6_policy` field: omitted policy
  blocks in full mode and permits out-of-scope IPv6 in split mode; explicit values
  are `block`, `fail`, `allow`. Shipped full-mode profiles explicitly select block.
- Blocking uses one exclusively created random `ip6 pqvpn_client6_<random>` table.
  An atomic nft batch blocks non-loopback OUTPUT and FORWARD before IPv4 route setup,
  including existing connections. No unrelated table, persistent sysctl or IPv6
  routing is changed. Loopback works; other IPv6, including link-local/ND, is blocked.
  ClientNetwork removes its exact table on ordinary cleanup and every failure path;
  SIGKILL/crash can leave a block behind and root can bypass it.
- `fail` checks IPv6 routes and usable global-scope addresses before TUN mutation
  and again before route setup, rejecting connectivity or inspection failures.
  This is snapshot protection only; subsequent IPv6 network changes require block
  mode. `allow` visibly warns about bypass. Doctor only inspects policy/state.
- Revocation remains future-authentication revocation. New ClientHello authorization
  is rejected after database update; already-authorized handshakes/active sessions
  may continue. CLI help/output now says server restart terminates all sessions;
  no live reload or per-client active termination is implemented.
- The native installer pins tag 0.16.0 to commit
  `5a1a854b0dc9f2141bdc771c555ee60c37950183` and aborts before build on mismatch.
  Production Python versions remain unchanged. Existing constraints/version evidence
  are retained; package artifact hash locking was not added.

### Current validation matrix

| Check | Result |
|---|---|
| `pytest -q` | PASS: 245 collected, 243 passed, 0 failed, 2 skipped |
| `python -m pytest -q` | PASS: 245 collected, 243 passed, 0 failed, 2 skipped |
| New IPv6/revocation/provenance coverage | PASS: 34 initial cases; continuation adds one Python-baseline case; focused IPv6/doctor run 41 passed |
| Native ML-KEM marker, separately | PASS: 2 passed, 243 deselected; `ALLOW_MOCK_PQC=0` |
| Python / liboqs-python / native liboqs | 3.14.7 / 0.16.0 / 0.16.0 |
| Native source commit | `5a1a854b0dc9f2141bdc771c555ee60c37950183` |
| Native provenance | PASS: exact upstream tag/checkout verified, ML-KEM-only shared library built; loaded path verified in `/proc/self/maps`; options/digest in `constraints-tested.txt` |
| Compileall | PASS: crypto, handshake, vpn, app, benchmarks, tests |
| Setup shell syntax | PASS |
| Cleanup shell syntax | PASS |
| liboqs installer shell syntax | PASS |
| Namespace shell syntax | PASS |
| JavaScript syntax | PASS: extracted inline script parsed by Node's `Function` constructor |
| Docker Compose config | PASS: schema only |
| Dependency consistency | PASS: `pip check`; production pins unchanged |
| `git diff --check` | PASS |
| Server doctor | WARN only for external provider/host firewall; exit 0; configuration/native identities PASS |
| Client doctor | PASS including `IPv6 leak policy: block`; exit 0; configuration/native identities PASS |
| Read-only doctors | PASS: files, links, IPv4/IPv6 routes, IPv6 addresses, forwarding and resolver before/after snapshots identical |
| IPv6 leak prevention | PASS at unit/static policy level; actual client setup/disconnect/dead-peer/control/rekey/SIGTERM cleanup exercised with simulated kernel commands |
| Root namespace | SKIPPED: host UID 1000; TUN, ip and nft present; passwordless sudo unavailable; marker returned 1 skipped / 244 deselected |
| Privileged IPv6 leak test | NOT EXECUTED: namespace harness expanded, root gate unavailable |
| Docker runtime | NOT VALIDATED; development/integration convenience only |
| Systemd runtime | NOT VALIDATED; real TUN/nft/listeners/journal gate pending |
| Real systemd-resolved | NOT VALIDATED; real-client before/during/after DNS verification pending |
| Real VPS | NOT PERFORMED |
| Release secret-path checks | PASS: no tracked private.key / authorized_clients.json / .env paths; environments/caches/private profiles remain ignored |

The 2 normal-suite skips are root namespace and mock-only fallback while native
crypto is available. Full suites ran sequentially with 120-second outer timeouts
and loopback socket access as UID 1000. The namespace harness now creates a separate
IPv6 physical default route, proves pre-connect reachability, checks blocked ICMPv6
and TCP plus working loopback during full mode, then checks restored IPv6 reachability
and routes after SIGTERM/disconnect and dead-peer cleanup. These are executable
privileged tests, not claimed kernel validation on this host.

Continuation doctor profiles are `/tmp/pqvpn-continuation.PdFUxu/doctor/server.toml`
and `client.toml`. Server used service_user shadow, detected WAN enp0s20f0u4, forwarding
0 with management enabled and one authorized native test identity. Client used a
matching pin, managed DNS and loopback server address for read-only route diagnosis.
Doctor saw 3 usable IPv6 routes/addresses and reported the default block policy
without installing it. Both temporary profiles exited 0. The unchanged shipped
sample profiles exited 1 because deployment identities/database are intentionally
absent and the pqvpn service account is not installed. This is not a provisioned
deployment failure or a reason to commit keys. Run doctor again with actual
deployment identities/config.

The explicit native build used source commit above, GCC 16.2.1, CMake 4.4.3,
Ninja 1.13.2, shared Release library and `OQS_MINIMAL_BUILD=KEM_ml_kem_768`, installed
under `/tmp/pqvpn-continuation.PdFUxu/native` for this continuation. The prior
temporary build and virtual environment were gone, so both were recreated without
changing source or dependency versions. Full/native runs selected the new build with
`OQS_INSTALL_PATH` and `LD_LIBRARY_PATH`. It is independent of the previously
installed 0.16.0 binary whose source revision was not recoverable from its version
string. No system library was replaced. The installer uses the same pinned revision
with the existing broader default build; unused algorithms are not validated here.

Upstream [liboqs security policy/advisories](https://github.com/open-quantum-safe/liboqs/security)
and [releases](https://github.com/open-quantum-safe/liboqs/releases) checked on 2026-09-07
still list 0.16.0 as the supported/current release; no published advisory requiring
a newer version was found. [liboqs-python security](https://github.com/open-quantum-safe/liboqs-python/security)
was checked too. Recheck before deployment; any required upgrade must get its own
dependency-validation pass.

The local annotated `v2-pre-vps` tag identifies this validated source baseline.
Resolve its exact commit with `git rev-parse 'v2-pre-vps^{commit}'`; the final task
report records the hash. No automatic push or remote deployment occurs. Private
identities and the authorization DB are separately provisioned inputs, not source
artifacts. This is not independent cryptographic review or deployment approval.

### Source-review continuation

The complete staged diff and final IPv6 lifecycle were reviewed before release.
No IPv6 enforcement or frozen cryptographic regression was found. Doctor's former
`Python supported` label incorrectly suggested every version at least 3.11 was
tested; it now reports the runtime minimum separately and warns outside 3.14.7.
One additional parametrized regression verifies that boundary. CLI revocation now
explicitly says existing active sessions continue until disconnect/expiration/server
restart; its existing regression checks that sentence. No session-kill mechanism,
handshake, rekey, route or firewall behavior changed during continuation.

The [next-phase handoff](deployment.md) records local-tag transfer without pushing,
the actual bounded namespace invocation and the VPS/client sequence. Full available
tests, native validation, static checks and doctors are rerun after the final file
edits before the local commit/tag. Historical counts remain intact in git history.

Remaining limitations: custom protocol lacks independent review; Ed25519 client
identity proof is classical; re-handshake provides post-compromise recovery
against passive adversaries (active adversary with full epoch state is not
recovered from); routed IPv6, dynamic authenticated PMTU and general kill switch
remain incomplete. Root namespaces, native systemd, real client DNS and
**REAL VPS + SEPARATE REAL LINUX CLIENT** remain the next validation gates.

## Privileged systemd execution trust boundary

Every executable, script, interpreter and module used directly or indirectly by
`ExecStartPre=+` and `ExecStopPost=+` must be root-owned and not writable by
`pqvpn`, its groups, or other users. This includes `/opt/pqvpn/scripts/server-network.sh`,
`/opt/pqvpn/scripts/server-network.sh`, `/opt/pqvpn/vpn/network.py`, all application
packages, `/opt/pqvpn/.venv/bin/python`, the entire venv/dependencies, symlink targets,
and their containing directories. Install the system Python, standard library,
native liboqs and helper OS commands administratively with the same trust boundary.
Do not grant write ACLs to the service account. The `+` prefixes remain necessary
for privileged nftables and forwarding sysctl setup/restoration; the daemon retains
`User=pqvpn`, `Group=pqvpn` and its existing limited capabilities.

`/opt/pqvpn` and its source/venv are `root:root`, directories/executables 0755 and
ordinary files 0644 (or more restrictive while retaining service read/execute).
Create the production venv and install dependencies as administrator, never as
`pqvpn`. Perform future source/dependency updates administratively, while stopped,
then restore ownership/modes and rerun production doctor before restart. For an
existing service-owned installation, rebuild source and venv from trusted inputs;
chown alone cannot remove previously planted code. The provisioning commands assume a
fresh installation from the validated source.

`/etc/pqvpn` is `root:pqvpn 0750`: the group may read/traverse, never write.
`server.toml`, the public identity and `authorized_clients.json` are `root:pqvpn 0640`.
The private identity is `pqvpn:root 0400`, compatible with the existing validator;
the daemon cannot replace it through the directory. As its file owner, it could
chmod its private key, so 0400 is not immutability against a compromised daemon.
No private key or policy file is imported/executed by the privileged helpers.

Run authorize/revoke as root. Each successful atomic update creates a root-owned
0600 database; immediately restore `root:pqvpn 0640` with the documented chown/chmod
commands, including after future updates. Between replacement and chmod daemon
reads fail closed. The root-only lock and temporary files stay in `/etc/pqvpn`;
locking, fsync and atomic replacement are unchanged. Never grant the service
configuration-directory write access to support administration.

Server doctor checks the complete `/opt/pqvpn` tree, symlink targets and ancestors
when examining `/etc/pqvpn` configuration or running from `/opt/pqvpn`. It fails on
non-root owners, any group/world write bits, missing required helpers/interpreter,
or unreadable entries. Ordinary development profiles explicitly report this check
as not applicable. It is a read-only filesystem snapshot, not runtime systemd
validation or a complete audit of external system libraries/loader configuration.

## Systemd ownership hardening — 2026-09-08

Source parent: `a09f65b948df985b97285b145faacb53ad292797` (`v2-pre-vps`).
The original tag is retained; this pass targets the new local annotated
`v2-pre-vps-2` release. No push or production provisioning is performed.

The deployment recipe now installs source and venv administratively, uses a
non-writable configuration directory, and runs authorization mutations as root
with post-replacement ownership/mode restoration. Doctor adds a production-only
ownership check. Fifteen new regressions exercise staged files with simulated
root/service metadata, including safe trees, service ownership, group/world
writes, imported dependencies, missing Python, symlink chains and replacement
parents, diagnostic FAIL output, production scope and deployment documentation.
The fixture does not chown the development checkout or require root.

Validation uses `/tmp/pqvpn-ownership-venv`, CPython 3.14.7 and unchanged constrained
application/test packages (pip check passes). Native liboqs 0.16.0 was freshly built
from clean source `5a1a854b0dc9f2141bdc771c555ee60c37950183`, with liboqs-python 0.16.0,
GCC 16.2.1 20260810, CMake 4.4.3 and Ninja 1.13.2. Build options match the earlier
ML-KEM-768-only shared Release validation, installed at `/tmp/pqvpn-ownership-native`.
Explicit `OQS_INSTALL_PATH`/`LD_LIBRARY_PATH` and `/proc/self/maps` confirm the loaded
library; SHA-256 is `dfc9ac670e5292f9b8b1efbfad3908cc92fda16765bfbe53d9112119c6736a31`.
The production installer and native source pin are unchanged.

Server/client doctors use temporary native identities under
`/tmp/pqvpn-ownership-doctor`, service user `shadow`, visible WAN `wlp46s0`,
loopback server address and client IPv6 block/managed DNS. They do not provision
`/opt/pqvpn` or `/etc/pqvpn`. Production ownership is tested via the staged fixture;
it is explicitly not applicable to these development doctor profiles.

Handshake, cryptography, packet/firewall policy, replay/IPv6/rekey/dead-peer/DNS
behavior, identity/database implementation and dependency pins are unchanged.
Systemd executable directives/capabilities are unchanged; only a trust-boundary
comment was added to the unit. Actual systemd start, root namespace, real nftables
enforcement, real resolver restoration and VPS/client validation remain runtime
gates. Host UID is 1000, TUN exists, and `sudo -n true` requires a password.

| Ownership-pass validation | Result |
|---|---|
| `pytest -q` | PASS: 258 passed, 2 skipped, 260 collected; 38.42s |
| `python -m pytest -q` | PASS: 258 passed, 2 skipped, 260 collected; 38.69s |
| Native ML-KEM (`ALLOW_MOCK_PQC=0`) | PASS: 2 passed, 258 deselected; 0.20s |
| Staged ownership/deployment regression | PASS: 15 passed |
| Server doctor | Exit 0; only external provider/host firewall WARN |
| Client doctor | Exit 0; all checks PASS |
| Compileall | PASS: crypto handshake vpn app benchmarks tests |
| Shell syntax | PASS: setup, cleanup, liboqs installer, namespace harness |
| JavaScript syntax | PASS: extracted inline script parsed by Node's `Function` constructor |
| Compose config | PASS: default and development-client profile; runtime unvalidated |
| Dependency consistency / diff whitespace | PASS |
| Root namespace | SKIPPED: UID 1000, no passwordless sudo; TUN unchanged |

The initial focused sandbox run was interrupted after identifying a fixture issue
(Python 3.14 lstat needs its own metadata patch); that fixture was corrected.
The final full runs above used host socket visibility and passed after all code
changes. No skipped root test is represented as a runtime pass.

## Minimal-layout structural refactor — 2026-09-08

This refactor starts from clean commit `3e072a1e995a318cdd28f2816da9a67c3262a52c`
(`v2-pre-vps-2`) on branch `refactor/minimal-layout`. Meaningful files are counted
with Git metadata, Python caches/environments and generated benchmark results excluded.
The tree moved from 73 to 43 files, a reduction of 30 files (41.10%).

All 19 prior Python test modules were mechanically consolidated into six responsibility
suites while retaining their cases and markers. One deterministic regression now pins
the exact length, six-byte header and SHA-256 digest of each frozen ClientHello,
ServerHello, ClientKeyExchange and ServerFinished serialization. Final collection is
261 tests: both `pytest -q` and `python -m pytest -q` pass 259 with 2 root/environment
skips. The isolated native marker passes 2 tests with 259 deselected.

The fresh install uses `python -m pip install -c constraints-tested.txt '.[dev]'` from
`pyproject.toml`. Pip dependency consistency, imports from outside the checkout,
packaged GUI assets, `vpn.cli --help`, and `python -m benchmarks --help` pass. No
dependency version changed. The native tests load liboqs-python 0.16.0 and liboqs
0.16.0 built from source commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`
under Python 3.14.7; mock PQC is disabled.

The continuation rebuilt the pinned ML-KEM-only library from that exact commit and
verified `/proc/self/maps`; SHA-256 is
`accf52d6e4e6b277aa3fa80e0fdee171fa95bd21b40f6888294c5fa8557abc4d`.
Its temporary source, build, and install prefix was removed after validation. The
management bearer dependency is async so this constant-time in-memory check does not
depend on AnyIO worker-thread offload under Python 3.14; HTTP 401/200 coverage remains.

Server doctor exits 0 with only the expected external provider/host-firewall warning;
client doctor exits 0 with all checks passing. The development doctor correctly marks
production `/opt/pqvpn` ownership as not applicable; staged production ownership tests
remain active. Compileall, both shell scripts, extracted inline JavaScript, both Compose
profiles, local documentation links, stale-path search and `git diff --check` pass.
A one-iteration native benchmark run produces all metrics and four charts successfully;
generated results are removed and ignored afterward.

Handshake and cryptographic implementation files are unchanged except for a documentation
link in the crypto module. Runtime changes are import-path-only. The explicit Docker
`--server-host` override is validated through the existing client config validator.
Wire bytes, algorithms, authentication, key schedule, records, replay, rekey, dead-peer,
IPv6, DNS and firewall policy are unchanged. UID remains 1000, TUN is present, and
passwordless sudo is unavailable, so root namespace/systemd/VPS validation remains
skipped rather than passed.
