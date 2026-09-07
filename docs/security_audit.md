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
File/function: `handshake/kemtls.py`; `vpn/engine.py:VPNServerDaemon._handle_client`  
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
File/function: `handshake/kemtls.py:HandshakeSession.rekey`; `vpn/engine.py:VPNService.rotate_keys`  
Problem: A locally random nonce derives and activates new keys without being transmitted. Declared rekey message constants are unused.  
Impact: The initiating peer immediately loses interoperability with its peer.  
Attack/failure scenario: Scheduled client rekey causes all subsequent packets to fail authentication.  
Fix: Authenticated counter-framed control messages with monotonic epoch, request nonce, response confirmation, and coordinated activation.  
Verification: Synchronized rekey, replayed-rekey rejection, post-rekey traffic, and old-epoch rejection tests.  
Status: Confirmed; remediation in progress.

## A-07 — UDP endpoint negotiation is functionally broken

Severity: Critical  
Component: UDP data-plane establishment  
File/function: `vpn/engine.py:VPNService.connect`, `VPNServerDaemon._handle_client`  
Problem: Client sends UDP to the TCP destination port; server sends UDP to the client's TCP source address and binds an unrelated ephemeral UDP socket. TCP and UDP source ports are unrelated.  
Impact: Real data-plane traffic does not reliably reach either endpoint and NAT cannot work.  
Attack/failure scenario: A normal NAT assigns a distinct UDP mapping; server ciphertext is sent to the TCP source port and discarded.  
Fix: One known UDP server port and authenticated `UDP_BIND`/`UDP_BIND_ACK`; learn the client endpoint only from a valid encrypted bind frame.  
Verification: Different TCP/UDP source-port and endpoint-binding tests.  
Status: Confirmed; remediation in progress.

## A-08 — Server architecture cannot support real multi-client routing

Severity: Critical  
Component: Server tunnel architecture  
File/function: `vpn/engine.py:VPNServerDaemon._handle_client`  
Problem: Every connection opens the same TUN name and a separate UDP socket; no session demultiplexer, destination-IP routing map, endpoint map, or IP pool exists.  
Impact: The second native client conflicts; server return packets cannot be assigned to sessions; all clients default to 10.8.0.2.  
Attack/failure scenario: Concurrent users collide on device/IP resources and cannot receive routed responses.  
Fix: One `pqvpn0`, one UDP listener, session-ID/IP/endpoint maps, server-side IP pool allocation/release.  
Verification: Multi-session and allocation/release tests.  
Status: Confirmed; remediation in progress.

## A-09 — No real host/client routing lifecycle

Severity: Critical  
Component: Linux networking  
File/function: `vpn/engine.py:VPNService`, `VPNServerDaemon`; deployment files  
Problem: Server forwarding/NAT is absent; client default/split routes, transport bypass, DNS setup/restoration, transactional rollback, kill switch, and applied MSS clamp are absent. TUN IP setup errors are ignored.  
Impact: A UI may say CONNECTED while Internet traffic does not traverse the server.  
Attack/failure scenario: Client traffic continues over its original default route; server cannot forward decrypted packets to WAN.  
Fix: Transactional Linux network configurator, server setup/cleanup scripts with project-specific nftables chains, route/DNS restoration, optional kill switch, and actual MSS rules.  
Verification: Namespace integration tests and setup-script validation.  
Status: Confirmed; remediation in progress.

## A-10 — Production silently falls back to an emulated TUN

Severity: High  
Component: TUN lifecycle  
File/function: `vpn/engine.py:VPNService._allocate_tun`; `VPNServerDaemon._handle_client`  
Problem: Missing `/dev/net/tun` or permissions silently select a socket pair, yet connection state becomes CONNECTED.  
Impact: Operators can believe traffic is protected when no traffic can leave the host.  
Attack/failure scenario: A container missing `NET_ADMIN` appears connected but leaks traffic via the normal route.  
Fix: Native TUN is mandatory unless an explicit `--dev-emulated-tun` option is set.  
Verification: Fail-closed and explicit-emulation tests.  
Status: Confirmed; remediation in progress.

## A-11 — MTU accounting is incorrect and unapplied

Severity: Medium  
Component: MTU/fragmentation  
File/function: `vpn/engine.py:MTUMonitor`; `benchmarks/runner.py:PacketOverheadAnalyzer`  
Problem: Calculations include a nonexistent two-byte UDP length prefix, omit the future authenticated header, do not set the chosen TUN MTU, and only calculate (not apply) MSS values.  
Impact: Inner packets can exceed PMTU and fragment/drop; published overhead is false.  
Attack/failure scenario: Full-size TCP packets exceed the outer path MTU and black-hole on DF paths.  
Fix: Define one frame header, derive exact overhead from it, set TUN MTU, reject oversized inner packets, and apply project-specific MSS clamp.  
Verification: 1500/1400/1280 MTU size tests and namespace traffic tests.  
Status: Confirmed; remediation in progress.

## A-12 — Telemetry is labelled real but never sampled on the tunnel

Severity: Medium  
Component: Quality telemetry  
File/function: `vpn/engine.py:VPNService.connect/get_telemetry`; `NetworkQualityMonitor.probe`  
Problem: The monitor is constructed but never fed. Its standalone probe targets arbitrary UDP/33434 and is not authenticated tunnel measurement.  
Impact: Latency, jitter, and loss remain zero and mislead operators.  
Attack/failure scenario: A degraded tunnel is reported as zero-latency/zero-loss.  
Fix: Authenticated encrypted PING/PONG frames on the actual UDP path with timeout accounting.  
Verification: Keepalive RTT/loss tests and API telemetry assertions.  
Status: Confirmed; remediation in progress.

## A-13 — Handshake parsers accept inconsistent/trailing data

Severity: High  
Component: Wire parsing  
File/function: `handshake/kemtls.py`, all `unpack` methods and `_unpack_header`; `vpn/engine.py:_recv_message`  
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
File/function: `vpn/engine.py:VPNServerDaemon.start/_handle_client`  
Problem: No maximum clients, source rate limiting, session/idle timeout, bounded thread cleanup, or production startup self-test. Listener backlog is five but accepted connections spawn indefinitely.  
Impact: Remote clients can consume threads, sockets, ML-KEM work, and tunnel resources.  
Attack/failure scenario: Repeated slow handshakes or idle control sockets exhaust the server.  
Fix: Semaphores/session manager, handshake deadlines, strict message cap, per-source token bucket, idle/session expiry, and cleanup.  
Verification: Limit/timeout tests.  
Status: Confirmed; remediation in progress.

## A-18 — Deployment artifacts do not produce a routed VPN

Severity: High  
Component: Docker/VPS deployment  
File/function: `Dockerfile.server`, `Dockerfile.client`, `docker-compose.yml`; absent setup/service files  
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
an unchanged `requirements-dev.txt` / `constraints-tested.txt` installation.
`pip check` passed; every installed constrained package matched its pin.
Native **liboqs-python 0.16.0** loaded the existing **liboqs 0.16.0** installation.
No dependency upgrades, native library build or remote deployment were performed.

| Check | Result | Evidence / limits |
|---|---|---|
| `pytest -q` | PASS | 210 collected; 208 passed, 0 failed, 2 skipped; 37.19s |
| `python -m pytest -q` | PASS | 210 collected; 208 passed, 0 failed, 2 skipped; 36.17s |
| Python compileall | PASS | `python -m compileall -q crypto handshake vpn app benchmarks tests` |
| Server setup shell syntax | PASS | `bash -n scripts/server-setup.sh` |
| Server cleanup shell syntax | PASS | `bash -n scripts/server-cleanup.sh` |
| Namespace shell syntax | PASS | `bash -n tests/namespace_vpn.sh` |
| Native installer shell syntax | PASS | `bash -n scripts/install-liboqs.sh` |
| JavaScript syntax | PASS | `node --check app/frontend/js/app.js` |
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
authentication; epoch key evolution without post-compromise recovery; incomplete
routed IPv6, dynamic authenticated PMTU and kill switch. Python key wiping remains
best-effort. Passing these checks does not establish production suitability.
