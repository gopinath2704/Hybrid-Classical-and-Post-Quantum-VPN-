# Threat Model

PQVPN protects IP packets between an authenticated client and a provisioned server against passive observers, active network attackers, replay, cross-session injection, and unauthorized clients. The server public-key fingerprint and client authorization database are trusted provisioning inputs. Server compromise, endpoint compromise, traffic analysis, denial of service, malicious kernel/root, and compromise of provisioning are out of scope.

ML-KEM mock mode is explicitly insecure and is limited to development/test operation. Production startup requires runtime-enabled ML-KEM-768 and a successful self-test. No silent TOFU exists.

The custom protocol has not received independent cryptographic review or a formal proof. Ed25519 authenticates clients while the server uses a static ML-KEM possession proof. Long-term server identity compromise permits impersonation and may affect recordings involving that static KEM contribution; ephemeral X25519 and one client-ephemeral ML-KEM exchange remain separate inputs. A second bidirectional ephemeral ML-KEM exchange was removed because it duplicated the ephemeral PQ role rather than authentication; this judgment requires independent review.

Frequent epoch rekey derives successors from the prior `rekey_secret` plus a public nonce. It provides key evolution, not post-compromise recovery: compromise of the current rekey secret plus observation/decryption of the rekey records can expose future epochs. A fresh hybrid X25519 + ML-KEM refresh for long-lived sessions remains future work.

Python cannot guarantee erasure of all secret copies. Mutable long-lived buffers are overwritten on rekey/disconnect as best-effort in-process zeroization; interpreter, library, allocator, swap, and core-dump copies may remain.

### Authentication boundary

PQVPN KEMTLS-inspired v2 is a custom protocol, not standardized KEMTLS.
Static ML-KEM-768 authenticates the server; X25519 + ML-KEM-768 establish
hybrid session keys. Ed25519 authenticates clients and is classical, not
post-quantum. This is not fully post-quantum mutual authentication.
Status: deployable research/prototype PQ-VPN. Root namespace validation and
a real VPS/client deployment must both succeed before revising that status.

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

Management HTTP uses a bearer; WebSocket telemetry uses bounded, 30-second,
single-use tickets. Local configuration, private identities, and the service's
CAP_NET_ADMIN privilege are trusted. Private keys require mode 0600/0400 and server
ML-KEM keypairs are tested for consistency. These checks and passing regression/native
tests do not substitute for independent protocol review, root namespace execution,
or real VPS/client validation.

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
