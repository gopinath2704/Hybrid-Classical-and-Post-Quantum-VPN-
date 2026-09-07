# Architecture

PQVPN separates an authenticated TCP control plane from an encrypted UDP data plane.

1. The client verifies a provisioned SHA-256 fingerprint for the server's static ML-KEM-768 identity.
2. A strict KEMTLS-inspired handshake combines ephemeral X25519, one ephemeral ML-KEM session secret, and a static server-identity ML-KEM authentication secret. The client proves its authorized Ed25519 identity. The provisioned identity key is not retransmitted; its transcript-bound SHA-256 identifier selects and binds the pinned key.
3. HKDF derives role- and channel-separated Finished, DATA, CONTROL, nonce, rekey, and confirmation secrets bound to protocol/version/algorithms/session/randoms/transcript.
4. Encrypted CONFIG assigns the VPN address, server address, prefix, MTU, UDP port, routes, DNS, and epoch.
5. Authenticated UDP_BIND teaches the server the client's actual NAT endpoint. No TCP source port is reused or inferred.
6. One server TUN and UDP listener serve all clients. Maps connect compact session IDs, client VPN addresses, endpoints, and traffic-key state.
7. Client TUN packets become AES-GCM DATA frames. The server decrypts them into `pqvpn0`; Linux forwarding and the project-specific nftables masquerade route them to WAN. Return packets are selected by inner destination, encrypted, and injected into the client TUN.

Every record header is AAD, including its DATA/CONTROL channel. Each channel and direction has an independent key, nonce base, send counter, and receive state. Sequence allocation plus encryption is atomic. DATA uses a locked 128-packet replay window; ordered CONTROL requires exactly the next sequence. TCP control rekey is confirmed under the old epoch before either side installs matching successor material.

Production never falls back to socket-pipe TUN. Emulation requires `--dev-emulated-tun`. Host changes are transactional on the client; server firewall helpers own isolated nftables tables and do not flush user rules.

Current limitations are tracked in `progress.md`: IPv4 routing is implemented; IPv6 forwarding/data-route coverage, optional kill switch, dynamic PMTU discovery, stateless pre-PQ cookies, and fresh hybrid post-compromise recovery remain future work. The root namespace integration marker requires a privileged Linux runner and is not evidence until executed there.

## Deployment and diagnostics

`vpn/config.py` validates TOML before networking. Relative paths and omitted identity
filenames resolve beside the TOML. `vpn/identity.py` checks private permissions,
server ML-KEM pair consistency and the authorized-client database; locked atomic
updates use file fsync, replace and directory fsync. Static leases are excluded from
dynamic allocation, and configured maximum clients cannot exceed usable subnet capacity.

`vpn/firewall.py` renders scoped client/host/private isolation and WAN NAT;
`scripts/server-setup.sh` atomically replaces only PQVPN-owned tables and preserves
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

The optional browser management API has pinned dependencies separate from the daemon.
HTTP bearer authentication issues bounded single-use telemetry tickets; the dashboard
currently polls HTTP. See [management API](management-api.md) and the
[validation matrix](security_audit.md#final-validation--2026-09-07).
