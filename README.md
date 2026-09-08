# Hybrid Classical and Post-Quantum VPN

PQVPN is a Linux TUN/UDP VPN research implementation using ephemeral X25519 plus ML-KEM-768, HKDF-SHA256, directional AES-256-GCM traffic keys, a pinned static ML-KEM-768 server identity, and authorized Ed25519 client identities.

The protocol is KEMTLS-inspired, not formally KEMTLS-compatible and not formally proven. The design reduces post-quantum handshake communication overhead and fragmentation/segmentation pressure; it does not eliminate fragmentation.

## Security modes

- Native mode: current liboqs must report `ML-KEM-768` from `oqs.get_enabled_kem_mechanisms()` and pass a startup keygen/encapsulation/decapsulation self-test. Production fails closed otherwise.
- Development mode: `ALLOW_MOCK_PQC=1` makes the insecure SHA mock available, and a runtime additionally requires `--allow-mock-pqc`. It is always reported as not quantum-safe. Add `--dev-emulated-tun` separately only when no real TUN is intended.

## Provision and run

Status: **Deployable research/prototype PQ-VPN**. Root namespace integration and
real VPS/client validation remain pending. Follow the [server deployment guide](docs/deployment.md)
for OS prerequisites, explicit native liboqs installation, provisioning and the
systemd validation gate. The tested baseline is Python 3.14.7, liboqs-python 0.16.0,
and native liboqs 0.16.0; no virtual environment is shipped.

```bash
# After installing the OS prerequisites from the deployment guide:
sudo bash scripts/install-liboqs.sh /usr/local
python3.14 -m venv .venv
.venv/bin/python -m pip install -c constraints-tested.txt '.[dev]'
.venv/bin/python -m vpn.cli identity generate
.venv/bin/python -m vpn.cli client-key generate
.venv/bin/python -m vpn.cli client authorize config/client_identity_public.key --client-id local-client
# Set the server fingerprint and actual hostname in config/client.toml.
# Set server interfaces/subnet and provision the service account as described in the guide.
.venv/bin/python -m pytest -q -m native_pqc
.venv/bin/python -m vpn.cli doctor server --config config/server.toml
.venv/bin/python -m vpn.cli doctor client --config config/client.toml
```

Install `.` for the daemon or CLI, `.[management]` for browser management, and
`.[dev]` for validation/benchmarks. Always pass `-c constraints-tested.txt` to
reproduce the complete tested dependency set. The optional
PyWebView desktop shell is outside the pinned/tested installation; browser management
needs no desktop libraries. Native crypto is installed before starting any service;
the daemon does not download or build it.

The server owns one `pqvpn0` TUN and one 51820/UDP listener. It assigns client IPs, authenticates UDP_BIND from the client's real NAT-mapped source, demultiplexes sessions, and routes return packets by inner destination IP. The retained TCP channel carries encrypted configuration, synchronized rekey, CLOSE, and errors. Encrypted UDP PING/PONG feeds actual tunnel RTT/jitter telemetry.

The management API binds to 127.0.0.1 by default. Set a strong `PQVPN_MANAGEMENT_TOKEN`; APIs use `Authorization: Bearer ...` and WebSocket telemetry uses a 30-second, single-use `?ticket=...` obtained through authenticated `POST /api/v1/ws-ticket`. The bearer never belongs in a WebSocket URL. See the [management contract](docs/deployment.md); remote exposure requires explicit HTTPS origins and a TLS reverse proxy.

CLI-client mode and API-owned client mode are alternatives. A separate Uvicorn process cannot control an already-running `vpn.cli client connect` process. For management endpoints, start the API first and let `POST /api/v1/vpn/connect` create and own its `VPNClient`; `/rekey` and `/disconnect` operate on that same in-process instance.

Relative key/database paths resolve against the TOML file location, including configurations stored under `/etc/pqvpn`, rather than against the process working directory.

## Tests

```bash
source .venv/bin/activate
pytest -q
python -m pytest -q
ALLOW_MOCK_PQC=0 python -m pytest -q -m native_pqc
sudo env PATH="$VIRTUAL_ENV/bin:$PATH" "$VIRTUAL_ENV/bin/python" -m pytest -q -m 'integration and requires_root'
```

Passing mock tests does not validate native ML-KEM. See [protocol](docs/design.md), [threat model](docs/design.md), [server deployment](docs/deployment.md), [client setup](docs/deployment.md), and the [security audit](docs/security_audit.md).

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

Client receive liveness also uses a monotonic `dead_peer_timeout` (30 seconds by
default). Valid PONG or DATA keeps it alive; outgoing PING does not. A UDP blackhole
enters FAILED and restores routes/DNS even while TCP remains established.

## Network policy

Full tunnel means supported IPv4 Internet traffic uses PQVPN, while unsupported
IPv6 is **blocked by default**. This is not dual-stack tunneling. The client requires
nftables for `ipv6_policy="block"`; loopback remains available and the temporary IPv6
policy is removed on cleanup. `fail` refuses existing IPv6 connectivity before setup;
`allow` explicitly accepts IPv6 bypass with a warning. An omitted policy in split
mode leaves unrelated IPv6 alone. See the [IPv6 policy details](docs/deployment.md#ipv6-policy).


PQVPN-owned nftables tables isolate clients, block VPS host services (optional
server-IP ping only), metadata and private destinations, and allow public forwarding
through the configured WAN. `allowed_forward_networks` deliberately permits selected
forwarded private networks; setup reconciles only owned tables. Managed IPv4 forwarding
saves the original value once and cleanup restores it. Unmanaged forwarding must
already be enabled. Existing host/provider policy still requires operator verification.

Full-tunnel managed DNS requires working `resolvectl` when DNS is configured; failure
rolls back network setup. `dns_mode="none"` explicitly accepts unmanaged DNS with a
warning. Split DNS uses `dns_routing_domains` and does not implicitly install `~.`.
See the [client guide](docs/deployment.md).

Current results and their limits are recorded in the [final validation matrix](docs/security_audit.md#pre-vps-hardening--2026-09-07).
Routed IPv6, a kill switch, dynamic authenticated PMTU discovery, independent protocol
review and post-compromise recovery remain incomplete.

Docker is a **development/integration convenience** with unvalidated runtime routing.
The first VPS deployment should follow the native systemd guide; actual systemd
startup and real Linux-client DNS restoration remain mandatory real-machine gates.
The local `v2-minimal-layout` annotated tag identifies the consolidated pre-VPS source; verify
`git rev-parse 'v2-minimal-layout^{commit}'` before deploying that exact revision. No push or
remote deployment is part of this hardening pass. See the
[pre-VPS validation record](docs/security_audit.md#pre-vps-hardening--2026-09-07).
The [root namespace and VPS handoff](docs/deployment.md) gives the next commands,
including transfer of the local tag without a push.
