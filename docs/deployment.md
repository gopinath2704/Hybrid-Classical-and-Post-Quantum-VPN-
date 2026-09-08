# PQVPN Deployment

## Linux VPS deployment gate

Status: **Deployable research/prototype PQ-VPN**. Unit tests are not a deployment
approval. First pass doctor, native ML-KEM tests, and the full root namespace
suite on a disposable Linux VM. Then validate a real VPS with a separate Linux
client. Privileged namespace, systemd, and VPS results must be recorded separately.

## Exact tested dependencies

The recorded baseline is CPython **3.14.7**, **liboqs-python 0.16.0**, native
**liboqs 0.16.0**, Linux x86_64. `deploy/versions.txt` records the versions;
`constraints-tested.txt` pins every Python dependency in the test environment.
Install `.` for the daemon or CLI, `.[management]` for the optional management API,
and `.[dev]` for validation and benchmarks. Always pass `-c constraints-tested.txt`
to reproduce all transitive pins. IPv6 leak blocking additionally needs nftables
on the client. The core install excludes management, benchmark, and test packages.
No environment is shipped. Other Python versions/platforms require fresh validation.
Doctor distinguishes the Python 3.11 runtime minimum from the tested 3.14.7 baseline;
meeting the minimum does not validate another Python version.
The Ubuntu 24.04 Docker examples use distro Python and remain independently
unvalidated; Compose syntax validation does not establish image/runtime validity.

Install Python 3.14.7 from a trusted distribution/build, plus venv support, git,
CMake, Ninja, a C compiler, OpenSSL development headers, iproute2, nftables,
util-linux (flock), rsync and procps (sysctl). Native liboqs must be installed
explicitly before importing the application or starting the service:

```bash
python3.14 --version  # must report the tested 3.14.7 baseline
sudo bash scripts/install-liboqs.sh /usr/local
# The helper verifies the exact 0.16.0 commit, builds a shared library and runs ldconfig.
ldconfig -p | grep liboqs
```

The build procedure follows the upstream [liboqs shared-library build instructions](https://github.com/open-quantum-safe/liboqs)
and [Python binding installation guidance](https://github.com/open-quantum-safe/liboqs-python).
PQVPN probes for a preinstalled library before importing the binding; missing
native liboqs fails closed without triggering its automatic download/build path.
For a custom prefix set `OQS_INSTALL_PATH` and configure the dynamic loader before
launch. Do not use mock PQC in deployment. Save the native build/compiler provenance
alongside test results; version pins alone do not reproduce an operating-system image.

## Install and provision, then diagnose

```bash
sudo useradd --system --home /opt/pqvpn --shell /usr/sbin/nologin pqvpn
sudo install -d -o root -g root -m 0755 /opt/pqvpn
sudo install -d -o root -g pqvpn -m 0750 /etc/pqvpn
sudo rsync -a --chown=root:root --exclude=.git --exclude=.venv --exclude=venv --exclude=env --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache ./ /opt/pqvpn/
sudo python3.14 -m venv /opt/pqvpn/.venv
sudo /opt/pqvpn/.venv/bin/python -m pip install -c /opt/pqvpn/constraints-tested.txt /opt/pqvpn
sudo chown -R root:root /opt/pqvpn
sudo chmod -R u=rwX,go=rX /opt/pqvpn
cd /opt/pqvpn
sudo .venv/bin/python -m vpn.cli identity generate --private /etc/pqvpn/server_identity_private.key --public /etc/pqvpn/server_identity_public.key
sudo chown pqvpn:root /etc/pqvpn/server_identity_private.key
sudo chmod 0400 /etc/pqvpn/server_identity_private.key
sudo chown root:pqvpn /etc/pqvpn/server_identity_public.key
sudo chmod 0640 /etc/pqvpn/server_identity_public.key
sudo install -o root -g pqvpn -m 0640 config/server.toml /etc/pqvpn/server.toml
sudo editor /etc/pqvpn/server.toml
# Obtain only the client's public key through authenticated provisioning.
sudo .venv/bin/python -m vpn.cli client authorize /tmp/alice_public.key --database /etc/pqvpn/authorized_clients.json --client-id alice
sudo chown root:pqvpn /etc/pqvpn/authorized_clients.json
sudo chmod 0640 /etc/pqvpn/authorized_clients.json
```

Private identity files must be regular, non-symlink files with mode 0600 or 0400.
The server checks static key lengths and keypair consistency before opening TUN
or listeners. The client checks its private identity equivalently. Never copy a
server private key to clients; provision only its public key and SHA-256 pin.
The database is strictly validated at startup; malformed records, mismatched
fingerprints, duplicate identities/client IDs/static leases and unusable addresses
fail startup. CLI updates lock, fsync and atomically replace the database. Restart
after authorization/static-address changes so startup validates the entire new
allocation policy. Keep private keys and the authorization database out of archives.

Doctor is read-only: PASS/WARN/FAIL, nonzero for blocking failures. It checks
native crypto, configuration, identities, visible routes/interfaces (including
Docker routes), command availability, WAN/default route, ports, forwarding state,
and service-user readability. Port availability is a snapshot, not a reservation;
provider policy and hidden networks cannot be inferred from local checks.

## Native and root namespace gate

Install dev dependencies in a fresh validation environment with the same Python:

```bash
python3.14 -m venv /tmp/pqvpn-validation
/tmp/pqvpn-validation/bin/python -m pip install -c constraints-tested.txt '.[dev]'
ALLOW_MOCK_PQC=0 /tmp/pqvpn-validation/bin/python -m pytest -q -m native_pqc
sudo -u pqvpn /opt/pqvpn/.venv/bin/python -m vpn.cli doctor server --config /etc/pqvpn/server.toml
sudo env PATH="/tmp/pqvpn-validation/bin:$PATH" /tmp/pqvpn-validation/bin/python -m pytest -q -m 'integration and requires_root'
```

The namespace test requires root, `/dev/net/tun`, iproute2, nftables, curl and ping.
It is bounded at 180 seconds and includes two clients, public TCP/UDP/NAT, isolation,
metadata/private blocking and allowlist reconciliation, quiet/idle sessions,
manual/automatic rekey, a real UDP blackhole, reconnect and forwarding-state restore.
Its isolated namespaces deliberately do not call the host's systemd-resolved.
DNS command rollback is unit-tested; actual resolver integration/restoration must
also be checked on the disposable systemd VM and real client. A SKIP is not a PASS.

## Firewall policy and subnet selection

The exclusively owned tables are `inet pqvpn`, `ip pqvpn_nat`, and
`inet pqvpn_mangle`. Setup atomically replaces these tables from validated TOML;
repeated setup reconciles changes. No unrelated tables or global DROP policy are
installed. Existing host policy can still deny PQVPN traffic.

Default TUN policy:

- Allow IPv4 traffic through the configured WAN, after destination filtering.
- Allow established/related WAN return traffic to VPN clients.
- Deny client-to-client, other-interface forwarding, and arbitrary VPS host services.
- Allow only ICMP echo to `server_vpn_ip` when `allow_server_ping=true`.
- Deny link-local metadata `169.254.0.0/16`, RFC1918, CGNAT, loopback, unspecified,
  benchmarking, multicast and reserved destination ranges.

`allowed_forward_networks=[]` is empty by default. To deliberately allow a private
service through WAN set e.g. `["10.50.0.10/32"]`. Exceptions precede destination
denies but cannot enable client-to-client or VPS-host access. Filtering uses the
inner destination, so a private-address WAN gateway does not block public Internet.
There is no host-service or client-to-client opt-in in this pass.

`manage_ip_forward=true` records the original sysctl once under
`/run/pqvpn/ip_forward.prev`; repeated setup preserves it, and cleanup restores then
removes it. `false` requires forwarding already enabled. Coordinate ownership with
other forwarding services. Only one PQVPN firewall instance manages these tables
and this saved state; the namespace harness uses its own runtime directory.

Use doctor to detect visible VPN-subnet collisions on both server and client.
If `10.8.0.0/24` is already used, explicitly choose e.g. `10.66.0.0/24`, update
`server_vpn_ip`, static leases, and the client's `expected_vpn_subnet`. Do not
silently select a random subnet. Client control uses the provisioned TCP port;
the UDP port comes from authenticated server CONFIG (`server_udp_port` was removed).

## Start systemd only after the VM gate

```bash
sudo cp deploy/pqvpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pqvpn-server
sudo journalctl -u pqvpn-server -f
sudo ss -lntup
sudo nft list ruleset
ip addr show pqvpn0
```

The unit runs `User=pqvpn`, `Group=pqvpn`, `WorkingDirectory=/opt/pqvpn` and
`ExecStart=/opt/pqvpn/.venv/bin/python -m vpn.cli server --config /etc/pqvpn/server.toml`.
There is no EnvironmentFile. `PQVPN_PYTHON` selects the same Python for setup;
relative key/database paths resolve within `/etc/pqvpn`, including standard identity/database filenames when fields are omitted. `RuntimeDirectory=pqvpn`
recreates runtime storage. Setup/cleanup are privileged helpers; the Python daemon
retains CAP_NET_ADMIN, a meaningful privilege boundary. Existing systemd restrictions
are retained. No additional hardening directives were added without actual systemd
startup testing; that test remains a deployment gate.

## Provider and real-client checklist

Open only the configured VPN TCP/UDP ports (defaults 51820/TCP and 51820/UDP) in the
provider and host policy. Keep SSH reachable, preferably only from administrator
addresses. PQVPN does not require any public 8000/API/database port. Local doctor,
`ss`, and nftables checks cannot certify the provider firewall.

Verify with a separate Linux client: exit IP becomes the VPS address; TCP/UDP and
approved DNS work; two clients remain isolated; metadata/private/host services are
blocked; rekey succeeds under traffic; server restart and temporary UDP blackhole
trigger FAILED and restore routes/DNS; manual reconnect succeeds. Recheck VPS SSH
access, TUN, listeners, nftables and absence of public management exposure.

The service does not launch FastAPI. Optional management binds loopback. Remote
management requires an explicitly configured TLS reverse proxy, a random 32-byte
bearer token, and explicit HTTPS CORS origins; no direct public Uvicorn listener.
See [management API](deployment.md) for short-lived WebSocket tickets.

## Current validation record

The [2026-09-07 validation matrix](security_audit.md#pre-vps-hardening--2026-09-07)
records the complete regression, syntax, dependency installation, native ML-KEM and
read-only doctor checks. The development doctor used temporary native identities,
`service_user="shadow"`, and the visible WAN; it did not provision `/etc/pqvpn` or
start systemd. Run doctor again with the actual service account and VPS config.
The host is UID 1000 with TUN visible outside the sandbox: root namespace integration
is still SKIPPED, not passed. Real VPS/client validation is NOT PERFORMED.

Current Docker examples are not the validated native installation path. Their raw
Python entrypoints do not invoke firewall helpers: explicit setup/cleanup inside the
server network namespace is required for NAT/isolation. The development client image
also lacks systemd-resolved; its managed DNS config fails safely unless a supported
manager is supplied or the operator explicitly chooses `dns_mode="none"`. Do not treat
`docker compose config` success as a working container VPN or native systemd result.

## Native source provenance and advisory review

`liboqs 0.16.0` is pinned to full source commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183` in `scripts/install-liboqs.sh` and
`deploy/versions.txt`. The helper clones tag 0.16.0 and compares HEAD with that
commit before running CMake; any mismatch fails. It never selects latest/main.
The Python binding remains 0.16.0 and every Python dependency version remains unchanged.

On 2026-09-07, the upstream [security policy/advisories](https://github.com/open-quantum-safe/liboqs/security)
and [release list](https://github.com/open-quantum-safe/liboqs/releases) still identified
0.16.0 as the supported current release. No published advisory requiring a newer
version for this baseline was found. The [Python binding security page](https://github.com/open-quantum-safe/liboqs-python/security)
was also checked. Recheck before deployment; a required security update needs a separate
dependency-validation pass, not an untested upgrade.

This pass built the verified revision in a temporary prefix with only ML-KEM-768
enabled and ran native tests and complete regressions against that loaded library.
`deploy/versions.txt` records compiler/build options and the tested binary digest.
The installer keeps its broader default algorithm build; the validation does not
certify unused algorithms or an OS image. The prior installed library exposed the
same 0.16.0 version but lacked a source provenance record. Python versions are pinned
through the existing tested constraints; package artifact hash locking remains outside
this prototype baseline.

## Revocation semantics

```bash
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli client revoke FINGERPRINT --database /etc/pqvpn/authorized_clients.json
sudo chown root:pqvpn /etc/pqvpn/authorized_clients.json
sudo chmod 0640 /etc/pqvpn/authorized_clients.json
```

Revocation disables future authentication: a new ClientHello reads the updated
database and is rejected. Existing sessions and handshakes already authorized may
continue until disconnect, expiry or server restart. The CLI says this explicitly.
There is no live reload or per-identity active-session termination API. For immediate
termination, `sudo systemctl restart pqvpn-server` disconnects **all clients**;
revoked identities cannot establish a new session afterward.

## Reproducible pre-VPS source

Use the local annotated `v2-minimal-layout` tag, resolve it with
`git rev-parse 'v2-minimal-layout^{commit}'`, and deploy that exact commit after the disposable
root namespace gate. The hardening pass creates no automatic push. Never archive or
copy private keys, the authorized-client DB, tokens, virtual environments or build
outputs as part of source distribution. Provision secrets separately.

Docker remains a development/integration convenience, not the first VPS path.
Native systemd is the intended path, but actual daemon-reload/start/status/journal,
real TUN/nft/listeners remain unvalidated until executed. Real systemd-resolved
before/during/after state and approved-resolver lookups remain a separate Linux-client
gate. IPv6 leak unit tests do not replace the expanded privileged namespace test.

See the [exact next-phase handoff](deployment.md) for local-tag transfer,
disposable root namespace execution, provisioning and separate real-runtime gates.

## Privileged systemd execution trust boundary

Every executable, script, interpreter and module used directly or indirectly by
`ExecStartPre=+` and `ExecStopPost=+` must be root-owned and not writable by
`pqvpn`, its groups, or other users. This includes `/opt/pqvpn/scripts/server-network.sh`,
`/opt/pqvpn/vpn/network.py`, all application
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

## Client Setup
### Linux client setup

Status: **Deployable research/prototype PQ-VPN**. Use a separate Linux client after
native and root-namespace validation on a disposable VM. Routed IPv6, a kill switch,
dynamic authenticated PMTU, and post-compromise hybrid rekey remain future work.

Use the tested CPython 3.14.7, liboqs-python 0.16.0 and native liboqs 0.16.0 baseline.
Install native liboqs explicitly using the [server guide](deployment.md)
before importing the application. Create a fresh environment:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -c constraints-tested.txt .
.venv/bin/python -m vpn.cli client-key generate
# Provision server public identity + exact SHA-256 fingerprint securely.
# Send only config/client_identity_public.key to the administrator for authorization.
editor config/client.toml
.venv/bin/python -m vpn.cli doctor client --config config/client.toml
sudo -E .venv/bin/python -m vpn.cli client connect --config config/client.toml
```

Doctor checks the server pin, client private-key permissions, native crypto, TUN,
iproute2, DNS manager, name resolution, route to server, and obvious VPN-subnet
collisions. Check your LAN/container routes too. Set `expected_vpn_subnet` to the
provisioned server subnet; a different authenticated server subnet fails connection
setup. `server_control_port` configures TCP; authenticated CONFIG supplies UDP.
The obsolete `server_udp_port` setting is rejected rather than silently ignored.

`ping_interval=5`, `ping_timeout=4`, and `dead_peer_timeout=30` are validated seconds.
Only current authenticated server UDP (matching PONG, valid DATA, initial bind ACK)
refreshes the monotonic receive deadline. Outgoing PING, wrong endpoint/session,
replays, obsolete epochs, malformed records and bad AEAD do not. No valid UDP before
the deadline means FAILED, TUN/socket close, key wipe best-effort and route/DNS
cleanup even if TCP is still established. Manual reconnect is supported; no automatic
reconnect was added. Healthy PING/PONG refreshes server idle activity as well.

## IPv6 policy

IPv4 tunnel: supported. IPv6 tunnel: unsupported. IPv6 leak prevention: supported
through temporary blocking or a fail-closed preflight policy. Full tunnel means all
supported IPv4 Internet traffic is routed through PQVPN, while unsupported IPv6 is
blocked by default; existing more-specific IPv4/LAN routes retain normal precedence.
This does not provide dual-stack tunneling.

`ipv6_policy` accepts only:

- `block`: full-tunnel default. Requires `nft` and CAP_NET_ADMIN/root. An exclusively
  created `ip6 pqvpn_client6_<random>` table blocks all non-loopback IPv6 OUTPUT and
  IPv6 FORWARD traffic in the client's network namespace, including existing flows.
  Loopback remains available. The policy also blocks IPv6 LAN, link-local, multicast
  and neighbor-discovery output while active; routed IPv4 is unaffected. No persistent
  sysctl, global config file or unrelated firewall table is changed.
- `fail`: read IPv6 routes in all tables and IPv6 addresses before TUN/routing mutation,
  and check again before tunnel route installation. A unicast default/non-link-local
  route or usable global-scope address (including ULA) refuses connection. Errors
  inspecting state also abort. This is a conservative snapshot, not an Internet
  reachability test or continuous monitor; later network changes are not blocked.
  Use `block` for protection on changing networks.
- `allow`: explicitly allow unsupported IPv6 to bypass PQVPN, with a prominent warning.
  IPv6 traffic is unprotected and can expose the client's normal Internet address.
  This is never the full-tunnel default.

If omitted, the policy is `block` in full mode and `allow` in split mode. Explicit
`block` also works in split mode. The shipped full-tunnel TOML examples explicitly
set `block`; remove that setting when switching to split mode if unrelated IPv6
should remain available. Emulated TUN mode performs no real networking or blocking.

The block installs atomically before IPv4 tunnel routes, and its exact owned table
is removed after route/DNS rollback on disconnect, failed setup, dead-peer/control
loss, SIGTERM and rekey failure. Failed installation cannot replace an existing table.
If kernel cleanup is denied, the table name is logged for operator recovery. SIGKILL
or process/kernel crashes cannot run cleanup and may leave the IPv6 block installed;
this is not a general kill switch. Do not flush unrelated firewall tables to recover.

Doctor reports the effective policy and inspects IPv6 state without installing rules.
On a disposable test client, record `ip -6 route show table all` and verify a working
IPv6 destination before connection, failure to reach it while `block` is active, and
restored IPv6 reachability after disconnect. The expanded root namespace suite includes
bounded ICMPv6/TCP checks, preserved loopback, SIGTERM restoration and dead-peer cleanup.
Those kernel checks remain pending until the root suite actually runs.

## DNS policy

`dns_mode="systemd-resolved"` is the safe default. For full tunnel, configured VPN
DNS (client override or authenticated server list) requires working resolvectl;
missing commands or partial failures abort setup and roll back routes/DNS. Full
mode routes DNS with `~.`. Install and enable systemd-resolved before connecting.
No permanent `/etc/resolv.conf` overwrite is performed.

`dns_mode="none"` explicitly opts out, emits a warning, and accepts unmanaged DNS
and possible leakage over a more-specific LAN route. It is not a safe default.
If both configured and advertised DNS lists are empty, no DNS is installed; this
also requires operator attention before full-tunnel deployment.

Split tunnel does not automatically install `~.`. Configure
`dns_routing_domains=["~corp.example"]` for intentional split DNS routing. An empty
list configures link DNS servers without a global routing-domain override; existing
systemd-resolved link policy determines their use. Setting `~.` explicitly requests
global routing. Inspect `resolvectl status` rather than assuming resolver selection.

## Separate real-client checks

Record `ip -4 route show` and `resolvectl status` before connecting. Verify the public
exit IP, TCP/UDP, the approved resolver and DNS routing domains after connecting.
Try the VPS's VPN IP for allowed ICMP; arbitrary host TCP/UDP, other VPN clients,
metadata and private destinations must fail unless the precise forwarded private
network is allowlisted. During traffic verify epoch changes and uninterrupted data.
Then block UDP temporarily or restart the server: the client must fail and restore
its prior routes and resolver state. Verify reconnect. Native DNS restoration is
still a real-systemd-client validation gate; namespace tests do not mutate host DNS.

The management API owns its own client; it cannot control a separately launched CLI
client. Use the optional API package and [management guide](deployment.md) only
when needed. Server authentication is ML-KEM-based; client authentication is classical
Ed25519, with hybrid X25519 + ML-KEM session establishment.

## Current validation record

The [2026-09-07 validation matrix](security_audit.md#pre-vps-hardening--2026-09-07)
records a successful client doctor with native temporary identities, a matching pin,
managed DNS and a loopback server address used only for read-only route diagnostics.
This is not a connection to a deployed server. Re-run doctor against the real server
hostname and provisioned subnet before connecting. Omitted identity path fields use
the standard filenames beside the TOML, just like the explicit example paths.

The CLI dependencies are declared in `pyproject.toml` and pinned by the tested
constraints. Browser management is optional (`.[management]`); the
PyWebView desktop shell is separately installed and is not part of the validated
baseline. The Docker development profile lacks a running DNS manager by default;
its full-tunnel managed DNS must fail safely until the operator supplies one or
explicitly opts into unmanaged DNS. Root/TUN integration and real Linux-client DNS
restoration remain pending.

## Management API
### Management API v2

Bearer-authenticated POST `/api/v1/vpn/connect?config=config/client.toml` connects
using an operator-provisioned profile (including its identity pin and client key).
The dashboard uses the default profile. It does not create a VPN server or accept
host/port overrides. GET `/api/v1/vpn/servers` lists that configured profile with
`id`, `name`, `host`, `port`; there are no location or flag fields.

Connect returns `status: connected` plus the same telemetry object as GET
`/api/v1/vpn/status` and `/ws/telemetry`:

- `connection_state`: DISCONNECTED, CONNECTING, CONNECTED, FAILED (ERROR on API setup failure)
- `error`: operational failure text, without handshake payloads
- `client_vpn_ip`, `epoch`, `tun_mtu`, `tun_mode`: null when inactive
- `pqc_mode`, `is_quantum_safe`: provider posture; this does not assert PQ client authentication
- `uptime_seconds`, `rekey_countdown` (seconds, null when disabled/inactive)
- `network`: measured `rtt_ms`, `jitter_ms`, `loss_rate` (0–1), probe counts and timestamp

RTT/jitter are unavailable until a probe returns. Loss measures expired probes.
No bandwidth or byte counters are exposed because they are not measured.
The dashboard polls status, displays permanent runtime failures, and permits retry.
There is no `/logs` endpoint or activity-log UI.

## Installation and telemetry tickets

Install `.[management]` with the tested constraints after native liboqs.
Run `python -m app.main --cli` from the repository root with a configured
`PQVPN_MANAGEMENT_TOKEN`. The supported browser dashboard polls authenticated HTTP;
PyWebView is an optional, separately installed and unvalidated desktop dependency.
The WebSocket implementation is consolidated in `app/backend/api.py`.

To use WebSocket telemetry:

1. Send an authenticated HTTP `POST /api/v1/ws-ticket` with `Authorization: Bearer ...`.
2. Read `{ "ticket": "...", "expires_in": 30 }` and connect to `/ws/telemetry?ticket=...`
   with an allowed browser Origin. Use `wss` behind the configured TLS proxy remotely.
3. Obtain a fresh ticket for every connection attempt; reuse, expiry, random tickets,
   and long-lived bearer URL tokens are rejected with close code 4401.

Tickets contain 32 cryptographically random bytes encoded with URL-safe base64.
Consumption pops the entry before the first await, so it is single-use within the
ASGI event loop. Expiration uses monotonic time; issuance removes expired entries
and limits outstanding tickets to 256 (HTTP 429 when full). Storage is process-local:
use one management worker, or route issuance and upgrade to the same worker. A ticket
opens read-only telemetry and cannot authorize HTTP connect/disconnect/rekey actions.
Do not log ticket query strings. Remote management requires explicit HTTPS CORS
origins, a strong random bearer token and a TLS reverse proxy; Uvicorn stays loopback.

## Pre-VPS Validation Handoff
### Pre-VPS validation handoff

These are next-phase commands, not results from this source-validation session.
Use a disposable root-capable Linux VM first, then an explicitly provisioned VPS
and two separate Linux clients. No remote deployment or push was performed.

## Transfer the local source baseline

The tag is local and will not appear in a fresh GitHub clone until separately
published. To transfer source without pushing, run on the validated workstation:

```bash
git rev-parse 'v2-minimal-layout^{commit}'
git bundle create /tmp/pqvpn-pre-vps.bundle v2-minimal-layout
git bundle verify /tmp/pqvpn-pre-vps.bundle
```

Transfer that bundle through your authenticated channel. On each test machine:

```bash
git clone --branch v2-minimal-layout /path/to/pqvpn-pre-vps.bundle pqvpn-source
cd pqvpn-source
git rev-parse HEAD
git rev-parse 'v2-minimal-layout^{commit}'
git status --short
```

Both hashes must equal the full commit hash in the final release report. The bundle
contains committed source/history, not untracked environments or provisioned keys.

## Disposable root namespace gate

Prerequisites: root, `/dev/net/tun`, `ip`, `nft`, `curl`, `ping`, `sysctl`, `flock`,
GNU coreutils (including `timeout`), Bash, and the tested Python 3.14.7 environment.
Native build prerequisites are Git, CMake, Ninja, a C compiler and OpenSSL headers.
Use a host with working IPv6 support for the added physical-path leak checks.

From the clean validated checkout:

```bash
python3.14 --version
sudo bash scripts/install-liboqs.sh /usr/local
python3.14 -m venv /tmp/pqvpn-validation
/tmp/pqvpn-validation/bin/python -m pip install -c constraints-tested.txt '.[dev]'
ALLOW_MOCK_PQC=0 /tmp/pqvpn-validation/bin/python -m pytest -q -m native_pqc
sudo id -u
test -c /dev/net/tun
sudo env PATH="/tmp/pqvpn-validation/bin:$PATH" ALLOW_MOCK_PQC=0 timeout 180s bash tests/namespace_vpn.sh
```

The installer verifies liboqs 0.16.0 source commit
`5a1a854b0dc9f2141bdc771c555ee60c37950183`. The binding is pinned to 0.16.0.
The liboqs installer accepts an OPTIONAL absolute prefix (default `/usr/local`),
for example `sudo bash scripts/install-liboqs.sh /usr/local`. The documented equivalent pytest gate is:

```bash
sudo env PATH="/tmp/pqvpn-validation/bin:$PATH" ALLOW_MOCK_PQC=0 /tmp/pqvpn-validation/bin/python -m pytest -q -m 'integration and requires_root'
```

Run one namespace invocation; preserve its output and exit status. A skipped marker
does not pass this gate. The harness permits mock development mode internally;
require the preceding two native tests to pass and inspect runtime output for native
ML-KEM before accepting a native-backed namespace result. It creates isolated
namespaces and temporary firewall state, and never tests real systemd-resolved.

## VPS provisioning after the disposable gate passes

Use the same bundle/commit and native install commands on the VPS. Install the OS
prerequisites in [server deployment](deployment.md), including rsync and
systemd. On a fresh machine, from the clean source checkout:

```bash
sudo useradd --system --home /opt/pqvpn --shell /usr/sbin/nologin pqvpn
sudo install -d -o root -g root -m 0755 /opt/pqvpn
sudo install -d -o root -g pqvpn -m 0750 /etc/pqvpn
sudo rsync -a --chown=root:root --exclude=.git --exclude=.venv --exclude=venv --exclude=env --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache ./ /opt/pqvpn/
sudo python3.14 -m venv /opt/pqvpn/.venv
sudo /opt/pqvpn/.venv/bin/python -m pip install -c /opt/pqvpn/constraints-tested.txt /opt/pqvpn
sudo chown -R root:root /opt/pqvpn
sudo chmod -R u=rwX,go=rX /opt/pqvpn
cd /opt/pqvpn
sudo .venv/bin/python -m vpn.cli identity generate --private /etc/pqvpn/server_identity_private.key --public /etc/pqvpn/server_identity_public.key
sudo chown pqvpn:root /etc/pqvpn/server_identity_private.key
sudo chmod 0400 /etc/pqvpn/server_identity_private.key
sudo chown root:pqvpn /etc/pqvpn/server_identity_public.key
sudo chmod 0640 /etc/pqvpn/server_identity_public.key
sudo install -o root -g pqvpn -m 0640 config/server.toml /etc/pqvpn/server.toml
sudo editor /etc/pqvpn/server.toml
```

Choose the WAN, free VPN subnet, DNS servers, ports and rekey interval explicitly.
For a short rekey test, configure `rekey_interval=10` on the disposable test VPS;
record that test configuration separately from the source tag.

On each client, install the same native revision, then follow the existing client CLI:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -c constraints-tested.txt .
.venv/bin/python -m vpn.cli client-key generate
editor config/client.toml
```

Provision the server public key and exact SHA-256 fingerprint through an authenticated
channel. Set the real server host/control port, matching `expected_vpn_subnet`,
`full_tunnel=true`, `ipv6_policy="block"`, and managed DNS. Send only each client's
public key to the administrator. On the VPS, using the received public files:

```bash
sudo .venv/bin/python -m vpn.cli client authorize /tmp/alice_public.key --database /etc/pqvpn/authorized_clients.json --client-id alice
sudo chown root:pqvpn /etc/pqvpn/authorized_clients.json
sudo chmod 0640 /etc/pqvpn/authorized_clients.json
sudo .venv/bin/python -m vpn.cli client authorize /tmp/bob_public.key --database /etc/pqvpn/authorized_clients.json --client-id bob
sudo chown root:pqvpn /etc/pqvpn/authorized_clients.json
sudo chmod 0640 /etc/pqvpn/authorized_clients.json
sudo -u pqvpn .venv/bin/python -m vpn.cli doctor server --config /etc/pqvpn/server.toml
python3.14 -m venv /tmp/pqvpn-validation
/tmp/pqvpn-validation/bin/python -m pip install -c constraints-tested.txt '.[dev]'
ALLOW_MOCK_PQC=0 /tmp/pqvpn-validation/bin/python -m pytest -q -m native_pqc
```

Run the root namespace command above on the VPS too when possible, before public
deployment. Configure provider and host firewalls to permit the configured VPN TCP
and UDP ports (both default to 51820) and appropriate administrator SSH access.
Do not expose port 8000 or a management API. Provider commands depend on the provider;
local doctor cannot verify that policy.

## Setup, systemd and real-client gates

The service runs `scripts/server-network.sh setup /etc/pqvpn/server.toml` via ExecStartPre,
using `/opt/pqvpn/.venv/bin/python`; ExecStopPost runs server cleanup. Start it with
the documented commands, which therefore perform setup before starting the daemon:

```bash
sudo cp deploy/pqvpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pqvpn-server
sudo systemctl status pqvpn-server
sudo journalctl -u pqvpn-server -b --no-pager
ip addr show pqvpn0
sudo ss -lntup
sudo nft list ruleset
```

Require the expected TUN address, TCP/UDP listeners, PQVPN filter/NAT/mangle tables,
working SSH and no public management listener. If manual setup is needed for a
foreground daemon, its actual invocation is:

```bash
sudo env PQVPN_PYTHON=/opt/pqvpn/.venv/bin/python bash scripts/server-network.sh setup /etc/pqvpn/server.toml
```

On each real Linux client, record baseline IPv4/IPv6 routes and resolver state,
then use the documented doctor and connection commands:

```bash
ip -4 route show
ip -6 route show table all
resolvectl status
.venv/bin/python -m vpn.cli doctor client --config config/client.toml
sudo -E .venv/bin/python -m vpn.cli client connect --config config/client.toml
```

While connected, use a second terminal for these gates:

| Gate | Required evidence |
|---|---|
| Exit IP | An IPv4 external address lookup reports the VPS public IP; record before/during values. |
| DNS | `resolvectl status` shows the approved DNS on pqvpn0 and full-tunnel `~.`; resolve a fresh name and verify the selected interface/resolver. |
| TCP | Bounded HTTP requests to a known reachable public test service succeed through the tunnel. |
| UDP | Exchange a datagram with a controlled public UDP echo service and verify its reply; the namespace harness contains the socket probe. |
| IPv6 | A known working IPv6 destination becomes unreachable using both bounded `ping -6` and `curl -6`; `ping -6 ::1` still works. Verify the owned table with `sudo nft list tables ip6`. No working pre-connect IPv6 means the real-path leak test is inconclusive. |
| Rekey | Continue TCP/UDP traffic over multiple configured rekey intervals. Observe advancing epoch fields in captured PQVPN UDP headers, or use the optional API-owned client's epoch telemetry described in the management guide. The API cannot observe/control a separate CLI client. Traffic continuity alone is not proof of rekey. |
| Dead peer | On a disposable test VPS, temporarily drop server UDP/51820 output in a separately owned test nft table while leaving TCP alive, as in `tests/namespace_vpn.sh`. Require client FAILED within its dead-peer timeout, TUN removal and route/DNS/IPv6 restoration; remove only that test table and reconnect. |
| Control loss | `sudo systemctl restart pqvpn-server` disconnects all clients; verify client cleanup and reconnect. |
| Two-client isolation | Run a known listener on client B's VPN address. Client A must not reach it; verify the listener locally first. |
| Host/metadata/private blocking | Known VPS host services, `169.254.169.254`, and controlled private services must be inaccessible unless a precise forwarded destination is allowlisted. The root harness supplies known-positive fixtures; an unreachable service alone cannot prove filtering. |
| Disconnect/SIGTERM | Stop the client normally and via SIGTERM in separate runs; compare routes and `resolvectl status` with baseline and recheck IPv6 connectivity. No owned client IPv6 guard should remain. |

Use bounded probes (`curl --max-time`, `ping -c ... -W ...`) and record each gate
separately. Do not mark Docker, systemd, real resolver restoration, or VPS/client
validation passed until the corresponding runtime has actually been exercised.
Revocation affects future sessions; active sessions continue until disconnect,
expiration or server restart. No remote session-kill subsystem is present.

## Privileged systemd execution trust boundary

Every executable, script, interpreter and module used directly or indirectly by
`ExecStartPre=+` and `ExecStopPost=+` must be root-owned and not writable by
`pqvpn`, its groups, or other users. This includes `/opt/pqvpn/scripts/server-network.sh`,
`/opt/pqvpn/vpn/network.py`, all application
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
