# Pre-VPS validation handoff

These are next-phase commands, not results from this source-validation session.
Use a disposable root-capable Linux VM first, then an explicitly provisioned VPS
and two separate Linux clients. No remote deployment or push was performed.

## Transfer the local source baseline

The tag is local and will not appear in a fresh GitHub clone until separately
published. To transfer source without pushing, run on the validated workstation:

```bash
git rev-parse 'v2-pre-vps-2^{commit}'
git bundle create /tmp/pqvpn-pre-vps.bundle v2-pre-vps-2
git bundle verify /tmp/pqvpn-pre-vps.bundle
```

Transfer that bundle through your authenticated channel. On each test machine:

```bash
git clone --branch v2-pre-vps-2 /path/to/pqvpn-pre-vps.bundle pqvpn-source
cd pqvpn-source
git rev-parse HEAD
git rev-parse 'v2-pre-vps-2^{commit}'
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
/tmp/pqvpn-validation/bin/python -m pip install -r requirements-dev.txt
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
prerequisites in [server deployment](server_deployment.md), including rsync and
systemd. On a fresh machine, from the clean source checkout:

```bash
sudo useradd --system --home /opt/pqvpn --shell /usr/sbin/nologin pqvpn
sudo install -d -o root -g root -m 0755 /opt/pqvpn
sudo install -d -o root -g pqvpn -m 0750 /etc/pqvpn
sudo rsync -a --chown=root:root --exclude=.git --exclude=.venv --exclude=venv --exclude=env --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache ./ /opt/pqvpn/
sudo python3.14 -m venv /opt/pqvpn/.venv
sudo /opt/pqvpn/.venv/bin/python -m pip install -r /opt/pqvpn/requirements-server.txt
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
.venv/bin/python -m pip install -r requirements-client.txt
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
/tmp/pqvpn-validation/bin/python -m pip install -r requirements-dev.txt
ALLOW_MOCK_PQC=0 /tmp/pqvpn-validation/bin/python -m pytest -q -m native_pqc
```

Run the root namespace command above on the VPS too when possible, before public
deployment. Configure provider and host firewalls to permit the configured VPN TCP
and UDP ports (both default to 51820) and appropriate administrator SSH access.
Do not expose port 8000 or a management API. Provider commands depend on the provider;
local doctor cannot verify that policy.

## Setup, systemd and real-client gates

The service runs `scripts/server-setup.sh /etc/pqvpn/server.toml` via ExecStartPre,
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
sudo env PQVPN_PYTHON=/opt/pqvpn/.venv/bin/python bash scripts/server-setup.sh /etc/pqvpn/server.toml
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
`pqvpn`, its groups, or other users. This includes `/opt/pqvpn/scripts/server-setup.sh`,
`/opt/pqvpn/scripts/server-cleanup.sh`, `/opt/pqvpn/vpn/firewall.py`, all application
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
