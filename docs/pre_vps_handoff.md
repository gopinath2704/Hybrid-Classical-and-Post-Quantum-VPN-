# Pre-VPS validation handoff

These are next-phase commands, not results from this source-validation session.
Use a disposable root-capable Linux VM first, then an explicitly provisioned VPS
and two separate Linux clients. No remote deployment or push was performed.

## Transfer the local source baseline

The tag is local and will not appear in a fresh GitHub clone until separately
published. To transfer source without pushing, run on the validated workstation:

```bash
git rev-parse 'v2-pre-vps^{commit}'
git bundle create /tmp/pqvpn-pre-vps.bundle v2-pre-vps
git bundle verify /tmp/pqvpn-pre-vps.bundle
```

Transfer that bundle through your authenticated channel. On each test machine:

```bash
git clone --branch v2-pre-vps /path/to/pqvpn-pre-vps.bundle pqvpn-source
cd pqvpn-source
git rev-parse HEAD
git rev-parse 'v2-pre-vps^{commit}'
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
The script takes no arguments. The documented equivalent pytest gate is:

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
sudo install -d -o pqvpn -g pqvpn -m 0750 /opt/pqvpn /etc/pqvpn
sudo rsync -a --chown=pqvpn:pqvpn --exclude=.git --exclude=.venv --exclude=venv --exclude=env --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache ./ /opt/pqvpn/
sudo -u pqvpn python3.14 -m venv /opt/pqvpn/.venv
sudo -u pqvpn /opt/pqvpn/.venv/bin/python -m pip install -r /opt/pqvpn/requirements-server.txt
cd /opt/pqvpn
sudo -u pqvpn .venv/bin/python -m vpn.cli identity generate --private /etc/pqvpn/server_identity_private.key --public /etc/pqvpn/server_identity_public.key
sudo install -o pqvpn -g pqvpn -m 0640 config/server.toml /etc/pqvpn/server.toml
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
sudo -u pqvpn .venv/bin/python -m vpn.cli client authorize /tmp/alice_public.key --database /etc/pqvpn/authorized_clients.json --client-id alice
sudo -u pqvpn .venv/bin/python -m vpn.cli client authorize /tmp/bob_public.key --database /etc/pqvpn/authorized_clients.json --client-id bob
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
