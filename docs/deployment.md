# PQ-VPN Deployment

PQ-VPN is a research prototype. Passing unit tests does not approve a deployment:
first run doctor, the native ML-KEM tests and the root namespace suite on a disposable
Linux VM, then check a real server with a separate Linux client. Record each of those
results on its own line. For AWS, see [AWS EC2 deployment](#aws-ec2-deployment), which
`scripts/deploy-server.sh` automates.

## Components and tested versions

| Part | What runs | Pinned by |
|---|---|---|
| Server daemon, account API, GUI, Python client | CPython (tested baseline **3.14.7**, minimum 3.11) | `pyproject.toml`, `constraints-tested.txt` |
| Python ML-KEM | native **liboqs 0.16.0** (commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`) + liboqs-python 0.16.0 | `scripts/install-liboqs.sh`, `constraints-tested.txt` |
| Rust core `pqvpn_core` (data plane, handshake) and native client `pqvpnd` | aws-lc-rs (ML-KEM, X25519, Ed25519, AES-GCM) | `core/Cargo.lock`, toolchain `core/rust-toolchain.toml` (1.99.1; MSRV 1.85) |

Doctor reports the 3.11 minimum and the 3.14.7 baseline separately; meeting the
minimum does not validate another Python. Install `.` for the daemon and CLI,
`.[desktop]` for the GUI and `.[dev]` for tests and benchmarks, always with
`-c constraints-tested.txt`.

aws-lc is built without CPU Jitter Entropy (`AWS_LC_SYS_NO_JITTER_ENTROPY=1` in the
repo-root `.cargo/config.toml`, picked up by cargo, maturin, the PKGBUILD and
debian/rules). Its DRBG is seeded from `getrandom` plus RDRAND, the same OS source the
Python path uses. The cost is aws-lc's second independent entropy source and FIPS
compatibility (not used here). The reason, about 27 ms on every cold connect, is in
[docs/rust-core-migration-plan.md](rust-core-migration-plan.md#phase-5-results).

## Native liboqs

Install OS prerequisites (Python with venv, git, CMake, Ninja, a C compiler, OpenSSL
headers, iproute2, nftables, util-linux, rsync, procps), then:

```bash
sudo bash scripts/install-liboqs.sh /usr/local   # verifies the 0.16.0 commit, builds a shared library, runs ldconfig
ldconfig -p | grep liboqs
```

The helper refuses any other commit. PQ-VPN looks for the installed library before
importing the binding, so a missing liboqs fails closed (`PQCUnavailableError`) and
never triggers the binding's automatic download/build. Never use mock PQC in a
deployment. For a custom prefix set `OQS_INSTALL_PATH` and configure the loader.
Before deploying, recheck the upstream
[liboqs advisories](https://github.com/open-quantum-safe/liboqs/security): a needed
upgrade is a new validation pass, not a drop-in.

## Server

### Install and provision

`scripts/deploy-server.sh` runs these steps (and the account API setup) on Ubuntu.
By hand, from a clean checkout:

```bash
sudo useradd --system --home /opt/pqvpn --shell /usr/sbin/nologin pqvpn
sudo install -d -o root -g root -m 0755 /opt/pqvpn
sudo install -d -o root -g pqvpn -m 0750 /etc/pqvpn
sudo install -d -o root -g pqvpn -m 2770 /var/lib/pqvpn/authorized
sudo rsync -a --chown=root:root --exclude=.git --exclude=.venv --exclude=venv --exclude=env --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache --exclude=target ./ /opt/pqvpn/
sudo python3 -m venv /opt/pqvpn/.venv
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
# Only the client's PUBLIC key, received over an authenticated channel:
sudo .venv/bin/python -m vpn.cli client authorize /tmp/alice_public.key --database /var/lib/pqvpn/authorized/authorized_clients.json --client-id alice
sudo -u pqvpn .venv/bin/python -m vpn.cli doctor server --config /etc/pqvpn/server.toml
```

In `server.toml`, choose the WAN (`outbound_interface`), a free VPN subnet, DNS
servers, ports and `rekey_interval` explicitly. `protocol_version` must match the
clients: managed desktop clients speak 2 (the code default), while the repo example
sets 3. A v3 server rejects v2 clients ("Unsupported version"). Other server options:
`resumption_ticket_lifetime` (default 86400 s, 0 disables 1-RTT resumption) and
`cookie_mode` (`off` by default, `under_load` or `always`, a stateless cookie against
ClientHello floods).

Private identities must be regular, non-symlink files with mode 0600 or 0400. The
server checks key lengths and keypair consistency before it opens TUN or a listener.
Never copy a server private key to a client; clients get only its public key and
SHA-256 pin. The client database is strictly validated at startup: malformed records,
mismatched fingerprints, duplicate identities, client IDs or static leases, and
unusable addresses all fail startup. CLI updates lock, fsync and atomically replace it.
Each handshake re-reads the database, so a newly authorized client can connect
without a restart; account auto-approve relies on this. Static leases (`--vpn-ip`) are
reserved only at startup, so restart `pqvpn-server` after adding or changing one.

Doctor is read-only (PASS/WARN/FAIL, nonzero on a blocking failure). It checks native
crypto, config, identities, visible routes and interfaces (including Docker), commands,
the WAN, ports, forwarding and service-user access. It cannot see the provider firewall.

### Privileged systemd execution trust boundary

`packaging/common/pqvpn-server.service` runs the daemon as `User=pqvpn`,
`Group=pqvpn` with only `CAP_NET_ADMIN`, `ProtectSystem=strict` and
`RuntimeDirectory=pqvpn`. Firewall setup and cleanup run as root through
`ExecStartPre=+` and `ExecStopPost=+` (`/opt/pqvpn/scripts/server-network.sh setup|cleanup /etc/pqvpn/server.toml`).

So every file that root path executes or imports must be root-owned and not writable
by `pqvpn`, its groups or others: `/opt/pqvpn/scripts/server-network.sh`,
`/opt/pqvpn/vpn/network.py`, all application packages, `/opt/pqvpn/.venv/bin/python`,
the whole venv, symlink targets and their parent directories. Create the venv and
install dependencies as root, never as `pqvpn`. Update while stopped, restore
ownership and modes, and rerun doctor before restarting. `chown` cannot remove code
already planted in a service-owned tree; rebuild such an install from trusted inputs.
Server doctor checks the whole `/opt/pqvpn` tree, symlink targets and ancestors.

| Path | Owner and mode | Why |
|---|---|---|
| `/opt/pqvpn` (code + venv) | `root:root`, dirs 0755, files 0644 | root executes it |
| `/etc/pqvpn` | `root:pqvpn 0750` | group may read, never write |
| `server.toml`, public identity | `root:pqvpn 0640` | |
| server private identity | `pqvpn:root 0400` | the daemon reads it but cannot replace it via the directory (as owner it could still chmod it) |
| `/var/lib/pqvpn/authorized` | `root:pqvpn 2770` (setgid) | holds `authorized_clients.json`, its lock and temp files, so the account API (group `pqvpn`) can update it without write access to `/etc/pqvpn` |

Each database update writes mode 0640 with the directory's group. Never chown or chmod
paths inside that group-writable directory as root.

### Start the service

```bash
sudo cp packaging/common/pqvpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pqvpn-server
sudo journalctl -u pqvpn-server -b --no-pager
ip addr show pqvpn0
sudo ss -lntup
sudo nft list ruleset
```

Expect the TUN address, the TCP and UDP listeners and the three PQ-VPN tables. For a
foreground daemon, run setup yourself first:
`sudo env PQVPN_PYTHON=/opt/pqvpn/.venv/bin/python bash scripts/server-network.sh setup /etc/pqvpn/server.toml`.
Relative key and database paths in the TOML resolve inside `/etc/pqvpn`.

### Rust data plane and handshake

Both settings live in `[server]` (and in an explicit client TOML). Defaults are `python`.

| Setting | Effect | Requires |
|---|---|---|
| `data_plane = "rust"` | UDP loop in Rust (recvmmsg/sendmmsg, GSO/GRO); thread `pqvpn-dp` | `pqvpn_core` importable |
| `handshake = "rust"` | handshake state machines in Rust; Python keeps authorization, the address pool, cookies, the rate limiter and revocation | `data_plane = "rust"`; not `experimental_suite = "v3-mldsa"` |

Config validation refuses a combination it cannot run, so a bad value fails at start,
not mid-session.

The server build needs a root Rust toolchain. `deploy-server.sh` installs cmake and a
C compiler, never rustup, so install it once:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
sudo env RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal --default-toolchain "$(sed -n 's/^channel = "\(.*\)"/\1/p' core/rust-toolchain.toml)"
```

Then `sudo env PQVPN_DATA_PLANE=rust bash scripts/deploy-server.sh` builds
`core/pqvpn_core` into `/opt/pqvpn/.venv` (pip runs maturin with `--locked`, so deploy
only a committed tree), sets `data_plane = "rust"` (backup `server.toml.bak.<stamp>`),
validates the config and restarts `pqvpn-server`, which drops live tunnels. Later
deploys rebuild the core whenever `server.toml` says rust. The script does not touch
`handshake`: set `handshake = "rust"` in `/etc/pqvpn/server.toml` by hand after the
data plane is rust, then restart. The release profile uses thin LTO; on a 2 GB host add
swap before the first build if `free -m` shows less than about 1.5 GB available.

The Rust loop asks for a 4 MB UDP receive buffer, which the kernel caps at
`net.core.rmem_max`, and Debian/Ubuntu keep the default of about 208 KB. To let it
take effect, set `net.core.rmem_max = 4194304` in `/etc/sysctl.d/` and run
`sysctl --system`. UNVERIFIED on EC2: no throughput number was measured there.

Check: `ps -L -o comm= -p "$(systemctl show -p MainPID --value pqvpn-server)" | grep -x pqvpn-dp`,
and `journalctl -u pqvpn-server` must not show `rust data plane failed`. Roll back with
`sudo env PQVPN_DATA_PLANE=python bash scripts/deploy-server.sh` (set `handshake =
"python"` first if you changed it, or validation refuses the config).

### Firewall policy and subnet

Setup atomically replaces the tables PQ-VPN owns (`inet pqvpn`, `ip pqvpn_nat`,
`inet pqvpn_mangle`) from the validated TOML, so re-running reconciles. No unrelated
table or global DROP policy is installed. Existing host policy can still block VPN traffic.

TUN policy: IPv4 to the WAN after destination filtering, and established return
traffic. Denied: client to client, other interfaces, VPS host services (only ICMP
echo to `server_vpn_ip` with `allow_server_ping = true`), metadata `169.254.0.0/16`,
RFC1918, CGNAT, loopback, multicast and reserved ranges. `allowed_forward_networks`
(empty by default, e.g. `["10.50.0.10/32"]`) opens specific private destinations
through the WAN; it cannot enable client-to-client or host access.

`manage_ip_forward = true` saves the original sysctl once in `/run/pqvpn/ip_forward.prev`
and cleanup restores it. `false` requires forwarding already on. If doctor reports
that `10.8.0.0/24` collides, choose another subnet explicitly and update
`server_vpn_ip`, static leases and each client's `expected_vpn_subnet`. Clients use the
provisioned TCP port; the UDP port comes from the authenticated server CONFIG.

### Revocation

```bash
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli client revoke FINGERPRINT --database /var/lib/pqvpn/authorized/authorized_clients.json
```

A new ClientHello, rekey or rehandshake from a disabled client is refused right away.
Every 30 s the server re-reads the database, ends the sessions of clients that are no
longer enabled, and rotates the resumption-ticket key so their tickets stop working
(`_revocation_loop` in `vpn/runtime.py`). The same applies to account sign-out and
administrator revocation ([accounts.md](accounts.md)). No server restart is needed.

## Validation gates

**Native and root namespace gate** (disposable VM; needs root, `/dev/net/tun`, iproute2,
nftables, curl, ping):

```bash
python3 -m venv /tmp/pqvpn-validation
/tmp/pqvpn-validation/bin/python -m pip install -c constraints-tested.txt '.[dev]'
ALLOW_MOCK_PQC=0 /tmp/pqvpn-validation/bin/python -m pytest -q -m native_pqc
sudo env PATH="/tmp/pqvpn-validation/bin:$PATH" ALLOW_MOCK_PQC=0 /tmp/pqvpn-validation/bin/python -m pytest -q -m 'integration and requires_root'
```

The namespace test (bounded at 180 s) covers two clients, public TCP/UDP/NAT,
isolation, metadata and private blocking, allowlist reconciliation, idle sessions,
rekey, a UDP blackhole, reconnect and forwarding restore. It does not touch the host's
systemd-resolved. A SKIP is not a PASS. The leak harness
`bash pentesting/attacks/attack33_40_network_leaks.sh` (no sudo, private namespace)
adds DNS, IPv6 and kill-switch cases.

**Provider and real-client checklist.** Open only the VPN ports (51820/TCP and
51820/UDP by default), SSH from administrator addresses, and 8443/TCP only if the
account API is used. Then, from a separate Linux client, record `ip -4 route show`,
`ip -6 route show table all` and `resolvectl status` before connecting, and check:

| Gate | Evidence |
|---|---|
| Exit IP | external IPv4 lookup shows the server address |
| DNS | `resolvectl status` shows the VPN DNS on `pqvpn0`, with `~.` in full tunnel |
| TCP / UDP | bounded requests to known public services succeed |
| IPv6 | a known working IPv6 destination becomes unreachable (`ping -6`, `curl -6`); `ping -6 ::1` still works |
| Rekey | traffic continues across several rekey intervals while the status epoch advances |
| Dead peer | drop server UDP in a separate test nft table: the client must reach FAILED within `dead_peer_timeout` and restore routes, DNS and IPv6 |
| Control loss | `sudo systemctl restart pqvpn-server`: clients clean up, then reconnect |
| Isolation | client A cannot reach a listener on client B; host services, `169.254.169.254` and private services are blocked |
| Disconnect / SIGTERM | routes and `resolvectl status` match the baseline, and no `pqvpn_client6_*` table remains |

Use bounded probes (`curl --max-time`, `ping -c N -W S`).

## Clients

### Desktop (managed) client

The GUI runs as the desktop user and talks to the privileged `pqvpn-client` service
over a local socket. The service accepts IPC only from root and the uids in
`PQVPN_ALLOWED_UIDS`, set in a drop-in. `install-client.sh` and the Debian postinst
write it from `SUDO_UID`. For the Arch package, create it yourself before the first install:

```bash
sudo install -d /etc/systemd/system/pqvpn-client.service.d
printf '[Service]\nEnvironment=PQVPN_ALLOWED_UIDS=%s\n' "$(id -u)" | sudo tee /etc/systemd/system/pqvpn-client.service.d/allowed-uids.conf
```

Without the drop-in the GUI shows "not authorized". From a checkout,
`sudo bash scripts/install-client.sh` installs liboqs, a root-owned `/opt/pqvpn` with
the GUI extra, the service and the `pqvpn-gui` launcher. It builds no Rust, so it gives
the Python backend only. Use either it or a package, not both: both install a
`pqvpn-client` unit.

The service keeps its state in `/var/lib/pqvpn` (mode 0700): an Ed25519 device identity
created once (private key 0600), and imported public profiles. The GUI gets only
public data. By default it signs in at `https://52.62.237.95:8443` and pins the
bundled `app/server-account-api.crt` exclusively. `PQVPN_ACCOUNT_API_URL` and
`PQVPN_ACCOUNT_CA_CERT` override that. Registration needs an invite, and signing out
suspends the device on the server; see [accounts.md](accounts.md).

Without an account, a profile can be imported by hand. Create a `.pqvpn` file from
the server's **public** key and send it over an authenticated channel. Then authorize
the `.pqenroll` request the GUI exports:

```bash
sudo /opt/pqvpn/.venv/bin/python - <<'PY'
import base64, hashlib, json
from pathlib import Path
public = Path("/etc/pqvpn/server_identity_public.key").read_bytes()
assert len(public) == 1184, "expected an ML-KEM-768 public key"
profile = {"version": 1, "profile_id": "lab", "name": "Lab Server", "server_host": "SERVER_IP",
           "server_control_port": 51820, "expected_vpn_subnet": "10.8.0.0/24",
           "server_identity_public_key": base64.b64encode(public).decode("ascii"),
           "server_identity_fingerprint": hashlib.sha256(public).hexdigest()}
Path("/tmp/lab.pqvpn").write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli client authorize-request /tmp/laptop.pqenroll \
  --database /var/lib/pqvpn/authorized/authorized_clients.json
```

The profile and the enrollment request hold public keys only. Import (8 KiB bound),
selection and removal are refused while a tunnel is up. Managed mode uses protocol v2
and the Python backend.

### Packages

Both formats install the GUI launcher, the Python application, `pqvpn_core`,
`/usr/bin/pqvpnd`, the `pqvpn-client.service` (enabled) and `pqvpn-account-api.service`
(installed but not enabled, since its unit points at the `/opt/pqvpn` server layout).
They never ship a private key, a trusted profile, a TLS key or a client database.
liboqs and liboqs-python are not in the distribution repos, so install them first. The
packaged service runs the system `python3 -s`, so the binding must be system-wide:

```bash
sudo bash scripts/install-liboqs.sh /usr/local
sudo pip install --break-system-packages liboqs-python==0.16.0
```

The flag is needed because the system Python on both Arch and Debian is PEP 668
"externally managed".

Both builds need network access for `cargo` (crates pinned by `Cargo.lock`; vendoring
is a follow-up). The repository declares no license, so the packages must not be
redistributed until the owner adds one.

**Arch / Omarchy.** The PKGBUILD builds from an allowlisted `git archive` of the
committed tree, with fixed mtimes so the checksum depends only on content:

```bash
git archive --format=tar.gz --mtime=2026-09-14T00:00:00Z --prefix=pqvpn-3.0.0/ \
  --output=packaging/arch/pqvpn-3.0.0.tar.gz 'HEAD^{tree}' -- \
  app crypto handshake vpn pyproject.toml README.md \
  docs/design.md docs/deployment.md docs/accounts.md packaging/common \
  config/account-api.toml scripts core .cargo
(cd packaging/arch && updpkgsums && makepkg -fC)
sudo pacman -U packaging/arch/pqvpn-3.0.0-1-x86_64.pkg.tar.zst
sudo systemctl restart pqvpn-client
```

The allowlist must match both lists in `tests/test_onboarding.py`, and that test pins
the archive's content digest. After a commit that changes any listed path, recreate the
archive, refresh `sha256sums` and the test pin in a checksum-only commit, and never
use `SKIP`. Always build with `-C`: the archive's fixed mtimes make a reused `src/`
build look newer than the sources, and the package silently ships old code. Check before installing:
`tar --zstd -xOf pqvpn-3.0.0-1-x86_64.pkg.tar.zst usr/lib/python3.14/site-packages/app/client.py | grep -c parse_allowed_uids`
must print `2`. `options=('!lto')` is required because makepkg's LTO makes aws-lc objects unlinkable.

**Debian 13 (trixie).** `dpkg-buildpackage` wants `debian/` at the top of the tree.
On a non-Debian host, build in a `debian:trixie` container (rustc 1.85.1 there is the MSRV check):

```bash
rm -rf /tmp/debbuild && mkdir -p /tmp/debbuild/pqvpn-3.0.0
git archive HEAD | tar -x -C /tmp/debbuild/pqvpn-3.0.0
cp -a packaging/deb/debian /tmp/debbuild/pqvpn-3.0.0/debian
sudo docker run --rm -v /tmp/debbuild:/build -e OWNER="$(id -u):$(id -g)" debian:trixie bash -c '
  apt-get update && apt-get install -y --no-install-recommends ca-certificates build-essential cargo rustc \
    python3-maturin debhelper dh-python dh-sequence-installsysusers pybuild-plugin-pyproject python3-all \
    python3-build python3-cryptography python3-installer python3-setuptools python3-wheel &&
  cd /build/pqvpn-3.0.0 && dpkg-buildpackage --build=binary --no-sign; s=$?; chown -R "$OWNER" /build; exit $s'
```

This exact `docker run` wrapper is UNVERIFIED. It installs the same package list as
the 2026-10-31 trixie build, which succeeded, but it was written for this doc and has
not been run as written. `ca-certificates` must be listed because
`--no-install-recommends` skips it, and
cargo cannot fetch crates without it. The closing `chown` returns the root-owned
output to you. debian/rules sets `PYO3_BUILD_EXTENSION_MODULE=1` on both the maturin
and the `pqvpnd` cargo line, so nothing links libpython, and `optimize=-lto` for the
same reason as the PKGBUILD. dpkg-shlibdeps warnings about unresolved `PyErr_*` in the
abi3 extension are expected. The build-time check only prints `pqc_mode`, because liboqs
is enforced at runtime. Install-testing the `.deb` on a real Debian-family host is
UNVERIFIED (it has been built in the container only).

### Explicit-TOML client (CLI)

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -c constraints-tested.txt .
.venv/bin/python -m vpn.cli client-key generate          # add --kem for protocol_version = 3
# send only config/client_identity_public.key to the administrator; set server_host,
# the server key + fingerprint and expected_vpn_subnet in config/client.toml
.venv/bin/python -m vpn.cli doctor client --config config/client.toml
sudo -E .venv/bin/python -m vpn.cli client connect --config config/client.toml
```

`--config PATH` means that TOML only; without it the service uses managed state. The
two are never merged. The service can also run a TOML:
`sudo PQVPN_ALLOWED_UIDS=$(id -u) .venv/bin/python -m app.client --service --config config/client.toml`.
Do not run the foreground CLI alongside the service. The obsolete `server_udp_port`
setting is rejected. `ping_interval` (5 s), `ping_timeout` (4 s) and
`dead_peer_timeout` (30 s) govern liveness: only authenticated server UDP refreshes the
deadline, and when it expires the client fails, closes the TUN and restores routes and
DNS. Reconnecting is manual.

### Native client (pqvpnd)

`sudo pqvpnd connect --config client.toml [--status-json]` reads the same `[client]`
table and refuses, with a reason, any option it does not implement. It runs `ip`, `nft`
and `resolvectl` only from `/usr/bin`, `/usr/sbin`, `/bin` or `/sbin`, and uses
aws-lc's ML-KEM, not liboqs. With `client_backend = "native"` in an explicit TOML, the
client service supervises `/usr/bin/pqvpnd connect --status-json` and treats each JSON
status line as untrusted (an invalid stream stops it and fails closed). Managed profiles
always use the Python backend.

### Kill switch

`kill_switch = true` requires `full_tunnel = true`, `ipv6_policy` `block` or `fail`, and
an IPv4 literal as `server_host`. Both clients install an nft table,
`inet pqvpn_killswitch`, before the tunnel comes up. While it is on, nothing leaves the
host outside the tunnel, LAN and IPv6 included. A lost session or a crash (even
SIGKILL) leaves traffic blocked, and the GUI shows BLOCKED. Only the user's Disconnect,
`sudo pqvpn client recover` or `sudo pqvpnd recover` lifts it; both commands are safe
to repeat. The switch is not active after a reboot until the first connect. After a
SIGKILL, also remove the leftover IPv6 guard by hand (`sudo nft list tables ip6`, then
`sudo nft delete table ip6 pqvpn_client6_<id>`); recover does not remove it. The
real-host `sudo kill -9` check is UNVERIFIED (verified in a network namespace only).

### IPv6 policy

IPv4 is tunnelled; IPv6 is not, so the client blocks it instead of letting it leak.
`ipv6_policy`:

- `block` (full-tunnel default): an owned `ip6 pqvpn_client6_<random>` table drops all
  non-loopback IPv6 output and forwarding, including existing flows. Needs `nft` and
  root. It is installed before the IPv4 routes and removed after route/DNS rollback on
  disconnect, failure, dead peer, SIGTERM or rekey failure.
- `fail`: refuse to connect if a default or global IPv6 route or address exists
  (checked twice before routes go in). This is a snapshot, not a monitor; use `block` on
  changing networks.
- `allow`: unprotected IPv6 bypasses the tunnel, with a warning. Never the full-tunnel default.

When the setting is omitted, the policy is `block` in full-tunnel mode and `allow` in
split mode. The shipped full-tunnel example sets `block` explicitly; remove that line
when switching to split mode.

### DNS policy

`dns_mode = "systemd-resolved"` is the default. A full tunnel routes DNS with `~.` to
the VPN servers (client override, or the authenticated server list) through
`resolvectl`. A missing `resolvectl` or a partial failure aborts setup and rolls back.
**A full tunnel with managed DNS and no DNS servers is refused**, because it would leak
DNS outside the tunnel; both clients enforce this. Split tunnel installs no `~.`. Use
`dns_routing_domains = ["~corp.example"]` for split DNS. `dns_mode = "none"` opts out
with a warning and accepts possible DNS leaks. The client never rewrites `/etc/resolv.conf`.

## AWS EC2 deployment

One small Ubuntu instance runs the server; `scripts/deploy-server.sh` performs the
install above. The validation gates still apply.

### 1. AWS side

| Setting | Value |
|---|---|
| AMI | Ubuntu Server 26.04 LTS, x86_64 |
| Instance type | `t3.small` (2 GB; the liboqs and Rust builds are slow on `t3.micro`) |
| Disk | 16 GB gp3 |
| Metadata | IMDSv2 required |
| Elastic IP | allocate and associate, so `server_host` stays fixed |

Security group, inbound only:

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 22 | TCP | your IP `/32` | SSH |
| 51820 | TCP | `0.0.0.0/0` | control channel (handshake) |
| 51820 | UDP | `0.0.0.0/0` | data channel |
| 8443 | TCP | trusted `/32`s, or `0.0.0.0/0` (see 4a) | account API (HTTPS) |

AWS CLI equivalent (replace the region, key name and IP):

```bash
REGION=eu-west-2 KEY=pqvpn MYIP=$(curl -s https://checkip.amazonaws.com)/32
AMI=$(aws ssm get-parameter --region $REGION --query Parameter.Value --output text \
  --name /aws/service/canonical/ubuntu/server/26.04/stable/current/amd64/hvm/ebs-gp3/ami-id)
SG=$(aws ec2 create-security-group --region $REGION --group-name pqvpn \
  --description "PQ-VPN" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region $REGION --group-id $SG --protocol tcp --port 22 --cidr $MYIP
aws ec2 authorize-security-group-ingress --region $REGION --group-id $SG --protocol tcp --port 51820 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region $REGION --group-id $SG --protocol udp --port 51820 --cidr 0.0.0.0/0
ID=$(aws ec2 run-instances --region $REGION --image-id $AMI --instance-type t3.small \
  --key-name $KEY --security-group-ids $SG --metadata-options HttpTokens=required \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=16,VolumeType=gp3}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=pqvpn}]' \
  --query 'Instances[0].InstanceId' --output text)
EIP=$(aws ec2 allocate-address --region $REGION --query AllocationId --output text)
aws ec2 wait instance-running --region $REGION --instance-ids $ID
aws ec2 associate-address --region $REGION --instance-id $ID --allocation-id $EIP
```

These create billable resources; tear them down in step 5.

### 2. Server install

```bash
ssh -i pqvpn.pem ubuntu@<ELASTIC_IP>
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/gopinath2704/hybrid-classical-and-post-quantum-vpn-.git pqvpn-src
cd pqvpn-src
sudo env PQVPN_PUBLIC_HOST=<ELASTIC_IP> bash scripts/deploy-server.sh                      # install only
sudo env PQVPN_PUBLIC_HOST=<ELASTIC_IP> bash scripts/deploy-server.sh /tmp/alice_public.key alice  # + authorize, doctor, start
```

The script installs OS packages and liboqs, creates `/opt/pqvpn` and the service users,
generates the server identity, installs `server.toml` (WAN auto-detected) and the
account API with a self-signed certificate whose SAN covers `PQVPN_PUBLIC_HOST`, and
prints the server fingerprint. It is idempotent: an existing identity, `server.toml`
and client database are kept, and a legacy client database under `/etc/pqvpn/` is
migrated to `/var/lib/pqvpn/authorized/`. For the Rust backends, install root rustup
and pass `PQVPN_DATA_PLANE=rust` ([Rust data plane and handshake](#rust-data-plane-and-handshake)).

### 3. TOML (CLI) client

On the client, generate a key (`client-key generate --kem` for v3) and copy only the
public key to the server (`scp ... ubuntu@<ELASTIC_IP>:/tmp/alice_public.key`) before
the second deploy command above. Fetch and pin the server key:

```bash
ssh -i pqvpn.pem ubuntu@<ELASTIC_IP> sudo cat /etc/pqvpn/server_identity_public.key > config/server_identity_public.key
sha256sum config/server_identity_public.key   # must equal the printed fingerprint
```

Set `server_host` and `server_identity_fingerprint` in `config/client.toml`, connect,
and check that `curl -4 --max-time 10 https://checkip.amazonaws.com` prints the
Elastic IP. Add more clients with `client authorize` (as in
[Install and provision](#install-and-provision)). They can connect at once; restart
only after adding a static lease.

### 4a. Desktop (managed) clients

- Set `protocol_version = 2` in `/etc/pqvpn/server.toml` and restart `pqvpn-server`.
- Deploy with `PQVPN_PUBLIC_HOST`. If the script says it is regenerating the
  certificate, stop and plan: every client needs the new `/etc/pqvpn/tls/account-api.crt`
  (copy it over SSH), and `app/server-account-api.crt` must be replaced before
  rebuilding packages.
- Open 8443. Opening it to `0.0.0.0/0` relies on invite-only registration and the
  login and registration rate limits; the reference server does this so users on
  changing IPs can register, and accepts that `/server/info` and `/openapi.json` are public.
- Create one invite per user and send the code privately (it prints once):
  `sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account invite-create --uses 1 --expires-hours 72 --accounts-db /var/lib/pqvpn/accounts/accounts.db`.

Users then install the client, register with the code and press Connect.

### Updating the server

Disconnect clients first: restarting `pqvpn-server` drops live tunnels.

```bash
# from your machine: ship the committed tree
git archive HEAD | ssh -i pqvpn.pem ubuntu@<HOST> 'rm -rf /tmp/pqvpn-src && mkdir /tmp/pqvpn-src && tar -x -C /tmp/pqvpn-src'
# on the instance: back up state, then redeploy (always restarts the account API)
sudo cp -a /var/lib/pqvpn/accounts/accounts.db{,.bak-$(date +%s)}
sudo cp -a /var/lib/pqvpn/authorized/authorized_clients.json{,.bak-$(date +%s)}
sudo env PQVPN_PUBLIC_HOST=<ELASTIC_IP> bash /tmp/pqvpn-src/scripts/deploy-server.sh
```

Account schema upgrades are one-way, so rolling back needs the database backup.

### SSH from changing networks

The SSH rule is a `/32`. On a mobile tether your IP changes often, so recheck it
(`curl https://checkip.amazonaws.com`) and update the rule. On some carrier networks
SSH to the raw IPv4 times out while SSH to the instance's public DNS name
(`ubuntu@ec2-<a>-<b>-<c>-<d>.<region>.compute.amazonaws.com`) works, because the name
resolves to a NAT64 address.

### 5. Stop or tear down

A running instance bills hourly; stop it when idle (`aws ec2 stop-instances`). The
Elastic IP stays associated and is billed a little while the instance is stopped.

```bash
aws ec2 terminate-instances --region $REGION --instance-ids $ID
aws ec2 wait instance-terminated --region $REGION --instance-ids $ID
aws ec2 release-address --region $REGION --allocation-id $EIP
aws ec2 delete-security-group --region $REGION --group-id $SG
```

## Docker

The Ubuntu 24.04 images (`Dockerfile`, `docker-compose.yml`) are for development and
the evaluation artifact, not a validated deployment path. Their entrypoints do not run
the firewall helpers, and the client image has no systemd-resolved, so managed DNS
fails safely there. `docker compose config` passing does not prove a working VPN.
