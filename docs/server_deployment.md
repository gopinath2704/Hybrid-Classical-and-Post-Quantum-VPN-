# Linux VPS deployment gate

Status: **Deployable research/prototype PQ-VPN**. Unit tests are not a deployment
approval. First pass doctor, native ML-KEM tests, and the full root namespace
suite on a disposable Linux VM. Then validate a real VPS with a separate Linux
client. Privileged namespace, systemd, and VPS results must be recorded separately.

## Exact tested dependencies

The recorded baseline is CPython **3.14.7**, **liboqs-python 0.16.0**, native
**liboqs 0.16.0**, Linux x86_64. `deploy/tested-versions.txt` records the versions;
`constraints-tested.txt` pins every Python dependency in the test environment.
Use `requirements-server.txt` for the daemon and `requirements-client.txt` for the
CLI client. IPv6 leak blocking additionally needs nftables on the client. Neither installs GUI, API, benchmark, or test packages. Management is
optional (`requirements-management.txt`); tests use `requirements-dev.txt`.
`requirements.txt` remains the full development compatibility entrypoint.
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
/tmp/pqvpn-validation/bin/python -m pip install -r requirements-dev.txt
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
See [management API](management-api.md) for short-lived WebSocket tickets.

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
`deploy/tested-versions.txt`. The helper clones tag 0.16.0 and compares HEAD with that
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
`deploy/native-build.txt` records compiler/build options and the tested binary digest.
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

Use the local annotated `v2-pre-vps-2` tag, resolve it with
`git rev-parse 'v2-pre-vps-2^{commit}'`, and deploy that exact commit after the disposable
root namespace gate. The hardening pass creates no automatic push. Never archive or
copy private keys, the authorized-client DB, tokens, virtual environments or build
outputs as part of source distribution. Provision secrets separately.

Docker remains a development/integration convenience, not the first VPS path.
Native systemd is the intended path, but actual daemon-reload/start/status/journal,
real TUN/nft/listeners remain unvalidated until executed. Real systemd-resolved
before/during/after state and approved-resolver lookups remain a separate Linux-client
gate. IPv6 leak unit tests do not replace the expanded privileged namespace test.

See the [exact next-phase handoff](pre_vps_handoff.md) for local-tag transfer,
disposable root namespace execution, provisioning and separate real-runtime gates.

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
