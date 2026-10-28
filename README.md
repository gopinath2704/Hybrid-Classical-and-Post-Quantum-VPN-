# PQ-VPN

A hybrid classical + post-quantum research VPN for Linux, combining X25519 and ML-KEM-768 to resist both current and future quantum threats.

---

## Overview

PQ-VPN is a deployable research prototype implementing a KEMTLS-inspired custom handshake protocol over Linux TUN/UDP. It pairs classical X25519 key exchange with post-quantum ML-KEM-768 (Kyber) so that compromise of either primitive alone does not break the session. Traffic is encrypted with AES-256-GCM using directional keys derived via HKDF-SHA256.

**This is a research prototype.** It is not standardized KEMTLS, has not received independent formal review, and does not claim production-grade security.

### How a connection is established

<p align="center">
  <img src="docs/media/handshake.gif" alt="Animated sequence diagram of the PQ-VPN v3 handshake: ClientHello, ServerHello, ClientKeyExchange and ServerFinished, then the encrypted tunnel opens" width="800">
</p>

The animation shows the **protocol v3** (KEMTLS-mode) handshake at 1.5× speed: four messages, 4,792 bytes, two round trips, then AES-256-GCM over UDP. The managed desktop client and the reference server currently run **protocol v2**, which uses the same hybrid session establishment but authenticates the client with Ed25519 (see [Cryptography](#cryptography)).
The full 1:19 interactive version, which also walks through the HKDF key schedule, is [here](https://claude.ai/artifact/4qBy7s7MUmgeEXbwBoR8Rn).

---

## Features

- **Hybrid handshake** — ephemeral X25519 + ML-KEM-768 session establishment
- **Post-quantum server identity** — static ML-KEM-768 key pinned by SHA-256 fingerprint
- **Three protocol variants** — v2 (Ed25519 client auth), v3 (fully PQ mutual auth via ML-KEM), v3-mldsa (ML-DSA-44 comparison)
- **1-RTT session resumption** — ticket-based reconnect with fresh ephemeral X25519 + ML-KEM material, skipping static-key exchange
- **Post-compromise recovery** — v3 hybrid re-handshake mixes fresh DH + KEM material (passive adversary after full state compromise; active adversary after control-key-only compromise)
- **DoS resistance** — stateless cookie challenge before resource allocation
- **Formal model** — Tamarin Prover verifies 13 security lemmas across two theories (secrecy, forward secrecy, mutual auth, KCI resistance, PCS)
- **Desktop GUI** — PySide6 app with managed identity, up to five server profiles, self-service or offline enrollment
- **Account system** — HTTPS API with invite-only registration, login, optional TOTP, device binding (auto-approved or admin-approved), and sign-out that suspends the device
- **Privilege separation** — unprivileged GUI talks to a CAP_NET_ADMIN service over a Unix socket; the service fails closed and only accepts root and the uids in `PQVPN_ALLOWED_UIDS`
- **Pentested** — a 70-attack checklist was run against the code and a live test server ([pentesting/](pentesting/)); the fixes add per-IP login and TOTP throttling and revoke all sessions on password change

---

## Cryptography

| Role | Algorithm |
|---|---|
| Server authentication | Static ML-KEM-768 (pinned SHA-256 fingerprint) |
| Session establishment | X25519 + ephemeral ML-KEM-768 |
| Client authentication | Ed25519 (v2) or ML-KEM-768 (v3) |
| Traffic encryption | AES-256-GCM (directional keys) |
| Key derivation | HKDF-SHA256 |

> **Note:** v2 client authentication uses classical Ed25519 and is not post-quantum. v3 replaces it with ML-KEM-768 for fully PQ mutual authentication. The managed desktop client speaks v2, so a server serving desktop users must set `protocol_version = 2` (the code default); the example files in `config/` set 3 for TOML-mode testing. A v3 server rejects v2 clients ("Unsupported version").

---

## Architecture

```
┌─────────────────┐
│  PySide6 GUI    │   normal user
│  (app/client)   │
└────────┬────────┘
         │ Unix domain socket IPC
┌────────▼────────┐
│  Client Service │   CAP_NET_ADMIN
│  (app/client    │
│   --service)    │
│                 │
│  ┌────────────┐ │
│  │ VPNClient  │ │
│  │ (runtime)  │ │
│  └──────┬─────┘ │
│         │       │
│  TUN + routes   │
│  + DNS + IPv6   │
└────────┬────────┘
         │ TCP control + UDP data
┌────────▼────────┐
│  VPN Server     │   pqvpn user + CAP_NET_ADMIN
│  TUN/NAT/nft    │
│  hybrid handshake│
└─────────────────┘
```

---

## Requirements

| | Client (desktop) | Server |
|---|---|---|
| OS | Linux (Arch or Debian/Ubuntu for the installer); Windows and macOS are not supported | Linux (Ubuntu for `deploy-server.sh`) |
| Python | 3.11+ (tested on 3.14) | 3.11+ (tested on 3.14) |
| Native | liboqs 0.16.0, built by `scripts/install-liboqs.sh` | same |
| Build tools | git, CMake, Ninja, gcc/g++, OpenSSL headers, rsync | same |
| Network tools | iproute2, nftables | iproute2, nftables |
| DNS | `systemd-resolved` (`resolvectl`); Connect fails closed without it unless `dns_mode = "none"`, which lets DNS bypass the VPN | n/a |
| Kernel | TUN device (`/dev/net/tun`) | TUN device |
| Python deps | pinned in `constraints-tested.txt`; GUI extra: PySide6 | same, minus the GUI |
| Privileges | `sudo` once, for install; the service then runs with `CAP_NET_ADMIN` only | root for install |
| Network | outbound TCP 8443 (account API) and UDP/TCP 51820 (tunnel) to the server | inbound 8443 and 51820 |
| Account | an **invite code** from the server admin (registration is invite-only) | n/a |

A graphical session is needed for the GUI (Wayland or X11).

---

## Quick start

### Install the desktop client (one command)

```bash
git clone git@github.com:gopinath2704/Hybrid-Classical-and-Post-Quantum-VPN-.git
cd Hybrid-Classical-and-Post-Quantum-VPN-
sudo bash scripts/install-client.sh
```

The script installs the system packages, builds liboqs, copies the app to `/opt/pqvpn`
with its own venv, and starts the privileged `pqvpn-client` service, authorizing only the user who ran
`sudo` (via `PQVPN_ALLOWED_UIDS` in a systemd drop-in). It is safe to
re-run to upgrade; the device identity and state in `/var/lib/pqvpn` are kept.

Then launch **PQ-VPN** from the app menu (or run `pqvpn-gui`), register with your
invite code, and press Connect. Check the service with `systemctl status pqvpn-client`.

Launch the GUI from a terminal:

```bash
sudo systemctl start pqvpn-client   # only if the service isn't active
pqvpn-gui
```

### Updating

```bash
git pull
sudo bash scripts/install-client.sh
```

The script syncs the new code into `/opt/pqvpn`, clears any stale `build/`, `dist/` and `*.egg-info`, reinstalls into the venv and restarts the service. You stay signed in. Close and reopen the GUI so it loads the new code. To confirm the installed copy matches the source:

```bash
diff -q /opt/pqvpn/app/client.py "$(/opt/pqvpn/.venv/bin/python -c 'import app.client as c; print(c.__file__)')" && echo up-to-date
```

### Distribution packages (alternative to the script)

Use **either** `install-client.sh` **or** a package, not both: they install separate copies and separate `pqvpn-client` units. Neither package bundles liboqs, so install it first: `sudo bash scripts/install-liboqs.sh /usr/local`, then the `liboqs-python==0.16.0` binding system-wide.

- **Arch:** `cd packaging/arch && makepkg -fC --nodeps`, then `sudo pacman -U pqvpn-3.0.0-1-x86_64.pkg.tar.zst`. Keep the `-C`: without it `makepkg` can reuse a stale `src/` build and package old code. Before the first install, create `/etc/systemd/system/pqvpn-client.service.d/allowed-uids.conf` with `[Service]` and `Environment=PQVPN_ALLOWED_UIDS=<your uid>`, or the GUI is refused.
- **Debian / Ubuntu / Kali:** build `pqvpn_3.0.0-1_amd64.deb` from `packaging/deb/debian` with `dpkg-buildpackage -b -uc -us` (the `debian/` directory must sit at the top of the source tree), then `sudo apt install ./pqvpn_3.0.0-1_amd64.deb`. It depends on `systemd-resolved`, and when installed with `sudo` its postinst writes the allowed-uids drop-in for you. Python binding on Debian-family systems: `sudo pip install --break-system-packages liboqs-python==0.16.0`.

### Manual / development setup

```bash
sudo bash scripts/install-liboqs.sh /usr/local        # native liboqs
python3 -m venv .venv && source .venv/bin/activate
pip install -c constraints-tested.txt '.[dev]'        # '.[desktop]' for the GUI only

python -m vpn.cli identity generate
python -m vpn.cli client-key generate
python -m vpn.cli client authorize config/client_identity_public.key --client-id local
```

Edit `config/client.toml` to set the server fingerprint and hostname, then see
[Running the server](#running-the-server). For full deployment instructions, see
[docs/deployment.md](docs/deployment.md).

---

## Running the server

### Option 1: Systemd (recommended)

```bash
sudo systemctl start pqvpn-server.service
sudo systemctl status pqvpn-server.service
journalctl -u pqvpn-server.service -f
```

### Option 2: Direct CLI

```bash
# Set up firewall and NAT (once per boot)
sudo bash scripts/server-network.sh setup $(pwd)/config/server.toml

# Start the server
sudo .venv/bin/python -m vpn.cli server --config config/server.toml
```

Verify the server is listening:

```bash
ss -tulpn | grep 51820
```

---

## Desktop client

The GUI runs as a normal user; a privileged service manages the VPN connection.

After `scripts/install-client.sh` the service is already running and you only launch
the GUI. To run from a source checkout instead:

```bash
# Install GUI dependencies
pip install -c constraints-tested.txt '.[desktop]'

# Terminal 1: start the privileged service
sudo PQVPN_ALLOWED_UIDS=$(id -u) .venv/bin/python -m app.client --service

# Terminal 2: launch the GUI
.venv/bin/python -m app.client
```

For production, use the systemd unit: `packaging/common/pqvpn-client-deploy.service`.

### Legacy TOML mode

Pass `--config` explicitly to use a TOML file instead of managed profiles:

```bash
sudo PQVPN_ALLOWED_UIDS=$(id -u) .venv/bin/python -m app.client --service --config config/client.toml
```

### Client enrollment

Self-service (default): sign in from the GUI and the device is enrolled for you.

```
Install  →  Launch PQ-VPN  →  Device identity auto-created
   →  Register / Sign in (account API over TLS)  →  Device bound + auto-approved
   →  Server profile fetched automatically  →  Connect
```

- The GUI talks to the built-in account API `https://52.62.237.95:8443` and trusts only the server certificate bundled with the package (`app/server-account-api.crt`, an exclusive pin), so users set nothing. For another deployment, override with `PQVPN_ACCOUNT_API_URL` and `PQVPN_ACCOUNT_CA_CERT` (a CA file replaces the system store for that connection; a URL without one uses the system store; plain `http://` is allowed only for loopback dev). TLS verification stays strict, so the server certificate must carry a SAN for the host you connect to:

  ```bash
  # server: cert SAN covers the public host (re-run regenerates the cert if it doesn't match)
  sudo env PQVPN_PUBLIC_HOST=<server-ip-or-dns> bash scripts/deploy-server.sh
  # client: fetch /etc/pqvpn/tls/account-api.crt over SSH (not the API port), then
  PQVPN_ACCOUNT_API_URL=https://<server-ip-or-dns>:8443 \
  PQVPN_ACCOUNT_CA_CERT=~/.config/pqvpn/server-account-api.crt  python -m app.client
  ```
  If the built-in server's certificate is regenerated, replace `app/server-account-api.crt` and rebuild the package.
- Registration is invite-only (`require_invite = true`, the default). The admin creates a code on the server and hands it over out of band; the user enters it in the register form:

  ```bash
  sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account invite-create [--uses N] [--expires-hours H] \
    --accounts-db /var/lib/pqvpn/accounts/accounts.db
  ```
  `account invites` lists id, uses left and expiry (never the code); `account invite-revoke ID` deletes one. Set `require_invite = false` only for local development.
- With `auto_approve = true` in `account-api.toml` (the default), binding a device adds its public key to `/var/lib/pqvpn/authorized/authorized_clients.json`; no admin step
- The client then calls `GET /server/info` and imports the server profile (endpoint, pinned ML-KEM-768 key, VPN subnet) itself, so there is no `.pqvpn` import and no hand-edited `client.toml`
- Account API: `POST /auth/register`, `/auth/login`, `/devices`; `GET /devices`, `/server/info`; optional MFA and password change. See [docs/accounts.md](docs/accounts.md)
- Server side: `scripts/deploy-server.sh` provisions the `pqvpn-account` user, TLS certificate and `pqvpn-account-api.service`

**The account API must be reachable by clients (TCP 8443) for self-service.** Restrict the source in your firewall or security group where you can. With `auto_approve = true`, anyone who can register (i.e. holds an invite) can obtain tunnel access; set it to `false` to require administrator approval.

Manual / offline fallback (no account API, `auto_approve = false`):

```bash
python -m vpn.cli client enrollment-request \
  --output my-device.pqenroll \
  --client-id my-device \
  --public-key /path/to/client_identity_public.key

sudo python -m vpn.cli client authorize-request my-device.pqenroll \
  --database /var/lib/pqvpn/authorized/authorized_clients.json \
  --vpn-ip 10.8.0.9
```

Import a `server.pqvpn` profile by hand in that mode. Profiles hold only public data: endpoint, pinned ML-KEM-768 key, subnet. No private keys, passwords, tokens or commands; no TOFU.

---

## Testing

```bash
python -m pytest -q                                    # full suite
ALLOW_MOCK_PQC=0 python -m pytest -q -m native_pqc    # native ML-KEM only
```

Root namespace integration tests require `sudo` with `/dev/net/tun`, nftables, and iproute2.

---

## Docker

```bash
# Runtime server
docker compose up --build

# Reproducibility artifact (runs tests + evaluation)
docker build --target artifact -t pqvpn-artifact .
docker run --rm -v $(pwd)/results:/app/results pqvpn-artifact
```

See [ARTIFACT.md](ARTIFACT.md) for full reproducibility instructions.

---

## Repository layout

```
app/
  client.py              Privileged client service, IPC, account client, GUI entry point
  ui/                    PySide6 windows: login/register, main window, pages, theme
crypto/
  hybrid_crypto.py       ML-KEM-768, X25519, AES-256-GCM, HKDF
handshake/
  kemtls.py              KEMTLS-inspired v2/v3 protocol state machine + session resumption
vpn/
  account_api.py         Account login/session and device-binding API
  accounts.py            Server-side account/device/session SQLite store
  cli.py                 Provisioning and runtime CLI
  config.py              TOML configuration with validation
  identity.py            Server/client identity management
  network.py             TUN, nftables, MTU, IPv6 guard
  runtime.py             VPNClient and VPNServer runtimes
eval/                    Evaluation campaign scripts and table generators
formal/                  Tamarin Prover models (pqvpn_v3.spthy, pqvpn_v3_pcs.spthy)
config/                  Default client/server TOML examples
packaging/               Arch PKGBUILD, Debian packaging, desktop entry, icon, systemd units
pentesting/              70-attack checklist, findings log and attack harnesses
scripts/                 Client and server installers, native liboqs installer, network helpers
tests/                   Pytest suite with shared fixtures
constraints-tested.txt   Tested version pins and native validation record
```

---

## Documentation

| Document | Description |
|---|---|
| [docs/design.md](docs/design.md) | Protocol design, wire formats, key schedule, threat model, design decisions |
| [docs/deployment.md](docs/deployment.md) | Server deployment, packaging, provisioning guide |
| [docs/aws.md](docs/aws.md) | Running the server on AWS EC2 |
| [docs/accounts.md](docs/accounts.md) | Account API, invites, device binding and authorization separation |
| [docs/security_audit.md](docs/security_audit.md) | Security audit and validation records (2026-09) |
| [pentesting/pentest.md](pentesting/pentest.md) | 70-attack pentest checklist and status |
| [pentesting/report.md](pentesting/report.md) | Per-attack findings and fixes |
| [report.md](report.md) | Black-box pentest of the live test server (2026-10-24) |
| [ARTIFACT.md](ARTIFACT.md) | Reproducibility artifact for the research evaluation |
| [eval/results-summary/](eval/results-summary/) | Evaluation write-up, figures and validity report |

---

## Current status

**Completed through Milestone 4.7:**

- Hybrid KEMTLS-inspired handshake (v2 + v3)
- 1-RTT session resumption with ticket-based reconnect
- Formal Tamarin model with 13 verified security lemmas
- Evaluation campaign with wire-size, latency, throughput, memory and DoS benchmarks
- Desktop GUI with managed identity, self-service and offline enrollment
- Account authentication API with invite-only registration, device binding and admin approval
- Post-compromise recovery via hybrid re-handshake (scoped: passive after full state compromise)
- Stateless DoS-resistance cookies
- ML-DSA-44 comparison protocol variant
- Reference test server on AWS EC2 ([docs/aws.md](docs/aws.md))
- 70-attack pentest; all findings fixed except two tracked follow-ups (#69 supply-chain pinning, #46 socket group permissions). The low-severity public `/openapi.json` from the live-server pass is also still open

**Pending:**

- Independent protocol and security review
- Routed IPv6, kill switch, dynamic PMTU discovery
- Distribution packages for liboqs and its Python binding (both are installed manually today)
- Moving the managed desktop client to protocol v3

---

## Known limitations

- IPv4 tunneling only; IPv6 is blocked (leak prevention), not routed
- No kill switch
- No dynamic PMTU discovery
- v2 client authentication is classical Ed25519 (not post-quantum)
- Re-handshake does not recover from an active adversary who holds the full epoch state (including rekey secret); recovery is against passive adversaries after full state compromise and active adversaries after control-key-only compromise
- Custom protocol without independent formal review
- Up to five imported profiles; no public server discovery
- The managed desktop client uses protocol v2 (classical Ed25519 client authentication)
- The Arch package is used day to day; the Debian package builds and lints cleanly on Debian 13 but has not yet been install-tested on a real Debian-family machine
- Python cannot guarantee complete cryptographic key zeroization

Detailed milestone history is available via `git log --grep="docs(progress)"`.
