# PQ-VPN

Hybrid Classical + Post-Quantum research VPN for Linux. Uses ephemeral X25519 plus ML-KEM-768 for session establishment, a pinned static ML-KEM-768 server identity, authorized Ed25519 client identities, and AES-256-GCM traffic encryption.

## What it is

A deployable research/prototype PQ-VPN implementing a KEMTLS-inspired custom protocol over Linux TUN/UDP. Not formally KEMTLS-compatible and not formally verified. The design reduces post-quantum handshake overhead; it does not claim production-ready or formally proven security.

## Current status

**Deployable research/prototype PQ-VPN.**

| Validation item | Result |
|---|---|
| Tested Python baseline | 3.14.7 |
| Native liboqs | 0.16.0 (source commit `5a1a854b`) |
| Native ML-KEM marker | 2 passed |
| Root namespace gate (Ubuntu 26.04.1) | PASS (1 passed, 261 deselected on `784419e`) |
| Desktop GUI | Milestone 3: managed identity, public profiles, offline enrollment |
| Account authentication | Milestone 4.2: dedicated HTTPS API and bearer sessions |
| Unit suite | 429 passed, 2 skipped |

**Not yet validated / pending:**

- Production VPS deployment
- Independent protocol/security review
- Routed IPv6, kill switch, post-compromise recovery

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

## Normal-user onboarding

```text
Install
  ↓
Launch PQ-VPN
  ↓
Device Ed25519 identity created once by the privileged service
  ↓
Import server.pqvpn (public server configuration only)
  ↓
Export device.pqenroll (public client identity only)
  ↓
Administrator authorizes the request offline
  ↓
Select the profile and Connect
```

The GUI remains unprivileged. The service stores managed state under
`/var/lib/pqvpn`, generates the device identity idempotently, and owns the only
`VPNClient`. Exporting an enrollment request does **not** prove that a server has
authorized it; authorization is confirmed only by a successful authenticated
connection.

A `.pqvpn` profile contains a version, profile ID/name, IPv4 server endpoint,
pinned public ML-KEM-768 server identity, matching SHA-256 fingerprint, and expected
IPv4 VPN subnet. A `.pqenroll` request contains a version, client ID, raw Ed25519
public key encoded as Base64, matching SHA-256 fingerprint, and UTC creation time.
Neither format permits private keys, passwords, tokens, commands, or arbitrary key
paths. There is no URL import, server discovery, TOFU, automatic invite service, or
Internet-facing enrollment API.

## Cryptography

| Role | Algorithm |
|---|---|
| Server authentication | Static ML-KEM-768 (pinned SHA-256 fingerprint) |
| Session establishment | X25519 + ephemeral ML-KEM-768 |
| Client authentication | Ed25519 (classical, not post-quantum) |
| Traffic encryption | AES-256-GCM (directional keys) |
| Key derivation | HKDF-SHA256 |

- KEMTLS-inspired custom protocol, not standardized KEMTLS
- Not formally verified
- Not fully post-quantum mutual authentication (client auth is classical Ed25519)

## Quick development setup

```bash
# Prerequisites: Python 3.14, git, CMake, Ninja, C compiler, iproute2, nftables
sudo bash scripts/install-liboqs.sh /usr/local
python3 -m venv .venv
.venv/bin/python -m pip install -c constraints-tested.txt '.[dev]'
.venv/bin/python -m vpn.cli identity generate
.venv/bin/python -m vpn.cli client-key generate
.venv/bin/python -m vpn.cli client authorize config/client_identity_public.key --client-id local
# Edit config/client.toml: set server fingerprint and hostname
```

See [docs/deployment.md](docs/deployment.md) for the full server deployment guide.

## Running the server

### Option 1: Systemd service (Recommended for background / VM deployment)
Install and manage the server with systemd (unit template at `deploy/pqvpn-server.service`):

```bash
# Start the server service
sudo systemctl start pqvpn-server.service

# Stop or restart the server
sudo systemctl stop pqvpn-server.service
sudo systemctl restart pqvpn-server.service

# Check status and live logs
systemctl status pqvpn-server.service
journalctl -u pqvpn-server.service -f
```

### Option 2: Direct CLI execution (Foreground / Debugging)
To run the server interactively in a terminal:

```bash
# 1. Configure firewall and NAT forwarding rules (run once per boot)
sudo bash scripts/server-network.sh setup $(pwd)/config/server.toml

# 2. Start the server daemon
sudo .venv/bin/python -m vpn.cli server --config config/server.toml
```

To verify that the server is actively listening on TCP & UDP port `51820`:
```bash
ss -tulpn | grep 51820
```

## Desktop client

The GUI runs as a normal user; a privileged client service manages the VPN connection.
Milestone 3 adds first-run setup, real multi-profile server management, and public
offline enrollment while retaining Home, Servers, Security, read-only Settings,
bounded sanitized Logs, About, and the validated Unix-socket privilege boundary.

```bash
# Install GUI dependencies
.venv/bin/python -m pip install 'pqvpn[desktop]'

# Start managed mode (service-owned identity/profile state)
sudo .venv/bin/python -m app.client --service

# In another terminal, launch the GUI
.venv/bin/python -m app.client
```

For production, use the systemd unit: `deploy/pqvpn-client.service`.

The installed desktop workflow uses managed state. Development remains compatible
through an explicit, unambiguous legacy configuration:

```bash
sudo .venv/bin/python -m app.client --service --config config/client.toml
# or the foreground runtime
sudo .venv/bin/python -m vpn.cli client connect --config config/client.toml
```

An explicit `--config` always selects legacy TOML mode. Omitting `--config` always
selects managed profile/identity mode; the two sources are never merged.

Create and authorize a public enrollment artifact from the CLI when needed:

```bash
python -m vpn.cli client enrollment-request \
  --output shadow-laptop.pqenroll \
  --client-id shadow-laptop \
  --public-key /path/to/client_identity_public.key

sudo python -m vpn.cli client authorize-request shadow-laptop.pqenroll \
  --database /etc/pqvpn/authorized_clients.json \
  --vpn-ip 10.8.0.9
```

See [docs/deployment.md](docs/deployment.md#packaging-foundation) for the Arch/Omarchy and Debian
packaging foundation. Package builds and installation have not yet been live-validated.

## Testing

```bash
.venv/bin/python -m pytest -q                                    # full suite
ALLOW_MOCK_PQC=0 .venv/bin/python -m pytest -q -m native_pqc    # native ML-KEM
```

Root namespace integration tests require `sudo` with `/dev/net/tun`, nftables, and iproute2. See [docs/deployment.md](docs/deployment.md).

## Repository layout

```
app/
  client.py           Desktop GUI + privileged client service
crypto/
  hybrid_crypto.py    ML-KEM-768, X25519, AES-256-GCM, HKDF
handshake/
  kemtls.py           KEMTLS-inspired v2 protocol state machine
vpn/
  account_api.py       Dedicated account registration/login/session API
  accounts.py         Server-side account/device/session SQLite store
  cli.py              Provisioning and runtime CLI
  config.py           TOML configuration with validation
  doctor.py           Read-only deployment diagnostics
  enrollment.py       Strict public .pqenroll artifacts
  identity.py         Server/client identity management
  network.py          TUN, nftables, MTU, IPv6 guard
  profiles.py         Strict .pqvpn profiles and atomic profile store
  runtime.py          VPNClient and VPNServer runtimes
config/               Default client/server TOML
deploy/               Systemd units, version provenance
tests/                Pytest suite
docs/                 Design, deployment, security audit
packaging/            Arch, Debian, desktop entry, icon, and package service
```

## Documentation

- [Protocol and design](docs/design.md)
- [Account database and authorization separation](docs/accounts.md)
- [Server deployment guide](docs/deployment.md)
- [Security audit and validation records](docs/security_audit.md)

## Limitations

- IPv4 tunneling only; IPv6 is blocked (leak prevention), not routed
- No kill switch implementation
- No dynamic PMTU discovery
- Ed25519 client authentication is classical (not post-quantum)
- No server enrollment API or invite codes
- Custom protocol without independent formal review
- Up to five explicitly imported profiles; no public server discovery
- Offline administrator-approved enrollment only
- Packaging is an initial foundation, not an installation-validation claim
- Python cannot guarantee complete cryptographic key zeroization
