# PQ-VPN

A hybrid classical + post-quantum research VPN for Linux, combining X25519 and ML-KEM-768 to resist both current and future quantum threats.

---

## Overview

PQ-VPN is a deployable research prototype implementing a KEMTLS-inspired custom handshake protocol over Linux TUN/UDP. It pairs classical X25519 key exchange with post-quantum ML-KEM-768 (Kyber) so that compromise of either primitive alone does not break the session. Traffic is encrypted with AES-256-GCM using directional keys derived via HKDF-SHA256.

**This is a research prototype.** It is not standardized KEMTLS, has not received independent formal review, and does not claim production-grade security.

---

## Features

- **Hybrid handshake** — ephemeral X25519 + ML-KEM-768 session establishment
- **Post-quantum server identity** — static ML-KEM-768 key pinned by SHA-256 fingerprint
- **Three protocol variants** — v2 (Ed25519 client auth), v3 (fully PQ mutual auth via ML-KEM), v3-mldsa (ML-DSA-44 comparison)
- **Post-compromise recovery** — v3 hybrid re-handshake mixes fresh DH + KEM material (passive adversary after full state compromise; active adversary after control-key-only compromise)
- **DoS resistance** — stateless cookie challenge before resource allocation
- **Formal model** — Tamarin Prover verifies 13 security lemmas across two theories (secrecy, forward secrecy, mutual auth, KCI resistance, PCS)
- **Desktop GUI** — PySide6 app with managed identity, multi-profile servers, offline enrollment
- **Account system** — HTTPS API for login, device binding, and admin approval
- **Privilege separation** — unprivileged GUI communicates with a CAP_NET_ADMIN service over Unix socket

---

## Cryptography

| Role | Algorithm |
|---|---|
| Server authentication | Static ML-KEM-768 (pinned SHA-256 fingerprint) |
| Session establishment | X25519 + ephemeral ML-KEM-768 |
| Client authentication | Ed25519 (v2) or ML-KEM-768 (v3) |
| Traffic encryption | AES-256-GCM (directional keys) |
| Key derivation | HKDF-SHA256 |

> **Note:** v2 client authentication uses classical Ed25519 and is not post-quantum. v3 replaces it with ML-KEM-768 for fully PQ mutual authentication.

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

## Quick start

### Prerequisites

- Python 3.14+, git, CMake, Ninja, C compiler (gcc/g++)
- iproute2, nftables, OpenSSL development headers
- Linux with TUN support

### 1. Install native liboqs

```bash
sudo bash scripts/install-liboqs.sh /usr/local
```

### 2. Set up the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -c constraints-tested.txt '.[dev]'
```

### 3. Generate identities

```bash
python -m vpn.cli identity generate
python -m vpn.cli client-key generate
python -m vpn.cli client authorize config/client_identity_public.key --client-id local
```

### 4. Configure and run

Edit `config/client.toml` to set the server fingerprint and hostname, then see
[Running the server](#running-the-server) below.

For full deployment instructions, see [docs/deployment.md](docs/deployment.md).

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

```bash
# Install GUI dependencies
pip install 'pqvpn[desktop]'

# Terminal 1: start the privileged service
sudo .venv/bin/python -m app.client --service

# Terminal 2: launch the GUI
.venv/bin/python -m app.client
```

For production, use the systemd unit: `packaging/common/pqvpn-client-deploy.service`.

### Legacy TOML mode

Pass `--config` explicitly to use a TOML file instead of managed profiles:

```bash
sudo .venv/bin/python -m app.client --service --config config/client.toml
```

### Client enrollment

```bash
# Export an enrollment request
python -m vpn.cli client enrollment-request \
  --output my-device.pqenroll \
  --client-id my-device \
  --public-key /path/to/client_identity_public.key

# Administrator authorizes it
sudo python -m vpn.cli client authorize-request my-device.pqenroll \
  --database /etc/pqvpn/authorized_clients.json \
  --vpn-ip 10.8.0.9
```

---

## Onboarding flow

```
Install  →  Launch PQ-VPN  →  Device identity auto-created
   →  Import server.pqvpn  →  Export device.pqenroll
   →  Admin authorizes offline  →  Connect
```

- `.pqvpn` profiles contain the server endpoint, pinned ML-KEM-768 public key, and VPN subnet
- `.pqenroll` requests contain the client's public Ed25519 key and fingerprint
- Neither format permits private keys, passwords, tokens, or commands
- No TOFU, no server discovery, no Internet-facing enrollment API

---

## Testing

```bash
python -m pytest -q                                    # full suite (555 tests)
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
  client.py              Desktop GUI + privileged client service
crypto/
  hybrid_crypto.py       ML-KEM-768, X25519, AES-256-GCM, HKDF
handshake/
  kemtls.py              KEMTLS-inspired v2/v3 protocol state machine
vpn/
  account_api.py         Account login/session and device-binding API
  accounts.py            Server-side account/device/session SQLite store
  cli.py                 Provisioning and runtime CLI
  config.py              TOML configuration with validation
  doctor.py              Read-only deployment diagnostics
  enrollment.py          Strict public .pqenroll artifacts
  identity.py            Server/client identity management
  network.py             TUN, nftables, MTU, IPv6 guard
  profiles.py            Strict .pqvpn profiles and atomic profile store
  runtime.py             VPNClient and VPNServer runtimes
eval/                    Evaluation campaign scripts and table generators
formal/                  Tamarin Prover models (pqvpn_v3.spthy, pqvpn_v3_pcs.spthy)
config/                  Default client/server TOML examples
packaging/               Arch, Debian, desktop entry, icon, systemd units
scripts/                 Native liboqs installer and server network helpers
tests/                   Pytest suite with shared fixtures
constraints-tested.txt   Tested version pins and native validation record
```

---

## Documentation

| Document | Description |
|---|---|
| [docs/design.md](docs/design.md) | Protocol design, wire formats, key schedule, threat model, design decisions |
| [docs/deployment.md](docs/deployment.md) | Server deployment, packaging, provisioning guide |
| [docs/accounts.md](docs/accounts.md) | Account database and authorization separation |
| [docs/security_audit.md](docs/security_audit.md) | Security audit and validation records |
| [ARTIFACT.md](ARTIFACT.md) | Reproducibility artifact for the research evaluation |

---

## Current status

**Completed through Milestone 4.7:**

- Hybrid KEMTLS-inspired handshake (v2 + v3)
- Formal Tamarin model with 13 verified security lemmas
- Evaluation campaign with wire-size and latency benchmarks
- Desktop GUI with managed identity and offline enrollment
- Account authentication API with device binding and admin approval
- Post-compromise recovery via hybrid re-handshake (scoped: passive after full state compromise)
- Stateless DoS-resistance cookies
- ML-DSA-44 comparison protocol variant

**Pending:**

- Production VPS deployment
- Independent protocol and security review
- Routed IPv6, kill switch, dynamic PMTU discovery

---

## Known limitations

- IPv4 tunneling only; IPv6 is blocked (leak prevention), not routed
- No kill switch
- No dynamic PMTU discovery
- v2 client authentication is classical Ed25519 (not post-quantum)
- No server enrollment API or invite codes
- Re-handshake does not recover from an active adversary who holds the full epoch state (including rekey secret); recovery is against passive adversaries after full state compromise and active adversaries after control-key-only compromise
- Custom protocol without independent formal review
- Up to five imported profiles; no public server discovery
- Offline administrator-approved enrollment only
- Packaging is foundational, not live-validated
- Python cannot guarantee complete cryptographic key zeroization

Detailed milestone history is available via `git log --grep="docs(progress)"`.
