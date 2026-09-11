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
| Unit suite | 259 passed, 2 skipped (root/env) |

**Not yet validated / pending:**

- Real end-user GUI connection through the desktop client
- Full Omarchy client → VM server validation
- Systemd client service live testing
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

## Desktop client

The GUI runs as a normal user; a privileged client service manages the VPN connection.

```bash
# Install GUI dependencies
.venv/bin/python -m pip install 'pqvpn[desktop]'

# Start the privileged client service (requires root / CAP_NET_ADMIN)
sudo .venv/bin/python -m app.client --service --config config/client.toml

# In another terminal, launch the GUI
.venv/bin/python -m app.client
```

For production, use the systemd unit: `deploy/pqvpn-client.service`.

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
  cli.py              Provisioning and runtime CLI
  config.py           TOML configuration with validation
  doctor.py           Read-only deployment diagnostics
  identity.py         Server/client identity management
  network.py          TUN, nftables, MTU, IPv6 guard
  runtime.py          VPNClient and VPNServer runtimes
config/               Default client/server TOML
deploy/               Systemd units, version provenance
tests/                Pytest suite
docs/                 Design, deployment, security audit
```

## Documentation

- [Protocol and design](docs/design.md)
- [Server deployment guide](docs/deployment.md)
- [Security audit and validation records](docs/security_audit.md)

## Limitations

- IPv4 tunneling only; IPv6 is blocked (leak prevention), not routed
- No kill switch implementation
- No dynamic PMTU discovery
- Ed25519 client authentication is classical (not post-quantum)
- No server enrollment API or invite codes
- Custom protocol without independent formal review
- Single server profile (no multi-server discovery)
- Python cannot guarantee complete cryptographic key zeroization
