# Hybrid PQ-VPN

Inherits all rules from the workspace CLAUDE.md (`/home/shadow/Sentinel/CLAUDE.md`).

## Project-Specific

- **Language**: Python 3.x
- **Test command**: `python -m pytest tests/ -x`
- **Benchmark command**: `python benchmarks.py`
- **Graph location**: `graphify-out/`

## Security Rules

This is a post-quantum cryptographic VPN — security is critical:

- Activate agent-skills:security-and-hardening automatically for any crypto/network change
- Minimal code reduces attack surface (ponytail reinforces this)
- Never weaken security properties in a refactor
- All crypto paths require tests

### Security-related work (crypto, key, handshake, certificate, auth, TLS, quantum, KEM, signature)

1. `graphify query` to understand the security flow
2. Activate agent-skills:security-and-hardening
3. Activate ponytail:ponytail (full mode) — minimal code = smaller attack surface
4. Run tests + verify no security properties are weakened

Implementation of the above is delegated to an **Opus** agent; the main (Sonnet) session reviews the diff, re-runs `python -m pytest tests/ -q`, and commits.

## Deploy and packaging gotchas

Full detail in the vault: `[[pq-vpn-deploy-gotchas]]`, `[[pq-vpn-aws-server]]`.

- The `pqvpn-client` systemd service runs the **pacman-installed package**, not this repo. After code changes: `cd packaging/arch && makepkg -fC --nodeps` (the `-C` is required: a reused `src/` build ships old code), then the user runs `sudo pacman -U ...pkg.tar.zst` and `sudo systemctl restart pqvpn-client`. The `.deb` is built in a `debian:trixie` container (`[[pq-vpn-deploy-gotchas]]`).
- The package is built from the **committed** tree (`git archive HEAD`). After committing, refresh `packaging/arch/pqvpn-3.0.0.tar.gz`, the `sha256sums` in `PKGBUILD`, and the digest pin in `tests/test_onboarding.py`.
- Managed desktop clients speak `protocol_version = 2`; a v3 server rejects them ("Unsupported version").
- The GUI defaults to the built-in account API `https://52.62.237.95:8443` with the bundled cert `app/server-account-api.crt` (exclusive pin); `PQVPN_ACCOUNT_API_URL` / `PQVPN_ACCOUNT_CA_CERT` only override. If the server cert is regenerated (`PQVPN_PUBLIC_HOST` must be in its SAN), replace the bundled cert. Registration is invite-only (`vpn.cli account invite-create`); sign-out suspends the device on the server.
- Authorized clients DB lives in `/var/lib/pqvpn/authorized/`; never make `/etc/pqvpn` group-writable.
- Update the AWS server with `scripts/deploy-server.sh` (idempotent); disconnect the client first, a restart drops tunnels.
