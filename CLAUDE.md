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
