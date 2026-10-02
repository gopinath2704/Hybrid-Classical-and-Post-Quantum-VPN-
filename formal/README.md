# PQVPN v3 Formal Model

Tamarin Prover model of the PQVPN v3 handshake protocol.

## Prerequisites

Install [Tamarin Prover](https://tamarin-prover.com/):

```bash
# Arch Linux
sudo pacman -S tamarin-prover

# macOS (Homebrew)
brew install tamarin-prover

# From source: https://tamarin-prover.com/manual/master/book/002_installation.html
```

Tamarin requires Maude (installed as a dependency on most package managers).

## Running

Verify all lemmas automatically:

```bash
# From the repository root:
./scripts/verify_formal.sh

# Or directly:
tamarin-prover --prove formal/pqvpn_v3.spthy
```

Interactive exploration (opens a web UI):

```bash
tamarin-prover interactive formal/pqvpn_v3.spthy
```

## Expected output

All lemmas should report `verified`:

| Lemma | Property | Status |
|---|---|---|
| `protocol_completes` | Sanity: a full handshake trace exists | verified |
| `session_key_secrecy` | Keys secret unless both LTKs compromised | verified |
| `forward_secrecy` | Post-session LTK compromise doesn't reveal keys | verified |
| `server_auth` | Injective agreement: client authenticates server | verified |
| `client_auth` | Injective agreement: server authenticates client | verified |
| `kci_resistance_client` | Client key compromise doesn't allow server impersonation | verified |
| `kci_resistance_server` | Server key compromise doesn't allow client impersonation | verified |

## Model structure

```
formal/pqvpn_v3.spthy    The complete Tamarin theory
```

### Protocol rules

| Rule | Handshake message |
|---|---|
| `C1_Hello` | Client sends ClientHello |
| `S1_Hello` | Server processes ClientHello, sends ServerHello |
| `C2_KeyExchange` | Client processes ServerHello, sends ClientKeyExchange |
| `S2_Finished` | Server processes ClientKeyExchange, sends ServerFinished |
| `C3_Complete` | Client verifies ServerFinished |

### Cryptographic primitives

- **X25519:** Tamarin's built-in Diffie-Hellman (`diffie-hellman` builtin)
- **ML-KEM-768:** Modelled as public-key encryption with CCA security (`kem_enc`/`kem_dec` with equational theory)
- **HKDF:** Modelled as a keyed derivation function (`kdf`/`kdf3`)
- **Finished MAC:** Modelled as a MAC (`mac` with equational verification)

### Key schedule

```
hs     = kdf(<dhss, k_eph>, 'hs')           -- ephemeral handshake secret
master = kdf3(hs, <k_s, k_c>, transcript)   -- authenticated master secret
```

Session keys are derived deterministically from `master`:
- `c2s(master)`: client-to-server data key
- `s2c(master)`: server-to-client data key
- `cf_key(master)`: client Finished key
- `sf_key(master)`: server Finished key

### Compromise model

- `Reveal($A)`: reveals any party's long-term KEM secret key
- Lemmas express security under various compromise scenarios

## Assumptions

1. **Perfect cryptography.** DH is CDH-hard; KEM is IND-CCA2 secure; HKDF is a PRF; MACs are unforgeable.
2. **Dolev-Yao adversary.** The attacker controls the network: can intercept, modify, replay, and inject messages. Cannot break the cryptographic assumptions.
3. **Pre-shared public keys.** Both sides have the peer's long-term public key before the handshake starts (provisioned via `.pqvpn` and `.pqenroll`).
4. **Fresh randomness.** All nonces, session IDs, and ephemeral keys are generated freshly.

## What is NOT modelled

- Timing, side channels, or implementation bugs
- TCP/UDP transport, fragmentation, MTU, or message ordering beyond causality
- Rate limiting, denial of service, or resource exhaustion
- The data-plane record layer (encrypted frames after handshake)
- Hash-based rekey (Phase 3 adds a `pcs_recovery` lemma for the hybrid re-handshake)
- The stateless cookie (Phase 4)
- Enrollment or key distribution protocols
- Multi-session composition beyond Tamarin's built-in multi-session semantics

## Hybrid security argument

The key schedule mixes independent DH and KEM contributions:

```
master = kdf3(kdf(<dhss, k_eph>, 'hs'), <k_s, k_c>, transcript)
```

- If DH is broken but KEM holds: `dhss` is known, but `k_eph`, `k_s`, `k_c` are KEM-protected. The master depends on all four, so knowing only `dhss` is insufficient.
- If KEM is broken but DH holds: `k_eph`, `k_s`, `k_c` are known, but `dhss` is CDH-protected.

This structural argument holds because `kdf3` is a PRF: knowing some inputs but not all does not reveal the output. The `session_key_secrecy` lemma verifies this in the standard (both-sound) setting; the hybrid guarantee is a consequence of the key schedule design.
