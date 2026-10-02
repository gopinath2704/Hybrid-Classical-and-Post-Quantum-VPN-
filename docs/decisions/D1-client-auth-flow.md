# D1: Client authentication flow for v3

## Context

v2 uses Ed25519 signatures for client authentication — the only classical
cryptographic primitive remaining in the handshake. Replacing it with ML-KEM
makes the system fully post-quantum mutually authenticated without any
signatures.

Both long-term public keys are pre-shared: the client pins the server key
(from `.pqvpn`), and the server stores the client key (from `.pqenroll`).
Each side can authenticate the other by encapsulating to the peer's static
key — only the true key owner can decapsulate and derive the Finished MAC.

## Options

**A: Keep current message shape.** `ct_S` stays in ClientKeyExchange; server
adds `ct_C` to ServerHello. Minimal change from v2. Client identity hash is
sent in the clear (same exposure as v2's Ed25519 public key). 1.5 RTT.

**B: PDK-style.** `ct_S` moves into ClientHello; client identity is encrypted
under a key derived from `K_S`. Hides client identity from passive observers.
Larger ClientHello, replay handling needed, more modelling work.

## Choice

**Option A.**

## Why

- Minimal wire-format delta from v2 — easier to verify correctness and model
  in Tamarin (Phase 2).
- Client identity exposure is equivalent to v2 (the v2 Ed25519 public key was
  already sent in the clear).
- Option B can be revisited after the Tamarin model is stable if the paper
  needs identity hiding as a contribution.

## Wire sizes (Option A)

| Message | v2 | v3 | Delta |
|---|---|---|---|
| ClientHello | 1,318 | 1,318 | 0 |
| ServerHello | 1,222 | 2,310 | +1,088 (ct_C) |
| ClientKeyExchange | 1,190 | 1,126 | −64 (no signature) |
| ServerFinished | 38 | 38 | 0 |
| **Total** | **3,768** | **4,792** | **+1,024** |

## Key schedule

```
ES  = HKDF-Extract(salt, X25519_ss ‖ K_eph)     — ephemeral handshake secret
AS  = HKDF-Extract(ES,  K_S ‖ K_C ‖ transcript)  — authenticated master secret
```

From AS, derive Finished keys, data/control keys, rekey secret, and
confirmation key using the same HKDF-Expand labels as v2.
