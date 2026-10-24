# Pentest Report — Live Server Black-Box Pass

**Date:** 2026-10-24
**Target:** `52.62.237.95` (EC2 `i-0c22d8c523739b435`, PQ-VPN Server), account API
on 8443, control plane 51820/tcp, data plane 51820/udp.
**Method:** black-box network recon and light active probing from an external
host. Non-destructive — no fuzzing campaigns, bruteforce, or load/DoS testing.
**Scope note:** this was a standalone pass before the structured 70-attack
checklist existed in this repo. The ongoing, attack-by-attack run against that
checklist lives in `pentesting/pentest.md` + `pentesting/report.md` — this file
is the narrative summary of what's already been covered.

## Summary

No exploitable issues found. Port exposure, TLS configuration, CORS policy,
auth enforcement, and invite-code gating all held up under live testing,
corroborating that the `docs/security_audit.md` (A-01–A-19) remediations hold
externally, not just in unit tests. Two items worth fixing: no explicit login
rate limit, and a public `/openapi.json`.

## Results

| Area | Result |
|---|---|
| Port exposure | Only 8443 + 51820 reachable — matches the security group exactly, no leaks |
| TLS (8443) | TLS1.0/1.1 rejected (handshake never completes); TLS1.2+ only, strong ciphers (`ECDHE-ECDSA-AES256-GCM-SHA384`, `TLS_AES_256_GCM_SHA384`) |
| CORS | No wildcard, no origin reflected — A-14 fix holds live |
| Auth enforcement | `/auth/me`, `/devices` → `401` without bearer token |
| User enumeration | Bad login → generic `invalid_credentials`, no field-level leak |
| Invite-code gating | Null/missing/garbage `invite_code` all rejected `403` — can't bypass despite the OpenAPI schema marking the field nullable |
| Control-plane (51820/tcp) malformed input | Immediate RST, no crash, no echo-back, server stayed up |
| Data-plane (51820/udp) malformed input | Silently dropped — no reflection/amplification vector |
| Banner leakage | No `Server` header, no framework/version disclosure |

## Findings

1. **Credential stuffing not rate-limited (moderate).** The `/auth/login` limiter is
   keyed on *(IP + identifier)*, so trying one password against many different accounts
   from one IP never trips it (this is what the black-box "10 attempts, no 429" actually
   showed — distinct identifiers each time). Single-account brute force *is* throttled
   (429 after 5) and per-account lockout works — so **#13 is defended**; the gap is
   **#14 credential stuffing**. Registration already has a per-IP-only limiter; login
   doesn't. **Fix:** add a per-IP-only limiter on `/auth/login`. Confirmed locally in
   `pentesting/attacks/attack14_credential_stuffing.py`. (Earlier "stale deployment"
   theory was wrong — the live server matches the code.)
2. **Low — `/openapi.json` is public and unauthenticated**, exposing the full
   API schema (endpoint names, field constraints) to any scanner.
3. **Low — self-signed account-API cert has 10-year validity** (2026–2036).
   Acceptable under the client-pinning model but increases blast radius if the
   private key ever leaks; relevant if a CA-issued cert is adopted later.
4. **Info — no `HSTS`/`X-Content-Type-Options` headers.** Low relevance since
   the API isn't browser-facing.
5. **Info, not a vulnerability — the SSH `/32` security-group rule is stale**
   (allows `42.104.142.137`, current tester IP was `157.51.103.6`). Just means
   SSH access needs the rule refreshed before any SSH-based check.

## What wasn't tested here

Protocol-level attacks (actual KEMTLS handshake MITM, replay-window bypass,
rekey desynchronization, nonce reuse, etc.) need the project's own client/
handshake code, not raw sockets — those map to attacks #1–12, #23–29, #66–68 in
`pentesting/pentest.md` and are tracked there as the structured checklist is
executed one attack at a time.

## Instance state

Server was stopped before this session; started for testing and left running
afterward (user's call — remember to stop it in the AWS console when done,
billing is hourly while running).
