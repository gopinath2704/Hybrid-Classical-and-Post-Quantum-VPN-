# Management API v2

Bearer-authenticated POST `/api/v1/vpn/connect?config=config/client.toml` connects
using an operator-provisioned profile (including its identity pin and client key).
The dashboard uses the default profile. It does not create a VPN server or accept
host/port overrides. GET `/api/v1/vpn/servers` lists that configured profile with
`id`, `name`, `host`, `port`; there are no location or flag fields.

Connect returns `status: connected` plus the same telemetry object as GET
`/api/v1/vpn/status` and `/ws/telemetry`:

- `connection_state`: DISCONNECTED, CONNECTING, CONNECTED, FAILED (ERROR on API setup failure)
- `error`: operational failure text, without handshake payloads
- `client_vpn_ip`, `epoch`, `tun_mtu`, `tun_mode`: null when inactive
- `pqc_mode`, `is_quantum_safe`: provider posture; this does not assert PQ client authentication
- `uptime_seconds`, `rekey_countdown` (seconds, null when disabled/inactive)
- `network`: measured `rtt_ms`, `jitter_ms`, `loss_rate` (0–1), probe counts and timestamp

RTT/jitter are unavailable until a probe returns. Loss measures expired probes.
No bandwidth or byte counters are exposed because they are not measured.
The dashboard polls status, displays permanent runtime failures, and permits retry.
There is no `/logs` endpoint or activity-log UI.

## Installation and telemetry tickets

Install `requirements-management.txt` in a fresh environment after native liboqs.
Run `python -m app.main --cli` from the repository root with a configured
`PQVPN_MANAGEMENT_TOKEN`. The supported browser dashboard polls authenticated HTTP;
PyWebView is an optional, separately installed and unvalidated desktop dependency.
The WebSocket implementation is consolidated in `app/backend/api.py`.

To use WebSocket telemetry:

1. Send an authenticated HTTP `POST /api/v1/ws-ticket` with `Authorization: Bearer ...`.
2. Read `{ "ticket": "...", "expires_in": 30 }` and connect to `/ws/telemetry?ticket=...`
   with an allowed browser Origin. Use `wss` behind the configured TLS proxy remotely.
3. Obtain a fresh ticket for every connection attempt; reuse, expiry, random tickets,
   and long-lived bearer URL tokens are rejected with close code 4401.

Tickets contain 32 cryptographically random bytes encoded with URL-safe base64.
Consumption pops the entry before the first await, so it is single-use within the
ASGI event loop. Expiration uses monotonic time; issuance removes expired entries
and limits outstanding tickets to 256 (HTTP 429 when full). Storage is process-local:
use one management worker, or route issuance and upgrade to the same worker. A ticket
opens read-only telemetry and cannot authorize HTTP connect/disconnect/rekey actions.
Do not log ticket query strings. Remote management requires explicit HTTPS CORS
origins, a strong random bearer token and a TLS reverse proxy; Uvicorn stays loopback.
