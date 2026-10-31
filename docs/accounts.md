# Accounts, invites and device binding

The account API (`vpn.account_api`, launcher `pqvpn-account-api`) lets desktop users
get VPN access without copying keys by hand. A user registers with an
administrator-issued invite, signs in, binds the device's managed public identity and
fetches the server profile. Optional TOTP, account lockout, password change and
administrator reset/unlock are supported. There is no password recovery and no admin
web interface.

Three decisions live in separate stores:

1. The account database says **who the user is**.
2. The managed Ed25519 device identity says **which device is connecting**.
3. `AuthorizedClients` (`/var/lib/pqvpn/authorized/authorized_clients.json`) says
   **whether that device may open a tunnel**. The VPN server reads only this store.

**Signing in alone never grants VPN access.** The API writes `AuthorizedClients` only here:

| Event | Effect on `AuthorizedClients` |
|---|---|
| New device bound with `auto_approve = true` | authorized, then marked `approved` (if the write fails the device stays `pending` and a re-bind retries) |
| Sign-out carrying this device's fingerprint | device **suspended**. Fail closed: if suspension fails, logout returns `503` and the session stays valid |
| Sign-in re-binding an approved, suspended device | suspension lifted. An administrator revocation is never undone this way |
| Password change | every device of the account suspended, every session revoked |

With `auto_approve = false`, binding only records a `pending` device for an
administrator to approve. A suspended or revoked device loses its tunnel within about
30 s: the VPN server re-reads `AuthorizedClients` every 30 s, ends sessions of disabled
clients and rotates its resumption-ticket key (`vpn/runtime.py`, `_revocation_loop`).
New handshakes, rekeys and rehandshakes are refused immediately.

## Storage

The default database is `/var/lib/pqvpn/accounts/accounts.db`. On creation the store
rejects symlink path components and uses directory mode 0700 and file mode 0600.
Foreign keys are enforced, all mutations are parameterized transactions, and the
schema version (4) is kept in `PRAGMA user_version`. An unversioned non-empty
database, an unexpected layout, an integrity failure or a newer version fails closed.
`initialize()` migrates versions 1–3 to 4 in one transaction after checking the
starting layout. **Migration is one-way:** rolling the code back needs a backup taken
before the upgrade.

Tables:

- `users`: normalized unique username and email, Argon2id hash, enabled flag,
  timestamps, optional TOTP secret, failed-login counter, `locked_until`,
  `password_change_required`.
- `devices`: owner (`ON DELETE CASCADE`), name, unique SHA-256 fingerprint, exactly 32
  public Ed25519 bytes (the fingerprint must be their digest), enabled flag, timestamps,
  review `status` (`pending`, `approved`, `rejected`, `revoked`).
- `sessions`: owner, unique SHA-256 of the token (no raw-token column),
  created/expiry/revoked/last-used timestamps.
- `invites`: unique SHA-256 of the code (never the code), uses left, optional expiry, created time.

No table holds a private key.

## Input and password policy

- **Username:** trimmed, NFKC-normalized, lower-cased; 1–64 ASCII characters, starting
  with a letter or digit, then letters, digits, `.`, `_` or `-`.
- **Email:** trimmed, NFKC-normalized, case-folded; a practical `local@domain` check,
  not a full RFC parser.
- **Password:** not trimmed or normalized; 12–1024 characters, no composition rules.
  Hashed with `argon2-cffi` Argon2id defaults and a fresh salt, and rehashed on login
  when the parameters change.

## API

JSON in and out (logout success has no body). Unknown fields are rejected, bodies are
limited to 16 KiB including streamed requests, and errors have one shape,
`{"error":{"code":"...","message":"..."}}`, without SQL, paths, hashes or tracebacks.
The interactive docs pages are disabled, but `/openapi.json` is still served without
authentication.

| Endpoint | Auth | Behaviour |
|---|---|---|
| `POST /auth/register` | none | `{username, email, password, invite_code}` → `201 {user}`. No session is created. `400` bad input, `409` duplicate |
| `POST /auth/login` | none | `{identifier, password[, totp_code]}` → `200 {access_token, token_type, expires_at, user}` |
| `GET /auth/me` | Bearer | public user fields |
| `GET /devices` | Bearer | `{devices: [{id, device_name, fingerprint, enabled, status, created_at}]}` |
| `POST /devices` | Bearer | `{device_name, public_key, fingerprint}`; `201` new, `200` same binding again |
| `POST /auth/logout` | Bearer | optional `{fingerprint}` suspends that device first; `204` |
| `POST /auth/change-password` | Bearer | `{old_password, new_password}` |
| `POST /mfa/setup`, `/mfa/confirm`, `/mfa/disable` | Bearer | TOTP enrolment |
| `GET /server/info` | none | public profile: control port, host, expected subnet, server ML-KEM-768 public key and fingerprint |

**Registration.** With `require_invite = true` (the default) a missing, unknown,
expired or used-up code returns one generic `403 invalid_invite`, checked before the
duplicate check so outsiders cannot probe which accounts exist. A use is consumed in
the same transaction that inserts the user, so a failed registration does not burn the
code and two registrations cannot share a single-use code. `require_invite = false` is
for local development only.

**Login.** The identifier is a username or email. Unknown users, wrong passwords and
disabled users all get `401 invalid_credentials`, and unknown users are checked against
a dummy hash to hide the timing difference. The token is 32 random bytes from
`secrets`, URL-safe Base64, returned once; only its SHA-256 is stored. Sessions last
12 hours by default (configurable, never infinite), and `last_used_at` is updated at
most once a minute. With TOTP enabled, a missing code gives `403 mfa_required` and a
wrong one `401 invalid_totp`, which spends the same rate-limit budget as a wrong
password. Ten consecutive wrong passwords lock the account for 15 minutes
(`429 account_locked`).

**Devices.** The fingerprint must be the SHA-256 of exactly the 32 key bytes. A key
already bound to another account gives `409 device_exists`, and an account may own at
most 20 devices (`409 device_limit`). Re-binding an approved device is how sign-in
restores access after a sign-out.

**Logout.** It revokes the presented session. An invalid, expired or already revoked
session gets `401 invalid_session`, so a repeated logout returns `401`.

**Password change.** It revokes every session of the account, including the current
one, and suspends every device. Each device comes back at its owner's next sign-in.

## Rate limits

- Login failures per (source address + normalized identifier): 5 per 60 s, then a 60 s
  cooldown. A successful login clears the key.
- Login failures per source address across all identifiers: 20 per 60 s (users behind
  one NAT share it). Wrong TOTP codes count against both limits.
- Registration attempts per source: 3 per 60 s with the same cooldown. A wrong invite counts.

Limited requests get `429` with `Retry-After`. The limiters are in-memory, bounded
(4,096 login keys, 2,048 registration keys) and local to one API process: prototype
abuse protection, not a distributed service.

## Administrator commands

Run as root on the server. **Always pass `--database`**: its default
(`config/authorized_clients.json`) is a development path.

```bash
PY=/opt/pqvpn/.venv/bin/python
ACC=--accounts-db=/var/lib/pqvpn/accounts/accounts.db
AUTH=--database=/var/lib/pqvpn/authorized/authorized_clients.json

sudo $PY -m vpn.cli account invite-create --uses 1 --expires-hours 72 $ACC   # code printed once
sudo $PY -m vpn.cli account invites $ACC                                     # ids, uses left, expiry; never codes
sudo $PY -m vpn.cli account invite-revoke INVITE_ID $ACC

sudo $PY -m vpn.cli account devices --status pending $ACC
sudo $PY -m vpn.cli account approve DEVICE_ID $ACC $AUTH [--vpn-ip 10.8.0.N]
sudo $PY -m vpn.cli account reject DEVICE_ID $ACC
sudo $PY -m vpn.cli account revoke DEVICE_ID $ACC $AUTH

sudo $PY -m vpn.cli account unlock USERNAME $ACC
sudo $PY -m vpn.cli account reset-password USERNAME 'TEMPORARY PASSWORD' $ACC
```

`--uses` defaults to 1 (at most 1000), and an invite without `--expires-hours` never expires.

| Command | Allowed from | Account DB | `AuthorizedClients` |
|---|---|---|---|
| `approve` | pending, rejected, revoked | → `approved` | adds/enables the device as `<username>-<device id>` |
| `reject` | pending | → `rejected` | unchanged |
| `revoke` | approved | → `revoked` | disabled first, never restored by sign-in |

`approve` refuses a disabled account or device. Status changes are compare-and-set,
and if recording `approved` fails after the authorization write, the authorization is
disabled again. `reset-password` sets `password_change_required`. The password
appears in shell history and the process list, so give a temporary one. The CLI
cannot delete accounts.

## Desktop client

The GUI Account page uses a standard-library HTTPS client (`app/client.py`). By default
it talks to `https://52.62.237.95:8443` and pins the bundled
`app/server-account-api.crt` as its only trust anchor. `PQVPN_ACCOUNT_API_URL` and
`PQVPN_ACCOUNT_CA_CERT` override both. Cleartext HTTP is accepted only for a loopback
URL. The bearer token stays in GUI memory: it is never written to disk, sent over the
service socket or logged. A 60 s `/auth/me` check sends an expired or revoked session
back to Login.

"Register This Device" asks the service for the public identity (`SETUP_STATUS`),
re-checks the fingerprint and sends only public values to `POST /devices`. Sign Out
sends the fingerprint so the server suspends the device. If that fails, the GUI says
the device's VPN access could not be revoked. In account-managed mode, Connect (button,
tray, shortcut, auto-connect) is locked while signed out, and the server enforces the
same rule. The Home card combines the account, device and tunnel layers into one state;
the tunnel state always comes from the privileged service.

## HTTPS configuration and service

`config/account-api.toml` is installed as `/etc/pqvpn/account-api.toml`. It sets the
database, bind address and port (8443), TLS files, session lifetime, body limit, rate
limits, `authorized_clients_file` and the public profile fields. The sample sets
`auto_approve = true` and `require_invite = true`; the code defaults are
`auto_approve = false` and `require_invite = true`.

The bind host must be an IP literal, and any non-loopback bind needs both TLS files.
Cleartext needs a loopback address and `allow_insecure_loopback = true`. A missing or
partial TLS config, a symlink, a non-regular file, or a key readable by group or
others fails before binding. `scripts/deploy-server.sh` generates a self-signed
certificate whose SAN covers `PQVPN_PUBLIC_HOST`, regenerating it if it does not, with
a 0400 key owned by `pqvpn-account`. Clients pin that certificate, so replacing it
means redistributing it.

`pqvpn-account-api.service` runs as the non-login `pqvpn-account` user (supplementary
group `pqvpn`), separate from the VPN server. Hardening: no capabilities, `NoNewPrivileges`,
private `/tmp` and devices, `ProtectSystem=strict`, kernel protections, umask 0077. It
can write only to `/var/lib/pqvpn/accounts` and `/var/lib/pqvpn/authorized`, and the
server and client private identities are inaccessible to it. The deploy script enables
and restarts it on every run. Access logging is off. Audit lines carry the endpoint
outcome, source address and, after authentication, the user ID, never passwords,
tokens, hashes or key material.
