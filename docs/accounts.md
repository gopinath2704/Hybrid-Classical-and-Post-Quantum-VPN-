# Account storage, authentication, and device binding

The account API (`vpn.account_api`, installed as `pqvpn-account-api`) is how desktop
users get VPN access without copying keys by hand: they register with an
administrator-issued invite, sign in, bind the device's managed public identity, and
fetch the server profile. Optional TOTP, account lockout, password change and
administrator password reset/unlock are supported. There is no password recovery and
no administrator web interface.

Three decisions stay in separate stores:

1. The account database identifies **who the user is**.
2. A managed Ed25519 identity identifies **which device is connecting**.
3. `AuthorizedClients` (`authorized_clients.json`) decides **whether that device may
   establish a VPN tunnel**. The VPN server reads only this store, never the account
   database.

**Signing in alone never grants VPN access.** The API writes `AuthorizedClients` in
exactly these cases:

| Event | Effect on `AuthorizedClients` |
|---|---|
| Device bound with `auto_approve = true` | device authorized (then marked `approved`) |
| Sign-out with this device's fingerprint | device **suspended** (fail closed: if suspension fails, logout returns `503` and the session stays valid) |
| Sign-in re-binding an approved, suspended device | suspension lifted; an administrator revocation is never undone |
| Password change | every device of the account suspended, every session revoked |

With `auto_approve = false`, binding only records a `pending` device and an
administrator approves it (see below).

## Location and permissions

The deployment default is `/var/lib/pqvpn/accounts/accounts.db`. `AccountStore`
also accepts an explicit path so tests and future deployment wiring need no root
access. When it creates state, it rejects symlink path components, makes the
database directory mode `0700`, and makes the database mode `0600`.

SQLite foreign-key enforcement is enabled on every store connection. Mutations
use transactions and parameterized statements. The schema version (currently 4)
is recorded in SQLite `PRAGMA user_version`; an unversioned non-empty database,
incompatible layout, integrity failure, or newer version fails closed.
`initialize()` migrates versions 1, 2 and 3 to 4 in one transaction after checking
the exact layout of the starting version (v2 added the device `status` column, with
existing devices starting as `pending`; v3 added the TOTP, lockout and
forced-password-change columns; v4 added invites). Migration is one-way: rolling the
code back needs a database backup taken before the upgrade.

## Schema (version 4)

- `users`: numeric primary key, normalized unique username and email, Argon2id
  password hash, enabled flag, UTC creation/update timestamps, an optional TOTP
  secret, a failed-login counter, a `locked_until` timestamp, and a
  `password_change_required` flag (set by an administrator reset).
- `devices`: numeric primary key, owning user with `ON DELETE CASCADE`, display
  name, unique lowercase SHA-256 fingerprint, exactly 32 public Ed25519 key
  bytes, independent enabled flag, UTC timestamps, and an administrator review
  `status` (`pending`, `approved`, `rejected`, or `revoked`; default `pending`).
- `sessions`: numeric primary key, owning user with
  `ON DELETE CASCADE`, unique 32-byte token hash, creation/expiry timestamps, and
  nullable revocation/last-use timestamps. There is intentionally no raw-token
  column.
- `invites`: numeric primary key, unique 32-byte SHA-256 hash of the invite code
  (never the code itself), uses left, optional expiry, and creation time.

Devices and sessions are indexed by user; sessions are also indexed by expiry.
No client private-key field exists. The device table contains public identity
material only, and its fingerprint must equal the SHA-256 digest of those exact
32 public bytes.

## Input and password policy

Usernames are trimmed, Unicode NFKC-normalized, and case-folded to lowercase.
The stored form is 1–64 ASCII characters, starts with a letter or digit, and may
otherwise contain letters, digits, `.`, `_`, or `-`. Username lookup applies the
same normalization, so username case is not significant.

Email addresses are trimmed, Unicode NFKC-normalized, and case-folded in full.
Validation intentionally checks only a practical `local@domain` structure,
lengths, whitespace/control characters, dot placement in the local part, and
ASCII domain-label syntax; it is not an exhaustive RFC mail parser. Email case
is not significant in this account system.

Passwords are not trimmed or normalized. They must contain 12–1024 Unicode
characters; no symbol, number, or mixed-case rule is imposed. The maintained
`argon2-cffi` `PasswordHasher` abstraction uses its safe Argon2id defaults and
fresh random salts. Only encoded Argon2id hashes are stored. Malformed hashes
and mismatches fail authentication without exposing a database or library error,
and hashes can be checked for future parameter rehashing.

A database row or account session alone cannot make a device eligible for a VPN
tunnel; only an entry in `AuthorizedClients` can, written as described above.

## Authentication API

The dedicated FastAPI application is `vpn.account_api`; the installed launcher
is `pqvpn-account-api`. Requests and responses use JSON except that successful
logout has no body. Unknown JSON fields are rejected. Authentication documents
are limited to 16 KiB by default, including streamed requests.

### `POST /auth/register`

Request:

```json
{"username":"alice","email":"alice@example.com","password":"a long passphrase","invite_code":"..."}
```

Success is `201` with a `user` object containing only `id`, normalized
`username`, normalized `email`, `enabled`, and `created_at`. Registration does
not create a session. Invalid account input is `400`; an already-used username
or email is `409`. Passwords and password hashes are never returned.

With `require_invite = true` (the default) `invite_code` is required. A
missing, unknown, revoked, expired or used-up code returns one generic `403`
`invalid_invite`, checked before the duplicate-account check so non-invitees
cannot probe which accounts exist. One use is consumed in the same SQLite
transaction that inserts the user, so a failed registration (duplicate, invalid
input) does not burn the code and concurrent registrations cannot share a
single-use code. Every attempt, including a wrong code, counts against the
per-source registration rate limit. Codes are 256-bit random tokens; only their
SHA-256 is stored (like session tokens), in the `invites` table of the 0600
accounts database. `require_invite = false` restores open registration for
local development only.

### `POST /auth/login`

Request:

```json
{"identifier":"alice or alice@example.com","password":"a long passphrase"}
```

The identifier may be a username or email and uses the M4.1 normalization
rules. Success is `200`:

```json
{
  "access_token": "opaque-token-returned-once",
  "token_type": "bearer",
  "expires_at": "UTC timestamp",
  "user": {"id": 1, "username": "alice", "email": "alice@example.com", "enabled": true, "created_at": "UTC timestamp"}
}
```

The server obtains 32 random bytes (256 bits) from Python's `secrets` module and
encodes them with URL-safe Base64. Only `SHA-256(raw_token)` is stored in SQLite;
the raw token is returned once and is never logged or stored. Argon2id remains
reserved for human passwords. The default session lifetime is 12 hours and is
configurable, but cannot be infinite.

Unknown identifiers, wrong passwords, malformed identifiers, and disabled users
all return the same `401 invalid_credentials` response. Unknown identifiers are
verified against a precomputed dummy Argon2id hash to reduce the obvious timing
difference. A valid login transparently replaces a password hash whose Argon2id
parameters need rehashing.

If the account has TOTP enabled, the request must also carry `"totp_code"`. Without
it the response is `403 mfa_required`; a wrong code is `401 invalid_totp` and spends
the same rate-limit budgets as a wrong password, so the six digits cannot be brute
forced. After 10 consecutive failed passwords the account is locked for 15 minutes
(`429 account_locked`); an administrator can clear it with `account unlock`.

### `GET /auth/me`

This M4.2 session-check endpoint requires `Authorization: Bearer <token>` and
returns the same safe public user fields. Session validation requires an
unexpired, unrevoked session whose owning user still exists and remains enabled.
Valid activity updates `last_used_at` at most once per minute.

### `GET /devices` and `POST /devices`

Both require the Bearer header. `GET /devices` returns the signed-in account's
devices as `{"devices": [...]}` with only `id`, `device_name`, `fingerprint`,
`enabled`, `status`, and `created_at`. The review status changes only through
`auto_approve` or the administrator CLI.

`POST /devices` binds a public Ed25519 identity to the account:

```json
{"device_name":"work laptop","public_key":"base64 of 32 public bytes","fingerprint":"lowercase SHA-256 hex"}
```

The server verifies that the fingerprint is the SHA-256 digest of exactly those
32 bytes. A new binding is `201`; repeating the same binding for the same account
is `200` with the existing record. An identity already bound to any other account
is `409 device_exists`; an account may own at most 20 devices (`409
device_limit`). Unknown fields, including any private-key field, are rejected.
With `auto_approve = true` a new binding is authorized and marked `approved`; if the
authorization write fails the device stays `pending` and a later re-bind retries.
Re-binding an already-approved device is how a sign-in restores access suspended by
an earlier sign-out. With `auto_approve = false` binding never touches
`AuthorizedClients`.

### `POST /auth/logout`

This endpoint requires the same Bearer header, revokes the presented session,
and returns `204`. If the body carries this device's `fingerprint`, the device is
suspended in `AuthorizedClients` first; if that fails the response is `503
deauthorize_failed` and the session is left valid so the client can retry. A
missing, malformed, expired, random, already-revoked, or disabled-user session
returns `401 invalid_session`. Repeating logout therefore returns `401`.

### `POST /auth/change-password`

Requires the Bearer header and `{"old_password": ..., "new_password": ...}`. On
success every session of the account is revoked (including the current one) and
every device is suspended, so a stolen token or an attacker-bound device cannot
outlive the old password; each device is restored by its owner's next sign-in.

### `POST /mfa/setup`, `/mfa/confirm`, `/mfa/disable`

All require the Bearer header. `setup` returns a fresh TOTP secret and
`otpauth://` provisioning URI without storing anything; `confirm` stores the secret
only after a valid code for it; `disable` needs a current valid code.

### `GET /server/info`

Unauthenticated. Returns the public server profile the client imports: control
port, host, expected VPN subnet, and the server's public ML-KEM-768 key with its
SHA-256 fingerprint. It contains no secrets.

API errors have a stable JSON shape:

```json
{"error":{"code":"invalid_credentials","message":"invalid credentials"}}
```

Internal SQLite errors, SQL, paths, hashes, and tracebacks are not placed in API
responses.

## Rate limits

Device documents share the same body limit and JSON content-type requirement.

Login failures are limited by a SHA-256-derived key for source address plus
normalized identifier: five failures in 60 seconds cause a 60-second cooldown.
A successful login clears that key. A second limiter keyed on the source address
alone allows four times that budget (20 failures per 60 seconds) across all
identifiers, which throttles credential stuffing; users behind one shared NAT share
it. Wrong TOTP codes count against both. Registration has an independent per-source
limit of three attempts per 60 seconds and the same cooldown. Limited requests
receive `429` and `Retry-After`.

Both in-memory limiters use monotonic time and a lock. The login limiter retains
at most 4,096 keys and the registration limiter at most 2,048; old entries
expire and least-recent entries are evicted at the bound. The state is local to
one API process and intentionally provides prototype abuse protection rather
than a distributed rate-limit service.

## Administrator commands

With `auto_approve = false`, approval is an explicit administrator action on the
server, run as root with the `vpn.cli account` commands:

```bash
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account devices --status pending \
  --accounts-db /var/lib/pqvpn/accounts/accounts.db
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account approve DEVICE_ID \
  --accounts-db /var/lib/pqvpn/accounts/accounts.db \
  --database /var/lib/pqvpn/authorized/authorized_clients.json [--vpn-ip 10.8.0.N]
```

Registration invites (the code is printed once by `invite-create`; listing shows
only id, uses left and expiry):

```bash
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account invite-create --uses 1 --expires-hours 72 \
  --accounts-db /var/lib/pqvpn/accounts/accounts.db
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account invites --accounts-db /var/lib/pqvpn/accounts/accounts.db
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account invite-revoke INVITE_ID \
  --accounts-db /var/lib/pqvpn/accounts/accounts.db
```

| Command | Allowed from | Account DB | `AuthorizedClients` |
|---|---|---|---|
| `approve` | pending, rejected, revoked | → `approved` | adds/enables the device as `<username>-<device id>` |
| `reject` | pending | → `rejected` | unchanged |
| `revoke` | approved | → `revoked` | disables the fingerprint first |

`approve` refuses a disabled account or disabled device. Status changes are
compare-and-set, so a concurrent decision is not overwritten. If recording
`approved` fails after the authorization write, the authorization is disabled
again. As with `client revoke`, revocation affects new sessions only; restart the
VPN server to end existing sessions. The VPN server keeps using only
`AuthorizedClients`; it never reads the account database.

Accounts:

```bash
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account unlock USERNAME --accounts-db /var/lib/pqvpn/accounts/accounts.db
sudo /opt/pqvpn/.venv/bin/python -m vpn.cli account reset-password USERNAME 'NEW PASSWORD' \
  --accounts-db /var/lib/pqvpn/accounts/accounts.db
```

`reset-password` sets `password_change_required`. It takes the password on the
command line, where it reaches shell history and the process list, so use a
temporary password and have the user change it. The CLI cannot delete accounts.

## Desktop client

The GUI Account page talks to this API with a standard-library HTTPS client in
`app/client.py`. HTTPS certificates are always verified (an optional CA file can
be supplied for a private certificate); cleartext HTTP is accepted only for a
loopback URL. The bearer token is held only in GUI process memory: it is never
written to disk, sent over the service IPC socket, shown, or logged. A 60-second
`/auth/me` check returns an expired, revoked, or disabled-account session to the
Login view. Sign Out sends the device fingerprint so the server suspends the device;
if the server cannot suspend it, the Login view reports that the device's VPN access
could not be revoked.

The Home page "Account & Device" card combines the three layers into one
state: signed out, device not registered, pending approval, rejected, revoked,
disabled, approved (disconnected), VPN connecting, VPN connected, session
expired, or account server unavailable. The tunnel state always comes from the
privileged service. In account-managed mode, Connect (button, tray, shortcut and
auto-connect) is locked while there is no signed-in session; the server enforces the same rule, because a
signed-out device is suspended in `AuthorizedClients`.

"Register This Device" asks the local service for the managed public identity
(`SETUP_STATUS`), re-checks that the fingerprint matches the public key, and sends
only those public values to `POST /devices`. The private key never leaves the
privileged service.

## HTTPS configuration and service

The canonical sample is `config/account-api.toml`, installed as
`/etc/pqvpn/account-api.toml` by both packages. It explicitly configures the
database path, bind address and port, TLS certificate and key, session lifetime,
request-body limit, and the independent login and registration rate-limit
windows, cooldowns, and entry bounds. The sample sets `auto_approve = true` and
`require_invite = true`; the code defaults are `auto_approve = false` and
`require_invite = true`.

The bind host must be an IP literal. Any non-loopback bind requires both TLS
files. Cleartext HTTP is accepted only on an actual loopback address when
`allow_insecure_loopback = true`; this is intended for explicit local
development. Missing files, partial TLS configuration, symlinks, non-regular
files, or a TLS key accessible by group/others fail before binding. The service
does not create certificates, weaken client certificate validation, or copy
the key into SQLite. `scripts/deploy-server.sh` generates a self-signed
certificate whose SAN covers `PQVPN_PUBLIC_HOST` (and regenerates it if it does
not), with a mode `0400` key owned by the `pqvpn-account` service user; clients pin
that certificate. Otherwise provision a certificate and a mode `0600` or `0400` key
owned by `pqvpn-account` yourself.

`pqvpn-account-api.service` is separate from `pqvpn-server.service`. It uses
the dedicated, non-login `pqvpn-account` identity rather than the VPN data-plane
service identity. It uses
`NoNewPrivileges`, private temporary/device namespaces, strict system/home and
kernel protection, an empty capability bounding set, a `0077` umask, and write
access only to `/var/lib/pqvpn/accounts`. Known VPN private-identity paths are
explicitly inaccessible. It does not receive or need `CAP_NET_ADMIN`.

After provisioning the certificate and key, start it with:

```bash
sudo systemctl enable --now pqvpn-account-api.service
```

Framework access logging is disabled by the launcher. Application audit events
include only endpoint outcome categories, source address, rate limiting, and a
user ID after successful authentication; passwords, authorization headers, raw
tokens, token hashes, password hashes, and TLS key content are never logged.
