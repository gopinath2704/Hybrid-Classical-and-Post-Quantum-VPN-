# Account storage and authentication API (Milestones 4.1–4.2)

Milestone 4.1 is the frozen server-side persistence baseline. Milestone 4.2 adds
a dedicated account registration, login, logout, and session-validation API on
top of that store. It does not add a GUI, remote enrollment, account/device
binding workflow, password recovery, MFA, or an administrator web interface.

Three decisions remain deliberately independent:

1. The account database identifies **who the user is**.
2. A managed Ed25519 identity identifies **which device is connecting**.
3. `AuthorizedClients` decides **whether that device may establish a VPN tunnel**.

**Account login does NOT authorize VPN access.** Creating a user, authenticating
an account, or binding a device to a user never grants VPN access. **No account
API endpoint modifies `AuthorizedClients` or `authorized_clients.json`.** A later
milestone may add an explicit administrator-approved workflow between these
stores.

## Location and permissions

The deployment default is `/var/lib/pqvpn/accounts/accounts.db`. `AccountStore`
also accepts an explicit path so tests and future deployment wiring need no root
access. When it creates state, it rejects symlink path components, makes the
database directory mode `0700`, and makes the database mode `0600`.

SQLite foreign-key enforcement is enabled on every store connection. Mutations
use transactions and parameterized statements. Schema version 1 is recorded in
SQLite `PRAGMA user_version`; an unversioned non-empty database, incompatible
layout, integrity failure, or newer version fails closed. Version 1 has no
automatic migration because there is no earlier account schema to migrate.

## Version 1 schema

- `users`: numeric primary key, normalized unique username and email, Argon2id
  password hash, enabled flag, and UTC creation/update timestamps.
- `devices`: numeric primary key, owning user with `ON DELETE CASCADE`, display
  name, unique lowercase SHA-256 fingerprint, exactly 32 public Ed25519 key
  bytes, independent enabled flag, and UTC timestamps.
- `sessions`: numeric primary key, owning user with
  `ON DELETE CASCADE`, unique 32-byte token hash, creation/expiry timestamps, and
  nullable revocation/last-use timestamps. There is intentionally no raw-token
  column.

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

A database row or account session cannot make an account or device eligible for
a VPN tunnel.

## Authentication API

The dedicated FastAPI application is `vpn.account_api`; the installed launcher
is `pqvpn-account-api`. Requests and responses use JSON except that successful
logout has no body. Unknown JSON fields are rejected. Authentication documents
are limited to 16 KiB by default, including streamed requests.

### `POST /auth/register`

Request:

```json
{"username":"alice","email":"alice@example.com","password":"a long passphrase"}
```

Success is `201` with a `user` object containing only `id`, normalized
`username`, normalized `email`, `enabled`, and `created_at`. Registration does
not create a session. Invalid account input is `400`; an already-used username
or email is `409`. Passwords and password hashes are never returned.

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

### `GET /auth/me`

This M4.2 session-check endpoint requires `Authorization: Bearer <token>` and
returns the same safe public user fields. Session validation requires an
unexpired, unrevoked session whose owning user still exists and remains enabled.
Valid activity updates `last_used_at` at most once per minute.

### `POST /auth/logout`

This endpoint requires the same Bearer header, revokes the presented session,
and returns `204`. A missing, malformed, expired, random, already-revoked, or
disabled-user session returns `401 invalid_session`. Repeating logout therefore
returns `401`.

API errors have a stable JSON shape:

```json
{"error":{"code":"invalid_credentials","message":"invalid credentials"}}
```

Internal SQLite errors, SQL, paths, hashes, and tracebacks are not placed in API
responses.

## Rate limits

Login failures are limited by a SHA-256-derived key for source address plus
normalized identifier: five failures in 60 seconds cause a 60-second cooldown.
A successful login clears that key. Registration has an independent per-source
limit of three attempts per 60 seconds and the same cooldown. Limited requests
receive `429` and `Retry-After`.

Both in-memory limiters use monotonic time and a lock. The login limiter retains
at most 4,096 keys and the registration limiter at most 2,048; old entries
expire and least-recent entries are evicted at the bound. The state is local to
one API process and intentionally provides prototype abuse protection rather
than a distributed rate-limit service.

## HTTPS configuration and service

The canonical sample is `config/account-api.toml`, installed as
`/etc/pqvpn/account-api.toml` by both packages. It explicitly configures the
database path, bind address and port, TLS certificate and key, session lifetime,
request-body limit, and the independent login and registration rate-limit
windows, cooldowns, and entry bounds.

The bind host must be an IP literal. Any non-loopback bind requires both TLS
files. Cleartext HTTP is accepted only on an actual loopback address when
`allow_insecure_loopback = true`; this is intended for explicit local
development. Missing files, partial TLS configuration, symlinks, non-regular
files, or a TLS key accessible by group/others fail before binding. The service
does not create certificates, weaken client certificate validation, or copy
the key into SQLite. Administrators must provision a real certificate and a
mode `0600` or `0400` key owned by the `pqvpn-account` service user.

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
