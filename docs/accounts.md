# Account database (Milestone 4.1)

Milestone 4.1 adds server-side persistence for user authentication. It does not
add an HTTP API, registration or login endpoint, GUI, token delivery, remote
enrollment, or administrator web interface.

Three decisions remain deliberately independent:

1. The account database identifies **who the user is**.
2. A managed Ed25519 identity identifies **which device is connecting**.
3. `AuthorizedClients` decides **whether that device may establish a VPN tunnel**.

Creating a user or binding a device to a user never updates
`authorized_clients.json` and never grants VPN access. A later milestone may add
an explicit administrator-approved workflow between these stores.

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
- `sessions`: schema foundation only, with numeric primary key, owning user with
  `ON DELETE CASCADE`, unique 32-byte token hash, creation/expiry timestamps, and
  nullable revocation/last-use timestamps. There is intentionally no raw-token
  column and no session-token generation behavior in Milestone 4.1.

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

Milestone 4.1 has no network login API. A database row therefore cannot itself
authenticate a remote request or make an account or device eligible for a VPN
tunnel.
