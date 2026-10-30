# Phase 4 handshake inventory

This is a read-only inventory of the Python handshake, key schedule, IPC and metrics that the Phase 4 Rust port (`core/handshake`, `core/crypto`, `pqvpnd`) must reproduce. It was taken on main at `c038f53` (2026-10-30). All line references are against that commit. Nothing here is a design decision.

Shorthand used below: `‖` means concatenation. `H()` is SHA-256. `HKDF()` is full RFC 5869 extract plus expand with SHA-256. `Expand()` is HKDF-Expand only. Integers are big-endian unless stated.

## 1. Key schedule, transcript, cookies, resumption, rekey

### 1.1 Suites and wire constants

| Suite | Header version byte | Name constant | Client auth | Wired into runtime? |
| --- | --- | --- | --- | --- |
| v2-ed25519 | `0x20` (`kemtls.py:24`) | `PROTOCOL_NAME = b"PQVPN-KEMTLS-INSPIRED-v2"` (`:25`) | Ed25519 signature | yes, `protocol_version = 2`, the default (`config.py:22,39`) |
| v3-kem | `0x30` (`:822`) | `PROTOCOL_NAME_V3 = b"PQVPN-KEMTLS-v3"` (`:823`) | client static ML-KEM-768 (implicit) | yes, `protocol_version = 3` |
| v3-mldsa | `0x31` (`:1083`) | `PROTOCOL_NAME_V3_MLDSA = b"PQVPN-MLDSA-v3"` (`:1084`) | ML-DSA-44 signature | **no.** `config.py:113,151` allows only 2 or 3. It is used by tests and `eval/run_pqvpn.py` only. |

**Handshake header** (`kemtls.py:23,36,94-116`): the format is `!HBBH`, which is `MAGIC=0x4856 ‖ version u8 ‖ msg_type u8 ‖ payload_len u16`, 6 bytes in all.
- `payload_len` must satisfy 0 < len ≤ 8186, and the total must equal 6 + len exactly.
- Message types (`:41-50`): 1 CH, 2 SH, 3 CKE, 4 SF, 5 COOKIE_CHALLENGE, 6 COOKIE_RESPONSE, 7 RESUMPTION_HELLO, 8 RESUMPTION_ACCEPT, 0xFF error. 0xFF is never sent.

**TCP control framing** (`runtime.py:36,44-72`): each message goes on the wire as `!I` length plus the message, with a maximum of 16384 bytes. TCP_NODELAY is set at both ends (`:50`). The 4-byte length prefix is **not** part of any transcript.

**Record header** (`kemtls.py:395-400,533-534`): the format is `!2sBBBB8sIQ`, 26 bytes:
- `b"PV"`
- `version u8`
- `channel u8` (1 data, 2 control)
- `frame_type u8`
- `direction u8` (1 c2s, 2 s2c)
- `session_id[:8]`
- `epoch u32`
- `seq u64`

**Record encryption:**
- Cipher: AES-256-GCM, with the 26-byte header as AAD.
- Nonce: `nonce_base XOR (0x00000000 ‖ seq u64)` (`:518-521`).
- Sequences: control receive is strictly sequential (`:593`); data uses a 128-entry replay window (`:403-425`).
- Already in Rust for data: KATs `tests/vectors/frame_{encrypt,decrypt}.json`, made by `tests/test_rust_core.py:35`.

**Message layouts** (all fixed size, checked by `_fixed`):

| Message | v2 (`:134-210`) | v3-kem (`:828-905`) | v3-mldsa (`:1090-1168`) |
| --- | --- | --- | --- |
| CH payload | `client_random32 ‖ session_id32 ‖ x25519_pub32 ‖ mlkem_pub1184 ‖ ed25519_pub32` = 1312 | same, but the last field is `client_identity_hash32` = H(client ML-KEM pub) | same as v3, with H(client ML-DSA pub) |
| SH payload | `server_random32 ‖ session_id32 ‖ x25519_pub32 ‖ eph_ct1088 ‖ identity_id32` = 1216 | v2 layout plus `client_ct1088` = 2304 | same as v2 = 1216 |
| CKE payload | `identity_ct1088 ‖ ed25519_sig64 ‖ finished32` = 1184 | `server_ct1088 ‖ finished32` = 1120 | `server_ct1088 ‖ mldsa_sig2420 ‖ finished32` = 3540 |
| SF payload | `finished32` | same | same |

`identity_id` is H(server ML-KEM-768 identity public key). The fingerprint is `sha256(pub).hexdigest()` (`identity.py:27-28`). The server's 1184-byte identity public key is never sent: the client holds it out of band and pins it by fingerprint (`kemtls.py:691-695`).

### 1.2 Transcript hash (exact byte order)

`TranscriptHasher` (`kemtls.py:292-312`) is a running SHA-256 over **whole handshake messages: the 6-byte header plus payload**. `digest()` hashes a copy of the running state, so the transcript continues afterwards.

For a full handshake (v2, v3 and mldsa use the same order):
1. CH wire (client `:712`, server `:781`). The server hashes the ClientHello as it comes out of the cookie gate. COOKIE_CHALLENGE, COOKIE_RESPONSE and the 32-byte cookie are **never** hashed.
2. SH wire (client `:724`, server `:788`).
3. Then `digest_sh = transcript.digest()`, which is both the key-schedule `transcript_hash` and the input to the client Finished MAC.
4. CKE wire (client `:738`, server `:812`).
5. The Server Finished MAC is over `transcript.digest()` after CKE (`:746,813`).
6. SF wire is appended last (`:750,815`); nothing reads it afterwards.

For resumption (`:1488,1493,1538,1547`), the transcript covers:
- the RESUMPTION_HELLO wire;
- then the RESUMPTION_ACCEPT **header with `payload_len = 1216`** followed by only the **first 1184 payload bytes** (`server_random ‖ session_id ‖ x25519_pub ‖ ct`), without the MAC.

So the hashed header claims a length of 1216, but only 1184 body bytes follow it. A Rust port must reproduce this exactly.

### 1.3 Finished MACs and client proofs

- `finished(key, label, digest) = HMAC-SHA256(key, label ‖ digest)` (`kemtls.py:315-320`). The labels are `b"client finished"` and `b"server finished"` (`:323-324`), and `b"pqvpn resume finished"` for resumption (`:1468`).
- **Client Finished** = `finished(client_finished_key, "client finished", H(digest_sh ‖ partial))`, where `partial` is:
  - v2: `identity_ct ‖ ed25519_sig` (`:734-736`, server `:806-809`)
  - v3: `server_ct` (`:978-980`, server `:1064-1067`)
  - mldsa: `server_ct ‖ mldsa_sig` (`:1241-1244`, server `:1333-1337`)
- **Server Finished** = `finished(server_finished_key, "server finished", digest_after_CKE)` (`:813,1072,1342`).
- **Resume Finished** is server only: `finished(server_finished_key, "pqvpn resume finished", digest_after_accept_sans_mac)` (`:1503-1507,1555-1557`). There is no client Finished in resumption; the client is authenticated only by holding the ticket.
- **Signed message** for v2 (Ed25519) is `PROTOCOL_NAME ‖ b" client proof " ‖ digest_sh ‖ identity_ct` (`:732`, verified at `:801-803` through `identity.py:342`).
- **Signed message** for mldsa is `PROTOCOL_NAME_V3_MLDSA ‖ b" client proof " ‖ digest_sh ‖ server_ct` (`:1238,1328`).
- Server-side check order in v2: decapsulate, derive the schedule, verify the signature, then verify Finished (`:797-811`).

### 1.4 Key schedule (all HKDF labels)

**`KeyManager.derive_key`** (`hybrid_crypto.py:423-440`) is full HKDF-SHA256 (extract plus expand) with 32 bytes of output.

**`_expand(prk, label, context, n)`** (`kemtls.py:327-329`) is `Expand(prk, info = PROTOCOL_NAME ‖ "|" ‖ label ‖ "|" ‖ context, n)`.

> **Quirk:** `PROTOCOL_NAME` here is always the **v2** name `PQVPN-KEMTLS-INSPIRED-v2`, for every suite, for resumption and for rekey. Only `context` carries the suite.

**Traffic secrets.** `_derive_secrets(seed, context)` (`:380-383`) produces 12 secrets, in this order (`:332-345`):

| Field | Label | Bytes |
| --- | --- | --- |
| client_finished_key | `client finished` | 32 |
| server_finished_key | `server finished` | 32 |
| data_c2s_key | `data c2s key` | 32 |
| data_s2c_key | `data s2c key` | 32 |
| data_c2s_nonce_base | `data c2s nonce` | 12 |
| data_s2c_nonce_base | `data s2c nonce` | 12 |
| control_c2s_key | `control c2s key` | 32 |
| control_s2c_key | `control s2c key` | 32 |
| control_c2s_nonce_base | `control c2s nonce` | 12 |
| control_s2c_nonce_base | `control s2c nonce` | 12 |
| rekey_secret | `rekey` | 32 |
| control_confirm_key | `control confirm` | 32 |

**Per-suite master derivation.** Let `cr`, `sr` and `sid` be client_random, server_random and session_id, and `th` the transcript hash `digest_sh`.

| Suite | Context (passed to `_derive_secrets`) | Salt | Master |
| --- | --- | --- | --- |
| v2 (`:386-392`) | `PROTOCOL_NAME ‖ 0x20 ‖ "\|X25519\|ML-KEM-768\|AES-256-GCM\|" ‖ sid ‖ cr ‖ sr ‖ th` | `H("pqvpn extract" ‖ cr ‖ sr ‖ sid)` | `HKDF(ikm = x25519_ss ‖ eph_kem_ss ‖ identity_kem_ss, salt, info "pqvpn master secret")` (ikm order from `:730,798`) |
| v3-kem (`:908-920`) | `PROTOCOL_NAME_V3 ‖ 0x30 ‖ same suite string ‖ sid ‖ cr ‖ sr ‖ th` | same | `hs = HKDF(x25519_ss ‖ k_eph, salt, "pqvpn v3 handshake secret")`; `auth_salt = H(hs ‖ th)`; `master = HKDF(hs ‖ k_s ‖ k_c, auth_salt, "pqvpn v3 authenticated master")`. Here `k_s` is the client→server-identity encaps and `k_c` the server→client-static encaps (`:975,1061`). |
| v3-mldsa (`:1171-1178`) | `PROTOCOL_NAME_V3_MLDSA ‖ 0x31 ‖ "\|X25519\|ML-KEM-768\|ML-DSA-44\|AES-256-GCM\|" ‖ sid ‖ cr ‖ sr ‖ th` | same | `HKDF(x25519_ss ‖ k_eph ‖ k_s, salt, "pqvpn mldsa master secret")` |
| resume (`:1402-1412`) | `b"PQVPN-RESUME" ‖ 0x30 ‖ "\|X25519\|ML-KEM-768\|AES-256-GCM\|" ‖ sid ‖ cr ‖ sr ‖ th_resume` | `H("pqvpn resume" ‖ cr ‖ sr ‖ sid)` | `HKDF(resumption_secret ‖ x25519_ss ‖ kem_ss, salt, "pqvpn resume master secret")` |

> **Quirk:** the resume context hard-codes `0x30` (`PROTOCOL_VERSION_V3`), **including for v2 resumptions**, whose header byte is `0x20` (`:1406`).

In resumption, `sid` is a **fresh** server-chosen session_id (`:1540`), not the original one.

### 1.5 Rekey and rehandshake (control channel)

**Rekey**, which renews the symmetric keys:
- The client sends `REKEY_REQUEST` with payload `epoch u32 ‖ nonce32`, where `epoch = current + 1` and the nonce comes from `os.urandom(32)` (`runtime.py:1096-1101`).
- **Derivation** (`kemtls.py:627-635`):
  - `ctx = session_id ‖ epoch u32 ‖ nonce`
  - `seed = _expand(rekey_secret, "epoch", ctx, 32)`
  - then `_derive_secrets(seed, ctx)`
- **Confirmation:** the server replies with `REKEY_RESPONSE` = `payload[:4] ‖ HMAC(old control_confirm_key, "rekey response" ‖ payload)` (`runtime.py:583-585`; client check at `:1108-1111`). It is keyed with the **old** epoch's key and sent under the old epoch. The server then activates.
- The server checks authorization before deriving (`:577`), and the payload must be exactly 36 bytes (`:579`).

**Rehandshake**, which gives post-compromise security (PCS):
- **Request:** `REHANDSHAKE_REQUEST` = `epoch u32 ‖ x25519_pub32 ‖ mlkem_pub1184` (`runtime.py:1140-1147`). The server checks the length (1220 bytes) and authorization (`:590-595`).
- **Response:** `REHANDSHAKE_RESPONSE` = `epoch u32 ‖ server_x25519_pub32 ‖ ct1088 ‖ confirm32` (`:603-609`; client parses at `:1156-1172`); server keys and encapsulation at `:599-602`.
- **Derivation** (`kemtls.py:637-654`):
  - `transcript = request ‖ response_body`, where `response_body` is the response without the confirm.
  - `ctx = session_id ‖ epoch u32 ‖ H(transcript)`
  - `seed = H(rekey_secret ‖ dh_ss ‖ kem_ss ‖ epoch u32)`, which is **plain SHA-256, not HKDF**
  - then `_derive_secrets(seed, ctx)`
- **Confirmation:** `confirm = HMAC(**new** control_confirm_key, "rehandshake confirm" ‖ transcript)` (`runtime.py:606,1169`).
- The server builds its own `HybridKEM("ML-KEM-768")` without the mock flag (`:596`).

**Activation** (`kemtls.py:656-670`) sets `epoch += 1` exactly, resets all sequences and the replay window, and wipes the old secrets. With the Rust data plane, Python hands over the four data secrets and then zeroes them (`:505-516`).

### 1.6 Cookies, and what happened to the `bid - 1` window

**Current scheme** (`kemtls.py:213-248`), the WireGuard pattern:
- There are two 32-byte secrets, current and previous, both from `os.urandom`.
- Rotation is lazy: every `generate` or `verify` checks whether `time.monotonic() - rotated_at >= 120`.
- `cookie = HMAC-SHA256(secret, client_ip.encode() ‖ port u16)`, where `client_ip` is the ASCII dotted string from `accept()`. The listener is IPv4-only (`runtime.py:399`, `socket.socket()` defaults to `AF_INET`).
- `verify` accepts a MAC under the current **or** the previous secret, so a cookie lives between 120 and 240 s.

**Cookie wire format:**
- `COOKIE_CHALLENGE` = header (type 5, len 32) ‖ cookie (`:251-268`).
- `COOKIE_RESPONSE` = header (type 6) ‖ cookie ‖ **the full CH wire, including its own header** (`:271-289`).

**Server gate** (`runtime.py:433-439,550-574`):
- `cookie_mode` is `off` (the default), `under_load` (when pending handshakes ≥ `cookie_threshold`, default 10) or `always`.
- A COOKIE_RESPONSE as the first message is accepted directly; otherwise the server challenges once.
- The client side is at `runtime.py:874-884`.

**`bid - 1` no longer exists on main.** It was removed in `30e60fc` (2026-10-03, "remove bucket_id from cookie MAC").
- The old scheme MACed `ip ‖ !HQ(port, bucket_id)` with `bucket_id = int(monotonic()) // 120`.
- It verified the previous secret against `bid` and `bid - 1`.
- It crashed with `struct.error` in the first 120 s after boot, because `bid - 1 = -1` cannot be packed as u64, and its buckets drifted out of step with secret rotation.

The successor regression tests are listed in §5. The risk row at `docs/rust-core-migration-plan.md:292` ("cookie `bid - 1`") is stale and should say "cookie current/previous-secret window and boot-time verify".

### 1.7 Resumption ticket

**Issue** (`kemtls.py:1360-1399`, `runtime.py:491-496`):
- The server key is `AESGCM(os.urandom(32))`, held in memory only. A restart invalidates every ticket.
- The ticket is rotated whenever any client drops out of the enabled set (`runtime.py:624-626`).
- **Plaintext:** `resumption_secret32 ‖ !BqHH(protocol_version, expiry, len(cid), len(aip)) ‖ client_id utf8 ‖ assigned_ip utf8`. The expiry is a **signed i64** in wall-clock `time.time()` seconds, and the header is 13 bytes.
- **Ticket on the wire:** `nonce12 (os.urandom) ‖ AES-GCM(ct ‖ tag)`, with AAD `b"PQVPN-RESUME"`.
- `resumption_secret` is the epoch-0 `rekey_secret` of the session that issued the ticket (`runtime.py:494`).
- The ticket is sent as a `RESUMPTION_TICKET` control frame right after CONFIG.

**Lifetime:**
- `resumption_ticket_lifetime` defaults to 86400 s (`config.py:25`) and may be 0 to 604800 (`:117`); 0 disables resumption.
- Validate rejects a ticket when `now > expiry` (`kemtls.py:1395`).
- The version in the ticket must equal the server's version (`:1535`).
- Tickets are **not single-use**, and resumption **skips the cookie gate** (`runtime.py:449-453`, a ponytail note).
- Authorization is re-checked after validation (`:462-465`).

**Hello and accept:**
- `RESUMPTION_HELLO` payload = `client_random32 ‖ ticket_len u16 ‖ ticket ‖ x25519_pub32 ‖ mlkem_pub1184` (`:1415-1443`).
- `RESUMPTION_ACCEPT` payload = `server_random32 ‖ new_session_id32 ‖ x25519_pub32 ‖ ct1088 ‖ finished32` = 1216 (`:1446-1465`).
- The server detects resumption from `msg_type == 7` in the first message's header (`runtime.py:455-456`).

**Client storage** (`runtime.py:801-825`):
- The client keeps `<dir of client key>/.pqvpn_ticket.json`, mode 0600 and opened with `O_NOFOLLOW`.
- It holds `{fp, t: b64 ticket, s: b64 rekey_secret, v: protocol_version}`, so the resumption secret is stored in plaintext on disk.
- If resumption fails, the client reconnects over TCP and falls back to the full handshake (`:858-862`).

### 1.8 Randomness and clock sources (all must be injectable for KATs)

| Source | Where | Primitive |
| --- | --- | --- |
| client_random, session_id | `kemtls.py:709` (v2), `:950` (v3), `:1211` (mldsa) | `os.urandom(32)` ×2 |
| client ephemeral X25519 and ML-KEM keypair | `:708,949,1210` via `HybridKEM.generate_keypairs` (`hybrid_crypto.py:574-584`) | `X25519PrivateKey.generate()`; liboqs `generate_keypair` |
| server_random | `:783,1042,1307` | `os.urandom(32)` |
| server ephemeral X25519 | `:782,1041,1306` | `X25519PrivateKey.generate()` |
| ML-KEM encaps, server→client ephemeral | v2 `:785`, v3 `:1044`, mldsa `:1309` | liboqs `encap_secret` |
| ML-KEM encaps, server→client static (`k_c`) | v3 `:1045` | liboqs `encap_secret` |
| ML-KEM encaps, client→server identity | v2 `:728`, v3 `:971`, mldsa `:1231` | liboqs `encap_secret` |
| ML-DSA-44 signing | mldsa `:1239` | liboqs `Signature.sign`, which is hedged/randomized by default |
| Ed25519 signing | v2 `:733` | deterministic, needs no injection |
| resumption client_random and keypairs | `:1484-1485` | `os.urandom(32)`, `generate_keypairs` |
| resumption server_random, **new session_id**, X25519, encaps | `:1539-1543` | `os.urandom(32)` ×2, `generate()`, `encap_secret` |
| ticket key, ticket nonce | `:1365,1377` | `os.urandom(32)`, `os.urandom(12)` |
| cookie secrets | `:222-223,230` | `os.urandom(32)` |
| rekey nonce | `runtime.py:1096` | `os.urandom(32)` |
| rehandshake keypairs and encaps | client `runtime.py:1141-1142`, server `:599-602` | `generate()`, `generate_keypair`, `encap_secret` |
| mock PQC (tests only) | `hybrid_crypto.py:195,208,343` | `os.urandom(32)` |
| clocks | cookie rotation `time.monotonic` (`kemtls.py:224,227`); ticket expiry `time.time` (`:1370,1395`); session `established_at` `time.time` (`:461`) | n/a |

**Feasibility for Task 2 vectors:**
- The loaded liboqs exports `OQS_KEM_ml_kem_768_keypair_derand` and `OQS_KEM_ml_kem_768_encaps_derand`, plus generic `OQS_KEM_{keypair,encaps}_derand`.
- liboqs-python 0.16.0 wraps only `generate_keypair_seed` (`length_keypair_seed = 64`), so deterministic **encapsulation** on the Python side needs a ctypes shim. A custom `OQS_randombytes` callback would also work.
- X25519 can be injected with `X25519PrivateKey.from_private_bytes`. The `os.urandom` call sites need a seam or a monkeypatch.

## 2. Crypto libraries per primitive

**Libraries in use:**
- `cryptography==50.0.1` and `liboqs-python==0.16.0` (`constraints-tested.txt`).
- The venv loads **`/usr/local/lib/liboqs.so.0.16.0`**, checked through `/proc/self/maps`.
- That build exports BIKE and Classic McEliece symbols (1937 exported functions), so it is **not** the `OQS_MINIMAL_BUILD=KEM_ml_kem_768` build that `constraints-tested.txt` records.
- A second copy, `/usr/lib/liboqs.so.9`, also exists.
- liboqs is located through `_require_installed_liboqs` (`hybrid_crypto.py:98-108`): first `find_library`, then `$OQS_INSTALL_PATH`.
- An ML-KEM-768 keygen/encaps/decaps self-test runs at import, skipped when `_PQVPN_SELFTEST_PASSED=1` (`:111-150`).
- `ALLOW_MOCK_PQC=1` switches to a SHA-based mock (`:35,175-244`).

| Primitive | Backing | Used by |
| --- | --- | --- |
| X25519 | `cryptography` (`hybrid_crypto.py:38-80`) | all suites, resume, rehandshake |
| ML-KEM-768 keygen/encaps/decaps | liboqs through liboqs-python; a new `KeyEncapsulation` object per call (`:277-303`) | all suites, resume, rehandshake, server and client identities |
| Ed25519 sign/verify | `cryptography` (`kemtls.py:16,733`, `identity.py:20,183-187,342-343`) | v2 client identity |
| ML-DSA-44 sign/verify | liboqs through liboqs-python (`hybrid_crypto.py:364-392`) | v3-mldsa only (not wired) |
| HKDF (extract plus expand) | `cryptography` `HKDF` (`hybrid_crypto.py:25,434-440`) | masters for all suites |
| HKDF-Expand | `cryptography` `HKDFExpand` (`kemtls.py:18,329`) | `_derive_secrets`, rekey seed |
| SHA-256, HMAC-SHA256 | Python `hashlib`, `hmac` | transcript, salts, Finished, cookies, confirmations, rehandshake seed |
| AES-256-GCM (control, tickets) | `cryptography` `AESGCM` (`kemtls.py:17,499,1365`) | control channel, resumption tickets |
| AES-256-GCM (data) | Python `AESGCM`, or Rust `pqvpn_core.DataSession` when `data_plane = "rust"` (`:447-450,501-516`) | data channel |

**Per suite:**
- **v2-ed25519:** X25519, ML-KEM-768 ×2 (ephemeral, server identity), Ed25519, HKDF, HMAC.
- **v3-kem:** X25519, ML-KEM-768 ×3 (ephemeral, server identity, client static), two-stage HKDF, HMAC. No signature.
- **v3-mldsa:** X25519, ML-KEM-768 ×2, ML-DSA-44, HKDF, HMAC.

## 3. GUI ↔ client-service IPC contract (what `pqvpnd` must speak)

**Endpoint** (`app/client.py:27-31,47-51`):
- The socket is `$PQVPN_RUNTIME_DIR/client.sock`, defaulting to `/run/pqvpn/client.sock`.
- If that directory is missing, the fallback is `/tmp/pqvpn-client.sock`.
- `/run/pqvpn` is created by `RuntimeDirectory=pqvpn` in `packaging/common/pqvpn-client.service`.
- The unit runs `ExecStart=/usr/bin/python3 -s -m app.client --service` as root, with `AmbientCapabilities=CAP_NET_ADMIN`, `ProtectSystem=strict`, `StateDirectory=pqvpn` (mode 0700) and `UMask=0077`.
- The socket type is `AF_UNIX`, `SOCK_STREAM`, bound and then `chmod 0666` (`:478-482`), with `listen(4)` and a 1 s accept timeout and one thread per connection (`:484-512`).
- A stale socket is probed and unlinked (`:464-475`).

**Authentication**, in both directions:
- **Server side:** `SO_PEERCRED` uid must be 0 or in `PQVPN_ALLOWED_UIDS`, a comma-separated list of digits. Anything malformed gives an empty set, which means root only (`:148-167,455-458`). Packaging adds a drop-in for this (`packaging/arch/pqvpn.install:3-6`).
- An unauthorized peer gets `{"error": "unauthorized"}`, and the connection is closed without reading the request (`:540-546`).
- **Client side:** `IPCClient` **refuses any service whose peer uid is not 0** (`:781-783`), so `pqvpnd` must run as root.

**Framing:**
- `!I` length, then UTF-8 JSON, with 0 < len ≤ `MAX_IPC_MESSAGE = 16384` (`:23,117-145`).
- **One request and one response per connection.**
- The receive timeout is 10 s by default (`:125`). The GUI and `IPCClient` use that default, and **CONNECT is synchronous**, so a connect slower than 10 s shows up as an error in the GUI.
- The M1 warm harness uses 60 s.

**Requests and dispatch** (`:412-453`):
- A request is `{"command": str, ...}`, matched case-insensitively (`.upper()`).
- `_require_fields` rejects unknown keys and a missing or empty command (`:271-280`).
- Errors come back as `{"error": sanitized_str}` (`:548-552`, `sanitize_error` `:35-44`).

| Command | Extra fields | Success response | Notes |
| --- | --- | --- | --- |
| `STATUS` | none | `{"status": ClientStatus}` | `_get_status` `:563-678` |
| `CONNECT` | none | `{"status": "connected", "info": <server CONFIG dict>}` | `:694-748`. Uses a non-blocking lock, otherwise `{"error": "operation in progress"}`; also `"already connected"`. Errors are rewritten in managed mode (`:734-741`). |
| `DISCONNECT` | none | `{"status": "disconnected"}` | `:750-771`; `"not connected"` |
| `LOGS` | none | `{"logs": [{timestamp, level, message}]}` | ring buffer of 300 (`:195,256-268`) |
| `SETUP_STATUS` | none | `{"setup": {...}}` | `:291-322`; the keys differ between managed and `--config` mode |
| `ENSURE_IDENTITY` | none | `{"identity": setup}` | managed only (`:333-347`) |
| `LIST_PROFILES` | none | `{"profiles": [...], "active_profile_id"}` | managed only |
| `IMPORT_PROFILE` | `profile` (str, required), `replace` (bool) | `{"profile": {...}}` | `:349-366` |
| `SELECT_PROFILE` | `profile_id` (str) | `{"selected_profile_id"}` | `:368-383` |
| `DELETE_PROFILE` | `profile_id` (str) | `{"removed_profile_id"}` | `:385-399` |
| `EXPORT_ENROLLMENT_REQUEST` | `client_id` (str) | `{"enrollment": {...}, "content": json_str}` | `:401-410` |

**`ClientStatus` schema is strict** (`:63-114`). `IPCClient.status()` builds it with `ClientStatus(**resp["status"])` (`:804-811`). An **extra or renamed key raises `TypeError`** in the GUI; a missing key falls back to its default.

The fields are:
- `state`, `error`, `uptime_seconds`
- `client_vpn_ip`, `server_host`, `server_vpn_ip`
- `tun_name`, `tun_mode`
- `epoch`, `pqc_mode`, `is_quantum_safe`, `rekey_countdown`
- `rtt_ms`, `jitter_ms`, `loss_rate`
- `ipv6_guard_active`, `dns_managed`, `kill_switch_active`, `mtu`
- `config_path`, `server_control_port`, `connected_endpoint`, `expected_vpn_subnet`, `server_fingerprint`
- `full_tunnel`, `split_tunnel`, `ipv6_policy`, `dns_mode`, `dns_servers`
- `configured_tun_name`, `rekey_interval`
- `managed_mode`, `setup_complete`, `identity_ready`, `identity_fingerprint`
- `active_profile_id`, `active_profile_name`, `connected_profile_id`, `connected_profile_name`
- `profile_store_path`, `identity_path`, `profiles`

`state` takes the `ConnectionState` values (`:54-60`): DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, FAILED, SETUP_REQUIRED. The schema is pinned by `test_client_status_serialization_and_real_schema` (`tests/test_runtime.py:296`).

**Consumers:**
- The GUI uses `IPCClient` from `app/ui/window.py:101`, through `_IPCWorker` (`app/client.py:1774-1872`), with commands lowercased into method calls.
- The M1 warm harness (`eval/run_pqvpn_net.sh:244-250`) opens the socket directly through `ipc_send`/`ipc_recv`.
- **Modes:** with no `--config` the service runs in managed mode, with a profile store and identity under `/var/lib/pqvpn`. `--config PATH` is the legacy mode, where the onboarding commands raise (`:324-326,1971-1997`).

## 4. What M1 cold, M2 and M8 measure today

### M1, connect time: `eval/run_pqvpn_net.sh <profile> [--data-plane python|rust]`

The run needs root.

**Topology and suite:**
- netns, veth and netem.
- The server is a long-lived `python -m vpn.cli server` (`:170-175`).
- **The suite is v2-ed25519.** The configs set no `protocol_version` (`:136-164`) and `client-key generate` runs without `--kem` (`:129`).
- `cookie_mode` is off (the default), resumption is on (the server default), and `full_tunnel = false`.

**Cold** (`:208-230`):
- **Clock:** bash `date +%s%N` wall clock, taken *before* `ip link del pqbench0` and `rm -f .pqvpn_ticket.json`, so every run is a full handshake. Then a **new `python -m vpn.cli client connect` process** is spawned.
- **Stop:** the first successful `ping -c1 -W1 10.8.0.1` from the client netns, polled every 10 ms with one fork per poll (`:198-206`). Before Phase 1 the poll was every 50 ms.
- **What is included:**
  - interpreter start and imports
  - the liboqs load and the import-time ML-KEM self-test, which runs in a fresh process
  - TCP connect, the full handshake, CONFIG and receipt of the ticket
  - TUN open, then `ip addr` and `ip link` forks (`runtime.py:150-168`), then `ClientNetwork.apply` routes (`:200`)
  - the `UDP_BIND` round trip, and the first ping round trip
- 30 runs; the median and 95% CI are reported.

**Warm** (`:232-280`):
- `app.client --service` runs in a private mount namespace.
- The clock is `time.time_ns()`, printed just before `ipc_send(CONNECT)`, so it excludes Python startup. The stop condition is the same ping.
- There is one untimed warm-up CONNECT, and the ticket is still deleted each run.

**Cold numbers so far (LAN, v2):**

| Phase | Commit / date | Data plane | Cold (ms) | Warm (ms) |
| --- | --- | --- | --- | --- |
| Published | 2026-10-10 | Python | 163 | n/a |
| Phase 0 | b726b42 | Python | 163 | n/a |
| Phase 1 | 2026-10-29 | Python | 164 | 52 |
| Phase 2 | 17d4667 | Rust | 131 | 9.0 |
| Phase 3 | 2026-10-29 | Rust | 126 | 15 |

- The Phase 0 caveat (`eval/results-summary/phase0-2026-10-28/README.md`): metro and other non-LAN cold rows were really resumed connects, because the ticket was not deleted. This was fixed in Phase 1. LAN is unaffected.
- **The cold definition for Phases 0-3:** a new client process, no ticket, full v2 handshake, from spawn to the first tunnel ping.
- The ≤30 ms gate under this definition needs a **native one-shot client** (no Python interpreter or imports). `pqvpnd` alone would improve the warm row, not cold. Cold minus warm is about 110 ms, which is process start alone.

### M2, handshake CPU: `eval/run_pqvpn.py` `run_handshake` (`:105-147`), `evaluate_suite` (`:203-277`)

**What it measures:**
- Both roles run **in one process, with no network**, calling each other's methods directly.
- The clock is `time.process_time()` (whole-process CPU) around each step:
  - client CPU = initiate + process_server_hello + process_server_finished
  - server CPU = process_client_hello + process_client_key_exchange
- `latency_ms` is the `perf_counter` wall time of the whole exchange.
- Identities and endpoint construction (`HybridKEM`, `TranscriptHasher`) fall **outside** the timed region.
- Included: ephemeral keygen, every encaps/decaps (each builds a new liboqs object), HKDF, signatures and record-session construction.
- 5 warm-ups, then n = 50 runs.
- Data plane `python`, no cookie, no transcript of the TCP framing.

**Baseline:**
- The published "0.39 ms" is the **v3-kem total** (Table B: 0.204 + 0.184).
- Phase 0: v3-kem 0.207 + 0.187; v2 0.221 + 0.255 = 0.48; mldsa 0.24 + 0.20.
- The gate (≤ 0.2 ms) needs **both roles** in Rust to be meaningful under this definition.

### M8, memory per session: `eval/measure_memory.py`

**What it measures:**
- The **server** process's `VmRSS` from `/proc/<pid>/status`, read twice:
  - a baseline right after a 2 s settle (`:160-175,235`)
  - again 2 s after N clients ping through (`:253`)
- Per-session = (loaded − baseline) / connected, for N ∈ {1, 10, 50}. The headline is **N = 50**.

**Setup:**
- Python data plane, v2 (no `protocol_version`, no `--kem`), `cookie_mode = "off"`, server defaults otherwise, resumption on (`:100-151`).
- Each client is its own `vpn.cli client connect` process in its own netns.

**What it includes:** one server `_client` thread per session (stack plus objects), `ServerSession`, `HandshakeSession`, the AESGCM objects, the IP pool and the ticket-key state.

**Results:**
- 186 kB published (`EVALUATION.md` Table G); 170.3 kB at Phase 0 (`phase0-2026-10-28/m8-memory.csv`).
- Not to be confused with `eval/run_pqvpn.py:181` `measure_memory_per_session`: that is an in-process psutil RSS delta over 100 session pairs, both roles, a different metric.

## 5. Regression tests the port must keep

**Cookie** (the successors of `bid - 1`), in `tests/test_crypto_protocol.py`:
- `test_cookie_protector_round_trip` (995)
- `test_cookie_wrong_ip_rejected` (1002)
- `test_cookie_wrong_port_rejected` (1008)
- `test_cookie_bad_length_rejected` (1014)
- `test_cookie_challenge_pack_unpack` (1020)
- `test_cookie_challenge_v3_version` (1026)
- `test_cookie_response_pack_unpack` (1033)
- `test_cookie_response_invalid_too_short` (1043)
- `test_cookie_protector_rotation` (1049)
- `test_cookie_accepted_just_before_and_after_rotation` (1059)
- `test_cookie_rejected_after_two_rotations` (1068)
- `test_cookie_no_crash_at_boot_time` (1078, the `bid - 1` regression)

Runtime, in `tests/test_runtime.py`:
- `test_cookie_always_mode_handshake_completes` (809)
- `test_cookie_off_mode_no_challenge` (839)

**Rate limiter and admission:**
- `SourceRateLimiter` (`runtime.py:337-360`) allows 10 per source IP per 60 s, using a sliding deque.
- It caps distinct sources at 65536, rejecting new ones beyond that, and prunes once per window.
- It is applied at `accept()` before a thread is spawned (`:418-426`), alongside the `max_clients` semaphore and `CONTROL_LISTEN_BACKLOG = 64` (`:40`).
- Tests in `tests/test_runtime.py`: `test_rate_limiter_prunes_sources` (197), `test_rate_limiter_caps_unique_sources` (321), `test_source_rate_limiter_window` (369).

**Revocation:**
- Every 30 s (`runtime.py:635-640`), `_check_revocations` (`:620-633`) closes the control socket of any revoked session and rotates the ticket key if any client was removed.
- Authorization is also checked at resume (`:464`), rekey (`:577`) and rehandshake (`:590`).
- Tests:
  - `tests/test_runtime.py`: `test_revoked_client_session_terminated` (1082), `test_revocation_rotates_ticket_key` (1107), `test_rekey_rejects_revoked_client` (1128), `test_signed_out_client_cannot_resume_before_revocation_sweep` (1038)
  - `tests/test_networking.py`: `test_revoked_client_cannot_start_new_handshake` (261)
  - `tests/test_crypto_protocol.py`: `test_signed_out_client_fails_handshake_authorization` (432)
  - `tests/test_accounts.py`: `test_admin_revoke_disables_tunnel_authorization` (513)

**Resumption:**
- `tests/test_crypto_protocol.py`: `test_resumption_1rtt_roundtrip` (1252), `test_resumption_expired_ticket_rejected` (1294), `test_resumption_tampered_ticket_rejected` (1301), `test_resumption_wrong_key_rejected` (1310)
- `tests/test_runtime.py`: `test_resumption_ticket_file_permissions` (917), `test_v3_resumption_resumes_end_to_end_not_fallback` (933)
- `tests/test_rust_core.py`: `test_mixed_data_planes_interoperate_across_rekey` (264, parametrized `resumed`)

**Rekey:**
- `tests/test_crypto_protocol.py`: `test_synchronized_rekey_and_old_epoch_rejection` (465)
- `tests/test_runtime.py`:
  - `test_delayed_rekey_keeps_data_forwarding` (116)
  - `test_automatic_rekey_short_interval` (372)
  - `test_overlapping_rekey_rejected` (376)
  - `test_client_rekey_protocol_uses_control_domain` (382)
  - `test_rust_rekey_and_remove_under_load` (704)
  - `test_manual_and_automatic_rekey_during_authenticated_traffic` (797)
  - `test_mixed_data_planes_interoperate_end_to_end` (452)

**Rehandshake:**
- `tests/test_crypto_protocol.py`:
  - `test_rehandshake_epoch_derives_new_keys` (749)
  - `test_rehandshake_old_epoch_rejected` (771)
  - `test_rehandshake_wrong_epoch_rejected` (792)
  - `test_rehandshake_bad_secret_length_rejected` (799)
  - `test_rehandshake_multiple_epochs` (808)
  - `test_rehandshake_pcs_recovery` (829)
  - `test_rehandshake_after_rekey` (853)
  - `test_rehandshake_empty_transcript_rejected` (878)
  - `test_rehandshake_wrong_rekey_secret_yields_different_keys` (885)
  - `test_rehandshake_tampered_dh_public_key_yields_different_keys` (909)
  - `test_rehandshake_transcript_mismatch_yields_different_keys` (932)
  - `test_rehandshake_key_confirmation_rejects_flipped_byte` (954)
- `tests/test_runtime.py`: `test_rehandshake_succeeds_and_advances_epoch` (868), `test_rehandshake_tampered_confirmation_fails_client` (879), `test_rehandshake_after_rekey` (905)

**Handshake correctness and wire format**, in `tests/test_crypto_protocol.py`:
- v2:
  - `test_authenticated_handshake_and_directional_keys` (417)
  - `test_wrong_server_fingerprint_rejected` (422)
  - `test_mitm_identity_substitution_rejected` (425)
  - `test_unauthorized_client_rejected` (429)
  - `test_transcript_tampering_rejected` (439)
  - `test_trailing_and_header_mismatch_rejected` (446)
  - `test_exact_reduced_handshake_sizes` (478)
  - `test_message_fixed_sizes` (499)
  - **`test_frozen_v2_handshake_serialization` (503).** This pins the header hex and the SHA-256 of all four v2 messages built from fixed fields. It is a partial wire KAT, covering serialization only and no secrets; Task 2 should extend it.
  - `test_transcript_hash_copy_and_count` (522)
  - `test_finished_mac_labels_and_tampering` (525)
  - `test_handshake_state_transitions` (534)
  - `test_invalid_x25519_points_raise_handshake_error` (1316)
- v3-kem: `test_v3_*` (666-736)
- mldsa: `test_mldsa_*` (1115-1212), including `test_mldsa_key_schedule_differs_from_v3_kem`
- `test_native_mlkem_self_test` (1225)

**IPC** (keep these green against `pqvpnd`):
- `tests/test_client_app.py`: `TestIPCFraming` (39), `TestMalformedIPC` (245), `TestPeerAuthorization` (282) including `test_desktop_user_runs_commands_over_real_socket` (309), `TestIPCClient` (328)
- `tests/test_onboarding.py`: `test_managed_service_setup_and_narrow_ipc` (303), `test_maximum_profile_status_fits_unchanged_ipc_limit` (337), `test_ipc_rejects_unknown_fields_and_generic_file_writes` (390), `test_public_enrollment_roundtrip_over_real_ipc_frame` (398)

**Existing KATs:** `tests/test_rust_core.py:59-180` (record layer only). There is no handshake or key-schedule KAT yet; that gap is Task 2.

## 6. Points for the design review

1. **M8 measures the server process, but `pqvpnd` is the client daemon.** Reaching 64 kB per session needs the server's per-session handling (one Python thread per client plus its objects) moved or restructured, or the gate redefined.
2. **M2 is both roles in one process.** Porting only the client cannot pass 0.2 ms.
3. **M1 and M8 have only ever been measured on v2-ed25519,** while M2's baseline is v3-kem. Pick one suite for the Phase 4 gates.
4. **M1 cold ≤ 30 ms needs a native one-shot client.** About 110 ms of today's cold time is Python process start, and the `ip` forks are still present (the pyroute2 quick win has not landed).
5. **Byte-level quirks to reproduce exactly, not "fix" during the port:**
   - the v2 name in every HKDF `info`
   - the `0x30` byte in the resume context
   - the resume transcript header that claims 1216 bytes over 1184 hashed
   - the plain-SHA-256 rehandshake seed
   - rekey confirmed under the old key, rehandshake confirmed under the new key
6. **liboqs on this host is `/usr/local/lib/liboqs.so.0.16.0`, a full build,** not the minimal build in `constraints-tested.txt`. Decide which liboqs the Rust core links, or use a pure-Rust ML-KEM, before generating vectors.
7. **v3-mldsa is not reachable from config.** Decide whether Phase 4 ports it.
