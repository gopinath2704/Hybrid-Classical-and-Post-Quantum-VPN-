# PQVPN Protocol v2

This is a KEMTLS-inspired research protocol, not formal KEMTLS. Its static KEM identity design reduces post-quantum handshake communication overhead and fragmentation/segmentation pressure; it does not eliminate fragmentation.

Production has one suite: X25519, ML-KEM-768, HKDF-SHA256, Ed25519 client identities, and AES-256-GCM. The client is provisioned with the SHA-256 fingerprint of the server's 1,184-byte static ML-KEM public key. The server is provisioned with enabled Ed25519 client public-key fingerprints.

## Handshake

Every handshake message has `magic:u16 | version:u8 | type:u8 | payload_length:u16`. TCP adds a four-byte length. Both lengths must exactly match; the maximum control message is 16,384 bytes.

- ClientHello: random(32), session ID(32), ephemeral X25519 public(32), ephemeral ML-KEM public(1184), Ed25519 client public(32).
- ServerHello: random(32), echoed session ID(32), ephemeral X25519 public(32), ML-KEM ciphertext to the client's ephemeral key(1088), SHA-256 identity identifier(32). The provisioned 1,184-byte static key is not retransmitted.
- ClientKeyExchange: ciphertext to the static server identity key(1088), Ed25519 transcript proof(64), client Finished(32).
- ServerFinished: server Finished(32). Only possession of the pinned static ML-KEM private key produces the authentication secret needed for this MAC.

The hybrid input is the ephemeral X25519 secret, one client-ephemeral ML-KEM session secret, and the static authenticated server-KEM secret. The removed server-ephemeral ML-KEM direction duplicated the ephemeral PQ role without providing a distinct authentication role. The retained client ML-KEM key is fresh for each handshake; the static KEM has the separate server-possession role. This unproven protocol simplification requires independent review.

Exact wire sizes are ClientHello 1,318 bytes, ServerHello 1,222 bytes, ClientKeyExchange 1,190 bytes, and ServerFinished 38 bytes: 3,768 bytes total including handshake headers.

HKDF context includes protocol/version, algorithms, session ID, randoms, role-specific labels, and transcript hash. Expansions yield independent data C2S/S2C keys and nonce bases, independent control C2S/S2C keys and nonce bases, Finished keys, a rekey secret, and a control-confirmation key.

## Encrypted frame

All integer fields are network byte order. The 26-byte clear header is authenticated as AES-GCM AAD:

| Field | Bytes |
|---|---:|
| Magic `PV` | 2 |
| Version `0x20` | 1 |
| Channel: DATA or CONTROL | 1 |
| Frame type | 1 |
| Direction | 1 |
| Compact session ID | 8 |
| Key epoch | 4 |
| Sequence | 8 |
| Encrypted payload | variable |
| GCM tag | 16 |

Frame types are DATA, UDP_BIND, UDP_BIND_ACK, PING, PONG, CLOSE, CONFIG, REKEY_REQUEST, REKEY_RESPONSE, and ERROR. Record overhead is exactly 42 bytes before outer IP/UDP headers. DATA and CONTROL have different HKDF keys, nonce bases, counters, and receive state. DATA uses a 128-packet replay window; ordered TCP CONTROL requires exactly the next authenticated sequence. Records cannot authenticate in the other channel. Sequence allocation through encryption/increment is serialized, as is replay eligibility through successful authentication/commit.

After the TCP handshake the server sends encrypted CONFIG. The client sends an encrypted UDP_BIND to the configured UDP port. Only an authenticated `UDP_BIND` with payload `bind` can establish its observed source endpoint. Once bound, a different endpoint is rejected; reconnect to change it. DATA is then accepted only from that endpoint.

Rekey request payload is `next_epoch:u32 || nonce:32`. The server returns `next_epoch || HMAC(control_key, label || request)`, encrypted under the current epoch, then both activate independently derived next-epoch directional material. Replayed/non-monotonic epochs are rejected. This hash-based rekey is key rotation, not post-compromise security.

### Authentication boundary

PQVPN KEMTLS-inspired v2 is a custom protocol, not standardized KEMTLS.
Static ML-KEM-768 authenticates the server; X25519 + ML-KEM-768 establish
hybrid session keys. Ed25519 authenticates clients and is classical, not
post-quantum. This is not fully post-quantum mutual authentication.
Status: deployable research/prototype PQ-VPN. Root namespace validation and
a real VPS/client deployment must both succeed before revising that status.

## Session liveness

Authenticated keepalive traffic refreshes session liveness. Invalid, unauthenticated,
replayed, or wrong-endpoint traffic does not. UDP PING and PONG retain the existing
DATA-domain directional AES-256-GCM protection and replay/epoch checks; PING has
an eight-byte timestamp payload. Only accepted inner IPv4 DATA (including assigned
source-IP validation), valid endpoint binding, and authorized CONTROL activity
count. A bound endpoint cannot be replaced by traffic from another endpoint;
reconnect to establish a new binding. Rekey activity counts only after validation.

A quiet session with healthy PING/PONG survives `idle_timeout`; a genuinely inactive
session still expires. Expiry removes session/IP mappings and the endpoint, releases
the lease, wipes session keys best-effort, closes control, and logs the reason with
client ID and VPN IP, without key material. Client control-loss detection enters
FAILED and runs network cleanup. The absolute `session_timeout` remains independent
of keepalive. Python cannot guarantee complete key zeroization.

Server idle and absolute session expiry use monotonic clocks. Independently, the
client tracks `last_authenticated_udp_rx`: initial valid UDP_BIND_ACK, matching
PONG, or a complete IPv4 DATA packet addressed to its assigned IP refreshes the
receive deadline. Wrong endpoint/session/epoch, replay, bad tag and malformed data
do not. Outgoing PING and CONTROL rekey cannot mask a UDP blackhole. Exceeding
`dead_peer_timeout` enters FAILED and performs route/DNS/TUN/socket cleanup.
The wire format and 1,318 / 1,222 / 1,190 / 38-byte handshake remain unchanged by
the final validation pass.
