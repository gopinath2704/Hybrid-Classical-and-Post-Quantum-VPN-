//! KEMTLS handshake messages, transcript and primitives, mirroring handshake/kemtls.py for v2 (0x20), v3-kem (0x30)
//! and resumption. v3-mldsa (0x31) is not ported: `Suite::from_version` refuses it. No I/O and no state machine yet.
//! Every random draw goes through `Draws`, whose only non-test implementation is `Os`.

use aws_lc_rs::{agreement, digest, kem, rand, signature};
use zeroize::Zeroizing;

use crate::schedule::PROTOCOL_NAME;

const MAGIC: [u8; 2] = [0x48, 0x56];
pub const HEADER_LEN: usize = 6;
/// `MAX_HANDSHAKE_MESSAGE - HEADER_SIZE`.
pub const MAX_PAYLOAD: usize = 8192 - HEADER_LEN;
pub const EK_LEN: usize = 1184;
pub const CT_LEN: usize = 1088;
pub const COOKIE_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    V2,
    V3,
}

impl Suite {
    pub fn version(self) -> u8 {
        match self {
            Suite::V2 => 0x20,
            Suite::V3 => 0x30,
        }
    }

    pub fn from_version(version: u8) -> Result<Self, Error> {
        match version {
            0x20 => Ok(Suite::V2),
            0x30 => Ok(Suite::V3),
            0x31 => Err(Error::MldsaUnsupported),
            _ => Err(Error::Version),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    ClientHello = 1,
    ServerHello = 2,
    ClientKeyExchange = 3,
    ServerFinished = 4,
    CookieChallenge = 5,
    CookieResponse = 6,
    ResumptionHello = 7,
    ResumptionAccept = 8,
    Error = 0xFF,
}

impl MsgType {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => MsgType::ClientHello,
            2 => MsgType::ServerHello,
            3 => MsgType::ClientKeyExchange,
            4 => MsgType::ServerFinished,
            5 => MsgType::CookieChallenge,
            6 => MsgType::CookieResponse,
            7 => MsgType::ResumptionHello,
            8 => MsgType::ResumptionAccept,
            0xFF => MsgType::Error,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            MsgType::ClientHello => "CLIENT_HELLO",
            MsgType::ServerHello => "SERVER_HELLO",
            MsgType::ClientKeyExchange => "CLIENT_KEY_EXCHANGE",
            MsgType::ServerFinished => "SERVER_FINISHED",
            MsgType::CookieChallenge => "COOKIE_CHALLENGE",
            MsgType::CookieResponse => "COOKIE_RESPONSE",
            MsgType::ResumptionHello => "RESUMPTION_HELLO",
            MsgType::ResumptionAccept => "RESUMPTION_ACCEPT",
            MsgType::Error => "HANDSHAKE_ERROR",
        }
    }
}

/// Rejections, each with the message Python's `HandshakeError` carries for the same input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    HeaderShort(usize),
    Magic,
    Version,
    PayloadLength,
    LengthMismatch,
    MsgType,
    Expected(MsgType),
    FixedLength(MsgType),
    ResumptionExpected,
    ResumptionShort,
    ResumptionSize,
    CookieShort,
    CookieType,
    CookieLength,
    CookieSize,
    MldsaUnsupported,
    PeerKey,
    Crypto,
}

impl Error {
    pub fn message(self) -> String {
        match self {
            Error::HeaderShort(got) => format!("Header too short: expected {HEADER_LEN} bytes, got {got}"),
            Error::Magic => "Invalid magic".into(),
            Error::Version => "Unsupported version".into(),
            Error::PayloadLength => "invalid handshake payload length".into(),
            Error::LengthMismatch => "handshake header length mismatch".into(),
            Error::MsgType => "unexpected handshake message type".into(),
            Error::Expected(t) => format!("Expected {}", t.name()),
            Error::FixedLength(t) => format!("{} payload length mismatch", t.name()),
            Error::ResumptionExpected => "expected RESUMPTION_HELLO".into(),
            Error::ResumptionShort => "RESUMPTION_HELLO too short".into(),
            Error::ResumptionSize => "RESUMPTION_HELLO size mismatch".into(),
            Error::CookieShort => "cookie challenge too short".into(),
            Error::CookieType => "expected COOKIE_CHALLENGE".into(),
            Error::CookieLength => "invalid cookie challenge length".into(),
            Error::CookieSize => "invalid cookie size".into(),
            Error::MldsaUnsupported => "v3-mldsa is not supported by the Rust handshake".into(),
            Error::PeerKey => "invalid peer key material".into(),
            Error::Crypto => "internal cryptographic failure".into(),
        }
    }
}

/// `_pack_header` plus the payload.
fn pack(version: u8, msg_type: MsgType, payload: &[&[u8]]) -> Result<Vec<u8>, Error> {
    let len: usize = payload.iter().map(|p| p.len()).sum();
    if len == 0 || len > MAX_PAYLOAD {
        return Err(Error::PayloadLength);
    }
    let mut wire = Vec::with_capacity(HEADER_LEN + len);
    wire.extend_from_slice(&MAGIC);
    wire.extend_from_slice(&[version, msg_type as u8]);
    wire.extend_from_slice(&u16::try_from(len).map_err(|_| Error::PayloadLength)?.to_be_bytes());
    payload.iter().for_each(|p| wire.extend_from_slice(p));
    Ok(wire)
}

/// `_unpack_header`: returns the message type and the payload, checking in Python's order.
fn unpack(wire: &[u8], version: u8) -> Result<(MsgType, &[u8]), Error> {
    let (header, payload) = wire.split_first_chunk::<HEADER_LEN>().ok_or(Error::HeaderShort(wire.len()))?;
    if header[..2] != MAGIC {
        return Err(Error::Magic);
    }
    if header[2] != version {
        return Err(Error::Version);
    }
    let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if len == 0 || len > MAX_PAYLOAD {
        return Err(Error::PayloadLength);
    }
    if payload.len() != len {
        return Err(Error::LengthMismatch);
    }
    Ok((MsgType::from_u8(header[3]).ok_or(Error::MsgType)?, payload))
}

/// `_fixed`.
fn fixed(wire: &[u8], version: u8, wanted: MsgType, len: usize) -> Result<Reader<'_>, Error> {
    let (msg_type, payload) = unpack(wire, version)?;
    if msg_type != wanted {
        return Err(Error::Expected(wanted));
    }
    if payload.len() != len {
        return Err(Error::FixedLength(wanted));
    }
    Ok(Reader(payload))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// Callers check the payload length first, so `take` only fails on a bug; it reports one instead of panicking.
    fn take<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        let (field, rest) = self.0.split_first_chunk::<N>().ok_or(Error::LengthMismatch)?;
        self.0 = rest;
        Ok(field)
    }
}

/// `ClientHello` and `ClientHelloV3`: the last field is the Ed25519 public key (v2) or the client identity hash (v3).
#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello<'a> {
    pub client_random: &'a [u8; 32],
    pub session_id: &'a [u8; 32],
    pub x25519: &'a [u8; 32],
    pub mlkem_ek: &'a [u8; EK_LEN],
    pub client_identity: &'a [u8; 32],
}

impl<'a> ClientHello<'a> {
    pub const SIZE: usize = 1312;

    pub fn pack(&self, suite: Suite) -> Result<Vec<u8>, Error> {
        pack(suite.version(), MsgType::ClientHello,
             &[self.client_random, self.session_id, self.x25519, self.mlkem_ek, self.client_identity])
    }

    pub fn parse(suite: Suite, wire: &'a [u8]) -> Result<Self, Error> {
        let mut r = fixed(wire, suite.version(), MsgType::ClientHello, Self::SIZE)?;
        Ok(Self { client_random: r.take()?, session_id: r.take()?, x25519: r.take()?, mlkem_ek: r.take()?, client_identity: r.take()? })
    }
}

/// `ServerHello` (v2) and `ServerHelloV3`, which appends the encapsulation to the client's static key.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello<'a> {
    pub server_random: &'a [u8; 32],
    pub session_id: &'a [u8; 32],
    pub x25519: &'a [u8; 32],
    pub eph_ct: &'a [u8; CT_LEN],
    pub identity_id: &'a [u8; 32],
    pub client_ct: Option<&'a [u8; CT_LEN]>,
}

impl<'a> ServerHello<'a> {
    pub fn pack(&self, suite: Suite) -> Result<Vec<u8>, Error> {
        let mut fields: Vec<&[u8]> = vec![self.server_random, self.session_id, self.x25519, self.eph_ct, self.identity_id];
        fields.extend(self.client_ct.map(|ct| &ct[..]));
        pack(suite.version(), MsgType::ServerHello, &fields)
    }

    pub fn parse(suite: Suite, wire: &'a [u8]) -> Result<Self, Error> {
        let size = if suite == Suite::V3 { 2304 } else { 1216 };
        let mut r = fixed(wire, suite.version(), MsgType::ServerHello, size)?;
        Ok(Self {
            server_random: r.take()?,
            session_id: r.take()?,
            x25519: r.take()?,
            eph_ct: r.take()?,
            identity_id: r.take()?,
            client_ct: if suite == Suite::V3 { Some(r.take()?) } else { None },
        })
    }
}

/// `ClientKeyExchange` (v2: identity ciphertext, Ed25519 signature, Finished) and `ClientKeyExchangeV3` (no signature).
#[derive(Debug, PartialEq, Eq)]
pub struct KeyExchange<'a> {
    pub ct: &'a [u8; CT_LEN],
    pub signature: Option<&'a [u8; 64]>,
    pub finished: &'a [u8; 32],
}

impl<'a> KeyExchange<'a> {
    pub fn pack(&self, suite: Suite) -> Result<Vec<u8>, Error> {
        let mut fields: Vec<&[u8]> = vec![self.ct];
        fields.extend(self.signature.map(|s| &s[..]));
        fields.push(self.finished);
        pack(suite.version(), MsgType::ClientKeyExchange, &fields)
    }

    pub fn parse(suite: Suite, wire: &'a [u8]) -> Result<Self, Error> {
        let size = if suite == Suite::V3 { 1120 } else { 1184 };
        let mut r = fixed(wire, suite.version(), MsgType::ClientKeyExchange, size)?;
        Ok(Self { ct: r.take()?, signature: if suite == Suite::V2 { Some(r.take()?) } else { None }, finished: r.take()? })
    }
}

pub fn pack_server_finished(suite: Suite, finished: &[u8; 32]) -> Result<Vec<u8>, Error> {
    pack(suite.version(), MsgType::ServerFinished, &[finished])
}

pub fn parse_server_finished(suite: Suite, wire: &[u8]) -> Result<&[u8; 32], Error> {
    fixed(wire, suite.version(), MsgType::ServerFinished, 32)?.take()
}

/// `ResumptionHello`: the ticket is length-prefixed (u16) and opaque to the client.
#[derive(Debug, PartialEq, Eq)]
pub struct ResumptionHello<'a> {
    pub client_random: &'a [u8; 32],
    pub ticket: &'a [u8],
    pub x25519: &'a [u8; 32],
    pub mlkem_ek: &'a [u8; EK_LEN],
}

impl<'a> ResumptionHello<'a> {
    pub fn pack(&self, version: u8) -> Result<Vec<u8>, Error> {
        let ticket_len = u16::try_from(self.ticket.len()).map_err(|_| Error::PayloadLength)?.to_be_bytes();
        pack(version, MsgType::ResumptionHello, &[self.client_random, &ticket_len, self.ticket, self.x25519, self.mlkem_ek])
    }

    pub fn parse(version: u8, wire: &'a [u8]) -> Result<Self, Error> {
        let (msg_type, payload) = unpack(wire, version)?;
        if msg_type != MsgType::ResumptionHello {
            return Err(Error::ResumptionExpected);
        }
        if payload.len() < 34 + 32 + EK_LEN {
            return Err(Error::ResumptionShort);
        }
        let mut r = Reader(payload);
        let client_random = r.take()?;
        let ticket_len = usize::from(u16::from_be_bytes(*r.take::<2>()?));
        if payload.len() != 34 + ticket_len + 32 + EK_LEN {
            return Err(Error::ResumptionSize);
        }
        let (ticket, rest) = r.0.split_at(ticket_len);
        r.0 = rest;
        Ok(Self { client_random, ticket, x25519: r.take()?, mlkem_ek: r.take()? })
    }
}

/// `ResumptionAccept`, whose new session_id is chosen by the server.
#[derive(Debug, PartialEq, Eq)]
pub struct ResumptionAccept<'a> {
    pub server_random: &'a [u8; 32],
    pub session_id: &'a [u8; 32],
    pub x25519: &'a [u8; 32],
    pub ct: &'a [u8; CT_LEN],
    pub finished: &'a [u8; 32],
}

impl<'a> ResumptionAccept<'a> {
    pub const SIZE: usize = 1216;

    pub fn pack(&self, version: u8) -> Result<Vec<u8>, Error> {
        pack(version, MsgType::ResumptionAccept, &[self.server_random, self.session_id, self.x25519, self.ct, self.finished])
    }

    pub fn parse(version: u8, wire: &'a [u8]) -> Result<Self, Error> {
        let mut r = fixed(wire, version, MsgType::ResumptionAccept, Self::SIZE)?;
        Ok(Self { server_random: r.take()?, session_id: r.take()?, x25519: r.take()?, ct: r.take()?, finished: r.take()? })
    }

    /// What both sides hash: a header claiming 1216 bytes followed by only the 1184 bytes before the MAC.
    pub fn transcript_bytes(&self, version: u8) -> Vec<u8> {
        let mut out = pack(version, MsgType::ResumptionAccept, &[self.server_random, self.session_id, self.x25519, self.ct, self.finished])
            .expect("fixed-size message");
        out.truncate(HEADER_LEN + Self::SIZE - 32);
        out
    }
}

/// `unpack_cookie_challenge`, quirks kept: the version byte is not checked, trailing bytes are ignored, and a short
/// body yields a short cookie (which `cookie_response` then refuses).
pub fn parse_cookie_challenge(wire: &[u8]) -> Result<&[u8], Error> {
    let (header, body) = wire.split_first_chunk::<HEADER_LEN>().ok_or(Error::CookieShort)?;
    if header[..2] != MAGIC {
        return Err(Error::Magic);
    }
    if header[3] != MsgType::CookieChallenge as u8 {
        return Err(Error::CookieType);
    }
    if usize::from(u16::from_be_bytes([header[4], header[5]])) != COOKIE_LEN {
        return Err(Error::CookieLength);
    }
    Ok(&body[..body.len().min(COOKIE_LEN)])
}

/// `pack_cookie_response`: cookie ‖ the full ClientHello wire, header included.
pub fn cookie_response(version: u8, cookie: &[u8], client_hello: &[u8]) -> Result<Vec<u8>, Error> {
    if cookie.len() != COOKIE_LEN {
        return Err(Error::CookieSize);
    }
    let mut wire = Vec::with_capacity(HEADER_LEN + COOKIE_LEN + client_hello.len());
    wire.extend_from_slice(&MAGIC);
    wire.extend_from_slice(&[version, MsgType::CookieResponse as u8]);
    wire.extend_from_slice(&u16::try_from(COOKIE_LEN + client_hello.len()).map_err(|_| Error::PayloadLength)?.to_be_bytes());
    wire.extend_from_slice(cookie);
    wire.extend_from_slice(client_hello);
    Ok(wire)
}

/// `TranscriptHasher`: running SHA-256 over whole wire messages; `digest` does not consume it.
#[derive(Clone)]
pub struct Transcript(digest::Context);

impl Default for Transcript {
    fn default() -> Self {
        Self(digest::Context::new(&digest::SHA256))
    }
}

impl Transcript {
    pub fn update(&mut self, message: &[u8]) {
        self.0.update(message);
    }

    pub fn digest(&self) -> [u8; 32] {
        self.0.clone().finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
    }
}

/// `fingerprint()`: SHA-256 of a public key; the identity id on the wire.
pub fn fingerprint(public_key: &[u8]) -> [u8; 32] {
    crate::schedule::hash(&[public_key])
}

/// What the v2 client signs: PROTOCOL_NAME ‖ " client proof " ‖ transcript digest ‖ identity ciphertext.
pub fn client_proof(digest: &[u8; 32], identity_ct: &[u8; CT_LEN]) -> Vec<u8> {
    [PROTOCOL_NAME, b" client proof ", digest, identity_ct].concat()
}

pub fn x25519_public(private: &agreement::PrivateKey) -> Result<[u8; 32], Error> {
    private.compute_public_key().map_err(|_| Error::Crypto)?.as_ref().try_into().map_err(|_| Error::Crypto)
}

/// X25519 with the peer's raw key; aws-lc rejects the all-zero output of low-order points.
pub fn x25519(private: &agreement::PrivateKey, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    agreement::agree(private, agreement::UnparsedPublicKey::new(&agreement::X25519, peer), Error::PeerKey, |shared| {
        Ok(Zeroizing::new(shared.try_into().map_err(|_| Error::PeerKey)?))
    })
}

pub type DecapsulationKey = kem::DecapsulationKey<kem::AlgorithmId>;

/// Loads a 2400-byte ML-KEM-768 secret key in the liboqs / FIPS 203 expanded format.
pub fn mlkem_secret(secret_key: &[u8]) -> Result<DecapsulationKey, Error> {
    kem::DecapsulationKey::new(&kem::ML_KEM_768, secret_key).map_err(|_| Error::PeerKey)
}

/// ML-KEM-768 decapsulation; a tampered ciphertext gives FIPS 203's implicit-rejection secret, not an error.
pub fn decapsulate(key: &DecapsulationKey, ct: &[u8; CT_LEN]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let shared = key.decapsulate(kem::Ciphertext::from(&ct[..])).map_err(|_| Error::PeerKey)?;
    Ok(Zeroizing::new(shared.as_ref().try_into().map_err(|_| Error::Crypto)?))
}

/// The v2 client identity: a 32-byte Ed25519 seed, as `load_client_private` reads it.
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Error> {
    let pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| Error::Crypto)?;
    pair.sign(message).as_ref().try_into().map_err(|_| Error::Crypto)
}

pub fn ed25519_public(seed: &[u8; 32]) -> Result<[u8; 32], Error> {
    use signature::KeyPair;
    let pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| Error::Crypto)?;
    pair.public_key().as_ref().try_into().map_err(|_| Error::Crypto)
}

pub fn ed25519_verify(public: &[u8; 32], message: &[u8], signature_bytes: &[u8]) -> bool {
    signature::UnparsedPublicKey::new(&signature::ED25519, public).verify(message, signature_bytes).is_ok()
}

mod sealed {
    pub trait Sealed {}
}

/// Every randomized step of the handshake, rekey and rehandshake. The state machines are generic over this, so tests
/// can replay Python's recorded draws. Sealed: only `Os` (and the `cfg(test)` `Replay`) implement it, so no crate
/// linking pqvpn_core can inject randomness or KEM outputs.
pub trait Draws: sealed::Sealed {
    fn random(&mut self) -> Result<[u8; 32], Error>;
    fn x25519(&mut self) -> Result<agreement::PrivateKey, Error>;
    /// The key and its encapsulation key: aws-lc cannot derive the latter from an imported secret key.
    fn mlkem_keypair(&mut self) -> Result<(DecapsulationKey, Vec<u8>), Error>;
    fn encapsulate(&mut self, ek: &[u8; EK_LEN]) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>), Error>;
}

/// The operating system's randomness through aws-lc. Zero-sized.
pub struct Os;

impl sealed::Sealed for Os {}

impl Draws for Os {
    fn random(&mut self) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        rand::fill(&mut out).map_err(|_| Error::Crypto)?;
        Ok(out)
    }

    fn x25519(&mut self) -> Result<agreement::PrivateKey, Error> {
        agreement::PrivateKey::generate(&agreement::X25519).map_err(|_| Error::Crypto)
    }

    fn mlkem_keypair(&mut self) -> Result<(DecapsulationKey, Vec<u8>), Error> {
        let key = kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| Error::Crypto)?;
        let ek = key.encapsulation_key().and_then(|ek| ek.key_bytes()).map_err(|_| Error::Crypto)?.as_ref().to_vec();
        Ok((key, ek))
    }

    fn encapsulate(&mut self, ek: &[u8; EK_LEN]) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>), Error> {
        let key = kem::EncapsulationKey::new(&kem::ML_KEM_768, ek).map_err(|_| Error::PeerKey)?;
        let (ct, shared) = key.encapsulate().map_err(|_| Error::PeerKey)?;
        Ok((ct.as_ref().try_into().map_err(|_| Error::Crypto)?, Zeroizing::new(shared.as_ref().try_into().map_err(|_| Error::Crypto)?)))
    }
}

/// Test-only: replays one step's draws recorded by tests/test_handshake_vectors.py, checking kind and order.
#[cfg(test)]
pub(crate) struct Replay(std::collections::VecDeque<serde_json::Value>);

#[cfg(test)]
impl Replay {
    pub(crate) fn new(step: &serde_json::Value) -> Self {
        Self(step["draws"].as_array().expect("draws").iter().cloned().collect())
    }

    fn next(&mut self, kind: &str) -> serde_json::Value {
        let draw = self.0.pop_front().unwrap_or_else(|| panic!("Rust drew an extra {kind}"));
        assert_eq!(draw["kind"], kind, "draw order differs from Python");
        draw
    }

    /// Every recorded draw must have been used: Rust drawing less than Python is drift too.
    pub(crate) fn done(&self) {
        assert!(self.0.is_empty(), "{} recorded draws not consumed", self.0.len());
    }
}

#[cfg(test)]
pub(crate) fn unhex(value: &serde_json::Value) -> Vec<u8> {
    let s = value.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

#[cfg(test)]
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
impl sealed::Sealed for Replay {}

#[cfg(test)]
impl Draws for Replay {
    fn random(&mut self) -> Result<[u8; 32], Error> {
        Ok(unhex(&self.next("random")["value"]).try_into().expect("32-byte random"))
    }

    fn x25519(&mut self) -> Result<agreement::PrivateKey, Error> {
        agreement::PrivateKey::from_private_key(&agreement::X25519, &unhex(&self.next("x25519")["private"])).map_err(|_| Error::Crypto)
    }

    fn mlkem_keypair(&mut self) -> Result<(DecapsulationKey, Vec<u8>), Error> {
        let draw = self.next("mlkem_keypair");
        Ok((mlkem_secret(&unhex(&draw["sk"]))?, unhex(&draw["pk"])))
    }

    fn encapsulate(&mut self, ek: &[u8; EK_LEN]) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>), Error> {
        let draw = self.next("encapsulate");
        assert_eq!(unhex(&draw["ek_sha256"]), fingerprint(ek), "encapsulated to a different key than Python");
        Ok((unhex(&draw["ct"]).try_into().expect("ct"), Zeroizing::new(unhex(&draw["ss"]).try_into().expect("ss"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_v2_serialization_matches_python() {
        // test_frozen_v2_handshake_serialization in tests/test_crypto_protocol.py, byte for byte.
        let f = |b: u8, n: usize| vec![b; n];
        let (a, b, c, d, e) = (f(1, 32), f(2, 32), f(3, 32), f(4, EK_LEN), f(5, 32));
        let ch = ClientHello { client_random: (&a[..]).try_into().unwrap(), session_id: (&b[..]).try_into().unwrap(),
            x25519: (&c[..]).try_into().unwrap(), mlkem_ek: (&d[..]).try_into().unwrap(), client_identity: (&e[..]).try_into().unwrap() };
        let (g, h, i, j, k) = (f(6, 32), f(7, 32), f(8, 32), f(9, CT_LEN), f(10, 32));
        let sh = ServerHello { server_random: (&g[..]).try_into().unwrap(), session_id: (&h[..]).try_into().unwrap(),
            x25519: (&i[..]).try_into().unwrap(), eph_ct: (&j[..]).try_into().unwrap(), identity_id: (&k[..]).try_into().unwrap(), client_ct: None };
        let (l, m, n) = (f(11, CT_LEN), f(12, 64), f(13, 32));
        let cke = KeyExchange { ct: (&l[..]).try_into().unwrap(), signature: Some((&m[..]).try_into().unwrap()), finished: (&n[..]).try_into().unwrap() };
        let sf = pack_server_finished(Suite::V2, &[14; 32]).unwrap();
        let wires = [ch.pack(Suite::V2).unwrap(), sh.pack(Suite::V2).unwrap(), cke.pack(Suite::V2).unwrap(), sf];
        let expected = [
            (1318, "485620010520", "5cb01f9aa02ff578a960569d57c98eab1509b100e0ebf8c3a9d0db345b599a1a"),
            (1222, "4856200204c0", "3c3679256f04ee03a54f92eefd77074fe70347d727b54b46268cd6a7bc55b80f"),
            (1190, "4856200304a0", "b9a86d625f7354371b8c9219cbb8c4836346d25dccd2bdd1ab5901feb78785e5"),
            (38, "485620040020", "ffee0af94d03c49c9711872d9146d8bd2f0f8488d31e4c3a42ce6c4c2073dc0f"),
        ];
        for (wire, (len, header, digest)) in wires.iter().zip(expected) {
            assert_eq!((wire.len(), hex(&wire[..6]), hex(&fingerprint(wire))), (len, header.to_string(), digest.to_string()));
        }
        assert_eq!(ClientHello::parse(Suite::V2, &wires[0]).unwrap(), ch);
        assert_eq!(ServerHello::parse(Suite::V2, &wires[1]).unwrap(), sh);
        assert_eq!(KeyExchange::parse(Suite::V2, &wires[2]).unwrap(), cke);
    }

    #[test]
    fn mldsa_is_refused_and_unknown_versions_are_unsupported() {
        assert_eq!(Suite::from_version(0x31), Err(Error::MldsaUnsupported));
        assert_eq!(Suite::from_version(0x21), Err(Error::Version));
        assert_eq!(Suite::from_version(0x30), Ok(Suite::V3));
    }

    #[test]
    fn transcript_digest_does_not_consume() {
        let mut t = Transcript::default();
        assert_eq!(t.digest(), fingerprint(b""));
        t.update(b"a");
        let copy = t.clone();
        t.update(b"b");
        assert_eq!((t.digest(), copy.digest()), (fingerprint(b"ab"), fingerprint(b"a")));
    }

    #[test]
    fn cookie_response_layout_and_size() {
        let wire = cookie_response(0x20, &[7; 32], b"hello").unwrap();
        assert_eq!(&wire[..6], &[0x48, 0x56, 0x20, 6, 0, 37]);
        assert_eq!(cookie_response(0x20, &[7; 31], b"hello"), Err(Error::CookieSize));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// No decoder panics on arbitrary input, and anything a decoder accepts re-encodes to the same bytes.
        #[test]
        fn decoders_never_panic_and_roundtrip(body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2400),
                                              version in proptest::prop_oneof![proptest::strategy::Just(0x20u8), proptest::strategy::Just(0x30u8), proptest::prelude::any::<u8>()],
                                              msg_type in 0u8..10, exact in proptest::prelude::any::<bool>()) {
            let len = u16::try_from(body.len()).unwrap();
            let declared = if exact { len } else { len.wrapping_add(1) };
            let wire = [&[0x48, 0x56, version, msg_type][..], &declared.to_be_bytes(), &body].concat();
            for suite in [Suite::V2, Suite::V3] {
                if let Ok(m) = ClientHello::parse(suite, &wire) { proptest::prop_assert_eq!(m.pack(suite).unwrap(), wire.clone()); }
                if let Ok(m) = ServerHello::parse(suite, &wire) { proptest::prop_assert_eq!(m.pack(suite).unwrap(), wire.clone()); }
                if let Ok(m) = KeyExchange::parse(suite, &wire) { proptest::prop_assert_eq!(m.pack(suite).unwrap(), wire.clone()); }
                if let Ok(f) = parse_server_finished(suite, &wire) { proptest::prop_assert_eq!(pack_server_finished(suite, f).unwrap(), wire.clone()); }
                if let Ok(m) = ResumptionHello::parse(suite.version(), &wire) { proptest::prop_assert_eq!(m.pack(suite.version()).unwrap(), wire.clone()); }
                if let Ok(m) = ResumptionAccept::parse(suite.version(), &wire) { proptest::prop_assert_eq!(m.pack(suite.version()).unwrap(), wire.clone()); }
            }
            let _ = parse_cookie_challenge(&wire);
            let _ = parse_cookie_challenge(&body);
        }
    }
}

/// Byte-for-byte replay of tests/vectors/handshake.json (recorded by tests/test_handshake_vectors.py). Until the
/// state machines land, each step is composed here from the codecs, schedule and control channel, in Python's order.
#[cfg(test)]
mod vectors {
    use super::*;
    use crate::schedule::{self, CLIENT_FINISHED, RESUME_FINISHED, Randoms, SERVER_FINISHED, Secrets};
    use crate::session::{ControlChannel, Role};
    use serde_json::Value;

    const CONFIG: &[u8] = br#"{"client_vpn_ip": "10.8.0.2", "vector": true}"#;

    fn file() -> Value {
        serde_json::from_str(include_str!("../../../tests/vectors/handshake.json")).unwrap()
    }

    fn arr<const N: usize>(value: &Value) -> [u8; N] {
        unhex(value).try_into().unwrap()
    }

    fn step<'a>(run: &'a Value, name: &str) -> &'a Value {
        run["steps"].as_array().unwrap().iter().find(|s| s["name"] == name).unwrap()
    }

    fn wire(run: &Value, name: &str) -> Vec<u8> {
        unhex(&step(run, name)["wire"])
    }

    fn assert_secrets(s: &Secrets, expected: &Value, what: &str) {
        let fields: [(&str, &[u8]); 12] = [
            ("client_finished_key", &s.client_finished[..]), ("server_finished_key", &s.server_finished[..]),
            ("data_c2s_key", &s.data_c2s_key[..]), ("data_s2c_key", &s.data_s2c_key[..]),
            ("data_c2s_nonce_base", &s.data_c2s_nonce[..]), ("data_s2c_nonce_base", &s.data_s2c_nonce[..]),
            ("control_c2s_key", &s.control_c2s_key[..]), ("control_s2c_key", &s.control_s2c_key[..]),
            ("control_c2s_nonce_base", &s.control_c2s_nonce[..]), ("control_s2c_nonce_base", &s.control_s2c_nonce[..]),
            ("rekey_secret", &s.rekey[..]), ("control_confirm_key", &s.control_confirm[..]),
        ];
        for (name, value) in fields {
            assert_eq!(hex(value), expected[name].as_str().unwrap(), "{what}: {name}");
        }
    }

    fn control(role: Role, s: &Secrets, sid: &[u8; 32], version: u8, epoch: u32) -> ControlChannel {
        let (c2s, s2c) = ((&s.control_c2s_key[..], &s.control_c2s_nonce[..]), (&s.control_s2c_key[..], &s.control_s2c_nonce[..]));
        let ((sk, sn), (rk, rn)) = if role == Role::Client { (c2s, s2c) } else { (s2c, c2s) };
        ControlChannel::new(role, sid, version, epoch, sk, sn, rk, rn).unwrap()
    }

    fn full_run(run: &Value, ids: &Value) {
        let suite = Suite::from_version(u8::try_from(run["version"].as_u64().unwrap()).unwrap()).unwrap();
        let server_pk = unhex(&ids["server_kem_pk"]);
        let server_dk = mlkem_secret(&unhex(&ids["server_kem_sk"])).unwrap();
        let client_pk = unhex(&ids["client_kem_pk"]);
        let client_dk = mlkem_secret(&unhex(&ids["client_kem_sk"])).unwrap();
        let seed: [u8; 32] = arr(&ids["client_ed25519"]);
        let client_identity = if suite == Suite::V2 { ed25519_public(&seed).unwrap() } else { fingerprint(&client_pk) };

        let mut d = Replay::new(step(run, "client_hello"));
        let c_x = d.x25519().unwrap();
        let (c_dk, c_ek) = d.mlkem_keypair().unwrap();
        let (cr, sid) = (d.random().unwrap(), d.random().unwrap());
        d.done();
        let ch = ClientHello { client_random: &cr, session_id: &sid, x25519: &x25519_public(&c_x).unwrap(),
                               mlkem_ek: c_ek[..].try_into().unwrap(), client_identity: &client_identity }.pack(suite).unwrap();
        assert_eq!(ch, wire(run, "client_hello"));

        let hello = ClientHello::parse(suite, &ch).unwrap();
        let mut d = Replay::new(step(run, "server_hello"));
        let s_x = d.x25519().unwrap();
        let sr = d.random().unwrap();
        let (eph_ct, s_k_eph) = d.encapsulate(hello.mlkem_ek).unwrap();
        let client_static = (suite == Suite::V3).then(|| d.encapsulate(client_pk[..].try_into().unwrap()).unwrap());
        d.done();
        let identity_id = fingerprint(&server_pk);
        let sh = ServerHello { server_random: &sr, session_id: hello.session_id, x25519: &x25519_public(&s_x).unwrap(), eph_ct: &eph_ct,
                               identity_id: &identity_id, client_ct: client_static.as_ref().map(|(ct, _)| ct) }.pack(suite).unwrap();
        assert_eq!(sh, wire(run, "server_hello"));
        let s_xss = x25519(&s_x, hello.x25519).unwrap();
        let digest = fingerprint(&[&ch[..], &sh].concat());
        assert_eq!(digest, arr::<32>(&run["transcript_hash"]));

        let reply = ServerHello::parse(suite, &sh).unwrap();
        assert_eq!(reply.identity_id, &identity_id);
        let c_xss = x25519(&c_x, reply.x25519).unwrap();
        let c_k_eph = decapsulate(&c_dk, reply.eph_ct).unwrap();
        let mut d = Replay::new(step(run, "client_key_exchange"));
        let (identity_ct, c_k_s) = d.encapsulate(server_pk[..].try_into().unwrap()).unwrap();
        d.done();
        let r = Randoms { client_random: &cr, server_random: reply.server_random, session_id: &sid, transcript_hash: &digest };
        let (client_secrets, signature) = match suite {
            Suite::V2 => (schedule::v2(&r, &c_xss, &c_k_eph, &c_k_s), Some(ed25519_sign(&seed, &client_proof(&digest, &identity_ct)).unwrap())),
            Suite::V3 => {
                let c_k_c = decapsulate(&client_dk, reply.client_ct.unwrap()).unwrap();
                (schedule::v3(&r, &c_xss, &c_k_eph, &c_k_s, &c_k_c), None)
            }
        };
        let partial = [&identity_ct[..], signature.as_ref().map_or(&[][..], |s| &s[..])].concat();
        let finished = schedule::finished(&client_secrets.client_finished, CLIENT_FINISHED, &schedule::hash(&[&digest, &partial]));
        let cke = KeyExchange { ct: &identity_ct, signature: signature.as_ref(), finished: &finished }.pack(suite).unwrap();
        assert_eq!(cke, wire(run, "client_key_exchange"));

        let exchange = KeyExchange::parse(suite, &cke).unwrap();
        let s_k_s = decapsulate(&server_dk, exchange.ct).unwrap();
        let r = Randoms { client_random: hello.client_random, server_random: &sr, session_id: hello.session_id, transcript_hash: &digest };
        let server_secrets = match &client_static {
            None => schedule::v2(&r, &s_xss, &s_k_eph, &s_k_s),
            Some((_, s_k_c)) => schedule::v3(&r, &s_xss, &s_k_eph, &s_k_s, s_k_c),
        };
        if let Some(sig) = exchange.signature {
            assert!(ed25519_verify(hello.client_identity, &client_proof(&digest, exchange.ct), sig));
        }
        let partial = [&exchange.ct[..], exchange.signature.map_or(&[][..], |s| &s[..])].concat();
        assert!(schedule::verify_finished(&server_secrets.client_finished, CLIENT_FINISHED, &schedule::hash(&[&digest, &partial]), exchange.finished));
        let mut transcript = Transcript::default();
        [&ch, &sh, &cke].iter().for_each(|m| transcript.update(m));
        let sf = pack_server_finished(suite, &schedule::finished(&server_secrets.server_finished, SERVER_FINISHED, &transcript.digest())).unwrap();
        Replay::new(step(run, "server_finished")).done();
        assert_eq!(sf, wire(run, "server_finished"));
        assert!(schedule::verify_finished(&client_secrets.server_finished, SERVER_FINISHED, &transcript.digest(),
                                          parse_server_finished(suite, &sf).unwrap()));
        assert_secrets(&client_secrets, &run["secrets"]["0"], "client epoch 0");
        assert_secrets(&server_secrets, &run["secrets"]["0"], "server epoch 0");
        epochs(run, suite.version(), &sid, &client_secrets, &server_secrets);
    }

    /// CONFIG and friends on the control channel, then the rekey to epoch 1 and the rehandshake to epoch 2.
    fn epochs(run: &Value, version: u8, sid: &[u8; 32], c0: &Secrets, s0: &Secrets) {
        let (cc, sc) = (control(Role::Client, c0, sid, version, 0), control(Role::Server, s0, sid, version, 0));
        let expected = &run["control"];
        let config = sc.seal(7, CONFIG).unwrap();
        assert_eq!(hex(&config), expected["config"]);
        assert_eq!(cc.open(&config, Some(7)).unwrap(), (7, CONFIG.to_vec()));
        let error = cc.seal(10, b"client says hi").unwrap();
        assert_eq!(hex(&error), expected["client_error"]);
        assert_eq!(sc.open(&error, None).unwrap().1, b"client says hi");
        let second = sc.seal(6, b"").unwrap();
        assert_eq!(hex(&second), expected["second"]);
        assert_eq!(cc.open(&second, None).unwrap(), (6, vec![]));

        let mut d = Replay::new(step(run, "rekey_request"));
        let nonce = d.random().unwrap();
        d.done();
        let request = [&1u32.to_be_bytes()[..], &nonce].concat();
        let c1 = schedule::next_epoch(&c0.rekey, sid, 1, &nonce);
        let frame = cc.seal(8, &request).unwrap();
        assert_eq!(frame, wire(run, "rekey_request"));
        let (_, payload) = sc.open(&frame, Some(8)).unwrap();
        let s1 = schedule::next_epoch(&s0.rekey, sid, u32::from_be_bytes(payload[..4].try_into().unwrap()), payload[4..].try_into().unwrap());
        let confirmation = schedule::rekey_confirmation(&s0.control_confirm, &payload);
        let frame = sc.seal(9, &[&payload[..4], &confirmation].concat()).unwrap();
        Replay::new(step(run, "rekey_response")).done();
        assert_eq!(frame, wire(run, "rekey_response"));
        let (_, response) = cc.open(&frame, Some(9)).unwrap();
        assert_eq!(response[..4], request[..4]);
        assert!(schedule::verify_rekey_confirmation(&c0.control_confirm, &request, &response[4..]));
        assert!(!schedule::verify_rekey_confirmation(&c1.control_confirm, &request, &response[4..]), "rekey confirms under the OLD key");
        assert_secrets(&c1, &run["secrets"]["1"], "client epoch 1");
        assert_secrets(&s1, &run["secrets"]["1"], "server epoch 1");

        let (cc, sc) = (control(Role::Client, &c1, sid, version, 1), control(Role::Server, &s1, sid, version, 1));
        let mut d = Replay::new(step(run, "rehandshake_request"));
        let x = d.x25519().unwrap();
        let (dk, ek) = d.mlkem_keypair().unwrap();
        d.done();
        let request = [&2u32.to_be_bytes()[..], &x25519_public(&x).unwrap(), &ek].concat();
        let frame = cc.seal(11, &request).unwrap();
        assert_eq!(frame, wire(run, "rehandshake_request"));
        let (_, payload) = sc.open(&frame, Some(11)).unwrap();
        assert_eq!(payload.len(), 4 + 32 + EK_LEN);
        let mut d = Replay::new(step(run, "rehandshake_response"));
        let sx = d.x25519().unwrap();
        let dh = x25519(&sx, payload[4..36].try_into().unwrap()).unwrap();
        let (ct, kem) = d.encapsulate(payload[36..].try_into().unwrap()).unwrap();
        d.done();
        let body = [&2u32.to_be_bytes()[..], &x25519_public(&sx).unwrap(), &ct].concat();
        let transcript = [&payload[..], &body].concat();
        let s2 = schedule::rehandshake_epoch(&s1.rekey, sid, 2, &dh, &kem, &transcript).unwrap();
        let frame = sc.seal(12, &[&body[..], &schedule::rehandshake_confirmation(&s2.control_confirm, &transcript)].concat()).unwrap();
        assert_eq!(frame, wire(run, "rehandshake_response"));
        let (_, response) = cc.open(&frame, Some(12)).unwrap();
        let (body, confirmation) = response.split_at(4 + 32 + CT_LEN);
        let dh = x25519(&x, body[4..36].try_into().unwrap()).unwrap();
        let kem = decapsulate(&dk, body[36..].try_into().unwrap()).unwrap();
        let transcript = [&request[..], body].concat();
        let c2 = schedule::rehandshake_epoch(&c1.rekey, sid, 2, &dh, &kem, &transcript).unwrap();
        assert!(schedule::verify_rehandshake_confirmation(&c2.control_confirm, &transcript, confirmation));
        assert!(!schedule::verify_rehandshake_confirmation(&c1.control_confirm, &transcript, confirmation), "rehandshake confirms under the NEW key");
        assert_secrets(&c2, &run["secrets"]["2"], "client epoch 2");
        assert_secrets(&s2, &run["secrets"]["2"], "server epoch 2");
    }

    fn resume_run(run: &Value) {
        let version = u8::try_from(run["version"].as_u64().unwrap()).unwrap();
        let secret: [u8; 32] = arr(&run["resumption_secret"]);
        let ticket = unhex(&run["ticket"]);

        let mut d = Replay::new(step(run, "resumption_hello"));
        let x = d.x25519().unwrap();
        let (dk, ek) = d.mlkem_keypair().unwrap();
        let cr = d.random().unwrap();
        d.done();
        let hello = ResumptionHello { client_random: &cr, ticket: &ticket, x25519: &x25519_public(&x).unwrap(),
                                      mlkem_ek: ek[..].try_into().unwrap() }.pack(version).unwrap();
        assert_eq!(hello, wire(run, "resumption_hello"));

        let parsed = ResumptionHello::parse(version, &hello).unwrap();
        assert_eq!(parsed.ticket, &ticket[..]);
        let mut d = Replay::new(step(run, "resumption_accept"));
        let (sr, sid) = (d.random().unwrap(), d.random().unwrap());
        let sx = d.x25519().unwrap();
        let (ct, kem) = d.encapsulate(parsed.mlkem_ek).unwrap();
        d.done();
        let server_x = x25519_public(&sx).unwrap();
        let unmacced = ResumptionAccept { server_random: &sr, session_id: &sid, x25519: &server_x, ct: &ct, finished: &[0; 32] }.transcript_bytes(version);
        assert_eq!(u16::from_be_bytes([unmacced[4], unmacced[5]]), 1216, "the hashed header claims the full 1216 bytes");
        assert_eq!(unmacced.len(), HEADER_LEN + 1184);
        let mut transcript = Transcript::default();
        transcript.update(&hello);
        transcript.update(&unmacced);
        let digest = transcript.digest();
        let r = Randoms { client_random: parsed.client_random, server_random: &sr, session_id: &sid, transcript_hash: &digest };
        let server_secrets = schedule::resume(&r, &secret, &x25519(&sx, parsed.x25519).unwrap(), &kem);
        let finished = schedule::finished(&server_secrets.server_finished, RESUME_FINISHED, &digest);
        let accept = ResumptionAccept { server_random: &sr, session_id: &sid, x25519: &server_x, ct: &ct, finished: &finished }.pack(version).unwrap();
        assert_eq!(accept, wire(run, "resumption_accept"));

        let a = ResumptionAccept::parse(version, &accept).unwrap();
        let mut transcript = Transcript::default();
        transcript.update(&hello);
        transcript.update(&accept[..HEADER_LEN + 1184]);
        assert_eq!(transcript.digest(), digest);
        let r = Randoms { client_random: &cr, server_random: a.server_random, session_id: a.session_id, transcript_hash: &digest };
        let client_secrets = schedule::resume(&r, &secret, &x25519(&x, a.x25519).unwrap(), &decapsulate(&dk, a.ct).unwrap());
        assert!(schedule::verify_finished(&client_secrets.server_finished, RESUME_FINISHED, &digest, a.finished));
        assert_secrets(&client_secrets, &run["secrets"]["0"], "client resumed");
        assert_secrets(&server_secrets, &run["secrets"]["0"], "server resumed");
    }

    #[test]
    fn full_handshakes_rekey_and_rehandshake_match_python() {
        let v = file();
        let runs: Vec<_> = v["runs"].as_array().unwrap().iter().filter(|r| r["name"] == "v2" || r["name"] == "v3").collect();
        assert_eq!(runs.len(), 2);
        runs.iter().for_each(|run| full_run(run, &v["identities"]));
    }

    #[test]
    fn resumptions_match_python() {
        let v = file();
        let runs: Vec<_> = v["runs"].as_array().unwrap().iter().filter(|r| r["name"].as_str().unwrap().starts_with("resume-")).collect();
        assert_eq!(runs.len(), 2);
        runs.iter().for_each(|run| resume_run(run));
    }

    #[test]
    fn liboqs_decapsulation_kat_including_implicit_rejection() {
        let v = file();
        let kats = v["kem_kat"].as_array().unwrap();
        assert_eq!(kats.len(), 2);
        for kat in kats {
            let key = mlkem_secret(&unhex(&kat["sk"])).unwrap();
            assert_eq!(hex(&decapsulate(&key, &arr(&kat["ct"])).unwrap()[..]), kat["ss"], "{}", kat["name"]);
        }
    }

    #[test]
    fn codec_rejections_match_python() {
        let v = file();
        let cases = v["codec_rejections"].as_array().unwrap();
        assert!(cases.len() > 100);
        for case in cases {
            let wire = unhex(&case["wire"]);
            let version = u8::try_from(case["version"].as_u64().unwrap()).unwrap();
            let suite = || Suite::from_version(version).unwrap();
            let got = match case["parser"].as_str().unwrap() {
                "client_hello" => ClientHello::parse(suite(), &wire).map(|_| "ok".to_string()),
                "server_hello" => ServerHello::parse(suite(), &wire).map(|_| "ok".to_string()),
                "client_key_exchange" => KeyExchange::parse(suite(), &wire).map(|_| "ok".to_string()),
                "server_finished" => parse_server_finished(suite(), &wire).map(|_| "ok".to_string()),
                "resumption_hello" => ResumptionHello::parse(version, &wire).map(|_| "ok".to_string()),
                "resumption_accept" => ResumptionAccept::parse(version, &wire).map(|_| "ok".to_string()),
                "cookie_challenge" => parse_cookie_challenge(&wire).map(|c| format!("ok:{}", hex(c))),
                other => panic!("unknown parser {other}"),
            };
            assert_eq!(got.unwrap_or_else(Error::message), case["result"].as_str().unwrap(), "{} {}", case["parser"], case["mutation"]);
        }
    }

    /// Rust may reject more than Python (still failing closed), never less. Stricter cases are printed for the PR.
    #[test]
    fn primitive_rejections_are_at_least_as_strict_as_python() {
        let v = file();
        let p = &v["primitive_rejections"];
        let private = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        for case in p["x25519"].as_array().unwrap() {
            let rust_ok = x25519(&private, &arr(&case["point"])).is_ok();
            assert!(case["result"] != "error" || !rust_ok, "Python rejects X25519 point {} but Rust accepts it", case["point"]);
            if case["result"] == "ok" && !rust_ok {
                eprintln!("stricter than Python: X25519 point {}", case["point"]);
            }
        }
        for case in p["mlkem_encapsulation_key"].as_array().unwrap() {
            let rust_ok = Os.encapsulate(&arr(&case["ek"])).is_ok();
            assert_eq!(rust_ok, case["result"] == "ok", "ML-KEM encapsulation key {}", case["name"]);
        }
        for case in p["ed25519"].as_array().unwrap() {
            let rust_ok = ed25519_verify(&arr(&case["public"]), &unhex(&case["message"]), &unhex(&case["signature"]));
            assert_eq!(rust_ok, case["result"] == "ok", "Ed25519 {}", case["name"]);
        }
    }

    #[test]
    fn os_draws_roundtrip() {
        let (key, ek) = Os.mlkem_keypair().unwrap();
        let (ct, shared) = Os.encapsulate(ek[..].try_into().unwrap()).unwrap();
        assert_eq!(decapsulate(&key, &ct).unwrap(), shared);
        assert_ne!(Os.random().unwrap(), Os.random().unwrap());
        let (a, b) = (Os.x25519().unwrap(), Os.x25519().unwrap());
        assert_eq!(x25519(&a, &x25519_public(&b).unwrap()).unwrap(), x25519(&b, &x25519_public(&a).unwrap()).unwrap());
    }
}
