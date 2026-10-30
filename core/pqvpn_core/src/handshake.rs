//! KEMTLS handshake messages, transcript and primitives, mirroring handshake/kemtls.py for v2 (0x20), v3-kem (0x30)
//! and resumption. v3-mldsa (0x31) is not ported: `Suite::from_version` refuses it. No I/O and no state machine yet.
//! Every random draw goes through `Draws`, whose only non-test implementation is `Os`.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::{agreement, constant_time, digest, kem, rand, signature};
use nix::libc;
use zeroize::Zeroizing;

use crate::schedule::{self, CLIENT_FINISHED, PROTOCOL_NAME, RESUME_FINISHED, Randoms, SERVER_FINISHED, Secrets};
use crate::session::{self, ControlChannel, Role};

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
    State(&'static str),
    SessionIdMismatch,
    Substitution,
    Fingerprint,
    Identity,
    Unauthorized,
    StoreKey,
    ClientHash,
    ClientProof,
    ClientFinished,
    ServerFinished,
    Ticket,
    TicketVersion,
    ResumeFinished,
    Busy,
    NoPending,
    Role,
    RekeyRequest,
    RekeyEpoch,
    RekeyConfirm,
    RehandshakeRequest,
    RehandshakeEpoch,
    RehandshakeLength,
    RehandshakeMismatch,
    RehandshakeConfirm,
    /// A record-layer rejection; `message` gives its kind, which Python maps through `_RUST_REJECTIONS`.
    Record(session::Error),
}

impl From<session::Error> for Error {
    fn from(error: session::Error) -> Self {
        Error::Record(error)
    }
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
            Error::State(message) => message.into(),
            Error::SessionIdMismatch => "Session ID mismatch".into(),
            Error::Substitution => "server identity substitution detected".into(),
            Error::Fingerprint => "server identity fingerprint mismatch".into(),
            Error::Identity => "invalid ML-KEM-768 or Ed25519 identity key".into(),
            Error::Unauthorized => "unauthorized client".into(),
            Error::StoreKey => "invalid client ML-KEM public key in store".into(),
            Error::ClientHash => "client identity hash mismatch".into(),
            Error::ClientProof => "client identity proof failed".into(),
            Error::ClientFinished => "Client Finished MAC verification failed".into(),
            Error::ServerFinished => "Server Finished MAC verification failed".into(),
            Error::Ticket => "invalid or expired resumption ticket".into(),
            Error::TicketVersion => "resumption ticket protocol version mismatch".into(),
            Error::ResumeFinished => "resumption finished MAC failed".into(),
            Error::Busy => "rekey/rehandshake already in progress".into(),
            Error::NoPending => "no rekey or rehandshake in progress".into(),
            Error::Role => "operation not valid for this session role".into(),
            Error::RekeyRequest => "invalid rekey request".into(),
            Error::RekeyEpoch => "invalid rekey epoch or nonce".into(),
            Error::RekeyConfirm => "invalid rekey confirmation".into(),
            Error::RehandshakeRequest => "invalid rehandshake request".into(),
            Error::RehandshakeEpoch => "invalid rehandshake epoch".into(),
            Error::RehandshakeLength => "invalid rehandshake response length".into(),
            Error::RehandshakeMismatch => "rehandshake epoch mismatch".into(),
            Error::RehandshakeConfirm => "rehandshake key confirmation failed".into(),
            Error::Record(error) => error.as_str().into(),
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
    /// `os.urandom(len(out))`.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;
    fn random(&mut self) -> Result<[u8; 32], Error> {
        let mut out = [0u8; 32];
        self.fill(&mut out)?;
        Ok(out)
    }
    fn x25519(&mut self) -> Result<agreement::PrivateKey, Error>;
    /// The key and its encapsulation key: aws-lc cannot derive the latter from an imported secret key.
    fn mlkem_keypair(&mut self) -> Result<(DecapsulationKey, Vec<u8>), Error>;
    fn encapsulate(&mut self, ek: &[u8; EK_LEN]) -> Result<([u8; CT_LEN], Zeroizing<[u8; 32]>), Error>;
}

/// The operating system's randomness through aws-lc. Zero-sized.
pub struct Os;

impl sealed::Sealed for Os {}

impl Draws for Os {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        rand::fill(out).map_err(|_| Error::Crypto)
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

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

const RESUMPTION_AAD: &[u8] = b"PQVPN-RESUME";
const PRIVATE_FILE_MODES: [u32; 2] = [0o600, 0o400];
/// The ticket file is under 1 KB; anything far larger is not ours.
const MAX_TICKET_FILE: u64 = 64 * 1024;

/// `read_private`: no symlinks, a regular file, mode 0600 or 0400, checked on the inode that is read.
pub fn read_private(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || !PRIVATE_FILE_MODES.contains(&(meta.permissions().mode() & 0o7777)) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "private identity must be a regular file with mode 0600 (or 0400)"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0)));
    file.read_to_end(&mut out)?;
    Ok(out)
}

/// A long-term identity, loaded once and shared by every handshake that uses it.
pub enum Identity {
    /// The v2 client: a 32-byte Ed25519 seed, as `load_client_private` reads it.
    Ed25519 { seed: Zeroizing<[u8; 32]>, public: [u8; 32] },
    /// A server identity or a v3 client static key, liboqs / FIPS 203 format.
    Kem { key: DecapsulationKey, public: Box<[u8; EK_LEN]> },
}

impl Identity {
    pub fn ed25519(seed: &[u8]) -> Result<Self, Error> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed.try_into().map_err(|_| Error::Identity)?);
        let public = ed25519_public(&seed)?;
        Ok(Identity::Ed25519 { seed, public })
    }

    /// Like `validate_server_identity`: the secret must decapsulate what its public key encapsulates.
    pub fn kem(secret: &[u8], public: &[u8]) -> Result<Self, Error> {
        let public: Box<[u8; EK_LEN]> = Box::new(public.try_into().map_err(|_| Error::Identity)?);
        if secret.len() != 2400 {
            return Err(Error::Identity);
        }
        let key = mlkem_secret(secret).map_err(|_| Error::Identity)?;
        let (ct, expected) = Os.encapsulate(&public).map_err(|_| Error::Identity)?;
        if !ct_eq(&decapsulate(&key, &ct)?[..], &expected[..]) {
            return Err(Error::Identity);
        }
        Ok(Identity::Kem { key, public })
    }

    fn kem_parts(&self) -> Result<(&DecapsulationKey, &[u8; EK_LEN]), Error> {
        match self {
            Identity::Kem { key, public } => Ok((key, public)),
            Identity::Ed25519 { .. } => Err(Error::Identity),
        }
    }
}

/// One session after its handshake: all 12 secrets of the current epoch, the control channel, and the data channel
/// that the data plane shares. Nothing secret is readable from outside the crate.
pub struct Established {
    role: Role,
    version: u8,
    session_id: [u8; 32],
    epoch: u32,
    secrets: Box<Secrets>,
    control: ControlChannel,
    data: Arc<session::Session>,
    pending: Option<Pending>,
}

/// A client's epoch change between its request and the server's confirmation.
enum Pending {
    Rekey { epoch: u32, request: Vec<u8>, next: Box<Secrets> },
    Rehandshake { epoch: u32, request: Vec<u8>, x25519: agreement::PrivateKey, key: DecapsulationKey },
}

type Directional<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

fn data_keys(role: Role, s: &Secrets) -> Directional<'_> {
    let (c2s, s2c) = ((&s.data_c2s_key[..], &s.data_c2s_nonce[..]), (&s.data_s2c_key[..], &s.data_s2c_nonce[..]));
    let ((sk, sn), (rk, rn)) = if role == Role::Client { (c2s, s2c) } else { (s2c, c2s) };
    (sk, sn, rk, rn)
}

fn control_channel(role: Role, s: &Secrets, sid: &[u8; 32], version: u8, epoch: u32) -> Result<ControlChannel, Error> {
    let (c2s, s2c) = ((&s.control_c2s_key[..], &s.control_c2s_nonce[..]), (&s.control_s2c_key[..], &s.control_s2c_nonce[..]));
    let ((sk, sn), (rk, rn)) = if role == Role::Client { (c2s, s2c) } else { (s2c, c2s) };
    Ok(ControlChannel::new(role, sid, version, epoch, sk, sn, rk, rn)?)
}

const REKEY_REQUEST: u8 = 8;
const REKEY_RESPONSE: u8 = 9;
const REHANDSHAKE_REQUEST: u8 = 11;
const REHANDSHAKE_RESPONSE: u8 = 12;
const REHANDSHAKE_REQUEST_LEN: usize = 4 + 32 + EK_LEN;
const REHANDSHAKE_BODY_LEN: usize = 4 + 32 + CT_LEN;

impl Established {
    fn new(role: Role, version: u8, session_id: [u8; 32], secrets: Box<Secrets>) -> Result<Self, Error> {
        let (sk, sn, rk, rn) = data_keys(role, &secrets);
        let data = Arc::new(session::Session::new(role, &session_id, version, 0, sk, sn, rk, rn)?);
        let control = control_channel(role, &secrets, &session_id, version, 0)?;
        Ok(Self { role, version, session_id, epoch: 0, secrets, control, data, pending: None })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The data channel, shared with the data plane: one sealer per data key.
    pub fn data(&self) -> Arc<session::Session> {
        self.data.clone()
    }

    pub fn seal_control(&self, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.control.seal(frame_type, payload)?)
    }

    pub fn open_control(&self, frame: &[u8], expected: Option<u8>) -> Result<(u8, Vec<u8>), Error> {
        Ok(self.control.open(frame, expected)?)
    }

    /// `activate_epoch`: data and control switch together; the old epoch's secrets are wiped on drop.
    fn activate(&mut self, epoch: u32, secrets: Box<Secrets>) -> Result<(), Error> {
        let (sk, sn, rk, rn) = data_keys(self.role, &secrets);
        self.data.rekey(epoch, sk, sn, rk, rn)?;
        self.control = control_channel(self.role, &secrets, &self.session_id, self.version, epoch)?;
        self.secrets = secrets;
        self.epoch = epoch;
        Ok(())
    }

    fn next_epoch(&self) -> Result<u32, Error> {
        self.epoch.checked_add(1).ok_or(Error::Record(session::Error::Epoch))
    }

    fn client(&self) -> Result<(), Error> {
        if self.role != Role::Client {
            return Err(Error::Role);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        Ok(())
    }

    /// Client: the sealed REKEY_REQUEST (epoch ‖ nonce). The next epoch is derived now and held until confirmed.
    pub fn begin_rekey<D: Draws>(&mut self, d: &mut D) -> Result<Vec<u8>, Error> {
        self.client()?;
        let epoch = self.next_epoch()?;
        let nonce = d.random()?;
        let request = [&epoch.to_be_bytes()[..], &nonce].concat();
        let next = schedule::next_epoch(&self.secrets.rekey, &self.session_id, epoch, &nonce);
        let frame = self.seal_control(REKEY_REQUEST, &request)?;
        self.pending = Some(Pending::Rekey { epoch, request, next });
        Ok(frame)
    }

    /// Client: checks the REKEY_RESPONSE plaintext against the **old** confirm key, then activates.
    pub fn finish_rekey(&mut self, response: &[u8]) -> Result<(), Error> {
        let Some(Pending::Rekey { epoch, request, next }) = self.pending.take() else { return Err(Error::NoPending) };
        if response.len() < 4 || response[..4] != request[..4]
            || !schedule::verify_rekey_confirmation(&self.secrets.control_confirm, &request, &response[4..]) {
            return Err(Error::RekeyConfirm);
        }
        self.activate(epoch, next)
    }

    /// Server: derives the next epoch, seals the confirmation under the old keys, then activates.
    pub fn respond_rekey(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        if self.role != Role::Server {
            return Err(Error::Role);
        }
        if request.len() != 36 {
            return Err(Error::RekeyRequest);
        }
        let epoch = u32::from_be_bytes(request[..4].try_into().map_err(|_| Error::RekeyRequest)?);
        if Some(epoch) != self.epoch.checked_add(1) {
            return Err(Error::RekeyEpoch);
        }
        let next = schedule::next_epoch(&self.secrets.rekey, &self.session_id, epoch, request[4..].try_into().map_err(|_| Error::RekeyRequest)?);
        let confirmation = schedule::rekey_confirmation(&self.secrets.control_confirm, request);
        let frame = self.seal_control(REKEY_RESPONSE, &[&request[..4], &confirmation].concat())?;
        self.activate(epoch, next)?;
        Ok(frame)
    }

    /// Client: the sealed REHANDSHAKE_REQUEST (epoch ‖ X25519 ‖ ML-KEM key), fresh ephemeral keys held until the reply.
    pub fn begin_rehandshake<D: Draws>(&mut self, d: &mut D) -> Result<Vec<u8>, Error> {
        self.client()?;
        let epoch = self.next_epoch()?;
        let x25519 = d.x25519()?;
        let (key, ek) = d.mlkem_keypair()?;
        let request = [&epoch.to_be_bytes()[..], &x25519_public(&x25519)?, &ek].concat();
        let frame = self.seal_control(REHANDSHAKE_REQUEST, &request)?;
        self.pending = Some(Pending::Rehandshake { epoch, request, x25519, key });
        Ok(frame)
    }

    /// Client: checks the REHANDSHAKE_RESPONSE plaintext against the **new** confirm key, then activates.
    pub fn finish_rehandshake(&mut self, response: &[u8]) -> Result<(), Error> {
        let Some(Pending::Rehandshake { epoch, request, x25519: x, key }) = self.pending.take() else { return Err(Error::NoPending) };
        if response.len() != REHANDSHAKE_BODY_LEN + 32 {
            return Err(Error::RehandshakeLength);
        }
        let (body, confirmation) = response.split_at(REHANDSHAKE_BODY_LEN);
        if body[..4] != epoch.to_be_bytes() {
            return Err(Error::RehandshakeMismatch);
        }
        let dh = x25519(&x, body[4..36].try_into().map_err(|_| Error::RehandshakeLength)?)?;
        let kem = decapsulate(&key, body[36..].try_into().map_err(|_| Error::RehandshakeLength)?)?;
        let transcript = [&request[..], body].concat();
        let next = schedule::rehandshake_epoch(&self.secrets.rekey, &self.session_id, epoch, &dh, &kem, &transcript)
            .ok_or(Error::RehandshakeRequest)?;
        if !schedule::verify_rehandshake_confirmation(&next.control_confirm, &transcript, confirmation) {
            return Err(Error::RehandshakeConfirm);
        }
        self.activate(epoch, next)
    }

    /// Server: fresh X25519 and an encapsulation to the client's new key; sealed under the old keys, then activates.
    pub fn respond_rehandshake<D: Draws>(&mut self, d: &mut D, request: &[u8]) -> Result<Vec<u8>, Error> {
        if self.role != Role::Server {
            return Err(Error::Role);
        }
        if request.len() != REHANDSHAKE_REQUEST_LEN {
            return Err(Error::RehandshakeRequest);
        }
        let epoch = u32::from_be_bytes(request[..4].try_into().map_err(|_| Error::RehandshakeRequest)?);
        let x = d.x25519()?;
        let dh = x25519(&x, request[4..36].try_into().map_err(|_| Error::RehandshakeRequest)?)?;
        let (ct, kem) = d.encapsulate(request[36..].try_into().map_err(|_| Error::RehandshakeRequest)?)?;
        if Some(epoch) != self.epoch.checked_add(1) {
            return Err(Error::RehandshakeEpoch);
        }
        let body = [&epoch.to_be_bytes()[..], &x25519_public(&x)?, &ct].concat();
        let transcript = [request, &body].concat();
        let next = schedule::rehandshake_epoch(&self.secrets.rekey, &self.session_id, epoch, &dh, &kem, &transcript)
            .ok_or(Error::RehandshakeRequest)?;
        let confirmation = schedule::rehandshake_confirmation(&next.control_confirm, &transcript);
        let frame = self.seal_control(REHANDSHAKE_RESPONSE, &[&body[..], &confirmation].concat())?;
        self.activate(epoch, next)?;
        Ok(frame)
    }

    /// Drops a client's half-finished rekey or rehandshake; its secrets are wiped on drop.
    pub fn abort_epoch_change(&mut self) {
        self.pending = None;
    }

    /// Server: a resumption ticket carrying this epoch's rekey_secret (issued right after CONFIG, at epoch 0).
    #[allow(clippy::too_many_arguments)]
    pub fn issue_ticket<D: Draws>(&self, d: &mut D, key: &TicketKey, client_id: &str, lifetime: i64, assigned_ip: &str,
                                  now: i64) -> Result<Vec<u8>, Error> {
        if self.role != Role::Server {
            return Err(Error::Role);
        }
        key.issue(d, &self.secrets.rekey, client_id, self.version, lifetime, assigned_ip, now)
    }

    /// Client: writes the ticket file with this epoch's rekey_secret, as `VPNClient._save_ticket` does.
    pub fn save_ticket(&self, path: &Path, fingerprint: &str, protocol_version: u8, ticket: &[u8]) -> io::Result<()> {
        if self.role != Role::Client {
            return Err(io::Error::other(Error::Role.message()));
        }
        save_ticket(path, fingerprint, protocol_version, ticket, &self.secrets.rekey)
    }

    #[cfg(test)]
    pub(crate) fn secrets(&self) -> &Secrets {
        &self.secrets
    }
}

/// `KEMTLSClient` / `KEMTLSClientV3`.
pub struct ClientHandshake {
    suite: Suite,
    server_public: Box<[u8; EK_LEN]>,
    server_id: [u8; 32],
    identity: Arc<Identity>,
    client_identity: [u8; 32],
    state: ClientState,
}

enum ClientState {
    Idle,
    HelloSent { x25519: agreement::PrivateKey, key: DecapsulationKey, client_random: [u8; 32], session_id: [u8; 32], hello: Vec<u8> },
    KeySent { secrets: Box<Secrets>, transcript: Transcript, session_id: [u8; 32] },
    Done,
}

impl ClientHandshake {
    pub fn new(suite: Suite, server_public: &[u8], fingerprint_hex: &str, identity: Arc<Identity>) -> Result<Self, Error> {
        let server_public: Box<[u8; EK_LEN]> = Box::new(server_public.try_into().map_err(|_| Error::Fingerprint)?);
        let server_id = fingerprint(&server_public[..]);
        if !ct_eq(hex(&server_id).as_bytes(), fingerprint_hex.to_ascii_lowercase().as_bytes()) {
            return Err(Error::Fingerprint);
        }
        let client_identity = match (suite, &*identity) {
            (Suite::V2, Identity::Ed25519 { public, .. }) => *public,
            (Suite::V3, Identity::Kem { public, .. }) => fingerprint(&public[..]),
            _ => return Err(Error::Identity),
        };
        Ok(Self { suite, server_public, server_id, identity, client_identity, state: ClientState::Idle })
    }

    pub fn hello<D: Draws>(&mut self, d: &mut D) -> Result<Vec<u8>, Error> {
        if !matches!(self.state, ClientState::Idle) {
            return Err(Error::State("Cannot initiate handshake"));
        }
        let x25519 = d.x25519()?;
        let (key, ek) = d.mlkem_keypair()?;
        let (client_random, session_id) = (d.random()?, d.random()?);
        let hello = ClientHello { client_random: &client_random, session_id: &session_id, x25519: &x25519_public(&x25519)?,
                                  mlkem_ek: ek[..].try_into().map_err(|_| Error::Crypto)?, client_identity: &self.client_identity }
            .pack(self.suite)?;
        self.state = ClientState::HelloSent { x25519, key, client_random, session_id, hello: hello.clone() };
        Ok(hello)
    }

    /// Returns the ClientKeyExchange. Any failure leaves the handshake unusable.
    pub fn on_server_hello<D: Draws>(&mut self, d: &mut D, wire: &[u8]) -> Result<Vec<u8>, Error> {
        let ClientState::HelloSent { x25519: x, key, client_random, session_id, hello } = std::mem::replace(&mut self.state, ClientState::Done)
        else { return Err(Error::State("Cannot process ServerHello")) };
        let reply = ServerHello::parse(self.suite, wire)?;
        if reply.session_id != &session_id {
            return Err(Error::SessionIdMismatch);
        }
        if !ct_eq(reply.identity_id, &self.server_id) {
            return Err(Error::Substitution);
        }
        let mut transcript = Transcript::default();
        transcript.update(&hello);
        transcript.update(wire);
        let ecc = x25519(&x, reply.x25519)?;
        let k_eph = decapsulate(&key, reply.eph_ct)?;
        let k_c = match reply.client_ct {
            Some(ct) => Some(decapsulate(self.identity.kem_parts()?.0, ct)?),
            None => None,
        };
        let (ct, k_s) = d.encapsulate(&self.server_public)?;
        let digest = transcript.digest();
        let r = Randoms { client_random: &client_random, server_random: reply.server_random, session_id: &session_id, transcript_hash: &digest };
        let (secrets, signature) = match (&*self.identity, k_c) {
            (Identity::Ed25519 { seed, .. }, None) => (schedule::v2(&r, &ecc, &k_eph, &k_s), Some(ed25519_sign(seed, &client_proof(&digest, &ct))?)),
            (Identity::Kem { .. }, Some(k_c)) => (schedule::v3(&r, &ecc, &k_eph, &k_s, &k_c), None),
            _ => return Err(Error::Identity),
        };
        let partial = [&ct[..], signature.as_ref().map_or(&[][..], |s| &s[..])].concat();
        let finished = schedule::finished(&secrets.client_finished, CLIENT_FINISHED, &schedule::hash(&[&digest, &partial]));
        let exchange = KeyExchange { ct: &ct, signature: signature.as_ref(), finished: &finished }.pack(self.suite)?;
        transcript.update(&exchange);
        self.state = ClientState::KeySent { secrets, transcript, session_id };
        Ok(exchange)
    }

    pub fn on_server_finished(&mut self, wire: &[u8]) -> Result<Established, Error> {
        let ClientState::KeySent { secrets, transcript, session_id } = std::mem::replace(&mut self.state, ClientState::Done)
        else { return Err(Error::State("Cannot process ServerFinished")) };
        let finished = parse_server_finished(self.suite, wire)?;
        if !schedule::verify_finished(&secrets.server_finished, SERVER_FINISHED, &transcript.digest(), finished) {
            return Err(Error::ServerFinished);
        }
        Established::new(Role::Client, self.suite.version(), session_id, secrets)
    }
}

/// `KEMTLSServer` / `KEMTLSServerV3`. Authorization stays with the caller, between `client_identity` and `respond`.
pub struct ServerHandshake {
    suite: Suite,
    identity: Arc<Identity>,
    identity_id: [u8; 32],
    state: ServerState,
}

enum ServerState {
    Idle,
    HelloReceived { hello: Vec<u8> },
    HelloSent(Box<ServerKeys>),
    Done,
}

/// What the server holds between its ServerHello and the client's key exchange.
struct ServerKeys {
    transcript: Transcript,
    client_random: [u8; 32],
    server_random: [u8; 32],
    session_id: [u8; 32],
    client_identity: [u8; 32],
    ecc: Zeroizing<[u8; 32]>,
    k_eph: Zeroizing<[u8; 32]>,
    k_c: Option<Zeroizing<[u8; 32]>>,
}

impl ServerHandshake {
    pub fn new(suite: Suite, identity: Arc<Identity>) -> Result<Self, Error> {
        let identity_id = fingerprint(&identity.kem_parts()?.1[..]);
        Ok(Self { suite, identity, identity_id, state: ServerState::Idle })
    }

    /// Parses the ClientHello and returns what the caller authorizes: the Ed25519 public key (v2) or identity hash (v3).
    pub fn client_identity(&mut self, wire: &[u8]) -> Result<[u8; 32], Error> {
        if !matches!(self.state, ServerState::Idle) {
            return Err(Error::State("Cannot process ClientHello"));
        }
        self.state = ServerState::Done;
        let identity = *ClientHello::parse(self.suite, wire)?.client_identity;
        self.state = ServerState::HelloReceived { hello: wire.to_vec() };
        Ok(identity)
    }

    /// Call only after authorization passed. v3 passes the client's stored ML-KEM public key; v2 passes None.
    pub fn respond<D: Draws>(&mut self, d: &mut D, client_kem_public: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let ServerState::HelloReceived { hello } = std::mem::replace(&mut self.state, ServerState::Done)
        else { return Err(Error::State("Cannot process ClientHello")) };
        let parsed = ClientHello::parse(self.suite, &hello)?;
        let client_public: Option<&[u8; EK_LEN]> = match (self.suite, client_kem_public) {
            (Suite::V2, None) => None,
            (Suite::V3, Some(public)) => {
                let public: &[u8; EK_LEN] = public.try_into().map_err(|_| Error::StoreKey)?;
                if !ct_eq(&fingerprint(public), parsed.client_identity) {
                    return Err(Error::ClientHash);
                }
                Some(public)
            }
            _ => return Err(Error::Unauthorized),
        };
        let x = d.x25519()?;
        let server_random = d.random()?;
        let ecc = x25519(&x, parsed.x25519)?;
        let (eph_ct, k_eph) = d.encapsulate(parsed.mlkem_ek)?;
        let client_static = client_public.map(|public| d.encapsulate(public)).transpose()?;
        let reply = ServerHello { server_random: &server_random, session_id: parsed.session_id, x25519: &x25519_public(&x)?, eph_ct: &eph_ct,
                                  identity_id: &self.identity_id, client_ct: client_static.as_ref().map(|(ct, _)| ct) }.pack(self.suite)?;
        let mut transcript = Transcript::default();
        transcript.update(&hello);
        transcript.update(&reply);
        self.state = ServerState::HelloSent(Box::new(ServerKeys {
            transcript,
            client_random: *parsed.client_random,
            server_random,
            session_id: *parsed.session_id,
            client_identity: *parsed.client_identity,
            ecc,
            k_eph,
            k_c: client_static.map(|(_, k)| k),
        }));
        Ok(reply)
    }

    /// Returns (ServerFinished, the established session).
    pub fn on_key_exchange(&mut self, wire: &[u8]) -> Result<(Vec<u8>, Established), Error> {
        let ServerState::HelloSent(keys) = std::mem::replace(&mut self.state, ServerState::Done)
        else { return Err(Error::State("Cannot process ClientKeyExchange")) };
        let ServerKeys { mut transcript, client_random, server_random, session_id, client_identity, ecc, k_eph, k_c } = *keys;
        let exchange = KeyExchange::parse(self.suite, wire)?;
        let digest = transcript.digest();
        let k_s = decapsulate(self.identity.kem_parts()?.0, exchange.ct)?;
        let r = Randoms { client_random: &client_random, server_random: &server_random, session_id: &session_id, transcript_hash: &digest };
        let secrets = match &k_c {
            None => schedule::v2(&r, &ecc, &k_eph, &k_s),
            Some(k_c) => schedule::v3(&r, &ecc, &k_eph, &k_s, k_c),
        };
        if let Some(signature) = exchange.signature {
            if !ed25519_verify(&client_identity, &client_proof(&digest, exchange.ct), signature) {
                return Err(Error::ClientProof);
            }
        }
        let partial = [&exchange.ct[..], exchange.signature.map_or(&[][..], |s| &s[..])].concat();
        if !schedule::verify_finished(&secrets.client_finished, CLIENT_FINISHED, &schedule::hash(&[&digest, &partial]), exchange.finished) {
            return Err(Error::ClientFinished);
        }
        transcript.update(wire);
        let finished = pack_server_finished(self.suite, &schedule::finished(&secrets.server_finished, SERVER_FINISHED, &transcript.digest()))?;
        Ok((finished, Established::new(Role::Server, self.suite.version(), session_id, secrets)?))
    }
}

/// `ResumptionTicketKey`: AES-256-GCM over the resumption secret and the client's identity, held in memory only.
pub struct TicketKey(LessSafeKey);

impl TicketKey {
    pub fn new<D: Draws>(d: &mut D) -> Result<Self, Error> {
        let mut key = Zeroizing::new([0u8; 32]);
        d.fill(&mut key[..])?;
        Ok(Self(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).map_err(|_| Error::Crypto)?)))
    }

    /// nonce12 ‖ GCM(secret ‖ !BqHH(version, expiry, len cid, len ip) ‖ cid ‖ ip), AAD "PQVPN-RESUME".
    #[allow(clippy::too_many_arguments)]
    fn issue<D: Draws>(&self, d: &mut D, secret: &[u8; 32], client_id: &str, version: u8, lifetime: i64, assigned_ip: &str,
                       now: i64) -> Result<Vec<u8>, Error> {
        let (cid, aip) = (client_id.as_bytes(), assigned_ip.as_bytes());
        let mut plaintext = Zeroizing::new(Vec::with_capacity(45 + cid.len() + aip.len()));
        plaintext.extend_from_slice(secret);
        plaintext.push(version);
        plaintext.extend_from_slice(&now.checked_add(lifetime).ok_or(Error::Crypto)?.to_be_bytes());
        plaintext.extend_from_slice(&u16::try_from(cid.len()).map_err(|_| Error::Crypto)?.to_be_bytes());
        plaintext.extend_from_slice(&u16::try_from(aip.len()).map_err(|_| Error::Crypto)?.to_be_bytes());
        plaintext.extend_from_slice(cid);
        plaintext.extend_from_slice(aip);
        let mut nonce = [0u8; 12];
        d.fill(&mut nonce)?;
        let mut sealed = plaintext.to_vec();
        self.0.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(RESUMPTION_AAD), &mut sealed)
            .map_err(|_| Error::Crypto)?;
        Ok([&nonce[..], &sealed].concat())
    }

    /// `validate`: (secret, client_id, protocol_version, assigned_ip), or None for anything not ours or expired.
    fn validate(&self, ticket: &[u8], now: i64) -> Option<(Zeroizing<[u8; 32]>, String, u8, String)> {
        if ticket.len() < 12 + 16 + 32 + 13 {
            return None;
        }
        let (nonce, sealed) = ticket.split_at(12);
        let mut buffer = Zeroizing::new(sealed.to_vec());
        let plaintext = self.0.open_in_place(Nonce::try_assume_unique_for_key(nonce).ok()?, Aad::from(RESUMPTION_AAD), &mut buffer).ok()?;
        let (secret, rest) = plaintext.split_first_chunk::<32>()?;
        let (header, rest) = rest.split_first_chunk::<13>()?;
        let expiry = i64::from_be_bytes(header[1..9].try_into().ok()?);
        let (cid_len, aip_len) = (usize::from(u16::from_be_bytes([header[9], header[10]])), usize::from(u16::from_be_bytes([header[11], header[12]])));
        if rest.len() != cid_len + aip_len || now > expiry {
            return None;
        }
        let client_id = String::from_utf8(rest[..cid_len].to_vec()).ok()?;
        let assigned_ip = String::from_utf8(rest[cid_len..].to_vec()).ok()?;
        Some((Zeroizing::new(*secret), client_id, header[0], assigned_ip))
    }
}

/// Fuzzing only: seals arbitrary plaintext under a key the fuzzer knows, so it reaches the ticket parser behind GCM.
#[cfg(fuzzing)]
pub fn fuzz_ticket_plaintext(plaintext: &[u8], now: i64) {
    let key = TicketKey(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[7; 32]).expect("valid key")));
    let mut sealed = plaintext.to_vec();
    key.0.seal_in_place_append_tag(Nonce::assume_unique_for_key([0; 12]), Aad::from(RESUMPTION_AAD), &mut sealed).expect("seal");
    if let Some((secret, client_id, _, assigned_ip)) = key.validate(&[&[0u8; 12][..], &sealed].concat(), now) {
        assert_eq!(&secret[..], &plaintext[..32]);
        assert_eq!(plaintext.len(), 45 + client_id.len() + assigned_ip.len());
    }
}

/// `ResumptionClientHandshake`.
pub struct ResumeClient {
    version: u8,
    secret: Zeroizing<[u8; 32]>,
    ticket: Vec<u8>,
    pending: Option<(agreement::PrivateKey, DecapsulationKey, [u8; 32], Vec<u8>)>,
}

impl ResumeClient {
    pub fn new(version: u8, secret: Zeroizing<[u8; 32]>, ticket: Vec<u8>) -> Self {
        Self { version, secret, ticket, pending: None }
    }

    /// `_load_ticket`: None unless the file is ours, for this server fingerprint and protocol version.
    pub fn load(path: &Path, fingerprint: &str, protocol_version: u8, version: u8) -> Option<Self> {
        let (ticket, secret) = load_ticket(path, fingerprint, protocol_version)?;
        Some(Self::new(version, secret, ticket))
    }

    pub fn hello<D: Draws>(&mut self, d: &mut D) -> Result<Vec<u8>, Error> {
        let x = d.x25519()?;
        let (key, ek) = d.mlkem_keypair()?;
        let client_random = d.random()?;
        let hello = ResumptionHello { client_random: &client_random, ticket: &self.ticket, x25519: &x25519_public(&x)?,
                                      mlkem_ek: ek[..].try_into().map_err(|_| Error::Crypto)? }.pack(self.version)?;
        self.pending = Some((x, key, client_random, hello.clone()));
        Ok(hello)
    }

    pub fn on_accept(&mut self, wire: &[u8]) -> Result<Established, Error> {
        let (x, key, client_random, hello) = self.pending.take().ok_or(Error::State("Cannot process ResumptionAccept"))?;
        let accept = ResumptionAccept::parse(self.version, wire)?;
        let mut transcript = Transcript::default();
        transcript.update(&hello);
        transcript.update(&wire[..HEADER_LEN + ResumptionAccept::SIZE - 32]);
        let digest = transcript.digest();
        let r = Randoms { client_random: &client_random, server_random: accept.server_random, session_id: accept.session_id, transcript_hash: &digest };
        let (ecc, kem) = (x25519(&x, accept.x25519)?, decapsulate(&key, accept.ct)?);
        let secrets = schedule::resume(&r, &self.secret, &ecc, &kem);
        if !schedule::verify_finished(&secrets.server_finished, RESUME_FINISHED, &digest, accept.finished) {
            return Err(Error::ResumeFinished);
        }
        Established::new(Role::Client, self.version, *accept.session_id, secrets)
    }
}

/// `ResumptionServerHandshake.process_hello`: (accept, session, client_id, assigned_ip). The caller re-checks
/// authorization before it sends the accept or allocates anything.
pub fn resume_server<D: Draws>(d: &mut D, key: &TicketKey, wire: &[u8], version: u8, now: i64)
                               -> Result<(Vec<u8>, Established, String, String), Error> {
    let hello = ResumptionHello::parse(version, wire)?;
    let (secret, client_id, ticket_version, assigned_ip) = key.validate(hello.ticket, now).ok_or(Error::Ticket)?;
    if ticket_version != version {
        return Err(Error::TicketVersion);
    }
    let (server_random, session_id) = (d.random()?, d.random()?);
    let x = d.x25519()?;
    let ecc = x25519(&x, hello.x25519)?;
    let (ct, kem) = d.encapsulate(hello.mlkem_ek)?;
    let server_x = x25519_public(&x)?;
    let unmacced = ResumptionAccept { server_random: &server_random, session_id: &session_id, x25519: &server_x, ct: &ct, finished: &[0; 32] }
        .transcript_bytes(version);
    let mut transcript = Transcript::default();
    transcript.update(wire);
    transcript.update(&unmacced);
    let digest = transcript.digest();
    let r = Randoms { client_random: hello.client_random, server_random: &server_random, session_id: &session_id, transcript_hash: &digest };
    let secrets = schedule::resume(&r, &secret, &ecc, &kem);
    let finished = schedule::finished(&secrets.server_finished, RESUME_FINISHED, &digest);
    let accept = ResumptionAccept { server_random: &server_random, session_id: &session_id, x25519: &server_x, ct: &ct, finished: &finished }
        .pack(version)?;
    Ok((accept, Established::new(Role::Server, version, session_id, secrets)?, client_id, assigned_ip))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard padded base64, the format `base64.b64encode` writes into the ticket file.
fn b64_encode(data: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(data.len().div_ceil(3) * 4));
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            out.push(if i <= chunk.len() { char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]) } else { '=' });
        }
    }
    out
}

/// Strict decoding of what `b64_encode` (or Python) wrote: whole quads, padding only at the end.
fn b64_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() / 4 * 3));
    for (index, quad) in bytes.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && index + 1 != bytes.len() / 4) {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in quad[..4 - pad].iter().enumerate() {
            n |= u32::try_from(B64.iter().position(|&b| b == c)?).ok()? << (18 - 6 * i);
        }
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
}

/// The client's ticket file, `{fp, t, s, v}` as `VPNClient._save_ticket` writes it, written the same way: a temp file
/// in the same directory (O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600), fsync, rename over, fsync the directory.
pub fn save_ticket(path: &Path, fingerprint: &str, protocol_version: u8, ticket: &[u8], secret: &[u8; 32]) -> io::Result<()> {
    let fingerprint = serde_json::to_string(fingerprint).map_err(io::Error::other)?;
    let (ticket, secret) = (b64_encode(ticket), b64_encode(secret));
    let contents = Zeroizing::new(format!("{{\"fp\": {fingerprint}, \"t\": \"{}\", \"s\": \"{}\", \"v\": {protocol_version}}}",
                                          ticket.as_str(), secret.as_str()));
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut suffix = [0u8; 8];
    rand::fill(&mut suffix).map_err(|_| io::Error::other("no randomness"))?;
    let temp = directory.join(format!(".pqvpn_ticket.{}.tmp", hex(&suffix)));
    let written = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temp, path)
        });
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC).open(directory)?.sync_all()
}

/// `_load_ticket`: (ticket, resumption secret) if the file matches this server and protocol version.
pub fn load_ticket(path: &Path, fingerprint: &str, protocol_version: u8) -> Option<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).ok()?;
    let mut raw = Zeroizing::new(Vec::new());
    file.take(MAX_TICKET_FILE).read_to_end(&mut raw).ok()?;
    let mut data: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let secret_text = match data.get_mut("s") {
        Some(serde_json::Value::String(s)) => Zeroizing::new(std::mem::take(s)),
        _ => return None,
    };
    let result = (|| {
        if data.get("fp")?.as_str()? != fingerprint || data.get("v")?.as_u64()? != u64::from(protocol_version) {
            return None;
        }
        let ticket = b64_decode(data.get("t")?.as_str()?)?.to_vec();
        let secret: [u8; 32] = b64_decode(&secret_text)?.as_slice().try_into().ok()?;
        Some((ticket, Zeroizing::new(secret)))
    })();
    drop(secret_text);
    result
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
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let value = unhex(&self.next("random")["value"]);
        assert_eq!(value.len(), out.len(), "Python drew a different number of random bytes");
        out.copy_from_slice(&value);
        Ok(())
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


/// Byte-for-byte replay of tests/vectors/handshake.json (recorded by tests/test_handshake_vectors.py) through the real
/// state machines: every step gets exactly the draws Python made in it, in order, and must produce Python's bytes.
#[cfg(test)]
mod vectors {
    use super::*;
    use serde_json::Value;

    const CONFIG: &[u8] = br#"{"client_vpn_ip": "10.8.0.2", "vector": true}"#;
    const NOW: i64 = 1_800_000_000;

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

    /// Runs `f` with the step's recorded draws and checks they were all used.
    fn with_draws<T>(run: &Value, name: &str, f: impl FnOnce(&mut Replay) -> T) -> T {
        let mut d = Replay::new(step(run, name));
        let out = f(&mut d);
        d.done();
        out
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

    fn full_run(run: &Value, ids: &Value) {
        let suite = Suite::from_version(u8::try_from(run["version"].as_u64().unwrap()).unwrap()).unwrap();
        let server_pk = unhex(&ids["server_kem_pk"]);
        let server_id = Arc::new(Identity::kem(&unhex(&ids["server_kem_sk"]), &server_pk).unwrap());
        let client_pk = unhex(&ids["client_kem_pk"]);
        let client_id = Arc::new(match suite {
            Suite::V2 => Identity::ed25519(&unhex(&ids["client_ed25519"])).unwrap(),
            Suite::V3 => Identity::kem(&unhex(&ids["client_kem_sk"]), &client_pk).unwrap(),
        });
        let mut client = ClientHandshake::new(suite, &server_pk, &hex(&fingerprint(&server_pk)).to_uppercase(), client_id).unwrap();
        let mut server = ServerHandshake::new(suite, server_id).unwrap();

        let ch = with_draws(run, "client_hello", |d| client.hello(d).unwrap());
        assert_eq!(ch, wire(run, "client_hello"));
        let lookup = server.client_identity(&ch).unwrap();
        let store = match suite {
            Suite::V2 => None,
            Suite::V3 => {
                assert_eq!(lookup, fingerprint(&client_pk));
                Some(&client_pk[..])
            }
        };
        let sh = with_draws(run, "server_hello", |d| server.respond(d, store).unwrap());
        assert_eq!(sh, wire(run, "server_hello"));
        let cke = with_draws(run, "client_key_exchange", |d| client.on_server_hello(d, &sh).unwrap());
        assert_eq!(cke, wire(run, "client_key_exchange"));
        let (sf, mut s) = with_draws(run, "server_finished", |_| server.on_key_exchange(&cke).unwrap());
        assert_eq!(sf, wire(run, "server_finished"));
        let mut c = client.on_server_finished(&sf).unwrap();
        assert_eq!(c.session_id(), s.session_id());
        assert_secrets(c.secrets(), &run["secrets"]["0"], "client epoch 0");
        assert_secrets(s.secrets(), &run["secrets"]["0"], "server epoch 0");

        let ticket = with_draws(run, "issue_ticket", |d| {
            let key = TicketKey::new(d).unwrap();
            s.issue_ticket(d, &key, "vector", 86400, "10.8.0.2", NOW).unwrap()
        });
        assert_eq!(ticket, wire(run, "issue_ticket"));

        let expected = &run["control"];
        let config = s.seal_control(7, CONFIG).unwrap();
        assert_eq!(hex(&config), expected["config"].as_str().unwrap());
        assert_eq!(c.open_control(&config, Some(7)).unwrap(), (7, CONFIG.to_vec()));
        let error = c.seal_control(10, b"client says hi").unwrap();
        assert_eq!(hex(&error), expected["client_error"].as_str().unwrap());
        assert_eq!(s.open_control(&error, None).unwrap().1, b"client says hi");
        let second = s.seal_control(6, b"").unwrap();
        assert_eq!(hex(&second), expected["second"].as_str().unwrap());
        assert_eq!(c.open_control(&second, None).unwrap(), (6, vec![]));

        let request = with_draws(run, "rekey_request", |d| c.begin_rekey(d).unwrap());
        assert_eq!(request, wire(run, "rekey_request"));
        assert_eq!(c.begin_rekey(&mut Os), Err(Error::Busy));
        let (_, payload) = s.open_control(&request, Some(REKEY_REQUEST)).unwrap();
        let response = with_draws(run, "rekey_response", |_| s.respond_rekey(&payload).unwrap());
        assert_eq!(response, wire(run, "rekey_response"));
        let (_, confirmation) = c.open_control(&response, Some(REKEY_RESPONSE)).unwrap();
        c.finish_rekey(&confirmation).unwrap();
        assert_eq!((c.epoch(), s.epoch()), (1, 1));
        assert_secrets(c.secrets(), &run["secrets"]["1"], "client epoch 1");
        assert_secrets(s.secrets(), &run["secrets"]["1"], "server epoch 1");

        let request = with_draws(run, "rehandshake_request", |d| c.begin_rehandshake(d).unwrap());
        assert_eq!(request, wire(run, "rehandshake_request"));
        let (_, payload) = s.open_control(&request, Some(REHANDSHAKE_REQUEST)).unwrap();
        let response = with_draws(run, "rehandshake_response", |d| s.respond_rehandshake(d, &payload).unwrap());
        assert_eq!(response, wire(run, "rehandshake_response"));
        let (_, confirmation) = c.open_control(&response, Some(REHANDSHAKE_RESPONSE)).unwrap();
        c.finish_rehandshake(&confirmation).unwrap();
        assert_eq!((c.epoch(), s.epoch()), (2, 2));
        assert_secrets(c.secrets(), &run["secrets"]["2"], "client epoch 2");
        assert_secrets(s.secrets(), &run["secrets"]["2"], "server epoch 2");

        // Data and control both moved to epoch 2 together.
        let frame = c.data().seal(1, b"after").unwrap();
        assert_eq!(s.data().open(&frame, None).unwrap(), (1, b"after".to_vec()));
        assert_eq!(u32::from_be_bytes(frame[14..18].try_into().unwrap()), 2);
    }

    fn resume_run(run: &Value, full: &Value) {
        let version = u8::try_from(run["version"].as_u64().unwrap()).unwrap();
        let key = TicketKey::new(&mut Replay::new(step(full, "issue_ticket"))).unwrap();
        let mut client = ResumeClient::new(version, Zeroizing::new(arr(&run["resumption_secret"])), unhex(&run["ticket"]));
        let hello = with_draws(run, "resumption_hello", |d| client.hello(d).unwrap());
        assert_eq!(hello, wire(run, "resumption_hello"));
        let (accept, s, client_id, assigned_ip) = with_draws(run, "resumption_accept", |d| resume_server(d, &key, &hello, version, NOW).unwrap());
        assert_eq!((client_id.as_str(), assigned_ip.as_str()), ("vector", "10.8.0.2"));
        assert_eq!(accept, wire(run, "resumption_accept"));
        let c = client.on_accept(&accept).unwrap();
        assert_secrets(c.secrets(), &run["secrets"]["0"], "client resumed");
        assert_secrets(s.secrets(), &run["secrets"]["0"], "server resumed");
        // An expired ticket and a wrong-version ticket are refused before any draw.
        assert_eq!(resume_server(&mut Os, &key, &hello, version, NOW + 86401).err(), Some(Error::Ticket));
        let other = if version == 0x20 { 0x30 } else { 0x20 };
        let mut wrong = hello.clone();
        wrong[2] = other;
        assert_eq!(resume_server(&mut Os, &key, &wrong, other, NOW).err(), Some(Error::TicketVersion));
    }

    #[test]
    fn real_state_machines_reproduce_python_handshakes_rekey_and_rehandshake() {
        let v = file();
        let runs: Vec<_> = v["runs"].as_array().unwrap().iter().filter(|r| r["name"] == "v2" || r["name"] == "v3").collect();
        assert_eq!(runs.len(), 2);
        runs.iter().for_each(|run| full_run(run, &v["identities"]));
    }

    #[test]
    fn real_resumption_reproduces_python() {
        let v = file();
        let runs = v["runs"].as_array().unwrap();
        for name in ["v2", "v3"] {
            let full = runs.iter().find(|r| r["name"] == name).unwrap();
            let resumed = runs.iter().find(|r| r["name"] == format!("resume-{name}")).unwrap();
            resume_run(resumed, full);
        }
    }

    #[test]
    fn liboqs_decapsulation_kat_including_implicit_rejection() {
        let v = file();
        let kats = v["kem_kat"].as_array().unwrap();
        assert_eq!(kats.len(), 2);
        for kat in kats {
            let key = mlkem_secret(&unhex(&kat["sk"])).unwrap();
            assert_eq!(hex(&decapsulate(&key, &arr(&kat["ct"])).unwrap()[..]), kat["ss"].as_str().unwrap(), "{}", kat["name"]);
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

    /// Rust may reject more than Python (still failing closed), never less.
    #[test]
    fn primitive_rejections_are_at_least_as_strict_as_python() {
        let v = file();
        let p = &v["primitive_rejections"];
        let private = agreement::PrivateKey::generate(&agreement::X25519).unwrap();
        for case in p["x25519"].as_array().unwrap() {
            let rust_ok = x25519(&private, &arr(&case["point"])).is_ok();
            assert!(case["result"] != "error" || !rust_ok, "Python rejects X25519 point {} but Rust accepts it", case["point"]);
        }
        for case in p["mlkem_encapsulation_key"].as_array().unwrap() {
            assert_eq!(Os.encapsulate(&arr(&case["ek"])).is_ok(), case["result"] == "ok", "ML-KEM encapsulation key {}", case["name"]);
        }
        for case in p["ed25519"].as_array().unwrap() {
            let rust_ok = ed25519_verify(&arr(&case["public"]), &unhex(&case["message"]), &unhex(&case["signature"]));
            assert_eq!(rust_ok, case["result"] == "ok", "Ed25519 {}", case["name"]);
        }
    }
}

#[cfg(test)]
mod machine_tests {
    use super::*;

    fn kem_identity() -> (Arc<Identity>, Vec<u8>) {
        let (key, public) = Os.mlkem_keypair().unwrap();
        let secret = key.key_bytes().unwrap().as_ref().to_vec();
        (Arc::new(Identity::kem(&secret, &public).unwrap()), public)
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pqvpn-core-{name}-{}", hex(&Os.random().unwrap()[..8])));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    /// A full handshake with real randomness; returns (client, server).
    fn established(suite: Suite) -> (Established, Established) {
        let (server_id, server_pk) = kem_identity();
        let (client_id, client_pk) = match suite {
            Suite::V2 => (Arc::new(Identity::ed25519(&[7; 32]).unwrap()), vec![]),
            Suite::V3 => kem_identity(),
        };
        let mut client = ClientHandshake::new(suite, &server_pk, &hex(&fingerprint(&server_pk)), client_id).unwrap();
        let mut server = ServerHandshake::new(suite, server_id).unwrap();
        server.client_identity(&client.hello(&mut Os).unwrap()).unwrap();
        let sh = server.respond(&mut Os, (suite == Suite::V3).then_some(&client_pk[..])).unwrap();
        let (sf, s) = server.on_key_exchange(&client.on_server_hello(&mut Os, &sh).unwrap()).unwrap();
        (client.on_server_finished(&sf).unwrap(), s)
    }

    #[test]
    fn os_handshakes_agree_and_out_of_order_calls_fail() {
        for suite in [Suite::V2, Suite::V3] {
            let (c, s) = established(suite);
            let frame = c.seal_control(7, b"cfg").unwrap();
            assert_eq!(s.open_control(&frame, None).unwrap().1, b"cfg");
        }
        let (server_id, server_pk) = kem_identity();
        let mut client = ClientHandshake::new(Suite::V2, &server_pk, &hex(&fingerprint(&server_pk)), Arc::new(Identity::ed25519(&[1; 32]).unwrap())).unwrap();
        assert_eq!(client.on_server_finished(&[0; 38]).err(), Some(Error::State("Cannot process ServerFinished")));
        let mut server = ServerHandshake::new(Suite::V2, server_id).unwrap();
        assert_eq!(server.respond(&mut Os, None).err(), Some(Error::State("Cannot process ClientHello")));
        assert_eq!(ClientHandshake::new(Suite::V2, &server_pk, "00", Arc::new(Identity::ed25519(&[1; 32]).unwrap())).err(), Some(Error::Fingerprint));
        let (other_id, _) = kem_identity();
        assert_eq!(ClientHandshake::new(Suite::V2, &server_pk, &hex(&fingerprint(&server_pk)), other_id).err(), Some(Error::Identity));
    }

    #[test]
    fn tampered_messages_are_rejected() {
        let (server_id, server_pk) = kem_identity();
        let mut client = ClientHandshake::new(Suite::V2, &server_pk, &hex(&fingerprint(&server_pk)), Arc::new(Identity::ed25519(&[3; 32]).unwrap())).unwrap();
        let mut server = ServerHandshake::new(Suite::V2, server_id).unwrap();
        server.client_identity(&client.hello(&mut Os).unwrap()).unwrap();
        let sh = server.respond(&mut Os, None).unwrap();
        let mut cke = client.on_server_hello(&mut Os, &sh).unwrap();
        cke[6 + 1088] ^= 1; // the Ed25519 signature
        assert_eq!(server.on_key_exchange(&cke).err(), Some(Error::ClientProof));
        assert_eq!(server.on_key_exchange(&cke).err(), Some(Error::State("Cannot process ClientKeyExchange")), "a failed handshake stays failed");
    }

    #[test]
    fn v3_server_refuses_a_store_key_that_does_not_match_the_hello() {
        let (server_id, server_pk) = kem_identity();
        let (client_id, _) = kem_identity();
        let (_, someone_else) = kem_identity();
        let mut client = ClientHandshake::new(Suite::V3, &server_pk, &hex(&fingerprint(&server_pk)), client_id).unwrap();
        let mut server = ServerHandshake::new(Suite::V3, server_id).unwrap();
        server.client_identity(&client.hello(&mut Os).unwrap()).unwrap();
        assert_eq!(server.respond(&mut Os, Some(&someone_else)).err(), Some(Error::ClientHash));
    }

    #[test]
    fn epoch_changes_check_roles_confirmations_and_order() {
        let (mut c, mut s) = established(Suite::V3);
        assert_eq!(s.begin_rekey(&mut Os).err(), Some(Error::Role));
        assert_eq!(c.respond_rekey(&[0; 36]).err(), Some(Error::Role));
        assert_eq!(c.finish_rekey(b"x").err(), Some(Error::NoPending));
        let request = c.begin_rekey(&mut Os).unwrap();
        let (_, payload) = s.open_control(&request, None).unwrap();
        assert_eq!(s.respond_rekey(&payload[..35]).err(), Some(Error::RekeyRequest));
        let mut skipped = payload.clone();
        skipped[3] = 2;
        assert_eq!(s.respond_rekey(&skipped).err(), Some(Error::RekeyEpoch));
        let (_, mut confirmation) = c.open_control(&s.respond_rekey(&payload).unwrap(), None).unwrap();
        confirmation[10] ^= 1;
        assert_eq!(c.finish_rekey(&confirmation).err(), Some(Error::RekeyConfirm));
        assert_eq!(c.epoch(), 0, "a bad confirmation activates nothing");

        let (mut c, mut s) = established(Suite::V2);
        let request = c.begin_rehandshake(&mut Os).unwrap();
        let (_, payload) = s.open_control(&request, None).unwrap();
        let (_, mut response) = c.open_control(&s.respond_rehandshake(&mut Os, &payload).unwrap(), None).unwrap();
        *response.last_mut().unwrap() ^= 1;
        assert_eq!(c.finish_rehandshake(&response).err(), Some(Error::RehandshakeConfirm));
        assert_eq!(c.epoch(), 0);
        c.abort_epoch_change();
    }

    #[test]
    fn tickets_roundtrip_expire_and_reject_tampering() {
        let key = TicketKey::new(&mut Os).unwrap();
        let ticket = key.issue(&mut Os, &[9; 32], "alice", 0x30, 60, "10.8.0.9", 1000).unwrap();
        let (secret, cid, version, ip) = key.validate(&ticket, 1060).unwrap();
        assert_eq!((*secret, cid.as_str(), version, ip.as_str()), ([9; 32], "alice", 0x30, "10.8.0.9"));
        assert!(key.validate(&ticket, 1061).is_none(), "expired");
        let mut tampered = ticket.clone();
        tampered[20] ^= 1;
        assert!(key.validate(&tampered, 1000).is_none());
        assert!(TicketKey::new(&mut Os).unwrap().validate(&ticket, 1000).is_none(), "another key");
        assert!(key.validate(&ticket[..72], 1000).is_none());
    }

    #[test]
    fn base64_matches_rfc_4648_and_is_strict() {
        for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(&*b64_encode(plain.as_bytes()), encoded);
            assert_eq!(&b64_decode(encoded).unwrap()[..], plain.as_bytes());
        }
        for bad in ["Zg=", "Z===", "Zg==Zg==", "Zm9!", "Zm 9v"] {
            assert!(b64_decode(bad).is_none(), "{bad}");
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(&b64_decode(&b64_encode(&all)).unwrap()[..], &all[..]);
    }

    #[test]
    fn ticket_file_roundtrip_mode_and_symlink_refusal() {
        let dir = temp_dir("ticket");
        let path = dir.join(".pqvpn_ticket.json");
        save_ticket(&path, "ab\"cd", 3, b"ticket bytes", &[5; 32]).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let (ticket, secret) = load_ticket(&path, "ab\"cd", 3).unwrap();
        assert_eq!((ticket.as_slice(), *secret), (&b"ticket bytes"[..], [5; 32]));
        assert!(load_ticket(&path, "other", 3).is_none());
        assert!(load_ticket(&path, "ab\"cd", 2).is_none());
        assert!(std::fs::read_dir(&dir).unwrap().count() == 1, "no temp file left behind");
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_ticket(&link, "ab\"cd", 3).is_none(), "the reader does not follow symlinks");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_private_checks_type_and_mode() {
        let dir = temp_dir("private");
        let path = dir.join("key");
        std::fs::write(&path, [1u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_private(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&read_private(&path).unwrap()[..], &[1u8; 32]);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private(&link).is_err());
        assert!(read_private(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn kem_identity_must_be_a_consistent_keypair() {
        let (key, public) = Os.mlkem_keypair().unwrap();
        let secret = key.key_bytes().unwrap().as_ref().to_vec();
        let (_, other_public) = Os.mlkem_keypair().unwrap();
        assert!(Identity::kem(&secret, &public).is_ok());
        assert_eq!(Identity::kem(&secret, &other_public).err(), Some(Error::Identity));
        assert_eq!(Identity::kem(&secret[..2399], &public).err(), Some(Error::Identity));
        assert_eq!(Identity::ed25519(&[0; 31]).err(), Some(Error::Identity));
    }
}
