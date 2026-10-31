//! Record layer for one session epoch, mirroring `HandshakeSession` `_encrypt`/`_decrypt` in handshake/kemtls.py:
//! the data channel (`DataSession`, replay window) and the control channel (`ControlChannel`, strict sequence). No I/O.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::replay::{Reject, ReplayWindow};

/// `struct.calcsize("!2sBBBB8sIQ")`.
pub const HEADER_LEN: usize = 26;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
const MAGIC: [u8; 2] = *b"PV";
const CHANNEL_DATA: u8 = 1;
const CHANNEL_CONTROL: u8 = 2;
/// FrameType values 1..=13 exist; only DATA..=PONG may be sealed on the data channel, CLOSE..=RESUMPTION_TICKET on control.
const MAX_FRAME_TYPE: u8 = 13;
const MAX_DATA_FRAME_TYPE: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Rejections in the order Python raises them; `as_str` matches the Python-side kind names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidKey,
    Closed,
    Epoch,
    ControlType,
    Exhausted,
    Short,
    Header,
    FrameType,
    UnexpectedType,
    Binding,
    Replayed,
    OutsideWindow,
    Tag,
    DataType,
    ControlSequence,
    ControlTag,
}

impl Error {
    pub fn as_str(self) -> &'static str {
        match self {
            Error::InvalidKey => "invalid_key",
            Error::Closed => "closed",
            Error::Epoch => "epoch",
            Error::ControlType => "control_type",
            Error::Exhausted => "exhausted",
            Error::Short => "short",
            Error::Header => "header",
            Error::FrameType => "frame_type",
            Error::UnexpectedType => "unexpected_type",
            Error::Binding => "binding",
            Error::Replayed => "replayed",
            Error::OutsideWindow => "outside_window",
            Error::Tag => "tag",
            Error::DataType => "data_type",
            Error::ControlSequence => "control_sequence",
            Error::ControlTag => "control_tag",
        }
    }
}

impl From<Reject> for Error {
    fn from(reject: Reject) -> Self {
        match reject {
            Reject::Replayed => Error::Replayed,
            Reject::OutsideWindow => Error::OutsideWindow,
        }
    }
}

/// nonce = base XOR (0u32 || sequence as u64 big-endian).
pub fn nonce(base: &[u8; NONCE_LEN], sequence: u64) -> Zeroizing<[u8; NONCE_LEN]> {
    let mut nonce = Zeroizing::new(*base);
    for (n, s) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *n ^= s;
    }
    nonce
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::InvalidKey);
    }
    Ok(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::InvalidKey)?))
}

fn nonce_base(base: &[u8]) -> Result<Zeroizing<[u8; NONCE_LEN]>, Error> {
    Ok(Zeroizing::new(base.try_into().map_err(|_| Error::InvalidKey)?))
}

/// What every record of one session epoch is bound to, on both channels.
struct Binding {
    session_id: [u8; 8],
    version: u8,
    epoch: u32,
    send_direction: u8,
    recv_direction: u8,
}

impl Binding {
    fn new(role: Role, session_id: &[u8], version: u8, epoch: u32) -> Result<Self, Error> {
        if session_id.len() != 32 {
            return Err(Error::InvalidKey);
        }
        let (send_direction, recv_direction) = match role {
            Role::Client => (1, 2),
            Role::Server => (2, 1),
        };
        Ok(Self { session_id: session_id[..8].try_into().map_err(|_| Error::InvalidKey)?, version, epoch, send_direction, recv_direction })
    }

    /// `struct.pack("!2sBBBB8sIQ", ...)` followed by the payload; the tag is appended by the caller.
    fn frame(&self, channel: u8, frame_type: u8, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&[self.version, channel, frame_type, self.send_direction]);
        frame.extend_from_slice(&self.session_id);
        frame.extend_from_slice(&self.epoch.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// The checks `_decrypt` makes before touching the key, in its order. Returns (frame_type, sequence).
    fn check(&self, frame: &[u8], channel: u8, expected: Option<u8>) -> Result<(u8, u64), Error> {
        if frame.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Short);
        }
        let header = &frame[..HEADER_LEN];
        if header[..2] != MAGIC || header[2] != self.version || header[3] != channel {
            return Err(Error::Header);
        }
        let frame_type = header[4];
        if !(1..=MAX_FRAME_TYPE).contains(&frame_type) {
            return Err(Error::FrameType);
        }
        if expected.is_some_and(|t| t != frame_type) {
            return Err(Error::UnexpectedType);
        }
        let epoch = u32::from_be_bytes(header[14..18].try_into().map_err(|_| Error::Header)?);
        if header[6..14] != self.session_id || epoch != self.epoch || header[5] != self.recv_direction {
            return Err(Error::Binding);
        }
        Ok((frame_type, u64::from_be_bytes(header[18..26].try_into().map_err(|_| Error::Header)?)))
    }
}

pub struct DataSession {
    binding: Binding,
    send_key: LessSafeKey,
    send_nonce_base: Zeroizing<[u8; NONCE_LEN]>,
    next_sequence: AtomicU64,
    recv_key: LessSafeKey,
    recv_nonce_base: Zeroizing<[u8; NONCE_LEN]>,
    /// Held across check → open → commit, as `_data_receive_lock` is in Python.
    replay: Mutex<ReplayWindow>,
}

impl DataSession {
    /// `session_id` is the full 32-byte id; the wire carries its first 8 bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(role: Role, session_id: &[u8], version: u8, epoch: u32, send_key: &[u8], send_nonce_base: &[u8],
               recv_key: &[u8], recv_nonce_base: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            binding: Binding::new(role, session_id, version, epoch)?,
            send_key: aead_key(send_key)?,
            send_nonce_base: nonce_base(send_nonce_base)?,
            next_sequence: AtomicU64::new(0),
            recv_key: aead_key(recv_key)?,
            recv_nonce_base: nonce_base(recv_nonce_base)?,
            replay: Mutex::new(ReplayWindow::default()),
        })
    }

    pub fn seal(&self, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if !(1..=MAX_DATA_FRAME_TYPE).contains(&frame_type) {
            return Err(Error::ControlType);
        }
        // Claim the sequence before sealing; refuse at 2^64-1 instead of wrapping.
        // `try_update` (its replacement) is newer than our MSRV 1.85 (Debian trixie).
        #[allow(deprecated)]
        let sequence = self
            .next_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |s| (s < u64::MAX).then(|| s + 1))
            .map_err(|_| Error::Exhausted)?;
        let mut frame = self.binding.frame(CHANNEL_DATA, frame_type, sequence, payload);
        let (header, body) = frame.split_at_mut(HEADER_LEN);
        let tag = self
            .send_key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce(&self.send_nonce_base, sequence)), Aad::from(&*header), body)
            .map_err(|_| Error::Tag)?;
        frame.extend_from_slice(tag.as_ref());
        Ok(frame)
    }

    /// `expected` mirrors `decrypt_frame(frame, expected_type)`: checked before the replay window.
    pub fn open(&self, frame: &[u8], expected: Option<u8>) -> Result<(u8, Vec<u8>), Error> {
        let (frame_type, sequence) = self.binding.check(frame, CHANNEL_DATA, expected)?;
        let (header, sealed) = frame.split_at(HEADER_LEN);
        let mut replay = self.replay.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        replay.check(sequence)?;
        let mut buffer = sealed.to_vec();
        let plaintext_len = self
            .recv_key
            .open_in_place(Nonce::assume_unique_for_key(*nonce(&self.recv_nonce_base, sequence)), Aad::from(header), &mut buffer)
            .map_err(|_| Error::Tag)?
            .len();
        replay.commit(sequence);
        buffer.truncate(plaintext_len);
        Ok((frame_type, buffer))
    }
}

/// One epoch's control channel (CONFIG, rekey, rehandshake, ticket, CLOSE, ERROR). Unlike data, control frames arrive
/// over TCP in order, so the receiver demands exactly the next sequence instead of keeping a replay window.
pub struct ControlChannel {
    binding: Binding,
    send_key: LessSafeKey,
    send_nonce_base: Zeroizing<[u8; NONCE_LEN]>,
    recv_key: LessSafeKey,
    recv_nonce_base: Zeroizing<[u8; NONCE_LEN]>,
    send_sequence: Mutex<u64>,
    recv_sequence: Mutex<u64>,
}

impl ControlChannel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(role: Role, session_id: &[u8], version: u8, epoch: u32, send_key: &[u8], send_nonce_base: &[u8],
               recv_key: &[u8], recv_nonce_base: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            binding: Binding::new(role, session_id, version, epoch)?,
            send_key: aead_key(send_key)?,
            send_nonce_base: nonce_base(send_nonce_base)?,
            recv_key: aead_key(recv_key)?,
            recv_nonce_base: nonce_base(recv_nonce_base)?,
            send_sequence: Mutex::new(0),
            recv_sequence: Mutex::new(0),
        })
    }

    /// `encrypt_control`: only control frame types; the sequence is consumed only when sealing succeeds.
    pub fn seal(&self, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if !(MAX_DATA_FRAME_TYPE + 1..=MAX_FRAME_TYPE).contains(&frame_type) {
            return Err(Error::DataType);
        }
        let mut sequence = self.send_sequence.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if *sequence == u64::MAX {
            return Err(Error::Exhausted);
        }
        let mut frame = self.binding.frame(CHANNEL_CONTROL, frame_type, *sequence, payload);
        let (header, body) = frame.split_at_mut(HEADER_LEN);
        let tag = self
            .send_key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce(&self.send_nonce_base, *sequence)), Aad::from(&*header), body)
            .map_err(|_| Error::ControlTag)?;
        frame.extend_from_slice(tag.as_ref());
        *sequence += 1;
        Ok(frame)
    }

    /// `decrypt_control`: any known frame type, exactly the next sequence, and the counter advances only on success.
    pub fn open(&self, frame: &[u8], expected: Option<u8>) -> Result<(u8, Vec<u8>), Error> {
        let (frame_type, sequence) = self.binding.check(frame, CHANNEL_CONTROL, expected)?;
        let mut next = self.recv_sequence.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if sequence != *next {
            return Err(Error::ControlSequence);
        }
        let (header, sealed) = frame.split_at(HEADER_LEN);
        let mut buffer = sealed.to_vec();
        let plaintext_len = self
            .recv_key
            .open_in_place(Nonce::assume_unique_for_key(*nonce(&self.recv_nonce_base, sequence)), Aad::from(header), &mut buffer)
            .map_err(|_| Error::ControlTag)?
            .len();
        *next += 1;
        buffer.truncate(plaintext_len);
        Ok((frame_type, buffer))
    }
}

/// How long a switch keeps the previous epoch's receive state: covers the TCP delay before the peer switches too,
/// plus UDP delay and reordering of frames sealed before it did. Mirrors `RECEIVE_GRACE_SECONDS` in kemtls.py.
pub const RECEIVE_GRACE: Duration = Duration::from_secs(5);
/// How long the responder (server) keeps sealing under the previous epoch after it switched, unless an authenticated
/// frame at the new epoch shows the client switched first. Covers the TCP response plus a retransmit; strictly
/// shorter than `RECEIVE_GRACE`, so every held frame still has 3 s to reach a client whose grace is live.
pub const SEND_HOLD: Duration = Duration::from_secs(2);
const _: () = assert!(SEND_HOLD.as_nanos() < RECEIVE_GRACE.as_nanos());

/// One snapshot of the data channel, swapped whole: the current epoch and, for `RECEIVE_GRACE` after a switch,
/// the previous one, kept whole so it opens with its own replay window and the server's hold seals with its own
/// counter. Dropping a snapshot frees the previous epoch's keys once the last in-flight user lets go.
struct Epochs {
    current: Arc<DataSession>,
    previous: Option<Arc<DataSession>>,
    switched: Instant,
    /// Server only: cleared by the first authenticated frame at `current`.
    holding: AtomicBool,
}

/// A session's data channel across epochs. Each epoch's keys, send counter and replay window live in
/// one `DataSession` that is never rebuilt, so a (key, nonce) pair can never be sealed twice.
pub struct Session {
    role: Role,
    session_id: [u8; 32],
    version: u8,
    epochs: ArcSwapOption<Epochs>,
    /// Serializes rekey, grace expiry and close so none can resurrect what another dropped; reads stay lock-free.
    writer: Mutex<()>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(role: Role, session_id: &[u8], version: u8, epoch: u32, send_key: &[u8], send_nonce_base: &[u8],
               recv_key: &[u8], recv_nonce_base: &[u8]) -> Result<Self, Error> {
        let first = DataSession::new(role, session_id, version, epoch, send_key, send_nonce_base, recv_key, recv_nonce_base)?;
        Ok(Self {
            role,
            session_id: session_id.try_into().map_err(|_| Error::InvalidKey)?,
            version,
            epochs: ArcSwapOption::from_pointee(Epochs {
                current: Arc::new(first), previous: None, switched: Instant::now(), holding: AtomicBool::new(false),
            }),
            writer: Mutex::new(()),
        })
    }

    /// The live snapshot and, while a previous epoch is still in its grace, the time read. The clock is only read
    /// while a previous epoch exists; once its grace is over it is dropped here, under the writer lock.
    fn epochs(&self, now: &impl Fn() -> Instant) -> Result<(Arc<Epochs>, Option<Instant>), Error> {
        loop {
            let epochs = self.epochs.load_full().ok_or(Error::Closed)?;
            if epochs.previous.is_none() {
                return Ok((epochs, None));
            }
            let at = now();
            if at < epochs.switched + RECEIVE_GRACE {
                return Ok((epochs, Some(at)));
            }
            let _writer = self.writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            // Only the snapshot we judged expired; a concurrent rekey or close has already replaced it.
            if self.epochs.load().as_ref().is_some_and(|latest| Arc::ptr_eq(latest, &epochs)) {
                self.epochs.store(Some(Arc::new(Epochs {
                    current: epochs.current.clone(), previous: None, switched: epochs.switched, holding: AtomicBool::new(false),
                })));
            }
        }
    }

    pub fn seal(&self, frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.seal_at(frame_type, payload, &Instant::now)
    }

    fn seal_at(&self, frame_type: u8, payload: &[u8], now: &impl Fn() -> Instant) -> Result<Vec<u8>, Error> {
        let (epochs, at) = self.epochs(now)?;
        match (&epochs.previous, at) {
            (Some(previous), Some(at)) if epochs.holding.load(Ordering::Acquire) && at < epochs.switched + SEND_HOLD => {
                previous.seal(frame_type, payload)
            }
            _ => epochs.current.seal(frame_type, payload),
        }
    }

    pub fn open(&self, frame: &[u8], expected: Option<u8>) -> Result<(u8, Vec<u8>), Error> {
        self.open_at(frame, expected, &Instant::now)
    }

    /// The header epoch picks the state: the previous epoch only while its grace is live; everything else,
    /// malformed frames included, goes to the current epoch's checks and keeps their rejections.
    fn open_at(&self, frame: &[u8], expected: Option<u8>, now: &impl Fn() -> Instant) -> Result<(u8, Vec<u8>), Error> {
        let (epochs, _) = self.epochs(now)?;
        if let Some(previous) = &epochs.previous {
            if frame.get(14..18) == Some(&previous.binding.epoch.to_be_bytes()[..]) {
                return previous.open(frame, expected);
            }
        }
        let opened = epochs.current.open(frame, expected)?;
        if epochs.holding.load(Ordering::Acquire) {
            epochs.holding.store(false, Ordering::Release);
        }
        Ok(opened)
    }

    /// Switch to `epoch` (must be current + 1): new keys, counter at 0, empty replay window. The old epoch stays
    /// for `RECEIVE_GRACE`, and the server (always the responder) keeps sealing under it for up to `SEND_HOLD`.
    pub fn rekey(&self, epoch: u32, send_key: &[u8], send_nonce_base: &[u8], recv_key: &[u8], recv_nonce_base: &[u8]) -> Result<(), Error> {
        let _writer = self.writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = self.epochs.load_full().ok_or(Error::Closed)?.current.clone();
        if current.binding.epoch.checked_add(1) != Some(epoch) {
            return Err(Error::Epoch);
        }
        let next = DataSession::new(self.role, &self.session_id, self.version, epoch, send_key, send_nonce_base, recv_key, recv_nonce_base)?;
        self.epochs.store(Some(Arc::new(Epochs {
            current: Arc::new(next), previous: Some(current), switched: Instant::now(),
            holding: AtomicBool::new(self.role == Role::Server),
        })));
        Ok(())
    }

    /// Drops this session's keys, the previous epoch's included; the last in-flight user frees them (aws-lc cleanses on free).
    pub fn close(&self) {
        let _writer = self.writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.epochs.store(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (DataSession, DataSession) {
        let (sid, c2s, s2c, nc, ns) = ([7; 32], [1; 32], [2; 32], [3; 12], [4; 12]);
        (DataSession::new(Role::Client, &sid, 0x20, 0, &c2s, &nc, &s2c, &ns).unwrap(),
         DataSession::new(Role::Server, &sid, 0x20, 0, &s2c, &ns, &c2s, &nc).unwrap())
    }

    #[test]
    fn roundtrip_replay_reflection_and_control_types() {
        let (client, server) = pair();
        let frame = client.seal(1, b"hello").unwrap();
        assert_eq!(server.open(&frame, None), Ok((1, b"hello".to_vec())));
        assert_eq!(server.open(&frame, None), Err(Error::Replayed));
        assert_eq!(client.open(&frame, None), Err(Error::Binding));
        assert_eq!(client.seal(7, b"config"), Err(Error::ControlType));
        let mut tampered = client.seal(1, b"x").unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(server.open(&tampered, None), Err(Error::Tag));
        assert_eq!(server.open(&tampered[..HEADER_LEN + TAG_LEN - 1], None), Err(Error::Short));
    }

    #[test]
    fn control_channel_is_strictly_in_order_and_separate_from_data() {
        let (sid, c2s, s2c, nc, ns) = ([7; 32], [1; 32], [2; 32], [3; 12], [4; 12]);
        let client = ControlChannel::new(Role::Client, &sid, 0x30, 0, &c2s, &nc, &s2c, &ns).unwrap();
        let server = ControlChannel::new(Role::Server, &sid, 0x30, 0, &s2c, &ns, &c2s, &nc).unwrap();
        assert_eq!(client.seal(1, b"data"), Err(Error::DataType));
        let (first, second) = (client.seal(8, b"one").unwrap(), client.seal(10, b"two").unwrap());
        assert_eq!(first[3], CHANNEL_CONTROL);
        assert_eq!(server.open(&second, None), Err(Error::ControlSequence));
        let mut tampered = first.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(server.open(&tampered, None), Err(Error::ControlTag));
        assert_eq!(server.open(&first, Some(9)), Err(Error::UnexpectedType));
        assert_eq!(server.open(&first, Some(8)), Ok((8, b"one".to_vec())), "failures did not advance the counter");
        assert_eq!(server.open(&first, None), Err(Error::ControlSequence), "a control frame opens once");
        assert_eq!(server.open(&second, None), Ok((10, b"two".to_vec())));
        let data = DataSession::new(Role::Server, &sid, 0x30, 0, &s2c, &ns, &c2s, &nc).unwrap();
        assert_eq!(data.open(&client.seal(7, b"cfg").unwrap(), None), Err(Error::Header), "control frames never open as data");
        *client.send_sequence.lock().unwrap() = u64::MAX;
        assert_eq!(client.seal(8, b"x"), Err(Error::Exhausted));
    }

    fn epoch_of(frame: &[u8]) -> (u32, u64) {
        (u32::from_be_bytes(frame[14..18].try_into().unwrap()), u64::from_be_bytes(frame[18..26].try_into().unwrap()))
    }

    #[test]
    fn rekey_keeps_one_previous_epoch_for_its_grace_and_close_is_final() {
        let (sid, c2s, s2c, nc, ns) = ([7; 32], [1; 32], [2; 32], [3; 12], [4; 12]);
        let client = Session::new(Role::Client, &sid, 0x20, 0, &c2s, &nc, &s2c, &ns).unwrap();
        let server = Session::new(Role::Server, &sid, 0x20, 0, &s2c, &ns, &c2s, &nc).unwrap();
        let (seen, old, older) = (client.seal(1, b"seen").unwrap(), client.seal(1, b"old").unwrap(), client.seal(1, b"older").unwrap());
        assert!(server.open(&seen, None).is_ok());
        assert_eq!(client.rekey(2, &c2s, &nc, &s2c, &ns), Err(Error::Epoch));
        client.rekey(1, &[5; 32], &nc, &[6; 32], &ns).unwrap();
        server.rekey(1, &[6; 32], &ns, &[5; 32], &nc).unwrap();
        let new = client.seal(1, b"new").unwrap();
        assert_eq!(epoch_of(&new), (1, 0), "counter restarts with the new key");
        assert_eq!(server.open(&seen, None), Err(Error::Replayed), "the previous epoch keeps its own replay window");
        assert_eq!(server.open(&old, None), Ok((1, b"old".to_vec())));
        assert_eq!(server.open(&old, None), Err(Error::Replayed));
        assert_eq!(server.open(&new, Some(4)), Err(Error::UnexpectedType));
        assert_eq!(server.open(&new, Some(1)), Ok((1, b"new".to_vec())));
        let after_grace = || Instant::now() + RECEIVE_GRACE;
        assert_eq!(server.open_at(&older, None, &after_grace), Err(Error::Binding), "N-1 after the grace");
        assert!(server.epochs.load().as_ref().unwrap().previous.is_none(), "the expired epoch is dropped");
        client.rekey(2, &c2s, &nc, &s2c, &ns).unwrap();
        server.rekey(2, &s2c, &ns, &c2s, &nc).unwrap();
        server.rekey(3, &[6; 32], &ns, &[5; 32], &nc).unwrap();
        assert_eq!(server.open(&client.seal(1, b"n-1").unwrap(), None).map(|(_, p)| p), Ok(b"n-1".to_vec()));
        let n_minus_2 = Session::new(Role::Client, &sid, 0x20, 1, &[5; 32], &nc, &[6; 32], &ns).unwrap().seal(1, b"x").unwrap();
        assert_eq!(server.open(&n_minus_2, None), Err(Error::Binding), "N-2 is never accepted");
        server.close();
        assert!(server.epochs.load().is_none(), "close drops the previous epoch too");
        assert_eq!(server.open(&new, None), Err(Error::Closed));
        assert_eq!(server.rekey(4, &s2c, &ns, &c2s, &nc), Err(Error::Closed));
    }

    /// The server keeps sealing with the previous epoch's key and counter until an authenticated frame at the new
    /// epoch arrives or `SEND_HOLD` passes; a second switch mid-hold moves the hold to the epoch it just left.
    #[test]
    fn responder_holds_its_old_send_epoch_until_the_client_proves_it_switched() {
        let (sid, c2s, s2c, nc, ns) = ([7; 32], [1; 32], [2; 32], [3; 12], [4; 12]);
        let client = Session::new(Role::Client, &sid, 0x20, 0, &c2s, &nc, &s2c, &ns).unwrap();
        let server = Session::new(Role::Server, &sid, 0x20, 0, &s2c, &ns, &c2s, &nc).unwrap();
        assert_eq!(epoch_of(&server.seal(1, b"a").unwrap()), (0, 0));
        let stale = client.seal(1, b"stale").unwrap();
        server.rekey(1, &[6; 32], &ns, &[5; 32], &nc).unwrap();
        client.rekey(1, &[5; 32], &nc, &[6; 32], &ns).unwrap();
        assert_eq!(epoch_of(&server.seal(1, b"b").unwrap()), (0, 1), "held: same key, same counter");
        let after_hold = || Instant::now() + SEND_HOLD;
        assert_eq!(epoch_of(&server.seal_at(1, b"c", &after_hold).unwrap()), (1, 0), "the hold times out");
        assert_eq!(epoch_of(&server.seal(1, b"d").unwrap()), (0, 2), "and only for that call's clock");
        let mut forged = client.seal(1, b"forged").unwrap();
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(server.open(&forged, None), Err(Error::Tag));
        assert!(server.open(&stale, None).is_ok());
        assert_eq!(epoch_of(&server.seal(1, b"e").unwrap()), (0, 3), "neither a forged N+1 nor an N frame promotes");
        server.rekey(2, &s2c, &ns, &c2s, &nc).unwrap();
        assert_eq!(epoch_of(&server.seal(1, b"f").unwrap()), (1, 1), "the hold moves to epoch 1; epoch 0 is gone");
        client.rekey(2, &c2s, &nc, &s2c, &ns).unwrap();
        assert!(server.open(&client.seal(1, b"up").unwrap(), None).is_ok());
        assert_eq!(epoch_of(&server.seal(1, b"g").unwrap()), (2, 0), "promoted");
        assert_eq!(client.open(&server.seal(1, b"h").unwrap(), None), Ok((1, b"h".to_vec())));
        client.rekey(3, &c2s, &nc, &s2c, &ns).unwrap();
        assert_eq!(epoch_of(&client.seal(1, b"i").unwrap()), (3, 0), "the client never holds");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// (d) At the top of the space the sender never wraps: it issues unique sequences up to
        /// u64::MAX - 1, then refuses forever, and the receiver accepts each issued frame exactly once.
        #[test]
        fn never_wraps_and_every_issued_frame_opens_once(headroom in 0u64..100, attempts in 1usize..150) {
            let (client, server) = pair();
            client.next_sequence.store(u64::MAX - headroom, Ordering::Relaxed);
            let frames: Vec<_> = (0..attempts).map(|_| client.seal(1, b"x")).collect();
            let issued = usize::try_from(headroom).unwrap().min(attempts);
            for (i, frame) in frames.iter().enumerate() {
                if i < issued {
                    let frame = frame.as_ref().unwrap();
                    let expected = u64::MAX - headroom + u64::try_from(i).unwrap();
                    proptest::prop_assert_eq!(&frame[18..26], &expected.to_be_bytes());
                    proptest::prop_assert!(server.open(frame, None).is_ok());
                    proptest::prop_assert_eq!(server.open(frame, None), Err(Error::Replayed));
                } else {
                    proptest::prop_assert_eq!(frame, &Err(Error::Exhausted));
                }
            }
        }
    }

    #[test]
    fn sender_refuses_at_top_of_sequence_space() {
        let (client, _) = pair();
        client.next_sequence.store(u64::MAX - 1, Ordering::Relaxed);
        assert!(client.seal(1, b"last").is_ok());
        assert_eq!(client.seal(1, b"none"), Err(Error::Exhausted));
        assert_eq!(client.seal(1, b"none"), Err(Error::Exhausted));
    }
}
