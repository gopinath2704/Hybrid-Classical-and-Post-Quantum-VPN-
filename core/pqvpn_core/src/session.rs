//! Data-channel record layer for one session epoch, mirroring `HandshakeSession`
//! `_encrypt`/`_decrypt` for `Channel.DATA` in handshake/kemtls.py. No I/O.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::replay::{Reject, ReplayWindow};

/// `struct.calcsize("!2sBBBB8sIQ")`.
pub const HEADER_LEN: usize = 26;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
const MAGIC: [u8; 2] = *b"PV";
const CHANNEL_DATA: u8 = 1;
/// FrameType values 1..=13 exist; only DATA..=PONG may be sealed on the data channel.
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
    ControlType,
    Exhausted,
    Short,
    Header,
    FrameType,
    Binding,
    Replayed,
    OutsideWindow,
    Tag,
}

impl Error {
    pub fn as_str(self) -> &'static str {
        match self {
            Error::InvalidKey => "invalid_key",
            Error::ControlType => "control_type",
            Error::Exhausted => "exhausted",
            Error::Short => "short",
            Error::Header => "header",
            Error::FrameType => "frame_type",
            Error::Binding => "binding",
            Error::Replayed => "replayed",
            Error::OutsideWindow => "outside_window",
            Error::Tag => "tag",
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

pub struct DataSession {
    session_id: [u8; 8],
    version: u8,
    epoch: u32,
    send_direction: u8,
    recv_direction: u8,
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
        if session_id.len() != 32 {
            return Err(Error::InvalidKey);
        }
        let (send_direction, recv_direction) = match role {
            Role::Client => (1, 2),
            Role::Server => (2, 1),
        };
        Ok(Self {
            session_id: session_id[..8].try_into().map_err(|_| Error::InvalidKey)?,
            version,
            epoch,
            send_direction,
            recv_direction,
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
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&[self.version, CHANNEL_DATA, frame_type, self.send_direction]);
        frame.extend_from_slice(&self.session_id);
        frame.extend_from_slice(&self.epoch.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(payload);
        let (header, body) = frame.split_at_mut(HEADER_LEN);
        let tag = self
            .send_key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce(&self.send_nonce_base, sequence)), Aad::from(&*header), body)
            .map_err(|_| Error::Tag)?;
        frame.extend_from_slice(tag.as_ref());
        Ok(frame)
    }

    pub fn open(&self, frame: &[u8]) -> Result<(u8, Vec<u8>), Error> {
        if frame.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Short);
        }
        let (header, sealed) = frame.split_at(HEADER_LEN);
        if header[..2] != MAGIC || header[2] != self.version || header[3] != CHANNEL_DATA {
            return Err(Error::Header);
        }
        let frame_type = header[4];
        if !(1..=MAX_FRAME_TYPE).contains(&frame_type) {
            return Err(Error::FrameType);
        }
        let epoch = u32::from_be_bytes(header[14..18].try_into().map_err(|_| Error::Header)?);
        if header[6..14] != self.session_id || epoch != self.epoch || header[5] != self.recv_direction {
            return Err(Error::Binding);
        }
        let sequence = u64::from_be_bytes(header[18..26].try_into().map_err(|_| Error::Header)?);
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
        assert_eq!(server.open(&frame), Ok((1, b"hello".to_vec())));
        assert_eq!(server.open(&frame), Err(Error::Replayed));
        assert_eq!(client.open(&frame), Err(Error::Binding));
        assert_eq!(client.seal(7, b"config"), Err(Error::ControlType));
        let mut tampered = client.seal(1, b"x").unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(server.open(&tampered), Err(Error::Tag));
        assert_eq!(server.open(&tampered[..HEADER_LEN + TAG_LEN - 1]), Err(Error::Short));
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
