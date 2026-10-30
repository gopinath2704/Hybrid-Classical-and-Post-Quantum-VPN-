//! Key schedule, mirroring handshake/kemtls.py (`_expand`, `_derive_secrets`, `derive_schedule*`,
//! `derive_next_epoch`, `derive_rehandshake_epoch`) and the Finished/confirmation HMACs. Byte quirks kept on purpose:
//! the v2 protocol name is in every expand label for every suite, the resume context hard-codes 0x30, and the
//! rehandshake seed is plain SHA-256 rather than HKDF.

use aws_lc_rs::{digest, hkdf, hmac};
use zeroize::Zeroizing;

/// `PROTOCOL_NAME`: the v2 name, used by `_expand` for all suites.
pub const PROTOCOL_NAME: &[u8] = b"PQVPN-KEMTLS-INSPIRED-v2";
const PROTOCOL_NAME_V3: &[u8] = b"PQVPN-KEMTLS-v3";
const RESUMPTION_PROTOCOL: &[u8] = b"PQVPN-RESUME";
const SUITE: &[u8] = b"|X25519|ML-KEM-768|AES-256-GCM|";
pub const VERSION_V2: u8 = 0x20;
pub const VERSION_V3: u8 = 0x30;

pub const CLIENT_FINISHED: &[u8] = b"client finished";
pub const SERVER_FINISHED: &[u8] = b"server finished";
pub const RESUME_FINISHED: &[u8] = b"pqvpn resume finished";

type Key = Zeroizing<[u8; 32]>;
type NonceBase = Zeroizing<[u8; 12]>;

/// The 12 secrets of one epoch, in `_SECRET_SPECS` order. No `Debug`, no getters outside the crate.
pub struct Secrets {
    pub(crate) client_finished: Key,
    pub(crate) server_finished: Key,
    pub(crate) data_c2s_key: Key,
    pub(crate) data_s2c_key: Key,
    pub(crate) data_c2s_nonce: NonceBase,
    pub(crate) data_s2c_nonce: NonceBase,
    pub(crate) control_c2s_key: Key,
    pub(crate) control_s2c_key: Key,
    pub(crate) control_c2s_nonce: NonceBase,
    pub(crate) control_s2c_nonce: NonceBase,
    pub(crate) rekey: Key,
    pub(crate) control_confirm: Key,
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// aws-lc-rs has no write-to-buffer digest, so the `Digest` it returns is a stack copy we cannot wipe. That matters
/// only where the input is secret: the rehandshake seed and the v3 auth salt.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    parts.iter().for_each(|p| context.update(p));
    context.finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
}

fn fill(okm: Result<hkdf::Okm<'_, Len>, aws_lc_rs::error::Unspecified>, out: &mut [u8]) {
    // Lengths are 12 or 32, far below HKDF's 255 * 32 limit, so neither call can fail.
    okm.and_then(|okm| okm.fill(out)).expect("HKDF output length is valid");
}

/// `_expand`: HKDF-Expand(prk, PROTOCOL_NAME | label | context). Every output is at most 32 bytes, so this is one
/// block, T(1) = HMAC(prk, info ‖ 0x01) (RFC 5869 §2.3), written straight into a wiped buffer. aws-lc-rs's
/// expand-only `Prk::new_less_safe` would keep an unwiped copy of the PRK, which is the epoch's root secret.
fn expand<const N: usize>(prk: &[u8], label: &[u8], context: &[u8]) -> Zeroizing<[u8; N]> {
    const { assert!(N <= 32) };
    let info = [PROTOCOL_NAME, b"|", label, b"|", context, &[1]].concat();
    let mut block = Zeroizing::new([0u8; 32]);
    hmac::sign_to_buffer(&hmac::Key::new(hmac::HMAC_SHA256, prk), &info, &mut block[..]).expect("32-byte buffer fits HMAC-SHA256");
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(&block[..N]);
    out
}

/// `KeyManager.derive_key`: full HKDF-SHA256 (extract, then expand to 32 bytes).
fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    fill(prk.expand(&[info], Len(32)), &mut out[..]);
    out
}

/// `_derive_secrets(seed, context)`, boxed so moving an epoch's secrets never copies them.
fn secrets(seed: &[u8], context: &[u8]) -> Box<Secrets> {
    Box::new(Secrets {
        client_finished: expand(seed, b"client finished", context),
        server_finished: expand(seed, b"server finished", context),
        data_c2s_key: expand(seed, b"data c2s key", context),
        data_s2c_key: expand(seed, b"data s2c key", context),
        data_c2s_nonce: expand(seed, b"data c2s nonce", context),
        data_s2c_nonce: expand(seed, b"data s2c nonce", context),
        control_c2s_key: expand(seed, b"control c2s key", context),
        control_s2c_key: expand(seed, b"control s2c key", context),
        control_c2s_nonce: expand(seed, b"control c2s nonce", context),
        control_s2c_nonce: expand(seed, b"control s2c nonce", context),
        rekey: expand(seed, b"rekey", context),
        control_confirm: expand(seed, b"control confirm", context),
    })
}

/// The handshake inputs every suite shares.
pub struct Randoms<'a> {
    pub client_random: &'a [u8; 32],
    pub server_random: &'a [u8; 32],
    pub session_id: &'a [u8; 32],
    /// SHA-256 of ClientHello ‖ ServerHello (or of the resumption transcript).
    pub transcript_hash: &'a [u8; 32],
}

impl Randoms<'_> {
    fn context(&self, name: &[u8], version: u8) -> Vec<u8> {
        [name, &[version], SUITE, self.session_id, self.client_random, self.server_random, self.transcript_hash].concat()
    }

    fn salt(&self, label: &[u8]) -> [u8; 32] {
        sha256(&[label, self.client_random, self.server_random, self.session_id])
    }
}

/// `derive_schedule` (v2): ikm = x25519 ‖ ephemeral ML-KEM ‖ server-identity ML-KEM.
pub fn v2(r: &Randoms<'_>, x25519: &[u8; 32], k_eph: &[u8; 32], k_identity: &[u8; 32]) -> Box<Secrets> {
    let ikm = Zeroizing::new([&x25519[..], k_eph, k_identity].concat());
    let master = derive_key(&ikm, &r.salt(b"pqvpn extract"), b"pqvpn master secret");
    secrets(&master[..], &r.context(PROTOCOL_NAME, VERSION_V2))
}

/// `derive_schedule_v3`: k_s is the client→server-identity encapsulation, k_c the server→client-static one.
pub fn v3(r: &Randoms<'_>, x25519: &[u8; 32], k_eph: &[u8; 32], k_s: &[u8; 32], k_c: &[u8; 32]) -> Box<Secrets> {
    let handshake = derive_key(&Zeroizing::new([&x25519[..], k_eph].concat()), &r.salt(b"pqvpn extract"), b"pqvpn v3 handshake secret");
    let auth_salt = Zeroizing::new(sha256(&[&handshake[..], r.transcript_hash]));
    let ikm = Zeroizing::new([&handshake[..], k_s, k_c].concat());
    let master = derive_key(&ikm, &auth_salt[..], b"pqvpn v3 authenticated master");
    secrets(&master[..], &r.context(PROTOCOL_NAME_V3, VERSION_V3))
}

/// `derive_schedule_resume`. Its context always carries 0x30, even when a v2 session resumes.
pub fn resume(r: &Randoms<'_>, resumption_secret: &[u8; 32], x25519: &[u8; 32], kem: &[u8; 32]) -> Box<Secrets> {
    let ikm = Zeroizing::new([&resumption_secret[..], x25519, kem].concat());
    let master = derive_key(&ikm, &r.salt(b"pqvpn resume"), b"pqvpn resume master secret");
    secrets(&master[..], &r.context(RESUMPTION_PROTOCOL, VERSION_V3))
}

/// `derive_next_epoch`: the symmetric rekey. The caller checks `epoch == current + 1`.
pub fn next_epoch(rekey_secret: &[u8; 32], session_id: &[u8; 32], epoch: u32, nonce: &[u8; 32]) -> Box<Secrets> {
    let context = [&session_id[..], &epoch.to_be_bytes(), nonce].concat();
    let seed: Key = expand(rekey_secret, b"epoch", &context);
    secrets(&seed[..], &context)
}

/// `derive_rehandshake_epoch`. The seed is plain SHA-256, not HKDF. The caller checks the epoch.
pub fn rehandshake_epoch(rekey_secret: &[u8; 32], session_id: &[u8; 32], epoch: u32, dh: &[u8; 32], kem: &[u8; 32],
                         transcript: &[u8]) -> Option<Box<Secrets>> {
    if transcript.is_empty() {
        return None;
    }
    let context = [&session_id[..], &epoch.to_be_bytes(), &sha256(&[transcript])].concat();
    let seed = Zeroizing::new(sha256(&[rekey_secret, dh, kem, &epoch.to_be_bytes()]));
    Some(secrets(&seed[..], &context))
}

fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut context = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, key));
    parts.iter().for_each(|p| context.update(p));
    context.sign().as_ref().try_into().expect("HMAC-SHA256 is 32 bytes")
}

fn verify(key: &[u8; 32], parts: &[&[u8]], tag: &[u8]) -> bool {
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &parts.concat(), tag).is_ok()
}

/// `_compute_finished_mac`: HMAC(key, label ‖ digest).
pub fn finished(key: &[u8; 32], label: &[u8], digest: &[u8; 32]) -> [u8; 32] {
    mac(key, &[label, digest])
}

/// `_verify_finished_mac`, constant time.
pub fn verify_finished(key: &[u8; 32], label: &[u8], digest: &[u8; 32], tag: &[u8]) -> bool {
    verify(key, &[label, digest], tag)
}

/// REKEY_RESPONSE confirmation under the **old** epoch's control_confirm key (runtime.py:583).
pub fn rekey_confirmation(old_confirm: &[u8; 32], request: &[u8]) -> [u8; 32] {
    mac(old_confirm, &[b"rekey response", request])
}

pub fn verify_rekey_confirmation(old_confirm: &[u8; 32], request: &[u8], tag: &[u8]) -> bool {
    verify(old_confirm, &[b"rekey response", request], tag)
}

/// REHANDSHAKE_RESPONSE confirmation under the **new** epoch's control_confirm key (runtime.py:606).
pub fn rehandshake_confirmation(new_confirm: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    mac(new_confirm, &[b"rehandshake confirm", transcript])
}

pub fn verify_rehandshake_confirmation(new_confirm: &[u8; 32], transcript: &[u8], tag: &[u8]) -> bool {
    verify(new_confirm, &[b"rehandshake confirm", transcript], tag)
}

/// SHA-256, for transcripts and the Finished inputs that hash `digest ‖ partial`.
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    sha256(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finished_labels_separate_and_tamper_fails() {
        let (key, digest) = ([1u8; 32], [2u8; 32]);
        let tag = finished(&key, CLIENT_FINISHED, &digest);
        assert!(verify_finished(&key, CLIENT_FINISHED, &digest, &tag));
        assert!(!verify_finished(&key, SERVER_FINISHED, &digest, &tag));
        assert!(!verify_finished(&key, CLIENT_FINISHED, &digest, &tag[..31]));
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!verify_finished(&key, CLIENT_FINISHED, &digest, &bad));
    }

    #[test]
    fn rehandshake_refuses_an_empty_transcript() {
        assert!(rehandshake_epoch(&[1; 32], &[2; 32], 1, &[3; 32], &[4; 32], b"").is_none());
        assert!(rehandshake_epoch(&[1; 32], &[2; 32], 1, &[3; 32], &[4; 32], b"t").is_some());
    }
}
