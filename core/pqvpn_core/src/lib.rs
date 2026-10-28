#![forbid(unsafe_code)]
//! PQ-VPN Rust core. Keys go in; only ciphertext comes back out.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

/// `struct.calcsize("!2sBBBB8sIQ")` in handshake/kemtls.py.
pub const HEADER_LEN: usize = 26;
pub const KEY_LEN: usize = 32;

/// Matches `HandshakeSession._encrypt`: nonce = base XOR (0u32 || seq u64 BE),
/// AAD = packed header. Returns ciphertext || tag (the caller prepends the header).
pub fn seal(key: &[u8], nonce_base: &[u8], header: &[u8], sequence: u64, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if key.len() != KEY_LEN {
        return Err("key must be 32 bytes");
    }
    if header.len() != HEADER_LEN {
        return Err("header must be 26 bytes");
    }
    if sequence == u64::MAX {
        return Err("sequence exhausted; rekey required");
    }
    let mut nonce = Zeroizing::new(<[u8; NONCE_LEN]>::try_from(nonce_base).map_err(|_| "nonce_base must be 12 bytes")?);
    for (n, s) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *n ^= s;
    }
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| "invalid key")?);
    let mut out = plaintext.to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(header), &mut out)
        .map_err(|_| "encryption failed")?;
    Ok(out)
}

#[pyfunction]
fn encrypt_frame<'py>(py: Python<'py>, key: &[u8], nonce_base: &[u8], header: &[u8], sequence: u64, plaintext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    seal(key, nonce_base, header, sequence, plaintext)
        .map(|ct| PyBytes::new(py, &ct))
        .map_err(PyValueError::new_err)
}

#[pymodule]
fn pqvpn_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_frame, m)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn unhex(v: &Value) -> Vec<u8> {
        let s = v.as_str().unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn python_known_answer_vectors() {
        let vectors: Value = serde_json::from_str(include_str!("../../../tests/vectors/frame_encrypt.json")).unwrap();
        let vectors = vectors.as_array().unwrap();
        assert_eq!(vectors.len(), 12);
        for v in vectors {
            let header = unhex(&v["header"]);
            let ct = seal(&unhex(&v["key"]), &unhex(&v["nonce_base"]), &header, v["sequence"].as_u64().unwrap(), &unhex(&v["plaintext"])).unwrap();
            assert_eq!([header, ct].concat(), unhex(&v["frame"]), "{}", v["name"]);
        }
    }

    #[test]
    fn rejects_bad_input() {
        let (k, n, h) = ([0u8; 32], [0u8; 12], [0u8; HEADER_LEN]);
        assert!(seal(&k[..31], &n, &h, 0, b"").is_err());
        assert!(seal(&k, &n[..11], &h, 0, b"").is_err());
        assert!(seal(&k, &n, &h[..25], 0, b"").is_err());
        assert!(seal(&k, &n, &h, u64::MAX, b"").is_err());
        assert!(seal(&k, &n, &h, u64::MAX - 1, b"").is_ok());
    }
}
