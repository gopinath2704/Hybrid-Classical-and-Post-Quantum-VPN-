#![forbid(unsafe_code)]
//! PQ-VPN Rust core. Keys go in; only ciphertext comes back out.

pub mod packet;
pub mod replay;
pub mod session;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

pub use session::{HEADER_LEN, KEY_LEN};

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
    let nonce = session::nonce(&<[u8; NONCE_LEN]>::try_from(nonce_base).map_err(|_| "nonce_base must be 12 bytes")?, sequence);
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

fn role(name: &str) -> PyResult<session::Role> {
    match name {
        "client" => Ok(session::Role::Client),
        "server" => Ok(session::Role::Server),
        _ => Err(PyValueError::new_err("role must be client or server")),
    }
}

fn kind(error: session::Error) -> PyErr {
    PyValueError::new_err(error.as_str())
}

/// Copies a secret straight from a Python buffer (e.g. a TrafficSecrets bytearray) into wiped-on-drop
/// memory, with no intermediate bytes object that the caller's wipe() could not reach.
fn secret<const N: usize>(py: Python<'_>, buffer: &PyBuffer<u8>) -> PyResult<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    buffer.copy_to_slice(py, &mut out[..]).map_err(|_| kind(session::Error::InvalidKey))?;
    Ok(out)
}

/// A session's data channel. Keys go in at construction and on rekey; there are no getters.
#[pyclass(frozen, name = "DataSession")]
struct PyDataSession(session::Session);

#[pymethods]
impl PyDataSession {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(py: Python<'_>, role_name: &str, session_id: &[u8], protocol_version: u8, epoch: u32, send_key: PyBuffer<u8>,
           send_nonce_base: PyBuffer<u8>, recv_key: PyBuffer<u8>, recv_nonce_base: PyBuffer<u8>) -> PyResult<Self> {
        let (sk, sn) = (secret::<32>(py, &send_key)?, secret::<12>(py, &send_nonce_base)?);
        let (rk, rn) = (secret::<32>(py, &recv_key)?, secret::<12>(py, &recv_nonce_base)?);
        session::Session::new(role(role_name)?, session_id, protocol_version, epoch, &sk[..], &sn[..], &rk[..], &rn[..])
            .map(Self)
            .map_err(kind)
    }

    fn rekey(&self, py: Python<'_>, epoch: u32, send_key: PyBuffer<u8>, send_nonce_base: PyBuffer<u8>,
             recv_key: PyBuffer<u8>, recv_nonce_base: PyBuffer<u8>) -> PyResult<()> {
        let (sk, sn) = (secret::<32>(py, &send_key)?, secret::<12>(py, &send_nonce_base)?);
        let (rk, rn) = (secret::<32>(py, &recv_key)?, secret::<12>(py, &recv_nonce_base)?);
        self.0.rekey(epoch, &sk[..], &sn[..], &rk[..], &rn[..]).map_err(kind)
    }

    fn close(&self) {
        self.0.close();
    }

    fn seal<'py>(&self, py: Python<'py>, frame_type: u8, payload: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        self.0.seal(frame_type, payload).map(|f| PyBytes::new(py, &f)).map_err(kind)
    }

    /// Returns (frame_type, plaintext); raises ValueError(kind) on rejection.
    #[pyo3(signature = (frame, expected_type=None))]
    fn open<'py>(&self, py: Python<'py>, frame: &[u8], expected_type: Option<u8>) -> PyResult<(u8, Bound<'py, PyBytes>)> {
        self.0.open(frame, expected_type).map(|(t, p)| (t, PyBytes::new(py, &p))).map_err(kind)
    }
}

/// Inner-packet check after decryption: server checks the source lease, client its destination.
#[pyfunction]
fn inbound_ok(role_name: &str, packet: &[u8], address: [u8; 4], mtu: usize) -> PyResult<bool> {
    Ok(match role(role_name)? {
        session::Role::Server => packet::server_accepts(packet, address, mtu),
        session::Role::Client => packet::client_accepts(packet, address, mtu),
    })
}

#[pymodule]
fn pqvpn_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_frame, m)?)?;
    m.add_function(wrap_pyfunction!(inbound_ok, m)?)?;
    m.add_class::<PyDataSession>()
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
    fn python_decrypt_op_scripts() {
        let scripts: Value = serde_json::from_str(include_str!("../../../tests/vectors/frame_decrypt.json")).unwrap();
        let scripts = scripts.as_array().unwrap();
        assert_eq!(scripts.len(), 4);
        for s in scripts {
            let role = if s["role"] == "client" { session::Role::Client } else { session::Role::Server };
            let rx = session::DataSession::new(role, &unhex(&s["session_id"]), u8::try_from(s["protocol_version"].as_u64().unwrap()).unwrap(),
                u32::try_from(s["epoch"].as_u64().unwrap()).unwrap(), &unhex(&s["send_key"]), &unhex(&s["send_nonce_base"]),
                &unhex(&s["recv_key"]), &unhex(&s["recv_nonce_base"])).unwrap();
            for op in s["ops"].as_array().unwrap() {
                let outcome = match rx.open(&unhex(&op["frame"]), None) {
                    Ok((t, p)) => format!("ok {t} {p:?}"),
                    Err(e) => e.as_str().to_string(),
                };
                let expected = match op["expect"].as_str().unwrap() {
                    "ok" => format!("ok {} {:?}", op["frame_type"], unhex(&op["plaintext"])),
                    kind => kind.to_string(),
                };
                assert_eq!(outcome, expected, "{} {}", s["name"], op["name"]);
            }
        }
    }

    fn pair() -> (session::DataSession, session::DataSession) {
        let (sid, c2s, s2c, nc, ns) = ([9; 32], [1; 32], [2; 32], [3; 12], [4; 12]);
        (session::DataSession::new(session::Role::Client, &sid, 0x30, 1, &c2s, &nc, &s2c, &ns).unwrap(),
         session::DataSession::new(session::Role::Server, &sid, 0x30, 1, &s2c, &ns, &c2s, &nc).unwrap())
    }

    #[test]
    fn concurrent_seal_never_reuses_a_sequence() {
        let (client, server) = pair();
        let mut frames: Vec<Vec<u8>> = std::thread::scope(|s| {
            let workers: Vec<_> = (0..8).map(|_| s.spawn(|| (0..500).map(|_| client.seal(1, b"x").unwrap()).collect::<Vec<_>>())).collect();
            workers.into_iter().flat_map(|w| w.join().unwrap()).collect()
        });
        let sequences: std::collections::HashSet<_> = frames.iter().map(|f| f[18..26].to_vec()).collect();
        assert_eq!(sequences.len(), 4000);
        frames.sort_by(|a, b| a[18..26].cmp(&b[18..26]));
        assert!(frames.iter().all(|f| server.open(f, None).is_ok()));
    }

    #[test]
    fn concurrent_duplicate_opens_exactly_once() {
        let (client, server) = pair();
        for _ in 0..200 {
            let frame = client.seal(1, b"once").unwrap();
            let results: Vec<_> = std::thread::scope(|s| {
                let workers: Vec<_> = (0..4).map(|_| s.spawn(|| server.open(&frame, None))).collect();
                workers.into_iter().map(|w| w.join().unwrap()).collect()
            });
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            assert!(results.iter().filter(|r| r.is_err()).all(|r| *r == Err(session::Error::Replayed)));
        }
    }

    #[test]
    fn other_session_and_old_epoch_rejected() {
        let (client, _) = pair();
        let (sid, c2s, s2c, nc, ns) = ([9; 32], [1; 32], [2; 32], [3; 12], [4; 12]);
        let next_epoch = session::DataSession::new(session::Role::Server, &sid, 0x30, 2, &s2c, &ns, &c2s, &nc).unwrap();
        let other = session::DataSession::new(session::Role::Server, &[8; 32], 0x30, 1, &s2c, &ns, &c2s, &nc).unwrap();
        let frame = client.seal(1, b"old").unwrap();
        assert_eq!(next_epoch.open(&frame, None), Err(session::Error::Binding));
        assert_eq!(other.open(&frame, None), Err(session::Error::Binding));
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
