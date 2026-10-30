#![no_main]
//! An established session's control paths on arbitrary bytes: the server's respond_rekey / respond_rehandshake, both
//! sides' open_control, and the client's finish_* after a genuine request. Nothing may panic, and a failed epoch
//! change must leave both sides at epoch 0. Byte 0: bits 0-2 pick the path, bit 3 the suite, bit 4 "framed"
//! (the right length and next-epoch prefix, so the input reaches the key exchange and the MAC check).
use std::sync::{Arc, OnceLock};

use pqvpn_core::handshake::*;

struct Fixture {
    server: Arc<Identity>,
    server_pk: Vec<u8>,
    v2_client: Arc<Identity>,
    v3_client: Arc<Identity>,
    v3_client_pk: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let kem = || {
            let (key, public) = Os.mlkem_keypair().unwrap();
            (Arc::new(Identity::kem(key.key_bytes().unwrap().as_ref(), &public).unwrap()), public)
        };
        let ((server, server_pk), (v3_client, v3_client_pk)) = (kem(), kem());
        Fixture { server, server_pk, v2_client: Arc::new(Identity::ed25519(&[7; 32]).unwrap()), v3_client, v3_client_pk }
    })
}

/// A real handshake: (client, server) at epoch 0.
fn established(f: &Fixture, suite: Suite) -> (Established, Established) {
    let identity = if suite == Suite::V2 { f.v2_client.clone() } else { f.v3_client.clone() };
    let fingerprint_hex: String = fingerprint(&f.server_pk).iter().map(|b| format!("{b:02x}")).collect();
    let mut client = ClientHandshake::new(suite, &f.server_pk, &fingerprint_hex, identity).unwrap();
    let mut server = ServerHandshake::new(suite, f.server.clone()).unwrap();
    server.client_identity(&client.hello(&mut Os).unwrap()).unwrap();
    let reply = server.respond(&mut Os, (suite == Suite::V3).then_some(&f.v3_client_pk[..])).unwrap();
    let (finished, server) = server.on_key_exchange(&client.on_server_hello(&mut Os, &reply).unwrap()).unwrap();
    (client.on_server_finished(&finished).unwrap(), server)
}

/// `input` resized to `len` with the next epoch (1) in its first four bytes.
fn next_epoch(input: &[u8], len: usize) -> Vec<u8> {
    let mut body = input.to_vec();
    body.resize(len, 0);
    body[..4].copy_from_slice(&1u32.to_be_bytes());
    body
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else { return };
    let suite = if selector & 8 == 0 { Suite::V2 } else { Suite::V3 };
    let framed = selector & 16 != 0;
    let (mut c, mut s) = established(fixture(), suite);
    let payload = |len: usize| if framed { next_epoch(input, len) } else { input.to_vec() };
    match selector & 7 {
        // Any 36 bytes with the next epoch are a valid rekey request: the server rekeys, and must stay consistent.
        0 => {
            let request = payload(36);
            if s.respond_rekey(&request).is_ok() {
                assert_eq!(s.epoch(), 1);
            } else {
                assert_eq!(s.epoch(), 0);
            }
        }
        // Framed, these reach X25519 with the fuzzer's key and ML-KEM encapsulation to the fuzzer's key.
        1 => {
            let ok = s.respond_rehandshake(&mut Os, &payload(4 + 32 + 1184)).is_ok();
            assert_eq!(s.epoch(), u32::from(ok));
        }
        2 => {
            let _ = s.open_control(input, input.first().copied());
        }
        3 => {
            let _ = c.open_control(input, None);
        }
        // A genuine request, then a forged confirmation: it cannot verify, so nothing activates.
        4 => {
            c.begin_rekey(&mut Os).unwrap();
            assert!(c.finish_rekey(&payload(36)).is_err());
            assert_eq!(c.epoch(), 0);
        }
        5 => {
            c.begin_rehandshake(&mut Os).unwrap();
            assert!(c.finish_rehandshake(&payload(4 + 32 + 1088 + 32)).is_err());
            assert_eq!(c.epoch(), 0);
        }
        // What one side seals, the other opens to the same bytes; control types only.
        _ => {
            let Some((&frame_type, body)) = input.split_first() else { return };
            match c.seal_control(frame_type, body) {
                Ok(frame) => assert_eq!(s.open_control(&frame, Some(frame_type)).unwrap(), (frame_type, body.to_vec())),
                Err(_) => assert!(!(6..=13).contains(&frame_type)),
            }
        }
    }
});
