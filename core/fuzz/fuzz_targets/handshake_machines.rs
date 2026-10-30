#![no_main]
//! The handshake state machines fed arbitrary bytes after a genuine prefix, from both sides (a malicious client and a
//! malicious server). They must reject, never panic. Byte 0: bits 0-2 pick the step, bit 3 the suite, and bit 4
//! "framed": the fuzzed payload gets a valid header, length and binding fields so it reaches the crypto.
use std::sync::{Arc, OnceLock};

use pqvpn_core::handshake::*;

const NOW: i64 = 1_800_000_000;

struct Fixture {
    server: Arc<Identity>,
    server_pk: Vec<u8>,
    v2_client: Arc<Identity>,
    v3_client: Arc<Identity>,
    v3_client_pk: Vec<u8>,
    tickets: TicketKey,
}

fn kem() -> (Arc<Identity>, Vec<u8>) {
    let (key, public) = Os.mlkem_keypair().unwrap();
    (Arc::new(Identity::kem(key.key_bytes().unwrap().as_ref(), &public).unwrap()), public)
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let ((server, server_pk), (v3_client, v3_client_pk)) = (kem(), kem());
        Fixture { server, server_pk, v2_client: Arc::new(Identity::ed25519(&[7; 32]).unwrap()), v3_client, v3_client_pk,
                  tickets: TicketKey::new(&mut Os).unwrap() }
    })
}

/// A message with a valid header around `payload` resized to `len`.
fn framed(version: u8, msg_type: u8, payload: &[u8], len: usize) -> Vec<u8> {
    let mut body = payload.to_vec();
    body.resize(len, 0);
    [&[0x48, 0x56, version, msg_type][..], &u16::try_from(len).unwrap().to_be_bytes(), &body].concat()
}

fn client(f: &Fixture, suite: Suite) -> ClientHandshake {
    let identity = if suite == Suite::V2 { f.v2_client.clone() } else { f.v3_client.clone() };
    let fingerprint_hex: String = fingerprint(&f.server_pk).iter().map(|b| format!("{b:02x}")).collect();
    ClientHandshake::new(suite, &f.server_pk, &fingerprint_hex, identity).unwrap()
}

fn store(f: &Fixture, suite: Suite) -> Option<&[u8]> {
    (suite == Suite::V3).then_some(&f.v3_client_pk[..])
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else { return };
    let f = fixture();
    let suite = if selector & 8 == 0 { Suite::V2 } else { Suite::V3 };
    let (version, framed_mode) = (suite.version(), selector & 16 != 0);
    let v3 = suite == Suite::V3;
    match selector & 7 {
        // A malicious ClientHello.
        0 => {
            let mut server = ServerHandshake::new(suite, f.server.clone()).unwrap();
            let wire = if framed_mode { framed(version, 1, input, ClientHello::SIZE) } else { input.to_vec() };
            if server.client_identity(&wire).is_ok() {
                let _ = server.respond(&mut Os, store(f, suite));
            }
        }
        // A genuine hello, then a malicious ClientKeyExchange.
        1 => {
            let mut c = client(f, suite);
            let mut server = ServerHandshake::new(suite, f.server.clone()).unwrap();
            server.client_identity(&c.hello(&mut Os).unwrap()).unwrap();
            server.respond(&mut Os, store(f, suite)).unwrap();
            let wire = if framed_mode { framed(version, 3, input, if v3 { 1120 } else { 1184 }) } else { input.to_vec() };
            assert!(server.on_key_exchange(&wire).is_err(), "a fuzzed key exchange cannot carry a valid Finished MAC");
        }
        // A malicious server: arbitrary ServerHello after a genuine ClientHello. Framed keeps session id and identity.
        2 => {
            let mut c = client(f, suite);
            let hello = c.hello(&mut Os).unwrap();
            let wire = if framed_mode {
                let mut w = framed(version, 2, input, if v3 { 2304 } else { 1216 });
                w[6 + 32..6 + 64].copy_from_slice(&ClientHello::parse(suite, &hello).unwrap().session_id[..]);
                w[6 + 1184..6 + 1216].copy_from_slice(&fingerprint(&f.server_pk));
                w
            } else {
                input.to_vec()
            };
            let _ = c.on_server_hello(&mut Os, &wire);
        }
        // A genuine exchange, then a malicious ServerFinished.
        3 => {
            let mut c = client(f, suite);
            let mut server = ServerHandshake::new(suite, f.server.clone()).unwrap();
            server.client_identity(&c.hello(&mut Os).unwrap()).unwrap();
            let reply = server.respond(&mut Os, store(f, suite)).unwrap();
            c.on_server_hello(&mut Os, &reply).unwrap();
            let wire = if framed_mode { framed(version, 4, input, 32) } else { input.to_vec() };
            assert!(c.on_server_finished(&wire).is_err());
        }
        // A malicious ResumptionHello; framed puts the fuzz bytes in the ticket of an otherwise valid hello.
        4 => {
            let wire = if framed_mode {
                let x = x25519_public(&Os.x25519().unwrap()).unwrap();
                let (_, ek) = Os.mlkem_keypair().unwrap();
                let ticket = &input[..input.len().min(4000)];
                ResumptionHello { client_random: &[1; 32], ticket, x25519: &x, mlkem_ek: ek[..].try_into().unwrap() }.pack(version).unwrap()
            } else {
                input.to_vec()
            };
            assert!(resume_server(&mut Os, &f.tickets, &wire, version, NOW).is_err(), "no fuzzed ticket opens under GCM");
        }
        // A malicious ResumptionAccept after a genuine ResumptionHello.
        _ => {
            let mut c = ResumeClient::new(version, zeroize::Zeroizing::new([9; 32]), vec![1; 80]);
            c.hello(&mut Os).unwrap();
            let wire = if framed_mode { framed(version, 8, input, ResumptionAccept::SIZE) } else { input.to_vec() };
            assert!(c.on_accept(&wire).is_err(), "a fuzzed accept cannot carry a valid resumption MAC");
        }
    }
});
