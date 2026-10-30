#![no_main]
//! Every handshake decoder on arbitrary bytes, plus the ticket plaintext parser: each must reject or accept without
//! panicking, and anything accepted must re-encode to exactly the bytes it came from.
//! The first byte picks the decoder (bits 1-3) and the suite (bit 0); the rest is the input.
use pqvpn_core::handshake::*;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&selector, wire)) = data.split_first() else { return };
    let suite = if selector & 1 == 0 { Suite::V2 } else { Suite::V3 };
    let version = suite.version();
    match (selector >> 1) & 7 {
        0 => if let Ok(m) = ClientHello::parse(suite, wire) { assert_eq!(m.pack(suite).unwrap(), wire) },
        1 => if let Ok(m) = ServerHello::parse(suite, wire) { assert_eq!(m.pack(suite).unwrap(), wire) },
        2 => if let Ok(m) = KeyExchange::parse(suite, wire) { assert_eq!(m.pack(suite).unwrap(), wire) },
        3 => if let Ok(f) = parse_server_finished(suite, wire) { assert_eq!(pack_server_finished(suite, f).unwrap(), wire) },
        4 => if let Ok(m) = ResumptionHello::parse(version, wire) { assert_eq!(m.pack(version).unwrap(), wire) },
        5 => if let Ok(m) = ResumptionAccept::parse(version, wire) { assert_eq!(m.pack(version).unwrap(), wire) },
        6 => {
            if let Ok(cookie) = parse_cookie_challenge(wire) {
                assert!(cookie.len() <= COOKIE_LEN);
                let response = cookie_response(version, cookie, wire);
                assert_eq!(response.is_ok(), cookie.len() == COOKIE_LEN && wire.len() <= 65_535 - COOKIE_LEN);
            }
        }
        _ => fuzz_ticket_plaintext(wire, 1_800_000_000),
    }
});
