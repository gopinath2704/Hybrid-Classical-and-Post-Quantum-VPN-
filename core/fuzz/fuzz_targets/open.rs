#![no_main]
//! `Session::open` on arbitrary bytes: it must reject, never panic.
use pqvpn_core::session::{Role, Session};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let session = Session::new(Role::Server, &[7; 32], 0x20, 0, &[2; 32], &[4; 12], &[1; 32], &[3; 12]).unwrap();
    let expected = data.first().copied().filter(|t| t & 0x80 == 0);
    let _ = session.open(data, expected);
});
