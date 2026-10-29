#![no_main]
//! Both roles' UDP and TUN dispatch on arbitrary bytes; see `dataplane::fuzz_dispatch`.
libfuzzer_sys::fuzz_target!(|data: &[u8]| pqvpn_core::dataplane::fuzz_dispatch(data));
