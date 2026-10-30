//! Conformance against the real Python server (tests/conformance.py) inside `unshare -rn`: no sudo.
//! Rows: the Python handshake server on PYTHON (default python3), and the Rust handshake server on
//! PQVPND_RUST_SERVER_PYTHON, a Python with the current pqvpn_core (row skipped, and said so, if unset).
//! Prints SKIP and passes when user namespaces are unavailable.

use std::path::Path;
use std::process::Command;

fn run(python: &str, server_handshake: &str, server_plane: &str) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/conformance.py");
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let probe = Command::new("unshare").args(["-rn", "true"]).status();
    if !probe.is_ok_and(|status| status.success()) {
        println!("SKIP conformance: user namespaces unavailable");
        std::process::exit(0);
    }
    let status = Command::new("unshare").args(["-rn", python]).arg(&script).arg(env!("CARGO_BIN_EXE_pqvpnd")).arg(&repo)
        .args([server_handshake, server_plane, "2,3"]).env("PYTHONDONTWRITEBYTECODE", "1").status()
        .expect("run unshare");
    assert!(status.success(), "conformance with server handshake={server_handshake} data_plane={server_plane}: {status}");
}

fn main() {
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".into());
    run(&python, "python", "python");
    match std::env::var("PQVPND_RUST_SERVER_PYTHON") {
        Ok(rust_python) => run(&rust_python, "rust", "rust"),
        Err(_) => println!("SKIP conformance row server handshake=rust: set PQVPND_RUST_SERVER_PYTHON to a Python with current pqvpn_core"),
    }
}
