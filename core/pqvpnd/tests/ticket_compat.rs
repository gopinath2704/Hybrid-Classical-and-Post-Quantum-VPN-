//! pqvpnd and the Python client share one ticket file (`.pqvpn_ticket.json` next to the client key): the same
//! bytes in both directions, through `pqvpn_core::handshake` on this side and `VPNClient` on the other.

use std::path::{Path, PathBuf};
use std::process::Command;

use pqvpn_core::handshake::{load_ticket, save_ticket};

const FP: &str = "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";
const TICKET: &[u8] = b"opaque \x00\xff ticket bytes";
const SECRET: [u8; 32] = [0x5a; 32];

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pqvpnd-ticket-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Runs `VPNClient` in python3 against `dir/client.key`'s ticket path.
fn python(dir: &Path, action: &str) -> String {
    let script = format!(
        "import sys\nsys.path.insert(0, {root:?})\nfrom vpn.config import ClientConfig\nfrom vpn.runtime import VPNClient\n\
         c = VPNClient(ClientConfig(server_identity_fingerprint={FP:?}, protocol_version=3, \
         client_identity_private_key={key:?}))\n{action}\n",
        root = repo_root().to_str().unwrap(), key = dir.join("client.key").to_str().unwrap());
    let output = Command::new(std::env::var("PYTHON").unwrap_or_else(|_| "python3".into()))
        .arg("-c").arg(script).env("ALLOW_MOCK_PQC", "1").output().expect("python3 is needed for this test");
    assert!(output.status.success(), "python failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn python_and_rust_write_identical_files_and_read_each_other() {
    let (py_dir, rs_dir) = (temp_dir("py"), temp_dir("rs"));
    python(&py_dir, &format!("c._save_ticket(bytes.fromhex({:?}), bytes.fromhex({:?}), c.cfg.server_identity_fingerprint)",
                             hex(TICKET), hex(&SECRET)));
    save_ticket(&rs_dir.join(".pqvpn_ticket.json"), FP, 3, TICKET, &SECRET).unwrap();
    let (py_file, rs_file) = (std::fs::read(py_dir.join(".pqvpn_ticket.json")).unwrap(),
                              std::fs::read(rs_dir.join(".pqvpn_ticket.json")).unwrap());
    assert_eq!(String::from_utf8_lossy(&py_file), String::from_utf8_lossy(&rs_file), "byte-identical ticket files");

    // Rust reads Python's file, Python reads Rust's.
    let (ticket, secret) = load_ticket(&py_dir.join(".pqvpn_ticket.json"), FP, 3).unwrap();
    assert_eq!((ticket.as_slice(), *secret), (TICKET, SECRET));
    let read = python(&rs_dir, "t, s = c._load_ticket(c.cfg.server_identity_fingerprint); print(t.hex(), s.hex())");
    // liboqs-python prints a banner on stdout at import; the answer is the last line.
    assert_eq!(read.lines().last().unwrap_or(""), format!("{} {}", hex(TICKET), hex(&SECRET)));
    for dir in [py_dir, rs_dir] {
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn failed_save_leaves_no_temp_file_and_reader_refuses_symlinks() {
    let dir = temp_dir("fail");
    // The rename fails onto a non-empty directory, after the temp file was written and synced.
    let target = dir.join(".pqvpn_ticket.json");
    std::fs::create_dir_all(target.join("occupied")).unwrap();
    assert!(save_ticket(&target, FP, 2, TICKET, &SECRET).is_err());
    let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names, [".pqvpn_ticket.json"], "only the pre-existing directory remains, no .tmp");

    std::fs::remove_dir_all(&target).unwrap();
    let real = dir.join("real.json");
    save_ticket(&real, FP, 2, TICKET, &SECRET).unwrap();
    std::os::unix::fs::symlink(&real, &target).unwrap();
    assert!(load_ticket(&target, FP, 2).is_none(), "the ticket path is never followed through a symlink");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
