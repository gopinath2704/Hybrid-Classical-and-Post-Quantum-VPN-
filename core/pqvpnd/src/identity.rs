//! Identity files for `pqvpnd connect`, read with the same rules as the Python client and built on
//! `pqvpn_core::handshake`, so private keys are only ever held in zeroizing buffers.

use std::fmt;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;

use pqvpn_core::handshake::{EK_LEN, Identity, fingerprint, read_private};

use crate::config::ClientConfig;

#[derive(Debug)]
pub struct IdentityError(pub String);

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IdentityError {}

/// The pinned server identity and this client's long-term identity.
pub struct Identities {
    pub server_public: Box<[u8; EK_LEN]>,
    pub client: Arc<Identity>,
}

/// Never prints key material.
impl fmt::Debug for Identities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identities { .. }")
    }
}

/// `_read_public_file`: no symlinks, a regular file, at most `maximum` bytes.
pub fn read_public(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc_flags()).open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "public key must be a regular file"));
    }
    let mut data = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut data)?;
    if data.len() > maximum {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "public key size is out of bounds"));
    }
    Ok(data)
}

fn libc_flags() -> i32 {
    nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_NONBLOCK.bits()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Loads both identities. The server key must match the configured fingerprint (the client's only trust
/// anchor), and the client key must have the length and, for v3, the keypair consistency Python requires.
pub fn load(cfg: &ClientConfig) -> Result<Identities, IdentityError> {
    let fail = |what: &str, path: &Path, error: &dyn fmt::Display| IdentityError(format!("{what} {}: {error}", path.display()));
    let server = read_public(&cfg.server_identity_public_key, EK_LEN)
        .map_err(|e| fail("cannot read server identity", &cfg.server_identity_public_key, &e))?;
    let server_public: Box<[u8; EK_LEN]> = Box::new(server.as_slice().try_into().map_err(|_| {
        IdentityError(format!("server identity {} must be exactly {EK_LEN} bytes", cfg.server_identity_public_key.display()))
    })?);
    if hex(&fingerprint(&server_public[..])) != cfg.server_identity_fingerprint {
        return Err(IdentityError("server identity fingerprint mismatch".into()));
    }
    let secret = read_private(&cfg.client_identity_private_key)
        .map_err(|e| fail("cannot read client identity", &cfg.client_identity_private_key, &e))?;
    let client = if cfg.protocol_version == 2 {
        if secret.len() != 32 {
            return Err(IdentityError("client private key must be exactly 32 bytes".into()));
        }
        Identity::ed25519(&secret)
    } else {
        if secret.len() != 2400 {
            return Err(IdentityError("client ML-KEM-768 private key must be exactly 2400 bytes".into()));
        }
        let public = read_public(&cfg.client_identity_public_key, EK_LEN)
            .map_err(|e| fail("cannot read client public identity", &cfg.client_identity_public_key, &e))?;
        Identity::kem(&secret, &public)
    }
    .map_err(|e| IdentityError(format!("invalid client identity: {}", e.message())))?;
    Ok(Identities { server_public, client: Arc::new(client) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pqvpnd-identity-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, data: &[u8], mode: u32) {
        let _ = std::fs::remove_file(path); // a 0400 file cannot be rewritten in place
        std::fs::write(path, data).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn config(dir: &Path, fingerprint: String) -> ClientConfig {
        let text = format!("[client]\nserver_identity_fingerprint = \"{fingerprint}\"\nfull_tunnel = false\ndns_mode = \"none\"\n\
                            server_identity_public_key = \"server.pub\"\nclient_identity_private_key = \"client.key\"\n");
        crate::config::parse(&text, dir).unwrap()
    }

    #[test]
    fn v2_identity_loads_and_every_file_rule_is_enforced() {
        let dir = dir("v2");
        let server = vec![7u8; EK_LEN];
        write(&dir.join("server.pub"), &server, 0o644);
        write(&dir.join("client.key"), &[9u8; 32], 0o600);
        let cfg = config(&dir, hex(&fingerprint(&server)));
        let ids = load(&cfg).unwrap();
        assert_eq!(&ids.server_public[..], &server[..]);

        let wrong_fp = config(&dir, "00".repeat(32));
        assert!(load(&wrong_fp).unwrap_err().0.contains("fingerprint mismatch"));
        write(&dir.join("client.key"), &[9u8; 32], 0o644);
        assert!(load(&cfg).unwrap_err().0.contains("0600"), "group/world-readable private key is refused");
        write(&dir.join("client.key"), &[9u8; 31], 0o400);
        assert!(load(&cfg).unwrap_err().0.contains("32 bytes"));
        write(&dir.join("client.key"), &[9u8; 32], 0o600);
        write(&dir.join("server.pub"), &server[..100], 0o644);
        assert!(load(&cfg).unwrap_err().0.contains("exactly"));
        std::fs::remove_file(dir.join("server.pub")).unwrap();
        std::os::unix::fs::symlink(dir.join("client.key"), dir.join("server.pub")).unwrap();
        assert!(load(&cfg).unwrap_err().0.contains("cannot read server identity"), "symlinks are not followed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_public_bounds_size_and_type() {
        let dir = dir("public");
        write(&dir.join("big"), &[1u8; 10], 0o644);
        assert!(read_public(&dir.join("big"), 9).is_err());
        assert_eq!(read_public(&dir.join("big"), 10).unwrap().len(), 10);
        assert!(read_public(&dir, 10).is_err(), "a directory is not a key");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
