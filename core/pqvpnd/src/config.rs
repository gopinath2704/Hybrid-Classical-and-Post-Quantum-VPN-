//! `client.toml` for `pqvpnd connect`: the same file and rules as `load_client_config`, restricted to what
//! pqvpnd implements. Every option it cannot honour is an error, never silently ignored (fail closed).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The `[client]` table. Every key `ClientConfig` knows is listed, so a typo is an "unknown field" error as in
/// Python, and an option pqvpnd does not support is a clear refusal rather than an unknown key.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    server_host: Option<String>,
    server_control_port: Option<i64>,
    server_identity_public_key: Option<String>,
    server_identity_fingerprint: Option<String>,
    client_identity_private_key: Option<String>,
    client_identity_public_key: Option<String>,
    protocol_version: Option<i64>,
    data_plane: Option<String>,
    handshake: Option<String>,
    full_tunnel: Option<bool>,
    split_tunnel: Option<Vec<String>>,
    dns_servers: Option<Vec<String>>,
    kill_switch: Option<bool>,
    tun_name: Option<String>,
    dev_emulated_tun: Option<bool>,
    ping_interval: Option<f64>,
    ping_timeout: Option<f64>,
    dead_peer_timeout: Option<f64>,
    dns_mode: Option<String>,
    dns_routing_domains: Option<Vec<String>>,
    expected_vpn_subnet: Option<String>,
    ipv6_policy: Option<String>,
    experimental_suite: Option<String>,
}

/// Like Python, other top-level tables (a `[server]` in a shared file) are not read.
#[derive(Debug, Deserialize)]
struct RawFile {
    client: Option<RawClient>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientConfig {
    pub server_host: String,
    pub server_control_port: u16,
    pub server_identity_public_key: PathBuf,
    /// Lowercase hex SHA-256 of the server identity public key.
    pub server_identity_fingerprint: String,
    pub client_identity_private_key: PathBuf,
    pub client_identity_public_key: PathBuf,
    /// 2 (v2-ed25519) or 3 (v3-kem).
    pub protocol_version: u8,
    pub tun_name: String,
    pub ping_interval: f64,
    pub ping_timeout: f64,
    pub dead_peer_timeout: f64,
    pub expected_vpn_subnet: (Ipv4Addr, u8),
    pub ipv6_policy: Ipv6Policy,
    pub full_tunnel: bool,
    /// Validated IPv4 networks, as written; ignored in a full tunnel, as in Python.
    pub split_tunnel: Vec<String>,
    /// `dns_mode = "systemd-resolved"` (the default) rather than `"none"`.
    pub manage_dns: bool,
    /// Validated IP addresses; empty means the server's CONFIG `dns` list, as in Python.
    pub dns_servers: Vec<String>,
    pub dns_routing_domains: Vec<String>,
}

/// `ipv6_policy`, as `IPv6Guard` applies it: leave IPv6 alone, drop all of it but loopback, or refuse to connect
/// while any usable IPv6 exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Policy {
    Allow,
    Block,
    Fail,
}

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    /// The file could not be read or is not valid TOML of the expected shape.
    Read(String),
    /// A value Python would also reject.
    Invalid(String),
    /// A valid option that pqvpnd does not implement (yet).
    Unsupported(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(message) => write!(f, "cannot read client config: {message}"),
            Self::Invalid(message) => write!(f, "invalid client config: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported by pqvpnd: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

fn unsupported(message: impl Into<String>) -> ConfigError {
    ConfigError::Unsupported(message.into())
}

pub fn load(path: &Path) -> Result<ClientConfig, ConfigError> {
    let path = path.canonicalize().map_err(|e| ConfigError::Read(format!("{}: {e}", path.display())))?;
    let text = std::fs::read_to_string(&path).map_err(|e| ConfigError::Read(format!("{}: {e}", path.display())))?;
    let base = path.parent().unwrap_or(Path::new("/"));
    parse(&text, base)
}

/// Parses `[client]`; relative paths resolve against `base`, the directory of the TOML file, as in Python.
pub fn parse(text: &str, base: &Path) -> Result<ClientConfig, ConfigError> {
    let file: RawFile = toml::from_str(text).map_err(|e| ConfigError::Read(e.to_string()))?;
    let raw = file.client.unwrap_or_default();

    // Backend switches: pqvpnd is the Rust handshake and the Rust data plane by construction.
    for (name, value) in [("data_plane", &raw.data_plane), ("handshake", &raw.handshake)] {
        match value.as_deref() {
            None | Some("rust") => {}
            Some("python") => return Err(unsupported(format!("{name} = \"python\" (pqvpnd is the Rust {name}; use the Python client)"))),
            Some(_) => return Err(invalid(format!("{name} must be python or rust"))),
        }
    }
    match raw.experimental_suite.as_deref() {
        None | Some("") => {}
        Some("v3-mldsa") => return Err(unsupported("experimental_suite = \"v3-mldsa\" (not ported to the Rust handshake)")),
        Some(suite @ ("v2-ed25519" | "v3-kem")) => {
            return Err(unsupported(format!("experimental_suite = \"{suite}\" (select the suite with protocol_version)")));
        }
        Some(_) => return Err(invalid("experimental_suite must be one of v2-ed25519, v3-kem, v3-mldsa or empty")),
    }

    let full_tunnel = raw.full_tunnel.unwrap_or(true);
    let manage_dns = match raw.dns_mode.as_deref() {
        None | Some("systemd-resolved") => true,
        Some("none") => false,
        Some(_) => return Err(invalid("dns_mode must be systemd-resolved or none")),
    };
    if raw.kill_switch == Some(true) {
        return Err(unsupported("kill_switch = true"));
    }
    if raw.dev_emulated_tun == Some(true) {
        return Err(unsupported("dev_emulated_tun = true (pqvpnd always opens a native TUN)"));
    }
    let split_tunnel = raw.split_tunnel.unwrap_or_default();
    for route in &split_tunnel {
        ipv4_network(route).ok_or_else(|| invalid(format!("split_tunnel: {route:?} is not an IPv4 network")))?;
    }
    let dns_routing_domains = raw.dns_routing_domains.unwrap_or_default();
    if !dns_routing_domains.iter().all(|domain| routing_domain_ok(domain)) {
        return Err(invalid("invalid DNS routing domain"));
    }
    // `effective_policy`: unset means "block" in a full tunnel and "allow" in split mode.
    let ipv6_policy = match raw.ipv6_policy.as_deref() {
        None if full_tunnel => Ipv6Policy::Block,
        None | Some("allow") => Ipv6Policy::Allow,
        Some("block") => Ipv6Policy::Block,
        Some("fail") => Ipv6Policy::Fail,
        Some(_) => return Err(invalid("ipv6_policy must be block, fail or allow")),
    };
    // Unused with dns_mode = "none", exactly as in Python, but still validated.
    let dns_servers = raw.dns_servers.unwrap_or_default();
    for address in &dns_servers {
        address.parse::<IpAddr>().map_err(|_| invalid(format!("dns_servers: {address:?} is not an IP address")))?;
    }

    let server_control_port = match raw.server_control_port.unwrap_or(51820) {
        port @ 1..=65535 => u16::try_from(port).expect("in range"),
        _ => return Err(invalid("server_control_port: expected integer in [1, 65535]")),
    };
    let protocol_version = match raw.protocol_version.unwrap_or(2) {
        2 => 2,
        3 => 3,
        _ => return Err(invalid("protocol_version must be 2 or 3")),
    };
    let tun_name = raw.tun_name.unwrap_or_else(|| "pqvpn0".into());
    if !interface_name_ok(&tun_name) {
        return Err(invalid("tun_name: expected a Linux interface name of 1-15 characters"));
    }
    let number = |value: Option<f64>, default: f64, name: &str| -> Result<f64, ConfigError> {
        let value = value.unwrap_or(default);
        if value.is_finite() && (0.05..=3600.0).contains(&value) {
            Ok(value)
        } else {
            Err(invalid(format!("{name}: expected number in [0.05, 3600]")))
        }
    };
    let ping_interval = number(raw.ping_interval, 5.0, "ping_interval")?;
    let ping_timeout = number(raw.ping_timeout, 4.0, "ping_timeout")?;
    let dead_peer_timeout = number(raw.dead_peer_timeout, 30.0, "dead_peer_timeout")?;
    if dead_peer_timeout <= ping_interval.max(ping_timeout) {
        return Err(invalid("dead_peer_timeout must exceed ping_interval and ping_timeout"));
    }
    let expected_vpn_subnet = ipv4_network(raw.expected_vpn_subnet.as_deref().unwrap_or("10.8.0.0/24"))
        .ok_or_else(|| invalid("expected_vpn_subnet: expected an IPv4 network such as 10.8.0.0/24"))?;

    let fingerprint = raw.server_identity_fingerprint.unwrap_or_default().to_ascii_lowercase();
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("server_identity_fingerprint: expected 64 hex characters (SHA-256 of the server identity)"));
    }
    let server_host = raw.server_host.unwrap_or_else(|| "127.0.0.1".into());
    if server_host.is_empty() {
        return Err(invalid("server_host must be nonempty"));
    }
    // Omitted paths use the standard file name next to the TOML, relative paths resolve against it.
    let file = |value: Option<String>, default: &str| {
        let value = PathBuf::from(value.unwrap_or_else(|| default.into()));
        if value.is_absolute() { value } else { base.join(value) }
    };

    Ok(ClientConfig {
        server_host,
        server_control_port,
        server_identity_public_key: file(raw.server_identity_public_key, "server_identity_public.key"),
        server_identity_fingerprint: fingerprint,
        client_identity_private_key: file(raw.client_identity_private_key, "client_identity_private.key"),
        client_identity_public_key: file(raw.client_identity_public_key, "client_identity_public.key"),
        protocol_version,
        tun_name,
        ping_interval,
        ping_timeout,
        dead_peer_timeout,
        expected_vpn_subnet,
        ipv6_policy,
        full_tunnel,
        split_tunnel,
        manage_dns,
        dns_servers,
        dns_routing_domains,
    })
}

impl ClientConfig {
    /// `VPNClient._ticket_path`: next to the client private key, shared with the Python client.
    /// What `ClientNetwork.apply` routes through the TUN: both halves of IPv4 in a full tunnel, else the split list.
    pub fn routes(&self) -> Vec<String> {
        if self.full_tunnel { vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()] } else { self.split_tunnel.clone() }
    }

    /// The resolved routing domains for the TUN link: every name (`~.`) in a full tunnel, else the configured ones.
    pub fn dns_domains(&self) -> Vec<String> {
        if self.full_tunnel { vec!["~.".into()] } else { self.dns_routing_domains.clone() }
    }

    pub fn ticket_path(&self) -> PathBuf {
        self.client_identity_private_key.parent().unwrap_or(Path::new(".")).join(".pqvpn_ticket.json")
    }
}

/// `validate_client`'s routing-domain pattern: `~?[a-zA-Z0-9][a-zA-Z0-9.-]*` or `~.`.
fn routing_domain_ok(domain: &str) -> bool {
    let name = domain.strip_prefix('~').unwrap_or(domain);
    domain == "~." || name.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

/// `interface_name`: `[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}`.
fn interface_name_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=15).contains(&bytes.len())
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        && bytes[1..].iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `ipaddress.IPv4Network(value)` in strict mode: host bits must be zero.
pub fn ipv4_network(value: &str) -> Option<(Ipv4Addr, u8)> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, prefix.parse::<u8>().ok()?),
        None => (value, 32),
    };
    let address: Ipv4Addr = address.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (u32::from(address) & !mask == 0).then_some((address, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client.toml that eval/run_pqvpn_net.sh writes, plus the rust/rust backend lines.
    const BENCH: &str = r#"
[client]
server_host = "192.0.2.1"
server_control_port = 51820
server_identity_fingerprint = "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
server_identity_public_key = "../server/server.pub"
client_identity_private_key = "client.key"
full_tunnel = false
dns_mode = "none"
dns_servers = []
tun_name = "pqbench0"
data_plane = "rust"
handshake = "rust"
"#;

    fn with(extra: &str) -> Result<ClientConfig, ConfigError> {
        parse(&format!("{BENCH}{extra}\n"), Path::new("/run/bench/client"))
    }

    #[test]
    fn accepts_the_benchmark_config_and_resolves_paths_like_python() {
        let cfg = with("").unwrap();
        assert_eq!(cfg.server_identity_public_key, Path::new("/run/bench/client/../server/server.pub"));
        assert_eq!(cfg.client_identity_private_key, Path::new("/run/bench/client/client.key"));
        assert_eq!(cfg.client_identity_public_key, Path::new("/run/bench/client/client_identity_public.key"));
        assert_eq!(cfg.server_identity_fingerprint, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        assert_eq!((cfg.protocol_version, cfg.server_control_port, cfg.tun_name.as_str()), (2, 51820, "pqbench0"));
        assert_eq!(cfg.expected_vpn_subnet, (Ipv4Addr::new(10, 8, 0, 0), 24));
        assert_eq!(cfg.ticket_path(), Path::new("/run/bench/client/.pqvpn_ticket.json"));
        // Absolute paths stay as given; data_plane/handshake may be omitted; other tables are ignored.
        let cfg = parse(&BENCH.replace("data_plane = \"rust\"\nhandshake = \"rust\"\n", "client_identity_public_key = \"/k.pub\"\nprotocol_version = 3\n")
            .replace("[client]", "[server]\nanything = 1\n[client]"), Path::new("/x")).unwrap();
        assert_eq!((cfg.client_identity_public_key.as_path(), cfg.protocol_version), (Path::new("/k.pub"), 3));
    }

    #[test]
    fn refuses_every_option_it_cannot_honour() {
        let cases = [
            (format!("{BENCH}kill_switch = true"), "kill_switch"),
            (format!("{BENCH}dev_emulated_tun = true"), "dev_emulated_tun"),
            (format!("{BENCH}experimental_suite = \"v3-mldsa\""), "v3-mldsa"),
            (BENCH.replace("data_plane = \"rust\"", "data_plane = \"python\""), "data_plane"),
            (BENCH.replace("handshake = \"rust\"", "handshake = \"python\""), "handshake"),
        ];
        for (text, needle) in cases {
            match parse(&text, Path::new("/")) {
                Err(ConfigError::Unsupported(message)) => assert!(message.contains(needle), "{needle}: {message}"),
                other => panic!("{needle}: expected Unsupported, got {other:?}"),
            }
        }
        // Explicitly harmless values of those options are fine.
        for extra in ["kill_switch = false", "split_tunnel = []", "dns_routing_domains = []", "ipv6_policy = \"allow\"",
                      "dev_emulated_tun = false", "experimental_suite = \"\""] {
            with(extra).unwrap_or_else(|e| panic!("{extra}: {e}"));
        }
        parse(&BENCH.replace("dns_servers = []", "dns_servers = [\"1.1.1.1\", \"::1\"]"), Path::new("/")).unwrap();
        for (extra, policy) in [("", Ipv6Policy::Allow), ("ipv6_policy = \"allow\"", Ipv6Policy::Allow),
                                ("ipv6_policy = \"block\"", Ipv6Policy::Block), ("ipv6_policy = \"fail\"", Ipv6Policy::Fail)] {
            assert_eq!(with(extra).unwrap().ipv6_policy, policy, "{extra:?}");
        }
    }

    #[test]
    fn dns_follows_python() {
        let cfg = parse(&BENCH.replace("dns_mode = \"none\"\n", "").replace("dns_servers = []", "dns_servers = [\"10.8.0.1\"]")
            .replace("full_tunnel = false", "full_tunnel = false\ndns_routing_domains = [\"corp.example\", \"~lan\", \"~.\"]"), Path::new("/")).unwrap();
        assert!(cfg.manage_dns, "systemd-resolved is the default");
        assert_eq!(cfg.dns_servers, ["10.8.0.1"]);
        assert_eq!(cfg.dns_domains(), ["corp.example", "~lan", "~."], "split: the configured routing domains");
        let full = parse(&BENCH.replace("full_tunnel = false", ""), Path::new("/")).unwrap();
        assert_eq!((full.manage_dns, full.dns_domains()), (false, vec!["~.".to_owned()]), "full tunnel routes every name");
    }

    #[test]
    fn routes_follow_full_and_split_tunnel_like_python() {
        let split = with("split_tunnel = [\"203.0.113.0/24\", \"198.51.100.7\"]").unwrap();
        assert_eq!(split.routes(), ["203.0.113.0/24", "198.51.100.7"]);
        assert_eq!(split.ipv6_policy, Ipv6Policy::Allow);
        // Full tunnel is the default; the split list is then ignored and IPv6 defaults to block.
        let full = parse(&BENCH.replace("full_tunnel = false", "split_tunnel = [\"203.0.113.0/24\"]"), Path::new("/")).unwrap();
        assert_eq!(full.routes(), ["0.0.0.0/1", "128.0.0.0/1"]);
        assert_eq!(full.ipv6_policy, Ipv6Policy::Block);
        let explicit = parse(&BENCH.replace("full_tunnel = false", "full_tunnel = true\nipv6_policy = \"allow\""), Path::new("/")).unwrap();
        assert_eq!((explicit.full_tunnel, explicit.ipv6_policy), (true, Ipv6Policy::Allow));
    }

    #[test]
    fn rejects_what_python_rejects() {
        let invalid_cases = [
            format!("{BENCH}tun_name2 = 1"),                      // unknown field
            BENCH.replace("51820", "0"),
            BENCH.replace("51820", "70000"),
            BENCH.replace("server_control_port = 51820", "server_control_port = 1.5"),
            BENCH.replace("pqbench0", "a name with spaces"),
            BENCH.replace("pqbench0", "-starts-with-dash"),
            BENCH.replace("pqbench0", "sixteen-chars-xx"),
            format!("{BENCH}protocol_version = 4"),
            format!("{BENCH}expected_vpn_subnet = \"10.8.0.1/24\""),  // host bits set: strict like ipaddress
            format!("{BENCH}expected_vpn_subnet = \"10.8.0.0/33\""),
            format!("{BENCH}ping_interval = 0.01"),
            format!("{BENCH}dead_peer_timeout = 4"),
            format!("{BENCH}ipv6_policy = \"sometimes\""),
            format!("{BENCH}split_tunnel = [\"203.0.113.1/24\"]"),
            format!("{BENCH}split_tunnel = [\"::/0\"]"),
            format!("{BENCH}dns_routing_domains = [\"-corp\"]"),
            format!("{BENCH}dns_routing_domains = [\"corp;rm\"]"),
            format!("{BENCH}dns_routing_domains = [\"~\"]"),
            format!("{BENCH}dns_mode = \"dnsmasq\""),
            BENCH.replace("dns_servers = []", "dns_servers = [\"not-an-ip\"]"),
            BENCH.replace("ABCDEF", "XYZ"),
            BENCH.replace("server_identity_fingerprint = \"ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"", ""),
            BENCH.replace("data_plane = \"rust\"", "data_plane = \"go\""),
            "client = 1".into(),
            "[client\n".into(),
        ];
        for text in invalid_cases {
            assert!(matches!(parse(&text, Path::new("/")), Err(ConfigError::Invalid(_) | ConfigError::Read(_))), "{text}");
        }
        // A missing [client] gets Python's defaults, which then fail closed on the missing fingerprint.
        assert!(matches!(parse("", Path::new("/")), Err(ConfigError::Invalid(message)) if message.contains("fingerprint")));
    }

    #[test]
    fn ipv4_network_is_strict() {
        assert_eq!(ipv4_network("10.8.0.0/24"), Some((Ipv4Addr::new(10, 8, 0, 0), 24)));
        assert_eq!(ipv4_network("10.8.0.7"), Some((Ipv4Addr::new(10, 8, 0, 7), 32)));
        assert_eq!(ipv4_network("0.0.0.0/0"), Some((Ipv4Addr::UNSPECIFIED, 0)));
        for bad in ["10.8.0.1/24", "10.8.0.0/33", "10.8.0/24", "::1/128", "10.8.0.0/x"] {
            assert_eq!(ipv4_network(bad), None, "{bad}");
        }
    }
}
