//! `pqvpnd connect`, in the order `VPNClient.connect` uses: resume or full handshake (with the cookie response),
//! CONFIG, ticket, TUN and routes, UDP_BIND, the Rust data plane, then the control loop until the session ends
//! or a stop signal arrives. Teardown runs through drop: data plane first, then routes and TUN.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::SigSet;
use nix::sys::signalfd::{SfdFlags, SignalFd};
use pqvpn_core::dataplane::{self, Ping, Shared, Worker};
use pqvpn_core::handshake::{self, ClientHandshake, Established, Os, ResumeClient, Suite};
use pqvpn_core::session::Role;

use crate::config::{self, ClientConfig};
use crate::identity::{self, Identities};
use crate::net::{self, Network};

/// `socket.create_connection(..., timeout=10)`, which also bounds every handshake read.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// `self.control.settimeout(3)` / `self.udp.settimeout(3)` once established.
const SESSION_TIMEOUT: Duration = Duration::from_secs(3);
/// `MAX_CONTROL_MESSAGE`.
const MAX_CONTROL_MESSAGE: usize = 16384;
/// How long the client waits for a REKEY_RESPONSE / REHANDSHAKE_RESPONSE, as `_responses.get(timeout=…)`.
const REKEY_WAIT: f64 = 10.0;
const REHANDSHAKE_WAIT: f64 = 15.0;
const POLL_MS: u16 = 200;

const COOKIE_CHALLENGE: u8 = 5;
const UDP_BIND: u8 = 2;
const UDP_BIND_ACK: u8 = 3;
const CLOSE: u8 = 6;
const CONFIG: u8 = 7;
const REKEY_RESPONSE: u8 = 9;
const REHANDSHAKE_RESPONSE: u8 = 12;
const RESUMPTION_TICKET: u8 = 13;

#[derive(Debug)]
pub enum ConnectError {
    Config(config::ConfigError),
    Identity(identity::IdentityError),
    Network(String),
    Protocol(String),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => error.fmt(f),
            Self::Identity(error) => error.fmt(f),
            Self::Network(message) | Self::Protocol(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ConnectError {}

fn net(context: &str) -> impl Fn(io::Error) -> ConnectError + '_ {
    move |error| ConnectError::Network(format!("{context}: {error}"))
}

fn protocol(error: handshake::Error) -> ConnectError {
    ConnectError::Protocol(error.message())
}

/// `send_message`: a 4-byte big-endian length, then the message, in one write.
pub fn send_message(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    if data.is_empty() || data.len() > MAX_CONTROL_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid control message length"));
    }
    let mut wire = Vec::with_capacity(4 + data.len());
    wire.extend_from_slice(&(data.len() as u32).to_be_bytes());
    wire.extend_from_slice(data);
    stream.write_all(&wire)
}

/// `recv_message`.
pub fn recv_message(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let size = u32::from_be_bytes(length) as usize;
    if size == 0 || size > MAX_CONTROL_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid control message length"));
    }
    let mut data = vec![0; size];
    stream.read_exact(&mut data)?;
    Ok(data)
}

/// `socket.gethostbyname`: the first IPv4 address of `host`.
pub fn resolve_ipv4(host: &str, port: u16) -> Result<Ipv4Addr, ConnectError> {
    let addresses = (host, port).to_socket_addrs().map_err(|e| ConnectError::Network(format!("cannot resolve {host}: {e}")))?;
    addresses.filter_map(|address| match address.ip() { IpAddr::V4(v4) => Some(v4), IpAddr::V6(_) => None }).next()
        .ok_or_else(|| ConnectError::Network(format!("{host} has no IPv4 address")))
}

fn control_connection(server: SocketAddr) -> Result<TcpStream, ConnectError> {
    let stream = TcpStream::connect_timeout(&server, HANDSHAKE_TIMEOUT).map_err(net("control connection"))?;
    stream.set_nodelay(true).map_err(net("TCP_NODELAY"))?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(net("control timeout"))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(net("control timeout"))?;
    Ok(stream)
}

/// The authenticated CONFIG fields the client acts on.
#[derive(Debug, Clone, PartialEq)]
pub struct Tunnel {
    pub client_ip: Ipv4Addr,
    pub server_vpn_ip: Ipv4Addr,
    pub prefix: u8,
    pub udp_port: u16,
    pub mtu: u16,
    pub rekey_interval: u64,
    pub rehandshake_interval: u64,
    pub resumption: bool,
    /// The server's DNS servers, used when `dns_servers` is empty.
    pub dns: Vec<String>,
}

/// Parses CONFIG and applies the checks `connect` makes (advertised subnet, UDP port), plus type and range
/// checks Python gets implicitly from using the values; anything off is a protocol error, never a default.
pub fn parse_tunnel(payload: &[u8], expected_subnet: (Ipv4Addr, u8)) -> Result<Tunnel, ConnectError> {
    let bad = |what: &str| ConnectError::Protocol(format!("invalid CONFIG: {what}"));
    let config: serde_json::Value = serde_json::from_slice(payload).map_err(|_| bad("not JSON"))?;
    let ip = |name: &str| config.get(name).and_then(|v| v.as_str()).and_then(|s| s.parse::<Ipv4Addr>().ok()).ok_or_else(|| bad(name));
    let integer = |name: &str| config.get(name).and_then(serde_json::Value::as_u64).ok_or_else(|| bad(name));
    let prefix = u8::try_from(integer("prefix")?).ok().filter(|p| *p <= 30).ok_or_else(|| bad("prefix"))?;
    let tunnel = Tunnel {
        client_ip: ip("client_vpn_ip")?,
        server_vpn_ip: ip("server_vpn_ip")?,
        prefix,
        udp_port: u16::try_from(integer("udp_port")?).ok().filter(|p| *p >= 1).ok_or_else(|| {
            ConnectError::Protocol("invalid authenticated server UDP port".into())
        })?,
        mtu: u16::try_from(integer("mtu")?).ok().filter(|m| (576..=1400).contains(m)).ok_or_else(|| bad("mtu"))?,
        rekey_interval: config.get("rekey_interval").map_or(Some(0), serde_json::Value::as_u64).ok_or_else(|| bad("rekey_interval"))?,
        rehandshake_interval: config.get("rehandshake_interval").map_or(Some(0), serde_json::Value::as_u64)
            .ok_or_else(|| bad("rehandshake_interval"))?,
        resumption: config.get("resumption").and_then(serde_json::Value::as_bool).unwrap_or(false),
        dns: config.get("dns").and_then(serde_json::Value::as_array).and_then(|list| {
            list.iter().map(|v| v.as_str().filter(|s| s.parse::<IpAddr>().is_ok()).map(str::to_owned)).collect()
        }).ok_or_else(|| bad("dns"))?,
    };
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let advertised = (Ipv4Addr::from(u32::from(tunnel.server_vpn_ip) & mask), prefix);
    if advertised != expected_subnet {
        return Err(ConnectError::Protocol("server VPN subnet differs from expected_vpn_subnet".into()));
    }
    Ok(tunnel)
}

/// Resumption first when a ticket matches this server and version, else (or on any failure, on a fresh
/// connection) the full handshake, answering a cookie challenge if the server sends one.
fn handshake(cfg: &ClientConfig, ids: &Identities, server: SocketAddr) -> Result<(TcpStream, Established), ConnectError> {
    let suite = Suite::from_version(if cfg.protocol_version == 3 { 0x30 } else { 0x20 }).map_err(protocol)?;
    let mut os = Os;
    let mut control = control_connection(server)?;
    if let Some(mut resume) = ResumeClient::load(&cfg.ticket_path(), &cfg.server_identity_fingerprint, cfg.protocol_version, suite.version()) {
        let attempt = (|| -> Result<Established, ConnectError> {
            send_message(&mut control, &resume.hello(&mut os).map_err(protocol)?).map_err(net("resumption hello"))?;
            resume.on_accept(&recv_message(&mut control).map_err(net("resumption accept"))?).map_err(protocol)
        })();
        match attempt {
            Ok(established) => {
                eprintln!("pqvpnd: session resumed via 1-RTT ticket");
                return Ok((control, established));
            }
            Err(error) => {
                eprintln!("pqvpnd: resumption failed ({error}), falling back to full handshake");
                // A ticket the server rejected (e.g. key rotated on revocation) must not linger if the full handshake fails too.
                let _ = std::fs::remove_file(cfg.ticket_path());
                control = control_connection(server)?;
            }
        }
    }
    let mut client = ClientHandshake::new(suite, &ids.server_public[..], &cfg.server_identity_fingerprint, ids.client.clone())
        .map_err(protocol)?;
    let hello = client.hello(&mut os).map_err(protocol)?;
    send_message(&mut control, &hello).map_err(net("client hello"))?;
    let mut reply = recv_message(&mut control).map_err(net("server hello"))?;
    if reply.len() >= handshake::HEADER_LEN && reply[3] == COOKIE_CHALLENGE {
        let cookie = handshake::parse_cookie_challenge(&reply).map_err(protocol)?.to_vec();
        send_message(&mut control, &handshake::cookie_response(suite.version(), &cookie, &hello).map_err(protocol)?)
            .map_err(net("cookie response"))?;
        reply = recv_message(&mut control).map_err(net("server hello"))?;
    }
    let exchange = client.on_server_hello(&mut os, &reply).map_err(protocol)?;
    send_message(&mut control, &exchange).map_err(net("key exchange"))?;
    let established = client.on_server_finished(&recv_message(&mut control).map_err(net("server finished"))?).map_err(protocol)?;
    Ok((control, established))
}

/// `UDP_BIND` / `UDP_BIND_ACK`, through the session's data channel, before the data plane takes the socket.
fn udp_bind(established: &Established, server_udp: SocketAddrV4) -> Result<UdpSocket, ConnectError> {
    let udp = UdpSocket::bind("0.0.0.0:0").map_err(net("UDP socket"))?;
    udp.set_read_timeout(Some(SESSION_TIMEOUT)).map_err(net("UDP timeout"))?;
    let bind = established.data().seal(UDP_BIND, b"bind").map_err(|e| ConnectError::Protocol(e.as_str().into()))?;
    udp.send_to(&bind, server_udp).map_err(net("UDP bind"))?;
    let mut buffer = [0u8; 4096];
    let (size, from) = udp.recv_from(&mut buffer).map_err(net("UDP bind acknowledgement"))?;
    if from != SocketAddr::V4(server_udp) {
        return Err(ConnectError::Protocol("UDP bind acknowledgement from unexpected endpoint".into()));
    }
    let (_, ack) = established.data().open(&buffer[..size], Some(UDP_BIND_ACK)).map_err(|e| ConnectError::Protocol(e.as_str().into()))?;
    if ack != b"ok" {
        return Err(ConnectError::Protocol("malformed UDP bind acknowledgement".into()));
    }
    udp.set_nonblocking(true).map_err(net("UDP non-blocking"))?;
    Ok(udp)
}

/// The data plane and the network it runs on. Dropping it stops and joins the worker first, then
/// restores routes and closes the TUN (field order), as `_cleanup_owned` does.
struct Running {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
    _network: Network,
}

impl Running {
    fn stop_data_plane(&mut self) {
        self.shared.request_stop();
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop_data_plane();
    }
}

enum Pending {
    Rekey(f64),
    Rehandshake(f64),
}

/// The longest status line, newline excluded.
pub const STATUS_MAX: usize = 4095;
const STATUS_MAX_RTTS: usize = 64;
const STATUS_MAX_ERROR: usize = 512;

/// `--status-json`: status wire spec v1 on stdout, one JSON object per line. Lines carry no key material.
pub struct Status {
    enabled: bool,
    kill_switch: bool,
    /// The CONNECTED fields fixed for the session; None until the tunnel is up.
    tunnel: Option<serde_json::Map<String, serde_json::Value>>,
    epoch: u32,
    last: f64,
}

/// One line of the wire spec: `connected` adds the CONNECTED fields; `error` is shortened to keep the line bounded.
pub fn status_line(state: &str, error: &str, kill_switch: bool, connected: Option<serde_json::Map<String, serde_json::Value>>) -> String {
    let error: String = error.chars().take(STATUS_MAX_ERROR).collect();
    let mut line = serde_json::json!({"v": 1, "state": state, "error": error, "kill_switch": kill_switch});
    if let (Some(fields), Some(object)) = (connected, line.as_object_mut()) {
        object.extend(fields);
    }
    line.to_string()
}

impl Status {
    pub fn new(enabled: bool) -> Self {
        Status { enabled, kill_switch: false, tunnel: None, epoch: 0, last: 0.0 }
    }

    fn emit(&self, line: &str) {
        if self.enabled {
            debug_assert!(line.len() <= STATUS_MAX && !line.contains('\n'));
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{line}").and_then(|()| out.flush());
        }
    }

    fn state(&self, state: &str, error: &str) {
        self.emit(&status_line(state, error, self.kill_switch, None));
    }

    /// A CONNECTED line, with the keepalive results since the last one (fed to Python's NetworkQualityMonitor).
    fn connected(&mut self, now: f64, epoch: u32, rekey_in: Option<f64>, rehandshake_in: Option<f64>, shared: &Shared) {
        let Some(tunnel) = self.tunnel.clone() else { return };
        let probes = std::mem::take(&mut *shared.probes.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        let mut fields = tunnel;
        fields.insert("epoch".into(), epoch.into());
        fields.insert("rekey_in".into(), rekey_in.map(|s| s.max(0.0)).into());
        fields.insert("rehandshake_in".into(), rehandshake_in.map(|s| s.max(0.0)).into());
        let rtts: Vec<f64> = probes.rtts_ms.into_iter().take(STATUS_MAX_RTTS).collect();
        fields.insert("probes".into(), serde_json::json!({"sent": probes.sent, "lost": probes.lost, "rtts_ms": rtts}));
        self.emit(&status_line("CONNECTED", "", self.kill_switch, Some(fields)));
        (self.epoch, self.last) = (epoch, now);
    }

    /// Every second while connected, and at once when the epoch changes.
    fn tick(&mut self, now: f64, epoch: u32, rekey_in: Option<f64>, rehandshake_in: Option<f64>, shared: &Shared) {
        if self.enabled && (now - self.last >= 1.0 || epoch != self.epoch) {
            self.connected(now, epoch, rekey_in, rehandshake_in, shared);
        }
    }
}

/// The whole client: returns Ok when stopped by a signal, Err when the session fails or ends. With `status_json`,
/// stdout carries the status lines, ending in exactly one final line written after every cleanup.
pub fn connect(config_path: &Path, stop_signals: &SigSet, status_json: bool) -> Result<(), ConnectError> {
    let mut status = Status::new(status_json);
    let result = run(config_path, stop_signals, &mut status);
    // The table, not the outcome, decides BLOCKED: whatever this process left in place is what the reader faces.
    let blocking = status.kill_switch && net::killswitch_present().unwrap_or(true);
    status.kill_switch = blocking;
    let error = result.as_ref().err().map(ToString::to_string).unwrap_or_default();
    status.state(if blocking { "BLOCKED" } else if result.is_ok() { "DISCONNECTED" } else { "FAILED" }, &error);
    result
}

fn run(config_path: &Path, stop_signals: &SigSet, status: &mut Status) -> Result<(), ConnectError> {
    let cfg = config::load(config_path).map_err(ConnectError::Config)?;
    // `ipv6_preflight` first, as in `VPNClient.connect`: refuse before touching anything.
    crate::net::ipv6_preflight(cfg.ipv6_policy).map_err(net("IPv6 preflight"))?;
    if !cfg.kill_switch {
        status.state("CONNECTING", "");
        return session(&cfg, stop_signals, &mut false, status);
    }
    // Block everything but the handshake before it starts; config checked server_host is an IPv4 literal.
    let server: Ipv4Addr = cfg.server_host.parse().expect("validated");
    let preexisting = net::killswitch_present().map_err(net("kill switch"))?;
    net::killswitch_install(server, cfg.server_control_port, None).map_err(net("kill switch"))?;
    status.kill_switch = true;
    status.state("CONNECTING", "");
    let mut up = false;
    let result = session(&cfg, stop_signals, &mut up, status);
    // `_settle_kill_switch`, after the network is restored: a stop signal (the user's disconnect) or a fresh connect
    // that never came up removes it; a lost session, or a failed reconnect from the blocked state, keeps blocking.
    let settled = if result.is_err() && (up || preexisting) {
        net::killswitch_install(server, cfg.server_control_port, None)
            .inspect(|()| eprintln!("pqvpnd: kill switch is blocking all traffic; run `pqvpnd recover` to restore it"))
    } else {
        net::killswitch_remove()
    };
    if let Err(error) = settled {
        eprintln!("pqvpnd: kill switch update failed ({error}); run `pqvpnd recover` to remove it");
    }
    result
}

/// `dns = cfg.dns_servers or tunnel["dns"]`, refusing a full tunnel whose managed DNS would configure nothing
/// and so send every lookup to the uplink's resolver.
pub fn dns_servers<'a>(cfg: &'a ClientConfig, tunnel: &'a Tunnel) -> Result<&'a [String], ConnectError> {
    let dns = if cfg.dns_servers.is_empty() { &tunnel.dns } else { &cfg.dns_servers };
    if cfg.full_tunnel && cfg.manage_dns && dns.is_empty() {
        return Err(ConnectError::Network("full tunnel with managed DNS but no DNS servers".into()));
    }
    Ok(dns)
}

/// Handshake to teardown; `up` records whether the tunnel (and with it the kill switch's "up" phase) was reached.
fn session(cfg: &ClientConfig, stop_signals: &SigSet, up: &mut bool, status: &mut Status) -> Result<(), ConnectError> {
    let ids = identity::load(cfg).map_err(ConnectError::Identity)?;
    let server_ip = resolve_ipv4(&cfg.server_host, cfg.server_control_port)?;
    let (mut control, mut established) = handshake(cfg, &ids, SocketAddr::from((server_ip, cfg.server_control_port)))?;

    let (_, payload) = established.open_control(&recv_message(&mut control).map_err(net("CONFIG"))?, Some(CONFIG)).map_err(protocol)?;
    let tunnel = parse_tunnel(&payload, cfg.expected_vpn_subnet)?;
    if tunnel.resumption {
        // Best effort, as in Python: a lost ticket only means a full handshake next time.
        let saved = recv_message(&mut control).ok().and_then(|frame| established.open_control(&frame, None).ok())
            .filter(|(kind, _)| *kind == RESUMPTION_TICKET)
            .map(|(_, ticket)| established.save_ticket(&cfg.ticket_path(), &cfg.server_identity_fingerprint, cfg.protocol_version, &ticket));
        if !matches!(saved, Some(Ok(()))) {
            eprintln!("pqvpnd: resumption ticket not saved; will use full handshake next time");
        }
    }
    control.set_read_timeout(Some(SESSION_TIMEOUT)).map_err(net("control timeout"))?;
    control.set_write_timeout(Some(SESSION_TIMEOUT)).map_err(net("control timeout"))?;

    let dns = dns_servers(cfg, &tunnel)?;
    let mut network = Network::up(&cfg.tun_name, tunnel.client_ip, tunnel.prefix, tunnel.mtu, server_ip, cfg.ipv6_policy, &cfg.routes()).map_err(net("network setup"))?;
    network.dns(cfg.manage_dns, dns, &cfg.dns_domains(), net::resolvectl_binary).map_err(net("DNS setup"))?;
    if cfg.kill_switch {
        net::killswitch_install(server_ip, cfg.server_control_port, Some((&network.tun_name, tunnel.udp_port))).map_err(net("kill switch"))?;
        *up = true;
    }
    let server_udp = SocketAddrV4::new(server_ip, tunnel.udp_port);
    let udp = udp_bind(&established, server_udp)?;
    let tun: OwnedFd = network.tun.as_ref().expect("up() opened it").try_clone().map_err(net("TUN dup"))?;
    let shared = Arc::new(Shared::new(Role::Client, usize::from(tunnel.mtu), Some(server_udp)));
    shared.add(established.data(), established.session_id(), tunnel.client_ip.octets());
    let ping = Ping { initial: cfg.ping_interval.min(2.0), interval: cfg.ping_interval, timeout: cfg.ping_timeout };
    let worker = dataplane::spawn(shared.clone(), Worker { udp: OwnedFd::from(udp), tun, ping: Some(ping) }).map_err(net("data plane"))?;
    status.tunnel = Some(serde_json::json!({
        "client_vpn_ip": tunnel.client_ip.to_string(), "server_vpn_ip": tunnel.server_vpn_ip.to_string(), "prefix": tunnel.prefix,
        "endpoint": server_udp.to_string(), "tun_name": network.tun_name, "mtu": tunnel.mtu,
        // The suite this session negotiated: pqvpnd offers only the configured one, and the server accepts it or fails.
        "suite": if cfg.protocol_version == 3 { "v3-kem" } else { "v2-ed25519" },
        "ipv6_guard": network.ipv6_table.is_some(), "dns_managed": network.dns_managed(),
    }).as_object().cloned().expect("an object"));
    let mut running = Running { shared, worker: Some(worker), _network: network };
    let connected = format!("connected {} via {server_udp} epoch {}", tunnel.client_ip, established.epoch());
    if status.enabled {
        eprintln!("pqvpnd: {connected}");
    } else {
        println!("{connected}");
        let _ = io::stdout().flush();
    }

    let result = control_loop(cfg, &tunnel, &mut control, &mut established, &running.shared, stop_signals, status);
    running.stop_data_plane();
    if result.is_ok() {
        // `disconnect()`: tell the server, best effort, after the data plane is down.
        if let Ok(frame) = established.seal_control(CLOSE, b"close") {
            let _ = send_message(&mut control, &frame);
        }
    }
    let _ = control.shutdown(std::net::Shutdown::Both);
    drop(running);
    result
}

/// `_control_loop` + `_schedule_rekey` + `_forward_rust`'s supervision, on one thread: poll the control socket
/// and the stop signals, run the rekey and rehandshake timers, and enforce the dead-peer timeout.
fn control_loop(cfg: &ClientConfig, tunnel: &Tunnel, control: &mut TcpStream, established: &mut Established, shared: &Shared,
                stop_signals: &SigSet, status: &mut Status) -> Result<(), ConnectError> {
    let signals = SignalFd::with_flags(stop_signals, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC).map_err(|e| net("signalfd")(e.into()))?;
    let mut os = Os;
    let interval = |seconds: u64| (seconds > 0).then_some(seconds as f64);
    let started = dataplane::now();
    let mut next_rekey = interval(tunnel.rekey_interval).map(|i| started + i);
    let mut next_rehandshake = interval(tunnel.rehandshake_interval).map(|i| started + i);
    let mut pending: Option<Pending> = None;
    status.connected(started, established.epoch(), next_rekey.map(|due| due - started), next_rehandshake.map(|due| due - started), shared);
    loop {
        let (control_ready, stop) = {
            let mut fds = [PollFd::new(control.as_fd(), PollFlags::POLLIN), PollFd::new(signals.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, PollTimeout::from(POLL_MS)) {
                Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                Err(error) => return Err(net("poll")(error.into())),
            }
            let ready = |fd: &PollFd<'_>| fd.revents().is_some_and(|r| !r.is_empty());
            (ready(&fds[0]), ready(&fds[1]))
        };
        if stop {
            let signal = signals.read_signal().ok().flatten().map(|s| s.ssi_signo);
            eprintln!("pqvpnd: stopping on signal {}", signal.unwrap_or(0));
            return Ok(());
        }
        if control_ready {
            let frame = recv_message(control).map_err(|_| ConnectError::Protocol("control channel lost".into()))?;
            let opened = established.open_control(&frame, None);
            match (pending.take(), opened) {
                (Some(Pending::Rekey(_)), Ok((REKEY_RESPONSE, response))) => {
                    established.finish_rekey(&response).map_err(protocol)?;
                    eprintln!("pqvpnd: rekey complete epoch={}", established.epoch());
                }
                (Some(Pending::Rehandshake(_)), Ok((REHANDSHAKE_RESPONSE, response))) => {
                    established.finish_rehandshake(&response).map_err(protocol)?;
                    eprintln!("pqvpnd: rehandshake complete epoch={}", established.epoch());
                }
                (_, Ok((CLOSE, _))) => return Err(ConnectError::Protocol("server closed session".into())),
                _ => return Err(ConnectError::Protocol("control session failure".into())),
            }
        }
        if let Some(error) = shared.error() {
            return Err(ConnectError::Network(format!("rust data plane: {error}")));
        }
        let now = dataplane::now();
        // `last_authenticated_udp_rx` starts at the bind acknowledgement, just before the loop.
        if now - shared.last_rx().max(started) > cfg.dead_peer_timeout {
            return Err(ConnectError::Network("authenticated UDP dead-peer timeout".into()));
        }
        status.tick(now, established.epoch(), next_rekey.map(|due| due - now), next_rehandshake.map(|due| due - now), shared);
        match pending {
            Some(Pending::Rekey(deadline) | Pending::Rehandshake(deadline)) if now > deadline => {
                established.abort_epoch_change();
                return Err(ConnectError::Protocol("rekey/rehandshake response timed out".into()));
            }
            Some(_) => {}
            None => {
                // One epoch change at a time; a due timer waits for the other to finish, as with `_rekey_lock`.
                if next_rekey.is_some_and(|due| now >= due) {
                    send_message(control, &established.begin_rekey(&mut os).map_err(protocol)?).map_err(net("rekey request"))?;
                    pending = Some(Pending::Rekey(now + REKEY_WAIT));
                    next_rekey = interval(tunnel.rekey_interval).map(|i| now + i);
                } else if next_rehandshake.is_some_and(|due| now >= due) {
                    send_message(control, &established.begin_rehandshake(&mut os).map_err(protocol)?)
                        .map_err(net("rehandshake request"))?;
                    pending = Some(Pending::Rehandshake(now + REHANDSHAKE_WAIT));
                    next_rehandshake = interval(tunnel.rehandshake_interval).map(|i| now + i);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: &str) -> Result<Tunnel, ConnectError> {
        parse_tunnel(json.as_bytes(), (Ipv4Addr::new(10, 8, 0, 0), 24))
    }

    const GOOD: &str = r#"{"session_id": "ab", "client_vpn_ip": "10.8.0.2", "server_vpn_ip": "10.8.0.1", "prefix": 24,
        "udp_port": 51820, "mtu": 1380, "routes": ["0.0.0.0/1", "128.0.0.0/1"], "dns": [], "epoch": 0,
        "rekey_interval": 3600, "rehandshake_interval": 0, "resumption": true}"#;

    #[test]
    fn parses_the_servers_config() {
        let tunnel = config(GOOD).unwrap();
        assert_eq!(tunnel, Tunnel { client_ip: Ipv4Addr::new(10, 8, 0, 2), server_vpn_ip: Ipv4Addr::new(10, 8, 0, 1), prefix: 24,
                                    udp_port: 51820, mtu: 1380, rekey_interval: 3600, rehandshake_interval: 0, resumption: true,
                                    dns: vec![] });
        assert_eq!(config(&GOOD.replace("\"dns\": []", "\"dns\": [\"10.8.0.1\", \"::1\"]")).unwrap().dns, ["10.8.0.1", "::1"]);
    }

    #[test]
    fn rejects_a_config_it_must_not_act_on() {
        for (from, to, needle) in [
            ("\"prefix\": 24", "\"prefix\": 16", "subnet"),
            ("\"server_vpn_ip\": \"10.8.0.1\"", "\"server_vpn_ip\": \"10.9.0.1\"", "subnet"),
            ("\"udp_port\": 51820", "\"udp_port\": 0", "UDP port"),
            ("\"udp_port\": 51820", "\"udp_port\": 70000", "UDP port"),
            ("\"mtu\": 1380", "\"mtu\": 9000", "mtu"),
            ("\"client_vpn_ip\": \"10.8.0.2\"", "\"client_vpn_ip\": \"::1\"", "client_vpn_ip"),
            ("\"rekey_interval\": 3600", "\"rekey_interval\": -1", "rekey_interval"),
            ("\"prefix\": 24", "\"prefix\": \"24\"", "prefix"),
            ("\"dns\": []", "\"dns\": [\"--set-everything\"]", "dns"),
            ("\"dns\": [], ", "", "dns"),
        ] {
            let error = config(&GOOD.replace(from, to)).unwrap_err().to_string();
            assert!(error.contains(needle), "{to}: {error}");
        }
        assert!(config("not json").is_err());
    }

    #[test]
    fn status_lines_follow_the_wire_spec_and_stay_bounded() {
        let line: serde_json::Value = serde_json::from_str(&status_line("CONNECTING", "", true, None)).unwrap();
        assert_eq!(line, serde_json::json!({"v": 1, "state": "CONNECTING", "error": "", "kill_switch": true}));
        // The worst case: the longest error plus every CONNECTED field, with the most and longest RTTs.
        let fields = serde_json::json!({
            "client_vpn_ip": "255.255.255.255", "server_vpn_ip": "255.255.255.255", "prefix": 30, "endpoint": "255.255.255.255:65535",
            "tun_name": "a-name-of-15-ch", "mtu": 1400, "suite": "v2-ed25519", "ipv6_guard": true, "dns_managed": true,
            "epoch": u32::MAX, "rekey_in": f64::MAX, "rehandshake_in": f64::MAX,
            "probes": {"sent": u64::MAX, "lost": u64::MAX, "rtts_ms": vec![-f64::MAX / 3.0; STATUS_MAX_RTTS]},
        }).as_object().cloned().unwrap();
        let text = status_line("FAILED", &"é\"\\\n".repeat(1000), false, Some(fields));
        assert!(text.len() <= STATUS_MAX && !text.contains('\n'), "{} bytes", text.len());
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["v"], 1);
        assert_eq!(parsed["probes"]["rtts_ms"].as_array().unwrap().len(), STATUS_MAX_RTTS);
    }

    #[test]
    fn full_tunnel_with_managed_dns_needs_servers() {
        let cfg = |extra: &str| config::parse(&format!("[client]\nserver_identity_fingerprint = \"{}\"\n{extra}", "a".repeat(64)), Path::new("/")).unwrap();
        let (none, some) = (config(GOOD).unwrap(), config(&GOOD.replace("\"dns\": []", "\"dns\": [\"10.8.0.1\"]")).unwrap());
        let error = dns_servers(&cfg(""), &none).unwrap_err().to_string();
        assert!(error.contains("no DNS servers"), "{error}");
        assert_eq!(dns_servers(&cfg(""), &some).unwrap(), ["10.8.0.1"], "the server's list");
        assert_eq!(dns_servers(&cfg("dns_servers = [\"9.9.9.9\"]"), &some).unwrap(), ["9.9.9.9"], "the client's list wins");
        assert!(dns_servers(&cfg("dns_mode = \"none\""), &none).unwrap().is_empty(), "explicitly unmanaged");
        assert!(dns_servers(&cfg("full_tunnel = false"), &none).unwrap().is_empty(), "split tunnel leaves other DNS alone");
    }

    #[test]
    fn control_framing_round_trips_and_bounds_length() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        send_message(&mut client, b"hello").unwrap();
        assert_eq!(recv_message(&mut server).unwrap(), b"hello");
        assert!(send_message(&mut client, &[]).is_err() && send_message(&mut client, &[0; MAX_CONTROL_MESSAGE + 1]).is_err());
        server.write_all(&(MAX_CONTROL_MESSAGE as u32 + 1).to_be_bytes()).unwrap();
        assert_eq!(recv_message(&mut client).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn resolves_literals_and_localhost_to_ipv4() {
        assert_eq!(resolve_ipv4("192.0.2.1", 51820).unwrap(), Ipv4Addr::new(192, 0, 2, 1));
        assert!(resolve_ipv4("localhost", 51820).unwrap().is_loopback());
        assert!(matches!(resolve_ipv4("::1", 51820), Err(ConnectError::Network(_))));
    }
}
