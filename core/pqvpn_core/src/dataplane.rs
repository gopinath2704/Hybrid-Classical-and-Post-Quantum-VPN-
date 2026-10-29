//! The UDP <-> TUN forwarding loop, mirroring `VPNServer._data_loop`/`_handle_datagram` and
//! `VPNClient._forward_data` in vpn/runtime.py. One worker thread that never calls into Python;
//! Python keeps the control channel, rekey derivation, idle/dead-peer policy and teardown.

use std::collections::HashMap;
use std::io::{IoSlice, IoSliceMut};
use std::net::SocketAddrV4;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

use arc_swap::ArcSwap;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{ControlMessage, MsgFlags, MultiHeaders, SockaddrIn, recvmmsg, sendmmsg};
use nix::time::{ClockId, clock_gettime};
use nix::unistd::{read, write};

use crate::packet;
use crate::session::{Error, HEADER_LEN, Role, Session};

pub const BATCH: usize = 64;
const MAX_DATAGRAM: usize = 65535;
const POLL_MS: f64 = 100.0;
const MAX_PENDING_RTTS: usize = 1024;
const DATA: u8 = 1;
const BIND: u8 = 2;
const BIND_ACK: u8 = 3;
const PING: u8 = 4;
const PONG: u8 = 5;
/// `_DATA_PROTOCOL_VERSIONS`: wire versions the server routes; the session re-checks its own.
const VERSIONS: [u8; 3] = [0x20, 0x30, 0x31];

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// CLOCK_MONOTONIC seconds, the clock behind Python's `time.monotonic()`, so times compare directly.
pub fn now() -> f64 {
    clock_gettime(ClockId::CLOCK_MONOTONIC).map_or(0.0, |t| t.tv_sec() as f64 + t.tv_nsec() as f64 * 1e-9)
}

struct Peer {
    session: Arc<Session>,
    lease: [u8; 4],
    /// Server: pinned by the first authenticated BIND and never moved (no roaming). Client: the server.
    endpoint: Mutex<Option<SocketAddrV4>>,
    /// f64 bits of the last authenticated activity (`ServerSession.touch`); 0 = none.
    last_seen: AtomicU64,
}

/// Swapped whole on add/remove, like `SessionManager`'s snapshot dicts, so the loop reads lock-free.
#[derive(Default, Clone)]
struct Table {
    by_id: HashMap<[u8; 8], Arc<Peer>>,
    by_ip: HashMap<[u8; 4], Arc<Peer>>,
}

#[derive(Default)]
pub struct Counters {
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub drops: AtomicU64,
    pub replay_rejects: AtomicU64,
}

/// Client keepalive results since the last drain, for Python's `NetworkQualityMonitor`.
#[derive(Default)]
pub struct Probes {
    pub sent: u64,
    pub lost: u64,
    pub rtts_ms: Vec<f64>,
}

pub struct Ping {
    pub initial: f64,
    pub interval: f64,
    pub timeout: f64,
}

pub struct Shared {
    role: Role,
    mtu: usize,
    /// The client's server endpoint; frames from anywhere else are ignored.
    server: Option<SocketAddrV4>,
    table: ArcSwap<Table>,
    writer: Mutex<()>,
    pub counters: Counters,
    pub probes: Mutex<Probes>,
    last_rx: AtomicU64,
    stop: AtomicBool,
    error: Mutex<Option<String>>,
}

enum Out {
    Tun(Vec<u8>),
    Udp(Vec<u8>, SocketAddrV4),
    Nothing,
}

impl Shared {
    pub fn new(role: Role, mtu: usize, server: Option<SocketAddrV4>) -> Self {
        Self {
            role,
            mtu,
            server,
            table: ArcSwap::default(),
            writer: Mutex::new(()),
            counters: Counters::default(),
            probes: Mutex::default(),
            last_rx: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            error: Mutex::new(None),
        }
    }

    fn update(&self, change: impl FnOnce(&mut Table)) {
        let _writer = lock(&self.writer);
        let mut table = Table::clone(&self.table.load());
        change(&mut table);
        self.table.store(Arc::new(table));
    }

    /// The session object is shared with Python's `HandshakeSession`, so its rekeys apply here atomically.
    pub fn add(&self, session: Arc<Session>, session_id: &[u8; 32], lease: [u8; 4]) {
        let id: [u8; 8] = session_id[..8].try_into().unwrap_or_default();
        let peer = Arc::new(Peer { session, lease, endpoint: Mutex::new(self.server), last_seen: AtomicU64::new(0) });
        self.update(|t| {
            t.by_id.insert(id, peer.clone());
            t.by_ip.insert(lease, peer);
        });
    }

    pub fn remove(&self, session_id: &[u8]) {
        let Some(id) = session_id.get(..8) else { return };
        self.update(|t| {
            if let Some(peer) = t.by_id.remove(id) {
                t.by_ip.remove(&peer.lease);
            }
        });
    }

    pub fn last_seen(&self, session_id: &[u8]) -> Option<f64> {
        let seen = self.table.load().by_id.get(session_id.get(..8)?)?.last_seen.load(Relaxed);
        (seen != 0).then(|| f64::from_bits(seen))
    }

    pub fn last_rx(&self) -> f64 {
        f64::from_bits(self.last_rx.load(Relaxed))
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Relaxed);
    }

    pub fn error(&self) -> Option<String> {
        lock(&self.error).clone()
    }

    fn drop_packet(&self) -> Out {
        self.counters.drops.fetch_add(1, Relaxed);
        Out::Nothing
    }

    fn open(&self, peer: &Peer, frame: &[u8]) -> Option<(u8, Vec<u8>)> {
        peer.session
            .open(frame, None)
            .inspect_err(|e| {
                if matches!(e, Error::Replayed | Error::OutsideWindow) {
                    self.counters.replay_rejects.fetch_add(1, Relaxed);
                }
            })
            .ok()
    }

    fn reply(&self, peer: &Peer, frame_type: u8, payload: &[u8], to: SocketAddrV4) -> Out {
        peer.session.seal(frame_type, payload).map_or_else(|_| self.drop_packet(), |frame| Out::Udp(frame, to))
    }

    /// `SessionManager.from_frame`: header gate, then the 8-byte session id.
    fn by_frame(&self, frame: &[u8]) -> Option<Arc<Peer>> {
        if frame.len() < HEADER_LEN || frame[..2] != *b"PV" || !VERSIONS.contains(&frame[2]) || frame[3] != 1 {
            return None;
        }
        self.table.load().by_id.get(&frame[6..14]).cloned()
    }

    /// `_handle_datagram`. A wrong endpoint is dropped before decryption, so it never moves the replay window.
    fn server_inbound(&self, frame: &[u8], from: SocketAddrV4, now: f64) -> Out {
        let Some(peer) = self.by_frame(frame) else { return self.drop_packet() };
        let endpoint = *lock(&peer.endpoint);
        if endpoint.is_some_and(|bound| bound != from) {
            return self.drop_packet();
        }
        let Some((frame_type, payload)) = self.open(&peer, frame) else { return self.drop_packet() };
        let bound = endpoint == Some(from);
        let touch = || peer.last_seen.store(now.to_bits(), Relaxed);
        match frame_type {
            BIND if payload == b"bind" => {
                *lock(&peer.endpoint) = Some(from);
                touch();
                self.reply(&peer, BIND_ACK, b"ok", from)
            }
            DATA if bound && packet::server_accepts(&payload, peer.lease, self.mtu) => {
                touch();
                Out::Tun(payload)
            }
            PING if bound && payload.len() == 8 => {
                touch();
                self.reply(&peer, PONG, &payload, from)
            }
            _ => self.drop_packet(),
        }
    }

    fn client_peer(&self) -> Option<Arc<Peer>> {
        self.table.load().by_id.values().next().cloned()
    }

    /// The receive half of `_forward_data`.
    fn client_inbound(&self, frame: &[u8], from: SocketAddrV4, now: f64, pending: &mut HashMap<[u8; 8], f64>) -> Out {
        let Some(peer) = self.client_peer().filter(|_| self.server == Some(from)) else { return self.drop_packet() };
        let Some((frame_type, payload)) = self.open(&peer, frame) else { return self.drop_packet() };
        match frame_type {
            DATA if packet::client_accepts(&payload, peer.lease, self.mtu) => {
                self.last_rx.store(now.to_bits(), Relaxed);
                Out::Tun(payload)
            }
            PONG => match <[u8; 8]>::try_from(payload.as_slice()) {
                Ok(stamp) if pending.remove(&stamp).is_some() => {
                    self.last_rx.store(now.to_bits(), Relaxed);
                    let mut probes = lock(&self.probes);
                    if probes.rtts_ms.len() < MAX_PENDING_RTTS {
                        probes.rtts_ms.push((now - f64::from_be_bytes(stamp)) * 1000.0);
                    }
                    Out::Nothing
                }
                _ => self.drop_packet(),
            },
            _ => self.drop_packet(),
        }
    }

    /// `_data_loop`'s TUN half: route by inner IPv4 destination to a bound session.
    fn server_outbound(&self, packet: &[u8]) -> Out {
        let destination = (packet.len() >= 20 && packet[0] >> 4 == 4).then(|| [packet[16], packet[17], packet[18], packet[19]]);
        let Some(peer) = destination.and_then(|d| self.table.load().by_ip.get(&d).cloned()) else { return self.drop_packet() };
        let endpoint = *lock(&peer.endpoint);
        match endpoint {
            Some(to) if packet.len() <= self.mtu => self.reply(&peer, DATA, packet, to),
            _ => self.drop_packet(),
        }
    }

    /// A seal failure ends the client loop, as the exception does in `_forward_data`.
    fn client_outbound(&self, packet: &[u8]) -> Result<Out, String> {
        let (Some(peer), Some(to)) = (self.client_peer(), self.server) else { return Ok(self.drop_packet()) };
        if packet.is_empty() || packet.len() > self.mtu {
            return Ok(self.drop_packet());
        }
        peer.session.seal(DATA, packet).map(|frame| Out::Udp(frame, to)).map_err(|e| format!("seal failed: {}", e.as_str()))
    }

    /// The keepalive half of `_forward_data`: expire, count, then send a `!d` monotonic stamp.
    fn client_ping(&self, now: f64, ping: &Ping, pending: &mut HashMap<[u8; 8], f64>) -> Result<Out, String> {
        let (Some(peer), Some(to)) = (self.client_peer(), self.server) else { return Ok(Out::Nothing) };
        let before = pending.len();
        pending.retain(|_, deadline| *deadline > now);
        {
            let mut probes = lock(&self.probes);
            probes.lost += (before - pending.len()) as u64;
            probes.sent += 1;
        }
        let stamp = now.to_be_bytes();
        pending.insert(stamp, now + ping.timeout);
        peer.session.seal(PING, &stamp).map(|frame| Out::Udp(frame, to)).map_err(|e| format!("seal failed: {}", e.as_str()))
    }
}

/// Per-packet failures that drop one packet; anything else ends the loop.
fn transient(errno: Errno) -> bool {
    matches!(errno, Errno::EAGAIN | Errno::EINTR | Errno::ENOBUFS | Errno::EMSGSIZE | Errno::ECONNREFUSED
        | Errno::EHOSTUNREACH | Errno::ENETUNREACH | Errno::EHOSTDOWN | Errno::ENETDOWN | Errno::EPERM)
}

pub struct Worker {
    pub udp: OwnedFd,
    pub tun: OwnedFd,
    pub ping: Option<Ping>,
}

struct Loop<'a> {
    shared: &'a Shared,
    worker: &'a Worker,
    tx_headers: MultiHeaders<SockaddrIn>,
    outgoing: Vec<(Vec<u8>, SocketAddrV4)>,
}

impl Loop<'_> {
    fn deliver(&mut self, out: Out) -> Result<(), String> {
        match out {
            Out::Tun(packet) => match write(&self.worker.tun, &packet) {
                Ok(_) => {
                    self.shared.counters.rx_packets.fetch_add(1, Relaxed);
                    self.shared.counters.rx_bytes.fetch_add(packet.len() as u64, Relaxed);
                }
                Err(Errno::EAGAIN | Errno::EINTR | Errno::ENOBUFS) => {
                    self.shared.drop_packet();
                }
                Err(e) => return Err(format!("tun write failed: {e}")),
            },
            Out::Udp(frame, to) => {
                self.outgoing.push((frame, to));
                if self.outgoing.len() == BATCH {
                    self.flush()?;
                }
            }
            Out::Nothing => {}
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        let mut start = 0;
        while start < self.outgoing.len() {
            let batch = &self.outgoing[start..];
            let slices: Vec<[IoSlice; 1]> = batch.iter().map(|(frame, _)| [IoSlice::new(frame)]).collect();
            let addresses: Vec<Option<SockaddrIn>> = batch.iter().map(|(_, to)| Some(SockaddrIn::from(*to))).collect();
            let no_cmsgs: [ControlMessage; 0] = [];
            let sent = match sendmmsg(self.worker.udp.as_raw_fd(), &mut self.tx_headers, &slices, &addresses[..], no_cmsgs, MsgFlags::MSG_DONTWAIT) {
                Ok(results) => results.count(),
                Err(Errno::EINTR) => continue,
                Err(e) if transient(e) => {
                    self.shared.drop_packet();
                    start += 1;
                    continue;
                }
                Err(e) => return Err(format!("udp send failed: {e}")),
            };
            for (frame, _) in &batch[..sent] {
                if frame[4] == DATA {
                    self.shared.counters.tx_packets.fetch_add(1, Relaxed);
                    self.shared.counters.tx_bytes.fetch_add((frame.len() - HEADER_LEN - crate::session::TAG_LEN) as u64, Relaxed);
                }
            }
            start += sent.max(1);
        }
        self.outgoing.clear();
        Ok(())
    }
}

pub fn run(shared: &Shared, worker: &Worker) -> Result<(), String> {
    let mut buffers = vec![vec![0u8; MAX_DATAGRAM]; BATCH];
    let mut rx_headers = MultiHeaders::<SockaddrIn>::preallocate(BATCH, None);
    let mut tun_buffer = vec![0u8; MAX_DATAGRAM];
    let mut pending: HashMap<[u8; 8], f64> = HashMap::new();
    let mut next_ping = worker.ping.as_ref().map(|p| now() + p.initial);
    let mut io = Loop { shared, worker, tx_headers: MultiHeaders::preallocate(BATCH, None), outgoing: Vec::with_capacity(BATCH) };
    while !shared.stop.load(Relaxed) {
        let wait = next_ping.map_or(POLL_MS, |at| ((at - now()) * 1000.0).clamp(0.0, POLL_MS));
        let mut fds = [PollFd::new(worker.udp.as_fd(), PollFlags::POLLIN), PollFd::new(worker.tun.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(wait.ceil() as u8)) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(format!("poll failed: {e}")),
        }
        let [udp_events, tun_events] = fds.map(|fd| fd.revents().unwrap_or(PollFlags::empty()));
        if udp_events.contains(PollFlags::POLLNVAL) || tun_events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL) {
            return Err("udp or tun descriptor failed".into());
        }
        if udp_events.intersects(PollFlags::POLLIN | PollFlags::POLLERR) {
            let received: Vec<(usize, Option<SockaddrIn>)> = {
                let mut slices: Vec<[IoSliceMut; 1]> = buffers.iter_mut().map(|b| [IoSliceMut::new(b)]).collect();
                match recvmmsg(worker.udp.as_raw_fd(), &mut rx_headers, slices.iter_mut(), MsgFlags::MSG_DONTWAIT, None) {
                    Ok(results) => results.map(|m| (m.bytes, m.address)).collect(),
                    Err(e) if transient(e) => Vec::new(),
                    Err(e) => return Err(format!("udp receive failed: {e}")),
                }
            };
            let now = now();
            for (buffer, (len, from)) in buffers.iter().zip(received) {
                let Some(from) = from else { continue };
                let (frame, from) = (&buffer[..len], SocketAddrV4::from(from));
                let out = match shared.role {
                    Role::Server => shared.server_inbound(frame, from, now),
                    Role::Client => shared.client_inbound(frame, from, now, &mut pending),
                };
                io.deliver(out)?;
            }
        }
        if tun_events.contains(PollFlags::POLLIN) {
            for _ in 0..BATCH {
                let len = match read(&worker.tun, &mut tun_buffer) {
                    Ok(len) => len,
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(e) => return Err(format!("tun read failed: {e}")),
                };
                let out = match shared.role {
                    Role::Server => shared.server_outbound(&tun_buffer[..len]),
                    Role::Client => shared.client_outbound(&tun_buffer[..len])?,
                };
                io.deliver(out)?;
            }
        }
        if let (Some(ping), Some(at)) = (worker.ping.as_ref(), next_ping) {
            let now = now();
            if now >= at {
                let out = shared.client_ping(now, ping, &mut pending)?;
                io.deliver(out)?;
                next_ping = Some(now + ping.interval);
            }
        }
        io.flush()?;
    }
    Ok(())
}

/// Records a worker's error or panic in `shared` so Python sees it without joining.
pub fn guarded(shared: &Shared, work: impl FnOnce() -> Result<(), String>) {
    let failure = match catch_unwind(AssertUnwindSafe(work)) {
        Ok(Ok(())) => return,
        Ok(Err(message)) => message,
        Err(_) => "data-plane worker panicked".to_string(),
    };
    *lock(&shared.error) = Some(failure);
}

/// The worker owns its descriptors, so they close as soon as it exits.
pub fn spawn(shared: Arc<Shared>, worker: Worker) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new().name("pqvpn-dp".into()).spawn(move || guarded(&shared, || run(&shared, &worker)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::net::UnixDatagram;
    use std::time::{Duration, Instant};

    const SID: [u8; 32] = [7; 32];
    const LEASE: [u8; 4] = [10, 8, 0, 2];

    fn sessions(epoch: u32) -> (Arc<Session>, Arc<Session>) {
        let (c2s, s2c, nc, ns) = ([1; 32], [2; 32], [3; 12], [4; 12]);
        (Arc::new(Session::new(Role::Client, &SID, 0x20, epoch, &c2s, &nc, &s2c, &ns).unwrap()),
         Arc::new(Session::new(Role::Server, &SID, 0x20, epoch, &s2c, &ns, &c2s, &nc).unwrap()))
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(20 + payload.len()).unwrap().to_be_bytes();
        [&[0x45, 0, total[0], total[1]][..], &[0; 8], &src, &dst, payload].concat()
    }

    fn addr(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new([127, 0, 0, 1].into(), port)
    }

    /// The 14 cases of `test_only_authorized_current_records_touch_activity`, against a server
    /// whose session is already bound to `addr(12345)`.
    #[test]
    fn only_authorized_current_records_touch_activity() {
        let cases = ["ping", "data", "replay", "wrong_session", "unknown_session", "wrong_endpoint", "malformed_ping",
                     "bad_tag", "truncated", "spoof", "malformed_data", "old_epoch", "control_domain", "bad_bind"];
        for case in cases {
            let (client, server) = sessions(0);
            let shared = Shared::new(Role::Server, 1380, None);
            shared.add(server.clone(), &SID, LEASE);
            *lock(&shared.table.load().by_id[&SID[..8]].endpoint) = Some(addr(12345));
            let mut from = addr(12345);
            let stamp = 1.5f64.to_be_bytes();
            let mut frame = client.seal(PING, &stamp).unwrap();
            match case {
                "replay" => {
                    assert!(matches!(shared.server_inbound(&frame, from, 1.0), Out::Udp(..)));
                    lock(&shared.table.load().by_id[&SID[..8]].endpoint).take();
                    shared.remove(&SID);
                    shared.add(server.clone(), &SID, LEASE);
                    *lock(&shared.table.load().by_id[&SID[..8]].endpoint) = Some(from);
                }
                "wrong_session" => {
                    let other = Session::new(Role::Client, &[8; 32], 0x20, 0, &[1; 32], &[3; 12], &[2; 32], &[4; 12]).unwrap();
                    frame = other.seal(PING, &stamp).unwrap();
                    let peer = shared.table.load().by_id[&SID[..8]].clone();
                    shared.update(|t| { t.by_id.insert([8; 8], peer); });
                }
                "unknown_session" => {
                    let other = Session::new(Role::Client, &[8; 32], 0x20, 0, &[1; 32], &[3; 12], &[2; 32], &[4; 12]).unwrap();
                    frame = other.seal(PING, &stamp).unwrap();
                }
                "wrong_endpoint" => from = addr(54321),
                "malformed_ping" => frame = client.seal(PING, b"bad").unwrap(),
                "bad_tag" => *frame.last_mut().unwrap() ^= 1,
                "truncated" => frame.truncate(10),
                "data" => frame = client.seal(DATA, &ipv4(LEASE, [1, 1, 1, 1], b"")).unwrap(),
                "spoof" => frame = client.seal(DATA, &ipv4([10, 8, 0, 3], [1, 1, 1, 1], b"")).unwrap(),
                "malformed_data" => frame = client.seal(DATA, b"bad").unwrap(),
                "old_epoch" => server.rekey(1, &[5; 32], &[4; 12], &[6; 32], &[3; 12]).unwrap(),
                "control_domain" => frame[3] = 2,
                "bad_bind" => frame = client.seal(BIND, b"bad").unwrap(),
                _ => {}
            }
            let out = shared.server_inbound(&frame, from, 2.0);
            let seen = shared.last_seen(&SID);
            match case {
                "ping" => {
                    let Out::Udp(pong, to) = out else { panic!("ping: no pong") };
                    assert_eq!(to, from);
                    assert_eq!(client.open(&pong, Some(PONG)).unwrap().1, stamp);
                    assert_eq!(seen, Some(2.0));
                }
                "data" => {
                    assert!(matches!(out, Out::Tun(_)));
                    assert_eq!(seen, Some(2.0));
                }
                _ => {
                    assert!(matches!(out, Out::Nothing), "{case}");
                    assert_eq!(seen, None, "{case}");
                }
            }
        }
    }

    #[test]
    fn bind_pins_the_first_endpoint_and_never_roams() {
        let (client, server) = sessions(0);
        let shared = Shared::new(Role::Server, 1380, None);
        shared.add(server, &SID, LEASE);
        let packet = ipv4([1, 1, 1, 1], LEASE, b"down");
        assert!(matches!(shared.server_outbound(&packet), Out::Nothing), "unbound sessions get no traffic");
        let Out::Udp(ack, to) = shared.server_inbound(&client.seal(BIND, b"bind").unwrap(), addr(1000), 1.0) else { panic!() };
        assert_eq!((client.open(&ack, Some(BIND_ACK)).unwrap().1, to), (b"ok".to_vec(), addr(1000)));
        assert!(matches!(shared.server_inbound(&client.seal(BIND, b"bind").unwrap(), addr(2000), 2.0), Out::Nothing));
        let Out::Udp(down, to) = shared.server_outbound(&packet) else { panic!() };
        assert_eq!((client.open(&down, Some(DATA)).unwrap().1, to), (packet, addr(1000)));
        shared.remove(&SID);
        assert!(matches!(shared.server_outbound(&ipv4([1, 1, 1, 1], LEASE, b"")), Out::Nothing));
        assert_eq!(shared.last_seen(&SID), None);
    }

    #[test]
    fn client_accepts_only_its_server_its_lease_and_its_own_pongs() {
        let (client, server) = sessions(0);
        let shared = Shared::new(Role::Client, 1380, Some(addr(1)));
        shared.add(client, &SID, LEASE);
        let mut pending = HashMap::new();
        let Out::Udp(ping, _) = shared.client_ping(10.0, &Ping { initial: 0.0, interval: 1.0, timeout: 4.0 }, &mut pending).unwrap() else { panic!() };
        let (_, stamp) = server.open(&ping, Some(PING)).unwrap();
        assert_eq!(stamp, 10.0f64.to_be_bytes());
        let mine = ipv4([1, 1, 1, 1], LEASE, b"x");
        assert!(matches!(shared.client_inbound(&server.seal(DATA, &mine).unwrap(), addr(2), 11.0, &mut pending), Out::Nothing));
        assert!(matches!(shared.client_inbound(&server.seal(DATA, &ipv4([1, 1, 1, 1], [10, 8, 0, 9], b"")).unwrap(), addr(1), 11.0, &mut pending), Out::Nothing));
        assert!(matches!(shared.client_inbound(&server.seal(PONG, &[0; 8]).unwrap(), addr(1), 11.0, &mut pending), Out::Nothing));
        assert_eq!(shared.last_rx(), 0.0, "nothing authenticated and expected yet");
        assert!(matches!(shared.client_inbound(&server.seal(DATA, &mine).unwrap(), addr(1), 11.0, &mut pending), Out::Tun(p) if p == mine));
        assert_eq!(shared.last_rx(), 11.0);
        assert!(matches!(shared.client_inbound(&server.seal(PONG, &stamp).unwrap(), addr(1), 10.25, &mut pending), Out::Nothing));
        assert_eq!(lock(&shared.probes).rtts_ms, vec![250.0]);
        assert!(pending.is_empty());
    }

    #[test]
    fn unanswered_pings_count_as_lost_after_their_timeout() {
        let (client, _) = sessions(0);
        let shared = Shared::new(Role::Client, 1380, Some(addr(1)));
        shared.add(client, &SID, LEASE);
        let (ping, mut pending) = (Ping { initial: 0.0, interval: 1.0, timeout: 1.5 }, HashMap::new());
        for now in [1.0, 2.0, 3.0] {
            shared.client_ping(now, &ping, &mut pending).unwrap();
        }
        let probes = lock(&shared.probes);
        assert_eq!((probes.sent, probes.lost, pending.len()), (3, 1, 2));
    }

    fn worker(udp: &UdpSocket, tun: UnixDatagram, ping: Option<Ping>) -> Worker {
        udp.set_nonblocking(true).unwrap();
        tun.set_nonblocking(true).unwrap();
        Worker { udp: udp.try_clone().unwrap().into(), tun: tun.into(), ping }
    }

    fn recv(peer: &UnixDatagram) -> Vec<u8> {
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buffer = [0u8; 2048];
        let len = peer.recv(&mut buffer).unwrap();
        buffer[..len].to_vec()
    }

    #[test]
    fn forwards_both_ways_over_real_sockets_and_stops() {
        let (client_session, server_session) = sessions(0);
        let (server_udp, client_udp) = (UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap());
        let server_addr = match server_udp.local_addr().unwrap() { std::net::SocketAddr::V4(a) => a, _ => unreachable!() };
        let ((server_tun, server_wire), (client_tun, client_wire)) = (UnixDatagram::pair().unwrap(), UnixDatagram::pair().unwrap());
        let server = Arc::new(Shared::new(Role::Server, 1380, None));
        server.add(server_session, &SID, LEASE);
        let client = Arc::new(Shared::new(Role::Client, 1380, Some(server_addr)));
        client.add(client_session.clone(), &SID, LEASE);
        client_udp.send_to(&client_session.seal(BIND, b"bind").unwrap(), server_addr).unwrap();
        let workers = [spawn(server.clone(), worker(&server_udp, server_tun, None)).unwrap(),
                       spawn(client.clone(), worker(&client_udp, client_tun, Some(Ping { initial: 0.05, interval: 0.05, timeout: 1.0 }))).unwrap()];
        let deadline = Instant::now() + Duration::from_secs(2);
        while server.last_seen(&SID).is_none() {
            assert!(Instant::now() < deadline, "server never saw the BIND");
            std::thread::sleep(Duration::from_millis(5));
        }
        for i in 0..3u8 {
            let (up, down) = (ipv4(LEASE, [1, 1, 1, 1], &[i; 100]), ipv4([1, 1, 1, 1], LEASE, &[i; 1000]));
            client_wire.send(&up).unwrap();
            assert_eq!(recv(&server_wire), up);
            server_wire.send(&down).unwrap();
            assert_eq!(recv(&client_wire), down);
        }
        while lock(&client.probes).rtts_ms.is_empty() {
            assert!(Instant::now() < deadline, "no PONG came back");
            std::thread::sleep(Duration::from_millis(5));
        }
        for shared in [&server, &client] {
            shared.request_stop();
        }
        for handle in workers {
            handle.join().unwrap();
        }
        assert_eq!((client.counters.tx_packets.load(Relaxed), client.counters.rx_packets.load(Relaxed)), (3, 3));
        assert_eq!((server.counters.tx_bytes.load(Relaxed), server.counters.rx_bytes.load(Relaxed)), (3 * 1020, 3 * 120));
        assert!(server.error().is_none() && client.error().is_none());
        let closed = std::os::unix::net::UnixDatagram::unbound().unwrap();
        assert!(closed.connect_addr(&server_wire.peer_addr().unwrap()).is_err(), "the worker closed its tun end");
    }

    #[test]
    fn io_error_and_panic_reach_the_shared_error_without_hanging() {
        let (client_session, server_session) = sessions(0);
        let (client_udp, sender) = (UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap());
        let sender_addr = match sender.local_addr().unwrap() { std::net::SocketAddr::V4(a) => a, _ => unreachable!() };
        let (client_tun, client_wire) = UnixDatagram::pair().unwrap();
        drop(client_wire);
        let client = Arc::new(Shared::new(Role::Client, 1380, Some(sender_addr)));
        client.add(client_session, &SID, LEASE);
        let handle = spawn(client.clone(), worker(&client_udp, client_tun, None)).unwrap();
        sender.send_to(&server_session.seal(DATA, &ipv4([1, 1, 1, 1], LEASE, b"x")).unwrap(), client_udp.local_addr().unwrap()).unwrap();
        handle.join().unwrap();
        assert!(client.error().unwrap().starts_with("tun write failed"), "{:?}", client.error());

        let shared = Shared::new(Role::Server, 1380, None);
        guarded(&shared, || panic!("boom"));
        assert_eq!(shared.error().as_deref(), Some("data-plane worker panicked"));
    }
}
