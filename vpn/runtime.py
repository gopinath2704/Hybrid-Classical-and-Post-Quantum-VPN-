"""Linux client/server runtime with transactional networking and strict channel separation."""
from __future__ import annotations

import enum
import ipaddress
import json
import logging
import os
import queue
import select
import selectors
import shlex
import socket
import stat
import struct
import subprocess
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from crypto.hybrid_crypto import PQCUnavailableError
from handshake.kemtls import (Channel, DATA_HEADER_FORMAT, DATA_HEADER_SIZE, DATA_MAGIC,
    FrameType, HandshakeError, HandshakeSession, KEMTLSClient, KEMTLSServer, PROTOCOL_VERSION,
    KEMTLSClientV3, KEMTLSServerV3, PROTOCOL_VERSION_V3, PROTOCOL_VERSION_V3_MLDSA, HEADER_SIZE, HEADER_FORMAT,
    MessageType, CookieProtector, pack_cookie_challenge, unpack_cookie_challenge,
    pack_cookie_response, unpack_cookie_response,
    ResumptionTicketKey, ResumptionClientHandshake, ResumptionServerHandshake, _core)
from vpn.config import ClientConfig, ServerConfig, validate_server, validate_client
from vpn.network import NetworkQualityMonitor, TUNInterface, TUNMode
from vpn.identity import AuthorizedClients, load_client_kem_private, load_client_private, validate_server_identity
from vpn.network import IPv6Guard, effective_policy, preflight as ipv6_preflight

logger = logging.getLogger("pqvpn.runtime")
MAX_CONTROL_MESSAGE = 16384
# The Python loop warns per rejected inner packet; the Rust loop's count is logged at most this often.
INNER_REJECT_LOG_INTERVAL = 10.0
# ponytail: control accept backlog, fixed rather than max_clients (enforced at admission). M7 at a
# 10k/s flood: 64 beat 512 and 4096, whose deeper queue makes legitimate connects wait behind it.
CONTROL_LISTEN_BACKLOG = 64


def send_message(sock: socket.socket, data: bytes) -> None:
    if not data or len(data) > MAX_CONTROL_MESSAGE:
        raise HandshakeError("invalid control message length")
    sock.sendall(struct.pack("!I", len(data)) + data)


def set_nodelay(sock: socket.socket) -> socket.socket:
    # ServerFinished, CONFIG and the ticket are separate small writes; with Nagle, CONFIG waits
    # for the peer's delayed ACK (~40 ms + 1 RTT). Framing is unchanged: recv_exact reassembles.
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise HandshakeError("control connection closed")
        chunks.extend(part)
    return bytes(chunks)


def recv_message(sock: socket.socket) -> bytes:
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size <= 0 or size > MAX_CONTROL_MESSAGE:
        raise HandshakeError("invalid control message length")
    return recv_exact(sock, size)


class IPPool:
    def __init__(self, subnet: str, server_ip: str) -> None:
        self.network = ipaddress.ip_network(subnet)
        self.server = ipaddress.ip_address(server_ip)
        if self.server not in self.network or self.server in {self.network.network_address, self.network.broadcast_address}:
            raise ValueError("server VPN IP must be a usable host in the VPN subnet")
        self._leases: dict[str, ipaddress._BaseAddress] = {}
        self.reserved = {}
        self._used = {self.server}
        self._lock = threading.Lock()

    def _valid_host(self, candidate: ipaddress._BaseAddress) -> bool:
        return (candidate.version == self.network.version and candidate in self.network
                and candidate not in {self.network.network_address, self.network.broadcast_address, self.server}
                and candidate not in self._used)

    def allocate(self, client_id: str, preferred: str | None = None) -> str:
        with self._lock:
            if client_id in self._leases:
                return str(self._leases[client_id])
            if preferred is not None:
                try:
                    candidate = ipaddress.ip_address(preferred)
                except ValueError as exc:
                    raise ValueError("invalid preferred VPN IP") from exc
                if not self._valid_host(candidate):
                    raise ValueError("preferred VPN IP is not an available host address")
                candidates = (candidate,)
            else:
                candidates = self.network.hosts()
            for candidate in candidates:
                if self._valid_host(candidate) and self.reserved.get(str(candidate), client_id) == client_id:
                    self._leases[client_id] = candidate
                    self._used.add(candidate)
                    return str(candidate)
            raise RuntimeError("VPN address pool exhausted")

    def release(self, client_id: str) -> None:
        with self._lock:
            value = self._leases.pop(client_id, None)
            if value:
                self._used.discard(value)


def validate_client_packet(packet: bytes, assigned_ip: str) -> bool:
    """Accept only complete IPv4 packets whose inner source is the session lease."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return False
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(packet):
        return False
    total_length = struct.unpack("!H", packet[2:4])[0]
    if total_length < ihl or total_length != len(packet):
        return False
    try:
        source = str(ipaddress.IPv4Address(packet[12:16]))
    except ipaddress.AddressValueError:
        return False
    return source == assigned_ip


def rust_data_plane(role: str, udp: socket.socket, tun: TUNInterface, mtu: int, **client: object) -> object:
    """pqvpn_core.DataPlane over dups of `udp` and `tun`. Rust owns the dups only once it is built;
    until then they are ours to close. Python's originals stay open for the existing cleanup."""
    import pqvpn_core
    fds: list[int] = []
    try:
        fds.append(os.dup(udp.fileno()))
        fds.append(os.dup(tun.fileno()))
        return pqvpn_core.DataPlane(role, *fds, mtu, emulated_tun=tun.mode != TUNMode.NATIVE, **client)
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise


def run_ip(*args: str, check: bool = True):
    return subprocess.run(["ip", *args], check=check, capture_output=True, text=True)


def open_tun(name: str, mtu: int, dev: bool = False) -> TUNInterface:
    tun = TUNInterface(name=name, mtu=mtu, mode=TUNMode.SOCKET_PIPE if dev else TUNMode.NATIVE)
    try:
        tun.open()
    except (OSError, PermissionError) as exc:
        raise RuntimeError("native TUN required; use --dev-emulated-tun only for tests") from exc
    return tun


def configure_tun(tun: TUNInterface, address: str, prefix: int) -> None:
    if tun.mode != TUNMode.NATIVE:
        return
    run_ip("addr", "replace", f"{address}/{prefix}", "dev", tun.name)
    run_ip("link", "set", "dev", tun.name, "mtu", str(tun.mtu), "up")


@dataclass
class RouteUndo:
    destination: str
    installed: list[str]
    previous: list[list[str]]


class ClientNetwork:
    """Capture exact previous routes and restore all partial route/DNS changes."""
    def __init__(self, tun: TUNInterface, server_public: str, full_tunnel: bool,
                 split: list[str], dns: list[str], kill_switch: bool = False,
                 dns_mode: str = "systemd-resolved", dns_routing_domains: list[str] | None = None,
                 ipv6_policy: str | None = None) -> None:
        self.tun, self.server_public = tun, server_public
        self.full, self.split, self.dns, self.kill_switch = full_tunnel, split, dns, kill_switch
        self.dns_mode, self.dns_routing_domains = dns_mode, dns_routing_domains or []
        self.route_undo: list[RouteUndo] = []
        self.dns_cleanup_registered = False
        self.ipv6 = IPv6Guard(effective_policy(full_tunnel, ipv6_policy))

    @staticmethod
    def _existing_routes(destination: str) -> list[list[str]]:
        result = run_ip("route", "show", "exact", destination)
        return [shlex.split(line) for line in result.stdout.splitlines() if line.strip()]

    def _replace_route(self, destination: str, route_args: list[str]) -> None:
        previous = self._existing_routes(destination)
        run_ip("route", "replace", *route_args)
        self.route_undo.append(RouteUndo(destination, route_args, previous))

    def apply(self) -> None:
        if self.tun.mode != TUNMode.NATIVE:
            return
        try:
            self.ipv6.apply()
            route = shlex.split(run_ip("route", "get", self.server_public).stdout.splitlines()[0])
            gateway = route[route.index("via") + 1] if "via" in route else None
            device = route[route.index("dev") + 1]
            bypass = [f"{self.server_public}/32"] + (["via", gateway] if gateway else []) + ["dev", device]
            self._replace_route(f"{self.server_public}/32", bypass)
            for cidr in (["0.0.0.0/1", "128.0.0.0/1"] if self.full else self.split):
                self._replace_route(cidr, [cidr, "dev", self.tun.name])
            if self.dns_mode == "none":
                logger.warning("DNS is explicitly unmanaged (dns_mode=none); DNS may bypass the VPN")
            elif self.dns:
                if subprocess.run(["which", "resolvectl"], capture_output=True).returncode != 0:
                    raise RuntimeError("configured VPN DNS requires resolvectl; use dns_mode=none only to explicitly accept unmanaged DNS")
                # Register first so failure in either command still reverts the first mutation.
                self.dns_cleanup_registered = True
                subprocess.run(["resolvectl", "dns", self.tun.name, *self.dns], check=True)
                domains = ["~."] if self.full else self.dns_routing_domains
                if domains:
                    subprocess.run(["resolvectl", "domain", self.tun.name, *domains], check=True)
        except Exception:
            self.restore()
            raise

    def restore(self) -> None:
        try:
            self._restore_ipv4_dns()
        finally:
            # Remove the IPv6 guard last, including when an earlier undo fails.
            self.ipv6.restore()

    def _restore_ipv4_dns(self) -> None:
        if self.dns_cleanup_registered:
            subprocess.run(["resolvectl", "revert", self.tun.name], check=False)
            self.dns_cleanup_registered = False
        for undo in reversed(self.route_undo):
            run_ip("route", "del", *undo.installed, check=False)
            for previous in undo.previous:
                run_ip("route", "replace", *previous, check=False)
        self.route_undo.clear()


@dataclass
class ServerSession:
    crypto: HandshakeSession
    vpn_ip: str
    control: socket.socket
    client_id: str
    endpoint: tuple[str, int] | None = None
    last_seen: float = field(default_factory=time.monotonic)
    created: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        """Called under the session-manager lock after authentication/authorization."""
        self.last_seen = time.monotonic()


@dataclass
class _ControlConn:
    """An established session's control socket, owned by the selector thread after hand-off."""
    item: ServerSession
    sock: socket.socket
    source: str
    rx: bytearray = field(default_factory=bytearray)
    stalled_since: float = 0.0


# Data-plane wire versions the server will route; the per-session
# HandshakeSession re-validates the exact version in decrypt_frame.
_DATA_PROTOCOL_VERSIONS = frozenset(
    {PROTOCOL_VERSION, PROTOCOL_VERSION_V3, PROTOCOL_VERSION_V3_MLDSA})


class SessionManager:
    """Session index with lock-free reads on the hot data path.

    Mutations (add/remove) publish new snapshot dicts atomically via Python's
    GIL-protected reference assignment.  The data loop reads _snap_id / _snap_ip
    without locking — no contention on every datagram.
    """
    def __init__(self) -> None:
        self.by_id: dict[bytes, ServerSession] = {}
        self.by_ip: dict[str, ServerSession] = {}
        # ponytail: atomic snapshots for lock-free reads; upgrade to sharded
        # dicts if session count exceeds ~10k
        self._snap_id: dict[bytes, ServerSession] = {}
        self._snap_ip: dict[str, ServerSession] = {}
        self.lock = threading.RLock()
        # The Rust data plane (pqvpn_core.DataPlane) when data_plane="rust"; it mirrors this table.
        self.dp = None

    def _publish(self) -> None:
        """Publish immutable snapshots after a mutation (called under lock)."""
        self._snap_id = dict(self.by_id)
        self._snap_ip = dict(self.by_ip)

    def add(self, item: ServerSession) -> None:
        with self.lock:
            key = item.crypto.session_id[:8]
            if key in self.by_id or item.vpn_ip in self.by_ip:
                raise RuntimeError("duplicate session or VPN IP")
            self.by_id[key], self.by_ip[item.vpn_ip] = item, item
            if self.dp:
                self.dp.add_session(item.crypto._data, item.crypto.session_id, item.vpn_ip)
            self._publish()

    def remove(self, item: ServerSession) -> None:
        with self.lock:
            self.by_id.pop(item.crypto.session_id[:8], None)
            self.by_ip.pop(item.vpn_ip, None)
            if self.dp:
                # Keep the record's final data-path activity once Rust forgets the session.
                item.last_seen = max(item.last_seen, self.dp.last_seen(item.crypto.session_id) or 0.0)
                self.dp.remove_session(item.crypto.session_id)
            self._publish()

    def from_frame(self, data: bytes) -> ServerSession | None:
        if len(data) < DATA_HEADER_SIZE:
            return None
        try:
            magic, version, channel, _, _, session_id, _, _ = struct.unpack(DATA_HEADER_FORMAT, data[:DATA_HEADER_SIZE])
        except struct.error:
            return None
        if magic != DATA_MAGIC or version not in _DATA_PROTOCOL_VERSIONS or channel != Channel.DATA:
            return None
        # Lock-free read — _snap_id is an immutable snapshot.
        # The per-session HandshakeSession re-checks version against its own
        # protocol in decrypt_frame; here we only gate the wire magic/version.
        return self._snap_id.get(session_id)

    def destination(self, packet: bytes) -> ServerSession | None:
        if not packet:
            return None
        version = packet[0] >> 4
        if version == 4 and len(packet) >= 20:
            destination = str(ipaddress.ip_address(packet[16:20]))
        elif version == 6 and len(packet) >= 40:
            destination = str(ipaddress.ip_address(packet[24:40]))
        else:
            return None
        # Lock-free read
        return self._snap_ip.get(destination)


class SourceRateLimiter:
    def __init__(self, limit: int = 10, window: float = 60.0, max_sources: int = 65536) -> None:
        self.limit, self.window, self.max_sources = limit, window, max_sources
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()
        self.next_prune = 0.0

    def allow(self, source: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self.lock:
            if now >= self.next_prune:
                for key, events in list(self.events.items()):
                    if not events or events[-1] <= now - self.window:
                        del self.events[key]
                self.next_prune = now + self.window
            if source not in self.events and len(self.events) >= self.max_sources:
                return False
            queue = self.events[source]
            while queue and queue[0] <= now - self.window:
                queue.popleft()
            if len(queue) >= self.limit:
                return False
            queue.append(now)
            return True


class VPNServer:
    def __init__(self, config: ServerConfig) -> None:
        validate_server(config, test_ports=config.dev_emulated_tun)
        self.cfg = config
        self.auth = AuthorizedClients(Path(config.authorized_clients_file))
        self.pool = IPPool(config.vpn_subnet, config.server_vpn_ip)
        self.sessions = SessionManager()
        self.stop_event = threading.Event()
        self.tun = self.udp = self.tcp = None
        self.slots = threading.BoundedSemaphore(config.max_clients)
        self.rate_limiter = SourceRateLimiter(config.connections_per_source, config.rate_limit_window)
        if config.handshake == "rust":
            # pqvpn_core reads and checks the private key itself; Python never holds it.
            self.identity_public = Path(config.server_identity_public_key).read_bytes()
            self.identity_secret = _core().Identity.kem_file(config.server_identity_private_key, self.identity_public)
        else:
            self.identity_secret, self.identity_public = validate_server_identity(
                Path(config.server_identity_private_key), Path(config.server_identity_public_key))
        records = self.auth._load(required=True, subnet=config.vpn_subnet, server_ip=config.server_vpn_ip)
        self.pool.reserved = {item['assigned_ip']: item['client_id'] for item in records['clients'] if item.get('assigned_ip')}
        self._data_thread = None
        self._dp = None
        self._client_threads: list[threading.Thread] = []
        self._cookie = CookieProtector() if config.cookie_mode != "off" else None
        self._ticket_key = self._new_ticket_key() if config.resumption_ticket_lifetime > 0 else None
        self._pending_handshakes = 0
        self._pending_lock = threading.Lock()
        self._revocation_thread = None
        self._last_auth_snapshot: set[str] | None = None
        # Established sessions are served by one selector thread; handshake threads exit at hand-off,
        # so a session no longer pins a thread's stack (M8). The max_clients slot is held until session end.
        self._selector_thread = None
        self._selector_open = False
        self._selector_socks: set[socket.socket] = set()
        self._handoffs: queue.SimpleQueue = queue.SimpleQueue()
        self._handoff_lock = threading.Lock()
        self._wake_r = self._wake_w = -1

    def start(self) -> None:
        try:
            self.tun = open_tun(self.cfg.tun_name, self.cfg.mtu, self.cfg.dev_emulated_tun)
            configure_tun(self.tun, self.cfg.server_vpn_ip, ipaddress.ip_network(self.cfg.vpn_subnet).prefixlen)
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.bind((self.cfg.listen_host, self.cfg.udp_port))
            self.udp.setblocking(False)
            if self.cfg.data_plane == "rust":
                self._dp = rust_data_plane("server", self.udp, self.tun, self.cfg.mtu)
                self.sessions.dp = self._dp
                self._dp.start()
            self.tcp = socket.socket()
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp.bind((self.cfg.listen_host, self.cfg.control_port))
            self.tcp.listen(CONTROL_LISTEN_BACKLOG)
            self.tcp.settimeout(1)
            listener = self.tcp
            self._data_thread = threading.Thread(target=self._watch_data_plane if self._dp else self._data_loop,
                                                 daemon=True, name="pqvpn-data")
            self._data_thread.start()
            self._revocation_thread = threading.Thread(target=self._revocation_loop, daemon=True, name="pqvpn-revoke")
            self._revocation_thread.start()
            self._wake_r, self._wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            self._selector_open = True
            self._selector_thread = threading.Thread(target=self._serve_control, daemon=True, name="pqvpn-control")
            self._selector_thread.start()
            while not self.stop_event.is_set():
                try:
                    connection, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                if not self.rate_limiter.allow(address[0]):
                    logger.warning("handshake rate limit exceeded source=%s", address[0])
                    connection.close()
                    continue
                if not self.slots.acquire(False):
                    logger.warning("global handshake limit reached source=%s", address[0])
                    connection.close()
                    continue
                thread = threading.Thread(target=self._client, args=(connection, address), daemon=True)
                self._client_threads = [item for item in self._client_threads if item.is_alive()] + [thread]
                thread.start()
        finally:
            self._close_listeners()

    def _new_ticket_key(self) -> object:
        return _core().TicketKey() if self.cfg.handshake == "rust" else ResumptionTicketKey()

    def _needs_cookie(self) -> bool:
        if self._cookie is None:
            return False
        if self.cfg.cookie_mode == "always":
            return True
        with self._pending_lock:
            return self._pending_handshakes >= self.cfg.cookie_threshold

    def _client(self, connection: socket.socket, address: tuple[str, int]) -> None:
        item = None
        handed_off = False
        # Counts handshakes in progress for cookie_mode "under_load": decremented exactly once, when
        # the session is established (CONFIG and ticket sent) or on any earlier exit.
        in_handshake = True

        def end_handshake() -> None:
            nonlocal in_handshake
            if in_handshake:
                in_handshake = False
                with self._pending_lock:
                    self._pending_handshakes = max(0, self._pending_handshakes - 1)

        with self._pending_lock:
            self._pending_handshakes += 1
        try:
            set_nodelay(connection)
            connection.settimeout(self.cfg.handshake_timeout)
            first_msg = recv_message(connection)
            # Detect 1-RTT resumption attempt.
            # Resumption skips cookie_gate: invalid tickets fail fast (GCM reject),
            # and the per-source rate limiter + global slot bound still apply.
            # ponytail: single-use ticket set or resumption cookie gate if replay
            # of captured valid tickets becomes a DoS vector under M7 testing
            assigned_ip_hint = None
            if (self._ticket_key and len(first_msg) >= HEADER_SIZE
                    and struct.unpack(HEADER_FORMAT, first_msg[:HEADER_SIZE])[2] == MessageType.RESUMPTION_HELLO):
                resume = ResumptionServerHandshake(
                    self._ticket_key,
                    PROTOCOL_VERSION_V3 if self.cfg.protocol_version == 3 else PROTOCOL_VERSION,
                    data_plane=self.cfg.data_plane, handshake=self.cfg.handshake)
                accept_wire, session = resume.process_hello(first_msg)
                # Tickets outlive authorization; re-check so a revoked or signed-out
                # client cannot resume before the revocation loop rotates the ticket key.
                # The crypto is done, but nothing is sent, leased or registered before this check.
                if not self.auth.is_client_authorized(session.client_id):
                    session.secure_wipe()
                    raise HandshakeError("unauthorized: client authorization revoked")
                send_message(connection, accept_wire)
                assigned_ip_hint = resume.assigned_ip or None
            else:
                client_hello_wire = self._cookie_gate(connection, address, first_msg)
                if self.cfg.protocol_version == 3:
                    handshake = KEMTLSServerV3(self.identity_secret, self.identity_public, self.auth.find_by_fingerprint,
                                               data_plane=self.cfg.data_plane, handshake=self.cfg.handshake)
                else:
                    handshake = KEMTLSServer(self.identity_secret, self.identity_public, self.auth.find,
                                             data_plane=self.cfg.data_plane, handshake=self.cfg.handshake)
                send_message(connection, handshake.process_client_hello(client_hello_wire))
                finished, session = handshake.process_client_key_exchange(recv_message(connection))
                send_message(connection, finished)
                assigned_ip_hint = handshake.authz.get("assigned_ip")
            vpn_ip = self.pool.allocate(session.client_id, assigned_ip_hint)
            item = ServerSession(session, vpn_ip, connection, session.client_id)
            self.sessions.add(item)
            resumption_enabled = self._ticket_key is not None
            config = json.dumps({"session_id": session.session_id.hex(), "client_vpn_ip": vpn_ip,
                "server_vpn_ip": self.cfg.server_vpn_ip, "prefix": ipaddress.ip_network(self.cfg.vpn_subnet).prefixlen,
                "udp_port": self.cfg.udp_port, "mtu": self.cfg.mtu, "routes": ["0.0.0.0/1", "128.0.0.0/1"],
                "dns": self.cfg.dns_servers, "epoch": session.epoch, "rekey_interval": self.cfg.rekey_interval,
                "rehandshake_interval": self.cfg.rehandshake_interval,
                "resumption": resumption_enabled}).encode()
            send_message(connection, session.encrypt_control(config, FrameType.CONFIG))
            # Issue resumption ticket for next connect
            if resumption_enabled:
                ticket = session.issue_ticket(self._ticket_key, self.cfg.resumption_ticket_lifetime, vpn_ip)
                send_message(connection, session.encrypt_control(ticket, FrameType.RESUMPTION_TICKET))
            end_handshake()
            # From here the selector thread owns the socket and the session; this thread exits.
            connection.setblocking(False)
            handed_off = self._hand_off(item, connection, address)
        except Exception as exc:
            self._log_control_failure(exc, address[0])
        finally:
            end_handshake()
            if not handed_off:
                self._end_session(item, connection)

    @staticmethod
    def _log_control_failure(exc: Exception, source: str) -> None:
        if isinstance(exc, socket.timeout):
            logger.info("client timeout source=%s", source)
        elif isinstance(exc, HandshakeError):
            level = logging.INFO if "unauthorized" in str(exc) else logging.WARNING
            logger.log(level, "protocol/authentication rejection source=%s reason=%s", source, exc)
        elif isinstance(exc, PQCUnavailableError):
            logger.error("PQC failure source=%s reason=%s", source, exc)
        elif isinstance(exc, OSError):
            logger.info("client network closure source=%s reason=%s", source, exc)
        else:
            logger.error("unexpected client handler failure source=%s", source, exc_info=exc)

    def _end_session(self, item: ServerSession | None, connection: socket.socket) -> None:
        try:
            if item:
                with self.sessions.lock:
                    self.sessions.remove(item)
                    item.endpoint = None
                    self.pool.release(item.client_id)
                    item.crypto.secure_wipe()
        finally:
            connection.close()
            self.slots.release()

    def _hand_off(self, item: ServerSession, connection: socket.socket, address: tuple[str, int]) -> bool:
        with self._handoff_lock:
            if not self._selector_open:
                return False
            self._handoffs.put(_ControlConn(item, connection, address[0]))
            self._poke()
        return True

    def _poke(self) -> None:
        """Wake the selector; caller holds _handoff_lock and has checked _selector_open."""
        try:
            os.write(self._wake_w, b"\0")
        except BlockingIOError:
            pass

    def _serve_control(self) -> None:
        selector = selectors.DefaultSelector()
        selector.register(self._wake_r, selectors.EVENT_READ)
        last_sweep = 0.0
        try:
            while not self.stop_event.is_set():
                for key, _ in selector.select(1):
                    if key.data is None:
                        try:
                            while os.read(self._wake_r, 4096):
                                pass
                        except BlockingIOError:
                            pass
                    else:
                        self._control_readable(selector, key.data)
                self._adopt_handoffs(selector)
                now = time.monotonic()
                if now - last_sweep >= 1:
                    last_sweep = now
                    self._sweep_sessions(selector, now)
        except Exception:
            logger.exception("control selector failed; stopping server")
            self.stop()
        finally:
            with self._handoff_lock:
                self._selector_open = False
                os.close(self._wake_r)
                os.close(self._wake_w)
            for key in list(selector.get_map().values()):
                if key.data is not None:
                    self._drop_control(selector, key.data)
            self._adopt_handoffs(None)
            selector.close()

    def _adopt_handoffs(self, selector: selectors.BaseSelector | None) -> None:
        while True:
            try:
                conn = self._handoffs.get_nowait()
            except queue.Empty:
                return
            # Closed while queued (revocation) or shutting down: end it here, never register a dead fd.
            if selector is None or conn.sock.fileno() == -1:
                self._drop_control(None, conn)
                continue
            try:
                stale = selector.get_map().get(conn.sock.fileno())
                if stale is not None:  # its socket was closed elsewhere and the fd number reused
                    self._drop_control(selector, stale.data)
                selector.register(conn.sock, selectors.EVENT_READ, conn)
                self._selector_socks.add(conn.sock)
            except (ValueError, KeyError, OSError):  # closed between the check and register
                self._drop_control(selector, conn)

    def _drop_control(self, selector: selectors.BaseSelector | None, conn: _ControlConn) -> None:
        """End one session; never raises, so one session's failure cannot take the selector down."""
        if selector is not None:
            try:
                selector.unregister(conn.sock)
            except (KeyError, ValueError):
                pass
        self._selector_socks.discard(conn.sock)
        try:
            self._end_session(conn.item, conn.sock)
        except Exception:
            logger.exception("control session cleanup failed source=%s", conn.source)

    def _control_readable(self, selector: selectors.BaseSelector, conn: _ControlConn) -> None:
        """Read what is available without blocking, so one slow client cannot stall the others."""
        try:
            try:
                data = conn.sock.recv(65536)
            except BlockingIOError:
                return
            if not data:
                raise HandshakeError("control connection closed")
            conn.rx += data
            while len(conn.rx) >= 4:
                size = struct.unpack("!I", conn.rx[:4])[0]
                if size <= 0 or size > MAX_CONTROL_MESSAGE:
                    raise HandshakeError("invalid control message length")
                if len(conn.rx) < 4 + size:
                    break
                frame = bytes(conn.rx[4:4 + size])
                del conn.rx[:4 + size]
                if not self._dispatch_control(conn.item, frame):
                    self._drop_control(selector, conn)
                    return
            conn.stalled_since = time.monotonic()
        except Exception as exc:  # includes a failed non-blocking send: the stream is unusable
            self._log_control_failure(exc, conn.source)
            self._drop_control(selector, conn)

    def _dispatch_control(self, item: ServerSession, frame: bytes) -> bool:
        """Today's control dispatch for one frame; False when the client closed the session."""
        frame_type, payload = item.crypto.decrypt_control(frame)
        if frame_type == FrameType.CLOSE:
            return False
        if frame_type == FrameType.REKEY_REQUEST:
            with self.sessions.lock:
                self._rekey_server(item, payload)
                item.touch()
        elif frame_type == FrameType.REHANDSHAKE_REQUEST:
            with self.sessions.lock:
                self._rehandshake_server(item, payload)
                item.touch()
        elif frame_type not in {FrameType.ERROR}:
            raise HandshakeError("unexpected control message")
        else:
            with self.sessions.lock:
                item.touch()
        return True

    def _sweep_sessions(self, selector: selectors.BaseSelector, now: float) -> None:
        for key in list(selector.get_map().values()):
            conn = key.data
            if conn is None:
                continue
            if conn.sock.fileno() == -1:
                self._drop_control(selector, conn)
                continue
            item = conn.item
            try:
                with self.sessions.lock:
                    reason = ("idle timeout" if now - self._last_activity(item) > self.cfg.idle_timeout else
                              "session timeout" if now - item.created > self.cfg.session_timeout else None)
                    if reason:
                        self.sessions.remove(item)
                        logger.info("session expired reason=%s client_id=%s vpn_ip=%s",
                                    reason, item.client_id, item.vpn_ip)
            except Exception:
                logger.exception("session sweep failed source=%s", conn.source)
                self._drop_control(selector, conn)
                continue
            if reason:
                self._drop_control(selector, conn)
            elif conn.rx and now - conn.stalled_since > self.cfg.handshake_timeout:
                # A partial frame with no progress: the socket timeout the per-session thread used to give.
                logger.info("client timeout source=%s", conn.source)
                self._drop_control(selector, conn)

    def _cookie_gate(self, connection: socket.socket, address: tuple[str, int], first_msg: bytes) -> bytes:
        """Return the ClientHello wire bytes, issuing a cookie challenge if needed."""
        if not self._needs_cookie():
            return first_msg
        if len(first_msg) < HEADER_SIZE:
            raise HandshakeError("message too short for cookie gate")
        _, _, msg_type, _ = struct.unpack(HEADER_FORMAT, first_msg[:HEADER_SIZE])
        if msg_type == MessageType.COOKIE_RESPONSE:
            cookie, client_hello = unpack_cookie_response(first_msg)
            if not self._cookie.verify(cookie, address[0], address[1]):
                raise HandshakeError("invalid or expired cookie")
            return client_hello
        version = PROTOCOL_VERSION_V3 if self.cfg.protocol_version == 3 else PROTOCOL_VERSION
        cookie = self._cookie.generate(address[0], address[1])
        send_message(connection, pack_cookie_challenge(cookie, version))
        response = recv_message(connection)
        if len(response) < HEADER_SIZE:
            raise HandshakeError("cookie response too short")
        _, _, resp_type, _ = struct.unpack(HEADER_FORMAT, response[:HEADER_SIZE])
        if resp_type != MessageType.COOKIE_RESPONSE:
            raise HandshakeError("expected COOKIE_RESPONSE after challenge")
        resp_cookie, client_hello = unpack_cookie_response(response)
        if not self._cookie.verify(resp_cookie, address[0], address[1]):
            raise HandshakeError("invalid or expired cookie")
        return client_hello

    def _rekey_server(self, item: ServerSession, payload: bytes) -> None:
        if not self.auth.is_client_authorized(item.client_id):
            raise HandshakeError("client authorization revoked")
        # Derives, confirms under the old key, seals under the old keys, then activates: all inside the session.
        send_message(item.control, item.crypto.respond_rekey(payload))
        logger.info("rekey complete epoch=%d client_id=%s", item.crypto.epoch, item.client_id)

    def _rehandshake_server(self, item: ServerSession, payload: bytes) -> None:
        if not self.auth.is_client_authorized(item.client_id):
            raise HandshakeError("client authorization revoked")
        send_message(item.control, item.crypto.respond_rehandshake(payload))
        logger.info("rehandshake complete epoch=%d client_id=%s", item.crypto.epoch, item.client_id)

    def _enabled_client_ids(self) -> set[str]:
        try:
            db = self.auth._load(required=True)
            return {item['client_id'] for item in db['clients'] if item['enabled']}
        except Exception:
            return self._last_auth_snapshot or set()

    def _check_revocations(self) -> None:
        enabled = self._enabled_client_ids()
        old = self._last_auth_snapshot
        self._last_auth_snapshot = enabled
        if old is not None and old - enabled and self._ticket_key is not None:
            self._ticket_key = self._new_ticket_key()
            logger.info("resumption ticket key rotated due to client revocation")
        for item in list(self.sessions._snap_id.values()):
            if item.client_id not in enabled:
                logger.info("terminating revoked client session client_id=%s", item.client_id)
                try:
                    # The selector sees the shutdown as EOF and ends the session itself; closing a socket
                    # it holds would silently drop it from epoll and free the fd number for reuse.
                    item.control.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                if item.control not in self._selector_socks:
                    try:
                        item.control.close()
                    except Exception:
                        pass

    def _revocation_loop(self) -> None:
        while not self.stop_event.wait(30):
            try:
                self._check_revocations()
            except Exception:
                logger.exception("revocation check failed")

    def _last_activity(self, item: ServerSession) -> float:
        """Control activity is touched here; data-path activity lives in the Rust data plane."""
        seen = self._dp.last_seen(item.crypto.session_id) if self._dp else None
        return max(item.last_seen, seen or 0.0)

    def _watch_data_plane(self) -> None:
        logged, logged_at = 0, float("-inf")
        per_session: dict[bytes, int] = {}
        while not self.stop_event.wait(0.2):
            error = self._dp.error()
            if error:
                logger.error("rust data plane failed; stopping server: %s", error)
                self.stop()
                return
            rejects = self._dp.stats()["inner_rejects"]
            if rejects > logged and time.monotonic() - logged_at >= INNER_REJECT_LOG_INTERVAL:
                offenders, per_session = self._inner_reject_offenders(per_session)
                logger.warning("rejected %d spoofed/malformed inner packets; by client_id: %s",
                               rejects - logged, offenders or "sessions since removed")
                logged, logged_at = rejects, time.monotonic()

    def _inner_reject_offenders(self, before: dict[bytes, int], limit: int = 10) -> tuple[str, dict[bytes, int]]:
        """'client=N, ...' for sessions whose Rust reject count rose, and the new per-session baseline."""
        rising: list[str] = []
        now: dict[bytes, int] = {}
        for item in list(self.sessions._snap_id.values()):
            session_id = item.crypto.session_id
            now[session_id] = self._dp.inner_rejects(session_id) or 0
            if now[session_id] > before.get(session_id, 0):
                rising.append(f"{item.client_id}={now[session_id] - before.get(session_id, 0)}")
        more = f" and {len(rising) - limit} more" if len(rising) > limit else ""
        return ", ".join(rising[:limit]) + more, now

    # ponytail: batch size for draining sockets per wakeup; tune up if
    # profiling shows select() round-trips are still the bottleneck
    _BATCH_SIZE = 64

    def _data_loop(self) -> None:
        batch = self._BATCH_SIZE
        while not self.stop_event.is_set():
            # One snapshot per pass: stop() closes and nulls these concurrently. A closed socket raises
            # OSError and a closed TUNInterface RuntimeError; both end the loop instead of crashing it.
            udp, tun = self.udp, self.tun
            if udp is None:
                break
            try:
                tun_fd = tun.fileno() if tun else None
                readable, _, _ = select.select([udp] if tun_fd is None else [udp, tun_fd], [], [], 0.2)
            except (OSError, ValueError, RuntimeError):
                break
            if udp in readable:
                for _ in range(batch):
                    try:
                        data, address = udp.recvfrom(65535)
                    except (BlockingIOError, OSError):
                        break
                    self._handle_datagram(data, address)
            if tun_fd is not None and tun_fd in readable:
                mtu = tun.mtu
                for _ in range(batch):
                    try:
                        packet = tun.read()
                    except (BlockingIOError, OSError, RuntimeError):
                        break
                    item = self.sessions.destination(packet)
                    if item and item.endpoint and len(packet) <= mtu:
                        try: udp.sendto(item.crypto.seal_data(packet), item.endpoint)
                        except (HandshakeError, OSError): continue

    def _handle_datagram(self, data: bytes, address: tuple[str, int]) -> None:
        # Lock-free session lookup (snapshot dict), then decrypt.
        # Lock only for mutations (bind, touch) — the hot DATA path avoids it.
        item = self.sessions.from_frame(data)
        if item is None or (item.endpoint is not None and item.endpoint != address):
            return
        try:
            frame_type, payload = item.crypto.open_data(data)
            if frame_type == FrameType.UDP_BIND and payload == b"bind":
                with self.sessions.lock:
                    item.endpoint = address
                    item.touch()
                self.udp.sendto(item.crypto.seal_data(b"ok", FrameType.UDP_BIND_ACK), address)
            elif item.endpoint == address and frame_type == FrameType.DATA:
                if len(payload) <= self.tun.mtu and validate_client_packet(payload, item.vpn_ip):
                    item.touch()
                    self.tun.write(payload)
                else:
                    logger.warning("rejected spoofed/malformed inner packet client_id=%s", item.client_id)
            elif item.endpoint == address and frame_type == FrameType.PING and len(payload) == 8:
                item.touch()
                self.udp.sendto(item.crypto.seal_data(payload, FrameType.PONG), address)
        except (HandshakeError, OSError):
            return

    def _close_listeners(self) -> None:
        if self._dp:
            self._dp.stop()
        for name in ("tcp", "udp"):
            obj = getattr(self, name, None)
            if obj:
                try:
                    obj.close()
                except OSError: pass
                setattr(self, name, None)
        if self.tun:
            self.tun.close()
            self.tun = None

    def stop(self) -> None:
        self.stop_event.set()
        self._close_listeners()
        if self._data_thread and self._data_thread is not threading.current_thread():
            self._data_thread.join(timeout=3)
        if self._revocation_thread and self._revocation_thread is not threading.current_thread():
            self._revocation_thread.join(timeout=3)
        with self._handoff_lock:
            if self._selector_open:
                self._poke()
        if self._selector_thread and self._selector_thread is not threading.current_thread():
            self._selector_thread.join(timeout=3)
        for thread in list(self._client_threads):
            if thread is not threading.current_thread():
                thread.join(timeout=3)


class RekeyState(enum.Enum):
    IDLE = "IDLE"
    REQUESTED = "REQUESTED"
    WAITING_CONFIRMATION = "WAITING_CONFIRMATION"
    ACTIVATING = "ACTIVATING"


class VPNClient:
    PING_INITIAL_DELAY = 2.0
    PING_INTERVAL = 5.0

    def __init__(self, config: ClientConfig) -> None:
        validate_client(config)
        self.cfg = config
        self.PING_INTERVAL = config.ping_interval
        self.PING_INITIAL_DELAY = min(2.0, config.ping_interval)
        self.last_authenticated_udp_rx = None
        self.stop_event = threading.Event()
        self.quality = NetworkQualityMonitor()
        self.pending_pings = {}
        self.control = self.session = self.tun = self.network = self.udp = None
        self._thread = None
        self._dp = None
        self._rekey_lock = threading.Lock()
        self.rekey_state = RekeyState.IDLE
        self.next_rekey = None
        self.next_rehandshake = None
        self.state = "DISCONNECTED"
        self.error = ""
        self._cleanup_lock = threading.Lock()
        self._cleanup_done = threading.Event()
        self._control_write_lock = threading.Lock()
        self._control_thread = self._scheduler_thread = None
        self._responses = queue.Queue(maxsize=1)
        self._epoch_ready = threading.Event()
        self._epoch_ready.set()
        self._resumption_ticket: bytes | None = None
        self._resumption_secret: bytes | None = None

    def _ticket_path(self) -> Path:
        """Ticket stored next to client config for persistence across restarts."""
        return Path(self.cfg.client_identity_private_key).parent / ".pqvpn_ticket.json"

    def _save_ticket(self, ticket: bytes, secret: bytes, fingerprint: str) -> None:
        import base64
        data = {"fp": fingerprint, "t": base64.b64encode(ticket).decode(),
                "s": base64.b64encode(secret).decode(), "v": self.cfg.protocol_version}
        path = self._ticket_path()
        # Same directory, so os.replace stays on one filesystem; O_EXCL|O_NOFOLLOW never follows a planted link.
        tmp = path.parent / f".pqvpn_ticket.{os.urandom(8).hex()}.tmp"
        created = False
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            created = True
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            created = False
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            logger.debug("could not persist resumption ticket")
        finally:
            if created:
                try:
                    tmp.unlink()
                except OSError:
                    pass

    def _load_ticket(self, fingerprint: str) -> tuple[bytes, bytes] | None:
        import base64
        try:
            # O_NONBLOCK: a FIFO planted at the path must not hang connect; it fails the S_ISREG check instead.
            fd = os.open(self._ticket_path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            with os.fdopen(fd, encoding="utf-8") as f:
                # Same rule as identity.read_private, plus ownership: only a ticket this user wrote is trusted.
                info = os.fstat(f.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
                    return None
                data = json.load(f)
            if data.get("fp") != fingerprint or data.get("v") != self.cfg.protocol_version:
                return None
            return base64.b64decode(data["t"]), base64.b64decode(data["s"])
        except (OSError, KeyError, ValueError):
            return None

    def connect(self) -> dict:
        if self.state in {"CONNECTING", "CONNECTED"}:
            raise RuntimeError("client already active")
        if self.stop_event.is_set() and not self._cleanup_done.wait(12):
            raise RuntimeError("previous cleanup still running")
        self._cleanup_done.clear()
        self._responses = queue.Queue(maxsize=1)
        self._control_thread = self._scheduler_thread = None
        self.pending_pings.clear()
        self.quality.reset()
        self.stop_event.clear()
        self.state, self.error = "CONNECTING", ""
        try:
            if not self.cfg.dev_emulated_tun:
                ipv6_preflight(effective_policy(self.cfg.full_tunnel, self.cfg.ipv6_policy))
            identity = Path(self.cfg.server_identity_public_key).read_bytes()
            self.server_ip = socket.gethostbyname(self.cfg.server_host)
            self.control = set_nodelay(socket.create_connection((self.server_ip, self.cfg.server_control_port), timeout=10))
            # Try 1-RTT resumption first, fall back to full handshake
            resumed = False
            version = PROTOCOL_VERSION_V3 if self.cfg.protocol_version == 3 else PROTOCOL_VERSION
            rust = self.cfg.handshake == "rust"
            if rust:
                resume = ResumptionClientHandshake.from_ticket_file(
                    self._ticket_path(), self.cfg.server_identity_fingerprint, self.cfg.protocol_version, version)
                ticket = None
            else:
                saved = self._load_ticket(self.cfg.server_identity_fingerprint)
                resume = ticket = None
                if saved is not None:
                    ticket, resume_secret = saved
                    resume = ResumptionClientHandshake(resume_secret, version, data_plane=self.cfg.data_plane)
            if resume is not None:
                try:
                    send_message(self.control, resume.initiate(ticket))
                    self.session = resume.process_accept(recv_message(self.control))
                    resumed = True
                    logger.info("session resumed via 1-RTT ticket")
                except (HandshakeError, OSError) as exc:
                    logger.info("resumption failed (%s), falling back to full handshake", exc)
                    # A rejected ticket (e.g. key rotated on revocation) must not linger if the full handshake fails too.
                    try:
                        self._ticket_path().unlink(missing_ok=True)
                    except OSError:
                        pass
                    self.control.close()
                    self.control = set_nodelay(socket.create_connection(
                        (self.server_ip, self.cfg.server_control_port), timeout=10))
            if not resumed:
                private_path = self.cfg.client_identity_private_key
                if self.cfg.protocol_version == 3:
                    client_public = Path(self.cfg.client_identity_public_key).read_bytes()
                    # In rust mode pqvpn_core reads the private key itself; Python never holds it.
                    client_secret = (_core().Identity.kem_file(private_path, client_public) if rust
                                     else load_client_kem_private(Path(private_path)))
                    handshake = KEMTLSClientV3(identity, self.cfg.server_identity_fingerprint, client_secret, client_public,
                                               data_plane=self.cfg.data_plane, handshake=self.cfg.handshake)
                else:
                    private = _core().Identity.ed25519_file(private_path) if rust else load_client_private(Path(private_path))
                    handshake = KEMTLSClient(identity, self.cfg.server_identity_fingerprint, private,
                                             data_plane=self.cfg.data_plane, handshake=self.cfg.handshake)
                client_hello_wire = handshake.initiate_handshake()
                send_message(self.control, client_hello_wire)
                server_reply = recv_message(self.control)
                if len(server_reply) >= HEADER_SIZE:
                    _, _, reply_type, _ = struct.unpack(HEADER_FORMAT, server_reply[:HEADER_SIZE])
                    if reply_type == MessageType.COOKIE_CHALLENGE:
                        cookie = unpack_cookie_challenge(server_reply)
                        version = PROTOCOL_VERSION_V3 if self.cfg.protocol_version == 3 else PROTOCOL_VERSION
                        send_message(self.control, pack_cookie_response(cookie, client_hello_wire, version))
                        server_reply = recv_message(self.control)
                send_message(self.control, handshake.process_server_hello(server_reply))
                self.session = handshake.process_server_finished(recv_message(self.control))
            _, payload = self.session.decrypt_control(recv_message(self.control), FrameType.CONFIG)
            self.tunnel = json.loads(payload)
            # Store resumption ticket if server issued one
            if self.tunnel.get("resumption"):
                try:
                    frame = recv_message(self.control)
                    kind, ticket_data = self.session.decrypt_control(frame)
                    if kind == FrameType.RESUMPTION_TICKET and rust:
                        # pqvpn_core writes the file (same format and write discipline) with the secret it holds.
                        self.session.save_ticket(self._ticket_path(), self.cfg.server_identity_fingerprint,
                                                 self.cfg.protocol_version, ticket_data)
                    elif kind == FrameType.RESUMPTION_TICKET:
                        self._save_ticket(ticket_data, bytes(self.session.secrets.rekey_secret),
                                          self.cfg.server_identity_fingerprint)
                except (HandshakeError, OSError):
                    logger.debug("resumption ticket receive failed; will use full handshake next time")
            advertised = ipaddress.IPv4Network(f"{self.tunnel['server_vpn_ip']}/{self.tunnel['prefix']}", strict=False)
            if advertised != ipaddress.IPv4Network(self.cfg.expected_vpn_subnet):
                raise HandshakeError("server VPN subnet differs from expected_vpn_subnet")
            if not 1 <= self.tunnel['udp_port'] <= 65535:
                raise HandshakeError("invalid authenticated server UDP port")
            self.control.settimeout(3)
            self.tun = open_tun(self.cfg.tun_name, self.tunnel["mtu"], self.cfg.dev_emulated_tun)
            configure_tun(self.tun, self.tunnel["client_vpn_ip"], self.tunnel["prefix"])
            dns = self.cfg.dns_servers or self.tunnel["dns"]
            self.network = ClientNetwork(self.tun, self.server_ip,
                                         self.cfg.full_tunnel, self.cfg.split_tunnel, dns, self.cfg.kill_switch,
                                         self.cfg.dns_mode, self.cfg.dns_routing_domains, self.cfg.ipv6_policy)
            self.network.apply()
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.bind(("0.0.0.0", 0))
            self.udp.settimeout(3)
            self.server_udp = (self.server_ip, self.tunnel["udp_port"])
            self.udp.sendto(self.session.seal_data(b"bind", FrameType.UDP_BIND), self.server_udp)
            data, address = self.udp.recvfrom(4096)
            if address != self.server_udp:
                raise HandshakeError("UDP bind acknowledgement from unexpected endpoint")
            _, ack = self.session.open_data(data, FrameType.UDP_BIND_ACK)
            if ack != b"ok": raise HandshakeError("malformed UDP bind acknowledgement")
            self.last_authenticated_udp_rx = time.monotonic()
            self.udp.setblocking(False)
            interval = int(self.tunnel.get("rekey_interval", 0))
            self.next_rekey = time.monotonic() + interval if interval > 0 else None
            rh_interval = int(self.tunnel.get("rehandshake_interval", 0))
            self.next_rehandshake = time.monotonic() + rh_interval if rh_interval > 0 else None
            self._thread = threading.Thread(target=self._loop, daemon=True, name="pqvpn-client-data")
            self.state = "CONNECTED"
            self.control.settimeout(3)
            self._control_thread = threading.Thread(target=self._control_loop, daemon=True, name="pqvpn-control")
            self._scheduler_thread = threading.Thread(target=self._schedule_rekey, daemon=True, name="pqvpn-rekey")
            self._thread.start()
            self._control_thread.start()
            self._scheduler_thread.start()
            return self.tunnel
        except Exception:
            self._cleanup(send_close=False)
            raise

    def _loop(self) -> None:
        try:
            if self.session.data_plane == "rust":
                self._forward_rust()
            else:
                self._forward_data()
        except Exception as exc:
            logger.error("data transport failed: %s", exc)
            self._fail("data transport failed")

    def _forward_rust(self) -> None:
        """Supervise the Rust loop: surface its errors, feed quality, enforce the dead-peer timeout."""
        dp = rust_data_plane("client", self.udp, self.tun, self.tunnel["mtu"], peer=self.server_udp,
                             ping=(self.PING_INITIAL_DELAY, self.PING_INTERVAL, self.cfg.ping_timeout))
        dp.add_session(self.session._data, self.session.session_id, self.tunnel["client_vpn_ip"])
        # Whichever runs last, this finally or _cleanup_owned, stops it; stop() is idempotent.
        self._dp = dp
        try:
            dp.start()
            while not self.stop_event.wait(0.2):
                error = dp.error()
                if error:
                    raise RuntimeError(f"rust data plane: {error}")
                sent, lost, rtts = dp.drain_probes()
                for _ in range(sent):
                    self.quality.record_probe_sent()
                for _ in range(lost):
                    self.quality.record_loss()
                for rtt in rtts:
                    self.quality.record_rtt(rtt)
                last_rx = dp.stats()["last_rx"]
                if last_rx:
                    self.last_authenticated_udp_rx = max(self.last_authenticated_udp_rx or 0.0, last_rx)
                if (self.state == "CONNECTED" and self.last_authenticated_udp_rx is not None
                        and time.monotonic() - self.last_authenticated_udp_rx > self.cfg.dead_peer_timeout):
                    self._fail("authenticated UDP dead-peer timeout")
                    return
        finally:
            dp.stop()

    def _forward_data(self) -> None:
        next_ping = time.monotonic() + self.PING_INITIAL_DELAY
        while not self.stop_event.is_set():
            now = time.monotonic()
            if (self.state == "CONNECTED" and self.last_authenticated_udp_rx is not None
                    and now - self.last_authenticated_udp_rx > self.cfg.dead_peer_timeout):
                self._fail("authenticated UDP dead-peer timeout")
                return
            try:
                readable, _, _ = select.select([self.tun.fileno(), self.udp], [], [], 0.2)
            except (OSError, ValueError):
                if self.stop_event.is_set(): return
                raise
            if self.tun.fileno() in readable:
                try:
                    packet = self.tun.read()
                except BlockingIOError:
                    packet = b""
                if packet and len(packet) <= self.tunnel["mtu"]:
                    self.udp.sendto(self.session.seal_data(packet), self.server_udp)
            if self.udp in readable:
                data, address = self.udp.recvfrom(65535)
                if address != self.server_udp:
                    continue
                try:
                    frame_type, payload = self.session.open_data(data)
                except HandshakeError:
                    continue
                if frame_type == FrameType.DATA:
                    assigned = self.tunnel["client_vpn_ip"]
                    if (len(payload) > self.tunnel['mtu'] or not validate_client_packet(payload, str(ipaddress.IPv4Address(payload[12:16])) if len(payload) >= 20 else assigned)
                            or payload[16:20] != ipaddress.IPv4Address(assigned).packed):
                        continue
                    self.last_authenticated_udp_rx = time.monotonic()
                    self.tun.write(payload)
                elif frame_type == FrameType.PONG and len(payload) == 8:
                    if payload not in self.pending_pings:
                        continue
                    sent = struct.unpack("!d", payload)[0]
                    self.pending_pings.pop(payload, None)
                    self.last_authenticated_udp_rx = time.monotonic()
                    self.quality.record_rtt((time.monotonic() - sent) * 1000)
            now = time.monotonic()
            if now >= next_ping:
                for stamp, deadline in list(self.pending_pings.items()):
                    if deadline <= now:
                        self.pending_pings.pop(stamp, None)
                        self.quality.record_loss()
                self.quality.record_probe_sent()
                stamp = struct.pack("!d", now)
                self.pending_pings[stamp] = now + self.cfg.ping_timeout
                self.udp.sendto(self.session.seal_data(stamp, FrameType.PING), self.server_udp)
                next_ping = now + self.PING_INTERVAL


    def _fail(self, reason: str) -> None:
        if not self.stop_event.is_set():
            self.state, self.error = "FAILED", reason
            self._cleanup(send_close=False)

    def _control_loop(self) -> None:
        try:
            while not self.stop_event.is_set():
                if not select.select([self.control], [], [], .5)[0]:
                    continue
                frame = recv_message(self.control)
                self._epoch_ready.wait()
                if self.stop_event.is_set():
                    return
                kind, payload = self.session.decrypt_control(frame)
                if kind not in (FrameType.REKEY_RESPONSE, FrameType.REHANDSHAKE_RESPONSE) or self.rekey_state == RekeyState.IDLE:
                    raise HandshakeError("server closed session" if kind == FrameType.CLOSE else "control session failure")
                self._epoch_ready.clear()
                self._responses.put_nowait(payload)
                self._epoch_ready.wait()
        except Exception:
            self._fail("control channel lost or rejected; server session unavailable")

    def _schedule_rekey(self) -> None:
        while not self.stop_event.wait(0.2):
            now = time.monotonic()
            self._maybe_auto_rekey(now)
            self._maybe_auto_rehandshake(now)

    def _maybe_auto_rekey(self, now: float) -> bool:
        if self.next_rekey is None or now < self.next_rekey or self._rekey_lock.locked():
            return False
        try:
            self.rekey()
        except Exception as exc:
            logger.warning("automatic rekey failed: %s", exc)
            self._fail("automatic rekey failed")
        finally:
            self.next_rekey = now + int(self.tunnel["rekey_interval"])
        return True

    def _maybe_auto_rehandshake(self, now: float) -> bool:
        if self.next_rehandshake is None or now < self.next_rehandshake or self._rekey_lock.locked():
            return False
        try:
            self.rehandshake()
        except Exception as exc:
            logger.warning("automatic rehandshake failed: %s", exc)
            self._fail("automatic rehandshake failed")
        finally:
            self.next_rehandshake = now + int(self.tunnel["rehandshake_interval"])
        return True

    def rekey(self) -> None:
        if not self._rekey_lock.acquire(blocking=False):
            raise HandshakeError("rekey already in progress")
        begun = failed = False
        try:
            if self.rekey_state != RekeyState.IDLE:
                raise HandshakeError("rekey already in progress")
            self.rekey_state = RekeyState.REQUESTED
            # The session derives and holds the next epoch; its secrets never surface here.
            request = self.session.begin_rekey()
            begun = True
            self.rekey_state = RekeyState.WAITING_CONFIRMATION
            with self._control_write_lock:
                send_message(self.control, request)
            if self._control_thread is None:  # synchronous protocol harness
                _, response = self.session.decrypt_control(recv_message(self.control), FrameType.REKEY_RESPONSE)
            else:
                response = self._responses.get(timeout=10)
                if response is None or self.stop_event.is_set():
                    raise HandshakeError("session closed during rekey")
            self.rekey_state = RekeyState.ACTIVATING
            begun = False
            self.session.finish_rekey(response)
            logger.info("rekey complete epoch=%d", self.session.epoch)
        except Exception:
            failed = True
            raise
        finally:
            if begun:
                self.session.abort_epoch_change()
            self._epoch_ready.set()
            self.rekey_state = RekeyState.IDLE
            self._rekey_lock.release()
            if failed:
                self._fail("rekey negotiation failed")

    def rehandshake(self) -> None:
        """PCS re-handshake: fresh X25519 + ML-KEM ephemeral material."""
        if not self._rekey_lock.acquire(blocking=False):
            raise HandshakeError("rekey/rehandshake already in progress")
        begun = failed = False
        try:
            if self.rekey_state != RekeyState.IDLE:
                raise HandshakeError("rekey/rehandshake already in progress")
            self.rekey_state = RekeyState.REQUESTED
            request = self.session.begin_rehandshake()
            begun = True
            self.rekey_state = RekeyState.WAITING_CONFIRMATION
            with self._control_write_lock:
                send_message(self.control, request)
            if self._control_thread is None:
                _, response = self.session.decrypt_control(
                    recv_message(self.control), FrameType.REHANDSHAKE_RESPONSE)
            else:
                response = self._responses.get(timeout=15)
                if response is None or self.stop_event.is_set():
                    raise HandshakeError("session closed during rehandshake")
            self.rekey_state = RekeyState.ACTIVATING
            begun = False
            self.session.finish_rehandshake(response)
            logger.info("rehandshake complete epoch=%d", self.session.epoch)
        except Exception:
            failed = True
            raise
        finally:
            if begun:
                self.session.abort_epoch_change()
            self._epoch_ready.set()
            self.rekey_state = RekeyState.IDLE
            self._rekey_lock.release()
            if failed:
                self._fail("rehandshake negotiation failed")

    def disconnect(self) -> None:
        self._cleanup(send_close=True)
        self._cleanup_done.wait(timeout=12)

    def _cleanup(self, send_close: bool) -> None:
        self.stop_event.set()
        self._epoch_ready.set()
        if not self._cleanup_lock.acquire(blocking=False):
            return
        try:
            self._cleanup_owned(send_close)
        finally:
            self._cleanup_done.set()
            self._cleanup_lock.release()

    def _cleanup_owned(self, send_close: bool) -> None:
        # Stop the Rust loop before anything it uses (session, sockets, TUN) is torn down.
        dp, self._dp = self._dp, None
        if dp:
            dp.stop()
        if self.state != "FAILED":
            self.state = "DISCONNECTED"
        try: self._responses.put_nowait(None)
        except queue.Full: pass
        if self.control:
            self.control.settimeout(1)
        if send_close and self.session and self.control:
            try:
                with self._control_write_lock:
                    send_message(self.control, self.session.encrypt_control(b"close", FrameType.CLOSE))
            except Exception: pass
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=3)
        self._thread = None
        if self.network:
            try: self.network.restore()
            except Exception: logger.exception("network restoration failed")
            self.network = None
        for name in ("udp", "control"):
            obj = getattr(self, name, None)
            if obj:
                try:
                    if name == "control" and hasattr(obj, "shutdown"):
                        try: obj.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                    obj.close()
                except OSError: pass
                setattr(self, name, None)
        if self.tun:
            self.tun.close()
            self.tun = None
        with self._rekey_lock:
            if self.session:
                self.session.secure_wipe()
                self.session = None
        for thread in (self._control_thread, self._scheduler_thread):
            if thread and thread is not threading.current_thread():
                thread.join(timeout=2)
