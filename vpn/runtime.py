"""Linux client/server runtime with transactional networking and strict channel separation."""
from __future__ import annotations

import enum
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import queue
import select
import shlex
import socket
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
    KEMTLSClientV3, KEMTLSServerV3, PROTOCOL_VERSION_V3, HEADER_SIZE, HEADER_FORMAT,
    MessageType, CookieProtector, pack_cookie_challenge, unpack_cookie_challenge,
    pack_cookie_response, unpack_cookie_response)
from vpn.config import ClientConfig, ServerConfig, validate_server, validate_client
from vpn.network import NetworkQualityMonitor, TUNInterface, TUNMode
from vpn.identity import AuthorizedClients, load_client_kem_private, load_client_private, validate_server_identity
from vpn.network import IPv6Guard, effective_policy, preflight as ipv6_preflight

logger = logging.getLogger("pqvpn.runtime")
MAX_CONTROL_MESSAGE = 16384


def send_message(sock: socket.socket, data: bytes) -> None:
    if not data or len(data) > MAX_CONTROL_MESSAGE:
        raise HandshakeError("invalid control message length")
    sock.sendall(struct.pack("!I", len(data)) + data)


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


class SessionManager:
    def __init__(self) -> None:
        self.by_id, self.by_ip = {}, {}
        self.lock = threading.RLock()

    def add(self, item: ServerSession) -> None:
        with self.lock:
            key = item.crypto.session_id[:8]
            if key in self.by_id or item.vpn_ip in self.by_ip:
                raise RuntimeError("duplicate session or VPN IP")
            self.by_id[key], self.by_ip[item.vpn_ip] = item, item

    def remove(self, item: ServerSession) -> None:
        with self.lock:
            self.by_id.pop(item.crypto.session_id[:8], None)
            self.by_ip.pop(item.vpn_ip, None)

    def from_frame(self, data: bytes) -> ServerSession | None:
        if len(data) < DATA_HEADER_SIZE:
            return None
        try:
            magic, version, channel, _, _, session_id, _, _ = struct.unpack(DATA_HEADER_FORMAT, data[:DATA_HEADER_SIZE])
        except struct.error:
            return None
        if magic != DATA_MAGIC or version != PROTOCOL_VERSION or channel != Channel.DATA:
            return None
        with self.lock:
            return self.by_id.get(session_id)

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
        with self.lock:
            return self.by_ip.get(destination)


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
        self.identity_secret, self.identity_public = validate_server_identity(
            Path(config.server_identity_private_key), Path(config.server_identity_public_key))
        records = self.auth._load(required=True, subnet=config.vpn_subnet, server_ip=config.server_vpn_ip)
        self.pool.reserved = {item['assigned_ip']: item['client_id'] for item in records['clients'] if item.get('assigned_ip')}
        self._data_thread = None
        self._client_threads: list[threading.Thread] = []
        self._cookie = CookieProtector() if config.cookie_mode != "off" else None
        self._pending_handshakes = 0
        self._pending_lock = threading.Lock()

    def start(self) -> None:
        try:
            self.tun = open_tun(self.cfg.tun_name, self.cfg.mtu, self.cfg.dev_emulated_tun)
            configure_tun(self.tun, self.cfg.server_vpn_ip, ipaddress.ip_network(self.cfg.vpn_subnet).prefixlen)
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.bind((self.cfg.listen_host, self.cfg.udp_port))
            self.udp.setblocking(False)
            self.tcp = socket.socket()
            self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp.bind((self.cfg.listen_host, self.cfg.control_port))
            self.tcp.listen(self.cfg.max_clients)
            self.tcp.settimeout(1)
            listener = self.tcp
            self._data_thread = threading.Thread(target=self._data_loop, daemon=True, name="pqvpn-data")
            self._data_thread.start()
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
                self._client_threads.append(thread)
                thread.start()
        finally:
            self._close_listeners()

    def _needs_cookie(self) -> bool:
        if self._cookie is None:
            return False
        if self.cfg.cookie_mode == "always":
            return True
        with self._pending_lock:
            return self._pending_handshakes >= self.cfg.cookie_threshold

    def _client(self, connection: socket.socket, address: tuple[str, int]) -> None:
        item = None
        with self._pending_lock:
            self._pending_handshakes += 1
        try:
            connection.settimeout(self.cfg.handshake_timeout)
            first_msg = recv_message(connection)
            client_hello_wire = self._cookie_gate(connection, address, first_msg)
            if self.cfg.protocol_version == 3:
                handshake = KEMTLSServerV3(self.identity_secret, self.identity_public, self.auth.find_by_fingerprint)
            else:
                handshake = KEMTLSServer(self.identity_secret, self.identity_public, self.auth.find)
            send_message(connection, handshake.process_client_hello(client_hello_wire))
            finished, session = handshake.process_client_key_exchange(recv_message(connection))
            send_message(connection, finished)
            vpn_ip = self.pool.allocate(session.client_id, handshake.authz.get("assigned_ip"))
            item = ServerSession(session, vpn_ip, connection, session.client_id)
            self.sessions.add(item)
            config = json.dumps({"session_id": session.session_id.hex(), "client_vpn_ip": vpn_ip,
                "server_vpn_ip": self.cfg.server_vpn_ip, "prefix": ipaddress.ip_network(self.cfg.vpn_subnet).prefixlen,
                "udp_port": self.cfg.udp_port, "mtu": self.cfg.mtu, "routes": ["0.0.0.0/1", "128.0.0.0/1"],
                "dns": self.cfg.dns_servers, "epoch": session.epoch, "rekey_interval": self.cfg.rekey_interval,
                "rehandshake_interval": self.cfg.rehandshake_interval}).encode()
            send_message(connection, session.encrypt_control(config, FrameType.CONFIG))
            connection.settimeout(self.cfg.handshake_timeout)
            while not self.stop_event.is_set():
                with self.sessions.lock:
                    now = time.monotonic()
                    reason = ("idle timeout" if now - item.last_seen > self.cfg.idle_timeout else
                              "session timeout" if now - item.created > self.cfg.session_timeout else None)
                    if reason:
                        self.sessions.remove(item)
                        logger.info("session expired reason=%s client_id=%s vpn_ip=%s",
                                    reason, item.client_id, item.vpn_ip)
                        break
                if not select.select([connection], [], [], 1)[0]:
                    continue
                frame = recv_message(connection)
                frame_type, payload = session.decrypt_control(frame)
                if frame_type == FrameType.CLOSE:
                    break
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
        except socket.timeout:
            logger.info("client timeout source=%s", address[0])
        except HandshakeError as exc:
            level = logging.INFO if "unauthorized" in str(exc) else logging.WARNING
            logger.log(level, "protocol/authentication rejection source=%s reason=%s", address[0], exc)
        except PQCUnavailableError as exc:
            logger.error("PQC failure source=%s reason=%s", address[0], exc)
        except OSError as exc:
            logger.info("client network closure source=%s reason=%s", address[0], exc)
        except Exception:
            logger.exception("unexpected client handler failure source=%s", address[0])
        finally:
            if item:
                with self.sessions.lock:
                    self.sessions.remove(item)
                    item.endpoint = None
                    self.pool.release(item.client_id)
                    item.crypto.secure_wipe()
            connection.close()
            self.slots.release()
            with self._pending_lock:
                self._pending_handshakes = max(0, self._pending_handshakes - 1)

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
        if len(payload) != 36:
            raise HandshakeError("invalid rekey request")
        epoch, nonce = struct.unpack("!I", payload[:4])[0], payload[4:]
        next_keys = item.crypto.derive_next_epoch(epoch, nonce)
        confirmation = hmac.new(bytes(item.crypto.secrets.control_confirm_key),
                                b"rekey response" + payload, hashlib.sha256).digest()
        send_message(item.control, item.crypto.encrypt_control(payload[:4] + confirmation, FrameType.REKEY_RESPONSE))
        item.crypto.activate_epoch(epoch, next_keys)

    def _rehandshake_server(self, item: ServerSession, payload: bytes) -> None:
        from crypto.hybrid_crypto import HybridKEM
        expected_len = 4 + 32 + 1184
        if len(payload) != expected_len:
            raise HandshakeError("invalid rehandshake request")
        epoch = struct.unpack("!I", payload[:4])[0]
        client_dh_pub = payload[4:36]
        client_kem_pub = payload[36:]
        hybrid = HybridKEM("ML-KEM-768")
        server_dh_private, server_dh_public = hybrid.ecc.generate_keypair()
        dh_ss = hybrid.ecc.derive_shared_secret(server_dh_private, client_dh_pub)
        ct, k_mlkem = hybrid.pqc.encapsulate(client_kem_pub)
        response_body = struct.pack("!I", epoch) + server_dh_public + ct
        transcript = payload + response_body
        next_keys = item.crypto.derive_rehandshake_epoch(epoch, dh_ss, k_mlkem, transcript)
        confirmation = hmac.new(bytes(next_keys.control_confirm_key),
                                b"rehandshake confirm" + transcript, hashlib.sha256).digest()
        response = response_body + confirmation
        send_message(item.control, item.crypto.encrypt_control(response, FrameType.REHANDSHAKE_RESPONSE))
        item.crypto.activate_epoch(epoch, next_keys)

    def _data_loop(self) -> None:
        while not self.stop_event.is_set():
            descriptors = [self.udp]
            if self.tun:
                descriptors.append(self.tun.fileno())
            try:
                readable, _, _ = select.select(descriptors, [], [], 0.2)
            except (OSError, ValueError):
                break
            if self.udp in readable:
                try:
                    data, address = self.udp.recvfrom(65535)
                except OSError:
                    continue
                self._handle_datagram(data, address)
            if self.tun and self.tun.fileno() in readable:
                packet = self.tun.read()
                item = self.sessions.destination(packet)
                if item and item.endpoint and len(packet) <= self.tun.mtu:
                    try: self.udp.sendto(item.crypto.encrypt_frame(packet), item.endpoint)
                    except HandshakeError: continue

    def _handle_datagram(self, data: bytes, address: tuple[str, int]) -> None:
        # Serialize authorization/activity with expiry and epoch activation. No
        # removed session or record from a superseded epoch may refresh liveness.
        with self.sessions.lock:
            item = self.sessions.from_frame(data)
            if item is None or (item.endpoint is not None and item.endpoint != address):
                return
            try:
                frame_type, payload = item.crypto.decrypt_frame(data)
                if frame_type == FrameType.UDP_BIND and payload == b"bind":
                    item.endpoint = address
                    item.touch()
                    self.udp.sendto(item.crypto.encrypt_frame(b"ok", FrameType.UDP_BIND_ACK), address)
                elif item.endpoint == address and frame_type == FrameType.DATA:
                    if len(payload) <= self.tun.mtu and validate_client_packet(payload, item.vpn_ip):
                        item.touch()
                        self.tun.write(payload)
                    else:
                        logger.warning("rejected spoofed/malformed inner packet client_id=%s", item.client_id)
                elif item.endpoint == address and frame_type == FrameType.PING and len(payload) == 8:
                    item.touch()
                    self.udp.sendto(item.crypto.encrypt_frame(payload, FrameType.PONG), address)
            except (HandshakeError, OSError):
                return

    def _close_listeners(self) -> None:
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
            self.control = socket.create_connection((self.server_ip, self.cfg.server_control_port), timeout=10)
            if self.cfg.protocol_version == 3:
                client_secret = load_client_kem_private(Path(self.cfg.client_identity_private_key))
                client_public = Path(self.cfg.client_identity_public_key).read_bytes()
                handshake = KEMTLSClientV3(identity, self.cfg.server_identity_fingerprint,
                                           client_secret, client_public)
            else:
                private = load_client_private(Path(self.cfg.client_identity_private_key))
                handshake = KEMTLSClient(identity, self.cfg.server_identity_fingerprint, private)
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
            self.udp.sendto(self.session.encrypt_frame(b"bind", FrameType.UDP_BIND), self.server_udp)
            data, address = self.udp.recvfrom(4096)
            if address != self.server_udp:
                raise HandshakeError("UDP bind acknowledgement from unexpected endpoint")
            _, ack = self.session.decrypt_frame(data, FrameType.UDP_BIND_ACK)
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
            self._forward_data()
        except Exception:
            self._fail("data transport failed")

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
                packet = self.tun.read()
                if len(packet) <= self.tunnel["mtu"]:
                    self.udp.sendto(self.session.encrypt_frame(packet), self.server_udp)
            if self.udp in readable:
                data, address = self.udp.recvfrom(65535)
                if address != self.server_udp:
                    continue
                try:
                    frame_type, payload = self.session.decrypt_frame(data)
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
                self.udp.sendto(self.session.encrypt_frame(stamp, FrameType.PING), self.server_udp)
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
        pending = None
        failed = False
        try:
            if self.rekey_state != RekeyState.IDLE:
                raise HandshakeError("rekey already in progress")
            self.rekey_state = RekeyState.REQUESTED
            epoch, nonce = self.session.epoch + 1, os.urandom(32)
            payload = struct.pack("!I", epoch) + nonce
            pending = self.session.derive_next_epoch(epoch, nonce)
            self.rekey_state = RekeyState.WAITING_CONFIRMATION
            with self._control_write_lock:
                send_message(self.control, self.session.encrypt_control(payload, FrameType.REKEY_REQUEST))
            if self._control_thread is None:  # synchronous protocol harness
                _, response = self.session.decrypt_control(recv_message(self.control), FrameType.REKEY_RESPONSE)
            else:
                response = self._responses.get(timeout=10)
                if response is None or self.stop_event.is_set():
                    raise HandshakeError("session closed during rekey")
            expected = hmac.new(bytes(self.session.secrets.control_confirm_key),
                                b"rekey response" + payload, hashlib.sha256).digest()
            if response[:4] != payload[:4] or not hmac.compare_digest(response[4:], expected):
                raise HandshakeError("invalid rekey confirmation")
            self.rekey_state = RekeyState.ACTIVATING
            self.session.activate_epoch(epoch, pending)
            pending = None
        except Exception:
            failed = True
            raise
        finally:
            if pending:
                pending.wipe()
            self._epoch_ready.set()
            self.rekey_state = RekeyState.IDLE
            self._rekey_lock.release()
            if failed:
                self._fail("rekey negotiation failed")

    def rehandshake(self) -> None:
        """PCS re-handshake: fresh X25519 + ML-KEM ephemeral material."""
        from crypto.hybrid_crypto import HybridKEM
        if not self._rekey_lock.acquire(blocking=False):
            raise HandshakeError("rekey/rehandshake already in progress")
        pending = None
        failed = False
        try:
            if self.rekey_state != RekeyState.IDLE:
                raise HandshakeError("rekey/rehandshake already in progress")
            self.rekey_state = RekeyState.REQUESTED
            epoch = self.session.epoch + 1
            hybrid = HybridKEM("ML-KEM-768")
            dh_private, dh_public = hybrid.ecc.generate_keypair()
            kem_secret, kem_public = hybrid.pqc.generate_keypair()
            payload = struct.pack("!I", epoch) + dh_public + kem_public
            self.rekey_state = RekeyState.WAITING_CONFIRMATION
            with self._control_write_lock:
                send_message(self.control, self.session.encrypt_control(
                    payload, FrameType.REHANDSHAKE_REQUEST))
            if self._control_thread is None:
                _, response = self.session.decrypt_control(
                    recv_message(self.control), FrameType.REHANDSHAKE_RESPONSE)
            else:
                response = self._responses.get(timeout=15)
                if response is None or self.stop_event.is_set():
                    raise HandshakeError("session closed during rehandshake")
            expected_len = 4 + 32 + 1088 + 32
            if len(response) != expected_len:
                raise HandshakeError("invalid rehandshake response length")
            resp_epoch = struct.unpack("!I", response[:4])[0]
            if resp_epoch != epoch:
                raise HandshakeError("rehandshake epoch mismatch")
            response_body = response[:4 + 32 + 1088]
            server_confirm = response[4 + 32 + 1088:]
            server_dh_public = response[4:36]
            ct = response[36:36 + 1088]
            dh_ss = hybrid.ecc.derive_shared_secret(dh_private, server_dh_public)
            k_mlkem = hybrid.pqc.decapsulate(kem_secret, ct)
            transcript = payload + response_body
            pending = self.session.derive_rehandshake_epoch(epoch, dh_ss, k_mlkem, transcript)
            expected_confirm = hmac.new(bytes(pending.control_confirm_key),
                                        b"rehandshake confirm" + transcript, hashlib.sha256).digest()
            if not hmac.compare_digest(server_confirm, expected_confirm):
                raise HandshakeError("rehandshake key confirmation failed")
            self.rekey_state = RekeyState.ACTIVATING
            self.session.activate_epoch(epoch, pending)
            pending = None
        except Exception:
            failed = True
            raise
        finally:
            if pending:
                pending.wipe()
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
