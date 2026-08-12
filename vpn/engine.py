"""
VPN Engine & Dynamic Network Agility — Unified Module.

Consolidates the entire VPN engine layer into a single file:
    §1  TUN Interface           — Native Linux /dev/net/tun + cross-platform socket pipe fallback
    §2  VPN Tunnel Daemon       — Async UDP forwarding with HandshakeSession AES-256-GCM
    §3  MTU Monitor             — Path MTU discovery, overhead calculation, TCP MSS clamping
    §4  Network Quality Monitor — Real-time RTT latency, jitter (RFC 3550), and packet loss
    §5  OpenVPN Manager         — Management socket interface + dynamic config generator

Architecture:
    The VPN tunnel daemon binds a HandshakeSession (from handshake/kemtls.py) to a
    TUN virtual interface and a UDP transport socket. Raw IP packets read from TUN
    are encrypted via AES-256-GCM, transmitted over UDP, and decrypted/written back
    on the remote end.

    The MTU monitor and network quality monitor run alongside the tunnel to provide
    dynamic PMTU discovery, TCP MSS clamping, and real-time RTT/jitter/loss metrics.

Security model:
    All data-plane traffic is encrypted using AES-256-GCM session keys derived
    from the hybrid KEMTLS handshake (X25519 + ML-KEM/Kyber768 via HKDF-SHA256).
    Frame format: nonce(12B) || ciphertext || GCM-tag(16B).
"""

from __future__ import annotations

import os
import sys
import time
import enum
import socket
import struct
import select
import logging
import threading
import statistics
from dataclasses import dataclass, field
from typing import Optional, Callable
from collections import deque

# Import from project modules
from handshake.kemtls import HandshakeSession, HandshakeError


# Module-level logger
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# §1  TUN Interface — Native Linux /dev/net/tun + Cross-Platform Fallback
# ═══════════════════════════════════════════════════════════════════════════════

# Linux ioctl constants for TUN device allocation
_TUNSETIFF = 0x400454CA
_IFF_TUN = 0x0001
_IFF_NO_PI = 0x1000

# Default read buffer size (aligned to Ethernet jumbo frame)
_TUN_READ_BUFFER = 65535


class TUNMode(enum.Enum):
    """TUN interface operating mode."""
    NATIVE = "native"        # Linux /dev/net/tun via ioctl
    SOCKET_PIPE = "socket_pipe"  # Cross-platform loopback socket pair fallback


@dataclass
class TUNInterface:
    """
    Virtual TUN network interface for IP packet tunneling.

    On Linux, allocates a real ``/dev/net/tun`` device (``tun0``, ``tun1``, …)
    via ``ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI)``. The ``IFF_NO_PI`` flag
    strips the 4-byte packet info header, yielding raw IP packets.

    On non-Linux platforms (Windows, macOS), falls back to a ``socket.socketpair()``
    loopback pipe that presents the same ``read()`` / ``write()`` / ``fileno()``
    API, enabling full test coverage without kernel TUN support.

    Attributes:
        name: Interface name (e.g. ``"tun0"``).
        mtu: Maximum transmission unit (default 1500).
        mode: Operating mode (:attr:`TUNMode.NATIVE` or :attr:`TUNMode.SOCKET_PIPE`).
        is_open: Whether the interface is currently active.

    Usage::

        tun = TUNInterface(name="tun0")
        tun.open()
        packet = tun.read()
        tun.write(response_packet)
        tun.close()
    """
    name: str = "tun0"
    mtu: int = 1500
    mode: TUNMode = field(default=TUNMode.NATIVE)
    is_open: bool = field(default=False, repr=False)

    # Internal file descriptors / socket references
    _fd: Optional[int] = field(default=None, repr=False)
    _sock_local: Optional[socket.socket] = field(default=None, repr=False)
    _sock_remote: Optional[socket.socket] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Auto-detect mode based on platform if set to NATIVE on non-Linux."""
        if self.mode == TUNMode.NATIVE and sys.platform != "linux":
            logger.info(
                "Platform %s does not support /dev/net/tun; "
                "falling back to SOCKET_PIPE mode.",
                sys.platform,
            )
            self.mode = TUNMode.SOCKET_PIPE

    def open(self) -> None:
        """
        Open the TUN interface.

        For :attr:`TUNMode.NATIVE`: Opens ``/dev/net/tun`` and issues an
        ``ioctl`` call to allocate the named interface with ``IFF_TUN | IFF_NO_PI``.

        For :attr:`TUNMode.SOCKET_PIPE`: Creates a ``socket.socketpair()``
        as a bidirectional loopback pipe.

        Raises:
            OSError: If the native TUN device cannot be opened or allocated.
            RuntimeError: If the interface is already open.
        """
        if self.is_open:
            raise RuntimeError(f"TUN interface '{self.name}' is already open")

        if self.mode == TUNMode.NATIVE:
            self._open_native()
        else:
            self._open_socket_pipe()

        self.is_open = True
        logger.info(
            "TUN interface '%s' opened in %s mode (MTU=%d)",
            self.name, self.mode.value, self.mtu,
        )

    def _open_native(self) -> None:
        """Open a native Linux TUN device via /dev/net/tun ioctl."""
        import fcntl  # Linux-only

        fd = os.open("/dev/net/tun", os.O_RDWR)
        try:
            # struct ifreq: 16-byte name + 2-byte flags + padding
            ifr = struct.pack("16sH", self.name.encode("utf-8"), _IFF_TUN | _IFF_NO_PI)
            fcntl.ioctl(fd, _TUNSETIFF, ifr)
        except Exception:
            os.close(fd)
            raise

        self._fd = fd

    def _open_socket_pipe(self) -> None:
        """
        Open a cross-platform socket pair as a virtual TUN pipe.

        Uses socket.socketpair() with AF_INET/SOCK_STREAM on Windows
        (where AF_UNIX is unavailable), or AF_UNIX/SOCK_DGRAM on Linux/macOS.
        """
        if hasattr(socket, "AF_UNIX"):
            self._sock_local, self._sock_remote = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_DGRAM
            )
        else:
            # Windows fallback: TCP loopback socket pair via listener
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            self._sock_local = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock_local.connect(("127.0.0.1", port))
            self._sock_remote, _ = listener.accept()
            listener.close()

        self._sock_local.setblocking(False)
        self._sock_remote.setblocking(False)

    def read(self, buffer_size: int = _TUN_READ_BUFFER) -> bytes:
        """
        Read one IP packet from the TUN interface.

        Args:
            buffer_size: Maximum bytes to read (default 65535).

        Returns:
            bytes: Raw IP packet data.

        Raises:
            RuntimeError: If the interface is not open.
            BlockingIOError: If no data is available (non-blocking mode).
        """
        if not self.is_open:
            raise RuntimeError("TUN interface is not open")

        if self.mode == TUNMode.NATIVE:
            return os.read(self._fd, buffer_size)
        else:
            return self._sock_local.recv(buffer_size)

    def write(self, packet: bytes) -> int:
        """
        Write a raw IP packet to the TUN interface.

        Args:
            packet: Raw IP packet bytes to inject into the virtual interface.

        Returns:
            int: Number of bytes written.

        Raises:
            RuntimeError: If the interface is not open.
        """
        if not self.is_open:
            raise RuntimeError("TUN interface is not open")

        if self.mode == TUNMode.NATIVE:
            return os.write(self._fd, packet)
        else:
            return self._sock_local.send(packet)

    def inject(self, packet: bytes) -> int:
        """
        Inject a packet into the remote end of the socket pipe (test helper).

        Only available in SOCKET_PIPE mode. Simulates an incoming packet
        arriving at the TUN interface from the network side.

        Args:
            packet: Raw IP packet bytes.

        Returns:
            int: Number of bytes injected.

        Raises:
            RuntimeError: If not in SOCKET_PIPE mode or interface not open.
        """
        if self.mode != TUNMode.SOCKET_PIPE:
            raise RuntimeError("inject() is only available in SOCKET_PIPE mode")
        if not self.is_open:
            raise RuntimeError("TUN interface is not open")
        return self._sock_remote.send(packet)

    def drain(self, buffer_size: int = _TUN_READ_BUFFER) -> bytes:
        """
        Read a packet from the remote end of the socket pipe (test helper).

        Only available in SOCKET_PIPE mode. Reads what was written via ``write()``.

        Args:
            buffer_size: Maximum bytes to read.

        Returns:
            bytes: Data written to the TUN by the tunnel daemon.

        Raises:
            RuntimeError: If not in SOCKET_PIPE mode or interface not open.
        """
        if self.mode != TUNMode.SOCKET_PIPE:
            raise RuntimeError("drain() is only available in SOCKET_PIPE mode")
        if not self.is_open:
            raise RuntimeError("TUN interface is not open")
        return self._sock_remote.recv(buffer_size)

    def fileno(self) -> int:
        """
        Return the file descriptor for use with ``select()`` / ``poll()``.

        Returns:
            int: File descriptor (native) or socket fileno (pipe mode).
        """
        if not self.is_open:
            raise RuntimeError("TUN interface is not open")
        if self.mode == TUNMode.NATIVE:
            return self._fd
        else:
            return self._sock_local.fileno()

    def close(self) -> None:
        """
        Close the TUN interface and release all resources.

        Safe to call multiple times (idempotent).
        """
        if not self.is_open:
            return

        if self.mode == TUNMode.NATIVE and self._fd is not None:
            os.close(self._fd)
            self._fd = None
        elif self.mode == TUNMode.SOCKET_PIPE:
            if self._sock_local is not None:
                self._sock_local.close()
                self._sock_local = None
            if self._sock_remote is not None:
                self._sock_remote.close()
                self._sock_remote = None

        self.is_open = False
        logger.info("TUN interface '%s' closed.", self.name)

    def __enter__(self) -> "TUNInterface":
        """Context manager entry — opens the interface."""
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        """Context manager exit — closes the interface."""
        self.close()

    def get_info(self) -> dict:
        """Return interface metadata as a dictionary."""
        return {
            "name": self.name,
            "mtu": self.mtu,
            "mode": self.mode.value,
            "is_open": self.is_open,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# §2  VPN Tunnel Daemon — Async UDP Forwarding with AES-256-GCM
# ═══════════════════════════════════════════════════════════════════════════════

# Frame format overhead: nonce(12B) + GCM-tag(16B) = 28 bytes
FRAME_OVERHEAD_NONCE = 12
FRAME_OVERHEAD_TAG = 16
FRAME_OVERHEAD_TOTAL = FRAME_OVERHEAD_NONCE + FRAME_OVERHEAD_TAG

# Default UDP port for VPN tunnel transport
DEFAULT_VPN_PORT = 51820


class TunnelState(enum.Enum):
    """VPN tunnel daemon lifecycle states."""
    IDLE = "idle"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


@dataclass
class TunnelStats:
    """Real-time tunnel throughput and packet statistics."""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_dropped: int = 0
    started_at: Optional[float] = None

    @property
    def uptime(self) -> float:
        """Tunnel uptime in seconds."""
        if self.started_at is None:
            return 0.0
        return time.time() - self.started_at

    def to_dict(self) -> dict:
        """Serialize stats to a dictionary."""
        return {
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_dropped": self.packets_dropped,
            "uptime_seconds": round(self.uptime, 2),
        }


class VPNTunnelDaemon:
    """
    Encrypted UDP tunnel daemon binding a TUN interface to a HandshakeSession.

    Reads raw IP packets from the TUN interface, encrypts them using the
    AES-256-GCM cipher from the :class:`HandshakeSession`, and transmits them
    over a UDP socket to the remote peer. Inbound encrypted frames are
    decrypted and written back to the TUN.

    The daemon runs on a background thread with a ``select()``-based event loop
    that monitors both the TUN file descriptor and the UDP socket for readability.

    Architecture::

        ┌──────────┐     read()     ┌────────────────────┐    sendto()    ┌──────────┐
        │   TUN    │ ──────────────►│  VPNTunnelDaemon    │──────────────► │   UDP    │
        │ Interface│                │  (AES-256-GCM)      │               │  Socket  │
        │          │ ◄──────────────│                     │◄────────────── │          │
        └──────────┘     write()    └────────────────────┘    recvfrom()  └──────────┘

    Usage::

        daemon = VPNTunnelDaemon(tun=tun, session=session, remote_addr=("10.0.0.1", 51820))
        daemon.start()
        # ... tunnel is active ...
        daemon.stop()

    Attributes:
        tun: The TUN interface to read/write raw IP packets.
        session: The established HandshakeSession with AES-256-GCM cipher.
        remote_addr: Remote peer (host, port) tuple for UDP transport.
        bind_addr: Local bind address for the UDP socket.
        stats: Real-time packet/byte counters.
        state: Current daemon lifecycle state.
    """

    def __init__(
        self,
        tun: TUNInterface,
        session: HandshakeSession,
        remote_addr: tuple[str, int],
        bind_addr: tuple[str, int] = ("0.0.0.0", DEFAULT_VPN_PORT),
    ) -> None:
        self.tun = tun
        self.session = session
        self.remote_addr = remote_addr
        self.bind_addr = bind_addr
        self.stats = TunnelStats()
        self.state = TunnelState.IDLE

        self._udp_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """
        Start the tunnel daemon on a background thread.

        Creates a UDP socket, binds to the local address, and launches the
        event loop thread.

        Raises:
            RuntimeError: If the daemon is already running or TUN is not open.
        """
        if self.state == TunnelState.RUNNING:
            raise RuntimeError("Tunnel daemon is already running")
        if not self.tun.is_open:
            raise RuntimeError("TUN interface must be open before starting daemon")

        # Create and bind UDP socket
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_socket.bind(self.bind_addr)
        self._udp_socket.setblocking(False)

        self._stop_event.clear()
        self.stats = TunnelStats(started_at=time.time())
        self.state = TunnelState.RUNNING

        self._thread = threading.Thread(
            target=self._event_loop,
            name="vpn-tunnel-daemon",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Tunnel daemon started: %s:%d → %s:%d",
            self.bind_addr[0], self.bind_addr[1],
            self.remote_addr[0], self.remote_addr[1],
        )

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop the tunnel daemon gracefully.

        Signals the event loop to stop, waits for the thread to join,
        and closes the UDP socket.

        Args:
            timeout: Maximum seconds to wait for the thread to join.
        """
        if self.state != TunnelState.RUNNING:
            return

        self.state = TunnelState.STOPPING
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

        if self._udp_socket is not None:
            self._udp_socket.close()
            self._udp_socket = None

        self.state = TunnelState.STOPPED
        logger.info("Tunnel daemon stopped. Stats: %s", self.stats.to_dict())

    def _event_loop(self) -> None:
        """
        Main select()-based event loop processing TUN and UDP readability.

        Runs until ``_stop_event`` is set. On each iteration:
        1. If TUN is readable → encrypt IP packet → send over UDP.
        2. If UDP is readable → decrypt frame → write to TUN.
        """
        tun_fd = self.tun.fileno()
        udp_fd = self._udp_socket.fileno()

        while not self._stop_event.is_set():
            try:
                readable, _, _ = select.select([tun_fd, udp_fd], [], [], 0.1)
            except (OSError, ValueError):
                # Socket closed during shutdown
                break

            for fd in readable:
                if fd == tun_fd:
                    self._handle_tun_read()
                elif fd == udp_fd:
                    self._handle_udp_read()

    def _handle_tun_read(self) -> None:
        """Read an IP packet from TUN, encrypt, and send over UDP."""
        try:
            packet = self.tun.read()
            if not packet:
                return

            # Encrypt using HandshakeSession AES-256-GCM
            encrypted_frame = self.session.encrypt_frame(packet)

            # Send encrypted frame to remote peer
            self._udp_socket.sendto(encrypted_frame, self.remote_addr)

            self.stats.packets_sent += 1
            self.stats.bytes_sent += len(packet)

        except BlockingIOError:
            pass  # No data available (non-blocking)
        except Exception as e:
            logger.warning("TUN read/encrypt error: %s", e)
            self.stats.packets_dropped += 1

    def _handle_udp_read(self) -> None:
        """Read an encrypted frame from UDP, decrypt, and write to TUN."""
        try:
            data, addr = self._udp_socket.recvfrom(_TUN_READ_BUFFER)
            if not data:
                return

            # Decrypt using HandshakeSession AES-256-GCM
            plaintext = self.session.decrypt_frame(data)

            # Write decrypted IP packet to TUN
            self.tun.write(plaintext)

            self.stats.packets_received += 1
            self.stats.bytes_received += len(plaintext)

        except BlockingIOError:
            pass  # No data available (non-blocking)
        except HandshakeError as e:
            logger.warning("Frame decryption failed (auth error): %s", e)
            self.stats.packets_dropped += 1
        except Exception as e:
            logger.warning("UDP read/decrypt error: %s", e)
            self.stats.packets_dropped += 1

    def process_outbound(self, packet: bytes) -> bytes:
        """
        Encrypt a single outbound IP packet (synchronous / test helper).

        Args:
            packet: Raw IP packet bytes.

        Returns:
            bytes: AES-256-GCM encrypted frame (nonce + ciphertext + tag).
        """
        return self.session.encrypt_frame(packet)

    def process_inbound(self, frame: bytes) -> bytes:
        """
        Decrypt a single inbound encrypted frame (synchronous / test helper).

        Args:
            frame: AES-256-GCM encrypted frame (nonce + ciphertext + tag).

        Returns:
            bytes: Decrypted raw IP packet.

        Raises:
            HandshakeError: If decryption or authentication fails.
        """
        return self.session.decrypt_frame(frame)

    def get_info(self) -> dict:
        """Return tunnel daemon metadata."""
        return {
            "state": self.state.value,
            "remote_addr": f"{self.remote_addr[0]}:{self.remote_addr[1]}",
            "bind_addr": f"{self.bind_addr[0]}:{self.bind_addr[1]}",
            "stats": self.stats.to_dict(),
            "tun": self.tun.get_info(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# §3  MTU Monitor — Path MTU Discovery, Overhead Calculation, TCP MSS Clamping
# ═══════════════════════════════════════════════════════════════════════════════

# Standard MTU constants
DEFAULT_MTU = 1500                      # Ethernet default
MIN_MTU = 576                           # IPv4 minimum MTU (RFC 791)
IPV4_HEADER_SIZE = 20                   # Standard IPv4 header
IPV6_HEADER_SIZE = 40                   # Standard IPv6 header
UDP_HEADER_SIZE = 8                     # UDP header
TCP_HEADER_SIZE = 20                    # Standard TCP header (no options)

# AES-256-GCM frame overhead: nonce(12B) + tag(16B) = 28B
# Plus 2-byte length prefix for framing = 30B total VPN overhead
VPN_FRAME_OVERHEAD = FRAME_OVERHEAD_TOTAL  # 28 bytes crypto
VPN_LENGTH_PREFIX = 2                      # Length-prefix framing
VPN_TOTAL_OVERHEAD = VPN_FRAME_OVERHEAD + VPN_LENGTH_PREFIX  # 30 bytes


class MTUMonitor:
    """
    Dynamic Path MTU (PMTU) discovery and TCP MSS clamping calculator.

    Tracks the effective tunnel MTU after accounting for VPN encapsulation
    overhead (UDP header + AES-256-GCM nonce/tag + length prefix). Provides
    methods to:

    - Calculate the maximum plaintext payload that fits in a single UDP
      datagram after encryption overhead.
    - Compute the TCP Maximum Segment Size (MSS) for MSS clamping, which
      prevents fragmentation on the inner TCP connection.
    - Probe remote hosts with variable-size UDP payloads to discover the
      path MTU dynamically (ICMP-less binary search method).

    Overhead breakdown (IPv4 + UDP + VPN)::

        IPv4 header:     20 bytes
        UDP header:       8 bytes
        VPN nonce:       12 bytes
        VPN GCM tag:     16 bytes
        Length prefix:    2 bytes
        ──────────────────────────
        Total overhead:  58 bytes

        ⇒ Max plaintext payload = MTU - 58 bytes
        ⇒ TCP MSS = MTU - 58 - 20 (TCP header) = MTU - 78 bytes

    Attributes:
        path_mtu: Current discovered path MTU.
        mtu_history: Timestamped log of MTU changes.

    Usage::

        monitor = MTUMonitor(path_mtu=1500)
        max_payload = monitor.max_payload_size()     # 1442
        mss = monitor.tcp_mss_clamp()                # 1422
        monitor.update_mtu(1400)                     # PMTU change
    """

    def __init__(self, path_mtu: int = DEFAULT_MTU) -> None:
        self._path_mtu = path_mtu
        self._mtu_history: list[tuple[float, int]] = [(time.time(), path_mtu)]

    @property
    def path_mtu(self) -> int:
        """Current path MTU value."""
        return self._path_mtu

    def update_mtu(self, new_mtu: int) -> None:
        """
        Update the path MTU (e.g. after ICMP Fragmentation Needed).

        Args:
            new_mtu: New path MTU value.

        Raises:
            ValueError: If new_mtu is below the IPv4 minimum (576).
        """
        if new_mtu < MIN_MTU:
            raise ValueError(
                f"MTU {new_mtu} is below IPv4 minimum ({MIN_MTU})"
            )
        self._path_mtu = new_mtu
        self._mtu_history.append((time.time(), new_mtu))
        logger.info("Path MTU updated to %d bytes", new_mtu)

    def total_overhead(self, ipv6: bool = False) -> int:
        """
        Calculate total VPN encapsulation overhead in bytes.

        Args:
            ipv6: If True, use IPv6 header size (40B) instead of IPv4 (20B).

        Returns:
            int: Total overhead bytes (IP + UDP + VPN framing).
        """
        ip_header = IPV6_HEADER_SIZE if ipv6 else IPV4_HEADER_SIZE
        return ip_header + UDP_HEADER_SIZE + VPN_TOTAL_OVERHEAD

    def max_payload_size(self, ipv6: bool = False) -> int:
        """
        Maximum plaintext payload that fits in one encrypted UDP datagram.

        Args:
            ipv6: If True, account for IPv6 header overhead.

        Returns:
            int: Maximum payload bytes before fragmentation.
        """
        return self._path_mtu - self.total_overhead(ipv6=ipv6)

    def tcp_mss_clamp(self, ipv6: bool = False) -> int:
        """
        Calculate the TCP Maximum Segment Size for MSS clamping.

        Subtracts the TCP header from the max payload to prevent
        fragmentation on inner TCP connections traversing the tunnel.

        Args:
            ipv6: If True, account for IPv6 overhead.

        Returns:
            int: TCP MSS value for SYN packet rewriting.
        """
        return self.max_payload_size(ipv6=ipv6) - TCP_HEADER_SIZE

    def probe_mtu(
        self,
        target_host: str,
        target_port: int = 33434,
        min_mtu: int = MIN_MTU,
        max_mtu: int = DEFAULT_MTU,
        timeout: float = 2.0,
    ) -> int:
        """
        Probe the path MTU using binary search with UDP datagrams.

        Sends UDP packets of increasing size with the Don't Fragment (DF) bit
        set. If a packet is too large, the next hop router sends an ICMP
        "Fragmentation Needed" message, causing a socket error.

        Uses binary search between ``min_mtu`` and ``max_mtu`` to converge
        on the actual path MTU efficiently.

        Args:
            target_host: Remote host IP address to probe.
            target_port: UDP port to target (default: traceroute port 33434).
            min_mtu: Lower bound for binary search.
            max_mtu: Upper bound for binary search.
            timeout: Socket timeout per probe in seconds.

        Returns:
            int: Discovered path MTU. Also updates the internal path_mtu.

        Note:
            Requires raw socket or elevated privileges on some platforms.
            Falls back to ``max_mtu`` if probing is not supported.
        """
        discovered_mtu = max_mtu

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Set Don't Fragment bit (Linux only)
            if sys.platform == "linux":
                IP_MTU_DISCOVER = 10
                IP_PMTUDISC_DO = 2
                sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)

            low, high = min_mtu, max_mtu
            while low <= high:
                mid = (low + high) // 2
                # Subtract IP + UDP headers to get payload size
                payload_size = mid - IPV4_HEADER_SIZE - UDP_HEADER_SIZE
                if payload_size <= 0:
                    low = mid + 1
                    continue

                try:
                    sock.sendto(b"\x00" * payload_size, (target_host, target_port))
                    low = mid + 1
                    discovered_mtu = mid
                except OSError:
                    high = mid - 1

            sock.close()
        except Exception as e:
            logger.warning("MTU probe failed, using default: %s", e)
            discovered_mtu = max_mtu

        self.update_mtu(discovered_mtu)
        return discovered_mtu

    @property
    def mtu_history(self) -> list[tuple[float, int]]:
        """Return timestamped MTU change history."""
        return list(self._mtu_history)

    def get_info(self) -> dict:
        """Return MTU monitor metadata as a dictionary."""
        return {
            "path_mtu": self._path_mtu,
            "max_payload_ipv4": self.max_payload_size(ipv6=False),
            "max_payload_ipv6": self.max_payload_size(ipv6=True),
            "tcp_mss_ipv4": self.tcp_mss_clamp(ipv6=False),
            "tcp_mss_ipv6": self.tcp_mss_clamp(ipv6=True),
            "total_overhead_ipv4": self.total_overhead(ipv6=False),
            "total_overhead_ipv6": self.total_overhead(ipv6=True),
            "history_count": len(self._mtu_history),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# §4  Network Quality Monitor — RTT, Jitter (RFC 3550), Packet Loss
# ═══════════════════════════════════════════════════════════════════════════════

# Default configuration
_DEFAULT_WINDOW_SIZE = 100  # Rolling window for statistics
_DEFAULT_PROBE_INTERVAL = 1.0  # Seconds between probes


@dataclass
class QualitySnapshot:
    """
    Point-in-time network quality measurement.

    Attributes:
        timestamp: Measurement time (Unix epoch).
        rtt_ms: Round-trip time in milliseconds.
        jitter_ms: Interarrival jitter per RFC 3550 in milliseconds.
        loss_rate: Packet loss rate as a fraction [0.0, 1.0].
        probes_sent: Total probes sent since monitor start.
        probes_received: Total probe responses received.
    """
    timestamp: float
    rtt_ms: float
    jitter_ms: float
    loss_rate: float
    probes_sent: int
    probes_received: int

    def to_dict(self) -> dict:
        """Serialize snapshot to a dictionary."""
        return {
            "timestamp": round(self.timestamp, 3),
            "rtt_ms": round(self.rtt_ms, 3),
            "jitter_ms": round(self.jitter_ms, 3),
            "loss_rate": round(self.loss_rate, 4),
            "probes_sent": self.probes_sent,
            "probes_received": self.probes_received,
        }


class NetworkQualityMonitor:
    """
    Real-time network quality monitor measuring RTT, jitter, and packet loss.

    Implements RFC 3550 interarrival jitter tracking via an exponential moving
    average. RTT measurements are collected from UDP echo probes or manually
    via :meth:`record_rtt()`. Packet loss is tracked over a rolling window.

    RTT Measurement:
        Uses UDP echo probes (``probe()`` method) or passive recording
        (``record_rtt()``). The monitor maintains a rolling window of the
        most recent measurements for statistical aggregation.

    Jitter (RFC 3550):
        ``J(i) = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16``

        Where ``D(i-1,i)`` is the difference in one-way transit times
        between consecutive packets. This exponential moving average
        smooths transient spikes while tracking sustained jitter trends.

    Packet Loss:
        Tracked as ``1 - (received / sent)`` over the rolling window.

    Attributes:
        window_size: Number of recent measurements to retain.
        rtt_samples: Deque of recent RTT measurements (ms).

    Usage::

        monitor = NetworkQualityMonitor()
        monitor.record_rtt(12.5)
        monitor.record_rtt(14.2)
        monitor.record_rtt(11.8)
        snapshot = monitor.snapshot()
        print(f"RTT: {snapshot.rtt_ms}ms, Jitter: {snapshot.jitter_ms}ms")
    """

    def __init__(self, window_size: int = _DEFAULT_WINDOW_SIZE) -> None:
        self._window_size = window_size
        self._rtt_samples: deque[float] = deque(maxlen=window_size)
        self._jitter: float = 0.0
        self._last_rtt: Optional[float] = None
        self._probes_sent: int = 0
        self._probes_received: int = 0
        self._probes_lost: int = 0

    @property
    def window_size(self) -> int:
        """Rolling window size for statistics."""
        return self._window_size

    @property
    def rtt_samples(self) -> list[float]:
        """List of recent RTT samples (ms) in the rolling window."""
        return list(self._rtt_samples)

    def record_rtt(self, rtt_ms: float) -> None:
        """
        Record a round-trip time measurement.

        Updates the RTT rolling window and recalculates RFC 3550 jitter.

        Args:
            rtt_ms: Round-trip time in milliseconds (must be >= 0).

        Raises:
            ValueError: If rtt_ms is negative.
        """
        if rtt_ms < 0:
            raise ValueError(f"RTT cannot be negative: {rtt_ms}")

        self._rtt_samples.append(rtt_ms)
        self._probes_received += 1

        # RFC 3550 jitter calculation
        if self._last_rtt is not None:
            transit_diff = abs(rtt_ms - self._last_rtt)
            self._jitter += (transit_diff - self._jitter) / 16.0

        self._last_rtt = rtt_ms

    def record_loss(self) -> None:
        """Record a lost probe (no response received within timeout)."""
        self._probes_lost += 1

    def record_probe_sent(self) -> None:
        """Record that a probe was sent (for loss rate calculation)."""
        self._probes_sent += 1

    def probe(
        self,
        target_host: str,
        target_port: int = 33434,
        timeout: float = 2.0,
    ) -> Optional[float]:
        """
        Send a UDP echo probe and measure round-trip time.

        Args:
            target_host: Remote host IP address.
            target_port: Target UDP port.
            timeout: Socket timeout in seconds.

        Returns:
            float: RTT in milliseconds, or None if the probe timed out.
        """
        self._probes_sent += 1

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send probe with timestamp
            probe_data = struct.pack("!d", time.time())
            send_time = time.time()
            sock.sendto(probe_data, (target_host, target_port))

            try:
                sock.recvfrom(1024)
                rtt_ms = (time.time() - send_time) * 1000.0
                self.record_rtt(rtt_ms)
                sock.close()
                return rtt_ms
            except socket.timeout:
                self.record_loss()
                sock.close()
                return None
        except Exception as e:
            logger.warning("Probe to %s failed: %s", target_host, e)
            self.record_loss()
            return None

    @property
    def avg_rtt(self) -> float:
        """Average RTT over the rolling window (ms). Returns 0.0 if no samples."""
        if not self._rtt_samples:
            return 0.0
        return statistics.mean(self._rtt_samples)

    @property
    def min_rtt(self) -> float:
        """Minimum RTT over the rolling window (ms). Returns 0.0 if no samples."""
        if not self._rtt_samples:
            return 0.0
        return min(self._rtt_samples)

    @property
    def max_rtt(self) -> float:
        """Maximum RTT over the rolling window (ms). Returns 0.0 if no samples."""
        if not self._rtt_samples:
            return 0.0
        return max(self._rtt_samples)

    @property
    def jitter(self) -> float:
        """Current RFC 3550 interarrival jitter (ms)."""
        return self._jitter

    @property
    def loss_rate(self) -> float:
        """
        Packet loss rate as a fraction [0.0, 1.0].

        Calculated as ``lost / sent``. Returns 0.0 if no probes have been sent.
        """
        if self._probes_sent == 0:
            return 0.0
        return self._probes_lost / self._probes_sent

    def snapshot(self) -> QualitySnapshot:
        """
        Capture a point-in-time quality measurement snapshot.

        Returns:
            QualitySnapshot: Current RTT, jitter, loss, and probe counts.
        """
        return QualitySnapshot(
            timestamp=time.time(),
            rtt_ms=self.avg_rtt,
            jitter_ms=self._jitter,
            loss_rate=self.loss_rate,
            probes_sent=self._probes_sent,
            probes_received=self._probes_received,
        )

    def reset(self) -> None:
        """Reset all counters and clear the rolling window."""
        self._rtt_samples.clear()
        self._jitter = 0.0
        self._last_rtt = None
        self._probes_sent = 0
        self._probes_received = 0
        self._probes_lost = 0

    def get_info(self) -> dict:
        """Return monitor metadata as a dictionary."""
        return {
            "window_size": self._window_size,
            "sample_count": len(self._rtt_samples),
            "avg_rtt_ms": round(self.avg_rtt, 3),
            "min_rtt_ms": round(self.min_rtt, 3),
            "max_rtt_ms": round(self.max_rtt, 3),
            "jitter_ms": round(self._jitter, 3),
            "loss_rate": round(self.loss_rate, 4),
            "probes_sent": self._probes_sent,
            "probes_received": self._probes_received,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# §5  OpenVPN Manager — Management Socket Interface + Config Generator
# ═══════════════════════════════════════════════════════════════════════════════

# Default OpenVPN management socket path
_DEFAULT_MGMT_HOST = "127.0.0.1"
_DEFAULT_MGMT_PORT = 7505

# Default OpenVPN configuration parameters
_DEFAULT_OPENVPN_PORT = 1194
_DEFAULT_OPENVPN_PROTO = "udp"
_DEFAULT_OPENVPN_CIPHER = "AES-256-GCM"
_DEFAULT_OPENVPN_SUBNET = "10.8.0.0"
_DEFAULT_OPENVPN_MASK = "255.255.255.0"


class OpenVPNManager:
    """
    OpenVPN management socket interface and dynamic configuration generator.

    Provides a TCP client interface to the OpenVPN management socket for
    sending runtime commands (status, kill, signal, etc.) and methods to
    generate server/client configuration files dynamically.

    Management Socket Commands:
        - ``status``: Get current connection status and byte counters.
        - ``state``: Get the daemon state (CONNECTING, CONNECTED, etc.).
        - ``signal SIGHUP``: Restart the daemon without exiting.
        - ``signal SIGTERM``: Gracefully shut down.
        - ``kill <cn>``: Disconnect a specific client by common name.
        - ``verb <n>``: Change the logging verbosity level at runtime.

    Usage::

        mgr = OpenVPNManager()
        status = mgr.send_command("status")
        server_conf = mgr.generate_server_config()
        client_conf = mgr.generate_client_config(remote="vpn.example.com")

    Attributes:
        mgmt_host: Management socket host address.
        mgmt_port: Management socket TCP port.
    """

    def __init__(
        self,
        mgmt_host: str = _DEFAULT_MGMT_HOST,
        mgmt_port: int = _DEFAULT_MGMT_PORT,
    ) -> None:
        self.mgmt_host = mgmt_host
        self.mgmt_port = mgmt_port

    def send_command(self, command: str, timeout: float = 5.0) -> str:
        """
        Send a command to the OpenVPN management socket and return the response.

        Opens a TCP connection, sends the command followed by a newline,
        and reads the response until the ``END`` marker or timeout.

        Args:
            command: Management interface command (e.g. "status", "state").
            timeout: Socket timeout in seconds.

        Returns:
            str: Response text from the management interface.

        Raises:
            ConnectionError: If the management socket is unreachable.
            TimeoutError: If the response is not received within timeout.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.mgmt_host, self.mgmt_port))

            # Send command
            sock.sendall(f"{command}\n".encode("utf-8"))

            # Read response
            response_parts = []
            while True:
                try:
                    data = sock.recv(4096).decode("utf-8", errors="replace")
                    if not data:
                        break
                    response_parts.append(data)
                    if "END" in data or "SUCCESS" in data or "ERROR" in data:
                        break
                except socket.timeout:
                    break

            sock.close()
            return "".join(response_parts)

        except ConnectionRefusedError:
            raise ConnectionError(
                f"Cannot connect to OpenVPN management at "
                f"{self.mgmt_host}:{self.mgmt_port}"
            )
        except socket.timeout:
            raise TimeoutError(
                f"Timeout waiting for response from "
                f"{self.mgmt_host}:{self.mgmt_port}"
            )

    def generate_server_config(
        self,
        port: int = _DEFAULT_OPENVPN_PORT,
        proto: str = _DEFAULT_OPENVPN_PROTO,
        cipher: str = _DEFAULT_OPENVPN_CIPHER,
        subnet: str = _DEFAULT_OPENVPN_SUBNET,
        mask: str = _DEFAULT_OPENVPN_MASK,
        mgmt_bind: str = "127.0.0.1",
        mgmt_port: int = _DEFAULT_MGMT_PORT,
    ) -> str:
        """
        Generate an OpenVPN server configuration string.

        Args:
            port: Listening port (default 1194).
            proto: Transport protocol ("udp" or "tcp").
            cipher: Encryption cipher (default "AES-256-GCM").
            subnet: VPN subnet address.
            mask: VPN subnet mask.
            mgmt_bind: Management interface bind address.
            mgmt_port: Management interface TCP port.

        Returns:
            str: Complete OpenVPN server configuration.
        """
        return (
            f"# OpenVPN Server Configuration for Hybrid PQC Integration\n"
            f"port {port}\n"
            f"proto {proto}\n"
            f"dev tun\n"
            f"topology subnet\n"
            f"server {subnet} {mask}\n"
            f"\n"
            f"# Management Socket Interface\n"
            f"management {mgmt_bind} {mgmt_port}\n"
            f"\n"
            f"cipher {cipher}\n"
            f"keepalive 10 120\n"
            f"persist-key\n"
            f"persist-tun\n"
            f"status openvpn-status.log\n"
            f"verb 3\n"
        )

    def generate_client_config(
        self,
        remote: str = "127.0.0.1",
        port: int = _DEFAULT_OPENVPN_PORT,
        proto: str = _DEFAULT_OPENVPN_PROTO,
        cipher: str = _DEFAULT_OPENVPN_CIPHER,
    ) -> str:
        """
        Generate an OpenVPN client configuration string.

        Args:
            remote: Server hostname or IP address.
            port: Server port.
            proto: Transport protocol ("udp" or "tcp").
            cipher: Encryption cipher (default "AES-256-GCM").

        Returns:
            str: Complete OpenVPN client configuration.
        """
        return (
            f"# OpenVPN Client Configuration for Hybrid PQC Integration\n"
            f"client\n"
            f"dev tun\n"
            f"proto {proto}\n"
            f"remote {remote} {port}\n"
            f"resolv-retry infinite\n"
            f"nobind\n"
            f"persist-key\n"
            f"persist-tun\n"
            f"cipher {cipher}\n"
            f"verb 3\n"
        )

    def get_info(self) -> dict:
        """Return manager metadata as a dictionary."""
        return {
            "mgmt_host": self.mgmt_host,
            "mgmt_port": self.mgmt_port,
        }


# ─────────────────────────────────────────────────────────────────────────────
