"""
Comprehensive Test Suite for VPN Engine & Dynamic Network Agility Module.

Tests cover all 5 sections of vpn/engine.py:
    §1  TUNInterface            — Interface lifecycle, read/write, context manager, platform fallback
    §2  VPNTunnelDaemon         — Packet encryption/decryption, stats, daemon lifecycle
    §3  MTUMonitor              — PMTU calculation, overhead, MSS clamping, MTU updates
    §4  NetworkQualityMonitor   — RTT recording, RFC 3550 jitter, loss tracking, snapshots
    §5  OpenVPNManager          — Config generation, command interface
    §E2E Integration            — Full pipeline: KEMTLS handshake → tunnel framing → quality monitoring
"""

import time
import struct
import socket
import pytest
from unittest.mock import patch, MagicMock

# Import from unified VPN engine module
from vpn.engine import (
    # §1 TUN Interface
    TUNInterface,
    TUNMode,
    _TUN_READ_BUFFER,

    # §2 VPN Tunnel Daemon
    VPNTunnelDaemon,
    TunnelState,
    TunnelStats,
    FRAME_OVERHEAD_TOTAL,
    FRAME_OVERHEAD_NONCE,
    FRAME_OVERHEAD_TAG,
    DEFAULT_VPN_PORT,

    # §3 MTU Monitor
    MTUMonitor,
    DEFAULT_MTU,
    MIN_MTU,
    IPV4_HEADER_SIZE,
    IPV6_HEADER_SIZE,
    UDP_HEADER_SIZE,
    TCP_HEADER_SIZE,
    VPN_TOTAL_OVERHEAD,
    VPN_FRAME_OVERHEAD,
    VPN_LENGTH_PREFIX,

    # §4 Network Quality Monitor
    NetworkQualityMonitor,
    QualitySnapshot,

    # §5 OpenVPN Manager
    OpenVPNManager,
)

# Import handshake components for integration tests
from handshake.kemtls import (
    KEMTLSClient,
    KEMTLSServer,
    HandshakeSession,
    HandshakeState,
)


# ═══════════════════════════════════════════════════════════════════════════════
# §1  Tests for TUNInterface
# ═══════════════════════════════════════════════════════════════════════════════


class TestTUNInterface:
    """Unit tests for the TUNInterface class."""

    def test_default_construction(self):
        """TUNInterface defaults to tun0, MTU 1500, and auto-detects mode."""
        tun = TUNInterface()
        assert tun.name == "tun0"
        assert tun.mtu == 1500
        assert tun.is_open is False
        # On non-Linux, should auto-fallback to SOCKET_PIPE
        import sys
        if sys.platform != "linux":
            assert tun.mode == TUNMode.SOCKET_PIPE

    def test_custom_name_and_mtu(self):
        """TUNInterface respects custom name and MTU parameters."""
        tun = TUNInterface(name="tun7", mtu=9000)
        assert tun.name == "tun7"
        assert tun.mtu == 9000

    def test_socket_pipe_open_close(self):
        """SOCKET_PIPE mode can open and close cleanly."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        assert tun.is_open is False

        tun.open()
        assert tun.is_open is True

        tun.close()
        assert tun.is_open is False

    def test_context_manager(self):
        """TUNInterface works as a context manager (with statement)."""
        with TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE) as tun:
            assert tun.is_open is True
        assert tun.is_open is False

    def test_double_open_raises(self):
        """Opening an already-open interface raises RuntimeError."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        tun.open()
        try:
            with pytest.raises(RuntimeError, match="already open"):
                tun.open()
        finally:
            tun.close()

    def test_read_write_socket_pipe(self):
        """Read and write work correctly in SOCKET_PIPE mode."""
        with TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE) as tun:
            test_packet = b"\x45\x00\x00\x28" + os.urandom(36)  # Fake IPv4 header

            # Inject from the "network side" → read from "local side"
            tun.inject(test_packet)
            received = tun.read()
            assert received == test_packet

    def test_write_and_drain_socket_pipe(self):
        """Write to TUN and drain from remote end in SOCKET_PIPE mode."""
        with TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE) as tun:
            test_packet = b"\x45\x00\x00\x14" + os.urandom(16)

            # Write from "local side" → drain from "network side"
            bytes_written = tun.write(test_packet)
            assert bytes_written == len(test_packet)

            drained = tun.drain()
            assert drained == test_packet

    def test_read_when_closed_raises(self):
        """Reading from a closed interface raises RuntimeError."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        with pytest.raises(RuntimeError, match="not open"):
            tun.read()

    def test_write_when_closed_raises(self):
        """Writing to a closed interface raises RuntimeError."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        with pytest.raises(RuntimeError, match="not open"):
            tun.write(b"\x00")

    def test_inject_native_mode_raises(self):
        """inject() raises RuntimeError when not in SOCKET_PIPE mode."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        tun.open()
        # Temporarily change mode to test the guard
        tun.mode = TUNMode.NATIVE
        try:
            with pytest.raises(RuntimeError, match="SOCKET_PIPE"):
                tun.inject(b"\x00")
        finally:
            tun.mode = TUNMode.SOCKET_PIPE
            tun.close()

    def test_drain_native_mode_raises(self):
        """drain() raises RuntimeError when not in SOCKET_PIPE mode."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        tun.open()
        tun.mode = TUNMode.NATIVE
        try:
            with pytest.raises(RuntimeError, match="SOCKET_PIPE"):
                tun.drain()
        finally:
            tun.mode = TUNMode.SOCKET_PIPE
            tun.close()

    def test_fileno_socket_pipe(self):
        """fileno() returns a valid integer in SOCKET_PIPE mode."""
        with TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE) as tun:
            fd = tun.fileno()
            assert isinstance(fd, int)
            assert fd >= 0

    def test_fileno_when_closed_raises(self):
        """fileno() raises RuntimeError when interface is closed."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        with pytest.raises(RuntimeError, match="not open"):
            tun.fileno()

    def test_close_idempotent(self):
        """Calling close() multiple times is safe (idempotent)."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        tun.open()
        tun.close()
        tun.close()  # Should not raise
        assert tun.is_open is False

    def test_get_info(self):
        """get_info() returns correct metadata dictionary."""
        tun = TUNInterface(name="tun3", mtu=1400, mode=TUNMode.SOCKET_PIPE)
        info = tun.get_info()
        assert info["name"] == "tun3"
        assert info["mtu"] == 1400
        assert info["mode"] == "socket_pipe"
        assert info["is_open"] is False

    def test_multiple_packets_roundtrip(self):
        """Multiple packets can be sent and received in sequence."""
        with TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE) as tun:
            packets = [os.urandom(64) for _ in range(10)]
            for pkt in packets:
                tun.inject(pkt)
                received = tun.read()
                assert received == pkt


# ═══════════════════════════════════════════════════════════════════════════════
# §2  Tests for VPNTunnelDaemon
# ═══════════════════════════════════════════════════════════════════════════════


def _create_test_session() -> HandshakeSession:
    """Helper: perform a full KEMTLS handshake and return client session."""
    client = KEMTLSClient()
    server = KEMTLSServer()

    ch_bytes = client.initiate_handshake()
    sh_bytes = server.process_client_hello(ch_bytes)
    cke_bytes = client.process_server_hello(sh_bytes)
    sf_bytes, server_session = server.process_client_key_exchange(cke_bytes)
    client_session = client.process_server_finished(sf_bytes)

    return client_session, server_session


class TestTunnelStats:
    """Unit tests for TunnelStats."""

    def test_default_values(self):
        """TunnelStats initializes all counters to zero."""
        stats = TunnelStats()
        assert stats.packets_sent == 0
        assert stats.packets_received == 0
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.packets_dropped == 0

    def test_uptime_zero_when_not_started(self):
        """Uptime is 0.0 when started_at is None."""
        stats = TunnelStats()
        assert stats.uptime == 0.0

    def test_uptime_when_started(self):
        """Uptime returns positive value when started_at is set."""
        stats = TunnelStats(started_at=time.time() - 10.0)
        assert stats.uptime >= 9.0  # At least 9 seconds

    def test_to_dict(self):
        """to_dict() serializes all fields correctly."""
        stats = TunnelStats(
            packets_sent=100,
            packets_received=95,
            bytes_sent=50000,
            bytes_received=47000,
            packets_dropped=5,
            started_at=time.time() - 60.0,
        )
        d = stats.to_dict()
        assert d["packets_sent"] == 100
        assert d["packets_received"] == 95
        assert d["bytes_sent"] == 50000
        assert d["bytes_received"] == 47000
        assert d["packets_dropped"] == 5
        assert d["uptime_seconds"] >= 59.0


class TestVPNTunnelDaemon:
    """Unit tests for VPNTunnelDaemon."""

    def test_construction(self):
        """Daemon initializes with correct defaults."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_session, _ = _create_test_session()

        daemon = VPNTunnelDaemon(
            tun=tun,
            session=client_session,
            remote_addr=("10.0.0.1", 51820),
        )
        assert daemon.state == TunnelState.IDLE
        assert daemon.remote_addr == ("10.0.0.1", 51820)
        assert daemon.bind_addr == ("0.0.0.0", DEFAULT_VPN_PORT)

    def test_encrypt_decrypt_roundtrip(self):
        """process_outbound + process_inbound produces identical plaintext."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_session, server_session = _create_test_session()

        client_daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )
        server_daemon = VPNTunnelDaemon(
            tun=tun, session=server_session, remote_addr=("10.0.0.2", 51820),
        )

        # Client encrypts → Server decrypts
        original = b"\x45\x00\x00\x28" + os.urandom(36)  # Fake IP packet
        encrypted = client_daemon.process_outbound(original)
        decrypted = server_daemon.process_inbound(encrypted)
        assert decrypted == original

    def test_frame_overhead(self):
        """Encrypted frame includes expected nonce + tag overhead."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_session, _ = _create_test_session()

        daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )

        plaintext = b"A" * 100
        encrypted = daemon.process_outbound(plaintext)
        # encrypted = nonce(12) + ciphertext(100) + tag(16) = 128
        assert len(encrypted) == 100 + FRAME_OVERHEAD_TOTAL

    def test_bidirectional_roundtrip(self):
        """Both client→server and server→client directions work."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_session, server_session = _create_test_session()

        client_daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )
        server_daemon = VPNTunnelDaemon(
            tun=tun, session=server_session, remote_addr=("10.0.0.2", 51820),
        )

        # Client → Server
        pkt1 = os.urandom(200)
        enc1 = client_daemon.process_outbound(pkt1)
        dec1 = server_daemon.process_inbound(enc1)
        assert dec1 == pkt1

        # Server → Client
        pkt2 = os.urandom(300)
        enc2 = server_daemon.process_outbound(pkt2)
        dec2 = client_daemon.process_inbound(enc2)
        assert dec2 == pkt2

    def test_tampered_frame_rejected(self):
        """Tampered encrypted frame raises HandshakeError on decryption."""
        from handshake.kemtls import HandshakeError as HsError

        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_session, server_session = _create_test_session()

        client_daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )
        server_daemon = VPNTunnelDaemon(
            tun=tun, session=server_session, remote_addr=("10.0.0.2", 51820),
        )

        original = os.urandom(100)
        encrypted = client_daemon.process_outbound(original)

        # Tamper with the ciphertext
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        tampered = bytes(tampered)

        with pytest.raises(HsError, match="decryption failed"):
            server_daemon.process_inbound(tampered)

    def test_start_without_tun_open_raises(self):
        """Starting daemon without opening TUN raises RuntimeError."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_session, _ = _create_test_session()

        daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )
        with pytest.raises(RuntimeError, match="TUN interface must be open"):
            daemon.start()

    def test_get_info(self):
        """get_info() returns complete daemon metadata."""
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_session, _ = _create_test_session()

        daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )
        info = daemon.get_info()
        assert info["state"] == "idle"
        assert "10.0.0.1:51820" in info["remote_addr"]
        assert "stats" in info
        assert "tun" in info

    def test_frame_overhead_constants(self):
        """Frame overhead constants are correctly defined."""
        assert FRAME_OVERHEAD_NONCE == 12
        assert FRAME_OVERHEAD_TAG == 16
        assert FRAME_OVERHEAD_TOTAL == 28


# ═══════════════════════════════════════════════════════════════════════════════
# §3  Tests for MTUMonitor
# ═══════════════════════════════════════════════════════════════════════════════


class TestMTUMonitor:
    """Unit tests for the MTUMonitor class."""

    def test_default_mtu(self):
        """Default path MTU is 1500."""
        monitor = MTUMonitor()
        assert monitor.path_mtu == DEFAULT_MTU
        assert monitor.path_mtu == 1500

    def test_custom_mtu(self):
        """Custom path MTU is respected."""
        monitor = MTUMonitor(path_mtu=1400)
        assert monitor.path_mtu == 1400

    def test_update_mtu(self):
        """update_mtu() changes the path MTU and records history."""
        monitor = MTUMonitor()
        monitor.update_mtu(1400)
        assert monitor.path_mtu == 1400
        assert len(monitor.mtu_history) == 2  # Initial + update

    def test_update_mtu_below_minimum_raises(self):
        """MTU below IPv4 minimum (576) raises ValueError."""
        monitor = MTUMonitor()
        with pytest.raises(ValueError, match="below IPv4 minimum"):
            monitor.update_mtu(500)

    def test_update_mtu_at_minimum(self):
        """MTU at exactly 576 (IPv4 minimum) is accepted."""
        monitor = MTUMonitor()
        monitor.update_mtu(576)
        assert monitor.path_mtu == 576

    def test_total_overhead_ipv4(self):
        """IPv4 total overhead = 20 (IP) + 8 (UDP) + 30 (VPN) = 58."""
        monitor = MTUMonitor()
        overhead = monitor.total_overhead(ipv6=False)
        assert overhead == IPV4_HEADER_SIZE + UDP_HEADER_SIZE + VPN_TOTAL_OVERHEAD
        assert overhead == 58

    def test_total_overhead_ipv6(self):
        """IPv6 total overhead = 40 (IP) + 8 (UDP) + 30 (VPN) = 78."""
        monitor = MTUMonitor()
        overhead = monitor.total_overhead(ipv6=True)
        assert overhead == IPV6_HEADER_SIZE + UDP_HEADER_SIZE + VPN_TOTAL_OVERHEAD
        assert overhead == 78

    def test_max_payload_ipv4(self):
        """Max payload for MTU 1500 IPv4 = 1500 - 58 = 1442."""
        monitor = MTUMonitor(path_mtu=1500)
        assert monitor.max_payload_size(ipv6=False) == 1500 - 58

    def test_max_payload_ipv6(self):
        """Max payload for MTU 1500 IPv6 = 1500 - 78 = 1422."""
        monitor = MTUMonitor(path_mtu=1500)
        assert monitor.max_payload_size(ipv6=True) == 1500 - 78

    def test_tcp_mss_clamp_ipv4(self):
        """TCP MSS for MTU 1500 IPv4 = 1442 - 20 = 1422."""
        monitor = MTUMonitor(path_mtu=1500)
        mss = monitor.tcp_mss_clamp(ipv6=False)
        assert mss == monitor.max_payload_size(ipv6=False) - TCP_HEADER_SIZE
        assert mss == 1422

    def test_tcp_mss_clamp_ipv6(self):
        """TCP MSS for MTU 1500 IPv6 = 1422 - 20 = 1402."""
        monitor = MTUMonitor(path_mtu=1500)
        mss = monitor.tcp_mss_clamp(ipv6=True)
        assert mss == monitor.max_payload_size(ipv6=True) - TCP_HEADER_SIZE
        assert mss == 1402

    def test_mtu_history_initial(self):
        """MTU history contains the initial MTU at construction."""
        monitor = MTUMonitor(path_mtu=1500)
        history = monitor.mtu_history
        assert len(history) == 1
        assert history[0][1] == 1500  # (timestamp, mtu)

    def test_mtu_history_after_updates(self):
        """MTU history tracks all changes."""
        monitor = MTUMonitor(path_mtu=1500)
        monitor.update_mtu(1400)
        monitor.update_mtu(1300)
        monitor.update_mtu(1200)
        history = monitor.mtu_history
        assert len(history) == 4
        assert [h[1] for h in history] == [1500, 1400, 1300, 1200]

    def test_get_info(self):
        """get_info() returns complete MTU monitor metadata."""
        monitor = MTUMonitor(path_mtu=1400)
        info = monitor.get_info()
        assert info["path_mtu"] == 1400
        assert "max_payload_ipv4" in info
        assert "max_payload_ipv6" in info
        assert "tcp_mss_ipv4" in info
        assert "tcp_mss_ipv6" in info
        assert "total_overhead_ipv4" in info
        assert "total_overhead_ipv6" in info
        assert info["history_count"] == 1

    def test_vpn_overhead_constants(self):
        """VPN overhead constants are correctly defined."""
        assert VPN_FRAME_OVERHEAD == 28  # nonce(12) + tag(16)
        assert VPN_LENGTH_PREFIX == 2
        assert VPN_TOTAL_OVERHEAD == 30

    def test_small_mtu_payload(self):
        """Even at minimum MTU, payload calculations work correctly."""
        monitor = MTUMonitor(path_mtu=MIN_MTU)  # 576
        payload = monitor.max_payload_size()
        assert payload == 576 - 58
        assert payload > 0


# ═══════════════════════════════════════════════════════════════════════════════
# §4  Tests for NetworkQualityMonitor
# ═══════════════════════════════════════════════════════════════════════════════


class TestNetworkQualityMonitor:
    """Unit tests for NetworkQualityMonitor."""

    def test_default_construction(self):
        """Monitor initializes with empty state."""
        monitor = NetworkQualityMonitor()
        assert monitor.window_size == 100
        assert len(monitor.rtt_samples) == 0
        assert monitor.avg_rtt == 0.0
        assert monitor.jitter == 0.0
        assert monitor.loss_rate == 0.0

    def test_custom_window_size(self):
        """Custom window size is respected."""
        monitor = NetworkQualityMonitor(window_size=50)
        assert monitor.window_size == 50

    def test_record_single_rtt(self):
        """Single RTT recording works correctly."""
        monitor = NetworkQualityMonitor()
        monitor.record_rtt(12.5)
        assert len(monitor.rtt_samples) == 1
        assert monitor.avg_rtt == 12.5
        assert monitor.min_rtt == 12.5
        assert monitor.max_rtt == 12.5

    def test_record_multiple_rtts(self):
        """Multiple RTT samples compute correct statistics."""
        monitor = NetworkQualityMonitor()
        samples = [10.0, 20.0, 30.0]
        for s in samples:
            monitor.record_rtt(s)

        assert len(monitor.rtt_samples) == 3
        assert monitor.avg_rtt == pytest.approx(20.0)
        assert monitor.min_rtt == 10.0
        assert monitor.max_rtt == 30.0

    def test_negative_rtt_raises(self):
        """Negative RTT raises ValueError."""
        monitor = NetworkQualityMonitor()
        with pytest.raises(ValueError, match="negative"):
            monitor.record_rtt(-1.0)

    def test_zero_rtt_accepted(self):
        """Zero RTT is a valid measurement (loopback)."""
        monitor = NetworkQualityMonitor()
        monitor.record_rtt(0.0)
        assert monitor.avg_rtt == 0.0

    def test_rfc3550_jitter_calculation(self):
        """RFC 3550 jitter converges for constant RTT difference."""
        monitor = NetworkQualityMonitor()

        # Alternating RTTs: 10ms, 20ms, 10ms, 20ms...
        # Transit diff is always 10ms
        # Jitter should converge towards 10ms via: J += (|D| - J) / 16
        for i in range(100):
            rtt = 10.0 if i % 2 == 0 else 20.0
            monitor.record_rtt(rtt)

        # After many iterations, jitter should approach 10.0
        assert monitor.jitter > 5.0  # Should be converging towards 10
        assert monitor.jitter <= 10.0

    def test_jitter_zero_for_constant_rtt(self):
        """Jitter stays near zero for perfectly constant RTT."""
        monitor = NetworkQualityMonitor()
        for _ in range(50):
            monitor.record_rtt(15.0)

        assert monitor.jitter == pytest.approx(0.0, abs=0.01)

    def test_loss_rate_no_probes(self):
        """Loss rate is 0.0 when no probes have been sent."""
        monitor = NetworkQualityMonitor()
        assert monitor.loss_rate == 0.0

    def test_loss_rate_tracking(self):
        """Loss rate is correctly calculated."""
        monitor = NetworkQualityMonitor()
        # Simulate 10 probes, 3 lost
        for _ in range(7):
            monitor.record_probe_sent()
            monitor.record_rtt(10.0)  # Received
        for _ in range(3):
            monitor.record_probe_sent()
            monitor.record_loss()  # Lost

        assert monitor.loss_rate == pytest.approx(0.3)

    def test_rolling_window_overflow(self):
        """Window size limits the number of stored samples."""
        monitor = NetworkQualityMonitor(window_size=10)
        for i in range(20):
            monitor.record_rtt(float(i))

        assert len(monitor.rtt_samples) == 10
        # Should only contain the last 10 samples (10-19)
        assert monitor.rtt_samples[0] == 10.0
        assert monitor.rtt_samples[-1] == 19.0

    def test_snapshot(self):
        """Snapshot captures current state correctly."""
        monitor = NetworkQualityMonitor()
        monitor.record_rtt(10.0)
        monitor.record_rtt(20.0)
        monitor._probes_sent = 5
        monitor.record_loss()

        snap = monitor.snapshot()
        assert isinstance(snap, QualitySnapshot)
        assert snap.rtt_ms == pytest.approx(15.0)
        assert snap.probes_sent == 5
        assert snap.probes_received == 2
        assert snap.loss_rate > 0

    def test_snapshot_to_dict(self):
        """QualitySnapshot.to_dict() serializes all fields."""
        snap = QualitySnapshot(
            timestamp=1000.0,
            rtt_ms=15.5,
            jitter_ms=2.3,
            loss_rate=0.05,
            probes_sent=100,
            probes_received=95,
        )
        d = snap.to_dict()
        assert d["rtt_ms"] == 15.5
        assert d["jitter_ms"] == 2.3
        assert d["loss_rate"] == 0.05
        assert d["probes_sent"] == 100
        assert d["probes_received"] == 95

    def test_reset(self):
        """reset() clears all state."""
        monitor = NetworkQualityMonitor()
        monitor.record_rtt(10.0)
        monitor.record_rtt(20.0)
        monitor._probes_sent = 10
        monitor.record_loss()

        monitor.reset()
        assert len(monitor.rtt_samples) == 0
        assert monitor.avg_rtt == 0.0
        assert monitor.jitter == 0.0
        assert monitor.loss_rate == 0.0

    def test_get_info(self):
        """get_info() returns complete metadata."""
        monitor = NetworkQualityMonitor()
        monitor.record_rtt(12.0)
        monitor.record_rtt(18.0)

        info = monitor.get_info()
        assert info["window_size"] == 100
        assert info["sample_count"] == 2
        assert info["avg_rtt_ms"] == pytest.approx(15.0)
        assert info["min_rtt_ms"] == 12.0
        assert info["max_rtt_ms"] == 18.0
        assert "jitter_ms" in info
        assert "loss_rate" in info


# ═══════════════════════════════════════════════════════════════════════════════
# §5  Tests for OpenVPNManager
# ═══════════════════════════════════════════════════════════════════════════════


class TestOpenVPNManager:
    """Unit tests for OpenVPNManager."""

    def test_default_construction(self):
        """Manager initializes with default host and port."""
        mgr = OpenVPNManager()
        assert mgr.mgmt_host == "127.0.0.1"
        assert mgr.mgmt_port == 7505

    def test_custom_construction(self):
        """Manager respects custom host and port."""
        mgr = OpenVPNManager(mgmt_host="192.168.1.1", mgmt_port=9000)
        assert mgr.mgmt_host == "192.168.1.1"
        assert mgr.mgmt_port == 9000

    def test_generate_server_config_defaults(self):
        """Server config with defaults matches expected format."""
        mgr = OpenVPNManager()
        config = mgr.generate_server_config()

        assert "port 1194" in config
        assert "proto udp" in config
        assert "dev tun" in config
        assert "topology subnet" in config
        assert "server 10.8.0.0 255.255.255.0" in config
        assert "management 127.0.0.1 7505" in config
        assert "cipher AES-256-GCM" in config
        assert "keepalive 10 120" in config
        assert "persist-key" in config
        assert "persist-tun" in config
        assert "status openvpn-status.log" in config
        assert "verb 3" in config

    def test_generate_server_config_custom(self):
        """Server config with custom parameters."""
        mgr = OpenVPNManager()
        config = mgr.generate_server_config(
            port=443,
            proto="tcp",
            cipher="AES-128-GCM",
            subnet="172.16.0.0",
            mask="255.255.0.0",
        )
        assert "port 443" in config
        assert "proto tcp" in config
        assert "cipher AES-128-GCM" in config
        assert "server 172.16.0.0 255.255.0.0" in config

    def test_generate_client_config_defaults(self):
        """Client config with defaults matches expected format."""
        mgr = OpenVPNManager()
        config = mgr.generate_client_config()

        assert "client" in config
        assert "dev tun" in config
        assert "proto udp" in config
        assert "remote 127.0.0.1 1194" in config
        assert "resolv-retry infinite" in config
        assert "nobind" in config
        assert "persist-key" in config
        assert "persist-tun" in config
        assert "cipher AES-256-GCM" in config
        assert "verb 3" in config

    def test_generate_client_config_custom(self):
        """Client config with custom remote and parameters."""
        mgr = OpenVPNManager()
        config = mgr.generate_client_config(
            remote="vpn.example.com",
            port=443,
            proto="tcp",
        )
        assert "remote vpn.example.com 443" in config
        assert "proto tcp" in config

    def test_send_command_connection_refused(self):
        """send_command raises ConnectionError when socket is unreachable."""
        mgr = OpenVPNManager(mgmt_port=59999)  # Unlikely to be listening
        with pytest.raises(ConnectionError):
            mgr.send_command("status")

    def test_get_info(self):
        """get_info() returns correct metadata."""
        mgr = OpenVPNManager()
        info = mgr.get_info()
        assert info["mgmt_host"] == "127.0.0.1"
        assert info["mgmt_port"] == 7505


# ═══════════════════════════════════════════════════════════════════════════════
# §E2E  End-to-End Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestE2EIntegration:
    """
    End-to-end integration tests combining:
    - Phase 2 KEMTLS handshake → session establishment
    - Phase 3 VPN tunnel daemon → encrypted packet framing
    - Phase 3 MTU monitor → overhead calculation
    - Phase 3 Network quality monitor → metrics
    """

    def test_full_pipeline_handshake_to_tunnel(self):
        """Complete pipeline: KEMTLS handshake → tunnel encrypt/decrypt."""
        # Phase 2: Perform handshake
        client = KEMTLSClient()
        server = KEMTLSServer()

        ch_bytes = client.initiate_handshake()
        sh_bytes = server.process_client_hello(ch_bytes)
        cke_bytes = client.process_server_hello(sh_bytes)
        sf_bytes, server_session = server.process_client_key_exchange(cke_bytes)
        client_session = client.process_server_finished(sf_bytes)

        # Phase 3: Use sessions in tunnel daemons
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        client_daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )
        server_daemon = VPNTunnelDaemon(
            tun=tun, session=server_session, remote_addr=("10.0.0.2", 51820),
        )

        # Simulate 50 bidirectional packet exchanges
        for i in range(50):
            # Client → Server
            pkt = os.urandom(64 + i)
            enc = client_daemon.process_outbound(pkt)
            dec = server_daemon.process_inbound(enc)
            assert dec == pkt

            # Server → Client
            pkt2 = os.urandom(128 + i)
            enc2 = server_daemon.process_outbound(pkt2)
            dec2 = client_daemon.process_inbound(enc2)
            assert dec2 == pkt2

    def test_mtu_aware_framing(self):
        """MTU monitor correctly predicts frame sizes after encryption."""
        monitor = MTUMonitor(path_mtu=1500)
        max_payload = monitor.max_payload_size()  # 1442

        client_session, server_session = _create_test_session()
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )

        # Encrypt a packet at exactly max payload size
        packet = os.urandom(max_payload)
        encrypted = daemon.process_outbound(packet)

        # Encrypted frame = max_payload + 28 (nonce + tag)
        # Total wire size = IP(20) + UDP(8) + encrypted + length_prefix(2)
        wire_size = IPV4_HEADER_SIZE + UDP_HEADER_SIZE + VPN_LENGTH_PREFIX + len(encrypted)
        assert wire_size <= 1500 + VPN_LENGTH_PREFIX  # Within MTU bounds

    def test_quality_monitor_with_tunnel(self):
        """Network quality monitor records metrics alongside tunnel ops."""
        client_session, server_session = _create_test_session()
        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        daemon = VPNTunnelDaemon(
            tun=tun, session=client_session, remote_addr=("10.0.0.1", 51820),
        )
        quality = NetworkQualityMonitor()

        # Simulate tunnel with quality measurements
        for i in range(20):
            start = time.time()
            pkt = os.urandom(100)
            enc = daemon.process_outbound(pkt)
            elapsed_ms = (time.time() - start) * 1000.0
            quality.record_rtt(elapsed_ms)

        # Verify quality metrics are populated
        snap = quality.snapshot()
        assert snap.probes_received == 20
        assert snap.rtt_ms >= 0
        assert snap.jitter_ms >= 0

    def test_cross_session_isolation(self):
        """Different handshake sessions cannot decrypt each other's frames."""
        from handshake.kemtls import HandshakeError as HsError

        session_a_client, session_a_server = _create_test_session()
        session_b_client, session_b_server = _create_test_session()

        tun = TUNInterface(name="test0", mode=TUNMode.SOCKET_PIPE)
        daemon_a = VPNTunnelDaemon(
            tun=tun, session=session_a_client, remote_addr=("10.0.0.1", 51820),
        )
        daemon_b = VPNTunnelDaemon(
            tun=tun, session=session_b_server, remote_addr=("10.0.0.2", 51820),
        )

        # Session A encrypts, Session B cannot decrypt
        pkt = os.urandom(64)
        enc = daemon_a.process_outbound(pkt)
        with pytest.raises(HsError):
            daemon_b.process_inbound(enc)


# ─────────────────────────────────────────────────────────────────────────────

import os  # Used in test data generation
