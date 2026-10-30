"""Tests for the PQ-VPN desktop client application layer.

Covers IPC framing, peer authorization, state transitions, missing
configuration handling, service serialization, and GUI-headless widget tests.
"""
import json
import os
import socket
import struct
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

# Select the headless backend before app.client imports PySide6.
os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ.pop("QT_QPA_PLATFORMTHEME", None)
os.environ.setdefault("QT_STYLE_OVERRIDE", "Fusion")

from app.client import (
    ClientService,
    ClientStatus,
    ConnectionState,
    IPCClient,
    MAX_IPC_MESSAGE,
    ipc_recv,
    ipc_send,
    get_peer_uid,
    sanitize_error,
    _socket_path,
)


# ─── IPC framing tests ────────────────────────────────────────────────────

class TestIPCFraming:
    def test_roundtrip(self):
        """Messages survive encode → send → recv round-trip."""
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            payload = {"command": "STATUS", "extra": "value"}
            ipc_send(a, payload)
            result = ipc_recv(b, timeout=2.0)
            assert result == payload
        finally:
            a.close()
            b.close()

    def test_oversized_message_rejected(self):
        """Messages exceeding MAX_IPC_MESSAGE are refused by ipc_send."""
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            huge = {"data": "x" * (MAX_IPC_MESSAGE + 1)}
            with pytest.raises(ValueError, match="maximum size"):
                ipc_send(a, huge)
        finally:
            a.close()
            b.close()

    def test_oversized_header_rejected(self):
        """A forged length header > MAX_IPC_MESSAGE is rejected by ipc_recv."""
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            a.sendall(struct.pack("!I", MAX_IPC_MESSAGE + 1))
            with pytest.raises(ValueError, match="out of bounds"):
                ipc_recv(b, timeout=2.0)
        finally:
            a.close()
            b.close()

    def test_zero_length_rejected(self):
        """A zero-length header is rejected."""
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            a.sendall(struct.pack("!I", 0))
            with pytest.raises(ValueError, match="out of bounds"):
                ipc_recv(b, timeout=2.0)
        finally:
            a.close()
            b.close()

    def test_connection_closed_during_recv(self):
        """ConnectionError is raised when the peer closes mid-receive."""
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            a.close()
            with pytest.raises(ConnectionError):
                ipc_recv(b, timeout=2.0)
        finally:
            b.close()


# ─── ClientStatus serialization tests ──────────────────────────────────────

class TestClientStatus:
    def test_json_roundtrip(self):
        status = ClientStatus(
            state="CONNECTED",
            client_vpn_ip="10.8.0.2",
            epoch=3,
            rtt_ms=1.5,
        )
        restored = ClientStatus.from_json(status.to_json())
        assert restored.state == "CONNECTED"
        assert restored.client_vpn_ip == "10.8.0.2"
        assert restored.epoch == 3
        assert restored.rtt_ms == 1.5

    def test_defaults_are_safe(self):
        status = ClientStatus()
        assert status.state == "DISCONNECTED"
        assert status.error == ""
        assert not status.is_quantum_safe

    def test_all_states_representable(self):
        for state in ConnectionState:
            s = ClientStatus(state=state.value)
            data = json.loads(s.to_json())
            assert data["state"] == state.value


# ─── ClientService state/authorization tests ──────────────────────────────

class TestClientService:
    def test_missing_config_produces_setup_required(self, tmp_path):
        """Service with nonexistent config file reports SETUP_REQUIRED."""
        service = ClientService(str(tmp_path / "nonexistent.toml"))
        status = service._get_status()
        assert status.state == ConnectionState.SETUP_REQUIRED.value
        assert "not found" in status.error.lower() or "Configuration" in status.error

    def test_connect_with_missing_config_returns_error(self, tmp_path):
        """Attempting to connect with invalid config returns an error dict."""
        service = ClientService(str(tmp_path / "nonexistent.toml"))
        result = service._do_connect()
        assert "error" in result

    def test_disconnect_when_not_connected(self, tmp_path):
        """Disconnect when already disconnected returns an error."""
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))
        result = service._do_disconnect()
        assert "error" in result

    def test_kill_switch_left_by_an_earlier_session_is_reported_and_released(self, tmp_path, monkeypatch):
        import app.client as client_module
        import vpn.network as network
        config = tmp_path / "client.toml"
        config.write_text("[client]\nserver_host='vpn.example'\n")
        monkeypatch.setattr(client_module, "_kill_switch_present", lambda: True)
        removed = []
        monkeypatch.setattr(network.KillSwitch, "remove", staticmethod(lambda: removed.append(True)))
        service = ClientService(str(config))
        status = service._get_status()
        assert status.state == ConnectionState.BLOCKED.value and status.kill_switch_active
        assert service._do_disconnect() == {"status": "disconnected"} and removed == [True]
        assert service._get_status().state == ConnectionState.DISCONNECTED.value

    def test_failed_connect_that_leaves_traffic_blocked_keeps_the_client(self, tmp_path, monkeypatch):
        import vpn.runtime as runtime
        config = tmp_path / "client.toml"
        config.write_text("[client]\nserver_host='vpn.example'\n")
        class Blocked:
            def __init__(self, cfg):
                self.cfg, self.state, self.error = SimpleNamespace(kill_switch=True), "CONNECTING", ""
                self.disconnected = False
            def connect(self):
                self.state, self.error = "BLOCKED", "server unreachable"
                raise OSError("server unreachable")
            def disconnect(self):
                self.disconnected, self.state = True, "DISCONNECTED"
        monkeypatch.setattr(runtime, "VPNClient", Blocked)
        service = ClientService(str(config))
        assert "error" in service._do_connect()
        vpn = service._vpn
        status = service._get_status()
        assert status.state == ConnectionState.BLOCKED.value and status.kill_switch_active
        assert service._do_disconnect() == {"status": "disconnected"} and vpn.disconnected

    def test_concurrent_operations_serialized(self, tmp_path):
        """Two concurrent connect attempts do not both succeed."""
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))

        # Simulate the lock being held
        service._lock.acquire()
        result = service._do_connect()
        assert "error" in result and "in progress" in result["error"]
        service._lock.release()

    def test_unknown_command_rejected(self, tmp_path):
        """The service rejects unknown IPC commands."""
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))
        service.ALLOWED_UIDS = {os.getuid()}

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            ipc_send(a, {"command": "HACK_THE_PLANET"})
            # Directly call handler
            service._handle_connection(b)
            result = ipc_recv(a, timeout=2.0)
            assert "error" in result
            assert "unknown" in result["error"].lower()
        finally:
            a.close()

    def test_unauthorized_peer_rejected(self, tmp_path):
        """Authorization failure is returned before a command is processed."""
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))
        service._authorize_peer = Mock(return_value=False)

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            service._handle_connection(b)
            assert ipc_recv(a, timeout=2.0) == {"error": "unauthorized"}
        finally:
            a.close()

    def test_repeated_status_and_bounded_logs(self, tmp_path):
        config = tmp_path / "client.toml"
        config.write_text("[client]\nserver_host='vpn.example'\n")
        service = ClientService(str(config))
        service.ALLOWED_UIDS = {os.getuid()}

        for _ in range(2):
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                ipc_send(a, {"command": "STATUS"})
                service._handle_connection(b)
                response = ipc_recv(a, timeout=2.0)
                assert response["status"]["server_host"] == "vpn.example"
                assert "client_identity_private_key" not in response["status"]
            finally:
                a.close()

        for index in range(350):
            service._record_event("info", f"event {index}")
        assert len(service._get_logs()) == 300
        assert service._get_logs()[-1]["message"] == "event 349"

    def test_status_protection_flags_follow_runtime_objects(self, tmp_path):
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))
        ipv6 = SimpleNamespace(table="pqvpn_client6_test")
        network = SimpleNamespace(ipv6=ipv6, dns_cleanup_registered=True)
        service._vpn = SimpleNamespace(
            state="CONNECTED",
            error="",
            session=SimpleNamespace(epoch=0),
            tun=SimpleNamespace(name="pqvpn0", mode=SimpleNamespace(name="NATIVE"), mtu=1380),
            quality=None,
            network=network,
            tunnel={"client_vpn_ip": "10.8.0.2", "server_vpn_ip": "10.8.0.1"},
            next_rekey=None,
            server_ip="192.0.2.10",
        )
        service._connected_at = time.monotonic()
        status = service._get_status()
        assert status.ipv6_guard_active is True
        assert status.dns_managed is True
        ipv6.table = None
        network.dns_cleanup_registered = False
        status = service._get_status()
        assert status.ipv6_guard_active is False
        assert status.dns_managed is False


# ─── STATUS golden contract: what the GUI's ClientStatus(**status) accepts ─────

def _hint_matches(value: object, hint: object) -> bool:
    import types
    import typing
    if hint is type(None):
        return value is None
    if typing.get_origin(hint) in (typing.Union, types.UnionType):
        return any(_hint_matches(value, arm) for arm in typing.get_args(hint))
    if typing.get_origin(hint) is list:
        (item,) = typing.get_args(hint)
        return isinstance(value, list) and all(_hint_matches(v, item) for v in value)
    if hint is dict:
        return isinstance(value, dict)
    if hint is float:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if hint is int:
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, hint)


def assert_status_contract(status: dict) -> ClientStatus:
    """A STATUS payload exactly as the GUI needs it: ClientStatus(**status) raises on an extra key but silently
    defaults a missing one, so the key set must equal the dataclass fields, and every value must have its type."""
    import dataclasses
    import typing
    hints = typing.get_type_hints(ClientStatus)
    assert set(status) == {f.name for f in dataclasses.fields(ClientStatus)}, set(status) ^ set(hints)
    wrong = {k: v for k, v in status.items() if not _hint_matches(v, hints[k])}
    assert not wrong, wrong
    assert status["state"] in {state.value for state in ConnectionState}
    return ClientStatus(**status)


def _ipc_status(service: ClientService) -> dict:
    service.ALLOWED_UIDS = {os.getuid()}
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        ipc_send(a, {"command": "STATUS"})
        service._handle_connection(b)
        return ipc_recv(a, timeout=2.0)["status"]
    finally:
        a.close()


def _fake_vpn(state: str, quality: bool) -> SimpleNamespace:
    from vpn.network import NetworkQualityMonitor
    monitor = NetworkQualityMonitor()
    if quality:
        for rtt in (1.2, 1.6):
            monitor.record_probe_sent()
            monitor.record_rtt(rtt)
        monitor.record_probe_sent()
        monitor.record_loss()
    return SimpleNamespace(
        state=state, error="", cfg=SimpleNamespace(kill_switch=True), session=SimpleNamespace(epoch=2),
        tun=SimpleNamespace(name="pqvpn0", mode=SimpleNamespace(name="NATIVE"), mtu=1380), quality=monitor,
        network=SimpleNamespace(ipv6=SimpleNamespace(table="pqvpn_client6"), dns_cleanup_registered=True,
                                kill_switch=True),
        tunnel={"client_vpn_ip": "10.8.0.2", "server_vpn_ip": "10.8.0.1", "rekey_interval": 120},
        next_rekey=time.monotonic() + 60, server_ip="192.0.2.10")


class TestStatusContract:
    """Every STATUS the service can send, through the real IPC handler, meets the GUI's contract. The native
    backend (pqvpnd --status-json) is held to the same contract by the same assertion."""

    @pytest.fixture
    def explicit(self, tmp_path):
        config = tmp_path / "client.toml"
        config.write_text("[client]\nserver_host='vpn.example'\n")
        return ClientService(str(config))

    def test_setup_required_explicit_and_managed(self, tmp_path):
        assert assert_status_contract(_ipc_status(ClientService(str(tmp_path / "missing.toml")))).state == "SETUP_REQUIRED"
        managed = ClientService(None, state_dir=tmp_path / "state")
        status = assert_status_contract(_ipc_status(managed))
        assert status.state == "SETUP_REQUIRED" and status.managed_mode and status.identity_ready

    def test_disconnected_and_failed(self, explicit):
        assert assert_status_contract(_ipc_status(explicit)).state == "DISCONNECTED"
        explicit._last_failure = "server unreachable"
        status = assert_status_contract(_ipc_status(explicit))
        assert (status.state, status.error) == ("FAILED", "server unreachable")

    def test_blocked_by_a_leftover_kill_switch(self, tmp_path, monkeypatch):
        import app.client as client_module
        monkeypatch.setattr(client_module, "_kill_switch_present", lambda: True)  # checked at service start
        config = tmp_path / "client.toml"
        config.write_text("[client]\nserver_host='vpn.example'\n")
        status = assert_status_contract(_ipc_status(ClientService(str(config))))
        assert status.state == "BLOCKED" and status.kill_switch_active

    @pytest.mark.parametrize("state", ["CONNECTING", "CONNECTED", "DISCONNECTING", "BLOCKED"])
    @pytest.mark.parametrize("quality", [False, True])
    def test_with_a_session(self, explicit, state, quality):
        explicit._vpn = _fake_vpn(state, quality)
        explicit._connected_at = time.monotonic()
        status = assert_status_contract(_ipc_status(explicit))
        assert status.state == state
        if state == "CONNECTED":
            assert (status.client_vpn_ip, status.epoch, status.tun_mode) == ("10.8.0.2", 2, "NATIVE")
            assert (status.rtt_ms is not None) == quality and (status.loss_rate is not None) == quality

    def test_contract_rejects_drift(self):
        from dataclasses import asdict
        good = asdict(ClientStatus())
        assert_status_contract(good)
        for broken in ({**good, "extra": 1}, {k: v for k, v in good.items() if k != "epoch"},
                       {**good, "epoch": "2"}, {**good, "is_quantum_safe": 1}, {**good, "state": "UP"},
                       {**good, "split_tunnel": [1]}):
            with pytest.raises(AssertionError):
                assert_status_contract(broken)


# ─── Malformed IPC request tests ──────────────────────────────────────────

class TestMalformedIPC:
    def test_invalid_json_handled(self, tmp_path):
        """Non-JSON data after a valid length header does not crash the service."""
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))
        service.ALLOWED_UIDS = {os.getuid()}

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # Send a valid length header with invalid JSON body
            bad_data = b"not json at all"
            a.sendall(struct.pack("!I", len(bad_data)) + bad_data)
            # Handler should not crash
            service._handle_connection(b)
        finally:
            a.close()

    def test_missing_command_field(self, tmp_path):
        """A JSON message without a 'command' field gets an unknown-command error."""
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))
        service.ALLOWED_UIDS = {os.getuid()}

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            ipc_send(a, {"not_a_command": True})
            service._handle_connection(b)
            result = ipc_recv(a, timeout=2.0)
            assert "error" in result
        finally:
            a.close()


# ─── Peer authorization (pentest #46/#50) ─────────────────────────────────

class TestPeerAuthorization:
    def _service(self, tmp_path, monkeypatch, allowed: str | None):
        if allowed is None:
            monkeypatch.delenv("PQVPN_ALLOWED_UIDS", raising=False)
        else:
            monkeypatch.setenv("PQVPN_ALLOWED_UIDS", allowed)
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        return ClientService(str(config))

    def _authorized(self, service, monkeypatch, uid: int | None) -> bool:
        monkeypatch.setattr("app.client.get_peer_uid", lambda _sock: uid)
        return service._authorize_peer(None)

    def test_no_allowlist_rejects_non_root(self, tmp_path, monkeypatch):
        service = self._service(tmp_path, monkeypatch, None)
        assert not self._authorized(service, monkeypatch, 31337)
        assert not self._authorized(service, monkeypatch, None)
        assert self._authorized(service, monkeypatch, 0)

    def test_desktop_user_in_allowlist_is_authorized(self, tmp_path, monkeypatch):
        """GUI regression guard: the configured desktop uid must still reach the service."""
        service = self._service(tmp_path, monkeypatch, f"{os.getuid()}, 4242")
        assert self._authorized(service, monkeypatch, os.getuid())
        assert self._authorized(service, monkeypatch, 4242)
        assert not self._authorized(service, monkeypatch, 31337)

    def test_desktop_user_runs_commands_over_real_socket(self, tmp_path, monkeypatch):
        service = self._service(tmp_path, monkeypatch, str(os.getuid()))
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            ipc_send(a, {"command": "STATUS"})
            service._handle_connection(b)
            assert "status" in ipc_recv(a, timeout=2.0)
        finally:
            a.close()

    @pytest.mark.parametrize("bad", ["abc", "1000,x", "-1", "1000;0", "1e3", "１０００"])
    def test_malformed_allowlist_fails_closed(self, tmp_path, monkeypatch, bad):
        service = self._service(tmp_path, monkeypatch, bad)
        assert service.ALLOWED_UIDS == set()
        assert not self._authorized(service, monkeypatch, 1000)


# ─── IPCClient connection error tests ─────────────────────────────────────

class TestIPCClient:
    def test_unauthorized_user_gets_actionable_error(self, monkeypatch, tmp_path):
        """The service answers 'unauthorized' and closes unread; the GUI must not report a broken pipe."""
        monkeypatch.setattr("app.client._RUNTIME_DIR", tmp_path)
        monkeypatch.setattr("app.client.get_peer_uid", lambda _sock: 0)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(tmp_path / "client.sock"))
        listener.listen(1)
        replied = threading.Event()

        def serve() -> None:
            conn, _ = listener.accept()
            ipc_send(conn, {"error": "unauthorized"})
            conn.close()
            replied.set()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        real_send = ipc_send

        def late_send(sock, msg):
            replied.wait(2)
            real_send(sock, {"pad": "x" * 600_000, **msg})  # overflow the socket buffer -> EPIPE

        monkeypatch.setattr("app.client.ipc_send", late_send)
        monkeypatch.setattr("app.client.MAX_IPC_MESSAGE", 1_000_000)
        try:
            resp = IPCClient().send_command("STATUS")
        finally:
            thread.join(timeout=3)
            listener.close()
        assert "PQVPN_ALLOWED_UIDS" in resp["error"]

    def test_rejects_non_root_listener(self, monkeypatch, tmp_path):
        """A squatted fallback socket (not uid 0) is never trusted or sent the request (#46b)."""
        monkeypatch.setattr("app.client._RUNTIME_DIR", tmp_path / "missing")
        monkeypatch.setattr("app.client._FALLBACK_DIR", tmp_path)
        squatter = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        squatter.bind(str(tmp_path / "pqvpn-client.sock"))
        squatter.listen(1)
        received: list[bytes] = []

        def serve() -> None:
            conn, _ = squatter.accept()
            conn.settimeout(2)
            try:
                received.append(conn.recv(4096))
                ipc_send(conn, {"status": {"state": "CONNECTED"}})
            except OSError:
                pass
            finally:
                conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            status = IPCClient().status()
        finally:
            thread.join(timeout=3)
            squatter.close()
        assert status.state == ConnectionState.FAILED.value
        assert "root" in status.error
        assert received in ([], [b""])


    def test_service_not_running(self, monkeypatch, tmp_path):
        """IPCClient returns a useful error when no service is listening."""
        monkeypatch.setattr("app.client._RUNTIME_DIR", tmp_path / "nonexistent")
        monkeypatch.setattr("app.client._FALLBACK_DIR", tmp_path / "also_nonexistent")
        client = IPCClient()
        status = client.status()
        assert status.state == ConnectionState.FAILED.value
        assert "not running" in status.error.lower() or "error" in status.error.lower()


def test_error_sanitization_is_bounded_and_redacts_secrets():
    value = sanitize_error("failed\n token=top-secret " + "x" * 400)
    assert "top-secret" not in value
    assert "\n" not in value
    assert len(value) <= 281


# ─── PySide6 GUI headless tests (QT_QPA_PLATFORM=offscreen) ──────────────

def _pyside6_available():
    try:
        import PySide6.QtWidgets
        return True
    except ImportError:
        return False


@pytest.fixture(scope="session")
def qapp(tmp_path_factory):
    if not _pyside6_available():
        pytest.skip("PySide6 not installed")
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication
    settings_dir = str(tmp_path_factory.mktemp("qsettings"))
    for fmt in (QSettings.NativeFormat, QSettings.IniFormat):
        QSettings.setPath(fmt, QSettings.UserScope, settings_dir)
    return QApplication.instance() or QApplication([])


@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestGUIHeadless:
    """Non-interactive GUI widget tests using the offscreen platform."""

    class FakeIPC:
        def __init__(self):
            self.status_calls = 0
            self.connect_calls = 0
            self.disconnect_calls = 0
            self.log_calls = 0

        def status(self):
            self.status_calls += 1
            return ClientStatus()

        def connect(self):
            self.connect_calls += 1
            return {"status": "connected"}

        def disconnect(self):
            self.disconnect_calls += 1
            return {"status": "disconnected"}

        def logs(self):
            self.log_calls += 1
            return []

    @pytest.fixture
    def window(self, qapp):
        from app.ui.window import MainWindow
        fake = self.FakeIPC()
        result = MainWindow(fake, start_polling=False)
        yield result, fake
        result.close()
        qapp.processEvents()

    def test_import_succeeds(self):
        """The client module imports without errors."""
        import app.client
        assert hasattr(app.client, "_launch_gui")

    def test_home_constructs_at_target_size(self, window):
        gui, _ = window
        assert gui.pages.count() == 7
        assert gui.width() == 1180 and gui.height() == 760
        assert gui.minimumWidth() == 980 and gui.minimumHeight() == 650

    def test_all_connection_states_render_safely(self, window):
        gui, _ = window
        for state in ConnectionState:
            gui._render(ClientStatus(state=state.value))
            assert gui.state_label.text() == state.value.replace("_", " ")

    def test_navigation_switches_without_vpn_actions(self, window):
        gui, fake = window
        for index, name in enumerate(("Home", "Servers", "Security", "Account", "Settings", "Logs", "About")):
            gui.switch_page(index)
            assert gui.pages.currentIndex() == index
            assert gui.page_title.text() == name
        assert fake.connect_calls == 0
        assert fake.disconnect_calls == 0

    def test_connected_renders_real_fields(self, window):
        gui, _ = window
        gui._render(ClientStatus(
            state="CONNECTED",
            uptime_seconds=1122,
            client_vpn_ip="10.8.0.2",
            server_host="vpn.example",
            connected_endpoint="192.0.2.10",
            tun_mode="NATIVE",
            mtu=1380,
            epoch=4,
            pqc_mode="native_liboqs",
            is_quantum_safe=True,
            rekey_countdown=98.7,
            rtt_ms=1.25,
            jitter_ms=0.4,
            loss_rate=0.01,
            ipv6_guard_active=True,
            dns_managed=True,
        ))
        assert gui.detail_vpn_ip.value_label.text() == "10.8.0.2"
        assert gui.detail_uptime.value_label.text() == "00:18:42"
        assert gui.detail_rtt.value_label.text() == "1.2 ms"
        assert gui.detail_jitter.value_label.text() == "0.4 ms"
        assert gui.detail_loss.value_label.text() == "1.00%"
        assert gui.detail_rekey.value_label.text() == "98s"
        assert gui.sec_epoch.value_label.text() == "4"
        assert gui.sec_mtu.value_label.text() == "1380"
        assert gui.action_btn.text() == "Disconnect"

    def test_disconnected_clears_active_only_fields(self, window):
        gui, _ = window
        gui._render(ClientStatus(
            state="CONNECTED", client_vpn_ip="10.8.0.2", uptime_seconds=5,
            rtt_ms=2, jitter_ms=1, loss_rate=.2, rekey_countdown=20,
            tun_mode="NATIVE", mtu=1380, epoch=2,
            ipv6_guard_active=True, dns_managed=True, is_quantum_safe=True,
        ))
        gui._render(ClientStatus(
            state="DISCONNECTED", client_vpn_ip="should-not-render", uptime_seconds=5,
            rtt_ms=2, jitter_ms=1, loss_rate=.2, rekey_countdown=20,
            tun_mode="NATIVE", mtu=1380, epoch=2,
            ipv6_guard_active=True, dns_managed=True, is_quantum_safe=True,
        ))
        assert gui.detail_vpn_ip.value_label.text() == "—"
        assert gui.detail_uptime.value_label.text() == "—"
        assert gui.detail_rtt.value_label.text() == "—"
        assert gui.detail_rekey.value_label.text() == "—"
        assert gui.sec_epoch.value_label.text() == "—"
        assert gui.sec_tun.value_label.text() == "Idle"
        assert gui.sec_ipv6.status_label.text() != "Active"
        assert gui.sec_dns.status_label.text() != "Managed"

    def test_setup_required_shows_exact_config_path(self, window):
        gui, _ = window
        path = "/etc/pqvpn/client.toml"
        gui._render(ClientStatus(
            state="SETUP_REQUIRED", config_path=path,
            error=f"Configuration not found: {path}",
        ))
        assert path in gui.error_label.text()
        assert not gui.action_btn.isEnabled()
        assert gui.action_btn.text() == "Setup required"

    def test_failed_error_is_sanitized_and_retry_available(self, window):
        gui, _ = window
        gui._render(ClientStatus(state="FAILED", error="failure token=do-not-show"))
        assert "do-not-show" not in gui.error_label.text()
        assert "[redacted]" in gui.error_label.text()
        assert gui.action_btn.text() == "Retry"
        assert gui.action_btn.isEnabled()

    def test_runtime_protection_flags_are_active_only_when_connected(self, window):
        gui, _ = window
        gui._render(ClientStatus(
            state="DISCONNECTED", ipv6_guard_active=True, dns_managed=True,
        ))
        assert gui.sec_ipv6.status_label.text() != "Active"
        assert gui.sec_dns.status_label.text() != "Managed"
        gui._render(ClientStatus(
            state="CONNECTED", ipv6_guard_active=True, dns_managed=True,
        ))
        assert gui.sec_ipv6.status_label.text() == "Active"
        assert gui.sec_dns.status_label.text() == "Managed"

    def test_security_distinguishes_configured_from_active(self, window):
        gui, _ = window
        gui._render(ClientStatus(
            state="DISCONNECTED", pqc_mode="native_liboqs", is_quantum_safe=True,
        ))
        assert gui.sec_hybrid.status_label.text().startswith("Configured:")
        assert gui.sec_encryption.status_label.text().startswith("Configured:")
        gui._render(ClientStatus(
            state="CONNECTED", pqc_mode="native_liboqs", is_quantum_safe=True,
        ))
        assert gui.sec_hybrid.status_label.text().startswith("Active:")
        assert gui.sec_encryption.status_label.text().startswith("Active:")
        assert "classical" in gui.sec_client_auth.status_label.text()

    def test_servers_page_never_exposes_private_key(self, window):
        from PySide6.QtWidgets import QLabel
        gui, _ = window
        gui._render(ClientStatus(
            state="DISCONNECTED", server_host="vpn.example", server_control_port=51820,
            server_fingerprint="a" * 64,
        ))
        gui.switch_page(1)
        visible_text = " ".join(label.text() for label in gui.pages.currentWidget().findChildren(QLabel))
        assert "private key" not in visible_text.lower()
        assert "client_identity_private_key" not in visible_text
        assert "a" * 64 not in visible_text  # fingerprint is intentionally truncated

    def test_connect_button_ignores_duplicate_requests_while_busy(self, window):
        gui, _ = window
        gui._render(ClientStatus(state="DISCONNECTED"))
        gui._worker.request_action = Mock()
        gui._on_toggle()
        gui._on_toggle()
        gui._worker.request_action.assert_called_once_with("connect")

    def test_first_run_managed_onboarding_is_visible(self, window):
        gui, _ = window
        gui._render(ClientStatus(
            state="SETUP_REQUIRED", managed_mode=True, setup_complete=False,
            identity_ready=True, identity_fingerprint="a" * 64, profiles=[],
            error="Import and select a server profile",
        ))
        assert not gui.onboarding_card.isHidden()
        assert gui.onboarding_identity.status_label.text() == "Ready"
        assert "Import" in gui.onboarding_profile.status_label.text()
        assert not gui.action_btn.isEnabled()
        assert gui.onboarding_copy_btn.isEnabled()

    def test_completed_or_legacy_setup_hides_onboarding(self, window):
        gui, _ = window
        gui._render(ClientStatus(state="DISCONNECTED", managed_mode=False))
        assert gui.onboarding_card.isHidden()
        gui._render(ClientStatus(
            state="DISCONNECTED", managed_mode=True, setup_complete=True,
            identity_ready=True, active_profile_id="lab", active_profile_name="Lab",
        ))
        assert gui.onboarding_card.isHidden()
        assert gui.action_btn.isEnabled()

    def test_imported_and_active_profile_display_real_values(self, window, qapp):
        from PySide6.QtWidgets import QLabel
        gui, _ = window
        profile = {
            "version": 1, "profile_id": "ubuntu-lab", "name": "Ubuntu Lab",
            "server_host": "192.168.8.43", "server_control_port": 51820,
            "server_identity_public_key": "public-value-not-rendered",
            "server_identity_fingerprint": "b" * 64,
            "expected_vpn_subnet": "10.8.0.0/24", "active": True,
        }
        gui._render(ClientStatus(
            state="DISCONNECTED", managed_mode=True, setup_complete=True,
            identity_ready=True, active_profile_id="ubuntu-lab",
            active_profile_name="Ubuntu Lab", profiles=[profile],
            server_host="192.168.8.43", server_control_port=51820,
            server_fingerprint="b" * 64, expected_vpn_subnet="10.8.0.0/24",
        ))
        qapp.processEvents()
        visible = " ".join(
            label.text() for label in gui.server_profiles_card.findChildren(QLabel)
        )
        assert "Ubuntu Lab" in visible
        assert "192.168.8.43:51820" in visible
        assert "SELECTED" in visible
        assert "public-value-not-rendered" not in visible

    def test_connected_profile_is_named_and_mutation_disabled(self, window):
        gui, _ = window
        gui._render(ClientStatus(
            state="CONNECTED", managed_mode=True, setup_complete=True,
            active_profile_id="lab", active_profile_name="Lab",
            connected_profile_id="lab", connected_profile_name="Lab",
            server_host="vpn.example", profiles=[],
        ))
        assert gui.detail_server.value_label.text().startswith("Lab")
        assert not gui.server_import_btn.isEnabled()

    def test_settings_and_security_show_public_identity_only(self, window):
        gui, _ = window
        gui._render(ClientStatus(
            state="DISCONNECTED", managed_mode=True, setup_complete=True,
            identity_ready=True, identity_fingerprint="c" * 64,
            identity_path="/var/lib/pqvpn/identity",
            profile_store_path="/var/lib/pqvpn/profiles/profiles.json",
            config_path="/var/lib/pqvpn/profiles/profiles.json",
        ))
        assert "…" in gui.sec_client_fingerprint.value_label.text()
        assert gui.settings_state_path.value_label.text() == "/var/lib/pqvpn/identity"
        assert "private" not in gui.settings_state_path.value_label.text().lower()
        assert gui._worker._thread.is_alive()


# ─── Milestone 4.3: account API client, memory-only session, desktop auth ──

from app.client import (  # noqa: E402 - grouped with the M4 account tests
    BUNDLED_ACCOUNT_CA_CERT,
    DEFAULT_ACCOUNT_API_URL,
    AccountAPIError,
    AccountClient,
    AccountSession,
    SessionState,
    UserProfile,
    _sanitized_message,
)

ACCOUNT_PASSWORD = "correct horse battery staple"


def _invite(store) -> str:
    """A fresh single-use invite: the live API runs invite-only like production."""
    return store.create_invite()[1]


@pytest.fixture
def live_account_api(tmp_path):
    """Run the real pqvpn-account-api app on loopback for client integration tests."""
    import uvicorn
    from vpn.account_api import AccountAPIConfig, create_app
    from vpn.accounts import AccountStore

    store = AccountStore(tmp_path / "accounts" / "accounts.db")
    app = create_app(
        AccountAPIConfig(database_path=store.path, allow_insecure_loopback=True,
                         authorized_clients_file=tmp_path / "authorized" / "authorized_clients.json"),
        store=store,
    )
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    yield f"http://127.0.0.1:{port}", store, app
    server.should_exit = True
    thread.join(timeout=10)


class TestAccountClientConstruction:
    def test_loopback_http_allowed(self):
        assert AccountClient("http://127.0.0.1:8443")._ssl_context is None
        assert AccountClient("http://[::1]:8443")._ssl_context is None

    @pytest.mark.parametrize("url", [
        "http://192.168.1.1:8443", "http://localhost.example:8443", "http://8.8.8.8",
    ])
    def test_non_loopback_http_rejected(self, url):
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient(url)
        assert exc_info.value.code == "tls_required"

    @pytest.mark.parametrize("url", [
        "ftp://127.0.0.1", "https://", "https://u:p@server:8443", "https://server:99999",
        "https://server/?token=x",
    ])
    def test_invalid_urls_rejected(self, url):
        with pytest.raises(AccountAPIError):
            AccountClient(url)

    def test_https_always_verifies_certificates(self):
        import ssl
        context = AccountClient("https://server.example.com:8443/")._ssl_context
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_unreadable_ca_certificate_is_reported(self, tmp_path):
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient("https://server:8443", tmp_path / "missing.pem")
        assert exc_info.value.code == "ssl_error"

    def test_trailing_slash_stripped(self):
        assert AccountClient("http://127.0.0.1:8443/").base_url == "http://127.0.0.1:8443"


def _self_signed_cert(tmp_path: Path, name: str, san: str | None) -> tuple[Path, Path]:
    """Same openssl invocation as scripts/deploy-server.sh, optionally with a SAN."""
    import shutil
    import subprocess
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    crt, key = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cmd = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
           "-keyout", str(key), "-out", str(crt), "-days", "1", "-nodes",
           "-subj", "/CN=pqvpn-account-api"]
    subprocess.run(cmd + (["-addext", f"subjectAltName={san}"] if san else []),
                   check=True, capture_output=True)
    return crt, key


@pytest.fixture
def tls_info_server(tmp_path):
    """HTTPS /server/info on 127.0.0.1; yields (url, cert_path) for a cert of the given SAN."""
    import http.server
    import ssl
    servers = []

    def start(san: str | None, name: str = "server") -> tuple[str, Path]:
        crt, key = _self_signed_cert(tmp_path, name, san)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"https://127.0.0.1:{server.server_address[1]}", crt

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


class TestAccountClientFromEnv:
    def test_defaults_to_built_in_server_pinned_to_bundled_cert(self, monkeypatch):
        import ssl
        monkeypatch.delenv("PQVPN_ACCOUNT_API_URL", raising=False)
        monkeypatch.delenv("PQVPN_ACCOUNT_CA_CERT", raising=False)
        client = AccountClient.from_env()
        assert client.base_url == DEFAULT_ACCOUNT_API_URL == "https://52.62.237.95:8443"
        assert client.ca_cert == BUNDLED_ACCOUNT_CA_CERT
        context = client._ssl_context
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        # Exclusive pin: only the bundled certificate is trusted, not the system store.
        assert [ca["subject"] for ca in context.get_ca_certs()] == [
            ((("commonName", "pqvpn-account-api"),),)
        ]

    def test_bundled_cert_is_public_x509_with_server_ip_san(self):
        import ipaddress
        from cryptography import x509
        pem = BUNDLED_ACCOUNT_CA_CERT.read_bytes()
        assert b"PRIVATE" not in pem
        cert = x509.load_pem_x509_certificate(pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert ipaddress.ip_address("52.62.237.95") in san.get_values_for_type(x509.IPAddress)

    def test_bundled_cert_is_declared_package_data(self):
        import tomllib
        pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
        assert BUNDLED_ACCOUNT_CA_CERT.name in pyproject["tool"]["setuptools"]["package-data"]["app"]
        assert BUNDLED_ACCOUNT_CA_CERT.parent.name == "app"

    def test_env_url_override_does_not_trust_bundled_cert(self, monkeypatch):
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", "https://vpn.example.com:8443")
        monkeypatch.delenv("PQVPN_ACCOUNT_CA_CERT", raising=False)
        client = AccountClient.from_env()
        assert client.base_url == "https://vpn.example.com:8443" and client.ca_cert is None

    def test_env_ca_overrides_bundled_cert_for_default_url(self, monkeypatch, tmp_path):
        crt, _key = _self_signed_cert(tmp_path, "other", "IP:52.62.237.95")
        monkeypatch.delenv("PQVPN_ACCOUNT_API_URL", raising=False)
        monkeypatch.setenv("PQVPN_ACCOUNT_CA_CERT", str(crt))
        client = AccountClient.from_env()
        assert client.base_url == DEFAULT_ACCOUNT_API_URL and client.ca_cert == crt

    def test_env_loopback_cleartext_still_allowed_for_dev(self, monkeypatch):
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", "http://127.0.0.1:8443")
        monkeypatch.delenv("PQVPN_ACCOUNT_CA_CERT", raising=False)
        client = AccountClient.from_env()
        assert client.base_url == "http://127.0.0.1:8443" and client._ssl_context is None

    def test_env_url_and_pinned_ca_verify_self_signed_ip_cert(self, monkeypatch, tls_info_server):
        url, crt = tls_info_server("DNS:pqvpn-account-api,IP:127.0.0.1")
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", url)
        monkeypatch.setenv("PQVPN_ACCOUNT_CA_CERT", str(crt))
        client = AccountClient.from_env()
        assert client.base_url == url and client.ca_cert == crt
        assert client.server_info() == {"ok": True}

    def test_untrusted_cert_is_rejected(self, monkeypatch, tls_info_server):
        url, _crt = tls_info_server("IP:127.0.0.1")
        other, _ = _self_signed_cert(Path(_crt).parent, "other", "IP:127.0.0.1")
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", url)
        monkeypatch.setenv("PQVPN_ACCOUNT_CA_CERT", str(other))
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient.from_env().server_info()
        assert exc_info.value.code == "ssl_error"

    def test_cert_without_ip_san_is_rejected(self, monkeypatch, tls_info_server):
        url, crt = tls_info_server(None)
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", url)
        monkeypatch.setenv("PQVPN_ACCOUNT_CA_CERT", str(crt))
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient.from_env().server_info()
        assert exc_info.value.code == "ssl_error"

    def test_unloadable_ca_fails_closed(self, monkeypatch, tmp_path):
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate")
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", "https://52.62.237.95:8443")
        for ca in (tmp_path / "missing.pem", bad):
            monkeypatch.setenv("PQVPN_ACCOUNT_CA_CERT", str(ca))
            with pytest.raises(AccountAPIError) as exc_info:
                AccountClient.from_env()
            assert exc_info.value.code == "ssl_error"

    def test_env_cleartext_to_remote_host_rejected(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", "http://52.62.237.95:8443")
        monkeypatch.delenv("PQVPN_ACCOUNT_CA_CERT", raising=False)
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient.from_env()
        assert exc_info.value.code == "tls_required"


class TestAccountErrorMessages:
    def test_known_codes_are_uniform(self):
        assert _sanitized_message("invalid_credentials", 401) == "Invalid username/email or password."
        assert "expired" in _sanitized_message("invalid_session", 401)
        assert "already exists" in _sanitized_message("account_exists", 409)

    def test_unknown_codes_never_echo_server_text(self):
        assert "unavailable" in _sanitized_message("whatever", 503).lower()
        assert "unexpected" in _sanitized_message("whatever", 400).lower()


class TestAccountClientLiveAPI:
    def test_full_lifecycle_against_real_api(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        user = client.register("Alice", "Alice@Example.com", ACCOUNT_PASSWORD, _invite(store))
        assert user["username"] == "alice"
        token, login_user, expires_at = client.login("alice", ACCOUNT_PASSWORD)
        assert login_user["email"] == "alice@example.com" and expires_at
        assert client.get_me(token)["username"] == "alice"
        client.logout(token)
        with pytest.raises(AccountAPIError) as exc_info:
            client.get_me(token)
        assert exc_info.value.status_code == 401
        assert exc_info.value.code == "invalid_session"

    def test_email_login(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        client.register("bob", "bob@example.com", ACCOUNT_PASSWORD, _invite(store))
        token, user, _ = client.login("BOB@example.com", ACCOUNT_PASSWORD)
        assert user["username"] == "bob" and token

    def test_failures_are_indistinguishable(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        created = client.register("carol", "carol@example.com", ACCOUNT_PASSWORD, _invite(store))
        store.set_user_enabled(created["id"], False)
        messages = set()
        for identifier, password in (
            ("carol", "wrong password value"),   # wrong password
            ("nobody", ACCOUNT_PASSWORD),        # nonexistent account
            ("carol", ACCOUNT_PASSWORD),         # disabled account
        ):
            with pytest.raises(AccountAPIError) as exc_info:
                client.login(identifier, password)
            assert exc_info.value.status_code == 401
            messages.add((exc_info.value.code, exc_info.value.message))
        assert messages == {("invalid_credentials", "Invalid username/email or password.")}

    def test_disabled_account_session_is_rejected(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        created = client.register("dave", "dave@example.com", ACCOUNT_PASSWORD, _invite(store))
        token, _, _ = client.login("dave", ACCOUNT_PASSWORD)
        store.set_user_enabled(created["id"], False)
        with pytest.raises(AccountAPIError) as exc_info:
            client.get_me(token)
        assert exc_info.value.status_code == 401

    def test_login_rate_limit_reports_retry_after(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        for _ in range(5):
            with pytest.raises(AccountAPIError):
                client.login("erin", "wrong password value")
        with pytest.raises(AccountAPIError) as exc_info:
            client.login("erin", "wrong password value")
        assert exc_info.value.code == "rate_limited"
        assert exc_info.value.retry_after > 0
        assert str(exc_info.value.retry_after) in exc_info.value.message

    def test_registration_rate_limit(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        for index in range(3):
            client.register(f"user{index}", f"user{index}@example.com", ACCOUNT_PASSWORD, _invite(store))
        with pytest.raises(AccountAPIError) as exc_info:
            client.register("user9", "user9@example.com", ACCOUNT_PASSWORD, _invite(store))
        assert exc_info.value.code == "rate_limited"

    @pytest.mark.parametrize("username,email,password,code", [
        ("frank", "frank@example.com", "short", "invalid_registration"),
        ("frank", "frank@example.com", "x" * 1025, "invalid_registration"),
        ("bad name!", "frank@example.com", ACCOUNT_PASSWORD, "invalid_registration"),
        ("frank", "not-an-email", ACCOUNT_PASSWORD, "invalid_registration"),
    ], ids=["short-password", "long-password", "invalid-username", "invalid-email"])
    def test_invalid_registration(self, live_account_api, username, email, password, code):
        url, store, _app = live_account_api
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient(url).register(username, email, password, _invite(store))
        assert exc_info.value.code == code
        assert password not in exc_info.value.message

    def test_duplicate_username_and_email(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        client.register("gina", "gina@example.com", ACCOUNT_PASSWORD, _invite(store))
        for username, email in (("gina", "other@example.com"), ("other", "gina@example.com")):
            with pytest.raises(AccountAPIError) as exc_info:
                client.register(username, email, ACCOUNT_PASSWORD, _invite(store))
            assert exc_info.value.code == "account_exists"

    def test_api_unavailable(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient(f"http://127.0.0.1:{port}").login("x", "y")
        assert exc_info.value.code == "connection_error"


class TestAccountClientMalformedResponses:
    @pytest.fixture
    def stub(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        bodies = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                status, body = bodies[self.path]
                self.send_response(status)
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{server.server_address[1]}", bodies
        server.shutdown()

    @pytest.mark.parametrize("body", [
        b"not json", b"[1, 2]", b'{"access_token": ""}', b'{"access_token": "t", "user": 5}',
    ])
    def test_malformed_login_response(self, stub, body):
        url, bodies = stub
        bodies["/auth/login"] = (200, body)
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient(url).login("alice", ACCOUNT_PASSWORD)
        assert exc_info.value.code == "invalid_response"

    def test_server_error_text_is_not_echoed(self, stub):
        url, bodies = stub
        bodies["/auth/login"] = (500, b'{"error": {"code": "x", "message": "sqlite /var/lib secret"}}')
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient(url).login("alice", ACCOUNT_PASSWORD)
        assert "sqlite" not in exc_info.value.message
        assert exc_info.value.status_code == 500


class TestAccountSession:
    USER = UserProfile(id=1, username="alice", email="a@b.com", enabled=True, created_at="")

    def test_lifecycle(self):
        session = AccountSession()
        assert session.state == SessionState.LOGGED_OUT and session.get_token() is None
        session.set_authenticating()
        assert not session.is_authenticated and session.get_token() is None
        session.set_session("secret_token", self.USER, "2026-01-02")
        assert session.is_authenticated and session.get_token() == "secret_token"
        session.clear_session(expired=True)
        assert session.state == SessionState.SESSION_EXPIRED
        assert session.get_token() is None and session.get_user() is None

    def test_repr_and_str_redact_token(self):
        session = AccountSession()
        session.set_session("super_secret_token_value", self.USER, "2026-01-02")
        for text in (repr(session), str(session)):
            assert "super_secret_token_value" not in text
            assert "[REDACTED]" in text

    def test_user_profile_from_partial_dict(self):
        user = UserProfile.from_dict({})
        assert (user.id, user.username, user.email) == (0, "", "")
        with pytest.raises(AttributeError):
            user.username = "changed"

    def test_thread_safety(self):
        session = AccountSession()
        errors = []

        def churn():
            try:
                for _ in range(200):
                    session.set_session("tok", self.USER, "exp")
                    session.get_token()
                    session.clear_session()
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=churn) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        assert not errors


# ─── Helper: seed an authenticated MainWindow from the live API ──────────

def _sign_in_direct(gui, qapp, url, identifier="alice"):
    """Sign in by calling the API directly and seeding MainWindow's session."""
    client = AccountClient(url)
    token, _user, expires_at = client.login(identifier, ACCOUNT_PASSWORD)
    me = client.get_me(token)
    gui._account_client = client
    gui._account_session.set_session(token, UserProfile.from_dict(me), expires_at)
    gui._session_timer.start()
    gui._refresh_account_view()
    gui._account_worker.submit("devices", lambda: client.list_devices(token))
    _wait_for(qapp, lambda: gui._account_session.is_authenticated)


def _wait_for(qapp, predicate, timeout=15.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(0.01)
    qapp.processEvents()
    assert predicate()


# ─── LoginWindow tests ──────────────────────────────────────────────────

@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestLoginWindow:
    @pytest.fixture
    def login(self, qapp, monkeypatch):
        from app.ui.login import LoginWindow
        monkeypatch.delenv("PQVPN_ACCOUNT_CA_CERT", raising=False)
        window = LoginWindow()
        yield window
        window.close()
        qapp.processEvents()

    def test_login_flow_emits_signal(self, login, qapp, live_account_api, monkeypatch):
        url, store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", url)
        login.login_identifier.setText("alice@example.com")
        login.login_password.setText(ACCOUNT_PASSWORD)
        received = []
        login.login_succeeded.connect(lambda: received.append(True))
        login._on_login()
        _wait_for(qapp, lambda: login.login_btn.text() == "Sign In")
        assert received
        assert login.session_token and login.session_user["username"] == "alice"
        assert login.login_password.text() == ""

    def test_login_failure_shows_error(self, login, qapp, live_account_api, monkeypatch):
        url, store, _app = live_account_api
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", url)
        login.login_identifier.setText("nobody")
        login.login_password.setText(ACCOUNT_PASSWORD)
        login._on_login()
        _wait_for(qapp, lambda: login.login_btn.text() == "Sign In")
        assert login.login_error.text() == "Invalid username/email or password."
        assert login.session_token is None

    def test_cleartext_remote_url_refused(self, login, monkeypatch):
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", "http://203.0.113.5:8443")
        login.login_identifier.setText("alice")
        login.login_password.setText(ACCOUNT_PASSWORD)
        login._on_login()
        assert "loopback" in login.login_error.text()
        assert login.login_btn.isEnabled()

    def test_register_validation(self, login):
        login._show_register()
        login.register_username.setText("alice")
        login.register_email.setText("alice@example.com")
        login.register_password.setText("short")
        login.register_confirm.setText("short")
        login._on_register()
        assert "12" in login.register_error.text()
        login.register_password.setText(ACCOUNT_PASSWORD)
        login.register_confirm.setText(ACCOUNT_PASSWORD + "x")
        login._on_register()
        assert "match" in login.register_error.text()
        login.register_confirm.setText(ACCOUNT_PASSWORD)
        login._on_register()
        assert "invite code is required" in login.register_error.text()
        assert login.register_btn.text() == "Create Account"

    def test_register_then_login(self, login, qapp, live_account_api, monkeypatch):
        url, store, _app = live_account_api
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", url)
        login._show_register()
        login.register_username.setText("newuser")
        login.register_email.setText("new@example.com")
        login.register_password.setText(ACCOUNT_PASSWORD)
        login.register_confirm.setText(ACCOUNT_PASSWORD)
        login.register_invite.setText(_invite(store))
        login._on_register()
        _wait_for(qapp, lambda: login.register_btn.text() == "Create Account")
        assert "created" in login.register_error.text().lower()
        # After register, the identifier field should be pre-filled
        assert login.login_identifier.text() == "newuser"
        assert login.register_invite.text() == ""

    def test_register_rejected_invite_shows_clear_error(self, login, qapp, live_account_api,
                                                       monkeypatch, caplog):
        url, store, _app = live_account_api
        monkeypatch.setenv("PQVPN_ACCOUNT_API_URL", url)
        bad_code = "not-a-real-invite-code-0123456789abcdefghij"
        caplog.set_level("DEBUG")
        login._show_register()
        login.register_username.setText("newuser")
        login.register_email.setText("new@example.com")
        login.register_password.setText(ACCOUNT_PASSWORD)
        login.register_confirm.setText(ACCOUNT_PASSWORD)
        login.register_invite.setText(bad_code)
        login._on_register()
        _wait_for(qapp, lambda: login.register_btn.text() == "Create Account")
        assert login.register_error.text() == "The invite code is invalid, expired, or already used."
        assert bad_code not in caplog.text
        assert store.get_user_by_username("newuser") is None


# ─── Account GUI tests (MainWindow, post-login) ─────────────────────────

@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestAccountGUI:
    @pytest.fixture
    def gui(self, qapp):
        from app.ui.window import MainWindow
        window = MainWindow(TestGUIHeadless.FakeIPC(), start_polling=False)
        yield window
        window.close()
        qapp.processEvents()

    def test_login_logout_flow_keeps_token_out_of_ui(self, gui, qapp, live_account_api, caplog):
        from PySide6.QtWidgets import QLabel, QLineEdit
        url, store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        caplog.set_level("DEBUG")
        _sign_in_direct(gui, qapp, url, "alice@example.com")
        assert gui._account_session.is_authenticated
        assert gui.account_stack.currentIndex() == 1  # profile view
        assert gui.profile_username.text() == "@alice"
        token = gui._account_session.get_token()
        widgets_text = " ".join(
            w.text() for w in gui.findChildren(QLabel) + gui.findChildren(QLineEdit)
        )
        assert token not in widgets_text
        assert token not in caplog.text and ACCOUNT_PASSWORD not in caplog.text

        gui._on_logout_clicked()
        assert gui._account_session.get_token() is None
        assert gui.account_stack.currentIndex() == 0  # signed-out view
        token_hash = __import__("hashlib").sha256(token.encode()).digest()
        _wait_for(qapp, lambda: store.get_session_by_token_hash(token_hash).revoked_at)

    def test_logout_clears_locally_when_api_unavailable(self, gui):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._account_client = AccountClient("http://127.0.0.1:1")
        gui._on_logout_clicked()
        assert gui._account_session.get_token() is None
        assert gui._account_session.state == SessionState.LOGGED_OUT

    def test_revoked_session_shows_signed_out(self, gui, qapp, live_account_api):
        url, store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        _sign_in_direct(gui, qapp, url)
        AccountClient(url).logout(gui._account_session.get_token())
        gui._validate_account_session()
        _wait_for(qapp, lambda: gui._account_session.state == SessionState.SESSION_EXPIRED)
        assert gui.account_stack.currentIndex() == 0
        assert "expired" in gui.signed_out_message.text().lower()

    def test_api_unavailable_keeps_session_and_warns(self, gui):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._account_validate_finished(False, "connection_error", "x", 0, 0)
        assert gui._account_session.is_authenticated
        assert "UNAVAILABLE" in gui.profile_session_badge.text()

    def test_login_never_touches_authorized_clients(self, gui, qapp, live_account_api, tmp_path):
        url, store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        _sign_in_direct(gui, qapp, url)
        assert gui._account_session.is_authenticated
        assert not list(tmp_path.rglob("authorized_clients.json"))

    def test_session_seeded_at_construction(self, qapp, live_account_api):
        """MainWindow constructed with session data starts authenticated."""
        from app.ui.window import MainWindow
        url, store, _app = live_account_api
        client = AccountClient(url)
        client.register("seeded", "seeded@example.com", ACCOUNT_PASSWORD, _invite(store))
        token, _user, expires = client.login("seeded", ACCOUNT_PASSWORD)
        me = client.get_me(token)
        window = MainWindow(
            TestGUIHeadless.FakeIPC(), start_polling=False,
            account_client=client, session_token=token,
            session_user=me, session_expires_at=expires,
        )
        try:
            assert window._account_session.is_authenticated
            assert window.profile_username.text() == "@seeded"
            assert window.account_stack.currentIndex() == 1
        finally:
            window.close()
            qapp.processEvents()


# ─── Milestone 4.4: account ↔ managed device binding ──────────────────────

def _device_setup(seed: int = 7) -> dict:
    """SETUP_STATUS-shaped public identity built from a deterministic test key."""
    import base64
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return {"setup": {
        "identity_public_key": base64.b64encode(public).decode(),
        "identity_fingerprint": hashlib.sha256(public).hexdigest(),
    }}


class TestPublicDeviceIdentity:
    def test_valid_identity_is_returned(self):
        from app.client import public_device_identity
        setup = _device_setup()
        assert public_device_identity(setup) == (
            setup["setup"]["identity_public_key"], setup["setup"]["identity_fingerprint"]
        )

    @pytest.mark.parametrize("setup", [
        {"error": "Service not running"},
        {"setup": {"identity_public_key": None, "identity_fingerprint": None}},
        {"setup": {**_device_setup()["setup"], "identity_fingerprint": "0" * 64}},
        {"setup": {**_device_setup()["setup"], "identity_public_key": "!!"}},
    ])
    def test_missing_or_inconsistent_identity_is_refused(self, setup):
        from app.client import public_device_identity
        with pytest.raises(AccountAPIError) as exc_info:
            public_device_identity(setup)
        assert exc_info.value.code == "identity_unavailable"


@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestDeviceBindingGUI:
    class IdentityIPC(TestGUIHeadless.FakeIPC):
        def __init__(self):
            super().__init__()
            self.setup_calls = 0

        def setup_status(self):
            self.setup_calls += 1
            return _device_setup()

    @pytest.fixture
    def gui(self, qapp):
        from app.ui.window import MainWindow
        ipc = self.IdentityIPC()
        window = MainWindow(ipc, start_polling=False)
        window._render(ClientStatus(
            state="DISCONNECTED", managed_mode=True, identity_ready=True,
            identity_fingerprint=_device_setup()["setup"]["identity_fingerprint"],
        ))
        yield window
        window.close()
        qapp.processEvents()

    def test_bind_current_device_sends_public_identity_only(self, gui, qapp, live_account_api):
        url, store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        _sign_in_direct(gui, qapp, url)
        _wait_for(qapp, lambda: gui.device_bind_btn.isEnabled())
        assert gui.device_binding_row.value_label.text() == "Not registered"
        gui.device_name_input.setText("work laptop")
        gui._on_bind_device_clicked()
        _wait_for(qapp, lambda: gui._current_account_device() is not None)
        assert gui.device_binding_row.value_label.text() == (
            "Registered as work laptop · Pending administrator approval"
        )
        assert not gui.device_bind_btn.isEnabled()
        fingerprint = _device_setup()["setup"]["identity_fingerprint"]
        device = store.get_device_by_fingerprint(fingerprint)
        assert device.device_name == "work laptop" and len(device.client_public_key) == 32

    def test_bind_is_unavailable_when_signed_out(self, gui):
        assert not gui.device_bind_btn.isEnabled()
        gui._on_bind_device_clicked()
        assert gui.ipc.setup_calls == 0

    def test_identity_failure_is_reported(self, gui, qapp):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._account_client = AccountClient("http://127.0.0.1:1")
        gui.ipc.setup_status = lambda: {"error": "Service not running"}
        gui._on_bind_device_clicked()
        _wait_for(qapp, lambda: gui.device_error.isVisible() or not gui.device_error.isHidden())
        assert "identity" in gui.device_error.text().lower()


# ─── Milestone 4.6: account-aware desktop UX ──────────────────────────────

class TestAccountUXState:
    AUTH = SessionState.AUTHENTICATED

    @pytest.mark.parametrize("session,api,identity,device,vpn,expected", [
        (SessionState.LOGGED_OUT, True, True, None, "DISCONNECTED", "logged_out"),
        (AUTH, True, True, None, "DISCONNECTED", "no_device"),
        (AUTH, True, True, {"status": "pending", "enabled": True}, "DISCONNECTED", "device_pending"),
        (AUTH, True, True, {"status": "rejected", "enabled": True}, "DISCONNECTED", "device_rejected"),
        (AUTH, True, True, {"status": "approved", "enabled": False}, "DISCONNECTED", "device_disabled"),
        (AUTH, True, True, {"status": "approved", "enabled": True}, "DISCONNECTED", "approved_disconnected"),
        (AUTH, True, True, {"status": "approved", "enabled": True}, "CONNECTING", "vpn_connecting"),
        (AUTH, True, True, {"status": "approved", "enabled": True}, "CONNECTED", "vpn_connected"),
        (SessionState.SESSION_EXPIRED, True, True, None, "DISCONNECTED", "session_expired"),
        (AUTH, False, True, None, "DISCONNECTED", "server_unavailable"),
        (AUTH, True, True, {"status": "revoked", "enabled": True}, "DISCONNECTED", "device_revoked"),
    ])
    def test_state_matrix(self, session, api, identity, device, vpn, expected):
        from app.client import account_ux_state
        key, title, detail, tone = account_ux_state(
            session, api_available=api, identity_ready=identity, device=device, vpn_state=vpn
        )
        assert key == expected and title and detail
        assert tone in {"green", "amber", "red", "muted", "cyan"}

    def test_vpn_state_is_independent_of_login(self):
        """A logged-out user with an authorized device still sees the real tunnel state."""
        from app.client import account_ux_state
        key, *_ = account_ux_state(
            SessionState.LOGGED_OUT, api_available=True, identity_ready=True,
            device=None, vpn_state="CONNECTED",
        )
        assert key == "vpn_connected"


@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestAccountAwareHome:
    @pytest.fixture
    def gui(self, qapp):
        from app.ui.window import MainWindow
        window = MainWindow(TestDeviceBindingGUI.IdentityIPC(), start_polling=False)
        window._render(ClientStatus(
            state="DISCONNECTED", managed_mode=True, identity_ready=True,
            identity_fingerprint=_device_setup()["setup"]["identity_fingerprint"],
        ))
        yield window
        window.close()
        qapp.processEvents()

    def test_home_tracks_full_account_device_lifecycle(self, gui, qapp, live_account_api, tmp_path):
        url, store, _app = live_account_api
        assert gui.account_ux_key == "logged_out"
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        _sign_in_direct(gui, qapp, url)
        _wait_for(qapp, lambda: gui.account_ux_key == "no_device")
        assert gui.home_account_user.value_label.text() == "alice · alice@example.com"

        gui._on_bind_device_clicked()
        _wait_for(qapp, lambda: gui.account_ux_key == "device_pending")
        assert "Pending" in gui.home_account_device.value_label.text()

        # Administrator approves on the server; the next session check picks it up.
        from vpn.cli import main as cli
        device = store.get_device_by_fingerprint(_device_setup()["setup"]["identity_fingerprint"])
        cli(["account", "approve", str(device.id), "--accounts-db", str(store.path),
             "--database", str(tmp_path / "authorized_clients.json")])
        gui._validate_account_session()
        _wait_for(qapp, lambda: gui.account_ux_key == "approved_disconnected")

        store.set_device_enabled(device.id, False)
        gui._validate_account_session()
        _wait_for(qapp, lambda: gui.account_ux_key == "device_disabled")

        gui._on_logout_clicked()
        assert gui.account_ux_key == "logged_out"
        assert gui.home_account_user.value_label.text() == "Signed out"

    def test_unavailable_account_server_is_shown(self, gui):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._account_devices_finished(False, "connection_error", "x", 0, 0)
        assert gui.account_ux_key == "server_unavailable"

    def test_expired_session_and_vpn_states(self, gui):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._account_validate_finished(False, "invalid_session", "x", 401, 0)
        assert gui.account_ux_key == "session_expired"
        gui._render(ClientStatus(state="CONNECTED"))
        assert gui.account_ux_key == "vpn_connected"

    def test_open_account_button_switches_page(self, gui):
        gui.home_account_open_btn.click()
        assert gui.pages.currentIndex() == 3
        assert gui.page_title.text() == "Account"

    def test_account_state_never_blocks_connect(self, gui):
        gui._render(ClientStatus(state="DISCONNECTED", managed_mode=False))
        assert gui.account_ux_key == "logged_out"
        assert gui.action_btn.isEnabled()


# ─── GUI improvements: tray, live stats, stepper, logs, theme, a11y ─────────

from app.ui.components import sparkline_points, step_states  # noqa: E402
from app.ui.pages.settings import KILL_SWITCH_NOTE  # noqa: E402
from app.ui.pages.home import explain_failure  # noqa: E402
from app.ui.pages.logs import format_entries, redact_secrets  # noqa: E402
from app.ui.pages.servers import (  # noqa: E402
    format_latency, probe_tcp_latency, sort_profiles,
)
from app.ui.theme import (  # noqa: E402
    DARK, LIGHT, PALETTES, STATE_COLORS, contrast_ratio, recolor, resolve_theme,
)


class TestGUIPureHelpers:
    @pytest.mark.parametrize("error, page", [
        ("[Errno 111] Connection refused", 1),
        ("timed out", 1),
        ("[Errno -2] Name or service not known", 1),
        ("server identity fingerprint mismatch", 2),
        ("server identity substitution detected", 2),
        ("The selected server closed authentication. This device may not yet be authorized", 3),
        ("client authorization revoked", 3),
        ("Import and select a server profile", 1),
        ("Unsupported version", 6),
    ])
    def test_failure_reasons_map_to_pages(self, error, page):
        reason, target, link = explain_failure(error)
        assert target == page and link.startswith("Open ") and reason != error

    def test_unknown_failure_falls_back_to_raw(self):
        assert explain_failure("weird glitch 42") == ("weird glitch 42", None, "")

    def test_redaction_of_secret_looking_values(self):
        text = redact_secrets(
            "Authorization: Bearer abcdefghijklmnop api_key=XYZ123 session_key: s3cr3t "
            "jwt eyJhbGciOiJI.eyJzdWIiOiIx.c2lnbmF0dXJl otpauth://totp/x?secret=ABC")
        for leaked in ("abcdefghijklmnop", "XYZ123", "s3cr3t", "eyJhbGciOiJI", "secret=ABC"):
            assert leaked not in text
        assert "server fingerprint 1a2b" in redact_secrets("server fingerprint 1a2b")

    def test_format_entries_filters_level_and_search(self):
        entries = [
            {"timestamp": "t1", "level": "info", "message": "Client service started"},
            {"timestamp": "t2", "level": "warn", "message": "DNS unmanaged"},
            {"timestamp": "t3", "level": "error", "message": "Connection failed password=hunter2"},
        ]
        assert len(format_entries(entries, None, "")) == 3
        assert format_entries(entries, "WARNING", "") == ["[t2] WARNING DNS unmanaged"]
        errors = format_entries(entries, "ERROR", "")
        assert len(errors) == 1 and "hunter2" not in errors[0]
        assert len(format_entries(entries, None, "dns")) == 1

    def test_step_states(self):
        assert step_states([True, False, False]) == ["complete", "current", "pending"]
        assert step_states([True, True]) == ["complete", "complete"]
        assert step_states([False, True, False]) == ["current", "complete", "pending"]

    def test_sparkline_points_scale_into_box(self):
        assert sparkline_points([5.0], 100, 40) == []
        points = sparkline_points([10.0, 20.0, 15.0], 100, 40, pad=0)
        assert points[0] == (0, 40) and points[1] == (50, 0) and points[2] == (100, 20)
        flat = sparkline_points([3.0, 3.0], 10, 10, pad=0)
        assert all(y == 10 for _, y in flat)

    def test_sort_profiles_favourites_then_latency(self):
        profiles = [{"profile_id": pid, "name": pid} for pid in ("a", "b", "c", "d")]
        ordered = sort_profiles(profiles + ["junk"], {"a": 50.0, "b": 10.0, "c": None}, {"d"})
        assert [p["profile_id"] for p in ordered] == ["d", "b", "a", "c"]
        assert format_latency("x", {}) == "Latency not measured"
        assert "timeout" in format_latency("c", {"c": None})
        assert format_latency("b", {"b": 10.4}) == "TCP connect 10 ms"

    def test_probe_tcp_latency_is_bounded_and_validated(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            assert isinstance(probe_tcp_latency("127.0.0.1", port, timeout=1.0), float)
        finally:
            server.close()
        assert probe_tcp_latency("127.0.0.1", port, timeout=1.0) is None
        assert probe_tcp_latency("127.0.0.1", 0) is None
        assert probe_tcp_latency("127.0.0.1", True) is None
        assert probe_tcp_latency("", 51820) is None

    def test_palettes_are_consistent_and_recolor_keeps_alpha(self):
        assert DARK.keys() == LIGHT.keys()
        for palette in PALETTES.values():
            by_hex: dict[str, set[str]] = {}
            for other in PALETTES.values():
                for token, value in other.items():
                    by_hex.setdefault(value.upper(), set()).add(palette[token].upper())
            assert all(len(targets) == 1 for targets in by_hex.values())
        sheet = f"color: {DARK['green']}; border: 1px solid #55{DARK['green'][1:]}; x: #123456"
        assert recolor(sheet, LIGHT) == (
            f"color: {LIGHT['green']}; border: 1px solid #55{LIGHT['green'][1:]}; x: #123456")
        assert resolve_theme("system", True) == "light"
        assert resolve_theme("system", False) == "dark"
        assert resolve_theme("bogus", True) == "dark"

    @pytest.mark.parametrize("name", ["dark", "light"])
    def test_text_tokens_meet_wcag_aa(self, name):
        palette = PALETTES[name]
        for fg in ("text", "secondary", "muted", "green", "amber", "red", "cyan", "purple"):
            for bg in ("background", "sidebar", "surface", "card"):
                assert contrast_ratio(palette[fg], palette[bg]) >= 4.5, (name, fg, bg)
        assert contrast_ratio(palette["on_accent"], palette["green"]) >= 4.5
        assert contrast_ratio(palette["red"], palette["danger_bg"]) >= 4.5
        assert contrast_ratio(palette["amber"], palette["warn_bg"]) >= 4.5


@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestGUIImprovements:
    @pytest.fixture
    def gui(self, qapp, tmp_path):
        from PySide6.QtCore import QSettings
        from app.ui.window import MainWindow
        settings = QSettings(str(tmp_path / "gui.ini"), QSettings.IniFormat)
        window = MainWindow(TestGUIHeadless.FakeIPC(), start_polling=False, settings=settings)
        window._worker.request_action = Mock()
        yield window
        window._tray = None
        window._on_pref_changed("theme", "dark")
        window.close()
        qapp.processEvents()

    def test_failed_state_shows_reason_and_link(self, gui):
        gui._render(ClientStatus(state="FAILED", error="[Errno 111] Connection refused"))
        assert "could not be reached" in gui.error_label.text()
        assert "Connection refused" in gui.error_label.text()
        assert gui.action_btn.text() == "Retry"
        assert not gui.failure_link_btn.isHidden()
        gui.failure_link_btn.click()
        assert gui.pages.currentIndex() == 1
        gui._render(ClientStatus(state="FAILED", error="weird glitch"))
        assert gui.failure_link_btn.isHidden()
        assert gui.error_label.text() == "weird glitch"

    def test_logs_filter_copy_and_export_are_redacted(self, gui, tmp_path, qapp):
        from PySide6.QtGui import QGuiApplication
        gui._logs.render([
            {"timestamp": "t1", "level": "info", "message": "hello"},
            {"timestamp": "t2", "level": "error", "message": "boom token=abc123"},
        ], [])
        assert "abc123" not in gui.logs_view.toPlainText()
        gui.logs_level_filter.setCurrentText("Errors")
        assert "hello" not in gui.logs_view.toPlainText()
        gui.logs_level_filter.setCurrentText("All levels")
        gui.logs_search.setText("hello")
        assert gui.logs_view.toPlainText().endswith("hello")
        gui.logs_search.clear()
        gui._copy_logs()
        assert "boom" in QGuiApplication.clipboard().text()
        out = tmp_path / "events.log"
        with patch("app.ui.window.QFileDialog.getSaveFileName", return_value=(str(out), "")):
            gui._export_logs()
        exported = out.read_text()
        assert "boom" in exported and "abc123" not in exported

    def test_logs_poll_only_on_logs_page(self, gui):
        gui._worker.request_logs = Mock()
        gui._worker.request_status = Mock()
        gui._poll_status()
        gui._worker.request_logs.assert_not_called()
        gui.switch_page(5)
        gui._worker.request_logs.reset_mock()
        gui._poll_status()
        gui._worker.request_logs.assert_called_once()

    def test_security_badge_and_server_fingerprint_copy(self, gui):
        from PySide6.QtGui import QGuiApplication
        gui._render(ClientStatus(state="CONNECTED", is_quantum_safe=True,
                                 pqc_mode="native_liboqs", server_fingerprint="f" * 64))
        assert gui.sec_quantum_badge.text().startswith("QUANTUM-SAFE · ACTIVE")
        assert "native_liboqs" in gui.sec_suite.value_label.text()
        gui.sec_copy_server_fp_btn.click()
        assert QGuiApplication.clipboard().text() == "f" * 64
        gui._render(ClientStatus(state="CONNECTED", is_quantum_safe=False, pqc_mode="none"))
        assert gui.sec_quantum_badge.text().startswith("NOT QUANTUM-SAFE")

    def test_live_stats_sparkline_and_epoch(self, gui):
        for rtt in (10.0, 12.0, 11.0):
            gui._on_status(ClientStatus(state="CONNECTED", rtt_ms=rtt, epoch=3,
                                        rekey_countdown=30))
        assert list(gui.rtt_sparkline.samples) == [10.0, 12.0, 11.0]
        assert not gui.rtt_card.isHidden()
        assert "epoch 3" in gui.detail_rekey.note_label.text()
        gui._on_status(ClientStatus(state="DISCONNECTED"))
        assert not gui.rtt_sparkline.samples
        assert gui.rtt_card.isHidden()

    def test_handshake_stepper_only_while_connecting(self, gui):
        gui._render(ClientStatus(state="CONNECTING"))
        assert not gui.handshake_steps.isHidden()
        assert [m.text() for m in gui.handshake_steps.marks] == ["●"] * 3
        assert "together" in gui.handshake_note.text()
        gui._render(ClientStatus(state="CONNECTED"))
        assert gui.handshake_steps.isHidden()

    def test_onboarding_stepper_tracks_progress(self, gui):
        status = ClientStatus(state="SETUP_REQUIRED", managed_mode=True, setup_complete=False,
                              identity_ready=True, profiles=[])
        gui._render(status)
        marks = [m.text() for m in gui.onboarding_steps.marks]
        assert marks == ["✓", "●", "○", "○"]
        gui._action_finished("copy_enrollment", {"content": "public request"})
        gui._render(status)
        assert gui.onboarding_steps.marks[2].text() == "✓"

    def test_preferences_persist_and_kill_switch_is_honest(self, gui):
        gui.pref_auto_connect.setChecked(True)
        gui.pref_reduce_motion.setChecked(True)
        assert gui.settings.value("auto_connect", type=bool) is True
        assert gui.power_btn.reduce_motion
        gui._render(ClientStatus(state="CONNECTED", kill_switch_active=True))
        assert gui.kill_switch_chip.text() == "KILL SWITCH · ON"
        assert gui.settings_kill_switch.status_label.text() == "Enforced"
        gui._render(ClientStatus(state="CONNECTED", kill_switch_active=False))
        assert gui.kill_switch_chip.text() == "KILL SWITCH · NOT ARMED"
        gui._render(ClientStatus(state="BLOCKED", error="authenticated UDP dead-peer timeout", kill_switch_active=True))
        assert gui.kill_switch_chip.text() == "KILL SWITCH · BLOCKING"
        assert gui.settings_kill_switch.status_label.text() == "Blocking all traffic"
        assert gui.action_btn.text() == "Disconnect to restore network"
        for widget in (gui.kill_switch_chip, gui.settings_kill_switch.status_label, gui.action_btn):
            assert "not enforced" not in widget.text().lower()
        assert "not install" not in KILL_SWITCH_NOTE and "until you disconnect" in KILL_SWITCH_NOTE

    def test_auto_connect_runs_once_at_startup(self, gui):
        gui.prefs["auto_connect"] = True
        gui._auto_connect_pending = True
        gui._on_status(ClientStatus(state="DISCONNECTED"))
        gui._busy = False
        gui._on_status(ClientStatus(state="DISCONNECTED"))
        gui._worker.request_action.assert_called_once_with("connect")

    def test_server_latency_and_favourites(self, gui, qapp):
        profiles = [
            {"profile_id": "slow", "name": "Slow", "server_host": "192.0.2.1",
             "server_control_port": 51820},
            {"profile_id": "fast", "name": "Fast", "server_host": "192.0.2.2",
             "server_control_port": 51820},
        ]
        gui._render(ClientStatus(state="DISCONNECTED", managed_mode=True, profiles=profiles))
        gui._servers.latency_probe._probe = lambda host, port: 5.0 if host.endswith(".2") else 80.0
        gui.server_latency_btn.click()
        _wait_for(qapp, lambda: not gui._servers.latency_probe.running
                  and gui.server_latency_btn.text() == "Measure latency")
        assert gui._servers.latencies == {"slow": 80.0, "fast": 5.0}
        order = [p["profile_id"] for p in sort_profiles(profiles, gui._servers.latencies,
                                                        gui._servers.favourites)]
        assert order == ["fast", "slow"]
        gui._servers.toggle_favourite("slow")
        assert json.loads(gui.settings.value("favourites")) == ["slow"]

    def test_close_hides_to_tray_until_quit(self, gui):
        gui._tray = Mock()
        gui._tray_toggle_action = Mock()
        gui._tray_show_action = Mock()
        gui.show()
        assert gui.hides_to_tray()
        gui.close()
        assert not gui.isVisible() and gui._worker._thread.is_alive()
        gui.prefs["close_to_tray"] = False
        assert not gui.hides_to_tray()
        gui.prefs["close_to_tray"] = True
        gui._quitting = True
        assert not gui.hides_to_tray()

    def test_ctrl_k_toggles_connection(self, gui):
        gui._render(ClientStatus(state="DISCONNECTED"))
        assert gui._toggle_shortcut.key().toString() == "Ctrl+K"
        gui._toggle_shortcut.activated.emit()
        gui._worker.request_action.assert_called_once_with("connect")

    def test_motion_is_disabled_offscreen(self, gui):
        assert gui.power_btn.reduce_motion
        gui._render(ClientStatus(state="CONNECTING"))
        assert not gui.power_btn._animation.isActive()
        assert gui.connection_progress.isHidden()

    def test_light_theme_recolors_live_widgets(self, gui):
        gui._on_pref_changed("theme", "light")
        assert STATE_COLORS["CONNECTED"] == LIGHT["green"]
        assert LIGHT["text"] in gui.page_title.styleSheet()
        assert DARK["text"] not in gui.page_title.styleSheet()
        gui._on_pref_changed("theme", "dark")
        assert DARK["text"] in gui.page_title.styleSheet()


# ─── Sign-out means no VPN ────────────────────────────────────────────────

@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestSignOutGatesVPN:
    """Rule: when the GUI holds an account client, VPN connect needs a live account session."""

    FP = _device_setup()["setup"]["identity_fingerprint"]

    @pytest.fixture
    def gui(self, qapp, tmp_path):
        from PySide6.QtCore import QSettings
        from app.ui.window import MainWindow
        settings = QSettings(str(tmp_path / "gui.ini"), QSettings.IniFormat)
        window = MainWindow(TestDeviceBindingGUI.IdentityIPC(), start_polling=False,
                            settings=settings)
        window._account_client = AccountClient("http://127.0.0.1:1")
        window._worker.request_action = Mock()
        window._render(ClientStatus(state="DISCONNECTED", identity_fingerprint=self.FP))
        yield window
        window.close()
        qapp.processEvents()

    def _entry_points(self, gui, monkeypatch):
        """Button, tray, Ctrl+K and auto-connect: every way a connect can start."""
        from PySide6.QtWidgets import QSystemTrayIcon
        monkeypatch.setattr(QSystemTrayIcon, "isSystemTrayAvailable", staticmethod(lambda: True))
        gui._tray = gui._create_tray()
        from PySide6.QtWidgets import QApplication
        QApplication.instance().setQuitOnLastWindowClosed(True)
        gui.prefs["auto_connect"] = True

        def auto_connect():
            gui._auto_connect_pending = True
            gui._on_status(ClientStatus(state="DISCONNECTED", identity_fingerprint=self.FP))

        try:
            return [gui._on_toggle, gui._tray_toggle_action.trigger,
                    gui._toggle_shortcut.activated.emit, auto_connect]
        finally:
            gui._tray.hide()

    def _ready(self, gui):
        """Fresh DISCONNECTED state; the tray action is forced on so only the gate can refuse."""
        gui._busy = False
        gui._render(ClientStatus(state="DISCONNECTED", identity_fingerprint=self.FP))
        gui._tray_toggle_action.setEnabled(True)

    def test_every_connect_entry_point_refused_when_signed_out(self, gui, monkeypatch):
        for start in self._entry_points(gui, monkeypatch):
            self._ready(gui)
            start()
        gui._worker.request_action.assert_not_called()
        assert not gui.action_btn.isEnabled() and gui.action_btn.text() == "Sign in to connect"
        assert "Signed out" in gui.subtitle_label.text()
        assert any("Connect refused" in e["message"] for e in gui._gui_events)

    def test_every_connect_entry_point_allowed_when_signed_in(self, gui, monkeypatch):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._render(ClientStatus(state="DISCONNECTED", identity_fingerprint=self.FP))
        assert gui.action_btn.isEnabled() and gui.action_btn.text() == "Connect"
        starts = self._entry_points(gui, monkeypatch)
        for start in starts:
            self._ready(gui)
            start()
        assert gui._worker.request_action.call_count == len(starts)
        assert {c.args for c in gui._worker.request_action.call_args_list} == {("connect",)}

    def test_gui_without_account_client_is_not_gated(self, gui):
        gui._account_client = None  # legacy: no account API session got the user in
        gui._on_toggle()
        gui._worker.request_action.assert_called_once_with("connect")

    def test_disconnect_is_never_gated(self, gui):
        gui._render(ClientStatus(state="CONNECTED", identity_fingerprint=self.FP))
        gui._on_toggle()
        gui._worker.request_action.assert_called_once_with("disconnect")

    def test_sign_out_disconnects_first_then_suspends_device(
            self, gui, qapp, live_account_api, tmp_path):
        import base64
        from vpn.cli import main as cli
        from vpn.identity import AuthorizedClients
        url, store, _app = live_account_api
        authorized = AuthorizedClients(tmp_path / "authorized" / "authorized_clients.json")
        setup = _device_setup()["setup"]
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        _sign_in_direct(gui, qapp, url)
        gui._account_client.bind_device(gui._account_session.get_token(), "laptop",
                                        setup["identity_public_key"], self.FP)
        cli(["account", "approve", str(store.get_device_by_fingerprint(self.FP).id),
             "--accounts-db", str(store.path), "--database", str(authorized.path)])
        public = base64.b64decode(setup["identity_public_key"])
        assert authorized.find(public) is not None
        emitted: list[str] = []
        gui.signed_out.connect(emitted.append)
        gui._render(ClientStatus(state="CONNECTED", identity_fingerprint=self.FP))

        gui._on_logout_clicked()
        gui._worker.request_action.assert_called_once_with("disconnect")
        assert authorized.find(public) is not None  # nothing revoked before the tunnel is down
        gui._on_toggle()  # a connect attempt mid sign-out is refused
        gui._worker.request_action.assert_called_once_with("disconnect")

        gui._render(ClientStatus(state="DISCONNECTED", identity_fingerprint=self.FP))
        gui._action_finished("disconnect", {"status": "disconnected"})
        assert gui._account_session.state == SessionState.LOGGED_OUT
        _wait_for(qapp, lambda: emitted == [""])
        assert authorized.find(public) is None
        assert store.get_device_by_fingerprint(self.FP).status == "approved"

    def test_forced_expiry_disconnects_first(self, gui):
        emitted: list[str] = []
        gui.signed_out.connect(emitted.append)
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._render(ClientStatus(state="CONNECTED", identity_fingerprint=self.FP))
        gui._account_validate_finished(False, "invalid_session", "x", 401, 0)
        gui._worker.request_action.assert_called_once_with("disconnect")
        assert gui._account_session.is_authenticated and emitted == []
        gui._action_finished("disconnect", {"error": "service unreachable"})
        assert gui._account_session.state == SessionState.SESSION_EXPIRED
        assert emitted and "expired" in emitted[0]

    def test_unconfirmed_server_sign_out_is_reported(self, gui, qapp):
        emitted: list[str] = []
        gui.signed_out.connect(emitted.append)
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._on_logout_clicked()
        assert gui._account_session.get_token() is None
        _wait_for(qapp, lambda: emitted)
        assert "may still have VPN access" in emitted[0]

    def test_shutdown_stops_background_work_and_hides(self, gui):
        gui.show()
        gui.shutdown()
        assert not gui.isVisible() and not gui._timer.isActive()
        gui._worker._thread.join(2)
        assert not gui._worker._thread.is_alive()

    def test_sign_in_restores_signed_out_device(self, qapp, live_account_api, tmp_path):
        import base64
        from app.ui.window import MainWindow
        from vpn.cli import main as cli
        from vpn.identity import AuthorizedClients
        url, store, _app = live_account_api
        authorized = AuthorizedClients(tmp_path / "authorized" / "authorized_clients.json")
        setup = _device_setup()["setup"]
        public = base64.b64decode(setup["identity_public_key"])
        client = AccountClient(url)
        client.register("alice", "alice@example.com", ACCOUNT_PASSWORD, _invite(store))
        token, _user, _ = client.login("alice", ACCOUNT_PASSWORD)
        client.bind_device(token, "laptop", setup["identity_public_key"], self.FP)
        cli(["account", "approve", str(store.get_device_by_fingerprint(self.FP).id),
             "--accounts-db", str(store.path), "--database", str(authorized.path)])
        client.logout(token, self.FP)
        assert authorized.find(public) is None

        token, _user, expires = client.login("alice", ACCOUNT_PASSWORD)
        window = MainWindow(TestDeviceBindingGUI.IdentityIPC(), start_polling=False,
                            account_client=client, session_token=token,
                            session_user=client.get_me(token), session_expires_at=expires)
        try:
            _wait_for(qapp, lambda: authorized.find(public) is not None)
            _wait_for(qapp, lambda: window._account_devices)
        finally:
            window.close()
            qapp.processEvents()


@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
def test_login_window_shows_sign_out_message(qapp):
    from app.ui.login import LoginWindow
    login = LoginWindow()
    try:
        login.show_signed_out("server did not confirm")
        assert login.isVisible() and login.login_error.text() == "server did not confirm"
        assert login.stack.currentIndex() == 0
    finally:
        login.close()
        qapp.processEvents()
