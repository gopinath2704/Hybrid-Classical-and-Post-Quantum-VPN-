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


# ─── Malformed IPC request tests ──────────────────────────────────────────

class TestMalformedIPC:
    def test_invalid_json_handled(self, tmp_path):
        """Non-JSON data after a valid length header does not crash the service."""
        config = tmp_path / "client.toml"
        config.write_text("[client]\n")
        service = ClientService(str(config))

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

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            ipc_send(a, {"not_a_command": True})
            service._handle_connection(b)
            result = ipc_recv(a, timeout=2.0)
            assert "error" in result
        finally:
            a.close()


# ─── IPCClient connection error tests ─────────────────────────────────────

class TestIPCClient:
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
def qapp():
    if not _pyside6_available():
        pytest.skip("PySide6 not installed")
    from PySide6.QtWidgets import QApplication
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
        from app.client import MainWindow
        fake = self.FakeIPC()
        result = MainWindow(fake, start_polling=False)
        yield result, fake
        result.close()
        qapp.processEvents()

    def test_import_succeeds(self):
        """The client module imports without errors."""
        import app.client
        assert hasattr(app.client, "MainWindow")

    def test_home_constructs_at_target_size(self, window):
        gui, _ = window
        assert gui.pages.count() == 6
        assert gui.width() == 1180 and gui.height() == 760
        assert gui.minimumWidth() == 980 and gui.minimumHeight() == 650

    def test_all_connection_states_render_safely(self, window):
        gui, _ = window
        for state in ConnectionState:
            gui._render(ClientStatus(state=state.value))
            assert gui.state_label.text() == state.value.replace("_", " ")

    def test_navigation_switches_without_vpn_actions(self, window):
        gui, fake = window
        for index, name in enumerate(("Home", "Servers", "Security", "Settings", "Logs", "About")):
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
