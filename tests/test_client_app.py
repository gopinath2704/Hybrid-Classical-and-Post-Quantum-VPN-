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
    AccountAPIError,
    AccountClient,
    AccountSession,
    SessionState,
    UserProfile,
    _sanitized_message,
)

ACCOUNT_PASSWORD = "correct horse battery staple"


@pytest.fixture
def live_account_api(tmp_path):
    """Run the real pqvpn-account-api app on loopback for client integration tests."""
    import uvicorn
    from vpn.account_api import AccountAPIConfig, create_app
    from vpn.accounts import AccountStore

    store = AccountStore(tmp_path / "accounts" / "accounts.db")
    app = create_app(
        AccountAPIConfig(database_path=store.path, allow_insecure_loopback=True), store=store
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
        url, _store, _app = live_account_api
        client = AccountClient(url)
        user = client.register("Alice", "Alice@Example.com", ACCOUNT_PASSWORD)
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
        url, _store, _app = live_account_api
        client = AccountClient(url)
        client.register("bob", "bob@example.com", ACCOUNT_PASSWORD)
        token, user, _ = client.login("BOB@example.com", ACCOUNT_PASSWORD)
        assert user["username"] == "bob" and token

    def test_failures_are_indistinguishable(self, live_account_api):
        url, store, _app = live_account_api
        client = AccountClient(url)
        created = client.register("carol", "carol@example.com", ACCOUNT_PASSWORD)
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
        created = client.register("dave", "dave@example.com", ACCOUNT_PASSWORD)
        token, _, _ = client.login("dave", ACCOUNT_PASSWORD)
        store.set_user_enabled(created["id"], False)
        with pytest.raises(AccountAPIError) as exc_info:
            client.get_me(token)
        assert exc_info.value.status_code == 401

    def test_login_rate_limit_reports_retry_after(self, live_account_api):
        url, _store, _app = live_account_api
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
        url, _store, _app = live_account_api
        client = AccountClient(url)
        for index in range(3):
            client.register(f"user{index}", f"user{index}@example.com", ACCOUNT_PASSWORD)
        with pytest.raises(AccountAPIError) as exc_info:
            client.register("user9", "user9@example.com", ACCOUNT_PASSWORD)
        assert exc_info.value.code == "rate_limited"

    @pytest.mark.parametrize("username,email,password,code", [
        ("frank", "frank@example.com", "short", "invalid_registration"),
        ("frank", "frank@example.com", "x" * 1025, "invalid_registration"),
        ("bad name!", "frank@example.com", ACCOUNT_PASSWORD, "invalid_registration"),
        ("frank", "not-an-email", ACCOUNT_PASSWORD, "invalid_registration"),
    ], ids=["short-password", "long-password", "invalid-username", "invalid-email"])
    def test_invalid_registration(self, live_account_api, username, email, password, code):
        url, _store, _app = live_account_api
        with pytest.raises(AccountAPIError) as exc_info:
            AccountClient(url).register(username, email, password)
        assert exc_info.value.code == code
        assert password not in exc_info.value.message

    def test_duplicate_username_and_email(self, live_account_api):
        url, _store, _app = live_account_api
        client = AccountClient(url)
        client.register("gina", "gina@example.com", ACCOUNT_PASSWORD)
        for username, email in (("gina", "other@example.com"), ("other", "gina@example.com")):
            with pytest.raises(AccountAPIError) as exc_info:
                client.register(username, email, ACCOUNT_PASSWORD)
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


@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestAccountGUI:
    @pytest.fixture
    def gui(self, qapp):
        from app.client import MainWindow
        window = MainWindow(TestGUIHeadless.FakeIPC(), start_polling=False)
        yield window
        window.close()
        qapp.processEvents()

    @staticmethod
    def wait_for(qapp, predicate, timeout=15.0):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            qapp.processEvents()
            time.sleep(0.01)
        qapp.processEvents()
        assert predicate()

    def sign_in(self, gui, qapp, url, identifier="alice"):
        gui.account_api_url.setText(url)
        gui.login_identifier.setText(identifier)
        gui.login_password.setText(ACCOUNT_PASSWORD)
        gui._on_login_clicked()
        self.wait_for(qapp, lambda: gui.login_btn.text() == "Sign In")

    def test_login_logout_flow_keeps_token_out_of_ui(self, gui, qapp, live_account_api, caplog):
        from PySide6.QtWidgets import QLabel, QLineEdit
        url, store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD)
        caplog.set_level("DEBUG")
        self.sign_in(gui, qapp, url, "alice@example.com")
        assert gui._account_session.is_authenticated
        assert gui.account_stack.currentIndex() == 2
        assert gui.profile_username.text() == "@alice"
        assert gui.login_password.text() == ""
        token = gui._account_session.get_token()
        widgets_text = " ".join(
            w.text() for w in gui.findChildren(QLabel) + gui.findChildren(QLineEdit)
        )
        assert token not in widgets_text
        assert token not in caplog.text and ACCOUNT_PASSWORD not in caplog.text

        gui._on_logout_clicked()
        assert gui._account_session.get_token() is None
        assert gui.account_stack.currentIndex() == 0
        token_hash = __import__("hashlib").sha256(token.encode()).digest()
        self.wait_for(qapp, lambda: store.get_session_by_token_hash(token_hash).revoked_at)

    def test_login_failure_is_sanitized(self, gui, qapp, live_account_api):
        url, _store, _app = live_account_api
        self.sign_in(gui, qapp, url, "nobody")
        assert not gui._account_session.is_authenticated
        assert gui.login_error.text() == "Invalid username/email or password."

    def test_logout_clears_locally_when_api_unavailable(self, gui):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._account_client = AccountClient("http://127.0.0.1:1")
        gui._on_logout_clicked()
        assert gui._account_session.get_token() is None
        assert gui._account_session.state == SessionState.LOGGED_OUT

    def test_revoked_session_returns_to_login(self, gui, qapp, live_account_api):
        url, _store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD)
        self.sign_in(gui, qapp, url)
        AccountClient(url).logout(gui._account_session.get_token())
        gui._validate_account_session()
        self.wait_for(qapp, lambda: gui._account_session.state == SessionState.SESSION_EXPIRED)
        assert gui.account_stack.currentIndex() == 0
        assert "expired" in gui.login_error.text()

    def test_api_unavailable_keeps_session_and_warns(self, gui):
        gui._account_session.set_session("tok", TestAccountSession.USER, "")
        gui._account_validate_finished(False, "connection_error", "x", 0, 0)
        assert gui._account_session.is_authenticated
        assert "UNAVAILABLE" in gui.profile_session_badge.text()

    def test_cleartext_remote_url_is_refused_inline(self, gui):
        gui.account_api_url.setText("http://203.0.113.5:8443")
        gui.login_identifier.setText("alice")
        gui.login_password.setText(ACCOUNT_PASSWORD)
        gui._on_login_clicked()
        assert "loopback" in gui.login_error.text()
        assert gui.login_btn.isEnabled()

    def test_register_client_validation(self, gui):
        gui.register_username.setText("alice")
        gui.register_email.setText("alice@example.com")
        gui.register_password.setText("short")
        gui.register_confirm.setText("short")
        gui._on_register_clicked()
        assert "12" in gui.register_error.text()
        gui.register_password.setText(ACCOUNT_PASSWORD)
        gui.register_confirm.setText(ACCOUNT_PASSWORD + "x")
        gui._on_register_clicked()
        assert "match" in gui.register_error.text()

    def test_login_never_touches_authorized_clients(self, gui, qapp, live_account_api, tmp_path):
        url, _store, _app = live_account_api
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD)
        self.sign_in(gui, qapp, url)
        assert gui._account_session.is_authenticated
        assert not list(tmp_path.rglob("authorized_clients.json"))


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
        from app.client import MainWindow
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
        AccountClient(url).register("alice", "alice@example.com", ACCOUNT_PASSWORD)
        TestAccountGUI().sign_in(gui, qapp, url)
        TestAccountGUI.wait_for(qapp, lambda: gui.device_bind_btn.isEnabled())
        assert gui.device_binding_row.value_label.text() == "Not registered"
        gui.device_name_input.setText("work laptop")
        gui._on_bind_device_clicked()
        TestAccountGUI.wait_for(qapp, lambda: gui._current_account_device() is not None)
        assert gui.device_binding_row.value_label.text() == "Registered as work laptop"
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
        TestAccountGUI.wait_for(qapp, lambda: gui.device_error.isVisible() or not gui.device_error.isHidden())
        assert "identity" in gui.device_error.text().lower()
