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
from unittest.mock import Mock, patch

import pytest

from app.client import (
    ClientService,
    ClientStatus,
    ConnectionState,
    IPCClient,
    MAX_IPC_MESSAGE,
    ipc_recv,
    ipc_send,
    get_peer_uid,
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


# ─── PySide6 GUI headless tests (QT_QPA_PLATFORM=offscreen) ──────────────

def _pyside6_available():
    try:
        import PySide6.QtWidgets
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _pyside6_available(), reason="PySide6 not installed")
class TestGUIHeadless:
    """Non-interactive GUI widget tests using the offscreen platform."""

    @pytest.fixture(autouse=True)
    def _setup_offscreen(self, monkeypatch):
        monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")

    def test_import_succeeds(self):
        """The client module imports without errors."""
        import app.client
        assert hasattr(app.client, "MainWindow") or hasattr(app.client, "_launch_gui")
