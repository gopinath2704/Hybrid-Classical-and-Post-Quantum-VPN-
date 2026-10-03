"""Milestone 3 provisioning, profile, identity, enrollment, CLI, and IPC tests."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.client import (
    ClientService, ConnectionState, MAX_IPC_MESSAGE, ipc_recv, ipc_send,
)
from vpn import cli
from vpn.identity import (
    AuthorizedClients,
    EnrollmentError,
    EnrollmentRequest,
    MAX_ENROLLMENT_SIZE,
    MAX_PROFILE_SIZE,
    MAX_PROFILES,
    ProfileError,
    ProfileStore,
    ServerProfile,
    client_public_identity,
    ensure_client_identity,
    fingerprint,
    load_enrollment,
    parse_enrollment,
    parse_profile,
    write_enrollment,
)


@pytest.fixture
def server_public_key():
    return bytes(index % 251 for index in range(1184))


@pytest.fixture
def profile_value(server_public_key):
    return {
        "version": 1,
        "profile_id": "ubuntu-lab",
        "name": "Ubuntu Lab Server",
        "server_host": "192.168.8.43",
        "server_control_port": 51820,
        "server_identity_public_key": base64.b64encode(server_public_key).decode(),
        "server_identity_fingerprint": fingerprint(server_public_key),
        "expected_vpn_subnet": "10.8.0.0/24",
    }


@pytest.fixture
def profile_json(profile_value):
    return json.dumps(profile_value)


def test_valid_profile_parses_and_serializes_deterministically(profile_json):
    profile = parse_profile(profile_json)
    assert profile.profile_id == "ubuntu-lab"
    assert parse_profile(profile.to_json()) == profile
    assert profile.to_json() == profile.to_json()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("version", 2, "version"),
        ("server_identity_public_key", "%%%", "Base64"),
        ("server_identity_public_key", base64.b64encode(b"short").decode(), "1184"),
        ("server_identity_fingerprint", "0" * 64, "fingerprint"),
        ("server_control_port", 0, "1..65535"),
        ("server_control_port", 65536, "1..65535"),
        ("server_control_port", True, "1..65535"),
        ("expected_vpn_subnet", "10.8.0.3/24", "canonical"),
        ("expected_vpn_subnet", "2001:db8::/64", "IPv4"),
        ("profile_id", "../escape", "profile_id"),
        ("profile_id", "a..b", "profile_id"),
        ("server_host", "https://vpn.example", "URL"),
        ("server_host", "bad host", "hostname"),
        ("server_host", "2001:db8::1", "hostname"),
    ],
)
def test_invalid_profile_fields_rejected(profile_value, field, value, message):
    profile_value[field] = value
    with pytest.raises(ProfileError, match=message):
        ServerProfile.validate(profile_value)


def test_malformed_and_oversized_profiles_rejected():
    with pytest.raises(ProfileError, match="malformed"):
        parse_profile("{")
    with pytest.raises(ProfileError, match="bounds"):
        parse_profile("x" * (MAX_PROFILE_SIZE + 1))


def test_duplicate_json_profile_property_rejected(profile_value):
    content = json.dumps(profile_value)[:-1] + ', "version": 1}'
    with pytest.raises(ProfileError, match="duplicate JSON property"):
        parse_profile(content)


@pytest.mark.parametrize("secret", ["client_private_key", "password", "token", "command"])
def test_profile_rejects_secret_or_executable_fields(profile_value, secret):
    profile_value[secret] = "not-accepted"
    with pytest.raises(ProfileError, match="exactly"):
        ServerProfile.validate(profile_value)


def test_profile_store_import_list_select_remove_and_permissions(tmp_path, profile_json):
    store = ProfileStore(tmp_path / "profiles")
    profile = parse_profile(profile_json)
    store.import_profile(profile)
    assert [item.profile_id for item in store.list()] == ["ubuntu-lab"]
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.key_path(profile.profile_id).stat().st_mode) == 0o644
    assert store.key_path(profile.profile_id).read_bytes() == profile.public_key_bytes
    store.select(profile.profile_id)
    assert store.active().name == "Ubuntu Lab Server"
    store.remove(profile.profile_id)
    assert store.list() == []
    assert store.active_id() is None


def test_profile_store_duplicate_requires_explicit_replace(tmp_path, profile_value):
    store = ProfileStore(tmp_path / "profiles")
    original = ServerProfile.validate(profile_value)
    store.import_profile(original)
    profile_value["name"] = "Replacement"
    replacement = ServerProfile.validate(profile_value)
    with pytest.raises(ProfileError, match="explicit replace"):
        store.import_profile(replacement)
    store.import_profile(replacement, replace=True)
    assert store.get("ubuntu-lab").name == "Replacement"


def test_profile_store_corruption_and_exact_deletion(tmp_path, profile_json):
    store = ProfileStore(tmp_path / "profiles")
    store.import_profile(parse_profile(profile_json))
    with pytest.raises(ProfileError, match="not found"):
        store.remove("ubuntu")
    store.path.write_text("{broken")
    with pytest.raises(ProfileError, match="malformed"):
        store.list()


def test_profile_store_rejects_symlink_state(tmp_path, profile_json):
    target = tmp_path / "target.json"
    target.write_text("sentinel")
    store = ProfileStore(tmp_path / "profiles")
    store.root.mkdir()
    store.path.symlink_to(target)
    with pytest.raises(ProfileError, match="unable to read"):
        store.import_profile(parse_profile(profile_json))
    assert target.read_text() == "sentinel"


def test_profile_store_bound_keeps_ipc_responses_small(tmp_path, profile_value):
    store = ProfileStore(tmp_path / "profiles")
    for index in range(MAX_PROFILES):
        value = dict(profile_value, profile_id=f"server-{index}", name=f"Server {index}")
        store.import_profile(ServerProfile.validate(value))
    value = dict(profile_value, profile_id="one-too-many", name="Overflow")
    with pytest.raises(ProfileError, match="at most"):
        store.import_profile(ServerProfile.validate(value))


def test_first_identity_ensure_is_idempotent_and_private(tmp_path):
    private = tmp_path / "identity" / "client.key"
    public = tmp_path / "identity" / "client.pub"
    first = ensure_client_identity(private, public)
    private_bytes = private.read_bytes()
    private_mtime = private.stat().st_mtime_ns
    second = ensure_client_identity(private, public)
    assert second == first == fingerprint(public.read_bytes())
    assert private.read_bytes() == private_bytes
    assert private.stat().st_mtime_ns == private_mtime
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(public.stat().st_mode) == 0o644


def test_identity_repairs_public_without_rotating_private(tmp_path):
    private, public = tmp_path / "id" / "private", tmp_path / "id" / "public"
    expected = ensure_client_identity(private, public)
    secret = private.read_bytes()
    public.unlink()
    assert ensure_client_identity(private, public) == expected
    assert private.read_bytes() == secret


def test_identity_rejects_mismatch_partial_and_symlink(tmp_path):
    private, public = tmp_path / "id" / "private", tmp_path / "id" / "public"
    ensure_client_identity(private, public)
    public.write_bytes(b"x" * 32)
    with pytest.raises(ValueError, match="does not match"):
        ensure_client_identity(private, public)
    private.unlink()
    with pytest.raises(ValueError, match="incomplete"):
        ensure_client_identity(private, public)
    public.unlink()
    target = tmp_path / "target"
    target.write_bytes(b"x" * 32)
    os.chmod(target, 0o600)
    private.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        ensure_client_identity(private, public)


def test_enrollment_roundtrip_is_public_only(tmp_path):
    private, public = tmp_path / "id" / "private", tmp_path / "id" / "public"
    ensure_client_identity(private, public)
    public_bytes, expected = client_public_identity(private, public)
    request = EnrollmentRequest.create("shadow-laptop", public_bytes)
    serialized = request.to_json()
    assert "private" not in serialized.lower()
    assert parse_enrollment(serialized) == request
    assert request.client_fingerprint == expected


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(version=2),
        lambda value: value.update(client_id="../bad"),
        lambda value: value.update(client_public_key="%%%"),
        lambda value: value.update(client_public_key=base64.b64encode(b"short").decode()),
        lambda value: value.update(client_fingerprint="0" * 64),
        lambda value: value.update(created_at="not-a-time"),
        lambda value: value.update(private_key="forbidden"),
    ],
)
def test_malformed_enrollment_fields_rejected(mutation):
    request = EnrollmentRequest.create("client-1", b"c" * 32).to_dict()
    mutation(request)
    with pytest.raises(EnrollmentError):
        EnrollmentRequest.validate(request)


def test_enrollment_size_duplicate_key_and_output_symlink_rejected(tmp_path):
    request = EnrollmentRequest.create("client-1", b"c" * 32)
    with pytest.raises(EnrollmentError, match="bounds"):
        parse_enrollment("x" * (MAX_ENROLLMENT_SIZE + 1))
    duplicate = request.to_json().rstrip()[:-1] + ', "version": 1}'
    with pytest.raises(EnrollmentError, match="duplicate"):
        parse_enrollment(duplicate)
    target = tmp_path / "target"
    target.write_text("sentinel")
    output = tmp_path / "request.pqenroll"
    output.symlink_to(target)
    with pytest.raises(EnrollmentError, match="symlink"):
        write_enrollment(output, request)
    assert target.read_text() == "sentinel"


def test_enrollment_cli_generation_and_server_authorization(tmp_path, capsys):
    private, public = tmp_path / "id" / "private", tmp_path / "id" / "public"
    ensure_client_identity(private, public)
    request_path = tmp_path / "shadow-laptop.pqenroll"
    cli.main([
        "client", "enrollment-request", "--output", str(request_path),
        "--client-id", "shadow-laptop", "--public-key", str(public),
    ])
    request = load_enrollment(request_path)
    assert "Enrollment request created" in capsys.readouterr().out
    database = tmp_path / "authorized_clients.json"
    cli.main([
        "client", "authorize-request", str(request_path),
        "--database", str(database), "--vpn-ip", "10.8.0.9",
    ])
    output = capsys.readouterr().out
    assert "Client authorized" in output
    assert "Assigned VPN IP: 10.8.0.9" in output
    record = AuthorizedClients(database)._load()["clients"][0]
    assert record["client_id"] == "shadow-laptop"
    assert record["fingerprint"] == request.client_fingerprint

    # Existing authorize semantics replace the same fingerprint rather than duplicate it.
    cli.main([
        "client", "authorize-request", str(request_path), "--database", str(database),
    ])
    assert len(AuthorizedClients(database)._load()["clients"]) == 1


def test_authorize_request_preserves_assigned_ip_validation(tmp_path):
    request = EnrollmentRequest.create("client-1", b"c" * 32)
    path = tmp_path / "client.pqenroll"
    write_enrollment(path, request)
    with pytest.raises(ValueError):
        cli.main([
            "client", "authorize-request", str(path),
            "--database", str(tmp_path / "clients.json"), "--vpn-ip", "not-an-ip",
        ])


def test_managed_service_setup_and_narrow_ipc(tmp_path, profile_json):
    service = ClientService(None, state_dir=tmp_path / "state")
    initial = service._dispatch({"command": "SETUP_STATUS"})["setup"]
    assert initial["identity_ready"] is True
    assert initial["setup_complete"] is False
    assert "private" not in json.dumps(initial).lower()
    imported = service._dispatch({
        "command": "IMPORT_PROFILE", "profile": profile_json, "replace": False,
    })
    assert imported["profile"]["profile_id"] == "ubuntu-lab"
    listed = service._dispatch({"command": "LIST_PROFILES"})
    assert len(listed["profiles"]) == 1 and listed["active_profile_id"] is None
    service._dispatch({"command": "SELECT_PROFILE", "profile_id": "ubuntu-lab"})
    status = service._get_status()
    assert status.state == ConnectionState.DISCONNECTED.value
    assert status.setup_complete and status.active_profile_name == "Ubuntu Lab Server"
    assert status.server_host == "192.168.8.43"
    assert status.identity_fingerprint
    assert "private" not in status.to_json().lower()


def test_managed_service_export_is_public_and_identity_is_stable(tmp_path):
    service = ClientService(None, state_dir=tmp_path / "state")
    before = service.client_private_path.read_bytes()
    response = service._dispatch({
        "command": "EXPORT_ENROLLMENT_REQUEST", "client_id": "shadow-laptop",
    })
    request = parse_enrollment(response["content"])
    assert request.client_fingerprint == service._identity_fingerprint
    assert "private" not in response["content"].lower()
    service._dispatch({"command": "ENSURE_IDENTITY"})
    assert service.client_private_path.read_bytes() == before


def test_maximum_profile_status_fits_unchanged_ipc_limit(tmp_path, profile_value):
    service = ClientService(None, state_dir=tmp_path / "state")
    for index in range(MAX_PROFILES):
        value = dict(profile_value, profile_id=f"server-{index}", name=f"Server {index}")
        service._dispatch({
            "command": "IMPORT_PROFILE", "profile": json.dumps(value), "replace": False,
        })
    response = service._dispatch({"command": "STATUS"})
    assert len(json.dumps(response).encode("utf-8")) <= MAX_IPC_MESSAGE


def test_deleting_active_profile_returns_to_setup_required(tmp_path, profile_json):
    service = ClientService(None, state_dir=tmp_path / "state")
    service._dispatch({"command": "IMPORT_PROFILE", "profile": profile_json})
    service._dispatch({"command": "SELECT_PROFILE", "profile_id": "ubuntu-lab"})
    service._dispatch({"command": "DELETE_PROFILE", "profile_id": "ubuntu-lab"})
    status = service._get_status()
    assert status.state == ConnectionState.SETUP_REQUIRED.value
    assert status.active_profile_id is None


def test_managed_authentication_close_has_clear_non_claiming_message(
    tmp_path, profile_json, monkeypatch
):
    service = ClientService(None, state_dir=tmp_path / "state")
    service._dispatch({"command": "IMPORT_PROFILE", "profile": profile_json})
    service._dispatch({"command": "SELECT_PROFILE", "profile_id": "ubuntu-lab"})

    class RejectedClient:
        state = "CONNECTING"

        def __init__(self, cfg):
            self.cfg = cfg

        def connect(self):
            raise ConnectionError("connection closed")

    monkeypatch.setattr("vpn.runtime.VPNClient", RejectedClient)
    result = service._do_connect()
    assert "may not yet be authorized" in result["error"]
    assert "authorized" in service._get_status().error


def test_profile_mutations_refused_while_connected(tmp_path, profile_json):
    service = ClientService(None, state_dir=tmp_path / "state")
    service._dispatch({"command": "IMPORT_PROFILE", "profile": profile_json})
    service._vpn = SimpleNamespace(state="CONNECTED")
    with pytest.raises(ValueError, match="disconnect"):
        service._dispatch({"command": "SELECT_PROFILE", "profile_id": "ubuntu-lab"})
    with pytest.raises(ValueError, match="disconnect"):
        service._dispatch({"command": "DELETE_PROFILE", "profile_id": "ubuntu-lab"})


def test_ipc_rejects_unknown_fields_and_generic_file_writes(tmp_path):
    service = ClientService(None, state_dir=tmp_path / "state")
    with pytest.raises(ValueError, match="unknown fields"):
        service._dispatch({"command": "STATUS", "path": "/etc/shadow"})
    with pytest.raises(ValueError, match="unknown command"):
        service._dispatch({"command": "WRITE_FILE", "path": "/tmp/x", "data": "x"})


def test_public_enrollment_roundtrip_over_real_ipc_frame(tmp_path):
    service = ClientService(None, state_dir=tmp_path / "state")
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        ipc_send(client, {
            "command": "EXPORT_ENROLLMENT_REQUEST", "client_id": "shadow-laptop",
        })
        service._handle_connection(server)
        response = ipc_recv(client, timeout=2)
    finally:
        client.close()
    assert parse_enrollment(response["content"]).client_id == "shadow-laptop"
    assert "private" not in json.dumps(response).lower()
    assert len(json.dumps(response).encode()) <= MAX_IPC_MESSAGE


def test_explicit_config_mode_remains_unambiguous(tmp_path):
    config = tmp_path / "client.toml"
    config.write_text("[client]\nserver_host='vpn.example'\n")
    service = ClientService(str(config), state_dir=tmp_path / "unused-managed-state")
    status = service._get_status()
    assert status.managed_mode is False
    assert status.server_host == "vpn.example"
    assert not (tmp_path / "unused-managed-state").exists()
    with pytest.raises(ValueError, match="explicit --config"):
        service._dispatch({"command": "ENSURE_IDENTITY"})


def test_packaging_foundation_has_safe_launcher_and_managed_service():
    root = Path(__file__).parents[1]
    desktop = (root / "packaging/common/pqvpn.desktop").read_text()
    service = (root / "packaging/common/pqvpn-client.service").read_text()
    deploy_service = (root / "packaging/common/pqvpn-client-deploy.service").read_text()
    arch = (root / "packaging/arch/PKGBUILD").read_text()
    debian = (root / "packaging/deb/debian/control").read_text()
    debian_rules = (root / "packaging/deb/debian/rules").read_text()
    debian_dependency_patch = (
        root
        / "packaging/deb/debian/patches/use-debian-runtime-dependencies.patch"
    ).read_text()
    assert "Exec=pqvpn-gui" in desktop and "sudo" not in desktop.lower()
    assert "--service" in service and "--config" not in service
    assert "ExecStart=/usr/bin/python3 -s -m app.client --service" in service
    assert (
        "ExecStart=/opt/pqvpn/.venv/bin/python -s -m app.client --service"
        in deploy_service
    )
    assert "StateDirectory=pqvpn" in service and "/var/lib/pqvpn" in service
    for metadata in (arch, debian):
        assert "mock" not in metadata.lower()
    assert "'pyside6'" in arch
    assert "python-pyside6" not in arch
    assert "'python-setuptools'" in arch
    assert "PYTHONNOUSERSITE=1" in arch
    assert "#!/usr/bin/python -s" in arch
    assert "SKIP" not in arch
    assert "REPLACE_WITH" not in arch
    checksums = re.findall(r"'([0-9a-f]{64})'", arch)
    assert len(checksums) == 1

    assert "python3-liboqs (= 0.16.0)" not in debian
    assert "liboqs0 (= 0.16.0)" not in debian
    assert "python3-cryptography" in debian
    assert "+dependencies = []" in debian_dependency_patch
    assert '"cryptography==50.0.1"' in debian_dependency_patch
    assert '"liboqs-python==0.16.0"' in debian_dependency_patch
    assert "get_crypto_status" in debian_rules


def _make_arch_source_archive(root: Path, archive: Path) -> None:
    included = (
        "app", "benchmarks.py", "crypto", "handshake", "vpn", "pyproject.toml",
        "README.md", "docs/design.md", "docs/deployment.md", "docs/accounts.md",
        "packaging/common", "config/account-api.toml", "scripts",
    )
    subprocess.run(
        [
            "git", "archive", "--format=tar.gz", "--mtime=2026-09-14T00:00:00Z",
            "--prefix=pqvpn-3.0.0/",
            f"--output={archive}", "HEAD^{tree}", "--", *included,
        ],
        cwd=root,
        check=True,
    )


def _stable_archive_digest(root: Path, tmp: Path) -> str:
    """Hash the uncompressed tar to eliminate gzip-version differences."""
    included = (
        "app", "benchmarks.py", "crypto", "handshake", "vpn", "pyproject.toml",
        "README.md", "docs/design.md", "docs/deployment.md", "docs/accounts.md",
        "packaging/common", "config/account-api.toml", "scripts",
    )
    tar_path = tmp / "pqvpn-3.0.0.tar"
    subprocess.run(
        [
            "git", "archive", "--format=tar", "--mtime=2026-09-14T00:00:00Z",
            "--prefix=pqvpn-3.0.0/",
            f"--output={tar_path}", "HEAD^{tree}", "--", *included,
        ],
        cwd=root,
        check=True,
    )
    return hashlib.sha256(tar_path.read_bytes()).hexdigest()


def test_arch_development_archive_is_checksum_verified_and_secret_free(tmp_path):
    root = Path(__file__).parents[1]
    archive = tmp_path / "pqvpn-3.0.0.tar.gz"
    _make_arch_source_archive(root, archive)
    # Use uncompressed tar hash for cross-platform stability (gzip output
    # varies between zlib versions).
    digest = _stable_archive_digest(root, tmp_path)
    assert digest == "0a78dce7b6b2e42b86350b8fb3228741e43a4fe63f05853e9193c8861a291cbd"

    with tarfile.open(archive, "r:gz") as source:
        names = source.getnames()
    assert names
    assert all(name == "pqvpn-3.0.0" or name.startswith("pqvpn-3.0.0/") for name in names)
    forbidden_parts = {
        ".git", "__pycache__", ".pytest_cache", ".venv", "venv",
        "authorized_clients.json", "client.toml",
        "client_identity_private.key", "server_identity_private.key",
    }
    assert not any(forbidden_parts.intersection(Path(name).parts) for name in names)


def test_packages_do_not_include_deployment_identity_or_config(tmp_path):
    root = Path(__file__).parents[1]
    arch = (root / "packaging/arch/PKGBUILD").read_text()
    debian_install = (root / "packaging/deb/debian/install").read_text()
    archive = tmp_path / "pqvpn-3.0.0.tar.gz"
    _make_arch_source_archive(root, archive)

    with tarfile.open(archive, "r:gz") as source:
        names = [member.name for member in source.getmembers()]
    assert names
    forbidden_names = {
        "authorized_clients.json", "client_identity_private.key",
        "server_identity_private.key", "client.toml", "server.toml",
        ".env", "accounts.db", "account.db",
    }
    forbidden_directories = {
        ".git", "__pycache__", ".pytest_cache", ".venv", "venv",
        "build", "dist", "pkg", "src",
    }
    forbidden_suffixes = (
        ".key", ".pem", ".p12", ".pfx", ".crt", ".db",
        ".db-wal", ".db-shm", ".sqlite", ".sqlite3",
    )
    for name in names:
        path = Path(name)
        parts = {part.lower() for part in path.parts}
        filename = path.name.lower()
        assert not parts.intersection(forbidden_directories), name
        assert filename not in forbidden_names, name
        assert not filename.endswith(forbidden_suffixes), name
        assert ".pqenroll" not in filename, name
        assert not re.search(r"(^|[._-])(secret|credential|private_key)([._-]|$)", filename), name
        assert "var/lib/pqvpn" not in name.lower(), name

    installed_sources = "\n".join(
        line for line in arch.splitlines()
        if "installer" in line or line.lstrip().startswith("install ")
    )
    installed_sources += "\n" + debian_install
    for forbidden in (
        "192.168.8.43",
        "authorized_clients.json",
        "client_identity_private.key",
        "server_identity_private.key",
        "client.toml",
        "/var/lib/pqvpn",
        "/usr/local",
        "/.local",
    ):
        assert forbidden not in installed_sources
