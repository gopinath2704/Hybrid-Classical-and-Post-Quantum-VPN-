from __future__ import annotations

import base64
import hashlib
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from vpn.account_api import (
    DEFAULT_BODY_LIMIT,
    SESSION_TOKEN_BYTES,
    AccountAPIConfig,
    AccountAPIConfigError,
    BoundedRateLimiter,
    create_app,
    load_account_api_config,
)
from vpn.accounts import AccountNotFound, AccountStore, InvalidAccountInput, needs_rehash
from vpn.identity import AuthorizedClients


PASSWORD = "correct horse battery staple"


@pytest.fixture
def config(tmp_path) -> AccountAPIConfig:
    return AccountAPIConfig(
        database_path=tmp_path / "accounts" / "accounts.db",
        allow_insecure_loopback=True,
    )


@pytest.fixture
def app(config):
    return create_app(config)


@pytest.fixture
def client(app):
    with TestClient(app, client=("192.0.2.10", 50000)) as result:
        yield result


def register(client: TestClient, username="alice", email="alice@example.com", password=PASSWORD):
    return client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password},
    )


def login(client: TestClient, identifier="alice", password=PASSWORD):
    return client.post("/auth/login", json={"identifier": identifier, "password": password})


def raw_connection(store: AccountStore) -> sqlite3.Connection:
    connection = sqlite3.connect(store.path)
    connection.row_factory = sqlite3.Row
    return connection


def test_registration_returns_only_normalized_public_user(client, app):
    response = register(client, " Alice ", " ALICE@Example.COM ")
    assert response.status_code == 201
    assert response.json() == {
        "user": {
            "id": 1,
            "username": "alice",
            "email": "alice@example.com",
            "enabled": True,
            "created_at": response.json()["user"]["created_at"],
        }
    }
    rendered = response.text.casefold()
    assert "password" not in rendered
    assert "password_hash" not in rendered
    with raw_connection(app.state.account_store) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0


def test_duplicate_username_and_email_are_specific_registration_conflicts(client):
    assert register(client).status_code == 201
    username = register(client, "ALICE", "other@example.com")
    email = register(client, "other", "ALICE@EXAMPLE.COM")
    assert username.status_code == email.status_code == 409
    assert username.json()["error"]["code"] == "account_exists"
    assert "username" in username.json()["error"]["message"]
    assert "email" in email.json()["error"]["message"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("username", ".alice"),
        ("email", "not-an-email"),
        ("password", "too short"),
        ("password", "x" * 1025),
    ],
)
def test_invalid_registration_input_is_bounded_and_safe(client, field, value):
    payload = {"username": "alice", "email": "alice@example.com", "password": PASSWORD}
    payload[field] = value
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] in {"invalid_registration", "invalid_request"}
    assert "traceback" not in response.text.casefold()


def test_registration_never_changes_vpn_authorization(tmp_path):
    authorized_path = tmp_path / "authorized_clients.json"
    authorized_path.write_text('{"clients":[]}\n')
    before = authorized_path.read_bytes()
    cfg = AccountAPIConfig(
        database_path=tmp_path / "accounts" / "accounts.db",
        allow_insecure_loopback=True,
    )
    with TestClient(create_app(cfg)) as local_client:
        assert register(local_client).status_code == 201
    assert authorized_path.read_bytes() == before
    assert AuthorizedClients(authorized_path)._load(required=True) == {"clients": []}


@pytest.mark.parametrize("identifier", ["alice", " ALICE ", "ALICE@example.COM"])
def test_login_accepts_normalized_username_or_email(client, identifier):
    assert register(client).status_code == 201
    response = login(client, identifier)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["username"] == "alice"
    assert datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00")) > datetime.now(
        timezone.utc
    )


@pytest.mark.parametrize(
    ("identifier", "password"),
    [
        ("alice", "wrong password value"),
        ("unknown", "wrong password value"),
        ("unknown@example.com", "wrong password value"),
    ],
)
def test_login_failures_do_not_enumerate_accounts(client, identifier, password):
    assert register(client).status_code == 201
    response = login(client, identifier, password)
    assert response.status_code == 401
    assert response.json() == {
        "error": {"code": "invalid_credentials", "message": "invalid credentials"}
    }


def test_disabled_user_has_same_failure_and_old_session_stops(client, app):
    assert register(client).status_code == 201
    authenticated = login(client).json()
    token = authenticated["access_token"]
    user_id = authenticated["user"]["id"]
    app.state.account_store.set_user_enabled(user_id, False)
    assert login(client).json() == {
        "error": {"code": "invalid_credentials", "message": "invalid credentials"}
    }
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_session"


def test_successful_login_rehashes_old_argon2_parameters(client, app):
    assert register(client).status_code == 201
    old_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(PASSWORD)
    with raw_connection(app.state.account_store) as connection:
        connection.execute("UPDATE users SET password_hash = ? WHERE username = 'alice'", (old_hash,))
        connection.commit()
    assert login(client).status_code == 200
    with raw_connection(app.state.account_store) as connection:
        replacement = connection.execute(
            "SELECT password_hash FROM users WHERE username = 'alice'"
        ).fetchone()[0]
    assert replacement != old_hash
    assert needs_rehash(replacement) is False


def test_token_has_256_bits_of_random_input_and_only_its_sha256_is_stored(client, app):
    assert register(client).status_code == 201
    response = login(client)
    token = response.json()["access_token"]
    decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    assert len(decoded) == SESSION_TOKEN_BYTES == 32
    with raw_connection(app.state.account_store) as connection:
        row = connection.execute("SELECT token_hash FROM sessions").fetchone()
        columns = [item[1] for item in connection.execute("PRAGMA table_info(sessions)")]
    assert bytes(row[0]) == hashlib.sha256(token.encode("ascii")).digest()
    assert token.encode() not in app.state.account_store.path.read_bytes()
    assert "token" not in columns
    assert "raw_token" not in columns
    assert "token_hash" in columns


def test_valid_bearer_me_and_logout_revoke_current_session(client):
    assert register(client).status_code == 201
    token = login(client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    me = client.get("/auth/me", headers=headers)
    assert me.status_code == 200
    assert set(me.json()["user"]) == {"id", "username", "email", "enabled", "created_at"}
    assert "hash" not in me.text
    assert client.post("/auth/logout", headers=headers).status_code == 204
    assert client.get("/auth/me", headers=headers).status_code == 401
    repeated = client.post("/auth/logout", headers=headers)
    assert repeated.status_code == 401
    assert repeated.json()["error"]["code"] == "invalid_session"


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic abc", "Bearer", "Bearer a b", "bearer " + "x" * 513],
)
def test_malformed_or_wrong_authorization_is_rejected(client, authorization):
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.get("/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_random_expired_and_directly_revoked_tokens_are_rejected(client, app):
    assert register(client).status_code == 201
    assert client.get(
        "/auth/me", headers={"Authorization": "Bearer random-session-token"}
    ).status_code == 401
    first = login(client).json()["access_token"]
    first_hash = hashlib.sha256(first.encode()).digest()
    with raw_connection(app.state.account_store) as connection:
        connection.execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), first_hash),
        )
        connection.commit()
    assert client.get(
        "/auth/me", headers={"Authorization": f"Bearer {first}"}
    ).status_code == 401
    second = login(client).json()["access_token"]
    second_hash = hashlib.sha256(second.encode()).digest()
    assert app.state.account_store.revoke_session(second_hash)
    assert client.get(
        "/auth/me", headers={"Authorization": f"Bearer {second}"}
    ).status_code == 401


def test_last_used_is_touched_at_most_once_per_minute(client, app):
    assert register(client).status_code == 201
    token = login(client).json()["access_token"]
    token_hash = hashlib.sha256(token.encode()).digest()
    assert app.state.account_store.get_session_by_token_hash(token_hash).last_used_at is None
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/auth/me", headers=headers).status_code == 200
    first = app.state.account_store.get_session_by_token_hash(token_hash).last_used_at
    assert first is not None
    assert client.get("/auth/me", headers=headers).status_code == 200
    assert app.state.account_store.get_session_by_token_hash(token_hash).last_used_at == first


def test_concurrent_sessions_and_revoke_all_store_operation(client, app):
    assert register(client).status_code == 201
    first = login(client).json()
    second = login(client).json()
    assert first["access_token"] != second["access_token"]
    assert app.state.account_store.revoke_all_user_sessions(first["user"]["id"]) == 2
    for token in (first["access_token"], second["access_token"]):
        assert client.get(
            "/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 401
    with pytest.raises(AccountNotFound):
        app.state.account_store.revoke_all_user_sessions(9999)


def test_session_store_validates_inputs_and_expiry(config):
    store = AccountStore(config.database_path)
    store.initialize()
    user = store.create_user("alice", "alice@example.com", PASSWORD)
    now = datetime.now(timezone.utc)
    with pytest.raises(InvalidAccountInput):
        store.create_session(user.id, b"short", now + timedelta(hours=1))
    with pytest.raises(InvalidAccountInput):
        store.create_session(user.id, b"x" * 32, now - timedelta(seconds=1))
    with pytest.raises(InvalidAccountInput):
        store.create_session(user.id, b"x" * 32, now + timedelta(hours=1), now=now.replace(tzinfo=None))


def test_session_store_validation_touch_interval_and_revocation(config):
    store = AccountStore(config.database_path)
    store.initialize()
    user = store.create_user("alice", "alice@example.com", PASSWORD)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    token_hash = hashlib.sha256(b"test session secret with high entropy fixture").digest()
    created = store.create_session(user.id, token_hash, now + timedelta(hours=1), now=now)
    assert store.get_session_by_token_hash(token_hash) == created
    first_user, first = store.validate_session(token_hash, now=now)
    assert first_user == user
    assert first.last_used_at == "2026-01-01T00:00:00.000000Z"
    _, within_interval = store.validate_session(token_hash, now=now + timedelta(seconds=59))
    assert within_interval.last_used_at == first.last_used_at
    _, after_interval = store.validate_session(token_hash, now=now + timedelta(seconds=60))
    assert after_interval.last_used_at == "2026-01-01T00:01:00.000000Z"
    touched = store.touch_session(token_hash, now=now + timedelta(minutes=2))
    assert touched.last_used_at == "2026-01-01T00:02:00.000000Z"
    assert store.revoke_session(token_hash, now=now + timedelta(minutes=3)) is True
    assert store.revoke_session(token_hash, now=now + timedelta(minutes=4)) is False
    assert store.validate_session(token_hash, now=now + timedelta(minutes=4)) is None


def test_login_rate_limit_returns_429_retry_after_and_is_identifier_scoped(config):
    cfg = AccountAPIConfig(**{**config.__dict__, "login_rate_limit": 2})
    with TestClient(create_app(cfg), client=("192.0.2.20", 50000)) as local_client:
        assert register(local_client).status_code == 201
        assert login(local_client, "alice", "wrong password value").status_code == 401
        assert login(local_client, "alice", "wrong password value").status_code == 401
        limited = login(local_client, "alice", "wrong password value")
        assert limited.status_code == 429
        assert int(limited.headers["retry-after"]) >= 1
        assert login(local_client, "other", "wrong password value").status_code == 401


def test_login_rate_limit_is_source_scoped(config):
    cfg = AccountAPIConfig(**{**config.__dict__, "login_rate_limit": 1})
    application = create_app(cfg)
    with (
        TestClient(application, client=("192.0.2.30", 50000)) as first_source,
        TestClient(application, client=("192.0.2.31", 50000)) as second_source,
    ):
        assert register(first_source).status_code == 201
        assert login(first_source, password="wrong password value").status_code == 401
        assert login(first_source, password="wrong password value").status_code == 429
        assert login(second_source, password="wrong password value").status_code == 401


def test_successful_login_resets_failed_attempts(config):
    cfg = AccountAPIConfig(**{**config.__dict__, "login_rate_limit": 3})
    with TestClient(create_app(cfg)) as local_client:
        assert register(local_client).status_code == 201
        assert login(local_client, password="wrong password value").status_code == 401
        assert login(local_client).status_code == 200
        assert login(local_client, password="wrong password value").status_code == 401
        assert login(local_client, password="wrong password value").status_code == 401


def test_registration_limiter_is_separate_from_login_limiter(config):
    cfg = AccountAPIConfig(**{**config.__dict__, "registration_rate_limit": 1})
    with TestClient(create_app(cfg)) as local_client:
        assert register(local_client).status_code == 201
        limited = register(local_client, "bob", "bob@example.com")
        assert limited.status_code == 429
        assert limited.headers["retry-after"]
        assert login(local_client).status_code == 200


def test_limiter_is_monotonic_bounded_and_removes_stale_entries():
    now = [100.0]
    limiter = BoundedRateLimiter(2, 10, 5, 3, clock=lambda: now[0])
    for key in ("one", "two", "three", "four"):
        limiter.record_event(key)
    assert len(limiter) == 3
    limiter.record_event("four")
    assert limiter.retry_after("four") == 5
    now[0] = -1_000_000.0
    assert limiter.retry_after("four") > 0
    now[0] = 1_000_000.0
    assert len(limiter) == 0


@pytest.mark.parametrize(
    ("content", "content_type", "status"),
    [
        (b"{", "application/json", 400),
        (b"{}", "text/plain", 415),
        (b'{' + b'"padding":"' + b"x" * DEFAULT_BODY_LIMIT + b'"}', "application/json", 413),
    ],
)
def test_malformed_wrong_type_and_oversized_bodies(client, content, content_type, status):
    response = client.post("/auth/login", content=content, headers={"Content-Type": content_type})
    assert response.status_code == status
    assert set(response.json()) == {"error"}


def test_chunked_oversized_body_is_rejected_without_content_length(client):
    def chunks():
        for _ in range(20):
            yield b"x" * 1024

    response = client.post(
        "/auth/login", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert "content-length" not in response.request.headers
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"


def test_unexpected_fields_and_sql_injection_shapes_are_data(client):
    unexpected = client.post(
        "/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": PASSWORD,
            "admin": True,
        },
    )
    assert unexpected.status_code == 400
    assert register(client, "alice", "'or1@example.com").status_code == 201
    injected = login(client, "alice' OR 1=1 --", PASSWORD)
    assert injected.status_code == 401
    assert login(client, "'OR1@example.com", PASSWORD).status_code == 200


def test_password_and_token_are_never_logged(client, caplog):
    with caplog.at_level(logging.INFO, logger="pqvpn.account_api"):
        assert register(client).status_code == 201
        token = login(client).json()["access_token"]
        assert client.get(
            "/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 200
    assert PASSWORD not in caplog.text
    assert token not in caplog.text
    assert hashlib.sha256(token.encode()).hexdigest() not in caplog.text


def test_remote_or_implicit_cleartext_bind_fails_closed(tmp_path):
    with pytest.raises(AccountAPIConfigError, match="TLS is required"):
        AccountAPIConfig(
            database_path=tmp_path / "a.db", bind_host="0.0.0.0",
            allow_insecure_loopback=True,
        ).validate()
    with pytest.raises(AccountAPIConfigError, match="explicitly enabled"):
        AccountAPIConfig(database_path=tmp_path / "b.db").validate()
    AccountAPIConfig(
        database_path=tmp_path / "c.db", allow_insecure_loopback=True
    ).validate()


def test_tls_files_are_required_regular_and_private_key_is_private(tmp_path):
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("test certificate")
    key.write_text("test private key")
    key.chmod(0o600)
    AccountAPIConfig(
        database_path=tmp_path / "accounts.db",
        bind_host="0.0.0.0",
        tls_cert=cert,
        tls_key=key,
    ).validate()
    key.chmod(0o644)
    with pytest.raises(AccountAPIConfigError, match="group or others"):
        AccountAPIConfig(
            database_path=tmp_path / "accounts.db",
            bind_host="0.0.0.0",
            tls_cert=cert,
            tls_key=key,
        ).validate()
    key.unlink()
    key.symlink_to(cert)
    with pytest.raises(AccountAPIConfigError, match="non-symlink"):
        AccountAPIConfig(
            database_path=tmp_path / "accounts.db",
            bind_host="0.0.0.0",
            tls_cert=cert,
            tls_key=key,
        ).validate()


def test_dedicated_config_loads_relative_paths_and_rejects_unknown_values(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("certificate")
    key.write_text("private key")
    key.chmod(0o600)
    path = tmp_path / "account-api.toml"
    path.write_text(
        """
[account_api]
database_path = "state/accounts.db"
bind_host = "0.0.0.0"
bind_port = 8443
tls_cert = "cert.pem"
tls_key = "key.pem"
session_lifetime_seconds = 43200
login_rate_limit = 5
registration_rate_limit = 3
"""
    )
    loaded = load_account_api_config(path)
    assert loaded.database_path == tmp_path / "state/accounts.db"
    assert loaded.tls_key == key
    path.write_text("[account_api]\nallow_insecure_loopback=true\nunknown=true\n")
    with pytest.raises(AccountAPIConfigError, match="unknown"):
        load_account_api_config(path)


def test_default_session_lifetime_is_twelve_hours(client):
    assert register(client).status_code == 201
    before = datetime.now(timezone.utc) + timedelta(hours=12) - timedelta(seconds=2)
    expires = datetime.fromisoformat(login(client).json()["expires_at"].replace("Z", "+00:00"))
    after = datetime.now(timezone.utc) + timedelta(hours=12) + timedelta(seconds=2)
    assert before <= expires <= after


def device_identity(seed: int = 1) -> tuple[str, str]:
    """Deterministic public test fixture; no real secret material."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    public = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return base64.b64encode(public).decode(), hashlib.sha256(public).hexdigest()


def bearer(client: TestClient, username="alice", email="alice@example.com") -> dict[str, str]:
    assert register(client, username, email).status_code == 201
    return {"Authorization": f"Bearer {login(client, username).json()['access_token']}"}


def bind(client: TestClient, headers, seed=1, name="laptop", **overrides):
    public_key, fp = device_identity(seed)
    body = {"device_name": name, "public_key": public_key, "fingerprint": fp, **overrides}
    return client.post("/devices", json=body, headers=headers)


def test_device_endpoints_require_a_valid_session(client):
    assert client.get("/devices").status_code == 401
    response = bind(client, {"Authorization": "Bearer nope"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_session"


def test_bind_device_records_public_identity_only(client, app):
    headers = bearer(client)
    public_key, fp = device_identity(1)
    response = bind(client, headers)
    assert response.status_code == 201
    device = response.json()["device"]
    assert set(device) == {"id", "device_name", "fingerprint", "enabled", "created_at"}
    assert device["fingerprint"] == fp and device["device_name"] == "laptop"
    assert public_key not in response.text
    stored = app.state.account_store.get_device_by_fingerprint(fp)
    assert stored.client_public_key == base64.b64decode(public_key)
    listed = client.get("/devices", headers=headers).json()["devices"]
    assert [d["fingerprint"] for d in listed] == [fp]


def test_rebinding_same_device_is_idempotent(client):
    headers = bearer(client)
    first = bind(client, headers)
    again = bind(client, headers, name="renamed")
    assert again.status_code == 200
    assert again.json()["device"]["id"] == first.json()["device"]["id"]
    assert len(client.get("/devices", headers=headers).json()["devices"]) == 1


def test_device_owned_by_another_account_is_rejected(client):
    assert bind(client, bearer(client)).status_code == 201
    other = bearer(client, "bob", "bob@example.com")
    response = bind(client, other)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "device_exists"
    assert client.get("/devices", headers=other).json()["devices"] == []


@pytest.mark.parametrize("overrides", [
    {"fingerprint": "0" * 64},
    {"fingerprint": "Z" * 64},
    {"public_key": "not base64!"},
    {"public_key": base64.b64encode(b"x" * 31).decode()},
    {"device_name": "bad\x00name"},
    {"device_name": ""},
])
def test_invalid_device_identity_is_rejected(client, app, overrides):
    headers = bearer(client)
    response = bind(client, headers, **overrides)
    assert response.status_code == 400
    assert client.get("/devices", headers=headers).json()["devices"] == []


def test_private_key_field_and_non_json_are_refused(client):
    headers = bearer(client)
    assert bind(client, headers, private_key="secret").status_code == 400
    public_key, fp = device_identity(1)
    response = client.post(
        "/devices", content=f"device_name=x&public_key={public_key}&fingerprint={fp}",
        headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 415


def test_device_limit_per_account(client):
    from vpn.account_api import MAX_DEVICES_PER_USER

    headers = bearer(client)
    for seed in range(1, MAX_DEVICES_PER_USER + 1):
        assert bind(client, headers, seed=seed, name=f"d{seed}").status_code == 201
    response = bind(client, headers, seed=MAX_DEVICES_PER_USER + 1)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "device_limit"


def test_device_binding_never_changes_vpn_authorization(tmp_path):
    authorized_path = tmp_path / "authorized_clients.json"
    authorized_path.write_text('{"clients":[]}\n')
    before = authorized_path.read_bytes()
    cfg = AccountAPIConfig(
        database_path=tmp_path / "accounts" / "accounts.db", allow_insecure_loopback=True
    )
    with TestClient(create_app(cfg)) as local_client:
        assert bind(local_client, bearer(local_client)).status_code == 201
    assert authorized_path.read_bytes() == before


def test_dependency_and_service_packaging_metadata_are_declared():
    root = Path(__file__).parents[1]
    project = (root / "pyproject.toml").read_text()
    constraints = (root / "constraints-tested.txt").read_text()
    arch = (root / "packaging/arch/PKGBUILD").read_text()
    debian = (root / "packaging/deb/debian/control").read_text()
    assert '"fastapi==0.141.1"' in project
    assert '"uvicorn==0.52.4"' in project
    assert "fastapi==0.141.1" in constraints
    assert "uvicorn==0.52.4" in constraints
    assert "'python-fastapi'" in arch and "'uvicorn'" in arch
    assert "python3-fastapi" in debian and "python3-uvicorn" in debian
    service = (root / "packaging/common/pqvpn-account-api.service").read_text()
    assert "User=pqvpn-account" in service
    assert "CAP_NET_ADMIN" not in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    sysusers = (root / "packaging/common/pqvpn.conf").read_text()
    assert sysusers.startswith('u pqvpn-account - "PQ-VPN account API service" ')
    assert sysusers.rstrip().endswith("-")
    assert "packaging/common/pqvpn.conf" in arch
    assert "packaging/common/pqvpn.conf usr/lib/sysusers.d/" in (
        root / "packaging/deb/debian/install"
    ).read_text()
    assert "dh-sequence-installsysusers" in debian
    assert not (root / "packaging/common/pqvpn-account.conf").exists()
    assert not (root / "packaging/common/pqvpn-account.sysusers").exists()
    assert not (root / "packaging/deb/debian/pqvpn.sysusers").exists()
