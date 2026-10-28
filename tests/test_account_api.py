from __future__ import annotations

import base64
import hashlib
import logging
import os
import sqlite3
import stat
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
from vpn.accounts import (
    LOCKOUT_THRESHOLD,
    AccountNotFound,
    AccountStore,
    InvalidAccountInput,
    compute_totp,
    generate_totp_secret,
    needs_rehash,
)
from vpn.identity import AuthorizedClients, _atomic_private


PASSWORD = "correct horse battery staple"


@pytest.fixture
def config(tmp_path) -> AccountAPIConfig:
    return AccountAPIConfig(
        database_path=tmp_path / "accounts" / "accounts.db",
        allow_insecure_loopback=True,
        authorized_clients_file=tmp_path / "authorized" / "authorized_clients.json",
    )


@pytest.fixture
def app(config):
    return create_app(config)


@pytest.fixture
def client(app):
    with TestClient(app, client=("192.0.2.10", 50000)) as result:
        yield result


def invite(client: TestClient, **kwargs) -> str:
    return client.app.state.account_store.create_invite(**kwargs)[1]


def register(client: TestClient, username="alice", email="alice@example.com", password=PASSWORD,
             invite_code: str | None = None):
    """Register with a fresh single-use invite unless one is given explicitly."""
    return client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password,
              "invite_code": invite(client) if invite_code is None else invite_code},
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
            "mfa_enabled": False,
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
    payload = {"username": "alice", "email": "alice@example.com", "password": PASSWORD,
               "invite_code": invite(client)}
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
    assert set(me.json()["user"]) == {"id", "username", "email", "enabled", "created_at", "mfa_enabled"}
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
            "invite_code": invite(client),
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
    assert set(device) == {"id", "device_name", "fingerprint", "enabled", "status", "created_at"}
    assert device["status"] == "pending"
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


def _auto_approve_client(tmp_path):
    authorized = AuthorizedClients(tmp_path / "authorized" / "authorized_clients.json")
    cfg = AccountAPIConfig(
        database_path=tmp_path / "accounts" / "accounts.db", allow_insecure_loopback=True,
        auto_approve=True, authorized_clients_file=authorized.path,
    )
    return authorized, TestClient(create_app(cfg))


def test_auto_approve_authorizes_then_approves(tmp_path):
    authorized, local_client = _auto_approve_client(tmp_path)
    with local_client:
        response = bind(local_client, bearer(local_client))
        assert response.status_code == 201
        assert response.json()["device"]["status"] == "approved"
        assert local_client.app.state.account_store.list_devices()[0].status == "approved"
    public_key, _ = device_identity(1)
    assert authorized.find(base64.b64decode(public_key)) is not None


def test_auto_approve_failure_stays_pending_and_rebind_retries(tmp_path, monkeypatch):
    authorized, local_client = _auto_approve_client(tmp_path)
    real_authorize = AuthorizedClients.authorize

    def denied(self, *args, **kwargs):
        raise PermissionError("authorized_clients.json.lock")

    monkeypatch.setattr(AuthorizedClients, "authorize", denied)
    with local_client:
        headers = bearer(local_client)
        store = local_client.app.state.account_store
        first = bind(local_client, headers)
        assert first.status_code == 201
        assert first.json()["device"]["status"] == "pending"
        assert store.list_devices()[0].status == "pending"
        assert not authorized.path.exists()

        monkeypatch.setattr(AuthorizedClients, "authorize", real_authorize)
        retry = bind(local_client, headers)
        assert retry.status_code == 200
        assert retry.json()["device"]["status"] == "approved"
        assert store.list_devices()[0].status == "approved"
    public_key, _ = device_identity(1)
    assert authorized.find(base64.b64decode(public_key)) is not None


def test_authorized_clients_file_is_group_readable_never_world(tmp_path):
    authorized = AuthorizedClients(tmp_path / "authorized_clients.json")
    public_key, _ = device_identity(1)
    fp = authorized.authorize(base64.b64decode(public_key), "alice")
    for path in (authorized.path, Path(str(authorized.path) + ".lock")):
        info = os.stat(path)
        assert stat.S_IMODE(info.st_mode) == 0o640
        assert info.st_gid == tmp_path.stat().st_gid
    assert authorized.revoke(fp)
    assert stat.S_IMODE(os.stat(authorized.path).st_mode) == 0o640
    with pytest.raises(ValueError):
        _atomic_private(tmp_path / "x", b"", 0o644)


def _public(seed: int = 1) -> bytes:
    return base64.b64decode(device_identity(seed)[0])


def _logout(client: TestClient, headers, seed: int | None = 1):
    body = None if seed is None else {"fingerprint": device_identity(seed)[1]}
    return client.post("/auth/logout", headers=headers, json=body)


def _relogin(client: TestClient, username="alice") -> dict[str, str]:
    return {"Authorization": f"Bearer {login(client, username).json()['access_token']}"}


def test_logout_suspends_only_this_device_and_sign_in_restores_it(tmp_path):
    authorized, local_client = _auto_approve_client(tmp_path)
    with local_client:
        headers = bearer(local_client)
        assert bind(local_client, headers, seed=1).status_code == 201
        assert bind(local_client, headers, seed=2, name="phone").status_code == 201
        assert _logout(local_client, headers, seed=1).status_code == 204
        assert local_client.get("/auth/me", headers=headers).status_code == 401
        assert authorized.find(_public(1)) is None
        assert authorized.find(_public(2)) is not None  # other devices of the account untouched
        assert local_client.app.state.account_store.list_devices()[0].status == "approved"

        restored = bind(local_client, _relogin(local_client), seed=1)
        assert restored.status_code == 200 and restored.json()["device"]["status"] == "approved"
    assert authorized.find(_public(1)) is not None
    assert stat.S_IMODE(os.stat(authorized.path).st_mode) == 0o640


def test_logout_without_fingerprint_keeps_device_authorization(tmp_path):
    """Old clients send no body: session-only logout, as before."""
    authorized, local_client = _auto_approve_client(tmp_path)
    with local_client:
        headers = bearer(local_client)
        bind(local_client, headers)
        assert _logout(local_client, headers, seed=None).status_code == 204
    assert authorized.find(_public(1)) is not None


def test_logout_and_bind_never_touch_another_users_device(tmp_path):
    authorized, local_client = _auto_approve_client(tmp_path)
    with local_client:
        alice = bearer(local_client)
        bind(local_client, alice, seed=1)
        mallory = bearer(local_client, "mallory", "mallory@example.com")
        assert _logout(local_client, mallory, seed=1).status_code == 204
        assert authorized.find(_public(1)) is not None  # alice's device still authorized
        assert local_client.get("/auth/me", headers=mallory).status_code == 401

        assert _logout(local_client, alice, seed=1).status_code == 204
        mallory = _relogin(local_client, "mallory")
        stolen = bind(local_client, mallory, seed=1)
        assert stolen.status_code == 409 and stolen.json()["error"]["code"] == "device_exists"
    assert authorized.find(_public(1)) is None  # mallory cannot restore alice's device


def test_logout_fails_closed_when_suspension_fails(tmp_path, monkeypatch):
    authorized, local_client = _auto_approve_client(tmp_path)

    def denied(self, fp):
        raise PermissionError("authorized_clients.json.lock")

    with local_client:
        headers = bearer(local_client)
        bind(local_client, headers)
        monkeypatch.setattr(AuthorizedClients, "suspend", denied)
        response = _logout(local_client, headers)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "deauthorize_failed"
        assert "lock" not in response.text
        assert local_client.get("/auth/me", headers=headers).status_code == 200  # retry possible
    assert authorized.find(_public(1)) is not None


def test_session_cleanup_failure_after_suspension_leaves_device_blocked(tmp_path, monkeypatch):
    from vpn.accounts import AccountDatabaseError
    authorized, local_client = _auto_approve_client(tmp_path)

    def broken(self, token_hash, **kwargs):
        raise AccountDatabaseError("database is locked")

    with local_client:
        headers = bearer(local_client)
        bind(local_client, headers)
        monkeypatch.setattr(AccountStore, "revoke_session", broken)
        assert _logout(local_client, headers).status_code == 500
    assert authorized.find(_public(1)) is None


def test_sign_in_never_restores_disabled_or_revoked_access(tmp_path):
    authorized, local_client = _auto_approve_client(tmp_path)
    with local_client:
        store = local_client.app.state.account_store
        held = bearer(local_client)
        bind(local_client, held, seed=1)
        bind(local_client, held, seed=2, name="phone")
        bind(local_client, held, seed=3, name="tablet")
        _logout(local_client, _relogin(local_client), seed=1)
        _logout(local_client, _relogin(local_client), seed=2)
        _logout(local_client, _relogin(local_client), seed=3)

        user = store.get_user_by_username("alice")
        store.set_user_enabled(user.id, False)
        assert login(local_client).status_code == 401
        assert bind(local_client, held, seed=1).status_code == 401  # pre-existing session dies too
        store.set_user_enabled(user.id, True)

        devices = {d.client_fingerprint: d for d in store.list_devices()}
        # Administrator revocation (account revoke) and raw `client revoke` both outrank sign-in.
        authorized.revoke(device_identity(1)[1])
        store.set_device_status(devices[device_identity(1)[1]].id, "revoked", expected=("approved",))
        authorized.revoke(device_identity(2)[1])
        store.set_device_enabled(devices[device_identity(3)[1]].id, False)

        headers = _relogin(local_client)
        for seed in (1, 2, 3):
            assert bind(local_client, headers, seed=seed).status_code == 200
    for seed in (1, 2, 3):
        assert authorized.find(_public(seed)) is None


def test_restore_failure_is_reported(tmp_path, monkeypatch):
    authorized, local_client = _auto_approve_client(tmp_path)

    def denied(self, fp):
        raise PermissionError("authorized_clients.json.lock")

    with local_client:
        bind(local_client, bearer(local_client))
        _logout(local_client, _relogin(local_client))
        monkeypatch.setattr(AuthorizedClients, "restore", denied)
        response = bind(local_client, _relogin(local_client))
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "authorize_failed"
    assert authorized.find(_public(1)) is None


def test_suspend_and_restore_use_the_lock_and_atomic_write(tmp_path, monkeypatch):
    import vpn.identity as identity
    authorized = AuthorizedClients(tmp_path / "authorized_clients.json")
    authorized.authorize(_public(1), "alice-1", "10.8.0.5")
    events: list[str] = []
    real_lock, real_write = AuthorizedClients._lock, identity._atomic_private

    def lock(self):
        events.append("lock")
        return real_lock(self)

    def write(path, data, mode=0o600):
        events.append(f"write {oct(mode)}")
        return real_write(path, data, mode)

    monkeypatch.setattr(AuthorizedClients, "_lock", lock)
    monkeypatch.setattr(identity, "_atomic_private", write)
    fp = device_identity(1)[1]
    assert authorized.suspend(fp) and not authorized.suspend(fp)
    assert authorized.restore(fp) and not authorized.restore(fp)
    assert events == ["lock", "write 0o640", "lock", "lock", "write 0o640", "lock"]
    record = authorized.find(_public(1))
    assert record["assigned_ip"] == "10.8.0.5" and "signed_out" not in record  # record preserved
    assert stat.S_IMODE(os.stat(authorized.path).st_mode) == 0o640


def test_signed_out_marker_only_on_disabled_records(tmp_path):
    import json
    path = tmp_path / "authorized_clients.json"
    authorized = AuthorizedClients(path)
    authorized.authorize(_public(1), "alice-1")
    db = json.loads(path.read_text())
    db["clients"][0]["signed_out"] = True  # enabled + marker is inconsistent
    path.write_text(json.dumps(db))
    with pytest.raises(ValueError, match="signed_out"):
        authorized._load(required=True)


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


# --- MFA API ---

def test_mfa_setup_confirm_disable_flow(client):
    headers = bearer(client)
    resp = client.post("/mfa/setup", headers=headers)
    assert resp.status_code == 200
    secret = resp.json()["secret"]
    assert "provisioning_uri" in resp.json()
    code = compute_totp(secret)
    resp = client.post("/mfa/confirm", json={"secret": secret, "code": code}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "mfa_enabled"
    resp = client.post("/mfa/setup", headers=headers)
    assert resp.status_code == 409
    code = compute_totp(secret)
    resp = client.post("/mfa/disable", json={"code": code}, headers=headers)
    assert resp.status_code == 200


def test_mfa_confirm_rejects_wrong_code(client):
    headers = bearer(client)
    secret = client.post("/mfa/setup", headers=headers).json()["secret"]
    resp = client.post("/mfa/confirm", json={"secret": secret, "code": "000000"}, headers=headers)
    assert resp.status_code == 400


def test_login_requires_totp_when_mfa_enabled(client, app):
    register(client)
    resp = login(client)
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    secret = client.post("/mfa/setup", headers=headers).json()["secret"]
    code = compute_totp(secret)
    client.post("/mfa/confirm", json={"secret": secret, "code": code}, headers=headers)
    resp = client.post("/auth/login", json={"identifier": "alice", "password": PASSWORD})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "mfa_required"
    code = compute_totp(secret)
    resp = client.post("/auth/login", json={"identifier": "alice", "password": PASSWORD, "totp_code": code})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_totp_rejected(client, app):
    register(client)
    resp = login(client)
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    secret = client.post("/mfa/setup", headers=headers).json()["secret"]
    code = compute_totp(secret)
    client.post("/mfa/confirm", json={"secret": secret, "code": code}, headers=headers)
    resp = client.post("/auth/login", json={"identifier": "alice", "password": PASSWORD, "totp_code": "000000"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_totp"


# --- Account lockout API ---

def test_account_lockout_returns_429(tmp_path):
    cfg = AccountAPIConfig(
        database_path=tmp_path / "accounts" / "accounts.db",
        allow_insecure_loopback=True,
        login_rate_limit=LOCKOUT_THRESHOLD + 5,
    )
    with TestClient(create_app(cfg), client=("192.0.2.10", 50000)) as c:
        register(c)
        for _ in range(LOCKOUT_THRESHOLD):
            c.post("/auth/login", json={"identifier": "alice", "password": "wrong"})
        resp = c.post("/auth/login", json={"identifier": "alice", "password": PASSWORD})
        assert resp.status_code == 429
        assert resp.json()["error"]["code"] == "account_locked"


# --- Change password API ---

def test_change_password_endpoint(client):
    headers = bearer(client)
    resp = client.post("/auth/change-password", json={
        "old_password": PASSWORD, "new_password": "new-secure-password-123"
    }, headers=headers)
    assert resp.status_code == 200
    resp = login(client, password="new-secure-password-123")
    assert resp.status_code == 200


def test_change_password_wrong_old_rejected(client):
    headers = bearer(client)
    resp = client.post("/auth/change-password", json={
        "old_password": "wrong-password", "new_password": "new-secure-password-123"
    }, headers=headers)
    assert resp.status_code == 400


def test_public_user_includes_mfa_enabled(client):
    register(client)
    resp = login(client)
    assert "mfa_enabled" in resp.json()["user"]
    assert resp.json()["user"]["mfa_enabled"] is False


# --- Invite-only registration ---

def _invite_failures(client: TestClient) -> list:
    expired_id, expired = client.app.state.account_store.create_invite()
    with raw_connection(client.app.state.account_store) as connection:
        connection.execute(
            "UPDATE invites SET expires_at = '2000-01-01T00:00:00.000000Z' WHERE id = ?",
            (expired_id,),
        )
    used = invite(client)
    assert register(client, "first", "first@example.com", invite_code=used).status_code == 201
    missing = client.post("/auth/register", json={
        "username": "bob", "email": "bob@example.com", "password": PASSWORD,
    })
    return [missing, register(client, "bob", "bob@example.com", invite_code="x" * 43),
            register(client, "bob", "bob@example.com", invite_code=expired),
            register(client, "bob", "bob@example.com", invite_code=used)]


def test_invite_is_required_by_default_and_failures_are_indistinguishable(config):
    assert config.require_invite is True
    cfg = AccountAPIConfig(**{**config.__dict__, "registration_rate_limit": 10})
    with TestClient(create_app(cfg)) as local_client:
        responses = _invite_failures(local_client)
        assert {(r.status_code, r.text) for r in responses} == {(
            403, '{"error":{"code":"invalid_invite","message":"a valid invite code is required"}}'
        )}
        assert local_client.app.state.account_store.get_user_by_username("bob") is None


def test_invalid_invite_does_not_reveal_existing_accounts(client):
    assert register(client).status_code == 201
    response = register(client, "alice", "alice@example.com", invite_code="wrong")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "invalid_invite"


def test_wrong_invite_codes_count_against_registration_rate_limit(config):
    cfg = AccountAPIConfig(**{**config.__dict__, "registration_rate_limit": 3})
    with TestClient(create_app(cfg)) as local_client:
        for index in range(3):
            assert register(
                local_client, f"u{index}", f"u{index}@example.com", invite_code=f"guess{index}"
            ).status_code == 403
        limited = register(local_client, "bob", "bob@example.com")  # valid code, still limited
        assert limited.status_code == 429 and limited.headers["retry-after"]


def test_invite_code_is_never_logged(client, caplog):
    code = invite(client)
    with caplog.at_level(logging.DEBUG):
        assert register(client, invite_code=code).status_code == 201
        assert register(client, "bob", "bob@example.com", invite_code=code).status_code == 403
    assert code not in caplog.text
    assert hashlib.sha256(code.encode()).hexdigest() not in caplog.text


def test_require_invite_false_allows_open_registration_for_dev(config):
    cfg = AccountAPIConfig(**{**config.__dict__, "require_invite": False})
    with TestClient(create_app(cfg)) as local_client:
        response = local_client.post("/auth/register", json={
            "username": "alice", "email": "alice@example.com", "password": PASSWORD,
        })
        assert response.status_code == 201


def test_require_invite_must_be_boolean_and_loads_from_toml(tmp_path):
    with pytest.raises(AccountAPIConfigError, match="require_invite"):
        AccountAPIConfig(
            database_path=tmp_path / "a.db", allow_insecure_loopback=True, require_invite="no"
        ).validate()
    path = tmp_path / "account-api.toml"
    path.write_text('[account_api]\nallow_insecure_loopback = true\nrequire_invite = false\n')
    assert load_account_api_config(path).require_invite is False
    path.write_text('[account_api]\nallow_insecure_loopback = true\n')
    assert load_account_api_config(path).require_invite is True


def test_oversized_invite_code_is_rejected(client):
    response = register(client, invite_code="x" * 129)
    assert response.status_code == 400
    assert "x" * 129 not in response.text


def _change_password(client: TestClient, headers, new="new-secure-password-123"):
    return client.post("/auth/change-password", headers=headers,
                       json={"old_password": PASSWORD, "new_password": new})


def test_change_password_revokes_sessions_and_suspends_devices(tmp_path):
    """Pentest #65: a stolen token or attacker-bound device must not survive a password change."""
    authorized, local_client = _auto_approve_client(tmp_path)
    with local_client:
        headers = bearer(local_client)
        other = {"Authorization": f"Bearer {login(local_client).json()['access_token']}"}
        assert bind(local_client, headers, seed=1).status_code == 201
        assert bind(local_client, headers, seed=2, name="phone").status_code == 201
        assert _change_password(local_client, headers).status_code == 200
        assert local_client.get("/auth/me", headers=headers).status_code == 401
        assert local_client.get("/auth/me", headers=other).status_code == 401
        assert authorized.find(_public(1)) is None and authorized.find(_public(2)) is None

        fresh = {"Authorization": "Bearer " + login(local_client, password="new-secure-password-123")
                 .json()["access_token"]}
        assert bind(local_client, fresh, seed=1).status_code == 200
    assert authorized.find(_public(1)) is not None  # owner's sign-in restores that device only
    assert authorized.find(_public(2)) is None


def test_change_password_suspension_failure_still_revokes_sessions(tmp_path, monkeypatch):
    authorized, local_client = _auto_approve_client(tmp_path)

    def denied(self, fp):
        raise PermissionError("authorized_clients.json.lock")

    with local_client:
        headers = bearer(local_client)
        bind(local_client, headers)
        monkeypatch.setattr(AuthorizedClients, "suspend", denied)
        response = _change_password(local_client, headers)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "deauthorize_failed"
        assert "lock" not in response.text
        assert local_client.get("/auth/me", headers=headers).status_code == 401


def test_credential_stuffing_from_one_ip_is_throttled(config):
    """Pentest #14: distinct identifiers from one source share a per-IP failure budget."""
    cfg = AccountAPIConfig(**{**config.__dict__, "login_rate_limit": 2})
    app = create_app(cfg)
    with TestClient(app, client=("198.51.100.7", 40000)) as attacker:
        codes = [attacker.post("/auth/login", json={"identifier": f"user{i}", "password": "leaked"}).status_code
                 for i in range(4 * cfg.login_rate_limit + 1)]
        assert codes[:-1] == [401] * (4 * cfg.login_rate_limit)
        assert codes[-1] == 429
    with TestClient(app, client=("203.0.113.9", 40001)) as fresh:
        assert register(fresh).status_code == 201
        assert login(fresh).status_code == 200


def _mfa_app(config, **overrides):
    """App with alice registered and MFA enabled; returns (app, secret)."""
    app = create_app(AccountAPIConfig(**{**config.__dict__, **overrides}))
    with TestClient(app, client=("192.0.2.50", 1)) as setup:
        register(setup)
        headers = {"Authorization": f"Bearer {login(setup).json()['access_token']}"}
        secret = setup.post("/mfa/setup", headers=headers).json()["secret"]
        setup.post("/mfa/confirm", json={"secret": secret, "code": compute_totp(secret)}, headers=headers)
    return app, secret


def _wrong_totp(secret: str) -> str:
    return f"{(int(compute_totp(secret)) + 1) % 1_000_000:06d}"


def _totp_login(client: TestClient, code: str | None, identifier="alice"):
    body = {"identifier": identifier, "password": PASSWORD}
    if code is not None:
        body["totp_code"] = code
    return client.post("/auth/login", json=body)


def test_wrong_totp_codes_are_rate_limited(config):
    """A known password must not allow unthrottled TOTP guessing (403 mfa_required confirms it)."""
    app, secret = _mfa_app(config, login_rate_limit=3)
    with TestClient(app, client=("198.51.100.20", 1)) as attacker:
        assert [_totp_login(attacker, None).status_code for _ in range(5)] == [403] * 5  # two-step flow not penalized
        codes = [_totp_login(attacker, _wrong_totp(secret)).status_code for _ in range(4)]
        assert codes == [401, 401, 401, 429]
        assert _totp_login(attacker, compute_totp(secret)).status_code == 429
    with TestClient(app, client=("203.0.113.20", 1)) as owner:
        assert _totp_login(owner, compute_totp(secret)).status_code == 200


def test_wrong_totp_codes_count_against_the_per_ip_budget(config):
    app, secret = _mfa_app(config, login_rate_limit=50)
    app.state.login_source_limiter = BoundedRateLimiter(2, 60, 60, 16)
    with TestClient(app, client=("198.51.100.21", 1)) as attacker:
        assert _totp_login(attacker, _wrong_totp(secret)).status_code == 401
        assert _totp_login(attacker, _wrong_totp(secret), "alice@example.com").status_code == 401
        assert _totp_login(attacker, _wrong_totp(secret)).status_code == 429
