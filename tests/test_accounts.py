from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vpn.accounts import (
    LOCKOUT_THRESHOLD,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    SCHEMA_VERSION,
    AccountAlreadyExists,
    AccountDatabaseError,
    AccountLocked,
    AccountNotFound,
    AccountStore,
    DeviceRecord,
    InvalidAccountInput,
    InvalidInvite,
    SessionRecord,
    UnsupportedSchemaVersion,
    UserRecord,
    compute_totp,
    generate_totp_secret,
    hash_password,
    invite_code_hash,
    needs_rehash,
    verify_password,
    verify_totp,
)
from vpn.identity import AuthorizedClients, fingerprint


@pytest.fixture
def store(tmp_path) -> AccountStore:
    result = AccountStore(tmp_path / "accounts" / "accounts.db")
    result.initialize()
    return result


@pytest.fixture
def user(store) -> UserRecord:
    return store.create_user("alice", "alice@example.com", "correct horse battery staple")


def public_identity() -> tuple[bytes, str, bytes]:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes_raw()
    public = private.public_key().public_bytes_raw()
    return public, fingerprint(public), private_bytes


def raw_connection(store: AccountStore) -> sqlite3.Connection:
    connection = sqlite3.connect(store.path)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def test_fresh_database_initialization_schema_and_permissions(tmp_path):
    path = tmp_path / "state" / "accounts.db"
    account_store = AccountStore(path)
    assert not path.exists()
    account_store.initialize()

    assert account_store.schema_version() == SCHEMA_VERSION == 4
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with raw_connection(account_store) as connection:
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        indexes = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            )
        }
    assert tables == {"users", "devices", "sessions", "invites"}
    assert {"idx_devices_user_id", "idx_sessions_user_id", "idx_sessions_expires_at"} <= indexes


def test_initialization_is_idempotent_and_preserves_data(store):
    created = store.create_user("alice", "alice@example.com", "correct horse battery staple")
    store.initialize()
    assert store.get_user_by_id(created.id) == created


def test_store_connections_enable_foreign_keys(store):
    connection = store._connect()
    try:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        connection.close()


@pytest.mark.parametrize("version", [5, 99])
def test_newer_schema_version_fails_closed(tmp_path, version):
    path = tmp_path / "accounts.db"
    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA user_version = {version}")
    with pytest.raises(UnsupportedSchemaVersion, match="newer"):
        AccountStore(path).initialize()


def test_unversioned_nonempty_database_is_not_silently_migrated(tmp_path):
    path = tmp_path / "accounts.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE legacy (value TEXT)")
    with pytest.raises(UnsupportedSchemaVersion, match="no automatic migration"):
        AccountStore(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='legacy'"
        ).fetchone()


def test_current_version_with_incompatible_layout_fails(tmp_path):
    path = tmp_path / "accounts.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
        connection.execute("PRAGMA user_version = 1")
    with pytest.raises(AccountDatabaseError, match="incompatible table layout"):
        AccountStore(path).initialize()


def test_corrupt_database_fails_with_domain_error(tmp_path):
    path = tmp_path / "accounts.db"
    path.write_bytes(b"this is not sqlite")
    with pytest.raises(AccountDatabaseError, match="account database"):
        AccountStore(path).initialize()


def test_database_path_rejects_symlink_component(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(AccountDatabaseError, match="unsafe component"):
        AccountStore(link / "accounts.db").initialize()
    assert not (real / "accounts.db").exists()


def test_database_path_rejects_database_symlink(tmp_path):
    target = tmp_path / "target.db"
    target.write_bytes(b"")
    link = tmp_path / "accounts.db"
    link.symlink_to(target)
    with pytest.raises(AccountDatabaseError, match="non-symlink"):
        AccountStore(link).initialize()


def test_database_does_not_repermission_an_unsafe_shared_directory(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    with pytest.raises(AccountDatabaseError, match="mode 0700"):
        AccountStore(shared / "accounts.db").initialize()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    assert not (shared / "accounts.db").exists()


def test_create_and_retrieve_user_without_hash_exposure(store):
    created = store.create_user("Alice", "ALICE@Example.COM", "correct horse battery staple")
    assert isinstance(created, UserRecord)
    assert store.get_user_by_id(created.id) == created
    assert store.get_user_by_username(" ALICE ") == created
    assert store.get_user_by_email(" alice@EXAMPLE.com ") == created
    assert created.username == "alice"
    assert created.email == "alice@example.com"
    assert created.enabled is True
    assert "password" not in {field.name for field in fields(UserRecord)}
    assert "correct horse" not in repr(created)
    for timestamp in (created.created_at, created.updated_at):
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        assert parsed.utcoffset() == timedelta(0)


def test_duplicate_normalized_username_and_email_are_predictable(store):
    store.create_user("Alice", "first@example.com", "correct horse battery staple")
    with pytest.raises(AccountAlreadyExists, match="username"):
        store.create_user(" ALICE ", "second@example.com", "another secure passphrase")
    with pytest.raises(AccountAlreadyExists, match="email"):
        store.create_user("bob", " FIRST@example.COM ", "another secure passphrase")


@pytest.mark.parametrize(
    "username",
    ["", "   ", ".alice", "alice smith", "alice' OR 1=1 --", "a" * 65, None],
)
def test_invalid_username_rejected(store, username):
    with pytest.raises(InvalidAccountInput):
        store.create_user(username, "valid@example.com", "correct horse battery staple")


@pytest.mark.parametrize(
    "email",
    ["", "missing-at.example", "a@@example.com", ".a@example.com", "a..b@example.com",
     "a@-example.com", "a@example-.com", "a@exam ple.com", None],
)
def test_invalid_email_rejected(store, email):
    with pytest.raises(InvalidAccountInput):
        store.create_user("valid", email, "correct horse battery staple")


def test_user_enabled_state_blocks_password_verification(store):
    created = store.create_user("alice", "alice@example.com", "correct horse battery staple")
    assert store.verify_user_password("alice", "correct horse battery staple")
    disabled = store.set_user_enabled(created.id, False)
    assert disabled.enabled is False
    assert not store.verify_user_password("alice", "correct horse battery staple")
    enabled = store.set_user_enabled(created.id, True)
    assert enabled.enabled is True
    with pytest.raises(AccountNotFound):
        store.set_user_enabled(9999, False)


def test_password_hash_is_argon2id_and_plaintext_is_never_stored(store):
    password = "correct horse battery staple"
    created = store.create_user("alice", "alice@example.com", password)
    with raw_connection(store) as connection:
        stored = connection.execute(
            "SELECT password_hash FROM users WHERE id = ?", (created.id,)
        ).fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert stored != password
    assert password.encode() not in store.path.read_bytes()
    assert verify_password(stored, password)
    assert not verify_password(stored, "wrong password value")


def test_password_hash_helpers_fail_safely_and_detect_rehash():
    password = "correct horse battery staple"
    current = hash_password(password)
    old_parameters = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(password)
    assert verify_password(current, password)
    assert not verify_password("not-an-argon2-hash", password)
    assert not verify_password("x" * 1025, password)
    assert not verify_password(current, "too short")
    assert needs_rehash(current) is False
    assert needs_rehash(old_parameters) is True
    assert needs_rehash("malformed") is True
    assert needs_rehash("x" * 1025) is True


def test_password_length_boundaries_and_no_secret_in_errors():
    assert hash_password("a" * MIN_PASSWORD_LENGTH).startswith("$argon2id$")
    assert hash_password("b" * MAX_PASSWORD_LENGTH).startswith("$argon2id$")
    for password in ("x" * (MIN_PASSWORD_LENGTH - 1), "y" * (MAX_PASSWORD_LENGTH + 1)):
        with pytest.raises(InvalidAccountInput) as raised:
            hash_password(password)
        assert password not in str(raised.value)


def test_add_and_list_multiple_devices(store, user):
    first_public, first_fingerprint, _ = public_identity()
    second_public, second_fingerprint, _ = public_identity()
    first = store.add_device(user.id, " Alice Laptop ", first_fingerprint, first_public)
    second = store.add_device(user.id, "Alice Phone", second_fingerprint, second_public)
    assert isinstance(first, DeviceRecord)
    assert first.device_name == "Alice Laptop"
    assert first.client_public_key == first_public
    assert store.get_device_by_fingerprint(first_fingerprint) == first
    assert store.list_devices_for_user(user.id) == [first, second]


def test_duplicate_fingerprint_unknown_user_and_invalid_identity(store, user):
    public, identity_fingerprint, _ = public_identity()
    store.add_device(user.id, "Laptop", identity_fingerprint, public)
    with pytest.raises(AccountAlreadyExists, match="fingerprint"):
        store.add_device(user.id, "Duplicate", identity_fingerprint, public)
    other_public, other_fingerprint, _ = public_identity()
    with pytest.raises(AccountNotFound, match="user"):
        store.add_device(9999, "Unknown", other_fingerprint, other_public)
    with pytest.raises(InvalidAccountInput, match="lowercase"):
        store.add_device(user.id, "Uppercase", identity_fingerprint.upper(), public)
    with pytest.raises(InvalidAccountInput, match="mismatch"):
        store.add_device(user.id, "Mismatch", "0" * 64, public)
    with pytest.raises(InvalidAccountInput, match="exactly 32"):
        store.add_device(user.id, "Private-ish", fingerprint(b"x" * 31), b"x" * 31)


_V1_SCHEMA = (
    """CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE devices (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
        device_name TEXT NOT NULL, client_fingerprint TEXT NOT NULL UNIQUE,
        client_public_key BLOB NOT NULL CHECK (length(client_public_key) = 32),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)""",
    """CREATE TABLE sessions (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
        token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT,
        last_used_at TEXT, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)""",
    "CREATE INDEX idx_devices_user_id ON devices(user_id)",
    "CREATE INDEX idx_sessions_user_id ON sessions(user_id)",
    "CREATE INDEX idx_sessions_expires_at ON sessions(expires_at)",
)


def test_version_1_database_migrates_with_devices_pending(tmp_path):
    path = tmp_path / "accounts" / "accounts.db"
    path.parent.mkdir(mode=0o700)
    public, identity_fingerprint, _ = public_identity()
    with sqlite3.connect(path) as connection:
        for statement in _V1_SCHEMA:
            connection.execute(statement)
        connection.execute(
            "INSERT INTO users VALUES (1, 'alice', 'alice@example.com', ?, 1, 't', 't')",
            (hash_password("correct horse battery staple"),),
        )
        connection.execute(
            "INSERT INTO devices VALUES (1, 1, 'Laptop', ?, ?, 1, 't', 't')",
            (identity_fingerprint, public),
        )
        connection.execute("PRAGMA user_version = 1")
    store = AccountStore(path)
    store.initialize()
    assert store.schema_version() == 4
    device = store.get_device_by_fingerprint(identity_fingerprint)
    assert device.status == "pending" and device.client_public_key == public
    assert store.authenticate_user("alice", "correct horse battery staple") is not None
    store.initialize()  # idempotent after migration
    assert store.get_device_by_id(1) == device


def test_version_1_with_incompatible_layout_is_not_migrated(tmp_path):
    path = tmp_path / "accounts.db"
    with sqlite3.connect(path) as connection:
        for statement in _V1_SCHEMA:
            connection.execute(statement)
        connection.execute("ALTER TABLE devices ADD COLUMN surprise TEXT")
        connection.execute("PRAGMA user_version = 1")
    with pytest.raises(AccountDatabaseError, match="incompatible columns"):
        AccountStore(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1


def test_device_review_status_is_compare_and_set(store, user):
    public, identity_fingerprint, _ = public_identity()
    device = store.add_device(user.id, "Laptop", identity_fingerprint, public)
    assert device.status == "pending"
    assert store.list_devices("pending") == [device]
    approved = store.set_device_status(device.id, "approved", expected=("pending",))
    assert approved.status == "approved"
    with pytest.raises(InvalidAccountInput, match="approved"):
        store.set_device_status(device.id, "rejected", expected=("pending",))
    assert store.get_device_by_id(device.id).status == "approved"
    with pytest.raises(InvalidAccountInput, match="status"):
        store.set_device_status(device.id, "trusted")
    with pytest.raises(AccountNotFound):
        store.set_device_status(9999, "revoked")
    assert store.list_devices("pending") == []
    assert [d.id for d in store.list_devices()] == [device.id]
    with raw_connection(store) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute("UPDATE devices SET status = 'trusted'")


def test_device_can_be_disabled_independently(store, user):
    public, identity_fingerprint, _ = public_identity()
    device = store.add_device(user.id, "Laptop", identity_fingerprint, public)
    disabled = store.set_device_enabled(device.id, False)
    assert disabled.enabled is False
    assert store.get_user_by_id(user.id).enabled is True
    assert store.set_device_enabled(device.id, True).enabled is True
    store.set_user_enabled(user.id, False)
    assert store.get_device_by_fingerprint(identity_fingerprint).enabled is True
    with pytest.raises(AccountNotFound):
        store.set_device_enabled(9999, False)


def test_device_and_session_ownership_cascade(store, user):
    public, identity_fingerprint, _ = public_identity()
    store.add_device(user.id, "Laptop", identity_fingerprint, public)
    now = datetime.now(timezone.utc)
    with raw_connection(store) as connection:
        connection.execute(
            """
            INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (user.id, b"h" * 32, now.isoformat(), (now + timedelta(hours=1)).isoformat()),
        )
        connection.execute("DELETE FROM users WHERE id = ?", (user.id,))
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_session_schema_hash_only_and_foreign_key(store, user):
    with raw_connection(store) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(sessions)")]
        now = datetime.now(timezone.utc)
        connection.execute(
            "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (user.id, b"t" * 32, now.isoformat(), (now + timedelta(days=1)).isoformat()),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (9999, b"u" * 32, now.isoformat(), (now + timedelta(days=1)).isoformat()),
            )
    assert columns == [
        "id", "user_id", "token_hash", "created_at", "expires_at", "revoked_at", "last_used_at"
    ]
    assert "token" not in columns
    assert "raw_token" not in columns
    assert {field.name for field in fields(SessionRecord)} == set(columns)


def test_schema_has_no_client_private_key_and_database_contains_public_only(store, user):
    public, identity_fingerprint, private = public_identity()
    store.add_device(user.id, "Laptop", identity_fingerprint, public)
    with raw_connection(store) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(devices)")]
        stored = connection.execute("SELECT client_public_key FROM devices").fetchone()[0]
    assert "private" not in " ".join(columns).lower()
    assert bytes(stored) == public
    assert private not in store.path.read_bytes()


def test_sql_injection_shaped_values_are_data_not_sql(store):
    device_name = "Laptop'); DROP TABLE users; --"
    created = store.create_user("alice", "'or1@example.com", "correct horse battery staple")
    public, identity_fingerprint, _ = public_identity()
    device = store.add_device(created.id, device_name, identity_fingerprint, public)
    assert device.device_name == device_name
    assert store.get_user_by_email("'OR1@example.com") == created
    assert store.get_user_by_id(created.id) == created


def test_account_mutations_never_change_vpn_authorization(tmp_path):
    authorized_path = tmp_path / "authorized_clients.json"
    authorized_public, _, _ = public_identity()
    AuthorizedClients(authorized_path).authorize(authorized_public, "already-authorized")
    before = authorized_path.read_bytes()

    account_store = AccountStore(tmp_path / "accounts" / "accounts.db")
    account_store.initialize()
    created = account_store.create_user(
        "alice", "alice@example.com", "correct horse battery staple"
    )
    bound_public, bound_fingerprint, _ = public_identity()
    account_store.add_device(created.id, "Bound but not authorized", bound_fingerprint, bound_public)

    assert authorized_path.read_bytes() == before
    assert AuthorizedClients(authorized_path).find(bound_public) is None
    assert AuthorizedClients(authorized_path).find(authorized_public) is not None


def test_argon2_dependency_is_declared_for_python_arch_and_debian():
    root = Path(__file__).parents[1]
    assert '"argon2-cffi==25.1.0"' in (root / "pyproject.toml").read_text()
    assert "argon2-cffi==25.1.0" in (root / "constraints-tested.txt").read_text()
    assert "'python-argon2-cffi'" in (root / "packaging/arch/PKGBUILD").read_text()
    assert "python3-argon2" in (root / "packaging/deb/debian/control").read_text()


# ─── Milestone 4.5: administrator device approval (vpn.cli account) ───────

def _cli(*argv: str) -> None:
    from vpn.cli import main
    main(list(argv))


@pytest.fixture
def review(tmp_path, store, user):
    public, identity_fingerprint, _ = public_identity()
    device = store.add_device(user.id, "Laptop", identity_fingerprint, public)
    authorized = tmp_path / "authorized_clients.json"
    return store, device, authorized, ("--accounts-db", str(store.path))


def test_admin_lists_pending_devices(review, capsys):
    store, device, _authorized, db = review
    _cli("account", "devices", "--status", "pending", *db)
    out = capsys.readouterr().out
    assert device.client_fingerprint in out and "alice" in out and "pending" in out
    _cli("account", "devices", "--status", "approved", *db)
    assert "No devices" in capsys.readouterr().out


def test_admin_approval_is_the_only_path_into_authorized_clients(review):
    store, device, authorized, db = review
    assert not authorized.exists()  # binding alone never authorizes
    _cli("account", "approve", str(device.id), *db, "--database", str(authorized))
    record = AuthorizedClients(authorized).find(device.client_public_key)
    assert record["client_id"] == f"alice-{device.id}" and record["enabled"] is True
    assert store.get_device_by_id(device.id).status == "approved"
    with pytest.raises(SystemExit, match="already approved"):
        _cli("account", "approve", str(device.id), *db, "--database", str(authorized))


def test_admin_reject_leaves_vpn_authorization_untouched(review):
    store, device, authorized, db = review
    _cli("account", "reject", str(device.id), *db)
    assert store.get_device_by_id(device.id).status == "rejected"
    assert not authorized.exists()
    with pytest.raises(SystemExit, match="only pending"):
        _cli("account", "reject", str(device.id), *db)


def test_admin_revoke_disables_tunnel_authorization(review):
    store, device, authorized, db = review
    with pytest.raises(SystemExit, match="only approved"):
        _cli("account", "revoke", str(device.id), *db, "--database", str(authorized))
    _cli("account", "approve", str(device.id), *db, "--database", str(authorized))
    with pytest.raises(SystemExit, match="account revoke"):
        _cli("account", "reject", str(device.id), *db)
    _cli("account", "revoke", str(device.id), *db, "--database", str(authorized))
    assert AuthorizedClients(authorized).find(device.client_public_key) is None
    assert store.get_device_by_id(device.id).status == "revoked"
    # An explicit re-approval is allowed after revocation.
    _cli("account", "approve", str(device.id), *db, "--database", str(authorized))
    assert AuthorizedClients(authorized).find(device.client_public_key) is not None


def test_admin_refuses_disabled_account_or_device(review):
    store, device, authorized, db = review
    store.set_device_enabled(device.id, False)
    with pytest.raises(SystemExit, match="disabled"):
        _cli("account", "approve", str(device.id), *db, "--database", str(authorized))
    store.set_device_enabled(device.id, True)
    store.set_user_enabled(device.user_id, False)
    with pytest.raises(SystemExit, match="disabled"):
        _cli("account", "approve", str(device.id), *db, "--database", str(authorized))
    assert not authorized.exists()
    assert store.get_device_by_id(device.id).status == "pending"


def test_admin_unknown_device_and_bad_vpn_ip(review):
    store, device, authorized, db = review
    with pytest.raises(SystemExit, match="not found"):
        _cli("account", "approve", "999", *db, "--database", str(authorized))
    with pytest.raises(SystemExit, match="account error"):
        _cli("account", "approve", str(device.id), *db, "--database", str(authorized),
             "--vpn-ip", "not-an-ip")
    assert store.get_device_by_id(device.id).status == "pending"


# --- TOTP ---

def test_totp_compute_and_verify():
    secret = generate_totp_secret()
    code = compute_totp(secret)
    assert verify_totp(secret, code)
    assert not verify_totp(secret, "000000")
    assert not verify_totp(secret, "short")
    assert not verify_totp(secret, "abcdef")


def test_totp_enable_disable_flow(store, user):
    assert not user.mfa_enabled
    secret = generate_totp_secret()
    store.enable_totp(user.id, secret)
    fetched = store.get_user_by_id(user.id)
    assert fetched.mfa_enabled
    assert store.get_totp_secret(user.id) == secret
    store.disable_totp(user.id)
    fetched = store.get_user_by_id(user.id)
    assert not fetched.mfa_enabled
    assert store.get_totp_secret(user.id) is None


def test_totp_required_when_enabled(store, user):
    """authenticate_user succeeds but the caller must check mfa_enabled."""
    secret = generate_totp_secret()
    store.enable_totp(user.id, secret)
    result = store.authenticate_user("alice", "correct horse battery staple")
    assert result is not None
    assert result.mfa_enabled


# --- Account lockout ---

def test_account_lockout_after_failures(store, user):
    for _ in range(LOCKOUT_THRESHOLD):
        store.authenticate_user("alice", "wrong-password")
    with pytest.raises(AccountLocked):
        store.authenticate_user("alice", "correct horse battery staple")


def test_account_unlock(store, user):
    for _ in range(LOCKOUT_THRESHOLD):
        store.authenticate_user("alice", "wrong-password")
    store.unlock_account(user.id)
    result = store.authenticate_user("alice", "correct horse battery staple")
    assert result is not None


def test_successful_login_resets_failure_count(store, user):
    for _ in range(LOCKOUT_THRESHOLD - 1):
        store.authenticate_user("alice", "wrong-password")
    result = store.authenticate_user("alice", "correct horse battery staple")
    assert result is not None
    for _ in range(LOCKOUT_THRESHOLD - 1):
        store.authenticate_user("alice", "wrong-password")
    result = store.authenticate_user("alice", "correct horse battery staple")
    assert result is not None


# --- Password management ---

def test_admin_password_reset(store, user):
    store.set_password(user.id, "new-secure-password-123")
    result = store.authenticate_user("alice", "new-secure-password-123")
    assert result is not None
    assert result.password_change_required


def test_user_change_password(store, user):
    store.change_password(user.id, "correct horse battery staple", "new-secure-password-123")
    assert store.authenticate_user("alice", "correct horse battery staple") is None
    result = store.authenticate_user("alice", "new-secure-password-123")
    assert result is not None


def test_change_password_wrong_old(store, user):
    with pytest.raises(InvalidAccountInput, match="incorrect"):
        store.change_password(user.id, "wrong-old-password", "new-secure-password-123")


# --- Schema migration ---

def test_v2_to_v3_migration(tmp_path):
    db_path = tmp_path / "accounts" / "accounts.db"
    db_path.parent.mkdir(mode=0o700)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            last_used_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            device_name TEXT NOT NULL,
            client_fingerprint TEXT NOT NULL UNIQUE,
            client_public_key BLOB NOT NULL CHECK (length(client_public_key) = 32),
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'approved', 'rejected', 'revoked'))
        )
    """)
    conn.execute("CREATE INDEX idx_devices_user_id ON devices(user_id)")
    conn.execute("CREATE INDEX idx_sessions_user_id ON sessions(user_id)")
    conn.execute("CREATE INDEX idx_sessions_expires_at ON sessions(expires_at)")
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()
    os.chmod(db_path, 0o600)
    store = AccountStore(db_path)
    store.initialize()
    assert store.schema_version() == 4
    user = store.create_user("bob", "bob@example.com", "secure-password-1234")
    assert not user.mfa_enabled
    assert user.locked_until is None
    assert not user.password_change_required


# --- CLI reset-password / unlock ---

def test_cli_reset_password(review):
    store, _device, _authorized, db = review
    _cli("account", "reset-password", "alice", "new-password-12345", *db)
    result = store.authenticate_user("alice", "new-password-12345")
    assert result is not None
    assert result.password_change_required


def test_cli_unlock(review):
    store, _device, _authorized, db = review
    for _ in range(LOCKOUT_THRESHOLD):
        store.authenticate_user("alice", "wrong")
    with pytest.raises(AccountLocked):
        store.authenticate_user("alice", "correct horse battery staple")
    _cli("account", "unlock", "alice", *db)
    result = store.authenticate_user("alice", "correct horse battery staple")
    assert result is not None


# --- Registration invites ---

PW = "correct horse battery staple"


def test_invite_code_has_256_bits_and_only_its_hash_is_stored(store):
    invite_id, code = store.create_invite()
    assert len(code) == 43  # token_urlsafe(32): 256 random bits
    with raw_connection(store) as connection:
        row = connection.execute("SELECT * FROM invites WHERE id = ?", (invite_id,)).fetchone()
    assert code.encode() not in b"".join(
        value if isinstance(value, bytes) else str(value).encode() for value in row
    )
    assert invite_code_hash(code) in row
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_single_use_invite_is_consumed_once(store):
    _id, code = store.create_invite()
    assert store.create_user("alice", "alice@example.com", PW, invite_code=code)
    with pytest.raises(InvalidInvite):
        store.create_user("bob", "bob@example.com", PW, invite_code=code)
    assert store.list_invites()[0].uses_left == 0


def test_duplicate_account_does_not_burn_invite(store, user):
    _id, code = store.create_invite()
    with pytest.raises(AccountAlreadyExists):
        store.create_user("alice", "other@example.com", PW, invite_code=code)
    assert store.list_invites()[0].uses_left == 1
    assert store.create_user("bob", "bob@example.com", PW, invite_code=code)


def test_invalid_invite_is_checked_before_duplicates(store, user):
    """Without a valid invite, callers cannot probe which accounts exist."""
    with pytest.raises(InvalidInvite):
        store.create_user("alice", "alice@example.com", PW, invite_code="guess")


@pytest.mark.parametrize("state", ["unknown", "empty", "expired", "exhausted", "revoked"])
def test_every_invalid_invite_state_raises_the_same_error(store, state):
    invite_id, code = store.create_invite()
    if state == "unknown":
        code = code[:-1] + ("A" if code[-1] != "A" else "B")
    elif state == "empty":
        code = ""
    elif state == "expired":
        with raw_connection(store) as connection:
            connection.execute("UPDATE invites SET expires_at = '2000-01-01T00:00:00.000000Z'")
    elif state == "exhausted":
        store.create_user("first", "first@example.com", PW, invite_code=code)
    else:
        store.revoke_invite(invite_id)
    with pytest.raises(InvalidInvite) as exc_info:
        store.create_user("bob", "bob@example.com", PW, invite_code=code)
    assert str(exc_info.value) == "a valid invite code is required"
    assert store.get_user_by_username("bob") is None


def test_multi_use_invite_and_future_expiry(store):
    _id, code = store.create_invite(2, datetime.now(timezone.utc) + timedelta(hours=1))
    store.create_user("a1", "a1@example.com", PW, invite_code=code)
    store.create_user("a2", "a2@example.com", PW, invite_code=code)
    with pytest.raises(InvalidInvite):
        store.create_user("a3", "a3@example.com", PW, invite_code=code)


@pytest.mark.parametrize("uses", [0, -1, 1001, True])
def test_invite_use_bounds(store, uses):
    with pytest.raises(InvalidAccountInput):
        store.create_invite(uses)


def test_invite_expiry_must_be_future(store):
    with pytest.raises(InvalidAccountInput):
        store.create_invite(1, datetime.now(timezone.utc) - timedelta(seconds=1))


def test_concurrent_registrations_cannot_share_single_use_invite(store):
    import threading
    _id, code = store.create_invite()
    results: list[str] = []
    barrier = threading.Barrier(6)

    def attempt(index: int) -> None:
        barrier.wait()
        try:
            AccountStore(store.path).create_user(
                f"user{index}", f"user{index}@example.com", PW, invite_code=code
            )
            results.append("ok")
        except InvalidInvite:
            results.append("invite")

    threads = [threading.Thread(target=attempt, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert sorted(results) == ["invite"] * 5 + ["ok"]


def test_version_3_database_migrates_to_invites(tmp_path):
    store = AccountStore(tmp_path / "accounts" / "accounts.db")
    store.initialize()
    created = store.create_user("alice", "alice@example.com", PW)
    with raw_connection(store) as connection:
        connection.execute("DROP TABLE invites")
        connection.execute("PRAGMA user_version = 3")
    store.initialize()
    assert store.schema_version() == 4
    assert store.get_user_by_id(created.id) == created
    assert store.list_invites() == []


def test_cli_invite_lifecycle_never_shows_hash(store, capsys):
    db = ("--accounts-db", str(store.path))
    _cli("account", "invite-create", "--uses", "2", "--expires-hours", "24", *db)
    created = capsys.readouterr().out
    code = created.rsplit(": ", 1)[1].strip()
    assert len(code) == 43
    _cli("account", "invites", *db)
    listing = capsys.readouterr().out
    assert "uses_left=2" in listing and code not in listing
    assert invite_code_hash(code).hex() not in listing
    store.create_user("bob", "bob@example.com", PW, invite_code=code)
    _cli("account", "invite-revoke", "1", *db)
    assert store.list_invites() == []
    with pytest.raises(InvalidInvite):
        store.create_user("carol", "carol@example.com", PW, invite_code=code)
    with pytest.raises(SystemExit):
        _cli("account", "invite-revoke", "1", *db)
    with pytest.raises(SystemExit):
        _cli("account", "invite-create", "--expires-hours", "0", *db)
