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
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    SCHEMA_VERSION,
    AccountAlreadyExists,
    AccountDatabaseError,
    AccountNotFound,
    AccountStore,
    DeviceRecord,
    InvalidAccountInput,
    SessionRecord,
    UnsupportedSchemaVersion,
    UserRecord,
    hash_password,
    needs_rehash,
    verify_password,
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

    assert account_store.schema_version() == SCHEMA_VERSION == 2
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
    assert tables == {"users", "devices", "sessions"}
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


@pytest.mark.parametrize("version", [3, 99])
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
    assert store.schema_version() == 2
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
