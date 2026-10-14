"""Server-side account, device ownership, and session-schema persistence."""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import os
import re
import secrets
import sqlite3
import stat
import struct
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from argon2 import PasswordHasher
from argon2.exceptions import HashingError, InvalidHashError, VerificationError

from vpn.identity import fingerprint


SCHEMA_VERSION = 3
DEVICE_STATUSES = ("pending", "approved", "rejected", "revoked")
DEFAULT_ACCOUNT_DATABASE = Path("/var/lib/pqvpn/accounts/accounts.db")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
MAX_USERNAME_LENGTH = 64
MAX_EMAIL_LENGTH = 254
MAX_DEVICE_NAME_LENGTH = 100
LOCKOUT_THRESHOLD = 10
LOCKOUT_DURATION_SECONDS = 900

_USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
_PASSWORD_HASHER = PasswordHasher()
# Generated once with the same Argon2id policy. It gives unknown login
# identifiers the same expensive verification path as a wrong password without
# representing a usable account credential.
_DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$B5CsoZZWdy3XY8OhPPm6pA$"
    "1RvMzjIkQCKYsB9zqTKCN2tljKBW7UQgQ+YkHvRWvGY"
)


class AccountError(Exception):
    """Base class for account-domain failures safe to surface to callers."""


class AccountAlreadyExists(AccountError):
    """A unique account or device identity already exists."""


class InvalidAccountInput(AccountError, ValueError):
    """Account input failed validation."""


class AccountNotFound(AccountError):
    """A referenced account or device does not exist."""


class AccountDatabaseError(AccountError):
    """The account database is unavailable, corrupt, or incompatible."""


class UnsupportedSchemaVersion(AccountDatabaseError):
    """The database schema cannot be opened by this application version."""


class PasswordHashError(AccountError):
    """Argon2id could not safely process a password hash."""


class AccountLocked(AccountError):
    """The account is temporarily locked after too many failed login attempts."""
    def __init__(self, locked_until: str):
        self.locked_until = locked_until
        super().__init__("account is temporarily locked")


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    email: str
    enabled: bool
    created_at: str
    updated_at: str
    mfa_enabled: bool = False
    locked_until: str | None = None
    password_change_required: bool = False


@dataclass(frozen=True)
class DeviceRecord:
    id: int
    user_id: int
    device_name: str
    client_fingerprint: str
    client_public_key: bytes
    enabled: bool
    created_at: str
    updated_at: str
    status: str = "pending"


@dataclass(frozen=True)
class SessionRecord:
    id: int
    user_id: int
    token_hash: bytes
    created_at: str
    expires_at: str
    revoked_at: str | None
    last_used_at: str | None


def _validate_password(password: object) -> str:
    if not isinstance(password, str):
        raise InvalidAccountInput("password must be text")
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise InvalidAccountInput(
            f"password must contain {MIN_PASSWORD_LENGTH}..{MAX_PASSWORD_LENGTH} characters"
        )
    return password


def hash_password(password: str) -> str:
    """Hash a bounded password with argon2-cffi's current Argon2id defaults."""
    validated = _validate_password(password)
    try:
        return _PASSWORD_HASHER.hash(validated)
    except HashingError as exc:
        raise PasswordHashError("unable to hash password") from exc


def verify_password(password_hash: str, password: str) -> bool:
    """Return False for a mismatch, malformed hash, or out-of-policy input."""
    if not isinstance(password_hash, str) or len(password_hash) > 1024:
        return False
    try:
        validated = _validate_password(password)
        return bool(_PASSWORD_HASHER.verify(password_hash, validated))
    except (InvalidAccountInput, InvalidHashError, VerificationError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return True when a hash is malformed or no longer uses current defaults."""
    if not isinstance(password_hash, str) or len(password_hash) > 1024:
        return True
    try:
        return bool(_PASSWORD_HASHER.check_needs_rehash(password_hash))
    except (InvalidHashError, VerificationError):
        return True


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def compute_totp(secret_b32: str, now: float | None = None, period: int = 30) -> str:
    key = base64.b32decode(secret_b32)
    counter = struct.pack(">Q", int((now or time.time()) // period))
    mac = _hmac.new(key, counter, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def verify_totp(secret_b32: str, code: str, *, window: int = 1) -> bool:
    if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
        return False
    now = time.time()
    return any(_hmac.compare_digest(compute_totp(secret_b32, now + offset * 30), code)
               for offset in range(-window, window + 1))


def totp_provisioning_uri(secret_b32: str, username: str, issuer: str = "PQVPN") -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret_b32}&issuer={quote(issuer)}"


def normalize_username(username: object) -> str:
    """Normalize usernames to lowercase NFKC ASCII identifiers."""
    if not isinstance(username, str):
        raise InvalidAccountInput("username must be text")
    normalized = unicodedata.normalize("NFKC", username.strip()).casefold()
    if not _USERNAME_RE.fullmatch(normalized):
        raise InvalidAccountInput(
            "username must be 1..64 lowercase letters, digits, dots, underscores, or hyphens"
        )
    return normalized


def normalize_email(email: object) -> str:
    """Trim and case-fold a basic local@domain address without full RFC parsing."""
    if not isinstance(email, str):
        raise InvalidAccountInput("email must be text")
    normalized = unicodedata.normalize("NFKC", email.strip()).casefold()
    if not 3 <= len(normalized) <= MAX_EMAIL_LENGTH or normalized.count("@") != 1:
        raise InvalidAccountInput("email must be a valid address of reasonable length")
    local, domain = normalized.split("@")
    if (
        not local
        or len(local) > 64
        or not domain
        or len(domain) > 253
        or any(character.isspace() or unicodedata.category(character).startswith("C")
               for character in normalized)
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
    ):
        raise InvalidAccountInput("email must be a valid address of reasonable length")
    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isascii() and (character.isalnum() or character == "-")
                   for character in label)
        for label in labels
    ):
        raise InvalidAccountInput("email must be a valid address of reasonable length")
    return normalized


def _validate_device_name(device_name: object) -> str:
    if not isinstance(device_name, str):
        raise InvalidAccountInput("device name must be text")
    normalized = unicodedata.normalize("NFKC", device_name.strip())
    if (
        not 1 <= len(normalized) <= MAX_DEVICE_NAME_LENGTH
        or any(unicodedata.category(character).startswith("C") for character in normalized)
    ):
        raise InvalidAccountInput("device name must contain 1..100 non-control characters")
    return normalized


def _validate_device_status(status: object) -> str:
    if status not in DEVICE_STATUSES:
        raise InvalidAccountInput(f"device status must be one of {', '.join(DEVICE_STATUSES)}")
    return status


def _validate_enabled(enabled: object) -> bool:
    if type(enabled) is not bool:
        raise InvalidAccountInput("enabled must be boolean")
    return enabled


def _validate_id(value: object, description: str) -> int:
    if type(value) is not int or value < 1:
        raise InvalidAccountInput(f"{description} must be a positive integer")
    return value


def _validate_public_identity(client_fingerprint: object, client_public_key: object) -> tuple[str, bytes]:
    if not isinstance(client_fingerprint, str) or not _FINGERPRINT_RE.fullmatch(client_fingerprint):
        raise InvalidAccountInput("client fingerprint must be lowercase SHA-256 hex")
    if not isinstance(client_public_key, bytes) or len(client_public_key) != 32:
        raise InvalidAccountInput("client public key must be exactly 32 public Ed25519 bytes")
    if fingerprint(client_public_key) != client_fingerprint:
        raise InvalidAccountInput("client public key/fingerprint mismatch")
    return client_fingerprint, client_public_key


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_timestamp(value: datetime, description: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InvalidAccountInput(f"{description} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise AccountDatabaseError("account database contains an invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AccountDatabaseError("account database contains a non-UTC timestamp")
    return parsed.astimezone(timezone.utc)


def _validate_token_hash(token_hash: object) -> bytes:
    if not isinstance(token_hash, bytes) or len(token_hash) != 32:
        raise InvalidAccountInput("session token hash must be exactly 32 bytes")
    return token_hash


def _safe_database_parent(path: Path) -> None:
    """Create the state directory at 0700 and reject symlink path components."""
    absolute = path.absolute()
    current = Path(absolute.anchor)
    target_created = False
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
                if current == absolute:
                    target_created = True
            except FileExistsError:
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise AccountDatabaseError("account database path contains an unsafe component")
            continue
        except OSError as exc:
            raise AccountDatabaseError("unable to inspect account database directory") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise AccountDatabaseError("account database path contains an unsafe component")
    try:
        if target_created:
            os.chmod(absolute, 0o700, follow_symlinks=False)
        elif stat.S_IMODE(absolute.lstat().st_mode) != 0o700:
            raise AccountDatabaseError("account database directory must have mode 0700")
    except AccountDatabaseError:
        raise
    except OSError as exc:
        raise AccountDatabaseError("unable to secure account database directory") from exc


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        totp_secret TEXT,
        failed_login_count INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        password_change_required INTEGER NOT NULL DEFAULT 0
            CHECK (password_change_required IN (0, 1))
    )
    """,
    """
    CREATE TABLE devices (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        device_name TEXT NOT NULL,
        client_fingerprint TEXT NOT NULL UNIQUE
            CHECK (length(client_fingerprint) = 64
                   AND client_fingerprint NOT GLOB '*[^0-9a-f]*'),
        client_public_key BLOB NOT NULL CHECK (length(client_public_key) = 32),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE sessions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        last_used_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX idx_devices_user_id ON devices(user_id)",
    "CREATE INDEX idx_sessions_user_id ON sessions(user_id)",
    "CREATE INDEX idx_sessions_expires_at ON sessions(expires_at)",
)

# Version 1 → 2 adds the administrator review state. Existing bindings start as
# pending: no version 1 device was ever approved through the account workflow.
_MIGRATION_V2 = (
    """
    ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'revoked'))
    """,
)

_MIGRATION_V3 = (
    "ALTER TABLE users ADD COLUMN totp_secret TEXT",
    "ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN locked_until TEXT",
    """ALTER TABLE users ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 0
        CHECK (password_change_required IN (0, 1))""",
)

_EXPECTED_COLUMNS = {
    "users": (
        "id", "username", "email", "password_hash", "enabled", "created_at", "updated_at",
        "totp_secret", "failed_login_count", "locked_until", "password_change_required"
    ),
    "devices": (
        "id", "user_id", "device_name", "client_fingerprint", "client_public_key",
        "enabled", "created_at", "updated_at", "status"
    ),
    "sessions": (
        "id", "user_id", "token_hash", "created_at", "expires_at", "revoked_at",
        "last_used_at"
    ),
}
_EXPECTED_INDEXES = {"idx_devices_user_id", "idx_sessions_user_id", "idx_sessions_expires_at"}
_USER_COLUMNS = (
    "id, username, email, enabled, created_at, updated_at, "
    "totp_secret, locked_until, password_change_required"
)
_DEVICE_COLUMNS = (
    "id, user_id, device_name, client_fingerprint, client_public_key, "
    "enabled, created_at, updated_at, status"
)


class AccountStore:
    """SQLite persistence for accounts and device ownership, never VPN authorization."""

    def __init__(self, path: Path | str = DEFAULT_ACCOUNT_DATABASE):
        self.path = Path(path).absolute()

    def _prepare_path(self) -> None:
        _safe_database_parent(self.path.parent)
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(self.path, flags, 0o600)
            except FileExistsError:
                info = self.path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise AccountDatabaseError("account database must be a regular non-symlink file")
            except OSError as exc:
                raise AccountDatabaseError("unable to create account database") from exc
            else:
                try:
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                return
        except OSError as exc:
            raise AccountDatabaseError("unable to inspect account database") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise AccountDatabaseError("account database must be a regular non-symlink file")
        try:
            os.chmod(self.path, 0o600, follow_symlinks=False)
        except OSError as exc:
            raise AccountDatabaseError("unable to secure account database") from exc

    def _connect(self) -> sqlite3.Connection:
        self._prepare_path()
        try:
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA busy_timeout = 5000")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise AccountDatabaseError("SQLite foreign-key enforcement is unavailable")
            return connection
        except AccountDatabaseError:
            try:
                connection.close()
            except UnboundLocalError:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.close()
            except UnboundLocalError:
                pass
            raise AccountDatabaseError("unable to open account database") from exc

    @contextmanager
    def _connection(self, *, current_schema: bool = True) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            if current_schema:
                self._require_current_version(connection)
            yield connection
        except AccountError:
            raise
        except sqlite3.Error as exc:
            raise AccountDatabaseError("account database operation failed") from exc
        finally:
            connection.close()

    @staticmethod
    def _version(connection: sqlite3.Connection) -> int:
        return int(connection.execute("PRAGMA user_version").fetchone()[0])

    @classmethod
    def _require_current_version(cls, connection: sqlite3.Connection) -> None:
        version = cls._version(connection)
        if version > SCHEMA_VERSION:
            raise UnsupportedSchemaVersion(
                f"account schema version {version} is newer than supported version {SCHEMA_VERSION}"
            )
        if version != SCHEMA_VERSION:
            raise UnsupportedSchemaVersion(
                f"account schema version {version} is not supported; run initialize() to migrate"
            )

    @staticmethod
    def _application_tables(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        return {str(row[0]) for row in rows}

    @classmethod
    def _validate_schema(cls, connection: sqlite3.Connection, *, version: int = SCHEMA_VERSION) -> None:
        integrity = connection.execute("PRAGMA quick_check").fetchall()
        if len(integrity) != 1 or integrity[0][0] != "ok":
            raise AccountDatabaseError("account database integrity check failed")
        if cls._application_tables(connection) != set(_EXPECTED_COLUMNS):
            raise AccountDatabaseError("account database has an incompatible table layout")
        columns = dict(_EXPECTED_COLUMNS)
        if version <= 2:
            columns["users"] = columns["users"][:7]
        if version == 1:
            columns["devices"] = columns["devices"][:-1]
        for table, expected in columns.items():
            actual = tuple(row[1] for row in connection.execute(f'PRAGMA table_info("{table}")'))
            if actual != expected:
                raise AccountDatabaseError(f"account database table {table} has incompatible columns")
        indexes = {
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if not _EXPECTED_INDEXES.issubset(indexes):
            raise AccountDatabaseError("account database is missing required indexes")
        for table in ("devices", "sessions"):
            foreign_keys = connection.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
            if len(foreign_keys) != 1 or foreign_keys[0][2] != "users" or foreign_keys[0][6] != "CASCADE":
                raise AccountDatabaseError(f"account database table {table} has incompatible ownership rules")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise AccountDatabaseError("account database contains invalid ownership references")

    def initialize(self) -> None:
        """Create the current schema, migrate version 1, or validate a current database."""
        with self._connection(current_schema=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                version = self._version(connection)
                tables = self._application_tables(connection)
                if version == 0 and not tables:
                    for statement in _SCHEMA_STATEMENTS:
                        connection.execute(statement)
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                elif version == 1:
                    self._validate_schema(connection, version=1)
                    for statement in _MIGRATION_V2:
                        connection.execute(statement)
                    for statement in _MIGRATION_V3:
                        connection.execute(statement)
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                elif version == 2:
                    self._validate_schema(connection, version=2)
                    for statement in _MIGRATION_V3:
                        connection.execute(statement)
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                elif version > SCHEMA_VERSION:
                    raise UnsupportedSchemaVersion(
                        f"account schema version {version} is newer than supported version {SCHEMA_VERSION}"
                    )
                elif version != SCHEMA_VERSION:
                    raise UnsupportedSchemaVersion(
                        f"account schema version {version} is incompatible; no automatic migration exists"
                    )
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            self._require_current_version(connection)
            self._validate_schema(connection)

    def schema_version(self) -> int:
        with self._connection() as connection:
            return self._version(connection)

    @staticmethod
    def _user(row: sqlite3.Row | None) -> UserRecord | None:
        if row is None:
            return None
        return UserRecord(
            id=row["id"], username=row["username"], email=row["email"],
            enabled=bool(row["enabled"]), created_at=row["created_at"], updated_at=row["updated_at"],
            mfa_enabled=row["totp_secret"] is not None,
            locked_until=row["locked_until"],
            password_change_required=bool(row["password_change_required"]),
        )

    @staticmethod
    def _device(row: sqlite3.Row | None) -> DeviceRecord | None:
        if row is None:
            return None
        return DeviceRecord(
            id=row["id"], user_id=row["user_id"], device_name=row["device_name"],
            client_fingerprint=row["client_fingerprint"],
            client_public_key=bytes(row["client_public_key"]), enabled=bool(row["enabled"]),
            created_at=row["created_at"], updated_at=row["updated_at"], status=row["status"],
        )

    @staticmethod
    def _session(row: sqlite3.Row | None) -> SessionRecord | None:
        if row is None:
            return None
        return SessionRecord(
            id=row["id"], user_id=row["user_id"], token_hash=bytes(row["token_hash"]),
            created_at=row["created_at"], expires_at=row["expires_at"],
            revoked_at=row["revoked_at"], last_used_at=row["last_used_at"],
        )

    def create_user(self, username: str, email: str, password: str, *, enabled: bool = True) -> UserRecord:
        normalized_username = normalize_username(username)
        normalized_email = normalize_email(email)
        validated_enabled = _validate_enabled(enabled)
        password_hash = hash_password(password)
        now = _utc_now()
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM users WHERE username = ?", (normalized_username,)
                ).fetchone():
                    raise AccountAlreadyExists("username already exists")
                if connection.execute(
                    "SELECT 1 FROM users WHERE email = ?", (normalized_email,)
                ).fetchone():
                    raise AccountAlreadyExists("email already exists")
                cursor = connection.execute(
                    """
                    INSERT INTO users (username, email, password_hash, enabled, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (normalized_username, normalized_email, password_hash, int(validated_enabled), now, now),
                )
                row = connection.execute(
                    f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?",
                    (cursor.lastrowid,),
                ).fetchone()
                connection.commit()
            except AccountError:
                if connection.in_transaction:
                    connection.rollback()
                raise
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise AccountAlreadyExists("username or email already exists") from exc
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
        result = self._user(row)
        assert result is not None
        return result

    def get_user_by_id(self, user_id: int) -> UserRecord | None:
        validated = _validate_id(user_id, "user ID")
        with self._connection() as connection:
            return self._user(connection.execute(
                f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?",
                (validated,),
            ).fetchone())

    def get_user_by_username(self, username: str) -> UserRecord | None:
        normalized = normalize_username(username)
        with self._connection() as connection:
            return self._user(connection.execute(
                f"SELECT {_USER_COLUMNS} FROM users WHERE username = ?",
                (normalized,),
            ).fetchone())

    def get_user_by_email(self, email: str) -> UserRecord | None:
        normalized = normalize_email(email)
        with self._connection() as connection:
            return self._user(connection.execute(
                f"SELECT {_USER_COLUMNS} FROM users WHERE email = ?",
                (normalized,),
            ).fetchone())

    def verify_user_password(self, username: str, password: str) -> bool:
        normalized = normalize_username(username)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT password_hash, enabled FROM users WHERE username = ?", (normalized,)
            ).fetchone()
        if row is None or not bool(row["enabled"]):
            return False
        return verify_password(row["password_hash"], password)

    def authenticate_user(self, identifier: str, password: str) -> UserRecord | None:
        """Authenticate by normalized username or email with a generic failure path.

        Raises AccountLocked if the account has exceeded LOCKOUT_THRESHOLD
        failed attempts and the lockout period has not elapsed.
        """
        normalized: str | None
        try:
            normalized = normalize_email(identifier) if "@" in identifier else normalize_username(identifier)
        except (InvalidAccountInput, TypeError):
            normalized = None
        with self._connection() as connection:
            if normalized is None:
                row = None
            elif "@" in normalized:
                row = connection.execute(
                    f"""
                    SELECT {_USER_COLUMNS}, password_hash, failed_login_count
                    FROM users WHERE email = ?
                    """,
                    (normalized,),
                ).fetchone()
            else:
                row = connection.execute(
                    f"""
                    SELECT {_USER_COLUMNS}, password_hash, failed_login_count
                    FROM users WHERE username = ?
                    """,
                    (normalized,),
                ).fetchone()

        if row is not None:
            locked = row["locked_until"]
            if locked is not None and _parse_timestamp(locked) > datetime.now(timezone.utc):
                verify_password(row["password_hash"], password)
                raise AccountLocked(locked)

        candidate_hash = _DUMMY_PASSWORD_HASH if row is None else row["password_hash"]
        password_matches = verify_password(candidate_hash, password)
        if row is None or not password_matches or not bool(row["enabled"]):
            if row is not None and bool(row["enabled"]):
                self._record_failed_login(row["id"], row["failed_login_count"])
            return None

        self._reset_login_failures(row["id"])
        user = self._user(row)
        assert user is not None
        if needs_rehash(candidate_hash):
            replacement = hash_password(password)
            now = _utc_now()
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """
                    UPDATE users SET password_hash = ?, updated_at = ?
                    WHERE id = ? AND password_hash = ?
                    """,
                    (replacement, now, user.id, candidate_hash),
                )
                current = connection.execute(
                    f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?",
                    (user.id,),
                ).fetchone()
                connection.commit()
            if cursor.rowcount != 1:
                return None
            user = self._user(current)
            if user is None or not user.enabled:
                return None
        return user

    def _record_failed_login(self, user_id: int, current_count: int) -> None:
        now = _utc_now()
        new_count = current_count + 1
        locked_until = None
        if new_count >= LOCKOUT_THRESHOLD:
            lock_time = datetime.now(timezone.utc) + timedelta(seconds=LOCKOUT_DURATION_SECONDS)
            locked_until = _utc_timestamp(lock_time, "lockout time")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                (new_count, locked_until, now, user_id),
            )
            connection.commit()

    def _reset_login_failures(self, user_id: int) -> None:
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
                (now, user_id),
            )
            connection.commit()

    def enable_totp(self, user_id: int, secret: str) -> None:
        validated_id = _validate_id(user_id, "user ID")
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ? AND enabled = 1",
                (secret, now, validated_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AccountNotFound("user does not exist or is disabled")
            connection.commit()

    def disable_totp(self, user_id: int) -> None:
        validated_id = _validate_id(user_id, "user ID")
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE users SET totp_secret = NULL, updated_at = ? WHERE id = ?",
                (now, validated_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AccountNotFound("user does not exist")
            connection.commit()

    def get_totp_secret(self, user_id: int) -> str | None:
        validated_id = _validate_id(user_id, "user ID")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT totp_secret FROM users WHERE id = ? AND enabled = 1", (validated_id,)
            ).fetchone()
        if row is None:
            raise AccountNotFound("user does not exist or is disabled")
        return row["totp_secret"]

    def set_password(self, user_id: int, password: str, *, require_change: bool = True) -> None:
        """Admin password reset — sets a new password and optionally requires change on next login."""
        validated_id = _validate_id(user_id, "user ID")
        _validate_password(password)
        hashed = hash_password(password)
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE users SET password_hash = ?, password_change_required = ?, updated_at = ? WHERE id = ?",
                (hashed, int(require_change), now, validated_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AccountNotFound("user does not exist")
            connection.commit()

    def change_password(self, user_id: int, old_password: str, new_password: str) -> None:
        """User-initiated password change — verifies old password first."""
        validated_id = _validate_id(user_id, "user ID")
        _validate_password(new_password)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE id = ? AND enabled = 1", (validated_id,)
            ).fetchone()
        if row is None:
            raise AccountNotFound("user does not exist or is disabled")
        if not verify_password(row["password_hash"], old_password):
            raise InvalidAccountInput("current password is incorrect")
        hashed = hash_password(new_password)
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE users SET password_hash = ?, password_change_required = 0, updated_at = ? WHERE id = ?",
                (hashed, now, validated_id),
            )
            connection.commit()

    def unlock_account(self, user_id: int) -> None:
        validated_id = _validate_id(user_id, "user ID")
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
                (now, validated_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AccountNotFound("user does not exist")
            connection.commit()

    def set_user_enabled(self, user_id: int, enabled: bool) -> UserRecord:
        validated_id = _validate_id(user_id, "user ID")
        validated_enabled = _validate_enabled(enabled)
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE users SET enabled = ?, updated_at = ? WHERE id = ?",
                (int(validated_enabled), now, validated_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AccountNotFound("user does not exist")
            row = connection.execute(
                f"SELECT {_USER_COLUMNS} FROM users WHERE id = ?",
                (validated_id,),
            ).fetchone()
            connection.commit()
        result = self._user(row)
        assert result is not None
        return result

    def add_device(
        self,
        user_id: int,
        device_name: str,
        client_fingerprint: str,
        client_public_key: bytes,
        *,
        enabled: bool = True,
    ) -> DeviceRecord:
        validated_user_id = _validate_id(user_id, "user ID")
        normalized_name = _validate_device_name(device_name)
        validated_fingerprint, validated_key = _validate_public_identity(
            client_fingerprint, client_public_key
        )
        validated_enabled = _validate_enabled(enabled)
        now = _utc_now()
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if not connection.execute(
                    "SELECT 1 FROM users WHERE id = ?", (validated_user_id,)
                ).fetchone():
                    raise AccountNotFound("user does not exist")
                if connection.execute(
                    "SELECT 1 FROM devices WHERE client_fingerprint = ?", (validated_fingerprint,)
                ).fetchone():
                    raise AccountAlreadyExists("client fingerprint already exists")
                cursor = connection.execute(
                    """
                    INSERT INTO devices (
                        user_id, device_name, client_fingerprint, client_public_key,
                        enabled, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        validated_user_id, normalized_name, validated_fingerprint,
                        validated_key, int(validated_enabled), now, now,
                    ),
                )
                row = connection.execute(
                    f"""
                    SELECT {_DEVICE_COLUMNS}
                    FROM devices WHERE id = ?
                    """,
                    (cursor.lastrowid,),
                ).fetchone()
                connection.commit()
            except AccountError:
                if connection.in_transaction:
                    connection.rollback()
                raise
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise AccountAlreadyExists("client fingerprint already exists") from exc
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
        result = self._device(row)
        assert result is not None
        return result

    def get_device_by_fingerprint(self, client_fingerprint: str) -> DeviceRecord | None:
        if not isinstance(client_fingerprint, str) or not _FINGERPRINT_RE.fullmatch(client_fingerprint):
            raise InvalidAccountInput("client fingerprint must be lowercase SHA-256 hex")
        with self._connection() as connection:
            return self._device(connection.execute(
                f"""
                SELECT {_DEVICE_COLUMNS}
                FROM devices WHERE client_fingerprint = ?
                """,
                (client_fingerprint,),
            ).fetchone())

    def list_devices_for_user(self, user_id: int) -> list[DeviceRecord]:
        validated = _validate_id(user_id, "user ID")
        with self._connection() as connection:
            if not connection.execute("SELECT 1 FROM users WHERE id = ?", (validated,)).fetchone():
                raise AccountNotFound("user does not exist")
            rows = connection.execute(
                f"""
                SELECT {_DEVICE_COLUMNS}
                FROM devices WHERE user_id = ? ORDER BY id
                """,
                (validated,),
            ).fetchall()
        return [device for row in rows if (device := self._device(row)) is not None]

    def get_device_by_id(self, device_id: int) -> DeviceRecord | None:
        validated = _validate_id(device_id, "device ID")
        with self._connection() as connection:
            return self._device(connection.execute(
                f"SELECT {_DEVICE_COLUMNS} FROM devices WHERE id = ?", (validated,)
            ).fetchone())

    def list_devices(self, status: str | None = None) -> list[DeviceRecord]:
        """List every bound device, optionally filtered by review status (admin use)."""
        with self._connection() as connection:
            if status is None:
                rows = connection.execute(
                    f"SELECT {_DEVICE_COLUMNS} FROM devices ORDER BY id"
                ).fetchall()
            else:
                rows = connection.execute(
                    f"SELECT {_DEVICE_COLUMNS} FROM devices WHERE status = ? ORDER BY id",
                    (_validate_device_status(status),),
                ).fetchall()
        return [device for row in rows if (device := self._device(row)) is not None]

    def set_device_status(
        self, device_id: int, status: str, *, expected: tuple[str, ...] | None = None
    ) -> DeviceRecord:
        """Record an administrator review decision (compare-and-set)."""
        validated_id = _validate_id(device_id, "device ID")
        validated_status = _validate_device_status(status)
        allowed = tuple(_validate_device_status(item) for item in (expected or DEVICE_STATUSES))
        now = _utc_now()
        placeholders = ", ".join("?" for _ in allowed)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                f"UPDATE devices SET status = ?, updated_at = ? WHERE id = ? AND status IN ({placeholders})",
                (validated_status, now, validated_id, *allowed),
            )
            row = connection.execute(
                f"SELECT {_DEVICE_COLUMNS} FROM devices WHERE id = ?", (validated_id,)
            ).fetchone()
            connection.commit()
        if row is None:
            raise AccountNotFound("device does not exist")
        if cursor.rowcount != 1:
            raise InvalidAccountInput(f"device status is {row['status']}, expected {'/'.join(allowed)}")
        result = self._device(row)
        assert result is not None
        return result

    def set_device_enabled(self, device_id: int, enabled: bool) -> DeviceRecord:
        validated_id = _validate_id(device_id, "device ID")
        validated_enabled = _validate_enabled(enabled)
        now = _utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE devices SET enabled = ?, updated_at = ? WHERE id = ?",
                (int(validated_enabled), now, validated_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise AccountNotFound("device does not exist")
            row = connection.execute(
                f"""
                SELECT {_DEVICE_COLUMNS}
                FROM devices WHERE id = ?
                """,
                (validated_id,),
            ).fetchone()
            connection.commit()
        result = self._device(row)
        assert result is not None
        return result

    def create_session(
        self,
        user_id: int,
        token_hash: bytes,
        expires_at: datetime,
        *,
        now: datetime | None = None,
    ) -> SessionRecord:
        """Atomically create a hash-only session for an enabled user."""
        validated_user_id = _validate_id(user_id, "user ID")
        validated_hash = _validate_token_hash(token_hash)
        current = now or datetime.now(timezone.utc)
        created_text = _utc_timestamp(current, "session creation time")
        expiry_text = _utc_timestamp(expires_at, "session expiry")
        if expires_at.astimezone(timezone.utc) <= current.astimezone(timezone.utc):
            raise InvalidAccountInput("session expiry must be in the future")
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                owner = connection.execute(
                    "SELECT enabled FROM users WHERE id = ?", (validated_user_id,)
                ).fetchone()
                if owner is None:
                    raise AccountNotFound("user does not exist")
                if not bool(owner["enabled"]):
                    raise InvalidAccountInput("disabled user cannot own a new session")
                cursor = connection.execute(
                    """
                    INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (validated_user_id, validated_hash, created_text, expiry_text),
                )
                row = connection.execute(
                    """
                    SELECT id, user_id, token_hash, created_at, expires_at, revoked_at, last_used_at
                    FROM sessions WHERE id = ?
                    """,
                    (cursor.lastrowid,),
                ).fetchone()
                connection.commit()
            except AccountError:
                if connection.in_transaction:
                    connection.rollback()
                raise
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise AccountAlreadyExists("session token hash already exists") from exc
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
        result = self._session(row)
        assert result is not None
        return result

    def get_session_by_token_hash(self, token_hash: bytes) -> SessionRecord | None:
        validated_hash = _validate_token_hash(token_hash)
        with self._connection() as connection:
            return self._session(connection.execute(
                """
                SELECT id, user_id, token_hash, created_at, expires_at, revoked_at, last_used_at
                FROM sessions WHERE token_hash = ?
                """,
                (validated_hash,),
            ).fetchone())

    def validate_session(
        self,
        token_hash: bytes,
        *,
        now: datetime | None = None,
        touch_interval_seconds: int = 60,
    ) -> tuple[UserRecord, SessionRecord] | None:
        """Return an enabled user and live session, touching use at a bounded rate."""
        validated_hash = _validate_token_hash(token_hash)
        if type(touch_interval_seconds) is not int or touch_interval_seconds < 0:
            raise InvalidAccountInput("session touch interval must be a non-negative integer")
        current = now or datetime.now(timezone.utc)
        current_text = _utc_timestamp(current, "session validation time")
        current = current.astimezone(timezone.utc)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT s.id, s.user_id, s.token_hash, s.created_at, s.expires_at,
                       s.revoked_at, s.last_used_at,
                       u.username, u.email, u.enabled, u.created_at AS user_created_at,
                       u.updated_at AS user_updated_at,
                       u.totp_secret, u.locked_until, u.password_change_required
                FROM sessions AS s JOIN users AS u ON u.id = s.user_id
                WHERE s.token_hash = ?
                """,
                (validated_hash,),
            ).fetchone()
            if (
                row is None
                or row["revoked_at"] is not None
                or not bool(row["enabled"])
                or _parse_timestamp(row["expires_at"]) <= current
            ):
                connection.commit()
                return None
            last_used = row["last_used_at"]
            should_touch = (
                last_used is None
                or _parse_timestamp(last_used) <= current - timedelta(seconds=touch_interval_seconds)
            )
            if should_touch:
                connection.execute(
                    "UPDATE sessions SET last_used_at = ? WHERE id = ?", (current_text, row["id"])
                )
                row = connection.execute(
                    """
                    SELECT s.id, s.user_id, s.token_hash, s.created_at, s.expires_at,
                           s.revoked_at, s.last_used_at,
                           u.username, u.email, u.enabled, u.created_at AS user_created_at,
                           u.updated_at AS user_updated_at,
                           u.totp_secret, u.locked_until, u.password_change_required
                    FROM sessions AS s JOIN users AS u ON u.id = s.user_id
                    WHERE s.id = ?
                    """,
                    (row["id"],),
                ).fetchone()
            connection.commit()
        assert row is not None
        user = UserRecord(
            id=row["user_id"], username=row["username"], email=row["email"],
            enabled=bool(row["enabled"]), created_at=row["user_created_at"],
            updated_at=row["user_updated_at"],
            mfa_enabled=row["totp_secret"] is not None,
            locked_until=row["locked_until"],
            password_change_required=bool(row["password_change_required"]),
        )
        session = self._session(row)
        assert session is not None
        return user, session

    def touch_session(
        self, token_hash: bytes, *, now: datetime | None = None
    ) -> SessionRecord | None:
        validated_hash = _validate_token_hash(token_hash)
        timestamp = _utc_timestamp(now or datetime.now(timezone.utc), "session use time")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE sessions SET last_used_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (timestamp, validated_hash),
            )
            row = connection.execute(
                """
                SELECT id, user_id, token_hash, created_at, expires_at, revoked_at, last_used_at
                FROM sessions WHERE token_hash = ?
                """,
                (validated_hash,),
            ).fetchone() if cursor.rowcount else None
            connection.commit()
        return self._session(row)

    def revoke_session(self, token_hash: bytes, *, now: datetime | None = None) -> bool:
        validated_hash = _validate_token_hash(token_hash)
        timestamp = _utc_timestamp(now or datetime.now(timezone.utc), "session revocation time")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (timestamp, validated_hash),
            )
            connection.commit()
        return cursor.rowcount == 1

    def revoke_all_user_sessions(
        self, user_id: int, *, now: datetime | None = None
    ) -> int:
        validated_id = _validate_id(user_id, "user ID")
        timestamp = _utc_timestamp(now or datetime.now(timezone.utc), "session revocation time")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute(
                "SELECT 1 FROM users WHERE id = ?", (validated_id,)
            ).fetchone():
                connection.rollback()
                raise AccountNotFound("user does not exist")
            cursor = connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                (timestamp, validated_id),
            )
            connection.commit()
        return int(cursor.rowcount)
