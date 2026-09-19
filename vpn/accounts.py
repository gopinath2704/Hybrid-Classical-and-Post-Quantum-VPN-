"""Server-side account, device ownership, and session-schema persistence.

This module deliberately does not grant VPN access.  ``AuthorizedClients`` remains
the independent authority for deciding whether an Ed25519 device may connect.
"""
from __future__ import annotations

import os
import re
import sqlite3
import stat
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from argon2 import PasswordHasher
from argon2.exceptions import HashingError, InvalidHashError, VerificationError

from vpn.identity import fingerprint


SCHEMA_VERSION = 1
DEFAULT_ACCOUNT_DATABASE = Path("/var/lib/pqvpn/accounts/accounts.db")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
MAX_USERNAME_LENGTH = 64
MAX_EMAIL_LENGTH = 254
MAX_DEVICE_NAME_LENGTH = 100

_USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
_PASSWORD_HASHER = PasswordHasher()


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


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    email: str
    enabled: bool
    created_at: str
    updated_at: str


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
        updated_at TEXT NOT NULL
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

_EXPECTED_COLUMNS = {
    "users": (
        "id", "username", "email", "password_hash", "enabled", "created_at", "updated_at"
    ),
    "devices": (
        "id", "user_id", "device_name", "client_fingerprint", "client_public_key",
        "enabled", "created_at", "updated_at"
    ),
    "sessions": (
        "id", "user_id", "token_hash", "created_at", "expires_at", "revoked_at",
        "last_used_at"
    ),
}
_EXPECTED_INDEXES = {"idx_devices_user_id", "idx_sessions_user_id", "idx_sessions_expires_at"}


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
                f"account schema version {version} is not supported; initialize a version 1 database"
            )

    @staticmethod
    def _application_tables(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        return {str(row[0]) for row in rows}

    @classmethod
    def _validate_schema(cls, connection: sqlite3.Connection) -> None:
        integrity = connection.execute("PRAGMA quick_check").fetchall()
        if len(integrity) != 1 or integrity[0][0] != "ok":
            raise AccountDatabaseError("account database integrity check failed")
        if cls._application_tables(connection) != set(_EXPECTED_COLUMNS):
            raise AccountDatabaseError("account database has an incompatible table layout")
        for table, expected in _EXPECTED_COLUMNS.items():
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
        """Create schema version 1 or validate an existing current database."""
        with self._connection(current_schema=False) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                version = self._version(connection)
                tables = self._application_tables(connection)
                if version == 0 and not tables:
                    for statement in _SCHEMA_STATEMENTS:
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
            enabled=bool(row["enabled"]), created_at=row["created_at"], updated_at=row["updated_at"]
        )

    @staticmethod
    def _device(row: sqlite3.Row | None) -> DeviceRecord | None:
        if row is None:
            return None
        return DeviceRecord(
            id=row["id"], user_id=row["user_id"], device_name=row["device_name"],
            client_fingerprint=row["client_fingerprint"],
            client_public_key=bytes(row["client_public_key"]), enabled=bool(row["enabled"]),
            created_at=row["created_at"], updated_at=row["updated_at"]
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
                    "SELECT id, username, email, enabled, created_at, updated_at FROM users WHERE id = ?",
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
                "SELECT id, username, email, enabled, created_at, updated_at FROM users WHERE id = ?",
                (validated,),
            ).fetchone())

    def get_user_by_username(self, username: str) -> UserRecord | None:
        normalized = normalize_username(username)
        with self._connection() as connection:
            return self._user(connection.execute(
                "SELECT id, username, email, enabled, created_at, updated_at FROM users WHERE username = ?",
                (normalized,),
            ).fetchone())

    def get_user_by_email(self, email: str) -> UserRecord | None:
        normalized = normalize_email(email)
        with self._connection() as connection:
            return self._user(connection.execute(
                "SELECT id, username, email, enabled, created_at, updated_at FROM users WHERE email = ?",
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
                "SELECT id, username, email, enabled, created_at, updated_at FROM users WHERE id = ?",
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
                    """
                    SELECT id, user_id, device_name, client_fingerprint, client_public_key,
                           enabled, created_at, updated_at
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
                """
                SELECT id, user_id, device_name, client_fingerprint, client_public_key,
                       enabled, created_at, updated_at
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
                """
                SELECT id, user_id, device_name, client_fingerprint, client_public_key,
                       enabled, created_at, updated_at
                FROM devices WHERE user_id = ? ORDER BY id
                """,
                (validated,),
            ).fetchall()
        return [device for row in rows if (device := self._device(row)) is not None]

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
                """
                SELECT id, user_id, device_name, client_fingerprint, client_public_key,
                       enabled, created_at, updated_at
                FROM devices WHERE id = ?
                """,
                (validated_id,),
            ).fetchone()
            connection.commit()
        result = self._device(row)
        assert result is not None
        return result
