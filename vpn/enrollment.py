"""Strict public Ed25519 client enrollment request artifacts."""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from vpn.identity import fingerprint


ENROLLMENT_VERSION = 1
MAX_ENROLLMENT_SIZE = 4096
ENROLLMENT_FIELDS = {
    "version", "client_id", "client_public_key", "client_fingerprint", "created_at"
}
CLIENT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class EnrollmentError(ValueError):
    """Raised when a public enrollment request violates its schema."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EnrollmentError(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def _bounded_bytes(data: str | bytes) -> bytes:
    if isinstance(data, str):
        try:
            raw = data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EnrollmentError("enrollment request must be UTF-8") from exc
    elif isinstance(data, bytes):
        raw = data
    else:
        raise EnrollmentError("enrollment request must be JSON text")
    if not raw or len(raw) > MAX_ENROLLMENT_SIZE:
        raise EnrollmentError("enrollment request size is out of bounds")
    return raw


@dataclass(frozen=True)
class EnrollmentRequest:
    version: int
    client_id: str
    client_public_key: str
    client_fingerprint: str
    created_at: str

    @classmethod
    def validate(cls, value: object) -> "EnrollmentRequest":
        if not isinstance(value, dict) or set(value) != ENROLLMENT_FIELDS:
            raise EnrollmentError("enrollment request must contain exactly the version 1 public fields")
        if type(value["version"]) is not int or value["version"] != ENROLLMENT_VERSION:
            raise EnrollmentError("unsupported enrollment request version")
        client_id = value["client_id"]
        if (not isinstance(client_id, str) or not CLIENT_ID_RE.fullmatch(client_id)
                or ".." in client_id):
            raise EnrollmentError("invalid client_id")
        encoded = value["client_public_key"]
        if not isinstance(encoded, str) or len(encoded) > 64:
            raise EnrollmentError("invalid Ed25519 public key encoding")
        try:
            public_key = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise EnrollmentError("invalid Base64 Ed25519 public key") from exc
        if len(public_key) != 32:
            raise EnrollmentError("Ed25519 public key must be exactly 32 bytes")
        if base64.b64encode(public_key).decode("ascii") != encoded:
            raise EnrollmentError("Ed25519 public key must use canonical Base64")
        supplied = value["client_fingerprint"]
        if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied):
            raise EnrollmentError("client fingerprint must be lowercase SHA-256 hex")
        if fingerprint(public_key) != supplied:
            raise EnrollmentError("client public key/fingerprint mismatch")
        created_at = value["created_at"]
        if (not isinstance(created_at, str)
                or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created_at)):
            raise EnrollmentError("invalid created_at timestamp")
        try:
            timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EnrollmentError("invalid created_at timestamp") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
            raise EnrollmentError("created_at must use UTC")
        return cls(ENROLLMENT_VERSION, client_id, encoded, supplied, created_at)

    @classmethod
    def create(cls, client_id: str, public_key: bytes) -> "EnrollmentRequest":
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise EnrollmentError("Ed25519 public key must be exactly 32 bytes")
        value = {
            "version": ENROLLMENT_VERSION,
            "client_id": client_id,
            "client_public_key": base64.b64encode(public_key).decode("ascii"),
            "client_fingerprint": fingerprint(public_key),
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        return cls.validate(value)

    @property
    def public_key_bytes(self) -> bytes:
        return base64.b64decode(self.client_public_key, validate=True)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def parse_enrollment(data: str | bytes) -> EnrollmentRequest:
    raw = _bounded_bytes(data)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnrollmentError("malformed enrollment request JSON") from exc
    return EnrollmentRequest.validate(value)


def _read_public_file(path: Path, maximum: int, description: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise EnrollmentError(f"unable to read {description}") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise EnrollmentError(f"{description} must be a regular file")
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise EnrollmentError(f"{description} size is out of bounds")
    return data


def load_enrollment(path: Path) -> EnrollmentRequest:
    return parse_enrollment(_read_public_file(Path(path), MAX_ENROLLMENT_SIZE, ".pqenroll request"))


def load_ed25519_public_key(path: Path) -> bytes:
    raw = _read_public_file(Path(path), 33, "Ed25519 public key")
    if len(raw) != 32:
        raise EnrollmentError("Ed25519 public key must be exactly 32 bytes")
    return raw


def write_enrollment(path: Path, request: EnrollmentRequest) -> None:
    """Atomically write a public request without following an output symlink."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if stat.S_ISLNK(path.parent.lstat().st_mode):
        raise EnrollmentError("enrollment output directory must not be a symlink")
    try:
        if stat.S_ISLNK(path.lstat().st_mode):
            raise EnrollmentError("refusing to replace an enrollment output symlink")
    except FileNotFoundError:
        pass
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(request.to_json().encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
