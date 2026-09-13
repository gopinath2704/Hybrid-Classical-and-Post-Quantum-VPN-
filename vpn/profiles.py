"""Strict public server profiles and service-owned profile persistence."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from crypto.hybrid_crypto import MLKEM_PARAMS
from vpn.config import ClientConfig, validate_client
from vpn.identity import fingerprint


PROFILE_VERSION = 1
PROFILE_STORE_VERSION = 1
MAX_PROFILE_SIZE = 8192
MAX_PROFILE_STORE_SIZE = 65536
MAX_PROFILES = 5
PROFILE_FIELDS = {
    "version",
    "profile_id",
    "name",
    "server_host",
    "server_control_port",
    "server_identity_public_key",
    "server_identity_fingerprint",
    "expected_vpn_subnet",
}
PROFILE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
HOST_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class ProfileError(ValueError):
    """Raised when a profile or profile store violates its strict schema."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def _decode_json(data: str | bytes, maximum: int, description: str) -> object:
    if isinstance(data, str):
        try:
            raw = data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ProfileError(f"{description} must be UTF-8") from exc
    elif isinstance(data, bytes):
        raw = data
    else:
        raise ProfileError(f"{description} must be JSON text")
    if not raw or len(raw) > maximum:
        raise ProfileError(f"{description} size is out of bounds")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError(f"malformed {description} JSON") from exc


def _safe_parent(path: Path, mode: int = 0o700) -> None:
    """Create a directory and reject symlinks anywhere in its existing path."""
    path = Path(path).absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=mode)
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ProfileError("profile state path contains an unsafe component")
    os.chmod(path, mode)


def _read_regular(path: Path, maximum: int, description: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ProfileError(f"unable to read {description}") from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ProfileError(f"{description} must be a regular file")
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise ProfileError(f"{description} size is out of bounds")
    return data


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    _safe_parent(path.parent)
    try:
        if stat.S_ISLNK(path.lstat().st_mode):
            raise ProfileError("refusing to replace a symlink")
    except FileNotFoundError:
        pass
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
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


def _validate_host(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or value != value.strip():
        raise ProfileError("server_host must be a hostname or IPv4 address of reasonable length")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass
    if "://" in value or "/" in value or "$" in value or "\\" in value:
        raise ProfileError("server_host must not be a URL or path")
    labels = value.split(".")
    if not labels or any(not HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ProfileError("server_host has invalid hostname syntax")
    return value.lower()


@dataclass(frozen=True)
class ServerProfile:
    version: int
    profile_id: str
    name: str
    server_host: str
    server_control_port: int
    server_identity_public_key: str
    server_identity_fingerprint: str
    expected_vpn_subnet: str

    @classmethod
    def validate(cls, value: object) -> "ServerProfile":
        if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
            unknown = sorted(set(value) - PROFILE_FIELDS) if isinstance(value, dict) else []
            detail = f": {unknown}" if unknown else ""
            raise ProfileError(f"profile must contain exactly the version 1 public fields{detail}")
        if type(value["version"]) is not int or value["version"] != PROFILE_VERSION:
            raise ProfileError("unsupported profile version")
        profile_id = value["profile_id"]
        if (not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id)
                or ".." in profile_id):
            raise ProfileError("invalid profile_id")
        name = value["name"]
        if (not isinstance(name, str) or name != name.strip() or not 1 <= len(name) <= 80
                or any(ord(character) < 32 for character in name)):
            raise ProfileError("invalid profile name")
        port = value["server_control_port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ProfileError("server_control_port must be an integer in 1..65535")
        encoded_key = value["server_identity_public_key"]
        if not isinstance(encoded_key, str) or len(encoded_key) > 2048:
            raise ProfileError("invalid ML-KEM-768 public key encoding")
        try:
            public_key = base64.b64decode(encoded_key, validate=True)
        except (ValueError, TypeError) as exc:
            raise ProfileError("invalid Base64 ML-KEM-768 public key") from exc
        expected_length = MLKEM_PARAMS["ML-KEM-768"]["public_key_length"]
        if len(public_key) != expected_length:
            raise ProfileError(f"ML-KEM-768 public key must be exactly {expected_length} bytes")
        if base64.b64encode(public_key).decode("ascii") != encoded_key:
            raise ProfileError("ML-KEM-768 public key must use canonical Base64")
        supplied_fingerprint = value["server_identity_fingerprint"]
        if (not isinstance(supplied_fingerprint, str)
                or not re.fullmatch(r"[0-9a-f]{64}", supplied_fingerprint)):
            raise ProfileError("server identity fingerprint must be lowercase SHA-256 hex")
        if fingerprint(public_key) != supplied_fingerprint:
            raise ProfileError("server identity public key/fingerprint mismatch")
        try:
            network = ipaddress.IPv4Network(value["expected_vpn_subnet"], strict=True)
        except (TypeError, ValueError) as exc:
            raise ProfileError("expected_vpn_subnet must be a canonical IPv4 subnet") from exc
        if network.prefixlen > 30:
            raise ProfileError("expected_vpn_subnet must have usable client addresses")
        return cls(
            version=PROFILE_VERSION,
            profile_id=profile_id,
            name=name,
            server_host=_validate_host(value["server_host"]),
            server_control_port=port,
            server_identity_public_key=encoded_key,
            server_identity_fingerprint=supplied_fingerprint,
            expected_vpn_subnet=str(network),
        )

    @property
    def public_key_bytes(self) -> bytes:
        return base64.b64decode(self.server_identity_public_key, validate=True)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def parse_profile(data: str | bytes) -> ServerProfile:
    return ServerProfile.validate(_decode_json(data, MAX_PROFILE_SIZE, ".pqvpn profile"))


def load_profile(path: Path) -> ServerProfile:
    return parse_profile(_read_regular(Path(path), MAX_PROFILE_SIZE, ".pqvpn profile"))


class ProfileStore:
    """Atomic store for public profiles and an exact active profile ID."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / "profiles.json"
        self.keys_dir = self.root / "server-identities"

    def _empty(self) -> dict:
        return {"version": PROFILE_STORE_VERSION, "active_profile_id": None, "profiles": []}

    def _validate_store(self, value: object) -> dict:
        fields = {"version", "active_profile_id", "profiles"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ProfileError("profile store has an invalid schema")
        if type(value["version"]) is not int or value["version"] != PROFILE_STORE_VERSION:
            raise ProfileError("unsupported profile store version")
        if not isinstance(value["profiles"], list):
            raise ProfileError("profile store profiles must be a list")
        if len(value["profiles"]) > MAX_PROFILES:
            raise ProfileError(f"profile store supports at most {MAX_PROFILES} profiles")
        profiles = [ServerProfile.validate(item) for item in value["profiles"]]
        ids = [profile.profile_id for profile in profiles]
        if len(ids) != len(set(ids)):
            raise ProfileError("duplicate profile ID in profile store")
        active = value["active_profile_id"]
        if active is not None and (not isinstance(active, str) or active not in ids):
            raise ProfileError("active profile ID is not present in profile store")
        return {
            "version": PROFILE_STORE_VERSION,
            "active_profile_id": active,
            "profiles": [profile.to_dict() for profile in profiles],
        }

    def _load(self) -> dict:
        _safe_parent(self.root)
        try:
            exists = self.path.exists()
        except OSError as exc:
            raise ProfileError("unable to inspect profile store") from exc
        if not exists:
            return self._empty()
        data = _read_regular(self.path, MAX_PROFILE_STORE_SIZE, "profile store")
        return self._validate_store(_decode_json(data, MAX_PROFILE_STORE_SIZE, "profile store"))

    def _save(self, value: dict) -> None:
        validated = self._validate_store(value)
        encoded = (json.dumps(validated, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _atomic_write(self.path, encoded, 0o600)

    def list(self) -> list[ServerProfile]:
        return [ServerProfile.validate(item) for item in self._load()["profiles"]]

    def active_id(self) -> str | None:
        return self._load()["active_profile_id"]

    def get(self, profile_id: str) -> ServerProfile | None:
        if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
            raise ProfileError("invalid profile_id")
        return next((profile for profile in self.list() if profile.profile_id == profile_id), None)

    def active(self) -> ServerProfile | None:
        active = self.active_id()
        return self.get(active) if active else None

    def key_path(self, profile_id: str) -> Path:
        if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id) or ".." in profile_id:
            raise ProfileError("invalid profile_id")
        return self.keys_dir / f"{profile_id}.pub"

    def import_profile(self, profile: ServerProfile, *, replace: bool = False) -> None:
        if type(replace) is not bool:
            raise ProfileError("replace must be boolean")
        value = self._load()
        existing = next((item for item in value["profiles"]
                         if item["profile_id"] == profile.profile_id), None)
        if existing is not None and not replace:
            raise ProfileError("profile ID already exists; explicit replace is required")
        if existing is None and len(value["profiles"]) >= MAX_PROFILES:
            raise ProfileError(f"profile store supports at most {MAX_PROFILES} profiles")
        _atomic_write(self.key_path(profile.profile_id), profile.public_key_bytes, 0o644)
        profiles = [item for item in value["profiles"] if item["profile_id"] != profile.profile_id]
        profiles.append(profile.to_dict())
        profiles.sort(key=lambda item: item["profile_id"])
        value["profiles"] = profiles
        self._save(value)

    def select(self, profile_id: str) -> None:
        value = self._load()
        if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
            raise ProfileError("invalid profile_id")
        if profile_id not in {item["profile_id"] for item in value["profiles"]}:
            raise ProfileError("profile ID not found")
        value["active_profile_id"] = profile_id
        self._save(value)

    def remove(self, profile_id: str) -> None:
        value = self._load()
        if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
            raise ProfileError("invalid profile_id")
        remaining = [item for item in value["profiles"] if item["profile_id"] != profile_id]
        if len(remaining) == len(value["profiles"]):
            raise ProfileError("profile ID not found")
        key_path = self.key_path(profile_id)
        _safe_parent(self.keys_dir)
        try:
            if stat.S_ISLNK(key_path.lstat().st_mode):
                raise ProfileError("refusing to remove a symlink")
        except FileNotFoundError:
            pass
        value["profiles"] = remaining
        if value["active_profile_id"] == profile_id:
            value["active_profile_id"] = None
        self._save(value)
        try:
            key_path.unlink()
        except FileNotFoundError:
            pass

    def client_config(self, profile: ServerProfile, client_private_key: Path) -> ClientConfig:
        key_path = self.key_path(profile.profile_id)
        _safe_parent(self.keys_dir)
        current = _read_regular(key_path, 2048, "stored server public key")
        if current != profile.public_key_bytes:
            raise ProfileError("stored server public key does not match profile")
        cfg = ClientConfig(
            server_host=profile.server_host,
            server_control_port=profile.server_control_port,
            server_identity_public_key=str(key_path),
            server_identity_fingerprint=profile.server_identity_fingerprint,
            client_identity_private_key=str(client_private_key),
            expected_vpn_subnet=profile.expected_vpn_subnet,
        )
        validate_client(cfg)
        return cfg
