"""Provisioned server ML-KEM identity, authorized clients, and enrollment artifacts."""
from __future__ import annotations

import base64
import fcntl
import hmac
import ipaddress
import re
import stat
from contextlib import contextmanager
import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from crypto.hybrid_crypto import MLKEM_PARAMS, PQCProvider
from vpn.config import ClientConfig, validate_client


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def _atomic_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def generate_server_identity(private_path: Path, public_path: Path, *, allow_mock: bool = False) -> str:
    kem = PQCProvider("ML-KEM-768", allow_mock=allow_mock)
    secret, public = kem.generate_keypair()
    _atomic_private(private_path, secret)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(public)
    return fingerprint(public)


def generate_client_identity(private_path: Path, public_path: Path) -> str:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _atomic_private(private_path, private_raw)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(public_raw)
    return fingerprint(public_raw)


def generate_client_identity_kem(private_path: Path, public_path: Path, *, allow_mock: bool = False) -> str:
    kem = PQCProvider("ML-KEM-768", allow_mock=allow_mock)
    secret, public = kem.generate_keypair()
    _atomic_private(private_path, secret)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(public)
    return fingerprint(public)


def _safe_identity_parent(path: Path) -> None:
    path = Path(path).absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("client identity path contains an unsafe component")
    os.chmod(path, 0o700)


def _atomic_new(path: Path, data: bytes, mode: int) -> None:
    """Atomically create a file and refuse replacement of any existing entry."""
    _safe_identity_parent(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
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


def _read_client_public(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("unable to read client public identity") from exc
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("client public identity must be a regular file")
        raw = handle.read(1185)
    if len(raw) not in (32, 1184):
        raise ValueError("client public identity must be 32 bytes (Ed25519) or 1184 bytes (ML-KEM-768)")
    return raw


def client_public_identity(private_path: Path, public_path: Path) -> tuple[bytes, str]:
    """Validate a client keypair and return public information only."""
    private = load_client_private(Path(private_path))
    expected = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public = _read_client_public(Path(public_path))
    if not hmac.compare_digest(expected, public):
        raise ValueError("client public identity does not match the private identity")
    return public, fingerprint(public)


def ensure_client_identity(private_path: Path, public_path: Path) -> str:
    """Create one Ed25519 identity if absent; otherwise validate without rotation."""
    private_path, public_path = Path(private_path), Path(public_path)
    _safe_identity_parent(private_path.parent)
    _safe_identity_parent(public_path.parent)
    lock_path = private_path.parent / ".client-identity.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        private_exists = private_path.exists()
        public_exists = public_path.exists()
        if not private_exists and public_exists:
            raise ValueError("client identity is incomplete; private identity is missing")
        if private_exists:
            private = load_client_private(private_path)
            derived = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            if not public_exists:
                _atomic_new(public_path, derived, 0o644)
            public, result = client_public_identity(private_path, public_path)
            if not hmac.compare_digest(derived, public):  # defensive; helper already checks
                raise ValueError("client identity keypair mismatch")
            return result

        private = Ed25519PrivateKey.generate()
        private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        _atomic_new(private_path, private_raw, 0o600)
        try:
            _atomic_new(public_path, public_raw, 0o644)
        except FileExistsError as exc:
            raise ValueError("client identity appeared concurrently; refusing replacement") from exc
        return fingerprint(public_raw)


def load_client_private(path: Path) -> Ed25519PrivateKey:
    raw = read_private(path)
    if len(raw) != 32:
        raise ValueError("client private key must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_client_kem_private(path: Path) -> tuple[bytes, bytes]:
    """Load ML-KEM-768 client secret key; return (secret, public) after round-trip check."""
    secret = read_private(path)
    if len(secret) != 2400:
        raise ValueError("client ML-KEM-768 private key must be exactly 2400 bytes")
    return secret


def read_private(path: Path) -> bytes:
    """Open without following symlinks; check the same inode that is read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
            raise ValueError('private identity must be a regular file with mode 0600 (or 0400)')
        return handle.read()


def validate_server_identity(private: Path, public: Path, *, allow_mock=False):
    secret, pub = read_private(private), public.read_bytes()
    if len(secret) != 2400 or len(pub) != 1184:
        raise ValueError('ML-KEM-768 identity requires 2400-byte private and 1184-byte public key')
    kem = PQCProvider(allow_mock=allow_mock)
    ct, expected = kem.encapsulate(pub)
    actual = kem.decapsulate(secret, ct)
    if not hmac.compare_digest(expected, actual):
        raise ValueError('server identity keypair consistency check failed')
    return secret, pub


class AuthorizedClients:
    def __init__(self, path: Path):
        self.path = path

    @staticmethod
    def validate(value, subnet=None, server_ip=None):
        if not isinstance(value, dict) or set(value) != {'clients'} or not isinstance(value['clients'], list):
            raise ValueError('authorized client database must contain only a clients list')
        fingerprints, ids, addresses = set(), set(), set()
        network = ipaddress.IPv4Network(subnet) if subnet else None
        for item in value['clients']:
            if not isinstance(item, dict): raise ValueError('client record must be an object')
            try: public = base64.b64decode(item['public_key'], validate=True)
            except (KeyError, ValueError, TypeError) as exc: raise ValueError('invalid client public key') from exc
            fp, cid = item.get('fingerprint'), item.get('client_id')
            if len(public) not in (32, 1184) or fp != fingerprint(public): raise ValueError('client public key/fingerprint mismatch')
            if not isinstance(cid, str) or not cid or len(cid) > 128 or any(ord(x) < 32 for x in cid):
                raise ValueError('invalid client_id')
            if type(item.get('enabled')) is not bool: raise ValueError('client enabled must be boolean')
            if fp in fingerprints or cid in ids: raise ValueError('duplicate client fingerprint or client_id')
            fingerprints.add(fp); ids.add(cid)
            assigned = item.get('assigned_ip')
            if assigned is not None:
                ip = ipaddress.IPv4Address(assigned)
                if ip in addresses: raise ValueError('duplicate assigned VPN IP')
                if network and (ip not in network or ip in (network.network_address, network.broadcast_address, ipaddress.IPv4Address(server_ip))):
                    raise ValueError('assigned IP is not an available VPN host')
                addresses.add(ip)
        return value

    def _load(self, *, required=False, subnet=None, server_ip=None) -> dict:
        if not self.path.exists() and not required: return {'clients': []}
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError('duplicate JSON property')
                result[key] = value
            return result
        value = json.loads(self.path.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
        return self.validate(value, subnet, server_ip)

    def find(self, public_key: bytes) -> dict | None:
        wanted = fingerprint(public_key)
        for item in self._load(required=True)['clients']:
            if item['fingerprint'] == wanted and item['enabled']: return item
        return None

    def find_by_fingerprint(self, fp_hex: str) -> tuple[bytes, dict] | None:
        """Look up a client by fingerprint hash; return (public_key_bytes, authz_dict) or None."""
        for item in self._load(required=True)['clients']:
            if item['fingerprint'] == fp_hex and item['enabled']:
                public = base64.b64decode(item['public_key'], validate=True)
                return public, item
        return None

    @contextmanager
    def _lock(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def authorize(self, public_key: bytes, client_id: str | None = None, assigned_ip: str | None = None) -> str:
        if len(public_key) not in (32, 1184): raise ValueError('client public key must be 32 bytes (Ed25519) or 1184 bytes (ML-KEM-768)')
        fp = fingerprint(public_key)
        with self._lock():
            db = self._load()
            record = {'client_id': client_id or fp[:16], 'public_key': base64.b64encode(public_key).decode(),
                'fingerprint': fp, 'enabled': True, 'created_at': datetime.now(timezone.utc).isoformat(), 'assigned_ip': assigned_ip}
            db['clients'] = [x for x in db['clients'] if x['fingerprint'] != fp] + [record]
            self.validate(db)
            _atomic_private(self.path, (json.dumps(db, indent=2) + '\n').encode())
        return fp

    def revoke(self, fp: str) -> bool:
        with self._lock():
            db = self._load()
            found = False
            for item in db['clients']:
                if item['fingerprint'] == fp: item['enabled'] = False; found = True
            if found: _atomic_private(self.path, (json.dumps(db, indent=2) + '\n').encode())
            return found


def verify_client_signature(public_key: bytes, signature: bytes, message: bytes) -> None:
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)



ENROLLMENT_VERSION = 1
ENROLLMENT_VERSION_KEM = 2
MAX_ENROLLMENT_SIZE = 8192
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
            raise EnrollmentError("enrollment request must contain exactly the required public fields")
        version = value["version"]
        if type(version) is not int or version not in (ENROLLMENT_VERSION, ENROLLMENT_VERSION_KEM):
            raise EnrollmentError("unsupported enrollment request version")
        is_kem = version == ENROLLMENT_VERSION_KEM
        expected_key_size = 1184 if is_kem else 32
        key_label = "ML-KEM-768" if is_kem else "Ed25519"
        max_encoded_len = 1600 if is_kem else 64
        client_id = value["client_id"]
        if (not isinstance(client_id, str) or not CLIENT_ID_RE.fullmatch(client_id)
                or ".." in client_id):
            raise EnrollmentError("invalid client_id")
        encoded = value["client_public_key"]
        if not isinstance(encoded, str) or len(encoded) > max_encoded_len:
            raise EnrollmentError(f"invalid {key_label} public key encoding")
        try:
            public_key = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise EnrollmentError(f"invalid Base64 {key_label} public key") from exc
        if len(public_key) != expected_key_size:
            raise EnrollmentError(f"{key_label} public key must be exactly {expected_key_size} bytes")
        if base64.b64encode(public_key).decode("ascii") != encoded:
            raise EnrollmentError(f"{key_label} public key must use canonical Base64")
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
        return cls(version, client_id, encoded, supplied, created_at)

    @classmethod
    def create(cls, client_id: str, public_key: bytes) -> "EnrollmentRequest":
        if not isinstance(public_key, bytes) or len(public_key) not in (32, 1184):
            raise EnrollmentError("public key must be 32 bytes (Ed25519) or 1184 bytes (ML-KEM-768)")
        version = ENROLLMENT_VERSION_KEM if len(public_key) == 1184 else ENROLLMENT_VERSION
        value = {
            "version": version,
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


def load_client_public_key(path: Path) -> bytes:
    """Load either an Ed25519 (32B) or ML-KEM-768 (1184B) client public key."""
    raw = _read_public_file(Path(path), 1185, "client public key")
    if len(raw) not in (32, 1184):
        raise EnrollmentError("client public key must be 32 bytes (Ed25519) or 1184 bytes (ML-KEM-768)")
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


def _profile_unique_object(pairs: list[tuple[str, object]]) -> dict:
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
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_profile_unique_object)
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
