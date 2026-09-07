"""Provisioned server ML-KEM identity and authorized client identities."""
from __future__ import annotations

import base64
import fcntl
import hmac
import ipaddress
import stat
from contextlib import contextmanager
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from crypto.hybrid_crypto import PQCProvider


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


def load_client_private(path: Path) -> Ed25519PrivateKey:
    raw = read_private(path)
    if len(raw) != 32:
        raise ValueError("client private key must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


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
            if len(public) != 32 or fp != fingerprint(public): raise ValueError('client public key/fingerprint mismatch')
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

    @contextmanager
    def _lock(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def authorize(self, public_key: bytes, client_id: str | None = None, assigned_ip: str | None = None) -> str:
        if len(public_key) != 32: raise ValueError('Ed25519 client public key must be 32 bytes')
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
