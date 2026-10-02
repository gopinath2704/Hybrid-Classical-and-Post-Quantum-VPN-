"""Dedicated HTTPS account-authentication and device-binding API."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import logging
import math
import secrets
import stat
import threading
import time
import tomllib
import unicodedata
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from vpn.accounts import (
    DEFAULT_ACCOUNT_DATABASE,
    MAX_DEVICE_NAME_LENGTH,
    MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH,
    MAX_USERNAME_LENGTH,
    AccountAlreadyExists,
    AccountDatabaseError,
    AccountNotFound,
    AccountStore,
    DeviceRecord,
    InvalidAccountInput,
    SessionRecord,
    UserRecord,
)


logger = logging.getLogger("pqvpn.account_api")

DEFAULT_CONFIG = Path("/etc/pqvpn/account-api.toml")
DEFAULT_SESSION_LIFETIME_SECONDS = 12 * 60 * 60
DEFAULT_BODY_LIMIT = 16 * 1024
SESSION_TOKEN_BYTES = 32
SESSION_TOUCH_INTERVAL_SECONDS = 60
MAX_DEVICES_PER_USER = 20
_LIMITED_PREFIXES = ("/auth/", "/devices")
_JSON_POST_PATHS = {"/auth/register", "/auth/login", "/devices"}


class AccountAPIConfigError(ValueError):
    """The account API configuration is missing or unsafe."""


@dataclass(frozen=True)
class AccountAPIConfig:
    database_path: Path = DEFAULT_ACCOUNT_DATABASE
    bind_host: str = "127.0.0.1"
    bind_port: int = 8443
    tls_cert: Path | None = None
    tls_key: Path | None = None
    allow_insecure_loopback: bool = False
    session_lifetime_seconds: int = DEFAULT_SESSION_LIFETIME_SECONDS
    login_rate_limit: int = 5
    login_rate_window_seconds: int = 60
    login_cooldown_seconds: int = 60
    registration_rate_limit: int = 3
    registration_rate_window_seconds: int = 60
    registration_cooldown_seconds: int = 60
    login_rate_limit_entries: int = 4096
    registration_rate_limit_entries: int = 2048
    body_limit_bytes: int = DEFAULT_BODY_LIMIT

    def validate(self) -> None:
        if not isinstance(self.database_path, Path):
            raise AccountAPIConfigError("database_path must be a filesystem path")
        if not isinstance(self.bind_host, str):
            raise AccountAPIConfigError("bind_host must be an IP address literal")
        if type(self.allow_insecure_loopback) is not bool:
            raise AccountAPIConfigError("allow_insecure_loopback must be boolean")
        if self.tls_cert is not None and not isinstance(self.tls_cert, Path):
            raise AccountAPIConfigError("tls_cert must be a filesystem path")
        if self.tls_key is not None and not isinstance(self.tls_key, Path):
            raise AccountAPIConfigError("tls_key must be a filesystem path")
        try:
            address = ipaddress.ip_address(self.bind_host)
        except ValueError as exc:
            raise AccountAPIConfigError("bind_host must be an IPv4 or IPv6 address literal") from exc
        if type(self.bind_port) is not int or not 1 <= self.bind_port <= 65535:
            raise AccountAPIConfigError("bind_port must be in 1..65535")
        if (self.tls_cert is None) != (self.tls_key is None):
            raise AccountAPIConfigError("tls_cert and tls_key must be configured together")
        if self.tls_cert is None:
            if not address.is_loopback or not self.allow_insecure_loopback:
                raise AccountAPIConfigError(
                    "TLS is required unless insecure loopback HTTP is explicitly enabled"
                )
        else:
            _validate_tls_file(self.tls_cert, "TLS certificate", private=False)
            _validate_tls_file(self.tls_key, "TLS private key", private=True)
        numeric_bounds = {
            "session_lifetime_seconds": (self.session_lifetime_seconds, 60, 7 * 24 * 60 * 60),
            "login_rate_limit": (self.login_rate_limit, 1, 100),
            "login_rate_window_seconds": (self.login_rate_window_seconds, 1, 3600),
            "login_cooldown_seconds": (self.login_cooldown_seconds, 1, 3600),
            "registration_rate_limit": (self.registration_rate_limit, 1, 100),
            "registration_rate_window_seconds": (
                self.registration_rate_window_seconds, 1, 3600
            ),
            "registration_cooldown_seconds": (
                self.registration_cooldown_seconds, 1, 3600
            ),
            "login_rate_limit_entries": (self.login_rate_limit_entries, 1, 100_000),
            "registration_rate_limit_entries": (
                self.registration_rate_limit_entries, 1, 100_000
            ),
            "body_limit_bytes": (self.body_limit_bytes, 1024, 64 * 1024),
        }
        for name, (value, minimum, maximum) in numeric_bounds.items():
            if type(value) is not int or not minimum <= value <= maximum:
                raise AccountAPIConfigError(f"{name} must be in {minimum}..{maximum}")


def _validate_tls_file(path: Path | None, description: str, *, private: bool) -> None:
    assert path is not None
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:-1]:
        current /= part
        try:
            component = current.lstat()
        except OSError as exc:
            raise AccountAPIConfigError(f"{description} path is unavailable") from exc
        if stat.S_ISLNK(component.st_mode) or not stat.S_ISDIR(component.st_mode):
            raise AccountAPIConfigError(f"{description} path contains an unsafe component")
    try:
        info = absolute.lstat()
    except OSError as exc:
        raise AccountAPIConfigError(f"{description} is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AccountAPIConfigError(f"{description} must be a regular non-symlink file")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise AccountAPIConfigError("TLS private key must not be accessible by group or others")


def load_account_api_config(path: Path | str = DEFAULT_CONFIG) -> AccountAPIConfig:
    config_path = Path(path).absolute()
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise AccountAPIConfigError("unable to read account API configuration") from exc
    if set(raw) != {"account_api"} or not isinstance(raw["account_api"], dict):
        raise AccountAPIConfigError("configuration must contain only an [account_api] table")
    values = dict(raw["account_api"])
    allowed = set(AccountAPIConfig.__dataclass_fields__)
    unknown = set(values) - allowed
    if unknown:
        raise AccountAPIConfigError(f"unknown account API setting: {sorted(unknown)[0]}")
    base = config_path.parent
    for name in ("database_path", "tls_cert", "tls_key"):
        if name in values and values[name] is not None:
            if not isinstance(values[name], str):
                raise AccountAPIConfigError(f"{name} must be a path string")
            candidate = Path(values[name])
            values[name] = (candidate if candidate.is_absolute() else base / candidate).absolute()
    try:
        config = AccountAPIConfig(**values)
    except TypeError as exc:
        raise AccountAPIConfigError("invalid account API configuration") from exc
    config.validate()
    return config


@dataclass
class _RateEntry:
    events: deque[float] = field(default_factory=deque)
    blocked_until: float = 0.0
    last_seen: float = 0.0


class BoundedRateLimiter:
    """Thread-safe, bounded rolling-window event limiter using monotonic time."""

    def __init__(
        self,
        limit: int,
        window_seconds: int,
        cooldown_seconds: int,
        max_entries: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        if min(limit, window_seconds, cooldown_seconds, max_entries) < 1:
            raise ValueError("rate-limit values must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, _RateEntry] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        stale_after = max(self.window_seconds, self.cooldown_seconds)
        for key, entry in list(self._entries.items()):
            while entry.events and entry.events[0] <= now - self.window_seconds:
                entry.events.popleft()
            if not entry.events and entry.blocked_until <= now and entry.last_seen <= now - stale_after:
                del self._entries[key]

    def retry_after(self, key: str) -> int:
        now = self._clock()
        with self._lock:
            self._prune(now)
            entry = self._entries.get(key)
            if entry is None or entry.blocked_until <= now:
                return 0
            entry.last_seen = now
            self._entries.move_to_end(key)
            return max(1, math.ceil(entry.blocked_until - now))

    def record_event(self, key: str) -> None:
        now = self._clock()
        with self._lock:
            self._prune(now)
            entry = self._entries.get(key)
            if entry is None:
                entry = _RateEntry(events=deque(maxlen=self.limit))
                self._entries[key] = entry
            while entry.events and entry.events[0] <= now - self.window_seconds:
                entry.events.popleft()
            entry.events.append(now)
            entry.last_seen = now
            if len(entry.events) >= self.limit:
                entry.blocked_until = max(entry.blocked_until, now + self.cooldown_seconds)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def reset(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            self._prune(self._clock())
            return len(self._entries)


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    username: str = Field(max_length=MAX_USERNAME_LENGTH + 2)
    email: str = Field(max_length=MAX_EMAIL_LENGTH + 2)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH + 1)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    identifier: str = Field(min_length=1, max_length=MAX_EMAIL_LENGTH + 2)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class DeviceBindRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    device_name: str = Field(min_length=1, max_length=MAX_DEVICE_NAME_LENGTH + 2)
    public_key: str = Field(min_length=1, max_length=64)
    fingerprint: str = Field(min_length=64, max_length=64)


@dataclass(frozen=True)
class AuthenticatedContext:
    user: UserRecord
    session: SessionRecord
    token_hash: bytes


def _error(status: int, code: str, message: str, *, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
        headers=headers,
    )


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith(_LIMITED_PREFIXES):
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        length = headers.get(b"content-length")
        if length is not None:
            try:
                if int(length) > self.max_bytes:
                    await _error(413, "request_too_large", "request body is too large")(scope, receive, send)
                    return
            except ValueError:
                await _error(400, "invalid_request", "invalid Content-Length header")(scope, receive, send)
                return
        if scope.get("method") == "POST" and scope.get("path") in _JSON_POST_PATHS:
            content_type = headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
            if content_type != b"application/json":
                await _error(415, "unsupported_media_type", "Content-Type must be application/json")(
                    scope, receive, send
                )
                return
        if scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        consumed = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            consumed += len(body)
            if consumed > self.max_bytes:
                await _error(413, "request_too_large", "request body is too large")(
                    scope, receive, send
                )
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break
        buffered = b"".join(chunks)
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": buffered, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


def _public_user(user: UserRecord) -> dict[str, object]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "enabled": user.enabled,
        "created_at": user.created_at,
    }


def _public_device(device: DeviceRecord) -> dict[str, object]:
    """Public device fields only; the account API never handles private keys."""
    return {
        "id": device.id,
        "device_name": device.device_name,
        "fingerprint": device.client_fingerprint,
        "enabled": device.enabled,
        "status": device.status,
        "created_at": device.created_at,
    }


def _source(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


def _login_key(request: Request, identifier: str) -> str:
    normalized = unicodedata.normalize("NFKC", identifier.strip()).casefold()
    material = f"{_source(request)}\0{normalized}".encode("utf-8", errors="replace")
    return hashlib.sha256(material).hexdigest()


def _registration_key(request: Request) -> str:
    return hashlib.sha256(_source(request).encode("utf-8", errors="replace")).hexdigest()


def _presented_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization")
    if authorization is None or len(authorization) > 512:
        return None
    pieces = authorization.split()
    if len(pieces) != 2 or pieces[0].casefold() != "bearer" or not pieces[1]:
        return None
    return pieces[1]


async def get_authenticated_user(request: Request) -> AuthenticatedContext | JSONResponse:
    token = _presented_token(request)
    if token is None:
        return _error(
            401, "invalid_session", "valid bearer authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token_hash = hashlib.sha256(token.encode("ascii", errors="replace")).digest()
    validated = request.app.state.account_store.validate_session(
        token_hash, touch_interval_seconds=SESSION_TOUCH_INTERVAL_SECONDS
    )
    if validated is None:
        return _error(
            401, "invalid_session", "valid bearer authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user, session = validated
    return AuthenticatedContext(user=user, session=session, token_hash=token_hash)


def create_app(
    config: AccountAPIConfig,
    *,
    store: AccountStore | None = None,
    login_limiter: BoundedRateLimiter | None = None,
    registration_limiter: BoundedRateLimiter | None = None,
) -> FastAPI:
    config.validate()
    account_store = store or AccountStore(config.database_path)
    account_store.initialize()
    application = FastAPI(
        title="PQ-VPN Account Authentication API",
        version="4.2",
        docs_url=None,
        redoc_url=None,
    )
    application.add_middleware(BodyLimitMiddleware, max_bytes=config.body_limit_bytes)
    application.state.account_store = account_store
    application.state.config = config
    application.state.login_limiter = login_limiter or BoundedRateLimiter(
        config.login_rate_limit,
        config.login_rate_window_seconds,
        config.login_cooldown_seconds,
        config.login_rate_limit_entries,
    )
    application.state.registration_limiter = registration_limiter or BoundedRateLimiter(
        config.registration_rate_limit,
        config.registration_rate_window_seconds,
        config.registration_cooldown_seconds,
        config.registration_rate_limit_entries,
    )

    @application.exception_handler(RequestValidationError)
    async def request_validation_error(_request: Request, _exc: RequestValidationError):
        return _error(400, "invalid_request", "request body is invalid")

    @application.exception_handler(AccountDatabaseError)
    async def database_error(request: Request, _exc: AccountDatabaseError):
        logger.error("account database failure endpoint=%s", request.url.path)
        return _error(500, "internal_error", "internal server error")

    @application.exception_handler(Exception)
    async def internal_error(request: Request, _exc: Exception):
        logger.error("unexpected account API failure endpoint=%s", request.url.path)
        return _error(500, "internal_error", "internal server error")

    @application.post("/auth/register", status_code=201)
    async def register(payload: RegisterRequest, request: Request):
        key = _registration_key(request)
        retry = application.state.registration_limiter.retry_after(key)
        if retry:
            logger.warning("registration rate limited source=%s", _source(request))
            return _error(
                429, "rate_limited", "too many registration attempts",
                headers={"Retry-After": str(retry)},
            )
        application.state.registration_limiter.record_event(key)
        try:
            user = account_store.create_user(payload.username, payload.email, payload.password)
        except AccountAlreadyExists as exc:
            logger.info("registration rejected category=duplicate source=%s", _source(request))
            return _error(409, "account_exists", str(exc))
        except InvalidAccountInput as exc:
            logger.info("registration rejected category=invalid source=%s", _source(request))
            return _error(400, "invalid_registration", str(exc))
        logger.info("registration succeeded user_id=%d source=%s", user.id, _source(request))
        return JSONResponse(status_code=201, content={"user": _public_user(user)})

    @application.post("/auth/login")
    async def login(payload: LoginRequest, request: Request):
        key = _login_key(request, payload.identifier)
        retry = application.state.login_limiter.retry_after(key)
        if retry:
            logger.warning("login rate limited source=%s", _source(request))
            return _error(
                429, "rate_limited", "too many authentication attempts",
                headers={"Retry-After": str(retry)},
            )
        user = account_store.authenticate_user(payload.identifier, payload.password)
        if user is None:
            application.state.login_limiter.record_event(key)
            logger.info("login rejected category=invalid_credentials source=%s", _source(request))
            return _error(401, "invalid_credentials", "invalid credentials")
        application.state.login_limiter.reset(key)
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=config.session_lifetime_seconds
        )
        for _attempt in range(3):
            raw_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
            token_hash = hashlib.sha256(raw_token.encode("ascii")).digest()
            try:
                session = account_store.create_session(user.id, token_hash, expires_at)
            except AccountAlreadyExists:
                continue
            except (AccountNotFound, InvalidAccountInput):
                return _error(401, "invalid_credentials", "invalid credentials")
            break
        else:  # pragma: no cover - requires repeated SHA-256 token collisions
            logger.error("unable to allocate a unique account session")
            return _error(500, "internal_error", "internal server error")
        logger.info("login succeeded user_id=%d source=%s", user.id, _source(request))
        return {
            "access_token": raw_token,
            "token_type": "bearer",
            "expires_at": session.expires_at,
            "user": _public_user(user),
        }

    @application.get("/auth/me")
    async def me(context=Depends(get_authenticated_user)):
        if isinstance(context, JSONResponse):
            return context
        return {"user": _public_user(context.user)}

    @application.get("/devices")
    async def list_devices(context=Depends(get_authenticated_user)):
        if isinstance(context, JSONResponse):
            return context
        devices = account_store.list_devices_for_user(context.user.id)
        return {"devices": [_public_device(device) for device in devices]}

    @application.post("/devices", status_code=201)
    async def bind_device(
        payload: DeviceBindRequest, request: Request, context=Depends(get_authenticated_user)
    ):
        """Bind a public Ed25519 identity to the account; never grants VPN access."""
        if isinstance(context, JSONResponse):
            return context
        try:
            public_key = base64.b64decode(payload.public_key, validate=True)
        except (binascii.Error, ValueError):
            return _error(400, "invalid_device", "device public key must be base64")
        existing = None
        try:
            existing = account_store.get_device_by_fingerprint(payload.fingerprint)
        except InvalidAccountInput:
            pass  # rejected with the full validation message below
        if existing is not None:
            if existing.user_id == context.user.id and existing.client_public_key == public_key:
                return JSONResponse(status_code=200, content={"device": _public_device(existing)})
            logger.info("device binding rejected category=duplicate user_id=%d", context.user.id)
            return _error(409, "device_exists", "device identity is already registered")
        if len(account_store.list_devices_for_user(context.user.id)) >= MAX_DEVICES_PER_USER:
            return _error(409, "device_limit", "account device limit reached")
        try:
            device = account_store.add_device(
                context.user.id, payload.device_name, payload.fingerprint, public_key
            )
        except AccountAlreadyExists:
            return _error(409, "device_exists", "device identity is already registered")
        except InvalidAccountInput as exc:
            return _error(400, "invalid_device", str(exc))
        logger.info(
            "device bound user_id=%d device_id=%d source=%s",
            context.user.id, device.id, _source(request),
        )
        return JSONResponse(status_code=201, content={"device": _public_device(device)})

    @application.post("/auth/logout", status_code=204)
    async def logout(request: Request, context=Depends(get_authenticated_user)):
        if isinstance(context, JSONResponse):
            return context
        account_store.revoke_session(context.token_hash)
        logger.info("logout succeeded user_id=%d source=%s", context.user.id, _source(request))
        return Response(status_code=204)

    return application


def run(config: AccountAPIConfig) -> None:
    config.validate()
    import uvicorn

    uvicorn.run(
        create_app(config),
        host=config.bind_host,
        port=config.bind_port,
        ssl_certfile=str(config.tls_cert) if config.tls_cert else None,
        ssl_keyfile=str(config.tls_key) if config.tls_key else None,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        limit_concurrency=100,
        timeout_keep_alive=5,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pqvpn-account-api")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = load_account_api_config(args.config)
        run(config)
    except AccountAPIConfigError as exc:
        raise SystemExit(f"account API configuration error: {exc}") from None


if __name__ == "__main__":
    main()
