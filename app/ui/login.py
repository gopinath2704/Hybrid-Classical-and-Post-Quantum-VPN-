"""Standalone login/register window — authentication gate before the main app."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QStackedWidget, QVBoxLayout, QWidget,
)

from app.client import (
    DEFAULT_ACCOUNT_API_URL, AccountAPIError, AccountClient,
    _AccountWorker, _ACCOUNT_ERROR_MESSAGES,
)
from app.ui.theme import COLORS, LINK_BTN, PRIMARY_BTN, label
from app.ui.components import Card


class LoginWindow(QWidget):
    """Authentication gate shown before the main window."""

    login_succeeded = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PQ-VPN · Sign In")
        self.setMinimumSize(520, 480)
        self.resize(560, 580)
        self.setStyleSheet(f"background-color: {COLORS['background']};")

        self.session_token: str | None = None
        self.session_user: dict | None = None
        self.session_expires_at: str = ""
        self.account_client: AccountClient | None = None

        self._worker = _AccountWorker()
        self._worker.finished.connect(self._on_finished)
        self._cooldown_timer = QTimer(self)
        self._cooldown_timer.setInterval(1000)
        self._cooldown_timer.timeout.connect(self._tick_cooldown)
        self._cooldown_remaining = 0
        self._cooldown_is_login = True

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)

        brand = QHBoxLayout()
        mark = QLabel("PQ")
        mark.setAlignment(Qt.AlignCenter)
        mark.setFixedSize(38, 38)
        mark.setStyleSheet(
            f"background: #0E3423; color: {COLORS['green']}; "
            "border: 1px solid #1B5B3D; border-radius: 10px; "
            "font-size: 12px; font-weight: 750;"
        )
        brand.addWidget(mark)
        brand.addSpacing(8)
        brand.addWidget(label("PQ-VPN", 20, weight=700))
        brand.addStretch()
        root.addLayout(brand)

        api_card = Card("Account API Server")
        self.api_url = QLineEdit(DEFAULT_ACCOUNT_API_URL)
        self.api_url.setPlaceholderText("https://server:8443 or http://127.0.0.1:8443")
        self.api_url.setMaximumWidth(460)
        api_card.body.addWidget(label("API ENDPOINT", 9, COLORS["muted"], 700))
        api_card.body.addWidget(self.api_url)
        self.ca_cert = QLineEdit()
        self.ca_cert.setPlaceholderText("Optional CA certificate path for a private server certificate")
        self.ca_cert.setMaximumWidth(460)
        api_card.body.addWidget(label("CA CERTIFICATE", 9, COLORS["muted"], 700))
        api_card.body.addWidget(self.ca_cert)
        api_card.body.addWidget(label(
            "HTTPS certificates are always verified. Cleartext HTTP is accepted only on loopback.",
            10, COLORS["secondary"],
        ))
        root.addWidget(api_card)

        self.stack = QStackedWidget()
        self._build_login_view()
        self._build_register_view()
        root.addWidget(self.stack)
        root.addStretch()

    # ── Build views ──

    def _build_login_view(self) -> None:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        card = Card("Sign In", "Authenticate with your PQ-VPN account credentials.")
        card.body.addWidget(label("IDENTIFIER", 9, COLORS["muted"], 700))
        self.login_identifier = QLineEdit()
        self.login_identifier.setPlaceholderText("Username or email address")
        self.login_identifier.setMaximumWidth(440)
        card.body.addWidget(self.login_identifier)

        card.body.addWidget(label("PASSWORD", 9, COLORS["muted"], 700))
        pw_row = QHBoxLayout()
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Enter password")
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_password.setMaximumWidth(380)
        self.login_reveal_btn = QPushButton("Show")
        self.login_reveal_btn.setFixedWidth(60)
        self.login_reveal_btn.setCursor(Qt.PointingHandCursor)
        self.login_reveal_btn.clicked.connect(self._toggle_password_visibility)
        pw_row.addWidget(self.login_password)
        pw_row.addWidget(self.login_reveal_btn)
        pw_row.addStretch(1)
        card.body.addLayout(pw_row)

        self.login_totp_label = label("TOTP CODE", 9, COLORS["muted"], 700)
        self.login_totp_label.hide()
        card.body.addWidget(self.login_totp_label)
        self.login_totp = QLineEdit()
        self.login_totp.setPlaceholderText("6-digit code from your authenticator")
        self.login_totp.setMaxLength(6)
        self.login_totp.setMaximumWidth(220)
        self.login_totp.returnPressed.connect(self._on_login)
        self.login_totp.hide()
        card.body.addWidget(self.login_totp)

        self.login_error = label("", 11, COLORS["red"], 550)
        self.login_error.setWordWrap(True)
        self.login_error.hide()
        card.body.addWidget(self.login_error)
        self.login_cooldown_label = label("", 11, COLORS["amber"], 600)
        self.login_cooldown_label.hide()
        card.body.addWidget(self.login_cooldown_label)

        actions = QHBoxLayout()
        self.login_btn = QPushButton("Sign In")
        self.login_btn.setCursor(Qt.PointingHandCursor)
        self.login_btn.setFixedWidth(140)
        self.login_btn.setStyleSheet(PRIMARY_BTN)
        self.login_btn.clicked.connect(self._on_login)
        self.login_password.returnPressed.connect(self._on_login)
        self.login_register_link = QPushButton("Need an account? Register")
        self.login_register_link.setCursor(Qt.PointingHandCursor)
        self.login_register_link.setStyleSheet(LINK_BTN)
        self.login_register_link.clicked.connect(self._show_register)
        actions.addWidget(self.login_btn)
        actions.addWidget(self.login_register_link)
        actions.addStretch(1)
        card.body.addLayout(actions)

        layout.addWidget(card)
        layout.addStretch(1)
        self.stack.addWidget(widget)

    def _build_register_view(self) -> None:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        card = Card("Create Account", "Register a new PQ-VPN user account.")
        card.body.addWidget(label("USERNAME", 9, COLORS["muted"], 700))
        self.register_username = QLineEdit()
        self.register_username.setPlaceholderText("Choose a username")
        self.register_username.setMaximumWidth(440)
        card.body.addWidget(self.register_username)
        card.body.addWidget(label("EMAIL", 9, COLORS["muted"], 700))
        self.register_email = QLineEdit()
        self.register_email.setPlaceholderText("Your email address")
        self.register_email.setMaximumWidth(440)
        card.body.addWidget(self.register_email)
        card.body.addWidget(label("PASSWORD", 9, COLORS["muted"], 700))
        self.register_password = QLineEdit()
        self.register_password.setPlaceholderText("Minimum 12 characters")
        self.register_password.setEchoMode(QLineEdit.Password)
        self.register_password.setMaximumWidth(440)
        self.register_password.textChanged.connect(self._update_register_validation)
        card.body.addWidget(self.register_password)
        card.body.addWidget(label("CONFIRM PASSWORD", 9, COLORS["muted"], 700))
        self.register_confirm = QLineEdit()
        self.register_confirm.setPlaceholderText("Re-enter password")
        self.register_confirm.setEchoMode(QLineEdit.Password)
        self.register_confirm.setMaximumWidth(440)
        self.register_confirm.textChanged.connect(self._update_register_validation)
        card.body.addWidget(self.register_confirm)
        self.register_validation = label("", 10, COLORS["muted"])
        card.body.addWidget(self.register_validation)
        self.register_error = label("", 11, COLORS["red"], 550)
        self.register_error.setWordWrap(True)
        self.register_error.hide()
        card.body.addWidget(self.register_error)
        self.register_cooldown_label = label("", 11, COLORS["amber"], 600)
        self.register_cooldown_label.hide()
        card.body.addWidget(self.register_cooldown_label)
        actions = QHBoxLayout()
        self.register_btn = QPushButton("Create Account")
        self.register_btn.setCursor(Qt.PointingHandCursor)
        self.register_btn.setFixedWidth(180)
        self.register_btn.setStyleSheet(PRIMARY_BTN)
        self.register_btn.clicked.connect(self._on_register)
        self.register_confirm.returnPressed.connect(self._on_register)
        self.register_back_link = QPushButton("Already have an account? Sign In")
        self.register_back_link.setCursor(Qt.PointingHandCursor)
        self.register_back_link.setStyleSheet(LINK_BTN)
        self.register_back_link.clicked.connect(self._show_login)
        actions.addWidget(self.register_btn)
        actions.addWidget(self.register_back_link)
        actions.addStretch(1)
        card.body.addLayout(actions)

        layout.addWidget(card)
        layout.addStretch(1)
        self.stack.addWidget(widget)

    # ── View switching ──

    def show_login_view(self) -> None:
        self.stack.setCurrentIndex(0)
        self.login_error.hide()
        self.login_totp_label.hide()
        self.login_totp.hide()
        self.login_totp.clear()
        self.register_error.hide()

    def show_register_view(self) -> None:
        self.stack.setCurrentIndex(1)
        self.login_error.hide()
        self.register_error.hide()

    _show_login = show_login_view
    _show_register = show_register_view

    # ── Password toggle ──

    def _toggle_password_visibility(self) -> None:
        if self.login_password.echoMode() == QLineEdit.Password:
            self.login_password.setEchoMode(QLineEdit.Normal)
            self.login_reveal_btn.setText("Hide")
        else:
            self.login_password.setEchoMode(QLineEdit.Password)
            self.login_reveal_btn.setText("Show")

    # ── Register live-validation ──

    def _update_register_validation(self) -> None:
        password = self.register_password.text()
        confirm = self.register_confirm.text()
        parts: list[str] = []
        if password and len(password) < 12:
            parts.append(f"Password too short ({len(password)}/12 characters)")
        elif password:
            parts.append(f"Password length OK ({len(password)} characters)")
        if confirm and password != confirm:
            parts.append("Passwords do not match")
        elif confirm and password == confirm:
            parts.append("Passwords match ✓")
        color = COLORS["amber"] if any(
            "too short" in p or "do not match" in p for p in parts
        ) else COLORS["green"] if parts else COLORS["muted"]
        self.register_validation.setText("  ·  ".join(parts))
        self.register_validation.setStyleSheet(
            f"font-size: 10px; color: {color}; font-weight: 500;"
        )

    # ── Input enable/disable ──

    def set_inputs_enabled(self, enabled: bool) -> None:
        for w in (self.login_identifier, self.login_password, self.login_totp,
                  self.login_btn, self.login_register_link,
                  self.register_username, self.register_email,
                  self.register_password, self.register_confirm,
                  self.register_btn, self.register_back_link,
                  self.api_url, self.ca_cert):
            w.setEnabled(enabled)

    # ── Client ──

    def _get_or_create_client(self) -> AccountClient:
        url = self.api_url.text().strip() or DEFAULT_ACCOUNT_API_URL
        ca_text = self.ca_cert.text().strip()
        ca = Path(ca_text).expanduser() if ca_text else None
        client = self.account_client
        if client is None or client.base_url != url.rstrip("/") or client.ca_cert != ca:
            self.account_client = AccountClient(url, ca)
        return self.account_client

    def _submit(self, op: str, call, error_label=None) -> bool:
        try:
            client = self._get_or_create_client()
        except AccountAPIError as exc:
            if error_label is not None:
                error_label.setText(exc.message)
                error_label.show()
            return False
        self._worker.submit(op, lambda: call(client))
        return True

    # ── Login ──

    def _on_login(self) -> None:
        identifier = self.login_identifier.text().strip()
        password = self.login_password.text()
        if not identifier or not password:
            self.login_error.setText("Please enter your username/email and password.")
            self.login_error.show()
            return
        totp_code = self.login_totp.text().strip() or None
        if self.login_totp.isVisible() and not totp_code:
            self.login_error.setText("Enter the 6-digit code from your authenticator app.")
            self.login_error.show()
            return
        self.login_error.hide()

        def login(client: AccountClient) -> dict:
            token, _user, expires_at = client.login(identifier, password, totp_code)
            return {"token": token, "user": client.get_me(token), "expires_at": expires_at}

        if self._submit("login", login, self.login_error):
            self.set_inputs_enabled(False)
            self.login_btn.setText("Signing in…")

    # ── Register ──

    def _on_register(self) -> None:
        username = self.register_username.text().strip()
        email = self.register_email.text().strip()
        password = self.register_password.text()
        confirm = self.register_confirm.text()
        msg = ""
        if not username or not email or not password:
            msg = "All fields are required."
        elif len(password) < 12:
            msg = "Password must be at least 12 characters."
        elif len(password) > 1024:
            msg = "Password must be at most 1024 characters."
        elif password != confirm:
            msg = "Passwords do not match."
        self._set_register_message(msg)
        if msg:
            return
        if self._submit(
            "register", lambda client: client.register(username, email, password),
            self.register_error,
        ):
            self.set_inputs_enabled(False)
            self.register_btn.setText("Creating account…")

    def _set_register_message(self, text: str, *, success: bool = False) -> None:
        color = COLORS["green"] if success else COLORS["red"]
        self.register_error.setStyleSheet(
            f"font-size: 11px; color: {color}; font-weight: 550;"
        )
        self.register_error.setText(text)
        self.register_error.setVisible(bool(text))

    # ── Async result handler ──

    def _on_finished(self, op: str, ok: bool, data: object, message: str,
                     status_code: int, retry_after: int) -> None:
        if op == "login":
            self._login_finished(ok, data, message, status_code, retry_after)
        elif op == "register":
            self._register_finished(ok, data, message, status_code, retry_after)

    def _login_finished(self, ok, data, message, status_code, retry_after) -> None:
        self.set_inputs_enabled(True)
        self.login_btn.setText("Sign In")
        if ok and isinstance(data, dict):
            self.login_password.clear()
            self.login_totp.clear()
            self.login_totp_label.hide()
            self.login_totp.hide()
            self.session_token = data["token"]
            self.session_user = data["user"]
            self.session_expires_at = data.get("expires_at", "")
            self.login_succeeded.emit()
            return
        if isinstance(data, str) and data == "mfa_required":
            self.login_totp_label.show()
            self.login_totp.show()
            self.login_totp.setFocus()
            self.login_error.setText("Enter the 6-digit code from your authenticator app.")
            self.login_error.show()
            return
        if isinstance(data, str) and data == "account_locked":
            self.login_error.setText(message or _ACCOUNT_ERROR_MESSAGES["account_locked"])
            self.login_error.show()
            return
        self.login_password.clear()
        if retry_after > 0:
            self._start_cooldown(retry_after, is_login=True)
        self.login_error.setText(message or "Authentication failed.")
        self.login_error.show()

    def _register_finished(self, ok, data, message, status_code, retry_after) -> None:
        self.set_inputs_enabled(True)
        self.register_btn.setText("Create Account")
        if ok:
            username = data.get("username", "") if isinstance(data, dict) else ""
            for w in (self.register_password, self.register_confirm):
                w.clear()
            if username:
                self.login_identifier.setText(username)
            self._set_register_message(
                "Account created. Sign in to continue. This does not grant VPN access.",
                success=True,
            )
            QTimer.singleShot(1800, self._show_login)
            return
        if retry_after > 0:
            self._start_cooldown(retry_after, is_login=False)
        self._set_register_message(message or "Registration failed.")

    # ── Cooldown ──

    def _start_cooldown(self, seconds: int, *, is_login: bool) -> None:
        self._cooldown_remaining = seconds
        self._cooldown_is_login = is_login
        self.set_inputs_enabled(False)
        lbl = self.login_cooldown_label if is_login else self.register_cooldown_label
        lbl.setText(f"Rate limited. Please wait {seconds} seconds…")
        lbl.show()
        self._cooldown_timer.start()

    def _tick_cooldown(self) -> None:
        self._cooldown_remaining -= 1
        lbl = self.login_cooldown_label if self._cooldown_is_login else self.register_cooldown_label
        if self._cooldown_remaining <= 0:
            self._cooldown_timer.stop()
            lbl.hide()
            self.set_inputs_enabled(True)
        else:
            lbl.setText(f"Rate limited. Please wait {self._cooldown_remaining} seconds…")

    # ── Cleanup ──

    def closeEvent(self, event) -> None:  # noqa: N802
        self._cooldown_timer.stop()
        self._worker.stop()
        super().closeEvent(event)
