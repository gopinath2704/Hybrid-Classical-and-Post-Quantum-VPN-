"""Account page — profile, security, and device binding (login moved to LoginWindow)."""
from __future__ import annotations

import socket

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QStackedWidget, QVBoxLayout, QWidget,
)

from app.client import DEVICE_STATUS_LABELS, sanitize_error, truncate_fingerprint
from app.ui.theme import COLORS, DANGER_BTN, PRIMARY_BTN, badge_style, label
from app.ui.components import Card, DataRow


class AccountPage:
    def __init__(self, *, on_logout, on_bind_device,
                 on_mfa_enable, on_mfa_confirm, on_mfa_disable,
                 on_change_password) -> None:
        self._on_logout = on_logout
        self._on_bind_device = on_bind_device
        self._on_mfa_enable = on_mfa_enable
        self._on_mfa_confirm = on_mfa_confirm
        self._on_mfa_disable = on_mfa_disable
        self._on_change_password = on_change_password

    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(14)

        self.account_stack = QStackedWidget()

        # ── Signed-out view (index 0) ──
        signed_out_widget = QWidget()
        signed_out_layout = QVBoxLayout(signed_out_widget)
        signed_out_layout.setContentsMargins(0, 0, 0, 0)
        signed_out_layout.setSpacing(12)
        signed_out_card = Card("Not Signed In")
        self.signed_out_message = label(
            "You are not currently signed in. Restart the application to sign in.",
            12, COLORS["secondary"],
        )
        self.signed_out_message.setWordWrap(True)
        signed_out_card.body.addWidget(self.signed_out_message)
        signed_out_layout.addWidget(signed_out_card)
        signed_out_layout.addStretch(1)

        # ── Profile view (index 1) ──
        profile_widget = QWidget()
        profile_layout = QVBoxLayout(profile_widget)
        profile_layout.setContentsMargins(0, 0, 0, 0)
        profile_layout.setSpacing(12)

        profile_card = Card("Account Profile")
        profile_header = QHBoxLayout()
        self.profile_avatar = QLabel("\U0001F464")
        self.profile_avatar.setStyleSheet(f"""
            font-size: 36px; background: {COLORS['surface']};
            border: 2px solid {COLORS['green']}; border-radius: 28px; padding: 8px;
        """)
        self.profile_avatar.setFixedSize(56, 56)
        self.profile_avatar.setAlignment(Qt.AlignCenter)
        profile_names = QVBoxLayout()
        profile_names.setSpacing(2)
        self.profile_username = label("—", 18, weight=700)
        self.profile_email = label("—", 12, COLORS["secondary"])
        profile_names.addWidget(self.profile_username)
        profile_names.addWidget(self.profile_email)
        profile_header.addWidget(self.profile_avatar)
        profile_header.addSpacing(14)
        profile_header.addLayout(profile_names)
        profile_header.addStretch(1)
        self.profile_session_badge = label("SESSION ACTIVE", 9, COLORS["green"], 700)
        self.profile_session_badge.setStyleSheet(badge_style(COLORS["green"]))
        profile_header.addWidget(self.profile_session_badge)
        profile_card.body.addLayout(profile_header)

        self.profile_id_row = DataRow("User ID")
        self.profile_status_row = DataRow("Account status")
        self.profile_created_row = DataRow("Created")
        self.profile_expires_row = DataRow("Session expires")
        for row in (self.profile_id_row, self.profile_status_row,
                    self.profile_created_row, self.profile_expires_row):
            profile_card.body.addWidget(row)
        signout_row = QHBoxLayout()
        self.signout_btn = QPushButton("Sign Out")
        self.signout_btn.setCursor(Qt.PointingHandCursor)
        self.signout_btn.setFixedWidth(140)
        self.signout_btn.setStyleSheet(DANGER_BTN)
        self.signout_btn.clicked.connect(self._on_logout)
        signout_row.addWidget(self.signout_btn)
        signout_row.addStretch(1)
        profile_card.body.addLayout(signout_row)
        profile_layout.addWidget(profile_card)

        # Account Security
        security_card = Card("Account Security", "Multi-factor authentication and password management.")
        self.acct_mfa_status = DataRow("MFA status")
        security_card.body.addWidget(self.acct_mfa_status)
        self.acct_mfa_secret_label = label("", 10, COLORS["secondary"])
        self.acct_mfa_secret_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.acct_mfa_secret_label.setWordWrap(True)
        self.acct_mfa_secret_label.hide()
        security_card.body.addWidget(self.acct_mfa_secret_label)
        self.acct_mfa_uri_label = label("", 9, COLORS["muted"])
        self.acct_mfa_uri_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.acct_mfa_uri_label.setWordWrap(True)
        self.acct_mfa_uri_label.hide()
        security_card.body.addWidget(self.acct_mfa_uri_label)
        security_card.body.addWidget(label("CONFIRM CODE", 9, COLORS["muted"], 700))
        self.acct_mfa_code = QLineEdit()
        self.acct_mfa_code.setPlaceholderText("6-digit code from authenticator")
        self.acct_mfa_code.setMaxLength(6)
        self.acct_mfa_code.setMaximumWidth(220)
        self.acct_mfa_code.hide()
        security_card.body.addWidget(self.acct_mfa_code)
        self.acct_mfa_error = label("", 11, COLORS["red"], 550)
        self.acct_mfa_error.setWordWrap(True)
        self.acct_mfa_error.hide()
        security_card.body.addWidget(self.acct_mfa_error)
        mfa_actions = QHBoxLayout()
        self.acct_mfa_enable_btn = QPushButton("Enable MFA")
        self.acct_mfa_enable_btn.clicked.connect(self._on_mfa_enable)
        self.acct_mfa_confirm_btn = QPushButton("Confirm Code")
        self.acct_mfa_confirm_btn.setStyleSheet(PRIMARY_BTN)
        self.acct_mfa_confirm_btn.clicked.connect(self._on_mfa_confirm)
        self.acct_mfa_confirm_btn.hide()
        self.acct_mfa_disable_btn = QPushButton("Disable MFA")
        self.acct_mfa_disable_btn.setStyleSheet(DANGER_BTN)
        self.acct_mfa_disable_btn.clicked.connect(self._on_mfa_disable)
        self.acct_mfa_disable_btn.hide()
        mfa_actions.addWidget(self.acct_mfa_enable_btn)
        mfa_actions.addWidget(self.acct_mfa_confirm_btn)
        mfa_actions.addWidget(self.acct_mfa_disable_btn)
        mfa_actions.addStretch(1)
        security_card.body.addLayout(mfa_actions)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {COLORS['border_soft']};")
        security_card.body.addWidget(sep)
        security_card.body.addWidget(label("CHANGE PASSWORD", 9, COLORS["muted"], 700))
        self.acct_old_password = QLineEdit()
        self.acct_old_password.setPlaceholderText("Current password")
        self.acct_old_password.setEchoMode(QLineEdit.Password)
        self.acct_old_password.setMaximumWidth(380)
        security_card.body.addWidget(self.acct_old_password)
        self.acct_new_password = QLineEdit()
        self.acct_new_password.setPlaceholderText("New password (minimum 12 characters)")
        self.acct_new_password.setEchoMode(QLineEdit.Password)
        self.acct_new_password.setMaximumWidth(380)
        security_card.body.addWidget(self.acct_new_password)
        self.acct_pw_error = label("", 11, COLORS["red"], 550)
        self.acct_pw_error.setWordWrap(True)
        self.acct_pw_error.hide()
        security_card.body.addWidget(self.acct_pw_error)
        pw_actions = QHBoxLayout()
        self.acct_change_pw_btn = QPushButton("Change Password")
        self.acct_change_pw_btn.clicked.connect(self._on_change_password)
        pw_actions.addWidget(self.acct_change_pw_btn)
        pw_actions.addStretch(1)
        security_card.body.addLayout(pw_actions)
        profile_layout.addWidget(security_card)

        self._mfa_pending_secret: str | None = None

        # Device card
        device_card = Card(
            "This Device",
            "Bind this device's public identity to your account. Only the public key "
            "and fingerprint are sent; the private key never leaves this machine.",
        )
        self.device_fingerprint_row = DataRow("Device fingerprint")
        self.device_binding_row = DataRow("Account binding")
        self.device_count_row = DataRow("Devices on account")
        for row in (self.device_fingerprint_row, self.device_binding_row,
                    self.device_count_row):
            device_card.body.addWidget(row)
        device_card.body.addWidget(label("DEVICE NAME", 9, COLORS["muted"], 700))
        self.device_name_input = QLineEdit(socket.gethostname()[:100])
        self.device_name_input.setMaxLength(100)
        self.device_name_input.setMaximumWidth(440)
        device_card.body.addWidget(self.device_name_input)
        self.device_error = label("", 11, COLORS["red"], 550)
        self.device_error.setWordWrap(True)
        self.device_error.hide()
        device_card.body.addWidget(self.device_error)
        device_actions = QHBoxLayout()
        self.device_bind_btn = QPushButton("Register This Device")
        self.device_bind_btn.clicked.connect(self._on_bind_device)
        device_actions.addWidget(self.device_bind_btn)
        device_actions.addStretch(1)
        device_card.body.addLayout(device_actions)
        profile_layout.addWidget(device_card)

        separation_card = Card("VPN Authorization Notice")
        separation_notice = label(
            "⚠️  Account login authenticates user identity only. "
            "Device enrollment and administrator authorization are required "
            "for VPN tunnel access. Signing in does not grant VPN permission.",
            11, COLORS["amber"], 550,
        )
        separation_notice.setWordWrap(True)
        separation_card.body.addWidget(separation_notice)
        profile_layout.addWidget(separation_card)
        profile_layout.addStretch(1)

        self.account_stack.addWidget(signed_out_widget)
        self.account_stack.addWidget(profile_widget)
        self.account_stack.setCurrentIndex(0)
        layout.addWidget(self.account_stack)
        return page

    # ── View helpers ──

    def show_signed_out(self, message: str = "") -> None:
        if message:
            self.signed_out_message.setText(message)
        self.account_stack.setCurrentIndex(0)

    def show_profile_view(self) -> None:
        self.account_stack.setCurrentIndex(1)

    def refresh_mfa_ui(self, mfa_enabled: bool) -> None:
        self.acct_mfa_status.set_value(
            "Enabled" if mfa_enabled else "Disabled",
            COLORS["green"] if mfa_enabled else COLORS["secondary"],
        )
        self.acct_mfa_enable_btn.setVisible(not mfa_enabled)
        self.acct_mfa_disable_btn.setVisible(mfa_enabled)
        self.acct_mfa_error.hide()
        if mfa_enabled:
            self.acct_mfa_code.show()
        else:
            self.acct_mfa_code.hide()
            self.acct_mfa_code.clear()

    def render_device(self, fingerprint: str | None, device: dict | None,
                      devices: list[dict], is_authenticated: bool) -> None:
        self.device_fingerprint_row.set_value(truncate_fingerprint(fingerprint))
        if not fingerprint:
            binding = "Identity not ready"
        elif device is None:
            binding = "Not registered"
        else:
            status = DEVICE_STATUS_LABELS.get(device.get("status"), "Unknown status")
            if device.get("enabled") is False:
                status = "Disabled"
            binding = (
                f"Registered as {sanitize_error(device.get('device_name', ''), 100)} · {status}"
            )
        self.device_binding_row.set_value(binding)
        self.device_count_row.set_value(len(devices))
        self.device_bind_btn.setEnabled(
            bool(fingerprint) and device is None and is_authenticated
        )
