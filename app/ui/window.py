"""MainWindow coordinator — wires pages, workers, navigation, and status polling."""
from __future__ import annotations

import re
import socket
import time
from collections import deque
from dataclasses import asdict

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QInputDialog, QMainWindow, QMessageBox,
    QSizePolicy, QStackedWidget, QVBoxLayout, QWidget,
)

from app.client import (
    ACCOUNT_SESSION_CHECK_MS, AccountClient, AccountSession,
    ClientStatus, ConnectionState, DEFAULT_CONFIG,
    DEVICE_STATUS_LABELS, IPCClient, SessionState, UserProfile,
    _AccountWorker, _IPCWorker, account_ux_state, format_duration,
    public_device_identity, sanitize_error, truncate_fingerprint,
)
from app.ui.theme import COLORS, STATE_COLORS, badge_style, label
from app.ui.components import NavRail, scroll_page
from app.ui.pages.home import HomePage
from app.ui.pages.servers import ServersPage
from app.ui.pages.security import SecurityPage
from app.ui.pages.account import AccountPage
from app.ui.pages.settings import SettingsPage
from app.ui.pages.logs import LogsPage
from app.ui.pages.about import AboutPage


class MainWindow(QMainWindow):
    PAGE_TITLES = (
        ("Home", "Connection overview and live tunnel health"),
        ("Servers", "Imported public server profiles"),
        ("Security", "Cryptography, network protection, and identity"),
        ("Account", "Authentication and user session management"),
        ("Settings", "Validated service-owned configuration (read-only)"),
        ("Logs", "Bounded, sanitized client service events"),
        ("About", "Project scope and security boundaries"),
    )

    def __init__(self, ipc: IPCClient | None = None, start_polling: bool = True,
                 account_client: AccountClient | None = None,
                 session_token: str | None = None,
                 session_user: dict | None = None,
                 session_expires_at: str = "") -> None:
        super().__init__()
        self.setObjectName("pqvpnMainWindow")
        self.setWindowTitle("PQ-VPN")
        self.setMinimumSize(980, 650)
        self.resize(1180, 760)
        self.ipc = ipc or IPCClient()
        self._busy = False
        self._last_status = ClientStatus()
        self._gui_events: deque[dict[str, str]] = deque(maxlen=80)
        self._profile_signature: tuple = ()

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.nav = NavRail()
        self.nav.page_selected.connect(self.switch_page)
        root_layout.addWidget(self.nav)

        shell = QWidget()
        shell_layout = QVBoxLayout(shell)
        shell_layout.setContentsMargins(27, 22, 27, 16)
        shell_layout.setSpacing(14)
        root_layout.addWidget(shell, 1)

        header = QHBoxLayout()
        header_titles = QVBoxLayout()
        header_titles.setSpacing(2)
        self.page_title = label("Home", 23, weight=680)
        self.page_subtitle = label(
            "Connection overview and live tunnel health", 10, COLORS["secondary"]
        )
        header_titles.addWidget(self.page_title)
        header_titles.addWidget(self.page_subtitle)
        self.pqc_badge = label("PQC backend · CHECKING", 9, COLORS["muted"], 700)
        self.pqc_badge.setAlignment(Qt.AlignCenter)
        self.pqc_badge.setStyleSheet(badge_style(COLORS["muted"]))
        header.addLayout(header_titles)
        header.addStretch(1)
        header.addWidget(self.pqc_badge)
        shell_layout.addLayout(header)

        # ── Build pages ──
        self._home = HomePage(
            on_toggle=self._on_toggle,
            on_ensure_identity=self._ensure_identity,
            on_choose_profile=self._choose_profile,
            on_copy_enrollment=self._copy_enrollment_request,
            on_export_enrollment=self._export_enrollment_request,
            on_open_account=lambda: self.switch_page(3),
        )
        self._servers = ServersPage(
            on_choose_profile=self._choose_profile,
            on_poll_status=self._poll_status,
            on_select_profile=self._select_profile,
            on_remove_profile=self._remove_profile,
            on_copy_profile_info=self._copy_profile_info,
            on_copy_fingerprint=self._copy_fingerprint,
        )
        self._security = SecurityPage(
            on_copy_client_fp=self._copy_client_fingerprint,
            on_copy_enrollment=self._copy_enrollment_request,
            on_export_enrollment=self._export_enrollment_request,
        )
        self._account = AccountPage(
            on_logout=self._on_logout_clicked,
            on_bind_device=self._on_bind_device_clicked,
            on_mfa_enable=self._on_mfa_enable_clicked,
            on_mfa_confirm=self._on_mfa_confirm_clicked,
            on_mfa_disable=self._on_mfa_disable_clicked,
            on_change_password=self._on_change_password_clicked,
        )
        self._settings = SettingsPage()
        self._logs = LogsPage(on_refresh=self._refresh_logs, on_copy=self._copy_logs)
        self._about = AboutPage()

        self.pages = QStackedWidget()
        self.pages.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.pages.addWidget(scroll_page(self._home.build()))
        self.pages.addWidget(scroll_page(self._servers.build()))
        self.pages.addWidget(scroll_page(self._security.build()))
        self.pages.addWidget(scroll_page(self._account.build()))
        self.pages.addWidget(scroll_page(self._settings.build()))
        self.pages.addWidget(self._logs.build())
        self.pages.addWidget(scroll_page(self._about.build()))
        shell_layout.addWidget(self.pages, 1)

        footer = QHBoxLayout()
        self.footer_state = label("DISCONNECTED", 9, COLORS["muted"], 700)
        footer.addWidget(self.footer_state)
        footer.addStretch(1)
        footer.addWidget(label(
            "KEMTLS-inspired hybrid  ·  normal-user GUI  ·  privileged service",
            9, COLORS["muted"]
        ))
        shell_layout.addLayout(footer)

        # ── Workers ──
        self._worker = _IPCWorker(self.ipc)
        self._worker.status_ready.connect(self._render)
        self._worker.action_finished.connect(self._action_finished)
        self._worker.logs_ready.connect(self._render_logs_signal)

        self._account_session = AccountSession()
        self._account_client: AccountClient | None = account_client
        self._account_devices: list[dict] = []
        self._account_api_available = True
        self.account_ux_key = "logged_out"
        self._account_worker = _AccountWorker()
        self._account_worker.finished.connect(self._account_finished)
        self._session_timer = QTimer(self)
        self._session_timer.setInterval(ACCOUNT_SESSION_CHECK_MS)
        self._session_timer.timeout.connect(self._validate_account_session)

        # Seed session from login window if provided.
        if session_token and session_user is not None:
            user = UserProfile.from_dict(session_user)
            self._account_session.set_session(session_token, user, session_expires_at)
            self._session_timer.start()
            self._add_gui_event("info", f"Signed in as {user.username}")
            self._refresh_account_view()
            if account_client is not None:
                self._account_worker.submit(
                    "devices", lambda: account_client.list_devices(session_token))

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._poll_status)
        if start_polling:
            self._timer.start()
            QTimer.singleShot(80, self._poll_status)

    def __getattr__(self, name: str):
        for page in (self._home, self._servers, self._security,
                     self._account, self._settings, self._logs, self._about):
            try:
                return getattr(page, name)
            except AttributeError:
                continue
        raise AttributeError(f"'MainWindow' has no attribute {name!r}")

    # ── Navigation ──
    def switch_page(self, index: int, name: str | None = None) -> None:
        if not 0 <= index < self.pages.count():
            return
        self.pages.setCurrentIndex(index)
        self.nav.activate(index)
        title, subtitle = self.PAGE_TITLES[index]
        self.page_title.setText(title)
        self.page_subtitle.setText(subtitle)
        if index == 5:
            self._refresh_logs()

    # ── Polling ──
    def _poll_status(self) -> None:
        self._worker.request_status()

    def _refresh_logs(self) -> None:
        self._worker.request_logs()

    # ── Connection toggle ──
    def _on_toggle(self) -> None:
        state = self._last_status.state
        if self._busy or state in {ConnectionState.CONNECTING.value,
                                   ConnectionState.DISCONNECTING.value,
                                   ConnectionState.SETUP_REQUIRED.value}:
            return
        action = "disconnect" if state == ConnectionState.CONNECTED.value else "connect"
        transient = (ConnectionState.DISCONNECTING.value if action == "disconnect"
                     else ConnectionState.CONNECTING.value)
        self._busy = True
        self._set_visual_state(transient)
        self._add_gui_event("info", f"{action.title()} requested from desktop")
        self._worker.request_action(action)

    # ── Onboarding actions ──
    def _queue_onboarding_action(self, action: str, payload: object | None = None) -> None:
        if self._busy:
            return
        self._busy = True
        self._worker.request_action(action, payload)

    def _ensure_identity(self) -> None:
        self._queue_onboarding_action("ensure_identity")

    def _choose_profile(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import PQ-VPN server profile", "", "PQ-VPN Profiles (*.pqvpn)"
        )
        if path:
            self._queue_onboarding_action("import_profile", path)

    def _select_profile(self, profile_id: str) -> None:
        self._queue_onboarding_action("select_profile", profile_id)

    def _remove_profile(self, profile_id: str) -> None:
        answer = QMessageBox.question(
            self, "Remove server profile",
            f"Remove the exact profile '{profile_id}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self._queue_onboarding_action("delete_profile", profile_id)

    @staticmethod
    def _default_client_id() -> str:
        value = re.sub(r"[^A-Za-z0-9._-]+", "-", socket.gethostname()).strip(".-_")
        return (value or "linux-device")[:64]

    def _request_client_id(self) -> str | None:
        value, accepted = QInputDialog.getText(
            self, "Client enrollment", "Public client ID:",
            text=self._default_client_id(),
        )
        return value if accepted else None

    def _copy_enrollment_request(self) -> None:
        client_id = self._request_client_id()
        if client_id is not None:
            self._queue_onboarding_action("copy_enrollment", client_id)

    def _export_enrollment_request(self) -> None:
        client_id = self._request_client_id()
        if client_id is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export public enrollment request",
            f"{client_id}.pqenroll", "PQ-VPN Enrollment (*.pqenroll)",
        )
        if path:
            if not path.endswith(".pqenroll"):
                path += ".pqenroll"
            self._queue_onboarding_action("export_enrollment", (client_id, path))

    # ── Clipboard ──
    def _copy_fingerprint(self) -> None:
        fp = self._last_status.server_fingerprint
        if fp:
            QGuiApplication.clipboard().setText(fp)

    def _copy_client_fingerprint(self) -> None:
        fp = self._last_status.identity_fingerprint
        if fp:
            QGuiApplication.clipboard().setText(fp)

    def _copy_profile_info(self, profile: dict) -> None:
        fields = (
            ("Name", profile.get("name")),
            ("Endpoint", f"{profile.get('server_host')}:{profile.get('server_control_port')}"),
            ("Server fingerprint", profile.get("server_identity_fingerprint")),
            ("Expected VPN subnet", profile.get("expected_vpn_subnet")),
            ("Profile ID", profile.get("profile_id")),
        )
        QGuiApplication.clipboard().setText(
            "\n".join(f"{name}: {sanitize_error(value, 280)}" for name, value in fields)
        )

    def _copy_logs(self) -> None:
        QGuiApplication.clipboard().setText(self._logs.logs_view.toPlainText())

    # ── IPC action result ──
    def _action_finished(self, action: str, result: object) -> None:
        self._busy = False
        result = result if isinstance(result, dict) else {"error": "Invalid service response"}
        if "error" in result:
            error = sanitize_error(result["error"])
            self._add_gui_event("error", f"{action.title()} failed: {error}")
            if action in {"connect", "disconnect"}:
                values = asdict(self._last_status)
                values.update(state=ConnectionState.FAILED.value, error=error)
                self._render(ClientStatus(**values))
            else:
                self._home.error_label.setText(error)
                self._home.error_label.show()
        else:
            if action == "copy_enrollment":
                QGuiApplication.clipboard().setText(str(result.get("content", "")))
            elif action == "export_enrollment":
                self._add_gui_event(
                    "info", f"Public enrollment request exported: {result.get('output', 'selected file')}"
                )
            self._add_gui_event("info", f"{action.title()} completed")
        self._worker.request_status()
        if self.pages.currentIndex() == 5:
            self._worker.request_logs()

    def _add_gui_event(self, level: str, message: str) -> None:
        self._gui_events.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "level": level,
            "message": sanitize_error(message),
        })

    # ── Master render ──
    def _render(self, status: object) -> None:
        if not isinstance(status, ClientStatus):
            status = ClientStatus(
                state=ConnectionState.FAILED.value,
                error="Invalid status returned by client service",
            )
        valid_states = {state.value for state in ConnectionState}
        if status.state not in valid_states:
            values = asdict(status)
            values.update(state=ConnectionState.FAILED.value,
                          error="Unsupported connection state returned by service")
            status = ClientStatus(**values)
        self._last_status = status
        state = status.state
        connected = state == ConnectionState.CONNECTED.value
        self._set_visual_state(state)
        self._render_account_device()

        messages = {
            ConnectionState.DISCONNECTED.value: "Ready to establish a secure tunnel",
            ConnectionState.CONNECTING.value: "Establishing secure tunnel…",
            ConnectionState.CONNECTED.value: "Encrypted tunnel is active",
            ConnectionState.DISCONNECTING.value: "Restoring network…",
            ConnectionState.FAILED.value: "The connection could not be completed",
            ConnectionState.SETUP_REQUIRED.value: "Client configuration is required",
        }
        subtitle = messages[state]
        dns_exposed = connected and status.dns_mode == "none"
        if dns_exposed:
            subtitle = "Connected, DNS unprotected"
        self._home.subtitle_label.setText(subtitle)
        subtitle_color = COLORS["amber"] if dns_exposed else COLORS["secondary"]
        self._home.subtitle_label.setStyleSheet(f"font-size: 11px; color: {subtitle_color};")
        error = sanitize_error(status.error) if status.error else ""
        if state == ConnectionState.SETUP_REQUIRED.value:
            error = error or f"Configuration required: {status.config_path or DEFAULT_CONFIG}"
        self._home.error_label.setText(error)
        self._home.error_label.setVisible(bool(error))

        server_display = (status.connected_profile_name if connected else status.active_profile_name)
        server_display = server_display or status.server_host or "—"
        if connected and status.connected_endpoint and status.connected_endpoint != status.server_host:
            server_display = f"{server_display} · {status.connected_endpoint}"
        self._home.detail_server.set_value(server_display)
        self._home.detail_vpn_ip.set_value(status.client_vpn_ip if connected else "—")
        self._home.detail_uptime.set_value(format_duration(status.uptime_seconds) if connected else "—")
        self._home.detail_rtt.set_value(
            f"{status.rtt_ms:.1f} ms" if connected and status.rtt_ms is not None else "—",
            connected and status.rtt_ms is not None,
        )
        self._home.detail_jitter.set_value(
            f"{status.jitter_ms:.1f} ms" if connected and status.jitter_ms is not None else "—",
            connected and status.jitter_ms is not None,
        )
        self._home.detail_loss.set_value(
            f"{status.loss_rate * 100:.2f}%" if connected and status.loss_rate is not None else "—",
            connected and status.loss_rate is not None,
        )
        self._home.detail_rekey.set_value(
            f"{int(status.rekey_countdown)}s"
            if connected and status.rekey_countdown is not None else "—",
            connected and status.rekey_countdown is not None,
        )

        self._render_pq(status, connected)
        self._render_onboarding(status, connected)
        self._servers.render(status, self._busy)
        self._security.render(status, connected, self._busy)
        self._render_protection(status, connected)
        self._settings.render(status, connected)

    def _render_onboarding(self, status: ClientStatus, connected: bool) -> None:
        h = self._home
        h.onboarding_card.setVisible(status.managed_mode and not status.setup_complete)
        h.onboarding_identity.set_status(
            "Ready" if status.identity_ready else "Needs service setup",
            active=status.identity_ready, warning=not status.identity_ready,
        )
        profile_ready = bool(status.active_profile_id)
        profile_text = (f"Selected: {status.active_profile_name or status.active_profile_id}"
                        if profile_ready else
                        f"{len(status.profiles)} imported · select one" if status.profiles
                        else "Import a public .pqvpn profile")
        h.onboarding_profile.set_status(
            profile_text, active=profile_ready, warning=not profile_ready
        )
        h.onboarding_authorization.set_status(
            "Offline administrator approval required", warning=True,
        )
        mutations_enabled = status.managed_mode and not connected and not self._busy
        h.onboarding_identity_btn.setEnabled(mutations_enabled and not status.identity_ready)
        h.onboarding_import_btn.setEnabled(mutations_enabled)
        enrollment_enabled = status.managed_mode and status.identity_ready and not self._busy
        h.onboarding_copy_btn.setEnabled(enrollment_enabled)
        h.onboarding_export_btn.setEnabled(enrollment_enabled)

    def _render_pq(self, status: ClientStatus, connected: bool) -> None:
        h = self._home
        if connected and status.is_quantum_safe:
            badge_text, color = "SERVER PQ PROTECTION · ACTIVE", COLORS["green"]
            pq_text, pq_color = "Active · ML-KEM-768 + X25519", COLORS["green"]
        elif connected:
            badge_text, color = "SERVER PQ PROTECTION · UNAVAILABLE", COLORS["amber"]
            pq_text, pq_color = "Unavailable · native ML-KEM not reported", COLORS["amber"]
        elif status.is_quantum_safe:
            badge_text, color = "HYBRID PQ PROTECTION · IDLE", COLORS["secondary"]
            pq_text, pq_color = "Configured · ML-KEM-768 + X25519", COLORS["secondary"]
        elif not status.pqc_mode:
            badge_text, color = "PQC BACKEND · NOT REPORTED", COLORS["muted"]
            pq_text, pq_color = "Configured · runtime status not reported", COLORS["secondary"]
        else:
            badge_text, color = "PQC BACKEND · UNAVAILABLE", COLORS["amber"]
            pq_text, pq_color = "Configured · backend unavailable", COLORS["amber"]
        self.pqc_badge.setText(badge_text)
        self.pqc_badge.setStyleSheet(badge_style(color))
        h.home_pq_value.setText(pq_text)
        h.home_pq_value.setStyleSheet(f"font-size: 11px; color: {pq_color}; font-weight: 600;")
        prefix = "Active" if connected else "Configured"
        active_color = COLORS["green"] if connected else COLORS["secondary"]
        h.home_auth_value.setText(f"{prefix} · Ed25519 (classical)")
        h.home_traffic_value.setText(f"{prefix} · AES-256-GCM")
        for lbl in (h.home_auth_value, h.home_traffic_value):
            lbl.setStyleSheet(f"font-size: 11px; color: {active_color}; font-weight: 600;")

    def _render_protection(self, status: ClientStatus, connected: bool) -> None:
        h = self._home
        if connected:
            dns_ok = status.dns_managed
            dns_text = "Managed" if dns_ok else "Unmanaged — DNS may bypass VPN"
            dns_color = COLORS["green"] if dns_ok else COLORS["amber"]
            ipv6_ok = status.ipv6_guard_active
            ipv6_text = "Active" if ipv6_ok else "Inactive"
            ipv6_color = COLORS["green"] if ipv6_ok else COLORS["secondary"]
            ks_text = "Active" if status.kill_switch_active else "Inactive"
            ks_color = COLORS["green"] if status.kill_switch_active else COLORS["secondary"]
        else:
            dns_text = f"Configured: {status.dns_mode}" if status.dns_mode else "Idle"
            dns_color = COLORS["secondary"]
            ipv6_text = f"Configured: {status.ipv6_policy}" if status.ipv6_policy else "Idle"
            ipv6_color = COLORS["secondary"]
            ks_text = "Idle"
            ks_color = COLORS["secondary"]
        for lbl, text, color in (
            (h.home_dns_value, dns_text, dns_color),
            (h.home_ipv6_value, ipv6_text, ipv6_color),
            (h.home_ks_value, ks_text, ks_color),
        ):
            lbl.setText(text)
            lbl.setStyleSheet(f"font-size: 11px; color: {color}; font-weight: 600;")
        if connected and not status.dns_managed:
            h.connection_badge.setText("DNS EXPOSED")
            h.connection_badge.setStyleSheet(badge_style(COLORS["amber"]))

    def _set_visual_state(self, state: str) -> None:
        h = self._home
        color = STATE_COLORS.get(state, COLORS["muted"])
        h.state_label.setText(state.replace("_", " "))
        h.state_label.setStyleSheet(f"font-size: 20px; color: {color}; font-weight: 720;")
        h.power_btn.set_state(state)
        h.connection_badge.setText(
            "PROTECTED" if state == ConnectionState.CONNECTED.value else
            "WORKING" if state in {ConnectionState.CONNECTING.value,
                                   ConnectionState.DISCONNECTING.value} else
            "ATTENTION" if state in {ConnectionState.FAILED.value,
                                     ConnectionState.SETUP_REQUIRED.value} else "OFFLINE"
        )
        h.connection_badge.setStyleSheet(badge_style(color))
        self.nav.set_connection_state(state)
        self.footer_state.setText(state.replace("_", " "))
        self.footer_state.setStyleSheet(f"font-size: 9px; color: {color}; font-weight: 700;")
        busy_state = state in {ConnectionState.CONNECTING.value,
                               ConnectionState.DISCONNECTING.value}
        h.connection_progress.setVisible(busy_state)

        if state == ConnectionState.CONNECTED.value:
            text = "Disconnect"
            background, foreground, border = "#2A171B", COLORS["red"], "#63303A"
        elif state == ConnectionState.CONNECTING.value:
            text = "Connecting…"
            background, foreground, border = "#2B2112", COLORS["amber"], "#61491C"
        elif state == ConnectionState.DISCONNECTING.value:
            text = "Disconnecting…"
            background, foreground, border = "#2B2112", COLORS["amber"], "#61491C"
        elif state == ConnectionState.FAILED.value:
            text = "Retry"
            background, foreground, border = "#32191E", COLORS["red"], "#71313C"
        elif state == ConnectionState.SETUP_REQUIRED.value:
            text = "Setup required"
            background, foreground, border = "#211D16", COLORS["amber"], "#4E4025"
        else:
            text = "Connect"
            background, foreground, border = COLORS["green"], "#06110B", COLORS["green"]
        h.action_btn.setText(text)
        h.action_btn.setStyleSheet(f"""
            QPushButton {{
                min-height: 22px;
                background: {background}; color: {foreground};
                border: 1px solid {border}; border-radius: 9px;
                padding: 10px 22px; font-size: 12px; font-weight: 700;
            }}
            QPushButton:hover {{ border-color: {foreground}; }}
            QPushButton:disabled {{
                background: #11161C; color: {COLORS['muted']};
                border-color: {COLORS['border_soft']};
            }}
        """)
        enabled = not self._busy and state not in {
            ConnectionState.CONNECTING.value,
            ConnectionState.DISCONNECTING.value,
            ConnectionState.SETUP_REQUIRED.value,
        }
        h.action_btn.setEnabled(enabled)
        h.power_btn.setEnabled(enabled)

    # ── Logs ──
    def _render_logs_signal(self, entries: object) -> None:
        if isinstance(entries, list):
            self._logs.render(entries, self._gui_events)

    # ── Account helpers ──
    def _submit_account(self, op: str, call, error_label=None) -> bool:
        client = self._account_client
        if client is None:
            if error_label is not None:
                error_label.setText("Not connected to account API.")
                error_label.show()
            return False
        self._account_worker.submit(op, lambda: call(client))
        return True

    def _on_logout_clicked(self) -> None:
        token = self._account_session.get_token()
        self._end_account_session(expired=False)
        if token and self._account_client is not None:
            client = self._account_client
            self._account_worker.submit("logout", lambda: client.logout(token))

    def _end_account_session(self, *, expired: bool) -> None:
        self._session_timer.stop()
        self._account_session.clear_session(expired=expired)
        self._account_devices = []
        self._add_gui_event(
            "warning" if expired else "info",
            "Session expired — signed out automatically" if expired else "Signed out",
        )
        self._refresh_account_view()

    def _validate_account_session(self) -> None:
        token = self._account_session.get_token()
        client = self._account_client
        if token and client is not None:
            self._account_worker.submit("validate", lambda: client.get_me(token))
            self._account_worker.submit("devices", lambda: client.list_devices(token))

    def _on_bind_device_clicked(self) -> None:
        a = self._account
        token = self._account_session.get_token()
        client = self._account_client
        name = a.device_name_input.text().strip()
        if not token or client is None:
            return
        if not name:
            a.device_error.setText("Enter a device name.")
            a.device_error.show()
            return
        a.device_error.hide()
        ipc = self.ipc

        def bind() -> dict:
            public_key, fingerprint = public_device_identity(ipc.setup_status())
            return client.bind_device(token, name, public_key, fingerprint)

        a.device_bind_btn.setEnabled(False)
        a.device_bind_btn.setText("Registering…")
        self._account_worker.submit("bind", bind)

    def _on_mfa_enable_clicked(self) -> None:
        token = self._account_session.get_token()
        if not token:
            return
        self._account.acct_mfa_error.hide()
        self._account.acct_mfa_enable_btn.setEnabled(False)
        self._submit_account("mfa_setup",
            lambda client: client.mfa_setup(token), self._account.acct_mfa_error)

    def _on_mfa_confirm_clicked(self) -> None:
        a = self._account
        token = self._account_session.get_token()
        secret = a._mfa_pending_secret
        code = a.acct_mfa_code.text().strip()
        if not token or not secret:
            return
        if not code or len(code) != 6:
            a.acct_mfa_error.setText("Enter a 6-digit code.")
            a.acct_mfa_error.show()
            return
        a.acct_mfa_error.hide()
        a.acct_mfa_confirm_btn.setEnabled(False)
        self._submit_account("mfa_confirm",
            lambda client: client.mfa_confirm(token, secret, code), a.acct_mfa_error)

    def _on_mfa_disable_clicked(self) -> None:
        a = self._account
        token = self._account_session.get_token()
        code = a.acct_mfa_code.text().strip()
        if not token:
            return
        if not code or len(code) != 6:
            a.acct_mfa_error.setText("Enter your current 6-digit TOTP code to disable MFA.")
            a.acct_mfa_error.show()
            a.acct_mfa_code.show()
            return
        a.acct_mfa_error.hide()
        a.acct_mfa_disable_btn.setEnabled(False)
        self._submit_account("mfa_disable",
            lambda client: client.mfa_disable(token, code), a.acct_mfa_error)

    def _on_change_password_clicked(self) -> None:
        a = self._account
        token = self._account_session.get_token()
        if not token:
            return
        old_pw = a.acct_old_password.text()
        new_pw = a.acct_new_password.text()
        if not old_pw or not new_pw:
            a.acct_pw_error.setText("Both fields are required.")
            a.acct_pw_error.show()
            return
        if len(new_pw) < 12:
            a.acct_pw_error.setText("New password must be at least 12 characters.")
            a.acct_pw_error.show()
            return
        a.acct_pw_error.hide()
        a.acct_change_pw_btn.setEnabled(False)
        self._submit_account("change_password",
            lambda client: client.change_password(token, old_pw, new_pw), a.acct_pw_error)

    # ── Account callbacks ──
    def _account_finished(self, op: str, ok: bool, data: object, message: str,
                          status_code: int, retry_after: int) -> None:
        handler = getattr(self, f"_account_{op}_finished", None)
        if handler is not None:
            handler(ok, data, message, status_code, retry_after)

    def _account_devices_finished(self, ok, data, message, status_code, retry_after) -> None:
        if not self._account_session.is_authenticated:
            return
        if ok and isinstance(data, list):
            self._account_devices = data
            self._set_account_api_available(True)
            self._render_account_device()
        elif status_code == 401:
            self._end_account_session(expired=True)
        else:
            self._set_account_api_available(False)
            self._render_account_device()

    def _account_bind_finished(self, ok, data, message, status_code, retry_after) -> None:
        a = self._account
        a.device_bind_btn.setText("Register This Device")
        if ok and isinstance(data, dict):
            self._add_gui_event(
                "info", "Device bound to account; VPN access still requires administrator approval"
            )
            self._account_devices = [
                d for d in self._account_devices if d.get("fingerprint") != data.get("fingerprint")
            ] + [data]
        elif status_code == 401:
            self._end_account_session(expired=True)
            return
        else:
            a.device_error.setText(message or "Device registration failed.")
            a.device_error.show()
        self._render_account_device()

    def _account_mfa_setup_finished(self, ok, data, message, status_code, retry_after) -> None:
        a = self._account
        a.acct_mfa_enable_btn.setEnabled(True)
        if ok and isinstance(data, dict):
            a._mfa_pending_secret = data.get("secret", "")
            uri = data.get("provisioning_uri", "")
            a.acct_mfa_secret_label.setText(f"Secret: {a._mfa_pending_secret}")
            a.acct_mfa_secret_label.show()
            a.acct_mfa_uri_label.setText(f"URI: {uri}")
            a.acct_mfa_uri_label.show()
            a.acct_mfa_code.show()
            a.acct_mfa_confirm_btn.show()
            a.acct_mfa_enable_btn.hide()
        elif status_code == 401:
            self._end_account_session(expired=True)
        else:
            a.acct_mfa_error.setText(message or "MFA setup failed.")
            a.acct_mfa_error.show()

    def _account_mfa_confirm_finished(self, ok, data, message, status_code, retry_after) -> None:
        a = self._account
        a.acct_mfa_confirm_btn.setEnabled(True)
        if ok:
            a._mfa_pending_secret = None
            a.acct_mfa_secret_label.hide()
            a.acct_mfa_uri_label.hide()
            a.acct_mfa_code.hide()
            a.acct_mfa_code.clear()
            a.acct_mfa_confirm_btn.hide()
            self._add_gui_event("info", "MFA enabled")
            self._validate_account_session()
            a.refresh_mfa_ui(mfa_enabled=True)
        elif status_code == 401:
            self._end_account_session(expired=True)
        else:
            a.acct_mfa_error.setText(message or "Invalid code.")
            a.acct_mfa_error.show()

    def _account_mfa_disable_finished(self, ok, data, message, status_code, retry_after) -> None:
        a = self._account
        a.acct_mfa_disable_btn.setEnabled(True)
        if ok:
            a.acct_mfa_code.hide()
            a.acct_mfa_code.clear()
            self._add_gui_event("info", "MFA disabled")
            self._validate_account_session()
            a.refresh_mfa_ui(mfa_enabled=False)
        elif status_code == 401:
            self._end_account_session(expired=True)
        else:
            a.acct_mfa_error.setText(message or "Could not disable MFA.")
            a.acct_mfa_error.show()

    def _account_change_password_finished(self, ok, data, message, status_code, retry_after) -> None:
        a = self._account
        a.acct_change_pw_btn.setEnabled(True)
        a.acct_old_password.clear()
        a.acct_new_password.clear()
        if ok:
            self._add_gui_event("info", "Password changed")
            a.acct_pw_error.setStyleSheet(f"font-size: 11px; color: {COLORS['green']}; font-weight: 550;")
            a.acct_pw_error.setText("Password changed successfully.")
            a.acct_pw_error.show()
        elif status_code == 401:
            self._end_account_session(expired=True)
        else:
            a.acct_pw_error.setStyleSheet(f"font-size: 11px; color: {COLORS['red']}; font-weight: 550;")
            a.acct_pw_error.setText(message or "Password change failed.")
            a.acct_pw_error.show()

    def _account_logout_finished(self, ok, data, message, status_code, retry_after) -> None:
        if not ok and status_code != 401:
            self._add_gui_event("warning", "Remote sign-out failed; local session was cleared")

    def _account_validate_finished(self, ok, data, message, status_code, retry_after) -> None:
        if not self._account_session.is_authenticated:
            return
        if ok and isinstance(data, dict):
            self._account_session.update_user(UserProfile.from_dict(data))
            self._set_account_api_available(True)
            self._refresh_account_view()
        elif status_code == 401:
            self._end_account_session(expired=True)
        else:
            self._set_account_api_available(False)

    def _set_account_api_available(self, available: bool) -> None:
        a = self._account
        self._account_api_available = available
        if available:
            a.profile_session_badge.setText("SESSION ACTIVE")
            a.profile_session_badge.setStyleSheet(badge_style(COLORS["green"]))
        else:
            a.profile_session_badge.setText("ACCOUNT API UNAVAILABLE")
            a.profile_session_badge.setStyleSheet(badge_style(COLORS["amber"]))

    def _current_account_device(self) -> dict | None:
        fingerprint = self._last_status.identity_fingerprint
        if not fingerprint:
            return None
        return next(
            (d for d in self._account_devices if d.get("fingerprint") == fingerprint), None
        )

    def _render_account_device(self) -> None:
        fingerprint = self._last_status.identity_fingerprint
        device = self._current_account_device()
        self._account.render_device(
            fingerprint, device, self._account_devices,
            self._account_session.is_authenticated,
        )
        self._render_account_state()

    def _refresh_account_view(self) -> None:
        a = self._account
        state = self._account_session.state
        if state == SessionState.AUTHENTICATED:
            user = self._account_session.get_user()
            if user:
                a.profile_username.setText(f"@{user.username}")
                a.profile_email.setText(user.email)
                a.profile_id_row.set_value(user.id)
                a.profile_status_row.set_value("Active" if user.enabled else "Disabled")
                a.profile_created_row.set_value(user.created_at or "—")
                a.refresh_mfa_ui(user.mfa_enabled)
            a.profile_expires_row.set_value(self._account_session.get_expires_at() or "—")
            a.show_profile_view()
        elif state == SessionState.SESSION_EXPIRED:
            a.show_signed_out("Session expired — restart the application to sign in again.")
        else:
            a.show_signed_out()
        self._render_account_device()

    def _render_account_state(self) -> None:
        h = self._home
        fingerprint = self._last_status.identity_fingerprint
        device = self._current_account_device()
        key, title, detail, tone = account_ux_state(
            self._account_session.state,
            api_available=self._account_api_available,
            identity_ready=bool(fingerprint),
            device=device,
            vpn_state=self._last_status.state,
        )
        self.account_ux_key = key
        color = COLORS[tone]
        h.home_account_title.setText(title)
        h.home_account_title.setStyleSheet(f"font-size: 13px; color: {color}; font-weight: 700;")
        h.home_account_detail.setText(detail)
        user = self._account_session.get_user()
        h.home_account_user.set_value(
            f"{user.username} · {user.email}" if user and self._account_session.is_authenticated
            else "Signed out"
        )
        if device is not None:
            status = DEVICE_STATUS_LABELS.get(device.get("status"), "Unknown status")
            if device.get("enabled") is False:
                status = "Disabled"
            device_text = f"{sanitize_error(device.get('device_name', ''), 100)} · {status}"
        else:
            device_text = (f"{truncate_fingerprint(fingerprint)} · not registered"
                           if fingerprint else "Identity not ready")
        h.home_account_device.set_value(device_text)

    # ── Cleanup ──
    def closeEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        self._session_timer.stop()
        self._worker.stop()
        self._account_worker.stop()
        super().closeEvent(event)
