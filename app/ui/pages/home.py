"""Home page — connection hero, protection strip, account summary, metrics."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout, QHBoxLayout, QPushButton, QProgressBar, QVBoxLayout, QWidget,
)

from app.ui.theme import COLORS, LINK_BTN, badge_style, label
from app.ui.components import (
    Card, DataRow, MetricCard, PowerButton, Sparkline, Stepper, SummaryBlock,
)

PAGE_SERVERS, PAGE_SECURITY, PAGE_ACCOUNT, PAGE_SETTINGS, PAGE_ABOUT = 1, 2, 3, 4, 6

_FAILURE_HINTS: tuple[tuple[tuple[str, ...], str, int, str], ...] = (
    (("not yet be authorized", "authorization revoked", "not authorized",
      "unauthorized", "not registered", "device not bound", "identity proof failed"),
     "This device is not authorized on the server yet.", PAGE_ACCOUNT, "Open Account"),
    (("server identity", "fingerprint mismatch", "substitution detected",
      "signature verification failed", "certificate"),
     "The server's identity did not match the pinned fingerprint.", PAGE_SECURITY,
     "Open Security"),
    (("connection refused", "timed out", "timeout", "unreachable", "no route to host",
      "name or service not known", "temporary failure in name resolution",
      "nodename nor servname"),
     "The server could not be reached. Check the address, your network, and that the "
     "server is running.", PAGE_SERVERS, "Open Servers"),
    (("server profile", "no profile"),
     "No usable server profile is selected.", PAGE_SERVERS, "Open Servers"),
    (("unsupported version", "protocol version mismatch"),
     "The server speaks a different protocol version than this client.", PAGE_ABOUT,
     "Open About"),
    (("resolvectl", "native tun", "ipv6"),
     "A local network prerequisite is missing on this machine.", PAGE_SETTINGS,
     "Open Settings"),
)


def explain_failure(error: str) -> tuple[str, int | None, str]:
    """Return (plain-language reason, page to open, link text); unknown errors pass through."""
    lowered = error.lower()
    for needles, reason, page, link in _FAILURE_HINTS:
        if any(needle in lowered for needle in needles):
            return reason, page, link
    return error, None, ""


class HomePage:
    def __init__(self, *, on_toggle, on_ensure_identity, on_choose_profile,
                 on_copy_enrollment, on_export_enrollment, on_open_account,
                 on_open_page: Callable[[int], None]) -> None:
        self._on_toggle = on_toggle
        self._on_open_page = on_open_page
        self._failure_page: int | None = None
        self._on_open_account = on_open_account
        self._on_ensure_identity = on_ensure_identity
        self._on_choose_profile = on_choose_profile
        self._on_copy_enrollment = on_copy_enrollment
        self._on_export_enrollment = on_export_enrollment

    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(10)

        # ── Onboarding card ──
        self.onboarding_card = Card(
            "Finish device setup",
            "The privileged service owns identity and profiles; only public enrollment data leaves it.",
        )
        self.onboarding_steps = Stepper((
            "Device identity", "Server profile", "Enrollment request",
            "Administrator authorization",
        ))
        (self.onboarding_identity, self.onboarding_profile,
         self.onboarding_enrollment, self.onboarding_authorization) = self.onboarding_steps.rows
        self.onboarding_card.body.addWidget(self.onboarding_steps)
        self.onboarding_identity_btn = QPushButton("Ensure identity")
        self.onboarding_identity_btn.clicked.connect(self._on_ensure_identity)
        self.onboarding_import_btn = QPushButton("Import .pqvpn")
        self.onboarding_import_btn.clicked.connect(self._on_choose_profile)
        self.onboarding_copy_btn = QPushButton("Copy enrollment request")
        self.onboarding_copy_btn.clicked.connect(self._on_copy_enrollment)
        self.onboarding_export_btn = QPushButton("Export .pqenroll")
        self.onboarding_export_btn.clicked.connect(self._on_export_enrollment)
        for step, buttons in enumerate(((self.onboarding_identity_btn,),
                                        (self.onboarding_import_btn,),
                                        (self.onboarding_copy_btn, self.onboarding_export_btn))):
            for btn in buttons:
                self.onboarding_steps.actions[step].addWidget(btn)
            self.onboarding_steps.actions[step].addStretch(1)
        self.onboarding_note = label(
            "Exporting a request does not mean the server has authorized this device.",
            10, COLORS["amber"], 550,
        )
        self.onboarding_note.setWordWrap(True)
        self.onboarding_card.body.addWidget(self.onboarding_note)
        layout.addWidget(self.onboarding_card)

        # ── Hero card ──
        hero = Card()
        hero.body.setContentsMargins(26, 13, 26, 14)
        hero.body.setSpacing(5)

        state_row = QHBoxLayout()
        self.connection_badge = label("OFFLINE", 9, COLORS["muted"], 700)
        self.connection_badge.setStyleSheet(badge_style(COLORS["muted"]))
        self.kill_switch_chip = label("KILL SWITCH · OFF", 9, COLORS["muted"], 700)
        self.kill_switch_chip.setStyleSheet(badge_style(COLORS["muted"]))
        state_row.addWidget(self.kill_switch_chip)
        state_row.addStretch(1)
        state_row.addWidget(self.connection_badge)
        hero.body.addLayout(state_row)

        self.power_btn = PowerButton()
        self.power_btn.clicked.connect(self._on_toggle)
        hero.body.addWidget(self.power_btn, alignment=Qt.AlignHCenter)

        self.state_label = label("DISCONNECTED", 20, COLORS["muted"], 720)
        self.state_label.setAlignment(Qt.AlignCenter)
        self.subtitle_label = label("Ready to establish a secure tunnel", 11, COLORS["secondary"])
        self.subtitle_label.setAlignment(Qt.AlignCenter)
        self.subtitle_label.setWordWrap(True)
        self.error_label = label("", 10, COLORS["red"], 550)
        self.error_label.setAlignment(Qt.AlignCenter)
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        hero.body.addWidget(self.state_label)
        hero.body.addWidget(self.subtitle_label)
        hero.body.addWidget(self.error_label)
        self.failure_link_btn = QPushButton("")
        self.failure_link_btn.setStyleSheet(LINK_BTN)
        self.failure_link_btn.setCursor(Qt.PointingHandCursor)
        self.failure_link_btn.clicked.connect(self._open_failure_page)
        self.failure_link_btn.hide()
        hero.body.addWidget(self.failure_link_btn, alignment=Qt.AlignHCenter)

        self.handshake_steps = Stepper((
            "Classical key exchange (X25519)",
            "Post-quantum KEM (ML-KEM-768)",
            "Session established",
        ))
        self.handshake_note = label(
            "The service reports only the overall handshake state, so these steps "
            "complete together.", 9, COLORS["muted"],
        )
        self.handshake_note.setWordWrap(True)
        hero.body.addWidget(self.handshake_steps)
        hero.body.addWidget(self.handshake_note)
        self.handshake_steps.hide()
        self.handshake_note.hide()

        self.connection_progress = QProgressBar()
        self.connection_progress.setRange(0, 0)
        self.connection_progress.setFixedWidth(210)
        self.connection_progress.setTextVisible(False)
        self.connection_progress.hide()
        hero.body.addWidget(self.connection_progress, alignment=Qt.AlignHCenter)

        summary = QHBoxLayout()
        summary.setSpacing(9)
        self.detail_server = SummaryBlock("Configured server")
        self.detail_vpn_ip = SummaryBlock("VPN address")
        self.detail_uptime = SummaryBlock("Connected time")
        summary.addWidget(self.detail_server, 1)
        summary.addWidget(self.detail_vpn_ip, 1)
        summary.addWidget(self.detail_uptime, 1)
        hero.body.addLayout(summary)

        self.action_btn = QPushButton("Connect")
        self.action_btn.setFixedWidth(184)
        self.action_btn.setCursor(Qt.PointingHandCursor)
        self.action_btn.clicked.connect(self._on_toggle)
        hero.body.addWidget(self.action_btn, alignment=Qt.AlignHCenter)
        layout.addWidget(hero)

        # ── Protection strip ──
        protection = Card("Protection")
        protection_grid = QGridLayout()
        protection_grid.setHorizontalSpacing(22)
        dns_title = label("DNS", 9, COLORS["muted"], 700)
        self.home_dns_value = label("Idle", 11, COLORS["secondary"], 600)
        ipv6_title = label("IPV6 GUARD", 9, COLORS["muted"], 700)
        self.home_ipv6_value = label("Idle", 11, COLORS["secondary"], 600)
        ks_title = label("KILL SWITCH", 9, COLORS["muted"], 700)
        self.home_ks_value = label("Idle", 11, COLORS["secondary"], 600)
        for col, pair in enumerate(((dns_title, self.home_dns_value),
                                    (ipv6_title, self.home_ipv6_value),
                                    (ks_title, self.home_ks_value))):
            protection_grid.addWidget(pair[0], 0, col)
            protection_grid.addWidget(pair[1], 1, col)
            protection_grid.setColumnStretch(col, 1)
        protection.body.addLayout(protection_grid)
        layout.addWidget(protection)

        # ── Account & Device ──
        account_card = Card("Account & Device")
        account_header = QHBoxLayout()
        self.home_account_title = label("Signed out", 13, COLORS["muted"], 700)
        self.home_account_open_btn = QPushButton("Open Account")
        self.home_account_open_btn.clicked.connect(self._on_open_account)
        account_header.addWidget(self.home_account_title)
        account_header.addStretch(1)
        account_header.addWidget(self.home_account_open_btn)
        account_card.body.addLayout(account_header)
        self.home_account_detail = label("", 10, COLORS["secondary"])
        self.home_account_detail.setWordWrap(True)
        account_card.body.addWidget(self.home_account_detail)
        self.home_account_user = DataRow("Account")
        self.home_account_device = DataRow("This device")
        for row in (self.home_account_user, self.home_account_device):
            account_card.body.addWidget(row)
        layout.addWidget(account_card)

        # ── Metrics ──
        metrics = QGridLayout()
        metrics.setContentsMargins(0, 0, 0, 0)
        metrics.setHorizontalSpacing(10)
        metrics.setVerticalSpacing(10)
        self.detail_rtt = MetricCard("Latency", "Authenticated RTT")
        self.detail_jitter = MetricCard("Jitter", "Probe variation")
        self.detail_loss = MetricCard("Packet loss", "Probe window")
        self.detail_rekey = MetricCard("Next rekey", "Session rotation")
        for column, card in enumerate((self.detail_rtt, self.detail_jitter,
                                       self.detail_loss, self.detail_rekey)):
            metrics.addWidget(card, 0, column)
            metrics.setColumnStretch(column, 1)
        layout.addLayout(metrics)

        self.rtt_card = Card("Live latency", "Authenticated RTT, last 60 samples")
        self.rtt_sparkline = Sparkline(60, "Recent authenticated RTT samples")
        self.rtt_card.body.addWidget(self.rtt_sparkline)
        self.rtt_card.hide()
        layout.addWidget(self.rtt_card)

        # ── Security at a glance ──
        security = Card("Security at a glance")
        security_grid = QGridLayout()
        security_grid.setHorizontalSpacing(22)
        self.home_pq_title = label("HYBRID KEY ESTABLISHMENT", 9, COLORS["muted"], 700)
        self.home_pq_value = label("Configured · ML-KEM-768 + X25519", 11,
                                   COLORS["secondary"], 600)
        auth_title = label("CLIENT AUTHENTICATION", 9, COLORS["muted"], 700)
        self.home_auth_value = label("Configured · Ed25519 (classical)", 11,
                                     COLORS["secondary"], 600)
        traffic_title = label("TRAFFIC CIPHER", 9, COLORS["muted"], 700)
        self.home_traffic_value = label("Configured · AES-256-GCM", 11,
                                        COLORS["secondary"], 600)
        for column, pair in enumerate(((self.home_pq_title, self.home_pq_value),
                                       (auth_title, self.home_auth_value),
                                       (traffic_title, self.home_traffic_value))):
            security_grid.addWidget(pair[0], 0, column)
            security_grid.addWidget(pair[1], 1, column)
            security_grid.setColumnStretch(column, 1)
        security.body.addLayout(security_grid)
        layout.addWidget(security)
        layout.addStretch(1)
        return page

    def render_failure(self, error: str, failed: bool) -> None:
        """Plain-language reason plus a link to the page that can fix it; raw text kept."""
        reason, page, link = explain_failure(error) if failed else (error, None, "")
        text = f"{reason}\n{error}" if page is not None else error
        self.error_label.setText(text)
        self.error_label.setVisible(bool(error))
        self._failure_page = page
        self.failure_link_btn.setText(link)
        self.failure_link_btn.setAccessibleName(link)
        self.failure_link_btn.setVisible(page is not None)

    def _open_failure_page(self) -> None:
        if self._failure_page is not None:
            self._on_open_page(self._failure_page)
