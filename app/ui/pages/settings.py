"""Settings page — read-only service-owned configuration."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QVBoxLayout, QWidget

from app.client import DEFAULT_CONFIG, truncate_fingerprint
from app.ui.theme import COLORS, badge_style, label
from app.ui.components import Card, DataRow, StatusRow

DEFAULT_PREFS: dict[str, object] = {
    "theme": "dark",
    "reduce_motion": False,
    "close_to_tray": True,
    "auto_connect": False,
}

KILL_SWITCH_NOTE = (
    "The kill switch is a service configuration flag. The current runtime records it but "
    "does not install blocking firewall rules, so traffic is not blocked if the tunnel drops."
)


class SettingsPage:
    def __init__(self, *, on_pref_changed: Callable[[str, object], None]) -> None:
        self._on_pref_changed = on_pref_changed

    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(14)

        prefs = Card("Desktop preferences", "Stored for this user only; never sent to the service.")
        theme_row = QHBoxLayout()
        theme_row.addWidget(label("Theme", 11, COLORS["secondary"]))
        theme_row.addStretch(1)
        self.pref_theme = QComboBox()
        self.pref_theme.addItems(["Dark", "Light", "System"])
        self.pref_theme.setAccessibleName("Theme")
        self.pref_theme.currentTextChanged.connect(
            lambda text: self._on_pref_changed("theme", text.lower()))
        theme_row.addWidget(self.pref_theme)
        prefs.body.addLayout(theme_row)
        self.pref_reduce_motion = QCheckBox("Reduce motion (no pulse or spinning ring)")
        self.pref_close_to_tray = QCheckBox("Closing the window keeps PQ-VPN in the system tray")
        self.pref_auto_connect = QCheckBox(
            "Connect automatically when the desktop app starts and setup is complete")
        for key, box in (("reduce_motion", self.pref_reduce_motion),
                         ("close_to_tray", self.pref_close_to_tray),
                         ("auto_connect", self.pref_auto_connect)):
            box.setAccessibleName(box.text())
            box.toggled.connect(lambda checked, k=key: self._on_pref_changed(k, checked))
            prefs.body.addWidget(box)
        self.settings_kill_switch = StatusRow("Kill switch (service config)")
        self.settings_kill_switch.setToolTip(KILL_SWITCH_NOTE)
        prefs.body.addWidget(self.settings_kill_switch)
        ks_note = label(KILL_SWITCH_NOTE, 10, COLORS["amber"])
        ks_note.setWordWrap(True)
        prefs.body.addWidget(ks_note)
        layout.addWidget(prefs)

        read_only = label("READ-ONLY", 9, COLORS["cyan"], 700)
        read_only.setStyleSheet(badge_style(COLORS["cyan"]))
        layout.addWidget(read_only, alignment=Qt.AlignLeft)

        card = Card("Connection policy", "Values are validated and owned by the privileged service.")
        self.settings_tunnel = DataRow("Tunnel routing")
        self.settings_ipv6 = DataRow("IPv6 policy")
        self.settings_dns_mode = DataRow("DNS mode")
        self.settings_dns_servers = DataRow("DNS servers")
        self.settings_tun = DataRow("TUN name")
        self.settings_server = DataRow("Configured server")
        self.settings_rekey = DataRow("Rekey interval")
        self.settings_path = DataRow("Configuration / profile store")
        self.settings_state_path = DataRow("Identity state directory")
        self.settings_identity = DataRow("Device public fingerprint")
        for row in (self.settings_tunnel, self.settings_ipv6, self.settings_dns_mode,
                    self.settings_dns_servers, self.settings_tun, self.settings_server,
                    self.settings_rekey, self.settings_path, self.settings_state_path,
                    self.settings_identity):
            card.body.addWidget(row)
        layout.addWidget(card)
        layout.addWidget(label(
            "Configuration editing is intentionally deferred: reconnect-safe privileged "
            "writes need a dedicated, narrow API.",
            10, COLORS["secondary"]
        ))
        layout.addStretch(1)
        return page

    def load_prefs(self, prefs: dict[str, object]) -> None:
        widgets = (self.pref_theme, self.pref_reduce_motion,
                   self.pref_close_to_tray, self.pref_auto_connect)
        for widget in widgets:
            widget.blockSignals(True)
        self.pref_theme.setCurrentText(str(prefs["theme"]).title())
        self.pref_reduce_motion.setChecked(bool(prefs["reduce_motion"]))
        self.pref_close_to_tray.setChecked(bool(prefs["close_to_tray"]))
        self.pref_auto_connect.setChecked(bool(prefs["auto_connect"]))
        for widget in widgets:
            widget.blockSignals(False)

    def render(self, status, connected: bool) -> None:
        self.settings_kill_switch.set_status(
            ("Flag on · not enforced" if status.kill_switch_active else "Off")
            if connected else "Reported only while connected",
            warning=connected and status.kill_switch_active,
        )
        if status.full_tunnel is True:
            tunnel = "Full tunnel"
        elif status.full_tunnel is False:
            tunnel = "Split tunnel" + (
                f" · {', '.join(status.split_tunnel)}" if status.split_tunnel else " · no routes"
            )
        else:
            tunnel = "Unavailable"
        policy = status.ipv6_policy
        if policy is None and status.full_tunnel is not None:
            policy = "block (full-tunnel default)" if status.full_tunnel else "allow (split default)"
        self.settings_tunnel.set_value(tunnel)
        self.settings_ipv6.set_value(policy or "Unavailable")
        self.settings_dns_mode.set_value(status.dns_mode or "Unavailable")
        self.settings_dns_servers.set_value(
            ", ".join(status.dns_servers) if status.dns_servers
            else "Provided by server" if status.dns_mode is not None
            else "Unavailable"
        )
        self.settings_tun.set_value(status.configured_tun_name)
        endpoint = status.server_host or "—"
        if status.server_control_port:
            endpoint = f"{endpoint}:{status.server_control_port}"
        self.settings_server.set_value(endpoint)
        self.settings_rekey.set_value(
            f"{status.rekey_interval} seconds" if connected and status.rekey_interval
            else "Negotiated with server on connect" if status.full_tunnel is not None
            else "Not reported"
        )
        self.settings_path.set_value(status.config_path or DEFAULT_CONFIG)
        self.settings_state_path.set_value(status.identity_path or "Legacy explicit config")
        self.settings_identity.set_value(
            truncate_fingerprint(status.identity_fingerprint)
            if status.managed_mode else "Managed identity not in use"
        )
