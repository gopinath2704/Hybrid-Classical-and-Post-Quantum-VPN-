"""Settings page — read-only service-owned configuration."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QVBoxLayout, QWidget

from app.client import DEFAULT_CONFIG, truncate_fingerprint
from app.ui.theme import COLORS, badge_style, label
from app.ui.components import Card, DataRow


class SettingsPage:
    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(14)

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

    def render(self, status, connected: bool) -> None:
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
