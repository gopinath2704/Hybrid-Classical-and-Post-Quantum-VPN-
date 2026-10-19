"""Servers page — imported profiles, selected server detail, selection policy."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QPushButton, QVBoxLayout, QWidget,
)

from app.client import sanitize_error, truncate_fingerprint, ConnectionState
from app.ui.theme import COLORS, label
from app.ui.components import Card, DataRow


class ServersPage:
    def __init__(self, *, on_choose_profile, on_poll_status,
                 on_select_profile, on_remove_profile, on_copy_profile_info,
                 on_copy_fingerprint) -> None:
        self._on_choose_profile = on_choose_profile
        self._on_poll_status = on_poll_status
        self._on_select_profile = on_select_profile
        self._on_remove_profile = on_remove_profile
        self._on_copy_profile_info = on_copy_profile_info
        self._on_copy_fingerprint = on_copy_fingerprint
        self._profile_signature: tuple = ()

    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(14)

        actions = QHBoxLayout()
        self.server_import_btn = QPushButton("Import Profile")
        self.server_import_btn.clicked.connect(self._on_choose_profile)
        self.server_refresh_btn = QPushButton("Refresh profiles")
        self.server_refresh_btn.clicked.connect(self._on_poll_status)
        actions.addWidget(self.server_import_btn)
        actions.addWidget(self.server_refresh_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.server_profiles_card = Card(
            "Imported profiles", "Only public, strictly validated .pqvpn profiles are shown."
        )
        self.server_profiles_empty = label(
            "No server profiles imported.", 11, COLORS["secondary"]
        )
        self.server_profiles_card.body.addWidget(self.server_profiles_empty)
        self.server_profile_widgets: list[QWidget] = []
        layout.addWidget(self.server_profiles_card)

        card = Card("Selected Server", "Profile selected for the next connection.")
        self.server_host_row = DataRow("Server host")
        self.server_port_row = DataRow("Control port")
        self.server_subnet_row = DataRow("Expected VPN subnet")
        self.server_route_row = DataRow("Routing mode")
        self.server_fp_row = DataRow("Server fingerprint")
        for row in (self.server_host_row, self.server_port_row, self.server_subnet_row,
                    self.server_route_row, self.server_fp_row):
            card.body.addWidget(row)
        buttons = QHBoxLayout()
        self.server_copy_btn = QPushButton("Copy fingerprint")
        self.server_copy_btn.clicked.connect(self._on_copy_fingerprint)
        buttons.addWidget(self.server_copy_btn)
        buttons.addStretch(1)
        card.body.addLayout(buttons)
        layout.addWidget(card)

        self.servers_setup_label = label("", 11, COLORS["amber"], 550)
        self.servers_setup_label.setWordWrap(True)
        self.servers_setup_label.hide()
        layout.addWidget(self.servers_setup_label)

        note = Card("Selection policy")
        note.body.addWidget(label(
            "Profiles cannot be imported, selected, or removed while connected. "
            "No discovery, geolocation, load, or fabricated latency data is used.",
            11, COLORS["secondary"]
        ))
        layout.addWidget(note)
        layout.addStretch(1)
        return page

    def render(self, status, busy: bool) -> None:
        from app.client import DEFAULT_CONFIG
        self.server_host_row.set_value(status.server_host)
        self.server_port_row.set_value(status.server_control_port)
        self.server_subnet_row.set_value(status.expected_vpn_subnet)
        if status.full_tunnel is True:
            routing = "Full tunnel"
        elif status.full_tunnel is False:
            routing = "Split tunnel" + (f" · {len(status.split_tunnel)} routes"
                                          if status.split_tunnel else "")
        else:
            routing = "—"
        self.server_route_row.set_value(routing)
        self.server_fp_row.set_value(truncate_fingerprint(status.server_fingerprint))
        self.server_copy_btn.setEnabled(bool(status.server_fingerprint))

        signature = (status.state,) + tuple(
            (item.get("profile_id"), item.get("name"), item.get("server_host"),
             item.get("server_control_port"), item.get("active"))
            for item in status.profiles if isinstance(item, dict)
        )
        if signature != self._profile_signature:
            self._profile_signature = signature
            self._rebuild_profile_list(status.profiles, status.state)

        mutable = status.managed_mode and status.state not in {
            ConnectionState.CONNECTED.value,
            ConnectionState.CONNECTING.value,
            ConnectionState.DISCONNECTING.value,
        }
        self.server_import_btn.setEnabled(mutable and not busy)
        setup = (status.state == ConnectionState.SETUP_REQUIRED.value)
        self.servers_setup_label.setText(
            status.error or f"Configuration required: {status.config_path or DEFAULT_CONFIG}"
        )
        self.servers_setup_label.setVisible(setup)

    def _rebuild_profile_list(self, profiles: list[dict], state: str) -> None:
        for widget in self.server_profile_widgets:
            self.server_profiles_card.body.removeWidget(widget)
            widget.setParent(None)
            widget.deleteLater()
        self.server_profile_widgets.clear()
        valid = [item for item in profiles if isinstance(item, dict)]
        self.server_profiles_empty.setVisible(not valid)
        mutable = state not in {
            ConnectionState.CONNECTED.value,
            ConnectionState.CONNECTING.value,
            ConnectionState.DISCONNECTING.value,
        }
        for item in valid:
            profile_id = str(item.get("profile_id", ""))
            name = sanitize_error(item.get("name", "Unnamed profile"), 80)
            host = sanitize_error(item.get("server_host", "—"), 253)
            port = item.get("server_control_port", "—")
            subnet = sanitize_error(item.get("expected_vpn_subnet", "—"), 32)
            fingerprint = sanitize_error(item.get("server_identity_fingerprint", ""), 64)
            active = item.get("active") is True
            block = QFrame()
            block.setObjectName("summaryBlock")
            body = QVBoxLayout(block)
            body.setContentsMargins(14, 12, 14, 12)
            title = QHBoxLayout()
            title.addWidget(label(name, 13, weight=650))
            if active:
                title.addWidget(label("SELECTED", 9, COLORS["green"], 700))
            title.addStretch(1)
            body.addLayout(title)
            body.addWidget(label(f"{host}:{port}  ·  {subnet}", 10, COLORS["secondary"]))
            body.addWidget(label(
                f"Server identity: {truncate_fingerprint(fingerprint)}", 10, COLORS["muted"]
            ))
            actions = QHBoxLayout()
            select = QPushButton("Selected" if active else "Select")
            select.setEnabled(mutable and not active)
            select.clicked.connect(
                lambda checked=False, v=profile_id: self._on_select_profile(v)
            )
            remove = QPushButton("Remove")
            remove.setEnabled(mutable)
            remove.clicked.connect(
                lambda checked=False, v=profile_id: self._on_remove_profile(v)
            )
            copy = QPushButton("Copy profile info")
            copy.clicked.connect(
                lambda checked=False, v=dict(item): self._on_copy_profile_info(v)
            )
            actions.addWidget(select)
            actions.addWidget(remove)
            actions.addWidget(copy)
            actions.addStretch(1)
            body.addLayout(actions)
            self.server_profiles_card.body.addWidget(block)
            self.server_profile_widgets.append(block)
