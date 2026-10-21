"""Security page — cryptography, network protection, identity."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from app.client import truncate_fingerprint
from app.ui.theme import COLORS, badge_style, label
from app.ui.components import Card, DataRow, StatusRow


class SecurityPage:
    SUITE = "X25519 + ML-KEM-768 · AES-256-GCM · Ed25519 client auth"

    def __init__(self, *, on_copy_client_fp, on_copy_server_fp, on_copy_enrollment,
                 on_export_enrollment) -> None:
        self._on_copy_client_fp = on_copy_client_fp
        self._on_copy_server_fp = on_copy_server_fp
        self._on_copy_enrollment = on_copy_enrollment
        self._on_export_enrollment = on_export_enrollment

    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(14)

        self.sec_quantum_badge = label("QUANTUM-SAFE · IDLE", 13, COLORS["secondary"], 750)
        self.sec_quantum_badge.setStyleSheet(badge_style(COLORS["secondary"]))
        self.sec_quantum_badge.setAccessibleName("Quantum-safe status")
        layout.addWidget(self.sec_quantum_badge, alignment=Qt.AlignLeft)

        crypto = Card("Cryptography")
        self.sec_suite = DataRow("Active suite", self.SUITE)
        self.sec_hybrid = StatusRow("Server / session protection")
        self.sec_client_auth = StatusRow("Client authentication")
        self.sec_encryption = StatusRow("Traffic encryption")
        self.sec_protocol = DataRow("Protocol", "KEMTLS-inspired hybrid")
        self.sec_backend = StatusRow("PQC backend")
        self.sec_epoch = DataRow("Current epoch")
        self.sec_rekey = DataRow("Next rekey")
        for row in (self.sec_suite, self.sec_hybrid, self.sec_client_auth, self.sec_encryption,
                    self.sec_protocol, self.sec_backend, self.sec_epoch, self.sec_rekey):
            crypto.body.addWidget(row)
        layout.addWidget(crypto)

        network = Card("Network protection")
        self.sec_ipv6 = StatusRow("IPv6 protection")
        self.sec_dns = StatusRow("DNS management")
        self.sec_tun = DataRow("TUN mode")
        self.sec_mtu = DataRow("MTU")
        for row in (self.sec_ipv6, self.sec_dns, self.sec_tun, self.sec_mtu):
            network.body.addWidget(row)
        layout.addWidget(network)

        identity = Card("Identity")
        self.sec_client_fingerprint = DataRow("Device public fingerprint")
        self.sec_fingerprint = DataRow("Pinned server fingerprint")
        self.sec_identity_note = label(
            "Private client key material is never returned over IPC or displayed.",
            10, COLORS["secondary"]
        )
        identity.body.addWidget(self.sec_client_fingerprint)
        identity.body.addWidget(self.sec_fingerprint)
        identity.body.addWidget(self.sec_identity_note)
        identity_actions = QHBoxLayout()
        self.sec_copy_client_fp_btn = QPushButton("Copy device fingerprint")
        self.sec_copy_client_fp_btn.clicked.connect(self._on_copy_client_fp)
        self.sec_copy_server_fp_btn = QPushButton("Copy server fingerprint")
        self.sec_copy_server_fp_btn.setToolTip("Copy the full pinned server fingerprint")
        self.sec_copy_server_fp_btn.clicked.connect(self._on_copy_server_fp)
        self.sec_copy_enrollment_btn = QPushButton("Copy enrollment request")
        self.sec_copy_enrollment_btn.clicked.connect(self._on_copy_enrollment)
        self.sec_export_enrollment_btn = QPushButton("Export .pqenroll")
        self.sec_export_enrollment_btn.clicked.connect(self._on_export_enrollment)
        for btn in (self.sec_copy_client_fp_btn, self.sec_copy_server_fp_btn,
                    self.sec_copy_enrollment_btn,
                    self.sec_export_enrollment_btn):
            identity_actions.addWidget(btn)
        identity_actions.addStretch(1)
        identity.body.addLayout(identity_actions)
        layout.addWidget(identity)
        layout.addStretch(1)
        return page

    def render(self, status, connected: bool, busy: bool) -> None:
        if connected and status.is_quantum_safe:
            badge, color = "QUANTUM-SAFE · ACTIVE SESSION", COLORS["green"]
        elif connected:
            badge, color = "NOT QUANTUM-SAFE · ML-KEM NOT ACTIVE", COLORS["amber"]
        elif status.is_quantum_safe:
            badge, color = "QUANTUM-SAFE · READY (NOT CONNECTED)", COLORS["secondary"]
        elif not status.pqc_mode:
            badge, color = "PQC BACKEND NOT REPORTED", COLORS["muted"]
        else:
            badge, color = "NOT QUANTUM-SAFE · PQC BACKEND UNAVAILABLE", COLORS["amber"]
        self.sec_quantum_badge.setText(badge)
        self.sec_quantum_badge.setStyleSheet(
            badge_style(color).replace("font-size: 9px", "font-size: 13px"))
        self.sec_suite.set_value(
            self.SUITE + (f" · mode {status.pqc_mode}" if status.pqc_mode else ""))
        if connected and status.is_quantum_safe:
            self.sec_hybrid.set_status("Active: ML-KEM-768 + X25519", active=True)
        elif connected:
            self.sec_hybrid.set_status("Unavailable: native ML-KEM not active", warning=True)
        else:
            self.sec_hybrid.set_status("Configured: ML-KEM-768 + X25519")
        self.sec_client_auth.set_status(
            ("Active: " if connected else "Configured: ") + "Ed25519 (classical)",
            active=connected,
        )
        self.sec_encryption.set_status(
            ("Active: " if connected else "Configured: ") + "AES-256-GCM",
            active=connected,
        )
        self.sec_protocol.set_value("KEMTLS-inspired hybrid")

        backend = status.pqc_mode or "Not reported"
        if connected and status.is_quantum_safe:
            self.sec_backend.set_status(f"Active: {backend}", active=True)
        elif status.is_quantum_safe:
            self.sec_backend.set_status(f"Available: {backend}")
        elif not status.pqc_mode:
            self.sec_backend.set_status("Not reported")
        else:
            self.sec_backend.set_status(f"Unavailable: {backend}", warning=True)
        self.sec_epoch.set_value(status.epoch if connected and status.epoch is not None else "—")
        self.sec_rekey.set_value(
            f"{int(status.rekey_countdown)} seconds"
            if connected and status.rekey_countdown is not None else "Idle"
        )

        ipv6_active = connected and status.ipv6_guard_active
        dns_active = connected and status.dns_managed
        if connected:
            self.sec_ipv6.set_status("Active" if ipv6_active else "Inactive",
                                     active=ipv6_active)
            self.sec_dns.set_status("Managed" if dns_active else "Unmanaged",
                                    active=dns_active)
        else:
            policy = status.ipv6_policy
            if policy is None and status.full_tunnel is not None:
                policy = "block" if status.full_tunnel else "allow"
            self.sec_ipv6.set_status(
                f"Configured: {policy} · Idle" if policy else "Unavailable"
            )
            self.sec_dns.set_status(
                f"Configured: {status.dns_mode} · Idle"
                if status.dns_mode else "Unavailable"
            )
        self.sec_tun.set_value(status.tun_mode if connected else "Idle")
        self.sec_mtu.set_value(status.mtu if connected and status.mtu is not None else "—")
        self.sec_client_fingerprint.set_value(
            truncate_fingerprint(status.identity_fingerprint)
        )
        self.sec_fingerprint.set_value(truncate_fingerprint(status.server_fingerprint))
        enrollment_enabled = status.managed_mode and status.identity_ready and not busy
        self.sec_copy_client_fp_btn.setEnabled(bool(status.identity_fingerprint))
        self.sec_copy_server_fp_btn.setEnabled(bool(status.server_fingerprint))
        self.sec_copy_enrollment_btn.setEnabled(enrollment_enabled)
        self.sec_export_enrollment_btn.setEnabled(enrollment_enabled)
