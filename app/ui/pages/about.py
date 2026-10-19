"""About page — project branding, crypto summary, security scope."""
from __future__ import annotations

from PySide6.QtWidgets import QVBoxLayout, QWidget

from app.client import APP_VERSION
from app.ui.theme import COLORS, label
from app.ui.components import Card


class AboutPage:
    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(14)

        card = Card()
        title = label("PQ-VPN", 27, weight=720)
        version = label(f"Version {APP_VERSION}", 11, COLORS["green"], 650)
        description = label(
            "Hybrid Classical + Post-Quantum VPN for Linux", 14,
            COLORS["secondary"], 550
        )
        description.setWordWrap(True)
        card.body.addWidget(title)
        card.body.addWidget(version)
        card.body.addSpacing(5)
        card.body.addWidget(description)
        card.body.addWidget(label("Research / prototype", 10, COLORS["amber"], 650))
        layout.addWidget(card)

        crypto = Card("Cryptographic summary")
        crypto.body.addWidget(label("ML-KEM-768 + X25519 server/session protection", 11))
        crypto.body.addWidget(label("Ed25519 client authentication (classical)", 11))
        crypto.body.addWidget(label("AES-256-GCM traffic encryption", 11))
        layout.addWidget(crypto)

        warning = Card("Important security scope")
        warning.body.addWidget(label(
            "Custom KEMTLS-inspired protocol. Not formally verified. Not fully "
            "post-quantum mutual authentication.",
            11, COLORS["secondary"], 550
        ))
        layout.addWidget(warning)
        layout.addStretch(1)
        return page
