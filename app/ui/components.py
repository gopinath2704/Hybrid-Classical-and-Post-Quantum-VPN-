"""Reusable PQ-VPN widgets — cards, data rows, power button, navigation."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from app.ui.theme import COLORS, STATE_COLORS, badge_style, label


# ── Cards ─────────────────────────────────────────────────────────────
class Card(QFrame):
    def __init__(self, title: str | None = None, description: str | None = None) -> None:
        super().__init__()
        self.setObjectName("card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(20, 18, 20, 18)
        self.body.setSpacing(12)
        if title:
            self.title_label = label(title, 14, weight=650)
            self.body.addWidget(self.title_label)
        if description:
            desc = label(description, 11, COLORS["secondary"])
            desc.setWordWrap(True)
            self.body.addWidget(desc)


class DataRow(QWidget):
    """Compact name → value row for read-only detail pages."""

    def __init__(self, name: str, value: str = "—") -> None:
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 7, 0, 7)
        row.setSpacing(16)
        self.name_label = label(name, 11, COLORS["secondary"])
        self.value_label = label(value, 11, weight=550)
        self.value_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        row.addWidget(self.name_label)
        row.addStretch(1)
        row.addWidget(self.value_label, 2)

    def set_value(self, text: object, color: str | None = None) -> None:
        display = str(text) if text not in (None, "") else "—"
        self.value_label.setText(display)
        self.value_label.setStyleSheet(
            f"font-size: 11px; color: {color or COLORS['text']}; font-weight: 550;"
        )


class StatusRow(DataRow):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.status_label = self.value_label

    def set_status(self, text: str, active: bool = False, warning: bool = False) -> None:
        color = (COLORS["green"] if active else
                 COLORS["amber"] if warning else COLORS["secondary"])
        self.set_value(text, color)

    def set_active(self, active: bool, text: str = "") -> None:
        self.set_status(text or ("Active" if active else "Inactive"), active=active)


class SummaryBlock(QFrame):
    def __init__(self, name: str, value: str = "—") -> None:
        super().__init__()
        self.setObjectName("summaryBlock")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(3)
        self.name_label = label(name.upper(), 9, COLORS["muted"], 650)
        self.value_label = label(value, 12, weight=600)
        self.value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.name_label)
        layout.addWidget(self.value_label)

    def set_value(self, value: object, color: str | None = None) -> None:
        self.value_label.setText(str(value) if value not in (None, "") else "—")
        self.value_label.setStyleSheet(
            f"font-size: 12px; color: {color or COLORS['text']}; font-weight: 600;"
        )


class MetricCard(Card):
    def __init__(self, name: str, note: str) -> None:
        super().__init__()
        self.body.setContentsMargins(15, 14, 15, 14)
        self.body.setSpacing(5)
        self.name_label = label(name.upper(), 9, COLORS["muted"], 650)
        self.value_label = label("—", 22, weight=650)
        self.note_label = label(note, 9, COLORS["muted"])
        self.body.addWidget(self.name_label)
        self.body.addWidget(self.value_label)
        self.body.addWidget(self.note_label)

    def set_value(self, value: str, active: bool = False) -> None:
        self.value_label.setText(value or "—")
        color = COLORS["text"] if active else COLORS["secondary"]
        self.value_label.setStyleSheet(
            f"font-size: 22px; color: {color}; font-weight: 650;"
        )


# ── Power button ──────────────────────────────────────────────────────
class PowerButton(QPushButton):
    """Painted circular control with animated busy state."""

    def __init__(self) -> None:
        super().__init__()
        self.setFixedSize(170, 170)
        self.setCursor(Qt.PointingHandCursor)
        self.setAccessibleName("Connect to VPN")
        self.setToolTip("Connect")
        self.setStyleSheet("QPushButton { background: transparent; border: none; padding: 0; }")
        self._state = "DISCONNECTED"
        self._hovered = False
        self._phase = 0
        self._animation = QTimer(self)
        self._animation.setInterval(40)
        self._animation.timeout.connect(self._advance)

    def set_state(self, state: str) -> None:
        self._state = state
        if state in {"CONNECTING", "DISCONNECTING"}:
            self._animation.start()
        else:
            self._animation.stop()
        connected = state == "CONNECTED"
        self.setAccessibleName("Disconnect VPN" if connected else "Connect to VPN")
        self.setToolTip("Disconnect" if connected else "Connect")
        self.update()

    def _advance(self) -> None:
        self._phase = (self._phase + 8) % 360
        self.update()

    def enterEvent(self, event) -> None:
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        bounds = QRectF(10, 10, 150, 150)
        state_color = QColor(STATE_COLORS.get(self._state, COLORS["muted"]))
        if self._state == "DISCONNECTED" and self._hovered:
            state_color = QColor(COLORS["green"])

        if self._state == "CONNECTED":
            for width, alpha in ((12, 24), (7, 38)):
                glow = QColor(state_color)
                glow.setAlpha(alpha)
                painter.setPen(QPen(glow, width))
                painter.drawEllipse(bounds.adjusted(width / 2, width / 2, -width / 2, -width / 2))

        fill = QColor(COLORS["surface"])
        if self._state == "CONNECTED":
            fill = QColor(COLORS["green_dim"])
        elif self._state in {"CONNECTING", "DISCONNECTING"}:
            fill = QColor("#2B2112")
        elif self._state == "FAILED":
            fill = QColor("#2B171B")
        painter.setBrush(fill)
        painter.setPen(QPen(state_color, 4))
        painter.drawEllipse(bounds)

        if self._state in {"CONNECTING", "DISCONNECTING"}:
            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(state_color, 5, Qt.SolidLine, Qt.RoundCap))
            painter.drawArc(bounds.adjusted(-3, -3, 3, 3),
                            int(-self._phase * 16), int(105 * 16))

        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(state_color, 7, Qt.SolidLine, Qt.RoundCap))
        icon = bounds.adjusted(48, 45, -48, -45)
        painter.drawArc(icon, 45 * 16, 270 * 16)
        painter.drawLine(QPointF(85, 55), QPointF(85, 88))


# ── Sidebar navigation ───────────────────────────────────────────────
_NAV_ICONS = {
    "Home": "⌂",
    "Servers": "⬡",
    "Security": "◈",
    "Account": "◎",
    "Settings": "⚙",
    "Logs": "☰",
    "About": "ⓘ",
}


class NavButton(QPushButton):
    def __init__(self, nav_label: str) -> None:
        icon = _NAV_ICONS.get(nav_label, "")
        display = f" {icon}   {nav_label}" if icon else nav_label
        super().__init__(display)
        self.setCheckable(True)
        self.setFixedHeight(42)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(nav_label)
        self.setStyleSheet(f"""
            QPushButton {{
                border: none;
                border-left: 3px solid transparent;
                border-radius: 7px;
                background: transparent;
                color: {COLORS['secondary']};
                text-align: left;
                padding: 8px 13px;
                font-size: 12px;
                font-weight: 550;
            }}
            QPushButton:hover {{
                background: {COLORS['surface']};
                color: {COLORS['text']};
            }}
            QPushButton:checked {{
                background: #0E2A20;
                border-left-color: {COLORS['green']};
                color: {COLORS['green']};
                font-weight: 650;
            }}
            QPushButton:focus {{
                border-color: {COLORS['cyan']};
            }}
        """)


class NavRail(QFrame):
    page_selected = Signal(int, str)
    ITEMS = ("Home", "Servers", "Security", "Account", "Settings", "Logs", "About")

    def __init__(self) -> None:
        super().__init__()
        self.setFixedWidth(208)
        self.setStyleSheet(
            f"background: {COLORS['sidebar']}; "
            f"border-right: 1px solid {COLORS['border_soft']};"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 24, 18, 18)
        layout.setSpacing(5)

        brand_row = QHBoxLayout()
        mark = QLabel("PQ")
        mark.setAlignment(Qt.AlignCenter)
        mark.setFixedSize(38, 38)
        mark.setStyleSheet(f"""
            background: #0E3423;
            color: {COLORS['green']};
            border: 1px solid #1B5B3D;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 750;
        """)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(label("PQ-VPN", 16, weight=700))
        names.addWidget(label("DESKTOP", 8, COLORS["muted"], 700))
        brand_row.addWidget(mark)
        brand_row.addSpacing(8)
        brand_row.addLayout(names)
        brand_row.addStretch()
        layout.addLayout(brand_row)
        layout.addSpacing(28)

        self.buttons: list[NavButton] = []
        for index, name in enumerate(self.ITEMS):
            button = NavButton(name)
            button.clicked.connect(
                lambda checked=False, i=index, n=name: self.page_selected.emit(i, n)
            )
            self.buttons.append(button)
            layout.addWidget(button)
        layout.addStretch(1)

        self.status_label = label("DISCONNECTED", 9, COLORS["muted"], 700)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        boundary = label("LOCAL IPC", 8, COLORS["muted"], 700)
        boundary.setAlignment(Qt.AlignCenter)
        layout.addWidget(boundary)
        layout.addSpacing(8)
        from app.client import APP_VERSION
        version = label(f"v{APP_VERSION}", 9, COLORS["muted"])
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)
        self.activate(0)

    def activate(self, index: int) -> None:
        for i, button in enumerate(self.buttons):
            button.setChecked(i == index)

    def set_connection_state(self, state: str) -> None:
        color = STATE_COLORS.get(state, COLORS["muted"])
        self.status_label.setText(state.replace("_", " "))
        self.status_label.setStyleSheet(
            f"font-size: 9px; color: {color}; font-weight: 700;"
        )


# ── Utilities ─────────────────────────────────────────────────────────
def scroll_page(page: QWidget) -> QScrollArea:
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    scroll.setFrameShape(QFrame.NoFrame)
    scroll.setWidget(page)
    return scroll
