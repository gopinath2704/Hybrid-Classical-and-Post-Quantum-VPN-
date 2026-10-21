"""Reusable PQ-VPN widgets — cards, data rows, power button, navigation."""
from __future__ import annotations

from collections import deque

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QVBoxLayout, QWidget,
)

from app.ui.theme import COLORS, STATE_COLORS, label


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


# ── Stepper ───────────────────────────────────────────────────────────
STEP_MARKS = {"complete": "✓", "current": "●", "pending": "○"}


def step_states(done: list[bool]) -> list[str]:
    """First unfinished step is current; later unfinished steps are pending."""
    states: list[str] = []
    for finished in done:
        if finished:
            states.append("complete")
        elif "current" not in states:
            states.append("current")
        else:
            states.append("pending")
    return states


class Stepper(QWidget):
    """Numbered steps, each a StatusRow with a state mark and an optional action row."""

    def __init__(self, titles: tuple[str, ...]) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.marks: list[QLabel] = []
        self.rows: list[StatusRow] = []
        self.actions: list[QHBoxLayout] = []
        for number, title in enumerate(titles, 1):
            line = QHBoxLayout()
            mark = QLabel(STEP_MARKS["pending"])
            mark.setFixedWidth(22)
            mark.setAlignment(Qt.AlignCenter)
            row = StatusRow(f"{number}. {title}")
            line.addWidget(mark)
            line.addWidget(row, 1)
            actions = QHBoxLayout()
            actions.setContentsMargins(30, 0, 0, 4)
            layout.addLayout(line)
            layout.addLayout(actions)
            self.marks.append(mark)
            self.rows.append(row)
            self.actions.append(actions)

    def set_states(self, states: list[str]) -> None:
        colors = {"complete": COLORS["green"], "current": COLORS["cyan"],
                  "pending": COLORS["muted"]}
        for number, (mark, state) in enumerate(zip(self.marks, states), 1):
            mark.setText(STEP_MARKS[state])
            mark.setAccessibleName(f"Step {number}: {state}")
            mark.setStyleSheet(f"font-size: 14px; color: {colors[state]}; font-weight: 700;")


# ── Sparkline ─────────────────────────────────────────────────────────
def sparkline_points(values: list[float], width: float, height: float,
                     pad: float = 3.0) -> list[tuple[float, float]]:
    if len(values) < 2:
        return []
    low, high = min(values), max(values)
    span = (high - low) or 1.0
    step = (width - 2 * pad) / (len(values) - 1)
    return [(pad + i * step, height - pad - (v - low) / span * (height - 2 * pad))
            for i, v in enumerate(values)]


class Sparkline(QWidget):
    """Painted line of the most recent real samples (ring buffer)."""

    def __init__(self, capacity: int = 60, accessible_name: str = "Recent samples") -> None:
        super().__init__()
        self.samples: deque[float] = deque(maxlen=capacity)
        self.setMinimumHeight(46)
        self.setAccessibleName(accessible_name)

    def add(self, value: float) -> None:
        self.samples.append(float(value))
        low, high = min(self.samples), max(self.samples)
        self.setToolTip(f"{len(self.samples)} samples · min {low:.1f} · max {high:.1f}")
        self.update()

    def clear(self) -> None:
        self.samples.clear()
        self.setToolTip("")
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        points = sparkline_points(list(self.samples), self.width(), self.height())
        if not points:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor(COLORS["cyan"]), 2))
        painter.drawPolyline(QPolygonF([QPointF(x, y) for x, y in points]))


def motion_allowed(reduce_motion: bool) -> bool:
    return not reduce_motion and QGuiApplication.platformName() != "offscreen"


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
        self._pulse = 0.0
        self.reduce_motion = not motion_allowed(False)
        self._animation = QTimer(self)
        self._animation.setInterval(40)
        self._animation.timeout.connect(self._advance)
        self._pulse_animation = QVariantAnimation(self)
        self._pulse_animation.setDuration(650)
        self._pulse_animation.setStartValue(1.0)
        self._pulse_animation.setEndValue(0.0)
        self._pulse_animation.valueChanged.connect(self._set_pulse)

    def set_state(self, state: str) -> None:
        changed = state != self._state
        self._state = state
        if state in {"CONNECTING", "DISCONNECTING"} and not self.reduce_motion:
            self._animation.start()
        else:
            self._animation.stop()
        if changed and not self.reduce_motion:
            self._pulse_animation.stop()
            self._pulse_animation.start()
        connected = state == "CONNECTED"
        self.setAccessibleName("Disconnect VPN" if connected else "Connect to VPN")
        self.setToolTip("Disconnect" if connected else "Connect")
        self.update()

    def _advance(self) -> None:
        self._phase = (self._phase + 8) % 360
        self.update()

    def _set_pulse(self, value: float) -> None:
        self._pulse = float(value)
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

        if self._pulse > 0:
            ring = QColor(state_color)
            ring.setAlpha(int(110 * self._pulse))
            spread = 6 * (1 - self._pulse)
            painter.setPen(QPen(ring, 3))
            painter.drawEllipse(bounds.adjusted(-spread, -spread, spread, spread))

        fill = QColor(COLORS["surface"])
        if self._state == "CONNECTED":
            fill = QColor(COLORS["green_dim"])
        elif self._state in {"CONNECTING", "DISCONNECTING"}:
            fill = QColor(COLORS["warn_bg"])
        elif self._state == "FAILED":
            fill = QColor(COLORS["danger_bg"])
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

        if self.hasFocus():
            painter.setPen(QPen(QColor(COLORS["cyan"]), 2, Qt.DashLine))
            painter.drawEllipse(QRectF(2, 2, 166, 166))


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
                background: {COLORS['nav_active']};
                border-left-color: {COLORS['green']};
                color: {COLORS['green']};
                font-weight: 650;
            }}
            QPushButton:focus {{
                border: 1px solid {COLORS['cyan']};
                border-left: 3px solid {COLORS['cyan']};
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
            background: {COLORS['nav_active']};
            color: {COLORS['green']};
            border: 1px solid {COLORS['brand_border']};
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
