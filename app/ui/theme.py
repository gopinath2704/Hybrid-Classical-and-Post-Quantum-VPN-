"""Centralized design tokens, stylesheet, and styling helpers."""
from __future__ import annotations

from PySide6.QtWidgets import QLabel

# ── Design tokens ─────────────────────────────────────────────────────
COLORS = {
    "background": "#080D14",
    "sidebar": "#0D1520",
    "surface": "#111D2B",
    "card": "#111D2B",
    "card_hover": "#172536",
    "border": "#223244",
    "border_soft": "#1A2838",
    "green": "#00E599",
    "green_dim": "#0A3225",
    "cyan": "#38BDF8",
    "purple": "#A78BFA",
    "amber": "#FBBF24",
    "red": "#FB7185",
    "text": "#F1F5F9",
    "secondary": "#94A3B8",
    "muted": "#64748B",
}

STATE_COLORS = {
    "DISCONNECTED": COLORS["muted"],
    "CONNECTING": COLORS["amber"],
    "CONNECTED": COLORS["green"],
    "DISCONNECTING": COLORS["amber"],
    "FAILED": COLORS["red"],
    "SETUP_REQUIRED": COLORS["amber"],
}

FONT_STACK = '"Inter", "Noto Sans", "Segoe UI", sans-serif'
MONO_STACK = '"JetBrains Mono", "Noto Sans Mono", "Fira Code", monospace'

# ── Reusable button styles ────────────────────────────────────────────
PRIMARY_BTN = f"""
    QPushButton {{
        min-height: 22px;
        background: {COLORS['green']}; color: #06110B;
        border: 1px solid {COLORS['green']}; border-radius: 9px;
        padding: 10px 22px; font-size: 13px; font-weight: 700;
    }}
    QPushButton:hover {{ background: #2EE8A0; border-color: #2EE8A0; }}
    QPushButton:disabled {{
        background: #10151B; color: {COLORS['muted']};
        border-color: {COLORS['border_soft']};
    }}
"""

LINK_BTN = f"""
    QPushButton {{
        background: transparent; border: none; color: {COLORS['cyan']};
        font-size: 12px; font-weight: 550; padding: 8px 0px;
    }}
    QPushButton:hover {{ color: #7DD3FC; }}
"""

DANGER_BTN = f"""
    QPushButton {{
        min-height: 22px;
        background: #2A171B; color: {COLORS['red']};
        border: 1px solid #63303A; border-radius: 9px;
        padding: 10px 22px; font-size: 12px; font-weight: 700;
    }}
    QPushButton:hover {{ border-color: {COLORS['red']}; }}
    QPushButton:disabled {{
        background: #10151B; color: {COLORS['muted']};
        border-color: {COLORS['border_soft']};
    }}
"""

# ── Global stylesheet ─────────────────────────────────────────────────
STYLESHEET = f"""
    QMainWindow, QWidget#root {{
        background-color: {COLORS['background']};
    }}
    QWidget {{
        color: {COLORS['text']};
        font-family: {FONT_STACK};
    }}
    QLabel {{ background: transparent; }}
    QFrame#card {{
        background-color: {COLORS['card']};
        border: 1px solid {COLORS['border_soft']};
        border-radius: 12px;
    }}
    QFrame#summaryBlock {{
        background-color: {COLORS['surface']};
        border: 1px solid {COLORS['border_soft']};
        border-radius: 9px;
    }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QPushButton {{
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
        background-color: {COLORS['surface']};
        color: {COLORS['text']};
        padding: 9px 18px;
        font-size: 12px;
        font-weight: 600;
    }}
    QPushButton:hover {{
        background-color: {COLORS['card_hover']};
        border-color: #344758;
    }}
    QPushButton:disabled {{
        color: {COLORS['muted']};
        background-color: #10151B;
        border-color: {COLORS['border_soft']};
    }}
    QPushButton:focus {{
        border-color: {COLORS['cyan']};
        outline: none;
    }}
    QPlainTextEdit {{
        background-color: #0C1218;
        color: #C8D2DB;
        border: 1px solid {COLORS['border_soft']};
        border-radius: 9px;
        padding: 12px;
        selection-background-color: #1A3A4A;
        font-family: {MONO_STACK};
        font-size: 11px;
    }}
    QProgressBar {{
        border: none;
        border-radius: 2px;
        background: {COLORS['border_soft']};
        max-height: 3px;
    }}
    QProgressBar::chunk {{
        border-radius: 2px;
        background: {COLORS['amber']};
    }}
    QLineEdit {{
        background-color: {COLORS['surface']};
        color: {COLORS['text']};
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 13px;
        selection-background-color: #1A3A4A;
    }}
    QLineEdit:focus {{
        border-color: {COLORS['green']};
    }}
    QLineEdit:disabled {{
        color: {COLORS['muted']};
        background-color: #10151B;
        border-color: {COLORS['border_soft']};
    }}
"""


# ── Helpers ───────────────────────────────────────────────────────────
def label(
    text: str,
    size: int = 12,
    color: str | None = None,
    weight: int = 400,
) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"font-size: {size}px; color: {color or COLORS['text']}; "
        f"font-weight: {weight};"
    )
    return lbl


def badge_style(color: str) -> str:
    return (
        f"font-size: 9px; color: {color}; font-weight: 700; "
        f"background: {COLORS['surface']}; border: 1px solid {color}55; "
        "border-radius: 7px; padding: 7px 11px;"
    )
