"""Centralized design tokens, stylesheet, and styling helpers."""
from __future__ import annotations

import re

from PySide6.QtWidgets import QLabel, QWidget

# ── Design tokens ─────────────────────────────────────────────────────
DARK = {
    "background": "#080D14",
    "sidebar": "#0D1520",
    "surface": "#111D2B",
    "card": "#111D2B",
    "card_hover": "#172536",
    "border": "#223244",
    "border_soft": "#1A2838",
    "border_hover": "#344758",
    "green": "#00E599",
    "green_dim": "#0A3225",
    "accent_hover": "#2EE8A0",
    "on_accent": "#06110B",
    "nav_active": "#0E2A20",
    "brand_border": "#1B5B3D",
    "cyan": "#38BDF8",
    "link_hover": "#7DD3FC",
    "purple": "#A78BFA",
    "amber": "#FBBF24",
    "warn_bg": "#2B2112",
    "warn_border": "#61491C",
    "red": "#FB7185",
    "danger_bg": "#2A171B",
    "danger_border": "#63303A",
    "disabled_bg": "#10151B",
    "log_bg": "#0C1218",
    "log_text": "#C8D2DB",
    "selection": "#1A3A4A",
    "text": "#F1F5F9",
    "secondary": "#94A3B8",
    "muted": "#8494A9",
}

LIGHT = {
    "background": "#F3F6F9",
    "sidebar": "#EAEFF4",
    "surface": "#FFFFFF",
    "card": "#FFFFFF",
    "card_hover": "#EEF2F6",
    "border": "#CBD5E1",
    "border_soft": "#DFE5EC",
    "border_hover": "#94A3B7",
    "green": "#047857",
    "green_dim": "#D1F2E4",
    "accent_hover": "#065F46",
    "on_accent": "#FCFFFD",
    "nav_active": "#DDF3EA",
    "brand_border": "#9ED9C0",
    "cyan": "#0369A1",
    "link_hover": "#075985",
    "purple": "#6D28D9",
    "amber": "#A14A06",
    "warn_bg": "#FDF3E1",
    "warn_border": "#E8C88F",
    "red": "#BE123C",
    "danger_bg": "#FDECEF",
    "danger_border": "#F2A7B5",
    "disabled_bg": "#E9EDF2",
    "log_bg": "#F8FAFC",
    "log_text": "#1E293B",
    "selection": "#BAE6FD",
    "text": "#0F172A",
    "secondary": "#475569",
    "muted": "#5A6878",
}

PALETTES = {"dark": DARK, "light": LIGHT}
THEME_CHOICES = ("dark", "light", "system")

COLORS = dict(DARK)

_STATE_TOKENS = {
    "DISCONNECTED": "muted",
    "CONNECTING": "amber",
    "CONNECTED": "green",
    "DISCONNECTING": "amber",
    "FAILED": "red",
    "SETUP_REQUIRED": "amber",
}
STATE_COLORS = {state: COLORS[token] for state, token in _STATE_TOKENS.items()}

FONT_STACK = '"Inter", "Noto Sans", "Segoe UI", sans-serif'
MONO_STACK = '"JetBrains Mono", "Noto Sans Mono", "Fira Code", monospace'

# ── Reusable button styles ────────────────────────────────────────────
PRIMARY_BTN = f"""
    QPushButton {{
        min-height: 22px;
        background: {COLORS['green']}; color: {COLORS['on_accent']};
        border: 1px solid {COLORS['green']}; border-radius: 9px;
        padding: 10px 22px; font-size: 13px; font-weight: 700;
    }}
    QPushButton:hover {{ background: {COLORS['accent_hover']}; border-color: {COLORS['accent_hover']}; }}
    QPushButton:disabled {{
        background: {COLORS['disabled_bg']}; color: {COLORS['muted']};
        border-color: {COLORS['border_soft']};
    }}
"""

LINK_BTN = f"""
    QPushButton {{
        background: transparent; border: none; color: {COLORS['cyan']};
        font-size: 12px; font-weight: 550; padding: 8px 0px;
    }}
    QPushButton:hover {{ color: {COLORS['link_hover']}; }}
    QPushButton:focus {{ text-decoration: underline; }}
"""

DANGER_BTN = f"""
    QPushButton {{
        min-height: 22px;
        background: {COLORS['danger_bg']}; color: {COLORS['red']};
        border: 1px solid {COLORS['danger_border']}; border-radius: 9px;
        padding: 10px 22px; font-size: 12px; font-weight: 700;
    }}
    QPushButton:hover {{ border-color: {COLORS['red']}; }}
    QPushButton:disabled {{
        background: {COLORS['disabled_bg']}; color: {COLORS['muted']};
        border-color: {COLORS['border_soft']};
    }}
"""


# ── Global stylesheet ─────────────────────────────────────────────────
def build_stylesheet(c: dict[str, str]) -> str:
    return f"""
    QMainWindow, QWidget#root {{
        background-color: {c['background']};
    }}
    QWidget {{
        color: {c['text']};
        font-family: {FONT_STACK};
    }}
    QLabel {{ background: transparent; }}
    QFrame#card {{
        background-color: {c['card']};
        border: 1px solid {c['border_soft']};
        border-radius: 12px;
    }}
    QFrame#summaryBlock {{
        background-color: {c['surface']};
        border: 1px solid {c['border_soft']};
        border-radius: 9px;
    }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QPushButton {{
        border: 1px solid {c['border']};
        border-radius: 8px;
        background-color: {c['surface']};
        color: {c['text']};
        padding: 9px 18px;
        font-size: 12px;
        font-weight: 600;
    }}
    QPushButton:hover {{
        background-color: {c['card_hover']};
        border-color: {c['border_hover']};
    }}
    QPushButton:disabled {{
        color: {c['muted']};
        background-color: {c['disabled_bg']};
        border-color: {c['border_soft']};
    }}
    QPushButton:focus {{
        border: 2px solid {c['cyan']};
        outline: none;
    }}
    QPlainTextEdit {{
        background-color: {c['log_bg']};
        color: {c['log_text']};
        border: 1px solid {c['border_soft']};
        border-radius: 9px;
        padding: 12px;
        selection-background-color: {c['selection']};
        font-family: {MONO_STACK};
        font-size: 11px;
    }}
    QPlainTextEdit:focus {{ border-color: {c['cyan']}; }}
    QProgressBar {{
        border: none;
        border-radius: 2px;
        background: {c['border_soft']};
        max-height: 3px;
    }}
    QProgressBar::chunk {{
        border-radius: 2px;
        background: {c['amber']};
    }}
    QLineEdit, QComboBox {{
        background-color: {c['surface']};
        color: {c['text']};
        border: 1px solid {c['border']};
        border-radius: 8px;
        padding: 10px 14px;
        font-size: 13px;
        selection-background-color: {c['selection']};
    }}
    QComboBox {{ padding: 6px 12px; font-size: 12px; }}
    QComboBox QAbstractItemView {{
        background-color: {c['surface']};
        color: {c['text']};
        selection-background-color: {c['selection']};
    }}
    QLineEdit:focus, QComboBox:focus {{
        border: 2px solid {c['cyan']};
    }}
    QLineEdit:disabled {{
        color: {c['muted']};
        background-color: {c['disabled_bg']};
        border-color: {c['border_soft']};
    }}
    QCheckBox {{ font-size: 12px; spacing: 8px; }}
    QCheckBox:focus {{ color: {c['cyan']}; }}
    QCheckBox:disabled {{ color: {c['muted']}; }}
    QToolTip {{
        background-color: {c['surface']};
        color: {c['text']};
        border: 1px solid {c['border']};
    }}
"""


STYLESHEET = build_stylesheet(DARK)

_HEX = re.compile(r"#([0-9A-Fa-f]{8}|[0-9A-Fa-f]{6})\b")


def _hex_tokens() -> dict[str, str]:
    """Map every token hex of every palette to its token name."""
    return {value.upper(): token
            for palette in PALETTES.values() for token, value in palette.items()}


def recolor(stylesheet: str, palette: dict[str, str]) -> str:
    """Swap token colors in a stylesheet for the same tokens of ``palette``.

    Eight-digit values are Qt's #AARRGGBB, so the alpha prefix is kept.
    """
    tokens = _hex_tokens()

    def swap(match: re.Match[str]) -> str:
        digits = match.group(1)
        alpha, rgb = (digits[:2], digits[2:]) if len(digits) == 8 else ("", digits)
        token = tokens.get(f"#{rgb}".upper())
        return f"#{alpha}{palette[token][1:]}" if token else match.group(0)

    return _HEX.sub(swap, stylesheet)


def resolve_theme(choice: str, system_is_light: bool) -> str:
    if choice == "system":
        return "light" if system_is_light else "dark"
    return choice if choice in PALETTES else "dark"


def apply_palette(name: str, root: QWidget | None = None) -> str:
    """Switch the live tokens, recolor ``root``'s widget tree, return the app stylesheet."""
    palette = PALETTES[name]
    COLORS.update(palette)
    STATE_COLORS.update({state: palette[token] for state, token in _STATE_TOKENS.items()})
    if root is not None:
        for widget in [root, *root.findChildren(QWidget)]:
            sheet = widget.styleSheet()
            recolored = recolor(sheet, palette) if sheet else sheet
            if recolored != sheet:
                widget.setStyleSheet(recolored)
    return build_stylesheet(palette)


def contrast_ratio(foreground: str, background: str) -> float:
    """WCAG 2.x contrast ratio between two #RRGGBB colors."""
    def luminance(value: str) -> float:
        channels = [int(value[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        r, g, b = (c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
                   for c in channels)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    high, low = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (high + 0.05) / (low + 0.05)


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
        f"background: {COLORS['surface']}; border: 1px solid #55{color[1:]}; "
        "border-radius: 7px; padding: 7px 11px;"
    )
