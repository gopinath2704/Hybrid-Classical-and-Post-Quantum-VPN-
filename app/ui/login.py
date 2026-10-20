"""Full-screen login window with custom-painted dark background and sign-in card."""
from __future__ import annotations

import math
from pathlib import Path

from PySide6.QtCore import QEvent, QPointF, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush, QColor, QFont, QFontDatabase, QIcon, QLinearGradient,
    QPainter, QPainterPath, QPen, QPixmap, QRadialGradient,
)
from PySide6.QtWidgets import (
    QGraphicsDropShadowEffect, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSizePolicy, QStackedWidget, QVBoxLayout, QWidget,
)

from app.client import (
    AccountAPIError, AccountClient,
    _AccountWorker, _ACCOUNT_ERROR_MESSAGES,
)

# ── Colors ───────────────────────────────────────────────────────────
ACCENT = "#1de9a0"
C_HEAD = "#f2f8fb"
C_BODY = "#b4c6d3"
C_MUTED = "#8ea3b3"
C_LABEL = "#aab9c6"
C_HEADLINE = "#d6e6f2"
C_FEAT = "#eaf3f8"
C_FOOTER = "#c3d3de"
C_SUB = "#9db2c2"
C_CARD_SUB = "#a9bccb"
C_PH = "#7f93a3"
C_BTN = "#04201a"
C_ERR = "#fb7185"

FONT_FAMILY = "Manrope"


def _try_load_fonts() -> str:
    fonts_dir = Path(__file__).resolve().parent.parent.parent / "fonts"
    if fonts_dir.is_dir():
        for ext in ("*.ttf", "*.otf"):
            for f in fonts_dir.glob(ext):
                QFontDatabase.addApplicationFont(str(f))
    if FONT_FAMILY in QFontDatabase.families():
        return FONT_FAMILY
    return "sans-serif"


# ── QPainter icon drawing ───────────────────────────────────────────
class Icons:

    @staticmethod
    def _pen(color=ACCENT, width=1.6):
        return QPen(QColor(color), width, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)

    @staticmethod
    def draw_key(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen())
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 22
        p.drawEllipse(QPointF(cx - 4 * s, cy), 3.5 * s, 3.5 * s)
        p.drawLine(QPointF(cx - 0.5 * s, cy), QPointF(cx + 8 * s, cy))
        p.drawLine(QPointF(cx + 4 * s, cy), QPointF(cx + 4 * s, cy + 3 * s))
        p.drawLine(QPointF(cx + 7 * s, cy), QPointF(cx + 7 * s, cy + 2.5 * s))
        p.restore()

    @staticmethod
    def draw_padlock(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen())
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 22
        p.drawRoundedRect(QRectF(cx - 5 * s, cy - 1 * s, 10 * s, 8 * s), 1.5 * s, 1.5 * s)
        path = QPainterPath()
        path.moveTo(cx - 3 * s, cy - 1 * s)
        path.lineTo(cx - 3 * s, cy - 4 * s)
        path.cubicTo(cx - 3 * s, cy - 7 * s, cx + 3 * s, cy - 7 * s, cx + 3 * s, cy - 4 * s)
        path.lineTo(cx + 3 * s, cy - 1 * s)
        p.drawPath(path)
        p.restore()

    @staticmethod
    def draw_network(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen(width=1.4))
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 22
        corners = [QPointF(cx + dx * 6 * s, cy + dy * 6 * s)
                   for dx, dy in ((-1, -1), (1, -1), (-1, 1), (1, 1))]
        for c in corners:
            p.drawLine(QPointF(cx, cy), c)
        p.setBrush(QColor(ACCENT))
        for c in corners:
            p.drawEllipse(c, 2 * s, 2 * s)
        p.drawEllipse(QPointF(cx, cy), 2.5 * s, 2.5 * s)
        p.restore()

    @staticmethod
    def draw_shield_check(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen())
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 22
        path = QPainterPath()
        path.moveTo(cx, cy - 8 * s)
        path.lineTo(cx + 7 * s, cy - 4 * s)
        path.lineTo(cx + 7 * s, cy + 1 * s)
        path.cubicTo(cx + 7 * s, cy + 6 * s, cx, cy + 9 * s, cx, cy + 9 * s)
        path.cubicTo(cx, cy + 9 * s, cx - 7 * s, cy + 6 * s, cx - 7 * s, cy + 1 * s)
        path.lineTo(cx - 7 * s, cy - 4 * s)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(cx - 3 * s, cy + 0.5 * s), QPointF(cx - 0.5 * s, cy + 3 * s))
        p.drawLine(QPointF(cx - 0.5 * s, cy + 3 * s), QPointF(cx + 4 * s, cy - 2 * s))
        p.restore()

    @staticmethod
    def draw_user(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen(C_MUTED, 1.5))
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 18
        p.drawEllipse(QPointF(cx, cy - 3 * s), 3 * s, 3 * s)
        path = QPainterPath()
        path.moveTo(cx - 5.5 * s, cy + 7 * s)
        path.cubicTo(cx - 5.5 * s, cy + 2 * s, cx + 5.5 * s, cy + 2 * s, cx + 5.5 * s, cy + 7 * s)
        p.drawPath(path)
        p.restore()

    @staticmethod
    def draw_lock_sm(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen(C_MUTED, 1.5))
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 18
        p.drawRoundedRect(QRectF(cx - 4 * s, cy, 8 * s, 6.5 * s), 1.2 * s, 1.2 * s)
        path = QPainterPath()
        path.moveTo(cx - 2.5 * s, cy)
        path.lineTo(cx - 2.5 * s, cy - 2.5 * s)
        path.cubicTo(cx - 2.5 * s, cy - 5.5 * s, cx + 2.5 * s, cy - 5.5 * s,
                     cx + 2.5 * s, cy - 2.5 * s)
        path.lineTo(cx + 2.5 * s, cy)
        p.drawPath(path)
        p.restore()

    @staticmethod
    def draw_eye_off(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen(C_MUTED, 1.4))
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 18
        eye = QPainterPath()
        eye.moveTo(cx - 7 * s, cy)
        eye.cubicTo(cx - 4 * s, cy - 4.5 * s, cx + 4 * s, cy - 4.5 * s, cx + 7 * s, cy)
        eye.cubicTo(cx + 4 * s, cy + 4.5 * s, cx - 4 * s, cy + 4.5 * s, cx - 7 * s, cy)
        p.drawPath(eye)
        p.drawEllipse(QPointF(cx, cy), 2 * s, 2 * s)
        p.drawLine(QPointF(cx - 6 * s, cy + 5 * s), QPointF(cx + 6 * s, cy - 5 * s))
        p.restore()

    @staticmethod
    def draw_eye(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen(ACCENT, 1.4))
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 18
        eye = QPainterPath()
        eye.moveTo(cx - 7 * s, cy)
        eye.cubicTo(cx - 4 * s, cy - 4.5 * s, cx + 4 * s, cy - 4.5 * s, cx + 7 * s, cy)
        eye.cubicTo(cx + 4 * s, cy + 4.5 * s, cx - 4 * s, cy + 4.5 * s, cx - 7 * s, cy)
        p.drawPath(eye)
        p.drawEllipse(QPointF(cx, cy), 2 * s, 2 * s)
        p.restore()

    @staticmethod
    def draw_signin(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen(C_BTN, 2.0))
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 18
        p.drawLine(QPointF(cx - 5 * s, cy), QPointF(cx + 2 * s, cy))
        p.drawLine(QPointF(cx - 0.5 * s, cy - 3 * s), QPointF(cx + 2 * s, cy))
        p.drawLine(QPointF(cx - 0.5 * s, cy + 3 * s), QPointF(cx + 2 * s, cy))
        door = QPainterPath()
        door.moveTo(cx + 1 * s, cy - 6 * s)
        door.lineTo(cx + 6 * s, cy - 6 * s)
        door.lineTo(cx + 6 * s, cy + 6 * s)
        door.lineTo(cx + 1 * s, cy + 6 * s)
        p.drawPath(door)
        p.restore()

    @staticmethod
    def draw_shield_sm(p: QPainter, r: QRectF, color=ACCENT):
        p.save()
        p.setPen(Icons._pen(color, 1.4))
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 20
        path = QPainterPath()
        path.moveTo(cx, cy - 7 * s)
        path.lineTo(cx + 6 * s, cy - 3.5 * s)
        path.lineTo(cx + 6 * s, cy + 0.5 * s)
        path.cubicTo(cx + 6 * s, cy + 5 * s, cx, cy + 8 * s, cx, cy + 8 * s)
        path.cubicTo(cx, cy + 8 * s, cx - 6 * s, cy + 5 * s, cx - 6 * s, cy + 0.5 * s)
        path.lineTo(cx - 6 * s, cy - 3.5 * s)
        path.closeSubpath()
        p.drawPath(path)
        p.drawLine(QPointF(cx - 2 * s, cy + 0.5 * s), QPointF(cx - 0.5 * s, cy + 2.5 * s))
        p.drawLine(QPointF(cx - 0.5 * s, cy + 2.5 * s), QPointF(cx + 3 * s, cy - 1.5 * s))
        p.restore()

    @staticmethod
    def draw_lock_xs(p: QPainter, r: QRectF):
        p.save()
        p.setPen(Icons._pen(C_MUTED, 1.2))
        p.setBrush(Qt.NoBrush)
        cx, cy = r.center().x(), r.center().y()
        s = r.width() / 14
        p.drawRoundedRect(QRectF(cx - 3 * s, cy + 0.5 * s, 6 * s, 4.5 * s), s, s)
        arc = QPainterPath()
        arc.moveTo(cx - 1.8 * s, cy + 0.5 * s)
        arc.lineTo(cx - 1.8 * s, cy - 1.5 * s)
        arc.cubicTo(cx - 1.8 * s, cy - 4 * s, cx + 1.8 * s, cy - 4 * s,
                    cx + 1.8 * s, cy - 1.5 * s)
        arc.lineTo(cx + 1.8 * s, cy + 0.5 * s)
        p.drawPath(arc)
        p.restore()


def _make_icon(draw_fn, size=18) -> QIcon:
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    draw_fn(p, QRectF(0, 0, size, size))
    p.end()
    return QIcon(pix)


# ── Small helper widgets ─────────────────────────────────────────────

class _CardBg(QWidget):
    """Card with painted rounded-rect gradient background."""

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(0, 0, self.width(), self.height())
        path = QPainterPath()
        path.addRoundedRect(rect, 22, 22)
        grad = QLinearGradient(0, 0, 0, self.height())
        grad.setColorAt(0, QColor(20, 36, 48, 217))
        grad.setColorAt(1, QColor(12, 24, 33, 217))
        p.fillPath(path, grad)
        p.setPen(QPen(QColor(255, 255, 255, 25), 1))
        p.setBrush(Qt.NoBrush)
        p.drawPath(path)
        p.end()


class _PQLogo(QWidget):
    def __init__(self, size=50, font_px=19, radius=12, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._fpx, self._r = font_px, radius

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        p.setPen(QPen(QColor(ACCENT), 1))
        p.setBrush(QColor(29, 233, 160, 25))
        p.drawRoundedRect(r, self._r, self._r)
        f = p.font()
        f.setPixelSize(self._fpx)
        f.setWeight(QFont.ExtraBold)
        p.setFont(f)
        p.setPen(QColor(ACCENT))
        p.drawText(QRectF(0, 0, self.width(), self.height()), Qt.AlignCenter, "PQ")
        p.end()


class _IconTile(QWidget):
    def __init__(self, draw_fn, parent=None):
        super().__init__(parent)
        self.setFixedSize(42, 42)
        self._draw = draw_fn

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(QPen(QColor(29, 233, 160, 64), 1))
        p.setBrush(QColor(29, 233, 160, 25))
        p.drawRoundedRect(QRectF(0.5, 0.5, 41, 41), 10, 10)
        self._draw(p, QRectF(10, 10, 22, 22))
        p.end()


class _IconOverlay(QWidget):
    """Transparent icon overlay inside a line edit."""

    def __init__(self, draw_fn, size=18, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._draw = draw_fn

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        self._draw(p, QRectF(0, 0, self.width(), self.height()))
        p.end()


class _EyeToggle(QPushButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(36, 36)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet("QPushButton{background:transparent;border:none;padding:0;}")
        self._vis = False

    @property
    def password_visible(self):
        return self._vis

    def toggle(self):
        self._vis = not self._vis
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(9, 9, 18, 18)
        (Icons.draw_eye if self._vis else Icons.draw_eye_off)(p, r)
        p.end()


class _GlowDot(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(12, 12)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        g = QRadialGradient(6, 6, 8)
        g.setColorAt(0, QColor(29, 233, 160, 180))
        g.setColorAt(1, QColor(29, 233, 160, 0))
        p.setBrush(g)
        p.drawEllipse(QRectF(-2, -2, 16, 16))
        p.setBrush(QColor(ACCENT))
        p.drawEllipse(QRectF(2, 2, 8, 8))
        p.end()


class _SmallIcon(QWidget):
    def __init__(self, draw_fn, size=18, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._draw = draw_fn

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        self._draw(p, QRectF(0, 0, self.width(), self.height()))
        p.end()


# ── Field QSS ────────────────────────────────────────────────────────
_FIELD_QSS = (
    "QLineEdit {"
    " background: rgba(8,18,26,0.7);"
    " border: 1px solid rgba(255,255,255,0.12);"
    " border-radius: 10px;"
    f" color: {C_HEAD};"
    " font-size: 15px;"
    " padding: 0 16px 0 52px;"
    " min-height: 48px; max-height: 48px;"
    " }"
    f" QLineEdit:focus {{ border: 2px solid {ACCENT}; padding: 0 15px 0 51px; }}"
    " QLineEdit:disabled { background: rgba(6,12,18,0.7); color: #5a7080; }"
)

_PW_FIELD_QSS = _FIELD_QSS.replace(
    "padding:0 16px 0 52px", "padding:0 44px 0 52px"
).replace(
    "padding:0 15px 0 51px", "padding:0 43px 0 51px"
)

_LABEL_QSS = f"color:{C_LABEL};font-size:12px;font-weight:700;letter-spacing:0.06em;"

_BTN_QSS = (
    f"QPushButton {{ background:{ACCENT}; color:{C_BTN};"
    " border:none; border-radius:10px; font-size:16px; font-weight:800; }"
    f" QPushButton:hover {{ background:#2eefa8; }}"
    f" QPushButton:pressed {{ background:#18d690; }}"
    f" QPushButton:disabled {{ background:#0a4a3a; color:{C_BTN}; }}"
)


# ── LoginWindow ──────────────────────────────────────────────────────

class LoginWindow(QWidget):
    """Authentication gate shown before the main window."""

    login_succeeded = Signal()
    register_requested = Signal()

    _DW, _DH = 1440, 766

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("PQ-VPN")
        self.setMinimumSize(1080, 640)
        self.resize(self._DW, self._DH)

        ff = _try_load_fonts()
        font = QFont(ff)
        font.setStyleHint(QFont.SansSerif)
        self.setFont(font)

        self.session_token: str | None = None
        self.session_user: dict | None = None
        self.session_expires_at: str = ""
        self.account_client: AccountClient | None = None

        self._worker = _AccountWorker()
        self._worker.finished.connect(self._on_finished)
        self._cooldown_timer = QTimer(self)
        self._cooldown_timer.setInterval(1000)
        self._cooldown_timer.timeout.connect(self._tick_cooldown)
        self._cooldown_remaining = 0
        self._cooldown_is_login = True

        self._build_left_panel()
        self._build_card()

    # ── Left panel (all child widgets of self, positioned in resizeEvent) ──

    def _build_left_panel(self):
        # Brand
        self._brand = QWidget(self)
        bl = QHBoxLayout(self._brand)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(10)
        bl.addWidget(_PQLogo(50, 19, 12))
        bt = QVBoxLayout()
        bt.setSpacing(1)
        t = QLabel("PQ-VPN")
        t.setStyleSheet(f"color:{C_HEAD};font-size:26px;font-weight:800;")
        bt.addWidget(t)
        s = QLabel("Post-Quantum Secure Connectivity")
        s.setStyleSheet(f"color:{C_SUB};font-size:13px;")
        bt.addWidget(s)
        bl.addLayout(bt)
        bl.addStretch()

        # Headline (rich text for mixed colours)
        self._headline = QLabel(self)
        self._headline.setTextFormat(Qt.RichText)
        self._headline.setWordWrap(True)
        self._headline.setText(
            f'<span style="font-size:31px;font-weight:800;line-height:1.3;color:{C_HEADLINE};">'
            f'Next-Generation VPN<br>Classical + '
            f'<span style="color:{ACCENT};">Post-Quantum Security</span></span>'
        )

        # Description
        self._desc = QLabel("Hybrid encryption. Stronger privacy. A safer tomorrow.\n"
                            "Connect securely with PQ-VPN.", self)
        self._desc.setStyleSheet(f"color:{C_BODY};font-size:15px;")
        self._desc.setWordWrap(True)

        # Feature row
        self._feat = QWidget(self)
        fl = QHBoxLayout(self._feat)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.setSpacing(0)
        features = [
            (Icons.draw_key, "Hybrid Handshake", "X25519 +\nML-KEM-768"),
            (Icons.draw_padlock, "AES-256-GCM", "Fast & secure traffic\nencryption, per direction"),
            (Icons.draw_network, "IPv4 Tunnel", "Secure IPv4\ntunnel support"),
            (Icons.draw_shield_check, "Server Pinning", "ML-KEM-768 key,\nSHA-256 fingerprint"),
        ]
        for i, (fn, title, desc) in enumerate(features):
            if i > 0:
                dv = QWidget()
                dv.setFixedWidth(1)
                dv.setStyleSheet("background:rgba(255,255,255,0.1);")
                dv.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
                fl.addWidget(dv)
            col = QWidget()
            cl = QVBoxLayout(col)
            cl.setContentsMargins(20 if i > 0 else 0, 0, 0, 0)
            cl.setSpacing(8)
            cl.addWidget(_IconTile(fn))
            tl = QLabel(title)
            tl.setStyleSheet(f"color:{C_FEAT};font-size:14px;font-weight:700;")
            cl.addWidget(tl)
            dl = QLabel(desc)
            dl.setStyleSheet(f"color:{C_MUTED};font-size:13px;")
            dl.setWordWrap(True)
            cl.addWidget(dl)
            fl.addWidget(col, 1)
            fl.addWidget(col)

        # Footer
        self._footer = QWidget(self)
        ftl = QHBoxLayout(self._footer)
        ftl.setContentsMargins(0, 0, 0, 0)
        ftl.setSpacing(8)
        ftl.addWidget(_GlowDot())
        ftxt = QLabel("Secure  •  Private  •  Future Ready")
        ftxt.setStyleSheet(f"color:{C_FOOTER};font-size:14px;")
        ftl.addWidget(ftxt)
        ftl.addStretch()

    # ── Sign-in card ─────────────────────────────────────────────────

    def _build_card(self):
        self.card = _CardBg(self)
        self.card.setFixedWidth(620)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(80)
        shadow.setYOffset(30)
        shadow.setColor(QColor(0, 0, 0, 115))
        self.card.setGraphicsEffect(shadow)

        root = QVBoxLayout(self.card)
        root.setContentsMargins(40, 40, 40, 32)
        root.setSpacing(0)

        logo = _PQLogo(54, 21, 14)
        root.addWidget(logo, 0, Qt.AlignCenter)
        root.addSpacing(16)

        self.stack = QStackedWidget()
        self._build_login_form()
        self._build_register_form()
        root.addWidget(self.stack)

    def _configure_field(self, field: QLineEdit):
        from PySide6.QtGui import QPalette
        pal = field.palette()
        pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(C_PH))
        field.setPalette(pal)

    def _build_login_form(self):
        w = QWidget()
        lo = QVBoxLayout(w)
        lo.setContentsMargins(0, 0, 0, 0)
        lo.setSpacing(0)

        h = QLabel("Welcome Back")
        h.setAlignment(Qt.AlignCenter)
        h.setStyleSheet(f"color:{C_HEAD};font-size:25px;font-weight:800;")
        lo.addWidget(h)
        lo.addSpacing(8)

        sub = QLabel("Sign in to your PQ-VPN account")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(f"color:{C_CARD_SUB};font-size:15px;")
        lo.addWidget(sub)
        lo.addSpacing(34)

        # ── Username ──
        lo.addWidget(self._lbl("Username"))
        lo.addSpacing(8)

        self.login_identifier = QLineEdit()
        self.login_identifier.setPlaceholderText("Username or email address")
        self.login_identifier.setStyleSheet(_FIELD_QSS)
        self.login_identifier.setFixedHeight(50)
        self._configure_field(self.login_identifier)
        self.login_identifier.returnPressed.connect(self._on_login)
        lo.addWidget(self.login_identifier)

        _IconOverlay(Icons.draw_user, 18, self.login_identifier).move(17, 16)

        self.login_user_error = QLabel("")
        self.login_user_error.setStyleSheet(f"color:{C_ERR};font-size:12px;")
        self.login_user_error.hide()
        lo.addWidget(self.login_user_error)
        lo.addSpacing(22)

        # ── Password ──
        lo.addWidget(self._lbl("PASSWORD"))
        lo.addSpacing(8)

        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Enter password")
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_password.setStyleSheet(_PW_FIELD_QSS)
        self.login_password.setFixedHeight(50)
        self._configure_field(self.login_password)
        self.login_password.returnPressed.connect(self._on_login)
        self.login_password.installEventFilter(self)
        lo.addWidget(self.login_password)

        _IconOverlay(Icons.draw_lock_sm, 18, self.login_password).move(17, 16)
        self._eye = _EyeToggle(self.login_password)
        self._eye.clicked.connect(self._toggle_password_visibility)

        self.login_pw_error = QLabel("")
        self.login_pw_error.setStyleSheet(f"color:{C_ERR};font-size:12px;")
        self.login_pw_error.hide()
        lo.addWidget(self.login_pw_error)

        # ── TOTP (hidden until needed) ──
        self.login_totp_label = QLabel("TOTP CODE")
        self.login_totp_label.setStyleSheet(_LABEL_QSS)
        self.login_totp_label.hide()
        lo.addWidget(self.login_totp_label)
        self.login_totp = QLineEdit()
        self.login_totp.setPlaceholderText("6-digit code from your authenticator")
        self.login_totp.setMaxLength(6)
        self.login_totp.setStyleSheet(_FIELD_QSS)
        self.login_totp.setFixedHeight(50)
        self._configure_field(self.login_totp)
        self.login_totp.returnPressed.connect(self._on_login)
        self.login_totp.hide()
        lo.addWidget(self.login_totp)

        # ── General error / cooldown ──
        self.login_error = QLabel("")
        self.login_error.setStyleSheet(f"color:{C_ERR};font-size:12px;")
        self.login_error.setWordWrap(True)
        self.login_error.hide()
        lo.addWidget(self.login_error)
        self.login_cooldown_label = QLabel("")
        self.login_cooldown_label.setStyleSheet("color:#FBBF24;font-size:12px;font-weight:600;")
        self.login_cooldown_label.hide()
        lo.addWidget(self.login_cooldown_label)

        lo.addSpacing(26)

        # ── Sign In button ──
        self.login_btn = QPushButton("Sign In")
        self.login_btn.setCursor(Qt.PointingHandCursor)
        self.login_btn.setFixedHeight(52)
        self.login_btn.setStyleSheet(_BTN_QSS)
        self.login_btn.setIcon(_make_icon(Icons.draw_signin, 18))
        self.login_btn.setIconSize(QSize(18, 18))
        glow = QGraphicsDropShadowEffect()
        glow.setBlurRadius(24)
        glow.setYOffset(8)
        glow.setColor(QColor(29, 233, 160, 64))
        self.login_btn.setGraphicsEffect(glow)
        self.login_btn.clicked.connect(self._on_login)
        lo.addWidget(self.login_btn)
        lo.addSpacing(26)

        # ── Divider ──
        dv = QWidget()
        dv.setFixedHeight(1)
        dv.setStyleSheet("background:rgba(255,255,255,0.08);")
        lo.addWidget(dv)
        lo.addSpacing(20)

        # ── Footer row ──
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        lf = QHBoxLayout()
        lf.setSpacing(6)
        lf.addWidget(_SmallIcon(lambda p, r: Icons.draw_shield_sm(p, r, ACCENT), 20))
        lf.addWidget(self._footlbl("Need an account? "))
        self.login_register_link = QPushButton("Register")
        self.login_register_link.setCursor(Qt.PointingHandCursor)
        self.login_register_link.setStyleSheet(
            f"QPushButton {{background:transparent;border:none;color:{ACCENT};"
            " font-size:14px;font-weight:700;padding:0;}"
            " QPushButton:hover{color:#4ef0b8;}"
        )
        self.login_register_link.clicked.connect(self._show_register)
        lf.addWidget(self.login_register_link)
        lf.addStretch()
        footer.addLayout(lf)
        footer.addStretch()
        rf = QHBoxLayout()
        rf.setSpacing(4)
        rf.addWidget(_SmallIcon(Icons.draw_lock_xs, 14))
        rf.addWidget(self._footlbl("Secure Connection", C_MUTED, 13))
        footer.addLayout(rf)
        lo.addLayout(footer)

        self.stack.addWidget(w)

    def _build_register_form(self):
        w = QWidget()
        lo = QVBoxLayout(w)
        lo.setContentsMargins(0, 0, 0, 0)
        lo.setSpacing(0)

        h = QLabel("Create Account")
        h.setAlignment(Qt.AlignCenter)
        h.setStyleSheet(f"color:{C_HEAD};font-size:25px;font-weight:800;")
        lo.addWidget(h)
        lo.addSpacing(8)
        sub = QLabel("Register a new PQ-VPN account")
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(f"color:{C_CARD_SUB};font-size:15px;")
        lo.addWidget(sub)
        lo.addSpacing(28)

        for field_name, label_text, placeholder, echo in (
            ("register_username", "USERNAME", "Choose a username", False),
            ("register_email", "EMAIL", "Your email address", False),
            ("register_password", "PASSWORD", "Minimum 12 characters", True),
            ("register_confirm", "CONFIRM PASSWORD", "Re-enter password", True),
        ):
            lo.addWidget(self._lbl(label_text))
            lo.addSpacing(6)
            field = QLineEdit()
            field.setPlaceholderText(placeholder)
            field.setStyleSheet(_FIELD_QSS)
            field.setFixedHeight(46)
            self._configure_field(field)
            if echo:
                field.setEchoMode(QLineEdit.Password)
            setattr(self, field_name, field)
            lo.addWidget(field)
            lo.addSpacing(14)

        self.register_password.textChanged.connect(self._update_register_validation)
        self.register_confirm.textChanged.connect(self._update_register_validation)
        self.register_confirm.returnPressed.connect(self._on_register)

        self.register_validation = QLabel("")
        self.register_validation.setStyleSheet(f"color:{C_MUTED};font-size:11px;")
        lo.addWidget(self.register_validation)
        self.register_error = QLabel("")
        self.register_error.setStyleSheet(f"color:{C_ERR};font-size:12px;")
        self.register_error.setWordWrap(True)
        self.register_error.hide()
        lo.addWidget(self.register_error)
        self.register_cooldown_label = QLabel("")
        self.register_cooldown_label.setStyleSheet("color:#FBBF24;font-size:12px;font-weight:600;")
        self.register_cooldown_label.hide()
        lo.addWidget(self.register_cooldown_label)

        lo.addSpacing(20)

        self.register_btn = QPushButton("Create Account")
        self.register_btn.setCursor(Qt.PointingHandCursor)
        self.register_btn.setFixedHeight(52)
        self.register_btn.setStyleSheet(_BTN_QSS)
        glow = QGraphicsDropShadowEffect()
        glow.setBlurRadius(24)
        glow.setYOffset(8)
        glow.setColor(QColor(29, 233, 160, 64))
        self.register_btn.setGraphicsEffect(glow)
        self.register_btn.clicked.connect(self._on_register)
        lo.addWidget(self.register_btn)
        lo.addSpacing(20)

        dv = QWidget()
        dv.setFixedHeight(1)
        dv.setStyleSheet("background:rgba(255,255,255,0.08);")
        lo.addWidget(dv)
        lo.addSpacing(16)

        footer = QHBoxLayout()
        self.register_back_link = QPushButton("Already have an account? Sign In")
        self.register_back_link.setCursor(Qt.PointingHandCursor)
        self.register_back_link.setStyleSheet(
            f"QPushButton {{ background:transparent; border:none; color:{ACCENT};"
            " font-size:14px; font-weight:600; padding:0; }"
            " QPushButton:hover { color:#4ef0b8; }"
        )
        self.register_back_link.clicked.connect(self._show_login)
        footer.addWidget(self.register_back_link)
        footer.addStretch()
        lo.addLayout(footer)

        self.stack.addWidget(w)

    # ── Tiny helpers ──

    @staticmethod
    def _lbl(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(_LABEL_QSS)
        return lbl

    @staticmethod
    def _footlbl(text: str, color=C_FOOTER, size=14) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color:{color}; font-size:{size}px;")
        return lbl

    # ── Background painting ──────────────────────────────────────────

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()

        # Linear gradient 160°
        a = math.radians(160)
        diag = math.hypot(w, h) * 0.5
        cx, cy = w / 2, h / 2
        dx, dy = math.sin(a), -math.cos(a)
        grad = QLinearGradient(cx - dx * diag, cy - dy * diag,
                               cx + dx * diag, cy + dy * diag)
        grad.setColorAt(0.0, QColor("#07131c"))
        grad.setColorAt(0.5, QColor("#061017"))
        grad.setColorAt(1.0, QColor("#050d13"))
        p.fillRect(0, 0, w, h, grad)

        # Radial glow top-right
        glow = QRadialGradient(w * 0.85, h * 0.1, max(w, h) * 0.45)
        glow.setColorAt(0.0, QColor(13, 58, 61, 120))
        glow.setColorAt(1.0, QColor(13, 58, 61, 0))
        p.fillRect(0, 0, w, h, glow)

        self._paint_mountains(p, w, h)
        self._paint_waves(p, w, h)
        p.end()

    def _paint_mountains(self, p: QPainter, w: int, h: int):
        sx = min(w / self._DW, 1.2)
        mw = int(760 * sx)

        # Back ridge
        g1 = QLinearGradient(0, h - 330, 0, h)
        g1.setColorAt(0, QColor("#0c2a30"))
        g1.setColorAt(1, QColor("#050d13"))
        p1 = QPainterPath()
        p1.moveTo(0, h)
        peaks = [(0, .55), (.06, .7), (.13, .85), (.21, .65), (.29, .78),
                 (.38, .92), (.46, .72), (.55, .82), (.63, .68),
                 (.73, .75), (.83, .6), (.91, .7), (1, .55)]
        for fx, fy in peaks:
            p1.lineTo(mw * fx, h - 330 * fy)
        p1.lineTo(mw, h)
        p1.closeSubpath()
        p.setPen(Qt.NoPen)
        p.setBrush(g1)
        p.drawPath(p1)

        # Front ridge
        g2 = QLinearGradient(0, h - 200, 0, h)
        g2.setColorAt(0, QColor(10, 30, 38, 200))
        g2.setColorAt(1, QColor(5, 13, 19, 220))
        p2 = QPainterPath()
        p2.moveTo(0, h)
        peaks2 = [(0, .35), (.09, .45), (.19, .55), (.26, .4), (.36, .52),
                  (.43, .48), (.52, .55), (.62, .42), (.72, .5),
                  (.82, .38), (.93, .45), (1, .3)]
        for fx, fy in peaks2:
            p2.lineTo(mw * fx, h - 330 * fy)
        p2.lineTo(mw, h)
        p2.closeSubpath()
        p.setBrush(g2)
        p.drawPath(p2)

    def _paint_waves(self, p: QPainter, w: int, h: int):
        sx = min(w / self._DW, 1.2)
        mw = int(760 * sx)
        base = h - 160

        specs = [
            (base - 40, 2.0, 200),
            (base - 15, 2.0, 150),
            (base + 10, 1.0, 100),
            (base + 30, 1.0, 60),
        ]
        for y0, lw, ma in specs:
            g = QLinearGradient(0, 0, mw, 0)
            g.setColorAt(0.0, QColor(29, 233, 160, 0))
            g.setColorAt(0.5, QColor(29, 233, 160, ma))
            g.setColorAt(1.0, QColor(29, 233, 160, int(ma * 0.11)))
            pen = QPen(QBrush(g), lw)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.setBrush(Qt.NoBrush)
            path = QPainterPath()
            path.moveTo(60 * sx, y0)
            path.cubicTo(mw * .2, y0 - 25, mw * .35, y0 + 20, mw * .5, y0 - 10)
            path.cubicTo(mw * .65, y0 - 35, mw * .8, y0 + 15, mw * .95, y0 - 5)
            p.drawPath(path)

    # ── Layout / resize ──────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not hasattr(self, "card"):
            return
        w, h = self.width(), self.height()

        card_x = w - 641
        left_w = max(card_x - 80, 300)
        lx = 60

        self._brand.setGeometry(56, 36, min(500, left_w), 60)

        hw = min(700, left_w)
        self._headline.setFixedWidth(hw)
        hh = self._headline.heightForWidth(hw)
        if hh < 0:
            hh = self._headline.sizeHint().height()
        self._headline.setGeometry(lx, 160, hw, hh)

        desc_y = 160 + hh + 10
        self._desc.setGeometry(lx, desc_y, min(600, left_w), 50)

        feat_y = desc_y + 60
        self._feat.setGeometry(lx - 1, feat_y, min(740, left_w), 140)
        self._footer.setGeometry(66, h - 56, 400, 30)

        card_y = max(int(h * 123 / self._DH), 40)
        self.card.move(card_x, card_y)
        self.card.setFixedHeight(min(h - card_y - 30, 620))

    def eventFilter(self, obj, event):
        if obj is self.login_password and event.type() == QEvent.Type.Resize:
            self._eye.move(obj.width() - 44, (obj.height() - 36) // 2)
        return super().eventFilter(obj, event)

    # ── View switching ───────────────────────────────────────────────

    def show_login_view(self) -> None:
        self.stack.setCurrentIndex(0)
        for lbl in (self.login_error, self.login_user_error, self.login_pw_error,
                    self.login_totp_label, self.login_cooldown_label):
            lbl.hide()
        self.login_totp.hide()
        self.login_totp.clear()

    def show_register_view(self) -> None:
        self.stack.setCurrentIndex(1)
        self.login_error.hide()
        self.register_error.hide()

    _show_login = show_login_view
    _show_register = show_register_view

    # ── Password toggle ──────────────────────────────────────────────

    def _toggle_password_visibility(self) -> None:
        self._eye.toggle()
        mode = QLineEdit.Normal if self._eye.password_visible else QLineEdit.Password
        self.login_password.setEchoMode(mode)

    # ── Register live-validation ─────────────────────────────────────

    def _update_register_validation(self) -> None:
        pw = self.register_password.text()
        cf = self.register_confirm.text()
        parts: list[str] = []
        if pw and len(pw) < 12:
            parts.append(f"Password too short ({len(pw)}/12 characters)")
        elif pw:
            parts.append(f"Password length OK ({len(pw)} characters)")
        if cf and pw != cf:
            parts.append("Passwords do not match")
        elif cf and pw == cf:
            parts.append("Passwords match")
        color = "#FBBF24" if any("too short" in p or "do not match" in p for p in parts) \
            else ACCENT if parts else C_MUTED
        self.register_validation.setText("  ·  ".join(parts))
        self.register_validation.setStyleSheet(f"font-size:11px;color:{color};")

    # ── Input enable/disable ─────────────────────────────────────────

    def set_inputs_enabled(self, enabled: bool) -> None:
        for w in (self.login_identifier, self.login_password, self.login_totp,
                  self.login_btn, self.login_register_link,
                  self.register_username, self.register_email,
                  self.register_password, self.register_confirm,
                  self.register_btn, self.register_back_link):
            w.setEnabled(enabled)

    # ── Client ───────────────────────────────────────────────────────

    def _get_or_create_client(self) -> AccountClient:
        if self.account_client is None:
            self.account_client = AccountClient.from_env()
        return self.account_client

    def _submit(self, op: str, call, error_label=None) -> bool:
        try:
            client = self._get_or_create_client()
        except AccountAPIError as exc:
            if error_label is not None:
                error_label.setText(exc.message)
                error_label.show()
            return False
        self._worker.submit(op, lambda: call(client))
        return True

    # ── Login ────────────────────────────────────────────────────────

    def _on_login(self) -> None:
        identifier = self.login_identifier.text().strip()
        password = self.login_password.text()
        self.login_user_error.hide()
        self.login_pw_error.hide()
        self.login_error.hide()

        valid = True
        if not identifier:
            self.login_user_error.setText("Username or email is required.")
            self.login_user_error.show()
            valid = False
        if not password:
            self.login_pw_error.setText("Password is required.")
            self.login_pw_error.show()
            valid = False
        if not valid:
            return

        totp_code = self.login_totp.text().strip() or None
        if self.login_totp.isVisible() and not totp_code:
            self.login_error.setText("Enter the 6-digit code from your authenticator app.")
            self.login_error.show()
            return

        def login(client: AccountClient) -> dict:
            token, _user, expires_at = client.login(identifier, password, totp_code)
            return {"token": token, "user": client.get_me(token), "expires_at": expires_at}

        if self._submit("login", login, self.login_error):
            self.set_inputs_enabled(False)
            self.login_btn.setText("Signing in…")

    # ── Register ─────────────────────────────────────────────────────

    def _on_register(self) -> None:
        username = self.register_username.text().strip()
        email = self.register_email.text().strip()
        password = self.register_password.text()
        confirm = self.register_confirm.text()
        msg = ""
        if not username or not email or not password:
            msg = "All fields are required."
        elif len(password) < 12:
            msg = "Password must be at least 12 characters."
        elif len(password) > 1024:
            msg = "Password must be at most 1024 characters."
        elif password != confirm:
            msg = "Passwords do not match."
        self._set_register_message(msg)
        if msg:
            return
        if self._submit(
            "register", lambda client: client.register(username, email, password),
            self.register_error,
        ):
            self.set_inputs_enabled(False)
            self.register_btn.setText("Creating account…")

    def _set_register_message(self, text: str, *, success: bool = False) -> None:
        color = ACCENT if success else C_ERR
        self.register_error.setStyleSheet(f"font-size:12px;color:{color};font-weight:550;")
        self.register_error.setText(text)
        self.register_error.setVisible(bool(text))

    # ── Async result handler ─────────────────────────────────────────

    def _on_finished(self, op: str, ok: bool, data: object, message: str,
                     status_code: int, retry_after: int) -> None:
        if op == "login":
            self._login_finished(ok, data, message, status_code, retry_after)
        elif op == "register":
            self._register_finished(ok, data, message, status_code, retry_after)

    def _login_finished(self, ok, data, message, status_code, retry_after) -> None:
        self.set_inputs_enabled(True)
        self.login_btn.setText("Sign In")
        if ok and isinstance(data, dict):
            self.login_password.clear()
            self.login_totp.clear()
            self.login_totp_label.hide()
            self.login_totp.hide()
            self.session_token = data["token"]
            self.session_user = data["user"]
            self.session_expires_at = data.get("expires_at", "")
            self.login_succeeded.emit()
            return
        if isinstance(data, str) and data == "mfa_required":
            self.login_totp_label.show()
            self.login_totp.show()
            self.login_totp.setFocus()
            self.login_error.setText("Enter the 6-digit code from your authenticator app.")
            self.login_error.show()
            return
        if isinstance(data, str) and data == "account_locked":
            self.login_error.setText(message or _ACCOUNT_ERROR_MESSAGES["account_locked"])
            self.login_error.show()
            return
        self.login_password.clear()
        if retry_after > 0:
            self._start_cooldown(retry_after, is_login=True)
        self.login_error.setText(message or "Authentication failed.")
        self.login_error.show()

    def _register_finished(self, ok, data, message, status_code, retry_after) -> None:
        self.set_inputs_enabled(True)
        self.register_btn.setText("Create Account")
        if ok:
            username = data.get("username", "") if isinstance(data, dict) else ""
            for w in (self.register_password, self.register_confirm):
                w.clear()
            if username:
                self.login_identifier.setText(username)
            self._set_register_message(
                "Account created. Sign in to continue.", success=True,
            )
            QTimer.singleShot(1800, self._show_login)
            return
        if retry_after > 0:
            self._start_cooldown(retry_after, is_login=False)
        self._set_register_message(message or "Registration failed.")

    # ── Cooldown ─────────────────────────────────────────────────────

    def _start_cooldown(self, seconds: int, *, is_login: bool) -> None:
        self._cooldown_remaining = seconds
        self._cooldown_is_login = is_login
        self.set_inputs_enabled(False)
        lbl = self.login_cooldown_label if is_login else self.register_cooldown_label
        lbl.setText(f"Rate limited. Please wait {seconds} seconds…")
        lbl.show()
        self._cooldown_timer.start()

    def _tick_cooldown(self) -> None:
        self._cooldown_remaining -= 1
        lbl = self.login_cooldown_label if self._cooldown_is_login else self.register_cooldown_label
        if self._cooldown_remaining <= 0:
            self._cooldown_timer.stop()
            lbl.hide()
            self.set_inputs_enabled(True)
        else:
            lbl.setText(f"Rate limited. Please wait {self._cooldown_remaining} seconds…")

    # ── Cleanup ──────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:  # noqa: N802
        self._cooldown_timer.stop()
        self._worker.stop()
        super().closeEvent(event)
