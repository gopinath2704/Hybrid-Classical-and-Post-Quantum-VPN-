"""Logs page — bounded, sanitized, filterable event display."""
from __future__ import annotations

import re

from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from app.client import sanitize_error
from app.ui.theme import COLORS, label

LEVEL_FILTERS = {"All levels": None, "Info": "INFO", "Warnings": "WARNING", "Errors": "ERROR"}

_SECRET_PATTERNS = (
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [redacted]"),
    (re.compile(r"(?i)\b([\w-]*(?:token|secret|password|passwd|psk|api[_-]?key|session[_-]?key"
                r"|private[_ -]?key|otp|totp|cookie|authorization|credential)s?)"
                r"(\s*[:=]\s*)\S+"), r"\1\2[redacted]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[redacted-jwt]"),
    (re.compile(r"otpauth://\S+"), "[redacted-otpauth]"),
)


def redact_secrets(text: str) -> str:
    """Second redaction pass on top of sanitize_error for secret-looking values."""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def normalize_level(level: object) -> str:
    value = sanitize_error(level, 12).upper()
    return "WARNING" if value == "WARN" else value


def format_entries(entries: list[dict[str, str]], level: str | None, query: str) -> list[str]:
    needle = query.strip().lower()
    lines: list[str] = []
    for item in entries:
        item_level = normalize_level(item.get("level", "info"))
        if level is not None and item_level != level:
            continue
        line = redact_secrets(
            f"[{sanitize_error(item.get('timestamp', '—'), 48)}] {item_level:7} "
            f"{sanitize_error(item.get('message', ''))}"
        )
        if needle and needle not in line.lower():
            continue
        lines.append(line)
    return lines


class LogsPage:
    def __init__(self, *, on_refresh, on_copy, on_export) -> None:
        self._on_refresh = on_refresh
        self._on_copy = on_copy
        self._on_export = on_export
        self._entries: list[dict[str, str]] = []

    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(12)
        actions = QHBoxLayout()
        self.logs_level_filter = QComboBox()
        self.logs_level_filter.addItems(list(LEVEL_FILTERS))
        self.logs_level_filter.setAccessibleName("Filter by level")
        self.logs_level_filter.currentIndexChanged.connect(self._refilter)
        self.logs_search = QLineEdit()
        self.logs_search.setPlaceholderText("Search events")
        self.logs_search.setAccessibleName("Search events")
        self.logs_search.setClearButtonEnabled(True)
        self.logs_search.textChanged.connect(self._refilter)
        self.logs_refresh_btn = QPushButton("Refresh")
        self.logs_refresh_btn.clicked.connect(self._on_refresh)
        self.logs_copy_btn = QPushButton("Copy")
        self.logs_copy_btn.setToolTip("Copy the visible, redacted events")
        self.logs_copy_btn.clicked.connect(self._on_copy)
        self.logs_export_btn = QPushButton("Export…")
        self.logs_export_btn.setToolTip("Save the visible, redacted events to a file")
        self.logs_export_btn.clicked.connect(self._on_export)
        actions.addWidget(self.logs_level_filter)
        actions.addWidget(self.logs_search, 1)
        for btn in (self.logs_refresh_btn, self.logs_copy_btn, self.logs_export_btn):
            actions.addWidget(btn)
        layout.addLayout(actions)
        layout.addWidget(label(
            "Maximum 300 service events · secrets are redacted · auto-scroll pauses "
            "while you scroll up", 9, COLORS["muted"]))
        self.logs_view = QPlainTextEdit()
        self.logs_view.setReadOnly(True)
        self.logs_view.setPlaceholderText("No client service events reported.")
        self.logs_view.setAccessibleName("Client service events")
        self.logs_view.document().setMaximumBlockCount(300)
        layout.addWidget(self.logs_view, 1)
        return page

    def render(self, entries: list[dict], gui_events) -> None:
        service = [item for item in entries[-300:] if isinstance(item, dict)]
        self._entries = (service + list(gui_events))[-300:]
        self._refilter()

    def visible_text(self) -> str:
        return self.logs_view.toPlainText()

    def _refilter(self) -> None:
        level = LEVEL_FILTERS[self.logs_level_filter.currentText()]
        text = "\n".join(format_entries(self._entries, level, self.logs_search.text()))
        if text == self.logs_view.toPlainText():
            return
        bar = self.logs_view.verticalScrollBar()
        follow = bar.value() >= bar.maximum() - 2
        position = bar.value()
        self.logs_view.setPlainText(text)
        bar.setValue(bar.maximum() if follow else min(position, bar.maximum()))
