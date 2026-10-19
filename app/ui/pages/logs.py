"""Logs page — bounded sanitized event display."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from app.client import sanitize_error
from app.ui.theme import COLORS, label


class LogsPage:
    def __init__(self, *, on_refresh, on_copy) -> None:
        self._on_refresh = on_refresh
        self._on_copy = on_copy

    def build(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 2, 0, 10)
        layout.setSpacing(12)
        actions = QHBoxLayout()
        self.logs_refresh_btn = QPushButton("Refresh")
        self.logs_refresh_btn.clicked.connect(self._on_refresh)
        self.logs_copy_btn = QPushButton("Copy")
        self.logs_copy_btn.clicked.connect(self._on_copy)
        actions.addWidget(self.logs_refresh_btn)
        actions.addWidget(self.logs_copy_btn)
        actions.addStretch(1)
        actions.addWidget(label("Maximum 300 service events", 9, COLORS["muted"]))
        layout.addLayout(actions)
        self.logs_view = QPlainTextEdit()
        self.logs_view.setReadOnly(True)
        self.logs_view.setPlaceholderText("No client service events reported.")
        self.logs_view.document().setMaximumBlockCount(300)
        layout.addWidget(self.logs_view, 1)
        return page

    def render(self, entries: list[dict], gui_events) -> None:
        safe_entries: list[dict[str, str]] = []
        for item in entries[-300:]:
            if not isinstance(item, dict):
                continue
            safe_entries.append({
                "timestamp": sanitize_error(item.get("timestamp", "—"), 48),
                "level": sanitize_error(item.get("level", "info"), 12).upper(),
                "message": sanitize_error(item.get("message", "")),
            })
        combined = safe_entries + list(gui_events)
        combined = combined[-300:]
        lines = [
            f"[{item.get('timestamp', '—')}] "
            f"{str(item.get('level', 'info')).upper():7} "
            f"{sanitize_error(item.get('message', ''))}"
            for item in combined
        ]
        self.logs_view.setPlainText("\n".join(lines))
