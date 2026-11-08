"""Colored badge widgets for severity levels and incident statuses."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QWidget, QHBoxLayout

from src.core.events import EventSeverity
from src.ui.styles import SEVERITY_COLORS, STATUS_COLORS


class SeverityBadge(QLabel):
    """Pill badge showing event/alert severity with distinct color-coding."""

    def __init__(self, severity: EventSeverity | str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_severity(severity)

    def set_severity(self, severity: EventSeverity | str) -> None:
        if isinstance(severity, str):
            try:
                severity = EventSeverity(severity.upper())
            except ValueError:
                severity = EventSeverity.INFO

        color_spec = SEVERITY_COLORS.get(severity, SEVERITY_COLORS[EventSeverity.INFO])
        self.setText(severity.value)
        self.setStyleSheet(f"""
            QLabel {{
                color: {color_spec["text"]};
                background-color: {color_spec["bg"]};
                border: 1px solid {color_spec["border"]};
                border-radius: 4px;
                padding: 2px 8px;
                font-weight: 600;
                font-size: 11px;
                min-width: 60px;
                max-height: 20px;
            }}
        """)


class StatusBadge(QLabel):
    """Pill badge showing incident status with color-coding."""

    def __init__(self, status: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_status(status)

    def set_status(self, status: str) -> None:
        status_key = status.lower()
        color_spec = STATUS_COLORS.get(
            status_key,
            {"text": "#94a3b8", "bg": "rgba(148, 163, 184, 0.15)", "border": "#64748b"},
        )
        self.setText(status.upper())
        self.setStyleSheet(f"""
            QLabel {{
                color: {color_spec["text"]};
                background-color: {color_spec["bg"]};
                border: 1px solid {color_spec["border"]};
                border-radius: 4px;
                padding: 2px 8px;
                font-weight: 600;
                font-size: 11px;
                min-width: 70px;
                max-height: 20px;
            }}
        """)


def make_badge_cell_widget(badge: QWidget) -> QWidget:
    """Wrap a badge in a centered container suitable for QTableWidget cellWidget."""
    wrapper = QWidget()
    layout = QHBoxLayout(wrapper)
    layout.setContentsMargins(4, 2, 4, 2)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(badge)
    return wrapper
