"""Metric status card component for summary dashboards."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


class StatusCard(QFrame):
    """Metric card displaying a title, prominent value, and contextual subtitle."""

    def __init__(
        self,
        title: str,
        value: str = "0",
        subtitle: str = "",
        accent_color: str = "#38bdf8",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("statusCard")
        self.accent_color = accent_color

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet("color: #94a3b8; font-size: 11px; font-weight: 600; letter-spacing: 0.5px;")

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {accent_color}; font-size: 24px; font-weight: bold;")

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setStyleSheet("color: #64748b; font-size: 11px;")

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)

    def set_value(self, value: str, subtitle: str | None = None) -> None:
        """Update the displayed metric value and optional subtitle."""
        self.value_label.setText(str(value))
        if subtitle is not None:
            self.subtitle_label.setText(subtitle)
