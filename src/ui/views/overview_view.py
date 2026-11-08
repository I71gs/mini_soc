"""Overview page dashboard view for Mini SOC."""

from datetime import datetime, timezone, timedelta
import platform
import socket
from typing import Callable, Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.core.events import EventSeverity, SecurityEvent
from src.detection.rules import DetectionAlert
from src.incidents.models import Incident
from src.ui.components.severity_badge import SeverityBadge, make_badge_cell_widget
from src.ui.components.status_card import StatusCard


class OverviewView(QWidget):
    """Analyst overview dashboard presenting high-level SOC metrics, recent activity, and host health."""

    refresh_requested = Signal()
    view_events_requested = Signal()
    view_detections_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # 1. Top Controls Bar: Title, Timeframe Filter, Refresh
        controls_layout = QHBoxLayout()

        header_title = QLabel("System Security Overview")
        header_title.setStyleSheet("font-size: 18px; font-weight: 700; color: #f8fafc;")
        controls_layout.addWidget(header_title)

        controls_layout.addStretch()

        filter_label = QLabel("Timeframe:")
        filter_label.setStyleSheet("color: #94a3b8; font-weight: 500;")
        controls_layout.addWidget(filter_label)

        self.timeframe_combo = QComboBox()
        self.timeframe_combo.addItems(["1 Hour", "24 Hours", "7 Days", "All Time"])
        self.timeframe_combo.setCurrentText("24 Hours")
        self.timeframe_combo.currentIndexChanged.connect(self._on_timeframe_changed)
        controls_layout.addWidget(self.timeframe_combo)

        self.refresh_btn = QPushButton("Refresh Now")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #38bdf8;
                color: #0f172a;
                font-weight: 600;
                padding: 6px 14px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #0284c7;
                color: #ffffff;
            }
        """)
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        controls_layout.addWidget(self.refresh_btn)

        main_layout.addLayout(controls_layout)

        # 2. Metric Status Cards Grid
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(14)

        self.card_events = StatusCard("Total Events", "0", "Persisted in SQLite database", "#38bdf8")
        self.card_detections = StatusCard("Suspicious Detections", "0", "Triggered by detection engine", "#fb923c")
        self.card_incidents = StatusCard("Open Incidents", "0", "Requiring analyst triage", "#f87171")
        self.card_health = StatusCard("System Health", "Normal", "Sensors active and collecting", "#4ade80")

        cards_layout.addWidget(self.card_events)
        cards_layout.addWidget(self.card_detections)
        cards_layout.addWidget(self.card_incidents)
        cards_layout.addWidget(self.card_health)

        main_layout.addLayout(cards_layout)

        # 3. Host Summary Card
        host_frame = QFrame()
        host_frame.setStyleSheet("""
            QFrame {
                background-color: #131b2e;
                border: 1px solid #2e3b52;
                border-radius: 8px;
                padding: 10px 14px;
            }
        """)
        host_layout = QHBoxLayout(host_frame)
        host_layout.setContentsMargins(10, 8, 10, 8)

        self.lbl_hostname = QLabel(f"Host: <b>{socket.gethostname()}</b>")
        self.lbl_os = QLabel(f"OS: <b>{platform.system()} {platform.release()}</b>")
        self.lbl_python = QLabel(f"Environment: <b>Python {platform.python_version()}</b>")
        self.lbl_last_sync = QLabel("Last Collection: <b>Just now</b>")

        for lbl in (self.lbl_hostname, self.lbl_os, self.lbl_python, self.lbl_last_sync):
            lbl.setStyleSheet("color: #cbd5e1; font-size: 12px;")
            host_layout.addWidget(lbl)
            if lbl != self.lbl_last_sync:
                host_layout.addStretch()

        main_layout.addWidget(host_frame)

        # 4. Activity and Detections Panels (Split 50/50)
        panels_layout = QHBoxLayout()
        panels_layout.setSpacing(14)

        # Left: Recent Activity
        activity_box = QGroupBox("Recent Telemetry Activity")
        activity_box.setStyleSheet("""
            QGroupBox {
                background-color: #131b2e;
                border: 1px solid #2e3b52;
                border-radius: 8px;
                margin-top: 10px;
                font-weight: 600;
                color: #e2e8f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
            }
        """)
        activity_layout = QVBoxLayout(activity_box)
        activity_layout.setContentsMargins(10, 14, 10, 10)

        self.activity_table = QTableWidget(0, 4)
        self.activity_table.setHorizontalHeaderLabels(["Timestamp (UTC)", "Type", "Severity", "Description"])
        self.activity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.activity_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.activity_table.verticalHeader().setVisible(False)
        self.activity_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        activity_layout.addWidget(self.activity_table)

        panels_layout.addWidget(activity_box, 1)

        # Right: Recent Detections
        detections_box = QGroupBox("Recent Suspicious Detections")
        detections_box.setStyleSheet(activity_box.styleSheet())
        detections_layout = QVBoxLayout(detections_box)
        detections_layout.setContentsMargins(10, 14, 10, 10)

        self.detections_table = QTableWidget(0, 4)
        self.detections_table.setHorizontalHeaderLabels(["Detected Time", "Rule", "Severity", "Title"])
        self.detections_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.detections_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.detections_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.detections_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.detections_table.verticalHeader().setVisible(False)
        self.detections_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        detections_layout.addWidget(self.detections_table)

        panels_layout.addWidget(detections_box, 1)

        main_layout.addLayout(panels_layout, 1)

    def _on_timeframe_changed(self) -> None:
        self.refresh_requested.emit()

    def get_selected_timeframe(self) -> timedelta | None:
        """Return the timedelta representing selected timeframe or None for all."""
        text = self.timeframe_combo.currentText()
        if text == "1 Hour":
            return timedelta(hours=1)
        elif text == "24 Hours":
            return timedelta(hours=24)
        elif text == "7 Days":
            return timedelta(days=7)
        return None

    def update_data(
        self,
        total_events: int,
        events: Sequence[SecurityEvent],
        alerts: Sequence[DetectionAlert],
        incidents: Sequence[Incident],
        last_collection_time: str,
    ) -> None:
        """Update metrics, host info, recent activity table, and recent detections table."""
        self.card_events.set_value(f"{total_events:,}", f"Displaying {len(events)} loaded")
        self.card_detections.set_value(str(len(alerts)), "Evaluated by detection engine")
        open_count = sum(1 for i in incidents if i.status == "open")
        self.card_incidents.set_value(str(open_count), f"{len(incidents)} total incidents")

        if len(alerts) > 5 or open_count > 2:
            self.card_health.set_value("Attention", "Multiple security alerts flagged", )
            self.card_health.value_label.setStyleSheet("color: #f87171; font-size: 24px; font-weight: bold;")
        else:
            self.card_health.set_value("Normal", "No critical alerts observed")
            self.card_health.value_label.setStyleSheet("color: #4ade80; font-size: 24px; font-weight: bold;")

        self.lbl_last_sync.setText(f"Last Collection: <b>{last_collection_time}</b>")

        # Populate Recent Activity Table (top 15)
        self.activity_table.setRowCount(0)
        recent_events = events[:15]
        self.activity_table.setRowCount(len(recent_events))
        for row, evt in enumerate(recent_events):
            time_str = evt.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            self.activity_table.setItem(row, 0, QTableWidgetItem(time_str))
            self.activity_table.setItem(row, 1, QTableWidgetItem(evt.event_type))

            badge = SeverityBadge(evt.severity)
            self.activity_table.setCellWidget(row, 2, make_badge_cell_widget(badge))

            self.activity_table.setItem(row, 3, QTableWidgetItem(evt.description))

        # Populate Recent Detections Table (top 15)
        self.detections_table.setRowCount(0)
        recent_alerts = alerts[:15]
        self.detections_table.setRowCount(len(recent_alerts))
        for row, alert in enumerate(recent_alerts):
            time_str = alert.detected_at.strftime("%Y-%m-%d %H:%M:%S")
            self.detections_table.setItem(row, 0, QTableWidgetItem(time_str))
            self.detections_table.setItem(row, 1, QTableWidgetItem(alert.rule_name))

            badge = SeverityBadge(alert.severity)
            self.detections_table.setCellWidget(row, 2, make_badge_cell_widget(badge))

            self.detections_table.setItem(row, 3, QTableWidgetItem(alert.title))
