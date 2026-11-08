"""Settings and system diagnostics view for Mini SOC."""

import platform
import socket

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from src.core.config import AppConfig
from src.database.checkpoint_repository import CheckpointRepository
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.schema import CURRENT_SCHEMA_VERSION, get_current_schema_version


class SettingsView(QWidget):
    """Settings, path configurations, and system health status view."""

    def __init__(self, config: AppConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.config = config

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        title = QLabel("Application Settings & Diagnostics")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        layout.addWidget(title)

        # 1. Environment & Paths Box
        paths_box = QGroupBox("Environment & Storage Configuration")
        paths_box.setStyleSheet("""
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
        paths_layout = QFormLayout(paths_box)
        paths_layout.setContentsMargins(16, 16, 16, 16)
        paths_layout.setSpacing(10)

        def make_value_lbl(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setStyleSheet("color: #38bdf8; font-family: monospace; font-size: 12px;")
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            return lbl

        paths_layout.addRow("Application Name:", QLabel(f"{config.app_name} (v{config.version})"))
        paths_layout.addRow("Project Root:", make_value_lbl(str(config.project_root)))
        paths_layout.addRow("Data Directory:", make_value_lbl(str(config.data_dir)))
        paths_layout.addRow("SQLite Database:", make_value_lbl(str(config.database_path)))
        paths_layout.addRow("Log Directory:", make_value_lbl(str(config.log_dir)))
        paths_layout.addRow("Host System:", QLabel(f"{socket.gethostname()} ({platform.system()} {platform.release()})"))

        layout.addWidget(paths_box)

        # 2. Database & Checkpoints Diagnostics Box
        db_box = QGroupBox("Database Health & Checkpoints")
        db_box.setStyleSheet(paths_box.styleSheet())
        self.db_layout = QFormLayout(db_box)
        self.db_layout.setContentsMargins(16, 16, 16, 16)
        self.db_layout.setSpacing(10)

        self.lbl_schema_version = QLabel(f"Schema Version: v{CURRENT_SCHEMA_VERSION}")
        self.lbl_total_records = QLabel("0 events recorded")
        self.lbl_checkpoints = QLabel("None")
        self.lbl_checkpoints.setStyleSheet("color: #facc15; font-family: monospace;")

        self.db_layout.addRow("Schema Status:", self.lbl_schema_version)
        self.db_layout.addRow("Total Event Count:", self.lbl_total_records)
        self.db_layout.addRow("Event Log Checkpoints:", self.lbl_checkpoints)

        layout.addWidget(db_box)

        # 3. Telemetry Sensor Status Box
        sensor_box = QGroupBox("Active Telemetry Collectors")
        sensor_box.setStyleSheet(paths_box.styleSheet())
        sensor_layout = QVBoxLayout(sensor_box)
        sensor_layout.setContentsMargins(16, 16, 16, 16)
        sensor_layout.setSpacing(8)

        sensors = [
            ("Process Collector (psutil)", "Enabled", "Enumerates running processes, tracks PID + create_time"),
            ("Network Collector (psutil)", "Enabled", "Enumerates active sockets, TCP/UDP endpoints and PIDs"),
            ("Windows Event Collector (pywin32)", "Enabled", "Captures Security & System logs (IDs 4624, 4625, 1102, 7045)"),
            ("Detection Engine", "Enabled", "3 built-in rules: suspicious process, failed logon spike, risky network"),
        ]

        for name, status, desc in sensors:
            row = QHBoxLayout()
            lbl_name = QLabel(f"<b>{name}</b>")
            lbl_status = QLabel(status.upper())
            lbl_status.setStyleSheet("color: #4ade80; background-color: rgba(74, 222, 128, 0.15); border: 1px solid #22c55e; border-radius: 4px; padding: 2px 8px; font-size: 10px; font-weight: bold;")
            lbl_desc = QLabel(f"— {desc}")
            lbl_desc.setStyleSheet("color: #94a3b8; font-size: 11px;")

            row.addWidget(lbl_name)
            row.addWidget(lbl_status)
            row.addWidget(lbl_desc)
            row.addStretch()
            sensor_layout.addLayout(row)

        layout.addWidget(sensor_box)
        layout.addStretch()

    def update_diagnostics(self, total_events: int, checkpoints: dict[str, int]) -> None:
        """Update live statistics."""
        self.lbl_total_records.setText(f"{total_events:,} events persisted in SQLite")
        if checkpoints:
            chk_str = ", ".join(f"{ch}: #{rec_id}" for ch, rec_id in checkpoints.items())
            self.lbl_checkpoints.setText(chk_str)
        else:
            self.lbl_checkpoints.setText("No checkpoints recorded yet")
