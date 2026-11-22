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
        self.lbl_storage_notice = QLabel(
            f"Events older than {config.retention_days} days are removed at startup. "
            "The database and logs are not encrypted; protect this folder with Windows ACLs. "
            "Exports are saved separately and are not covered by database cleanup."
        )
        self.lbl_storage_notice.setWordWrap(True)
        self.lbl_storage_notice.setStyleSheet("color: #facc15; font-size: 11px;")
        paths_layout.addRow("Storage handling:", self.lbl_storage_notice)

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
            ("Process Collector", "Process Collector (psutil)", "Tracks new process starts and command lines"),
            ("Network Collector", "Network Collector (psutil)", "Enumerates active sockets and associated PIDs"),
            ("Windows Event Log", "Windows Event Collector (pywin32)", "Captures Security & System events"),
            ("Detection Engine", "Detection Engine", "Evaluates the configured built-in rules"),
        ]
        self.collector_status_labels: dict[str, QLabel] = {}
        self.collector_description_labels: dict[str, QLabel] = {}
        self.collector_descriptions: dict[str, str] = {}

        for key, name, desc in sensors:
            row = QHBoxLayout()
            lbl_name = QLabel(f"<b>{name}</b>")
            lbl_status = QLabel("NOT POLLED")
            lbl_status.setStyleSheet("color: #4ade80; background-color: rgba(74, 222, 128, 0.15); border: 1px solid #22c55e; border-radius: 4px; padding: 2px 8px; font-size: 10px; font-weight: bold;")
            self.collector_status_labels[key] = lbl_status
            lbl_desc = QLabel(f"— {desc}")
            lbl_desc.setStyleSheet("color: #94a3b8; font-size: 11px;")
            lbl_desc.setWordWrap(True)
            self.collector_description_labels[key] = lbl_desc
            self.collector_descriptions[key] = desc

            row.addWidget(lbl_name)
            row.addWidget(lbl_status)
            row.addWidget(lbl_desc)
            row.addStretch()
            sensor_layout.addLayout(row)

        layout.addWidget(sensor_box)
        layout.addStretch()

    def update_diagnostics(
        self,
        total_events: int,
        checkpoints: dict[str, int],
        collector_health: dict[str, dict[str, str | int | None]] | None = None,
    ) -> None:
        """Update live statistics."""
        self.lbl_total_records.setText(f"{total_events:,} events persisted in SQLite")
        if checkpoints:
            chk_str = ", ".join(f"{ch}: #{rec_id}" for ch, rec_id in checkpoints.items())
            self.lbl_checkpoints.setText(chk_str)
        else:
            self.lbl_checkpoints.setText("No checkpoints recorded yet")

        for key, label in self.collector_status_labels.items():
            health = (collector_health or {}).get(key)
            status = str(health.get("status", "not polled")) if health else "not polled"
            limitations = str(health.get("visibility_limitations") or "") if health else ""
            label.setText(
                f"{status.upper()} · LIMITED"
                if status == "healthy" and limitations else status.upper()
            )
            if status == "healthy":
                color = "#facc15" if limitations else "#4ade80"
            elif status == "not polled":
                color = "#94a3b8"
            else:
                color = "#facc15"
            label.setStyleSheet(
                f"color: {color}; border: 1px solid {color}; border-radius: 4px; "
                "padding: 2px 8px; font-size: 10px; font-weight: bold;"
            )
            if health:
                error = health.get("last_error")
                last_success = health.get("last_success_at")
                details = [
                    f"Last successful collection: {last_success or 'never'}",
                    f"Latest collection error or restriction: {error}" if error else None,
                    f"Known visibility limitations: {limitations}" if limitations else None,
                ]
                label.setToolTip("\n".join(detail for detail in details if detail))
                description = self.collector_descriptions[key]
                if limitations:
                    description += f"\nKnown limitations: {limitations}"
                description += f"\nLast successful collection: {last_success or 'never'}"
                if error:
                    description += f"\nLatest error/restriction: {error}"
                self.collector_description_labels[key].setText(f"— {description}")
            else:
                self.collector_description_labels[key].setText(
                    f"— {self.collector_descriptions[key]}\nLast successful collection: never"
                )
