"""Detections panel view for Mini SOC."""

import csv
import json
from typing import Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.core.events import EventSeverity
from src.core.security import redact_sensitive_data, safe_json_dumps, spreadsheet_safe
from src.detection.rules import DetectionAlert
from src.ui.components.severity_badge import SeverityBadge, make_badge_cell_widget


class DetectionsView(QWidget):
    """View displaying rule-based detection alerts with triage actions, filtering, and inspector."""

    refresh_requested = Signal()
    create_incident_requested = Signal(object)  # emits DetectionAlert
    open_related_event_requested = Signal(str)   # emits event_id string
    review_state_changed = Signal(str, bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._all_alerts: list[DetectionAlert] = []
        self._filtered_alerts: list[DetectionAlert] = []
        self._reviewed_alert_keys: set[str] = set()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # 1. Top Controls Bar: Search, Filters, Review, Incident creation
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)

        # Search Bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search detection titles, descriptions, rules, or hosts...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.search_input, 2)

        # Severity Filter
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.severity_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.severity_filter)

        # Rule Name Filter
        self.rule_filter = QComboBox()
        self.rule_filter.addItem("All Rules")
        self.rule_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.rule_filter)

        # Review Status Filter
        self.status_filter = QComboBox()
        self.status_filter.addItems(["Active (Unreviewed)", "Reviewed", "All Alerts"])
        self.status_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.status_filter)

        # Export CSV Button
        self.export_btn = QPushButton("Export CSV")
        self.export_btn.clicked.connect(self._export_csv)
        controls_layout.addWidget(self.export_btn)

        layout.addLayout(controls_layout)

        # 2. Main Splitter: Detections Table (Left) + Detail & Action Inspector (Right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet("QSplitter::handle { background-color: #2e3b52; }")

        # Detections Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Detected Time (UTC)",
            "Severity",
            "Rule Name",
            "Source",
            "Status",
            "Alert Title",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        splitter.addWidget(self.table)

        # Details & Actions Inspector Pane
        self.details_frame = QFrame()
        self.details_frame.setObjectName("detailsPane")
        self.details_frame.setMinimumWidth(340)
        details_layout = QVBoxLayout(self.details_frame)
        details_layout.setContentsMargins(14, 14, 14, 14)
        details_layout.setSpacing(10)

        details_title = QLabel("Detection Inspector & Actions")
        details_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #f8fafc;")
        details_layout.addWidget(details_title)

        # Action Buttons Row
        actions_layout = QHBoxLayout()

        self.btn_mark_reviewed = QPushButton("Mark as Reviewed")
        self.btn_mark_reviewed.setEnabled(False)
        self.btn_mark_reviewed.clicked.connect(self._toggle_reviewed)
        actions_layout.addWidget(self.btn_mark_reviewed)

        self.btn_create_incident = QPushButton("Create Incident")
        self.btn_create_incident.setObjectName("primaryAction")
        self.btn_create_incident.setEnabled(False)
        self.btn_create_incident.clicked.connect(self._create_incident)
        actions_layout.addWidget(self.btn_create_incident)

        details_layout.addLayout(actions_layout)

        # Related Events Shortcut Row
        related_layout = QHBoxLayout()
        self.lbl_related_events = QLabel("Related Events: None")
        self.lbl_related_events.setStyleSheet("color: #94a3b8; font-size: 11px;")
        related_layout.addWidget(self.lbl_related_events)

        related_layout.addStretch()

        self.btn_open_event = QPushButton("Open Event")
        self.btn_open_event.setEnabled(False)
        self.btn_open_event.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        self.btn_open_event.clicked.connect(self._open_related_event)
        related_layout.addWidget(self.btn_open_event)

        details_layout.addLayout(related_layout)

        # Inspector Details View
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setPlaceholderText("Select a detection alert to inspect rule description, evidence, and attributes.")
        self.details_text.setStyleSheet("""
            QTextEdit {
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                background-color: #0f172a;
                border: 1px solid #2e3b52;
                border-radius: 6px;
                color: #e2e8f0;
            }
        """)
        details_layout.addWidget(self.details_text)

        splitter.addWidget(self.details_frame)
        splitter.setSizes([750, 350])

        layout.addWidget(splitter, 1)

        self.lbl_empty_state = QLabel()
        self.lbl_empty_state.setWordWrap(True)
        self.lbl_empty_state.setStyleSheet("color: #facc15; padding: 4px;")
        layout.addWidget(self.lbl_empty_state)

        # Status footer bar
        self.lbl_count = QLabel("Showing 0 detections")
        self.lbl_count.setStyleSheet("color: #94a3b8; font-size: 11px;")
        layout.addWidget(self.lbl_count)

    def set_alerts(
        self,
        alerts: Sequence[DetectionAlert],
        reviewed_alert_keys: Sequence[str] | None = None,
        empty_context: str = "",
    ) -> None:
        """Update the table with a new batch of detection alerts."""
        self._all_alerts = list(alerts)
        if reviewed_alert_keys is not None:
            self._reviewed_alert_keys = set(reviewed_alert_keys)
        self._empty_context = empty_context

        # Update available rule choices dynamically
        current_rule = self.rule_filter.currentText()
        rules = sorted({a.rule_name for a in self._all_alerts})
        self.rule_filter.blockSignals(True)
        self.rule_filter.clear()
        self.rule_filter.addItem("All Rules")
        for r in rules:
            self.rule_filter.addItem(r)
        self.rule_filter.setCurrentText(current_rule if current_rule in rules else "All Rules")
        self.rule_filter.blockSignals(False)

        self._apply_filters()

    def _alert_key(self, alert: DetectionAlert) -> str:
        """Construct a unique key for a detection alert."""
        return alert.alert_key

    def _apply_filters(self) -> None:
        """Filter detection alerts."""
        query = self.search_input.text().strip().lower()
        sev_choice = self.severity_filter.currentText()
        rule_choice = self.rule_filter.currentText()
        status_choice = self.status_filter.currentText()

        self._filtered_alerts = []
        for a in self._all_alerts:
            # Severity check
            if sev_choice != "All Severities" and a.severity.value != sev_choice:
                continue

            # Rule check
            if rule_choice != "All Rules" and a.rule_name != rule_choice:
                continue

            # Status check (Reviewed vs Unreviewed)
            is_reviewed = self._alert_key(a) in self._reviewed_alert_keys
            if status_choice == "Active (Unreviewed)" and is_reviewed:
                continue
            if status_choice == "Reviewed" and not is_reviewed:
                continue

            # Search text query
            if query:
                searchable = (
                    f"{a.title} {a.description} {a.rule_name} {a.source} "
                    f"{' '.join(a.related_event_ids)} {json.dumps(a.attributes)}"
                ).lower()
                if query not in searchable:
                    continue

            self._filtered_alerts.append(a)

        self._populate_table()

    def _populate_table(self) -> None:
        """Fill QTableWidget with filtered alerts."""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setRowCount(len(self._filtered_alerts))

        for row, alert in enumerate(self._filtered_alerts):
            time_str = alert.detected_at.strftime("%Y-%m-%d %H:%M:%S")
            time_item = QTableWidgetItem(time_str)
            time_item.setData(Qt.ItemDataRole.UserRole, alert.alert_key)
            self.table.setItem(row, 0, time_item)

            badge = SeverityBadge(alert.severity)
            self.table.setCellWidget(row, 1, make_badge_cell_widget(badge))

            self.table.setItem(row, 2, QTableWidgetItem(alert.rule_name))
            self.table.setItem(row, 3, QTableWidgetItem(alert.source))

            is_reviewed = self._alert_key(alert) in self._reviewed_alert_keys
            status_item = QTableWidgetItem("Reviewed" if is_reviewed else "Active")
            status_item.setForeground(Qt.GlobalColor.darkGray if is_reviewed else Qt.GlobalColor.cyan)
            self.table.setItem(row, 4, status_item)

            self.table.setItem(row, 5, QTableWidgetItem(alert.title))

        self.table.setSortingEnabled(True)
        self.lbl_count.setText(f"Showing {len(self._filtered_alerts):,} of {len(self._all_alerts):,} detections")
        if self._filtered_alerts:
            self.lbl_empty_state.clear()
        elif self._all_alerts:
            self.lbl_empty_state.setText(
                "No detections match the current filters. Clear search and filter selections."
            )
        else:
            self.lbl_empty_state.setText(
                self._empty_context or "No detections were produced from the current event set."
            )
        self.details_text.clear()
        self.btn_mark_reviewed.setEnabled(False)
        self.btn_create_incident.setEnabled(False)
        self.btn_open_event.setEnabled(False)

    def _get_selected_alert(self) -> DetectionAlert | None:
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        item = self.table.item(selected_rows[0].row(), 0)
        alert_key = item.data(Qt.ItemDataRole.UserRole) if item else None
        return next((alert for alert in self._filtered_alerts if alert.alert_key == alert_key), None)

    def _on_selection_changed(self) -> None:
        alert = self._get_selected_alert()
        if not alert:
            self.details_text.clear()
            self.btn_mark_reviewed.setEnabled(False)
            self.btn_create_incident.setEnabled(False)
            self.btn_open_event.setEnabled(False)
            self.lbl_related_events.setText("Related Events: None")
            return

        is_reviewed = self._alert_key(alert) in self._reviewed_alert_keys
        self.btn_mark_reviewed.setText("Mark as Active" if is_reviewed else "Mark as Reviewed")
        self.btn_mark_reviewed.setEnabled(True)
        self.btn_create_incident.setEnabled(True)

        if alert.related_event_ids:
            self.lbl_related_events.setText(f"Related Events: {len(alert.related_event_ids)} event(s)")
            self.btn_open_event.setEnabled(True)
        else:
            self.lbl_related_events.setText("Related Events: None")
            self.btn_open_event.setEnabled(False)

        details_dict = {
            "title": alert.title,
            "rule_name": alert.rule_name,
            "severity": alert.severity.value,
            "source": alert.source,
            "detected_at": alert.detected_at.isoformat(),
            "description": alert.description,
            "related_event_ids": alert.related_event_ids,
            "attributes": alert.attributes,
            "status": "Reviewed" if is_reviewed else "Active",
        }
        self.details_text.setPlainText(json.dumps(redact_sensitive_data(details_dict), indent=2))

    def _toggle_reviewed(self) -> None:
        alert = self._get_selected_alert()
        if not alert:
            return

        key = self._alert_key(alert)
        if key in self._reviewed_alert_keys:
            self._reviewed_alert_keys.remove(key)
        else:
            self._reviewed_alert_keys.add(key)

        self.review_state_changed.emit(key, key in self._reviewed_alert_keys)
        self._apply_filters()

    def _create_incident(self) -> None:
        alert = self._get_selected_alert()
        if alert:
            self.create_incident_requested.emit(alert)

    def _open_related_event(self) -> None:
        alert = self._get_selected_alert()
        if alert and alert.related_event_ids:
            self.open_related_event_requested.emit(alert.related_event_ids[0])

    def _export_csv(self) -> None:
        """Export current filtered detection alerts to CSV file."""
        if not self._filtered_alerts:
            QMessageBox.information(self, "Export CSV", "No detections to export.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Detections CSV", "mini_soc_detections.csv", "CSV Files (*.csv)")
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Rule Name", "Title", "Severity", "Source",
                    "Detected At (UTC)", "Status", "Description",
                    "Related Event IDs", "Attributes (JSON)"
                ])
                for a in self._filtered_alerts:
                    is_reviewed = self._alert_key(a) in self._reviewed_alert_keys
                    writer.writerow([spreadsheet_safe(value) if isinstance(value, str) else value for value in (
                        a.rule_name,
                        a.title,
                        a.severity.value,
                        a.source,
                        a.detected_at.isoformat(),
                        "Reviewed" if is_reviewed else "Active",
                        a.description,
                        ";".join(a.related_event_ids),
                        safe_json_dumps(a.attributes),
                    )])
            QMessageBox.information(self, "Export Successful", f"Exported {len(self._filtered_alerts)} detections to:\n{path}")
        except Exception as err:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSV: {err}")
