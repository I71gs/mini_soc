"""Incidents management and triage view for Mini SOC."""

import json
from typing import Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
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
from src.database.event_repository import EventRepository
from src.core.security import redact_sensitive_data
from src.incidents.manager import IncidentManager
from src.incidents.models import Incident
from src.ui.components.severity_badge import SeverityBadge, StatusBadge, make_badge_cell_widget


class IncidentsView(QWidget):
    """View managing security incident cases with lifecycle triage, status updates, and notes."""

    incident_updated = Signal()
    open_related_event_requested = Signal(str)  # emits event_id
    PAGE_SIZE = 100

    def __init__(
        self,
        incident_manager: IncidentManager,
        parent: QWidget | None = None,
        event_repository: EventRepository | None = None,
    ) -> None:
        super().__init__(parent)
        self.incident_manager = incident_manager
        self.event_repository = event_repository
        self._filtered_incidents: list[Incident] = []
        self.page_index = 0
        self._page_count = 1
        self._page_incident_count = 0
        self._total_incident_count = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # 1. Top Controls Bar: Search, Status Filter, Severity Filter
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)

        # Search Bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search incident titles, descriptions, notes, or IDs...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.search_input, 2)

        # Status Filter
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", "Open", "Investigating", "Mitigated", "Resolved"])
        self.status_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.status_filter)

        # Severity Filter
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.severity_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.severity_filter)

        layout.addLayout(controls_layout)

        paging_layout = QHBoxLayout()
        self.previous_page_btn = QPushButton("Previous Page")
        self.previous_page_btn.clicked.connect(lambda: self._set_page(self.page_index - 1))
        paging_layout.addWidget(self.previous_page_btn)
        self.page_label = QLabel("Page 1 of 1")
        paging_layout.addWidget(self.page_label)
        self.next_page_btn = QPushButton("Next Page")
        self.next_page_btn.clicked.connect(lambda: self._set_page(self.page_index + 1))
        paging_layout.addWidget(self.next_page_btn)
        paging_layout.addStretch()
        layout.addLayout(paging_layout)

        # 2. Main Splitter: Incident Cases Table (Left) + Case Triage Pane (Right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet("QSplitter::handle { background-color: #2e3b52; }")

        # Incidents Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Created Time (UTC)",
            "Severity",
            "Status",
            "Source",
            "Title",
            "Incident ID",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        splitter.addWidget(self.table)

        # Triage Details Pane
        self.details_frame = QFrame()
        self.details_frame.setObjectName("detailsPane")
        self.details_frame.setMinimumWidth(360)
        details_layout = QVBoxLayout(self.details_frame)
        details_layout.setContentsMargins(14, 14, 14, 14)
        details_layout.setSpacing(10)

        details_title = QLabel("Incident Triage & Actions")
        details_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #f8fafc;")
        details_layout.addWidget(details_title)

        # Status Update Controls Row
        status_action_layout = QHBoxLayout()
        status_action_layout.addWidget(QLabel("Update Status:"))

        self.combo_update_status = QComboBox()
        self.combo_update_status.addItems(["open", "investigating", "mitigated", "resolved"])
        self.combo_update_status.setEnabled(False)
        status_action_layout.addWidget(self.combo_update_status)

        self.btn_apply_status = QPushButton("Save")
        self.btn_apply_status.setEnabled(False)
        self.btn_apply_status.clicked.connect(self._update_status)
        status_action_layout.addWidget(self.btn_apply_status)

        self.btn_mark_resolved = QPushButton("Mark Resolved")
        self.btn_mark_resolved.setEnabled(False)
        self.btn_mark_resolved.setStyleSheet("""
            QPushButton {
                background-color: #065f46;
                color: #ecfdf5;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #047857;
            }
        """)
        self.btn_mark_resolved.clicked.connect(self._mark_resolved)
        status_action_layout.addWidget(self.btn_mark_resolved)

        details_layout.addLayout(status_action_layout)

        # Analyst Notes Row
        notes_action_layout = QHBoxLayout()
        self.btn_add_note = QPushButton("+ Add Analyst Note")
        self.btn_add_note.setEnabled(False)
        self.btn_add_note.clicked.connect(self._add_note)
        notes_action_layout.addWidget(self.btn_add_note)

        notes_action_layout.addStretch()

        self.btn_open_event = QPushButton("Open Related Event")
        self.btn_open_event.setEnabled(False)
        self.btn_open_event.clicked.connect(self._open_related_event)
        notes_action_layout.addWidget(self.btn_open_event)

        details_layout.addLayout(notes_action_layout)

        # Inspector Details View
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setPlaceholderText("Select an incident to view summary, evidence, rule metadata, and analyst notes.")
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
        splitter.setSizes([700, 400])

        layout.addWidget(splitter, 1)

        # Status footer bar
        self.lbl_count = QLabel("Showing 0 incidents")
        self.lbl_count.setStyleSheet("color: #94a3b8; font-size: 11px;")
        layout.addWidget(self.lbl_count)

    def refresh(self) -> None:
        """Reload incidents from manager."""
        self._apply_filters()

    def _set_page(self, page_index: int) -> None:
        if 0 <= page_index < self._page_count and page_index != self.page_index:
            self.page_index = page_index
            self.refresh()

    def _apply_filters(self) -> None:
        """Filter incidents list."""
        query = self.search_input.text().strip().lower()
        status_choice = self.status_filter.currentText().lower()
        sev_choice = self.severity_filter.currentText()

        total_incidents = self.incident_manager.count_incidents()
        self._page_count = max(
            1,
            (total_incidents + self.PAGE_SIZE - 1) // self.PAGE_SIZE,
        )
        self.page_index = min(self.page_index, self._page_count - 1)
        all_incidents = self.incident_manager.hydrate_from_repository(
            limit=self.PAGE_SIZE,
            offset=self.page_index * self.PAGE_SIZE,
        )
        self._page_incident_count = len(all_incidents)
        self._total_incident_count = total_incidents
        self.page_label.setText(f"Page {self.page_index + 1} of {self._page_count}")
        self.previous_page_btn.setEnabled(self.page_index > 0)
        self.next_page_btn.setEnabled(self.page_index + 1 < self._page_count)
        self._filtered_incidents = []

        for inc in all_incidents:
            # Status check
            if status_choice != "all statuses" and inc.status.lower() != status_choice:
                continue

            # Severity check
            if sev_choice != "All Severities" and inc.severity.value != sev_choice:
                continue

            # Search text query
            if query:
                searchable = (
                    f"{inc.title} {inc.description} {inc.incident_id} {inc.source} "
                    f"{' '.join(inc.notes)} {json.dumps(inc.attributes)}"
                ).lower()
                if query not in searchable:
                    continue

            self._filtered_incidents.append(inc)

        self._populate_table()

    def _populate_table(self) -> None:
        """Fill QTableWidget with filtered incidents."""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setRowCount(len(self._filtered_incidents))

        for row, inc in enumerate(self._filtered_incidents):
            time_str = inc.created_at.strftime("%Y-%m-%d %H:%M:%S")
            created_item = QTableWidgetItem(time_str)
            created_item.setData(Qt.ItemDataRole.UserRole, inc.incident_id)
            self.table.setItem(row, 0, created_item)

            badge_sev = SeverityBadge(inc.severity)
            self.table.setCellWidget(row, 1, make_badge_cell_widget(badge_sev))

            badge_status = StatusBadge(inc.status)
            self.table.setCellWidget(row, 2, make_badge_cell_widget(badge_status))

            self.table.setItem(row, 3, QTableWidgetItem(inc.source))
            self.table.setItem(row, 4, QTableWidgetItem(inc.title))
            self.table.setItem(row, 5, QTableWidgetItem(inc.incident_id[:8] + "..."))

        self.table.setSortingEnabled(True)
        self.lbl_count.setText(
            f"Showing {len(self._filtered_incidents):,} of {self._page_incident_count:,} incidents on this page "
            f"({self.page_index * self.PAGE_SIZE + 1 if self._page_incident_count else 0:,}-"
            f"{self.page_index * self.PAGE_SIZE + self._page_incident_count:,} of "
            f"{self._total_incident_count:,} total)"
        )
        self.details_text.clear()
        self.combo_update_status.setEnabled(False)
        self.btn_apply_status.setEnabled(False)
        self.btn_mark_resolved.setEnabled(False)
        self.btn_add_note.setEnabled(False)
        self.btn_open_event.setEnabled(False)

    def _get_selected_incident(self) -> Incident | None:
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        item = self.table.item(selected_rows[0].row(), 0)
        incident_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        return next(
            (incident for incident in self._filtered_incidents if incident.incident_id == incident_id),
            None,
        )

    def _on_selection_changed(self) -> None:
        inc = self._get_selected_incident()
        if not inc:
            self.details_text.clear()
            self.combo_update_status.setEnabled(False)
            self.btn_apply_status.setEnabled(False)
            self.btn_mark_resolved.setEnabled(False)
            self.btn_add_note.setEnabled(False)
            self.btn_open_event.setEnabled(False)
            return

        self.combo_update_status.setEnabled(True)
        self.btn_apply_status.setEnabled(True)
        self.btn_mark_resolved.setEnabled(inc.status != "resolved")
        self.btn_add_note.setEnabled(True)
        self.btn_open_event.setEnabled(bool(inc.related_event_ids))

        # Select current status in combo
        idx = self.combo_update_status.findText(inc.status.lower())
        if idx >= 0:
            self.combo_update_status.setCurrentIndex(idx)

        # Build formatted presentation
        details_dict = {
            "incident_id": inc.incident_id,
            "alert_key": inc.alert_key,
            "title": inc.title,
            "status": inc.status.upper(),
            "severity": inc.severity.value,
            "created_at": inc.created_at.isoformat(),
            "source": inc.source,
            "description": inc.description,
            "rule_metadata": inc.attributes,
            "related_events": inc.related_event_ids,
            "investigation_timeline": self._get_investigation_timeline(inc),
            "analyst_notes": inc.notes if inc.notes else ["(No notes added yet)"],
        }
        self.details_text.setPlainText(json.dumps(redact_sensitive_data(details_dict), indent=2))

    def _get_investigation_timeline(self, incident: Incident) -> list[dict[str, str]]:
        """Resolve retained evidence events into a chronological incident timeline."""
        if self.event_repository is None:
            return [
                {"event_id": event_id, "status": "Timeline repository unavailable"}
                for event_id in incident.related_event_ids
            ]

        timeline: list[dict[str, str]] = []
        for event_id in incident.related_event_ids:
            event = self.event_repository.get_event(event_id)
            if event is None:
                timeline.append({"event_id": event_id, "status": "Evidence event not retained"})
            else:
                timeline.append(
                    {
                        "event_id": event_id,
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type,
                        "severity": event.severity.value,
                        "description": event.description,
                    }
                )
        return sorted(timeline, key=lambda item: item.get("timestamp", ""))

    def _update_status(self) -> None:
        inc = self._get_selected_incident()
        if not inc:
            return
        new_status = self.combo_update_status.currentText().lower()
        self.incident_manager.update_status(inc.incident_id, new_status)
        self._apply_filters()
        self.incident_updated.emit()

    def _mark_resolved(self) -> None:
        inc = self._get_selected_incident()
        if not inc:
            return
        self.incident_manager.update_status(inc.incident_id, "resolved")
        self._apply_filters()
        self.incident_updated.emit()

    def _add_note(self) -> None:
        inc = self._get_selected_incident()
        if not inc:
            return

        note, ok = QInputDialog.getText(
            self,
            "Add Analyst Note",
            f"Add note for Incident '{inc.title}':",
        )
        if ok and note.strip():
            self.incident_manager.add_note(inc.incident_id, note.strip())
            self._apply_filters()
            self._on_selection_changed()
            self.incident_updated.emit()

    def _open_related_event(self) -> None:
        inc = self._get_selected_incident()
        if inc and inc.related_event_ids:
            self.open_related_event_requested.emit(inc.related_event_ids[0])
