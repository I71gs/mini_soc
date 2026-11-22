"""Events telemetry browser view for Mini SOC."""

import csv
import json
from typing import Sequence

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
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

from src.core.events import EventSeverity, SecurityEvent
from src.core.security import redact_sensitive_data, safe_json_dumps, spreadsheet_safe
from src.ui.components.severity_badge import SeverityBadge, make_badge_cell_widget


class EventsView(QWidget):
    """Telemetry browser displaying collected security events with filtering, sorting, and inspector."""

    refresh_requested = Signal()
    page_changed = Signal(int)
    PAGE_SIZE = 100

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._all_events: list[SecurityEvent] = []
        self._filtered_events: list[SecurityEvent] = []
        self.page_index = 0
        self._page_count = 1

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # 1. Top Controls Bar: Search, Filters, Export, Refresh
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(10)

        # Search Bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search descriptions, hosts, types, or attributes...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.search_input, 2)

        # Severity Filter
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.severity_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.severity_filter)

        # Source Filter
        self.source_filter = QComboBox()
        self.source_filter.addItem("All Sources")
        self.source_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.source_filter)

        # Category Filter
        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.category_filter.currentTextChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.category_filter)

        # Export CSV Button
        self.export_btn = QPushButton("Export CSV")
        self.export_btn.clicked.connect(self._export_csv)
        controls_layout.addWidget(self.export_btn)

        # Refresh Button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                border: 1px solid #38bdf8;
                color: #38bdf8;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #38bdf8;
                color: #0f172a;
            }
        """)
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        controls_layout.addWidget(self.refresh_btn)

        layout.addLayout(controls_layout)

        paging_layout = QHBoxLayout()
        self.previous_page_btn = QPushButton("Previous Page")
        self.previous_page_btn.clicked.connect(lambda: self._request_page(self.page_index - 1))
        paging_layout.addWidget(self.previous_page_btn)
        self.page_label = QLabel("Page 1 of 1")
        paging_layout.addWidget(self.page_label)
        self.next_page_btn = QPushButton("Next Page")
        self.next_page_btn.clicked.connect(lambda: self._request_page(self.page_index + 1))
        paging_layout.addWidget(self.next_page_btn)
        paging_layout.addStretch()
        layout.addLayout(paging_layout)

        # 2. Main Splitter: Events Table (Left) + Event Inspector Pane (Right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet("QSplitter::handle { background-color: #2e3b52; }")

        # Events Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Timestamp (UTC)",
            "Severity",
            "Category",
            "Source",
            "Event Type",
            "Host",
            "Description",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        splitter.addWidget(self.table)

        # Details Inspector Pane
        self.details_frame = QFrame()
        self.details_frame.setObjectName("detailsPane")
        self.details_frame.setMinimumWidth(320)
        details_layout = QVBoxLayout(self.details_frame)
        details_layout.setContentsMargins(12, 12, 12, 12)
        details_layout.setSpacing(10)

        details_header_layout = QHBoxLayout()
        details_title = QLabel("Event Inspector")
        details_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #f8fafc;")
        details_header_layout.addWidget(details_title)

        details_header_layout.addStretch()

        self.copy_btn = QPushButton("Copy JSON")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self._copy_details)
        details_header_layout.addWidget(self.copy_btn)

        details_layout.addLayout(details_header_layout)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setPlaceholderText("Select an event from the table to inspect full metadata and attributes.")
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
        self.lbl_count = QLabel("Showing 0 events")
        self.lbl_count.setStyleSheet("color: #94a3b8; font-size: 11px;")
        layout.addWidget(self.lbl_count)

    def set_events(
        self,
        events: Sequence[SecurityEvent],
        total_event_count: int | None = None,
        matching_event_count: int | None = None,
        page_index: int = 0,
    ) -> None:
        """Update the table with a new batch of security events."""
        self._all_events = list(events)
        self._total_event_count = total_event_count
        self._matching_event_count = matching_event_count
        self.page_index = page_index
        page_count = max(
            1,
            (matching_event_count + self.PAGE_SIZE - 1) // self.PAGE_SIZE
            if matching_event_count is not None else 1,
        )
        self._page_count = page_count
        self.page_label.setText(f"Page {self.page_index + 1} of {self._page_count}")
        self.previous_page_btn.setEnabled(self.page_index > 0)
        self.next_page_btn.setEnabled(self.page_index + 1 < self._page_count)

        # Update available filter choices dynamically
        current_source = self.source_filter.currentText()
        current_cat = self.category_filter.currentText()

        sources = sorted({e.source for e in self._all_events})
        self.source_filter.blockSignals(True)
        self.source_filter.clear()
        self.source_filter.addItem("All Sources")
        for s in sources:
            self.source_filter.addItem(s)
        self.source_filter.setCurrentText(current_source if current_source in sources else "All Sources")
        self.source_filter.blockSignals(False)

        categories = sorted({str(e.category.value if hasattr(e.category, 'value') else e.category).lower() for e in self._all_events})
        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItem("All Categories")
        for c in categories:
            self.category_filter.addItem(c)
        self.category_filter.setCurrentText(current_cat.lower() if current_cat.lower() in categories else "All Categories")
        self.category_filter.blockSignals(False)

        self._apply_filters()

    def _request_page(self, page_index: int) -> None:
        if 0 <= page_index < self._page_count and page_index != self.page_index:
            self.page_changed.emit(page_index)

    def _apply_filters(self) -> None:
        """Filter the events list based on search text, severity, source, and category."""
        query = self.search_input.text().strip().lower()
        sev_choice = self.severity_filter.currentText()
        source_choice = self.source_filter.currentText()
        cat_choice = self.category_filter.currentText()

        self._filtered_events = []
        for e in self._all_events:
            # Severity check
            if sev_choice != "All Severities" and e.severity.value != sev_choice:
                continue

            # Source check
            if source_choice != "All Sources" and e.source != source_choice:
                continue

            # Category check
            cat_str = str(e.category.value if hasattr(e.category, 'value') else e.category).lower()
            if cat_choice != "All Categories" and cat_str != cat_choice.lower():
                continue

            # Search text query
            if query:
                searchable = (
                    f"{e.event_id} {e.description} {e.host} {e.event_type} {e.source} "
                    f"{json.dumps(e.attributes)}"
                ).lower()
                if query not in searchable:
                    continue

            self._filtered_events.append(e)

        self._populate_table()

    def _populate_table(self) -> None:
        """Fill QTableWidget with filtered events."""
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setRowCount(len(self._filtered_events))

        for row, evt in enumerate(self._filtered_events):
            time_str = evt.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            timestamp_item = QTableWidgetItem(time_str)
            timestamp_item.setData(Qt.ItemDataRole.UserRole, str(evt.event_id))
            self.table.setItem(row, 0, timestamp_item)

            badge = SeverityBadge(evt.severity)
            self.table.setCellWidget(row, 1, make_badge_cell_widget(badge))

            cat_str = str(evt.category.value if hasattr(evt.category, 'value') else evt.category)
            self.table.setItem(row, 2, QTableWidgetItem(cat_str))
            self.table.setItem(row, 3, QTableWidgetItem(evt.source))
            self.table.setItem(row, 4, QTableWidgetItem(evt.event_type))
            self.table.setItem(row, 5, QTableWidgetItem(evt.host))
            self.table.setItem(row, 6, QTableWidgetItem(evt.description))

        self.table.setSortingEnabled(True)
        matching_count = self._matching_event_count
        if matching_count is None:
            matching_count = len(self._all_events)
        total_count = self._total_event_count
        if total_count is None:
            total_count = len(self._all_events)
        first_event = self.page_index * self.PAGE_SIZE + 1 if self._all_events else 0
        last_event = self.page_index * self.PAGE_SIZE + len(self._all_events)
        self.lbl_count.setText(
            f"Showing {len(self._filtered_events):,} of {len(self._all_events):,} on this page "
            f"({first_event:,}-{last_event:,} of {matching_count:,} in timeframe; "
            f"{total_count:,} stored)"
        )
        if self._filtered_events:
            self.lbl_empty_state.clear()
        elif total_count == 0:
            self.lbl_empty_state.setText(
                "No telemetry has been observed or stored yet; this does not mean there was no activity. "
                "Process and network collectors suppress startup snapshots, may miss activity between polls, "
                "and can be restricted by Windows permissions. Select Poll Sensors, then check Settings "
                "for collector health and access errors."
            )
        elif matching_count == 0:
            self.lbl_empty_state.setText(
                f"No events are in the selected timeframe. {total_count:,} older stored event(s) "
                "may be available; change the Overview timeframe to All Time. No events in this timeframe "
                "does not establish that no activity occurred."
            )
        else:
            if not self._all_events:
                self.lbl_empty_state.setText(
                    "No events are on this page. Use the paging controls or change the Overview timeframe."
                )
            else:
                self.lbl_empty_state.setText(
                    "No events on this page match the current search and filters. Clear filters or browse another page."
                )
        self.details_text.clear()
        self.copy_btn.setEnabled(False)

    def _on_selection_changed(self) -> None:
        """Handle row selection to show event details."""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            self.details_text.clear()
            self.copy_btn.setEnabled(False)
            return

        item = self.table.item(selected_rows[0].row(), 0)
        event_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        event = next(
            (candidate for candidate in self._filtered_events if str(candidate.event_id) == event_id),
            None,
        )
        if event is not None:
            formatted_json = json.dumps(
                redact_sensitive_data(event.model_dump(mode="json")),
                indent=2,
            )
            self.details_text.setPlainText(formatted_json)
            self.copy_btn.setEnabled(True)

    def _copy_details(self) -> None:
        """Copy selected event JSON to system clipboard."""
        text = self.details_text.toPlainText()
        if text:
            clipboard = QGuiApplication.clipboard()
            clipboard.setText(text)
            self.copy_btn.setText("Copied!")
            from PySide6.QtCore import QTimer
            QTimer.singleShot(1500, lambda: self.copy_btn.setText("Copy JSON"))

    def _export_csv(self) -> None:
        """Export current filtered events to CSV file."""
        if not self._filtered_events:
            QMessageBox.information(self, "Export CSV", "No events to export.")
            return

        path, _ = QFileDialog.getSaveFileName(self, "Export Events CSV", "mini_soc_events.csv", "CSV Files (*.csv)")
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Event ID", "Timestamp (UTC)", "Severity", "Category",
                    "Source", "Event Type", "Host", "Description", "Attributes (JSON)"
                ])
                for e in self._filtered_events:
                    writer.writerow([spreadsheet_safe(value) if isinstance(value, str) else value for value in (
                        str(e.event_id),
                        e.timestamp.isoformat(),
                        e.severity.value,
                        str(e.category.value if hasattr(e.category, 'value') else e.category),
                        e.source,
                        e.event_type,
                        e.host,
                        e.description,
                        safe_json_dumps(e.attributes),
                    )])
            QMessageBox.information(self, "Export Successful", f"Exported {len(self._filtered_events)} events to:\n{path}")
        except Exception as err:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSV: {err}")
