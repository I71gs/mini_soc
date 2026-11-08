"""Automated UI tests for the Mini SOC PySide6 desktop interface.

Tests run in offscreen mode (QT_QPA_PLATFORM=offscreen) so they do not
require a visible display server and can execute in headless CI environments.
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

# Force offscreen rendering before any Qt import
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

from src.core.config import AppConfig
from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.incident_repository import IncidentRepository
from src.database.checkpoint_repository import CheckpointRepository
from src.database.schema import initialize_database
from src.detection.rules import DetectionAlert, DetectionEngine, default_detection_engine
from src.incidents.manager import IncidentManager
from src.incidents.models import Incident


# ────────────────────────────────────────────────────────────────────────────
# Fixtures
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def qapp():
    """Provide a single QApplication instance shared across the entire test session."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


@pytest.fixture()
def tmp_db(tmp_path: Path) -> DatabaseManager:
    """Create a temporary SQLite database for UI tests."""
    db_path = tmp_path / "test_ui.db"
    db_manager = DatabaseManager(db_path)
    initialize_database(db_manager)
    return db_manager


@pytest.fixture()
def sample_events() -> list[SecurityEvent]:
    """Produce a small batch of representative SecurityEvent objects."""
    now = datetime.now(timezone.utc)
    return [
        SecurityEvent(
            source="process_monitor",
            category=EventCategory.PROCESS,
            event_type="process_start",
            severity=EventSeverity.INFO,
            description="python.exe started",
            host="TESTHOST",
            attributes={"pid": 1234, "name": "python.exe"},
            timestamp=now - timedelta(minutes=5),
        ),
        SecurityEvent(
            source="network_monitor",
            category=EventCategory.NETWORK,
            event_type="connection_established",
            severity=EventSeverity.MEDIUM,
            description="Outbound connection to 192.168.1.100:8080",
            host="TESTHOST",
            attributes={"remote_ip": "192.168.1.100", "remote_port": 8080},
            timestamp=now - timedelta(minutes=3),
        ),
        SecurityEvent(
            source="windows_event_log",
            category=EventCategory.AUTHENTICATION,
            event_type="logon_failure",
            severity=EventSeverity.HIGH,
            description="Failed logon attempt for user admin",
            host="TESTHOST",
            attributes={"event_id": 4625, "user": "admin"},
            timestamp=now - timedelta(minutes=1),
        ),
    ]


@pytest.fixture()
def sample_alerts(sample_events: list[SecurityEvent]) -> list[DetectionAlert]:
    """Generate detection alerts matching the sample events."""
    return [
        DetectionAlert(
            rule_name="risky_outbound_port",
            title="Outbound connection on suspicious port 8080",
            description="A connection was made on a high-risk port.",
            severity=EventSeverity.MEDIUM,
            source="network_monitor",
            related_event_ids=[str(sample_events[1].event_id)],
            attributes={"remote_port": 8080},
        ),
        DetectionAlert(
            rule_name="failed_logon_spike",
            title="Repeated logon failures detected",
            description="Multiple failed logon events observed.",
            severity=EventSeverity.HIGH,
            source="windows_event_log",
            related_event_ids=[str(sample_events[2].event_id)],
            attributes={"event_id": 4625},
        ),
    ]


# ────────────────────────────────────────────────────────────────────────────
# Component Tests
# ────────────────────────────────────────────────────────────────────────────

class TestSeverityBadge:
    """Tests for the SeverityBadge widget."""

    def test_badge_from_enum(self, qapp: QApplication) -> None:
        from src.ui.components.severity_badge import SeverityBadge

        badge = SeverityBadge(EventSeverity.CRITICAL)
        assert badge.text() == "CRITICAL"

    def test_badge_from_string(self, qapp: QApplication) -> None:
        from src.ui.components.severity_badge import SeverityBadge

        badge = SeverityBadge("high")
        assert badge.text() == "HIGH"

    def test_badge_invalid_string_defaults_to_info(self, qapp: QApplication) -> None:
        from src.ui.components.severity_badge import SeverityBadge

        badge = SeverityBadge("nonexistent")
        assert badge.text() == "INFO"


class TestStatusBadge:
    """Tests for the StatusBadge widget."""

    def test_status_badge_text(self, qapp: QApplication) -> None:
        from src.ui.components.severity_badge import StatusBadge

        badge = StatusBadge("investigating")
        assert badge.text() == "INVESTIGATING"


class TestStatusCard:
    """Tests for the StatusCard widget."""

    def test_card_initial_value(self, qapp: QApplication) -> None:
        from src.ui.components.status_card import StatusCard

        card = StatusCard("Total Events", "42", "In database")
        assert card.value_label.text() == "42"
        assert card.title_label.text() == "TOTAL EVENTS"

    def test_card_set_value(self, qapp: QApplication) -> None:
        from src.ui.components.status_card import StatusCard

        card = StatusCard("Alerts", "0")
        card.set_value("7", "New alerts")
        assert card.value_label.text() == "7"
        assert card.subtitle_label.text() == "New alerts"


# ────────────────────────────────────────────────────────────────────────────
# View Tests
# ────────────────────────────────────────────────────────────────────────────

class TestOverviewView:
    """Tests for the OverviewView dashboard widget."""

    def test_overview_instantiation(self, qapp: QApplication) -> None:
        from src.ui.views.overview_view import OverviewView

        view = OverviewView()
        assert view is not None
        assert view.card_events.value_label.text() == "0"

    def test_overview_update_data(
        self, qapp: QApplication, sample_events: list[SecurityEvent], sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.overview_view import OverviewView

        view = OverviewView()
        incidents = [
            Incident(
                incident_id=str(uuid4()),
                title="Test Incident",
                description="Testing",
                severity=EventSeverity.HIGH,
                status="open",
            )
        ]
        view.update_data(
            total_events=100,
            events=sample_events,
            alerts=sample_alerts,
            incidents=incidents,
            last_collection_time="12:30:00",
        )
        assert view.card_events.value_label.text() == "100"
        assert view.card_detections.value_label.text() == "2"
        assert view.card_incidents.value_label.text() == "1"
        assert view.activity_table.rowCount() == len(sample_events)
        assert view.detections_table.rowCount() == len(sample_alerts)

    def test_overview_timeframe_default(self, qapp: QApplication) -> None:
        from src.ui.views.overview_view import OverviewView

        view = OverviewView()
        tf = view.get_selected_timeframe()
        assert tf == timedelta(hours=24)

    def test_overview_timeframe_all(self, qapp: QApplication) -> None:
        from src.ui.views.overview_view import OverviewView

        view = OverviewView()
        view.timeframe_combo.setCurrentText("All Time")
        tf = view.get_selected_timeframe()
        assert tf is None

    def test_overview_empty_data(self, qapp: QApplication) -> None:
        from src.ui.views.overview_view import OverviewView

        view = OverviewView()
        view.update_data(
            total_events=0, events=[], alerts=[], incidents=[], last_collection_time="Never"
        )
        assert view.card_events.value_label.text() == "0"
        assert view.activity_table.rowCount() == 0
        assert view.card_health.value_label.text() == "Normal"


class TestEventsView:
    """Tests for the EventsView telemetry browser."""

    def test_events_view_instantiation(self, qapp: QApplication) -> None:
        from src.ui.views.events_view import EventsView

        view = EventsView()
        assert view is not None
        assert view.table.rowCount() == 0

    def test_events_view_set_events(
        self, qapp: QApplication, sample_events: list[SecurityEvent]
    ) -> None:
        from src.ui.views.events_view import EventsView

        view = EventsView()
        view.set_events(sample_events)
        assert view.table.rowCount() == len(sample_events)
        assert "3" in view.lbl_count.text()

    def test_events_view_filter_by_severity(
        self, qapp: QApplication, sample_events: list[SecurityEvent]
    ) -> None:
        from src.ui.views.events_view import EventsView

        view = EventsView()
        view.set_events(sample_events)
        view.severity_filter.setCurrentText("HIGH")
        # Only the logon_failure event is HIGH
        assert view.table.rowCount() == 1

    def test_events_view_text_search(
        self, qapp: QApplication, sample_events: list[SecurityEvent]
    ) -> None:
        from src.ui.views.events_view import EventsView

        view = EventsView()
        view.set_events(sample_events)
        view.search_input.setText("python.exe")
        assert view.table.rowCount() == 1

    def test_events_view_filter_by_source(
        self, qapp: QApplication, sample_events: list[SecurityEvent]
    ) -> None:
        from src.ui.views.events_view import EventsView

        view = EventsView()
        view.set_events(sample_events)
        view.source_filter.setCurrentText("network_monitor")
        assert view.table.rowCount() == 1

    def test_events_view_filter_by_category(
        self, qapp: QApplication, sample_events: list[SecurityEvent]
    ) -> None:
        from src.ui.views.events_view import EventsView

        view = EventsView()
        view.set_events(sample_events)
        view.category_filter.setCurrentText("authentication")
        assert view.table.rowCount() == 1

    def test_events_view_empty_export(self, qapp: QApplication) -> None:
        """Export with no events should not crash."""
        from src.ui.views.events_view import EventsView

        view = EventsView()
        # Patch QMessageBox to avoid blocking dialog
        with patch("src.ui.views.events_view.QMessageBox") as mock_msg:
            view._export_csv()
            mock_msg.information.assert_called_once()


class TestDetectionsView:
    """Tests for the DetectionsView panel."""

    def test_detections_view_instantiation(self, qapp: QApplication) -> None:
        from src.ui.views.detections_view import DetectionsView

        view = DetectionsView()
        assert view is not None

    def test_detections_view_set_alerts(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.detections_view import DetectionsView

        view = DetectionsView()
        view.set_alerts(sample_alerts)
        assert view.table.rowCount() == len(sample_alerts)

    def test_detections_view_filter_severity(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.detections_view import DetectionsView

        view = DetectionsView()
        view.set_alerts(sample_alerts)
        view.severity_filter.setCurrentText("HIGH")
        assert view.table.rowCount() == 1

    def test_detections_view_filter_rule(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.detections_view import DetectionsView

        view = DetectionsView()
        view.set_alerts(sample_alerts)
        view.rule_filter.setCurrentText("risky_outbound_port")
        assert view.table.rowCount() == 1

    def test_detections_view_mark_reviewed(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.detections_view import DetectionsView

        view = DetectionsView()
        view.set_alerts(sample_alerts)

        # Select first row
        view.table.selectRow(0)

        # Mark as reviewed
        view._toggle_reviewed()

        # Default filter is "Active (Unreviewed)", so reviewed alert is hidden
        assert view.table.rowCount() == 1

        # Switch to show all
        view.status_filter.setCurrentText("All Alerts")
        assert view.table.rowCount() == 2

    def test_detections_view_empty_export(self, qapp: QApplication) -> None:
        from src.ui.views.detections_view import DetectionsView

        view = DetectionsView()
        with patch("src.ui.views.detections_view.QMessageBox") as mock_msg:
            view._export_csv()
            mock_msg.information.assert_called_once()


class TestIncidentsView:
    """Tests for the IncidentsView management panel."""

    def test_incidents_view_instantiation(self, qapp: QApplication) -> None:
        from src.ui.views.incidents_view import IncidentsView

        manager = IncidentManager()
        view = IncidentsView(manager)
        assert view is not None

    def test_incidents_view_populated(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.incidents_view import IncidentsView

        manager = IncidentManager()
        manager.create_from_alerts(sample_alerts)
        view = IncidentsView(manager)
        view.refresh()
        assert view.table.rowCount() == 2

    def test_incidents_view_filter_status(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.incidents_view import IncidentsView

        manager = IncidentManager()
        incidents = manager.create_from_alerts(sample_alerts)
        manager.update_status(incidents[0].incident_id, "resolved")

        view = IncidentsView(manager)
        view.refresh()
        view.status_filter.setCurrentText("Open")
        assert view.table.rowCount() == 1

    def test_incidents_view_update_status(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.incidents_view import IncidentsView

        manager = IncidentManager()
        incidents = manager.create_from_alerts(sample_alerts)
        view = IncidentsView(manager)
        view.refresh()

        # Select first row
        view.table.selectRow(0)

        # Update status to investigating
        view.combo_update_status.setCurrentText("investigating")
        view._update_status()

        assert incidents[0].status == "investigating"

    def test_incidents_view_mark_resolved(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.incidents_view import IncidentsView

        manager = IncidentManager()
        incidents = manager.create_from_alerts(sample_alerts)
        view = IncidentsView(manager)
        view.refresh()

        # Select first row
        view.table.selectRow(0)
        view._mark_resolved()

        assert incidents[0].status == "resolved"

    def test_incidents_view_add_note(
        self, qapp: QApplication, sample_alerts: list[DetectionAlert]
    ) -> None:
        from src.ui.views.incidents_view import IncidentsView

        manager = IncidentManager()
        incidents = manager.create_from_alerts(sample_alerts)
        view = IncidentsView(manager)
        view.refresh()

        # Select first row
        view.table.selectRow(0)

        # Patch QInputDialog to simulate user entering a note
        with patch("src.ui.views.incidents_view.QInputDialog.getText", return_value=("Test analyst note", True)):
            view._add_note()

        assert "Test analyst note" in incidents[0].notes


class TestSettingsView:
    """Tests for the SettingsView diagnostics panel."""

    def test_settings_view_instantiation(self, qapp: QApplication) -> None:
        from src.ui.views.settings_view import SettingsView

        config = AppConfig()
        view = SettingsView(config)
        assert view is not None

    def test_settings_view_update_diagnostics(self, qapp: QApplication) -> None:
        from src.ui.views.settings_view import SettingsView

        config = AppConfig()
        view = SettingsView(config)
        view.update_diagnostics(total_events=123, checkpoints={"Security": 5000, "System": 3000})
        assert "123" in view.lbl_total_records.text()
        assert "Security" in view.lbl_checkpoints.text()


# ────────────────────────────────────────────────────────────────────────────
# MainWindow Integration Tests
# ────────────────────────────────────────────────────────────────────────────

class TestMainWindow:
    """Integration tests for the main application window shell."""

    def test_main_window_instantiation(self, qapp: QApplication, tmp_db: DatabaseManager) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)
        assert window is not None
        assert window.windowTitle() == "Mini SOC — Security Operations Console"

    def test_main_window_sidebar_navigation(self, qapp: QApplication, tmp_db: DatabaseManager) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)

        # Default view is Overview (index 0)
        assert window.stack.currentIndex() == 0

        # Navigate to Events
        window._on_navigation_clicked(1)
        assert window.stack.currentIndex() == 1

        # Navigate to Detections
        window._on_navigation_clicked(2)
        assert window.stack.currentIndex() == 2

        # Navigate to Incidents
        window._on_navigation_clicked(3)
        assert window.stack.currentIndex() == 3

        # Navigate to Settings
        window._on_navigation_clicked(4)
        assert window.stack.currentIndex() == 4

        # Back to Overview
        window._on_navigation_clicked(0)
        assert window.stack.currentIndex() == 0

    def test_main_window_refresh_data(self, qapp: QApplication, tmp_db: DatabaseManager) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)

        # Refresh without collectors should not crash
        window.refresh_all_data(run_collectors=False)
        assert window.lbl_header_sync.text().startswith("Last Sync:")

    def test_main_window_refresh_with_collectors(
        self, qapp: QApplication, tmp_db: DatabaseManager
    ) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)

        # Mock collectors to avoid real system calls
        window.host_monitor.collect_once = MagicMock(return_value=[])
        window.win_collector.collect_events = MagicMock(return_value=[])

        window.refresh_all_data(run_collectors=True)
        window.host_monitor.collect_once.assert_called_once()
        window.win_collector.collect_events.assert_called_once()

    def test_main_window_navigate_to_event(
        self, qapp: QApplication, tmp_db: DatabaseManager
    ) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)

        test_event_id = str(uuid4())
        window._navigate_to_event(test_event_id)

        # Should switch to Events view (index 1)
        assert window.stack.currentIndex() == 1
        assert window.events_view.search_input.text() == test_event_id

    def test_main_window_create_incident_from_alert(
        self, qapp: QApplication, tmp_db: DatabaseManager
    ) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)

        alert = DetectionAlert(
            rule_name="test_rule",
            title="Test Alert",
            description="Test description",
            severity=EventSeverity.HIGH,
            source="test_source",
            related_event_ids=[str(uuid4())],
        )
        window._create_incident_from_alert(alert)

        # Should switch to Incidents view (index 3)
        assert window.stack.currentIndex() == 3
        assert len(window.incident_manager.incidents) == 1
        assert window.incident_manager.incidents[0].title == "Test Alert"

    def test_main_window_header_sync_updates(
        self, qapp: QApplication, tmp_db: DatabaseManager
    ) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)

        window.refresh_all_data(run_collectors=False)
        # After refresh the sync timestamp should be set (not "Never")
        assert "Never" not in window.lbl_header_sync.text()

    def test_main_window_minimum_size(self, qapp: QApplication, tmp_db: DatabaseManager) -> None:
        from src.ui.main_window import MainWindow

        config = AppConfig()
        window = MainWindow(config=config, db_manager=tmp_db)
        min_size = window.minimumSize()
        assert min_size.width() >= 1000
        assert min_size.height() >= 650
