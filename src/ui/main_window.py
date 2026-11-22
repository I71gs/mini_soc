"""Main dashboard window and navigation shell for Mini SOC."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Sequence

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent, QIcon
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from src.collectors.monitor_service import HostMonitorService
from src.collectors.windows_event_collector import WindowsEventCollector
from src.core.config import AppConfig
from src.core.events import SecurityEvent
from src.database.alert_state_repository import AlertStateRepository
from src.database.checkpoint_repository import CheckpointRepository
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.incident_repository import IncidentRepository
from src.detection.rules import DetectionAlert, DetectionEngine, default_detection_engine
from src.incidents.manager import IncidentManager
from src.ui.styles import GLOBAL_STYLESHEET
from src.ui.views.detections_view import DetectionsView
from src.ui.views.events_view import EventsView
from src.ui.views.incidents_view import IncidentsView
from src.ui.views.overview_view import OverviewView
from src.ui.views.settings_view import SettingsView

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Primary application window for the Mini SOC security console."""

    def __init__(
        self,
        config: AppConfig | None = None,
        db_manager: DatabaseManager | None = None,
        event_repo: EventRepository | None = None,
        checkpoint_repo: CheckpointRepository | None = None,
        detection_engine: DetectionEngine | None = None,
        incident_manager: IncidentManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Mini SOC — Security Operations Console")
        self.resize(1260, 840)
        self.setMinimumSize(1000, 650)
        self.setStyleSheet(GLOBAL_STYLESHEET)

        # 1. Backend Wiring
        self.config = config or AppConfig()
        self.db_manager = db_manager or DatabaseManager(self.config.database_path)
        self.event_repo = event_repo or EventRepository(self.db_manager)
        self.checkpoint_repo = checkpoint_repo or CheckpointRepository(self.db_manager)
        self.alert_state_repo = AlertStateRepository(self.db_manager)
        self.incident_repo = IncidentRepository(self.db_manager)
        self.detection_engine = detection_engine or default_detection_engine()
        self.incident_manager = incident_manager or IncidentManager(repository=self.incident_repo)

        self.win_collector = WindowsEventCollector(
            repository=self.event_repo,
            checkpoint_repo=self.checkpoint_repo,
        )
        self.host_monitor = HostMonitorService(
            repository=self.event_repo,
            windows_event_collector=self.win_collector,
        )
        self.host_monitor.initialize_baselines()

        self._cached_events: list[SecurityEvent] = []
        self._cached_alerts: list[DetectionAlert] = []
        self._last_sync_time: str = "Never"
        self._active_timeframe: str | None = None
        self.event_repo.delete_events_before(
            datetime.now(timezone.utc) - timedelta(days=self.config.retention_days)
        )

        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(30000)
        self.refresh_timer.timeout.connect(lambda: self.refresh_all_data(run_collectors=False))

        # 2. Central Layout Construction
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Header Bar
        header = self._build_header_bar()
        root_layout.addWidget(header)

        # Body (Sidebar + Content Stack)
        body_layout = QHBoxLayout()
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Sidebar Navigation
        sidebar = self._build_sidebar()
        body_layout.addWidget(sidebar)

        # Stacked Views Content Area
        self.stack = QStackedWidget()

        self.overview_view = OverviewView()
        self.events_view = EventsView()
        self.detections_view = DetectionsView()
        self.incidents_view = IncidentsView(
            self.incident_manager,
            event_repository=self.event_repo,
        )
        self.settings_view = SettingsView(self.config)

        self.stack.addWidget(self.overview_view)    # index 0: Overview
        self.stack.addWidget(self.events_view)      # index 1: Events
        self.stack.addWidget(self.detections_view)  # index 2: Detections
        self.stack.addWidget(self.incidents_view)   # index 3: Incidents
        self.stack.addWidget(self.settings_view)    # index 4: Settings

        body_layout.addWidget(self.stack, 1)
        root_layout.addLayout(body_layout, 1)

        # 3. Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet("background-color: #090d16; color: #64748b; font-size: 11px;")
        self.status_bar.showMessage("Ready. Local-first Windows Mini SOC initialized.")

        # 4. Signals and View Interactions
        self._connect_signals()

        self.refresh_timer.start()

        # Initial data load
        self.refresh_all_data(run_collectors=False)

    def _build_header_bar(self) -> QWidget:
        """Create the top header bar with branding, status indicator, and sync timestamp."""
        header = QFrame()
        header.setObjectName("headerBar")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 10, 18, 10)
        layout.setSpacing(14)

        # Brand / App Title
        brand_layout = QHBoxLayout()
        brand_layout.setSpacing(8)

        logo_indicator = QLabel("●")
        logo_indicator.setStyleSheet("color: #38bdf8; font-size: 18px;")
        brand_layout.addWidget(logo_indicator)

        brand_title = QLabel("MINI SOC")
        brand_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #f8fafc; letter-spacing: 1px;")
        brand_layout.addWidget(brand_title)

        version_badge = QLabel("LOCAL-FIRST")
        version_badge.setStyleSheet("color: #38bdf8; background-color: rgba(56, 189, 248, 0.15); border: 1px solid #0284c7; border-radius: 4px; padding: 1px 6px; font-size: 10px; font-weight: bold;")
        brand_layout.addWidget(version_badge)

        layout.addLayout(brand_layout)
        layout.addStretch()

        # Live Status Indicator
        status_box = QHBoxLayout()
        status_box.setSpacing(6)
        status_dot = QLabel("●")
        status_dot.setStyleSheet("color: #4ade80; font-size: 12px;")
        self.status_text = QLabel("HOST SENSORS ACTIVE")
        self.status_text.setStyleSheet("color: #cbd5e1; font-size: 11px; font-weight: 600;")
        status_box.addWidget(status_dot)
        status_box.addWidget(self.status_text)
        layout.addLayout(status_box)

        # Separator line
        sep = QLabel("|")
        sep.setStyleSheet("color: #334155; font-size: 14px;")
        layout.addWidget(sep)

        # Last Sync Label
        self.lbl_header_sync = QLabel("Last Sync: Never")
        self.lbl_header_sync.setStyleSheet("color: #94a3b8; font-size: 11px;")
        layout.addWidget(self.lbl_header_sync)

        # Global Refresh Button
        self.btn_header_refresh = QPushButton("Poll Sensors")
        self.btn_header_refresh.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                border: 1px solid #38bdf8;
                color: #38bdf8;
                font-weight: 600;
                padding: 4px 12px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #38bdf8;
                color: #0f172a;
            }
        """)
        self.btn_header_refresh.clicked.connect(lambda: self.refresh_all_data(run_collectors=True))
        layout.addWidget(self.btn_header_refresh)

        return header

    def _build_sidebar(self) -> QWidget:
        """Build the left navigation sidebar with section buttons."""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(10, 16, 10, 16)
        layout.setSpacing(6)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        self.btn_nav_overview = QPushButton("  Overview")
        self.btn_nav_overview.setCheckable(True)
        self.btn_nav_overview.setChecked(True)

        self.btn_nav_events = QPushButton("  Events")
        self.btn_nav_events.setCheckable(True)

        self.btn_nav_detections = QPushButton("  Detections")
        self.btn_nav_detections.setCheckable(True)

        self.btn_nav_incidents = QPushButton("  Incidents")
        self.btn_nav_incidents.setCheckable(True)

        self.btn_nav_settings = QPushButton("  Settings")
        self.btn_nav_settings.setCheckable(True)

        buttons = [
            (self.btn_nav_overview, 0),
            (self.btn_nav_events, 1),
            (self.btn_nav_detections, 2),
            (self.btn_nav_incidents, 3),
            (self.btn_nav_settings, 4),
        ]

        for btn, idx in buttons:
            self.nav_group.addButton(btn, idx)
            layout.addWidget(btn)

        self.nav_group.idClicked.connect(self._on_navigation_clicked)

        layout.addStretch()

        # Sidebar footer info
        footer_lbl = QLabel(f"{self.config.app_name} v{self.config.version}\nWindows 11 Local SOC")
        footer_lbl.setStyleSheet("color: #475569; font-size: 10px; padding: 8px;")
        layout.addWidget(footer_lbl)

        return sidebar

    def _on_navigation_clicked(self, view_index: int) -> None:
        """Switch the main stacked widget to the selected section."""
        self.stack.setCurrentIndex(view_index)
        section_names = ["Overview", "Telemetry Events", "Detection Alerts", "Incident Cases", "Settings"]
        if 0 <= view_index < len(section_names):
            self.status_bar.showMessage(f"Viewing {section_names[view_index]}")

    def _connect_signals(self) -> None:
        """Wire subview signals for cross-navigation and actions."""
        # Overview refresh
        self.overview_view.refresh_requested.connect(lambda: self.refresh_all_data(run_collectors=False))

        # Events refresh
        self.events_view.refresh_requested.connect(lambda: self.refresh_all_data(run_collectors=False))
        self.events_view.page_changed.connect(self._on_events_page_changed)

        # Detections: Create incident
        self.detections_view.create_incident_requested.connect(self._create_incident_from_alert)
        self.detections_view.review_state_changed.connect(self._set_alert_reviewed)

        # Detections: Open related event
        self.detections_view.open_related_event_requested.connect(self._navigate_to_event)

        # Incidents: Open related event
        self.incidents_view.open_related_event_requested.connect(self._navigate_to_event)

        # Incidents updated
        self.incidents_view.incident_updated.connect(self._on_incident_updated)

    def start_monitoring(self) -> None:
        """Start continuous process, network, and Windows Event Log polling."""
        self.host_monitor.start()
        self.status_bar.showMessage(
            f"Continuous monitoring active (poll interval: {self.host_monitor.poll_interval:g}s)."
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop background collection before the application window closes."""
        self.refresh_timer.stop()
        self.host_monitor.stop()
        super().closeEvent(event)

    def refresh_all_data(self, run_collectors: bool = False) -> None:
        """Synchronize telemetry from database, evaluate detection rules, and refresh all views."""
        self.status_bar.showMessage("Refreshing telemetry and evaluating detection engine...")

        # Optional live collection trigger
        if run_collectors:
            try:
                self.btn_header_refresh.setEnabled(False)
                self.btn_header_refresh.setText("Polling...")
                # Poll every configured collector through the serialized service.
                self.host_monitor.collect_once()
            except Exception as err:
                logger.warning("Error during manual sensor collection: %s", err)
            finally:
                self.btn_header_refresh.setEnabled(True)
                self.btn_header_refresh.setText("Poll Sensors")

        # 1. Load the requested event page from SQLite.
        timeframe = self.overview_view.get_selected_timeframe()
        timeframe_label = self.overview_view.timeframe_combo.currentText()
        if timeframe_label != self._active_timeframe:
            self.events_view.page_index = 0
            self._active_timeframe = timeframe_label
        start_time = datetime.now(timezone.utc) - timeframe if timeframe else None

        total_in_db = self.event_repo.count_events()
        matching_events = self.event_repo.count_events(start_time=start_time)
        event_page_count = max(
            1,
            (matching_events + self.events_view.PAGE_SIZE - 1) // self.events_view.PAGE_SIZE,
        )
        self.events_view.page_index = min(self.events_view.page_index, event_page_count - 1)
        self._cached_events = self.event_repo.list_events(
            start_time=start_time,
            limit=self.events_view.PAGE_SIZE,
            offset=self.events_view.page_index * self.events_view.PAGE_SIZE,
        )

        # 2. Evaluate rule evidence independently of the visible event page.
        self._cached_alerts = []
        now = datetime.now(timezone.utc)
        for rule in self.detection_engine.rules:
            event_types = getattr(rule, "event_types", ())
            if not event_types:
                rule_events = self.event_repo.list_events(start_time=start_time)
                self._cached_alerts.extend(rule.evaluate(rule_events))
                continue

            rule_window = getattr(rule, "window", None)
            rule_start = now - rule_window if rule_window is not None else start_time
            requires_complete_set = getattr(rule, "requires_complete_event_set", False)
            if requires_complete_set:
                complete_events: dict[str, SecurityEvent] = {}
                for event_type in event_types:
                    for event in self.event_repo.list_events(
                        event_type=event_type,
                        start_time=rule_start,
                    ):
                        complete_events[str(event.event_id)] = event
                self._cached_alerts.extend(rule.evaluate(list(complete_events.values())))
                continue

            for event_type in event_types:
                offset = 0
                while True:
                    rule_events = self.event_repo.list_events(
                        event_type=event_type,
                        start_time=rule_start,
                        limit=500,
                        offset=offset,
                    )
                    if not rule_events:
                        break
                    self._cached_alerts.extend(rule.evaluate(rule_events))
                    if len(rule_events) < 500:
                        break
                    offset += len(rule_events)

        # 3. Reconcile detections idempotently; incidents are persisted and paged separately.
        if self._cached_alerts:
            self.incident_manager.create_from_alerts(self._cached_alerts)

        # 4. Update sync timestamp
        now_str = datetime.now().strftime("%H:%M:%S")
        self._last_sync_time = now_str
        self.lbl_header_sync.setText(f"Last Sync: {now_str}")

        # 5. Distribute data to all subviews
        checkpoints = self.checkpoint_repo.list_checkpoints()
        health = self._collector_health_snapshot()
        self.incidents_view.refresh()
        overall_status = self._overall_collector_status(health)
        health_details = "; ".join(
            f"{name}: " + "; ".join(
                part for part in (
                    f"visibility limitation: {detail['visibility_limitations']}"
                    if detail["visibility_limitations"] else None,
                    f"latest error: {detail['last_error']}" if detail["last_error"] else None,
                )
                if part
            )
            for name, detail in health.items()
            if detail["last_error"] or detail["visibility_limitations"]
        )
        self.overview_view.update_data(
            total_events=total_in_db,
            events=self._cached_events,
            alerts=self._cached_alerts,
            incidents=self.incident_manager.incidents,
            last_collection_time=self._last_sync_time,
            system_health_status=overall_status,
            system_health_details=health_details or None,
            total_incidents=self.incident_manager.count_incidents(),
            open_incidents=self.incident_manager.count_incidents("open"),
        )

        self.events_view.set_events(
            self._cached_events,
            total_event_count=total_in_db,
            matching_event_count=matching_events,
            page_index=self.events_view.page_index,
        )
        if self._cached_alerts:
            empty_detection_context = ""
        elif total_in_db == 0:
            empty_detection_context = (
                "No detections can be evaluated because no telemetry is stored; this does not establish "
                "that no activity occurred. Process and network startup snapshots are intentionally "
                "suppressed, and Windows permissions or polling gaps can limit visibility. Poll Sensors "
                "and check Settings for collector health and access errors."
            )
        elif matching_events == 0:
            empty_detection_context = (
                "No events are in the selected timeframe, so no detections can be evaluated. "
                "This does not establish that no activity occurred."
            )
        else:
            empty_detection_context = (
                "No configured detection rules matched evidence in their applicable timeframes."
            )
        self.detections_view.set_alerts(
            self._cached_alerts,
            reviewed_alert_keys=sorted(self.alert_state_repo.list_reviewed_keys()),
            empty_context=empty_detection_context,
        )
        self.settings_view.update_diagnostics(total_in_db, checkpoints, health)
        self.status_text.setText({
            "healthy": "HOST SENSORS ACTIVE",
            "limited visibility": "SENSORS ACTIVE · LIMITED VISIBILITY",
            "degraded": "SENSORS DEGRADED",
            "not polled": "SENSORS NOT POLLED",
        }[overall_status])

        self.status_bar.showMessage(
            f"Updated view: {len(self._cached_events):,}/{matching_events:,} events in timeframe | "
            f"{len(self._cached_alerts)} detections | "
            f"{self.incident_manager.count_incidents()} incidents",
            4000,
        )

    def _on_events_page_changed(self, page_index: int) -> None:
        self.events_view.page_index = page_index
        self.refresh_all_data(run_collectors=False)

    def _collector_health_snapshot(self) -> dict[str, dict[str, str | int | None]]:
        """Return formatted last-run health for all collection and detection components."""
        health: dict[str, dict[str, str | int | None]] = {}
        collectors = {
            **self.host_monitor.health,
        }
        for name, state in collectors.items():
            health[name] = {
                "status": state.status,
                "last_attempt_at": state.last_attempt_at.isoformat() if state.last_attempt_at else None,
                "last_success_at": state.last_success_at.isoformat() if state.last_success_at else None,
                "last_error": state.last_error,
                "events_last_run": state.events_last_run,
                "visibility_limitations": "; ".join(state.visibility_limitations) or None,
            }
        health["Detection Engine"] = {
            "status": "healthy",
            "last_attempt_at": self._last_sync_time,
            "last_success_at": self._last_sync_time,
            "last_error": None,
            "events_last_run": len(self._cached_alerts),
            "visibility_limitations": None,
        }
        return health

    @staticmethod
    def _overall_collector_status(health: dict[str, dict[str, str | int | None]]) -> str:
        statuses = {str(item["status"]) for item in health.values()}
        if statuses.intersection({"degraded", "unavailable"}):
            return "degraded"
        if "not polled" in statuses:
            return "not polled"
        if any(item.get("visibility_limitations") for item in health.values()):
            return "limited visibility"
        return "healthy"

    def _set_alert_reviewed(self, alert_key: str, reviewed: bool) -> None:
        """Persist the analyst's review decision for a stable alert identity."""
        self.alert_state_repo.set_reviewed(alert_key, reviewed)

    def _create_incident_from_alert(self, alert: DetectionAlert) -> None:
        """Create an incident case from a detection alert and switch to Incidents view."""
        existing = self.incident_manager.get_incident_by_alert_key(alert.alert_key)
        incident = self.incident_manager.create_from_alert(alert)
        self.incidents_view.page_index = 0
        self.incidents_view.refresh()
        health = self._collector_health_snapshot()
        self.overview_view.update_data(
            total_events=self.event_repo.count_events(),
            events=self._cached_events,
            alerts=self._cached_alerts,
            incidents=self.incident_manager.incidents,
            last_collection_time=self._last_sync_time,
            system_health_status=self._overall_collector_status(health),
            system_health_details=self._health_details(health),
            total_incidents=self.incident_manager.count_incidents(),
            open_incidents=self.incident_manager.count_incidents("open"),
        )

        # Switch to Incidents tab
        self.btn_nav_incidents.setChecked(True)
        self._on_navigation_clicked(3)
        action = "Opened" if existing else "Created"
        self.status_bar.showMessage(f"{action} incident '{incident.title}' (ID: {incident.incident_id[:8]}...)", 5000)

    def _navigate_to_event(self, event_id: str) -> None:
        """Navigate to Events view and search for the specific related event ID."""
        self.btn_nav_events.setChecked(True)
        self._on_navigation_clicked(1)
        self.overview_view.timeframe_combo.blockSignals(True)
        self.overview_view.timeframe_combo.setCurrentText("All Time")
        self.overview_view.timeframe_combo.blockSignals(False)
        self.refresh_all_data(run_collectors=False)

        evidence_event = self.event_repo.get_event(event_id)
        if evidence_event is not None and all(
            str(event.event_id) != event_id for event in self._cached_events
        ):
            self._cached_events.append(evidence_event)
            self.events_view.set_events(
                self._cached_events,
                total_event_count=self.event_repo.count_events(),
                matching_event_count=self.event_repo.count_events(),
            )
        self.events_view.search_input.setText(event_id)
        if evidence_event is None:
            self.status_bar.showMessage(
                f"Evidence event {event_id} is not available (it may have expired under retention).",
                6000,
            )
        else:
            self.status_bar.showMessage(f"Filtered for related event: {event_id}", 4000)

    def _on_incident_updated(self) -> None:
        """Handle incident state changes."""
        health = self._collector_health_snapshot()
        self.overview_view.update_data(
            total_events=self.event_repo.count_events(),
            events=self._cached_events,
            alerts=self._cached_alerts,
            incidents=self.incident_manager.incidents,
            last_collection_time=self._last_sync_time,
            system_health_status=self._overall_collector_status(health),
            system_health_details=self._health_details(health),
            total_incidents=self.incident_manager.count_incidents(),
            open_incidents=self.incident_manager.count_incidents("open"),
        )

    @staticmethod
    def _health_details(health: dict[str, dict[str, str | int | None]]) -> str | None:
        messages = [
            f"{name}: {detail['last_error']}"
            for name, detail in health.items()
            if detail["last_error"]
        ]
        return "; ".join(messages) or None
