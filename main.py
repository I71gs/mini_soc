"""Mini SOC - Standalone, local-first Windows Mini SOC.

Entry point for bootstrapping configuration, database persistence,
host telemetry, Windows Event Log collection, and the PySide6 desktop UI.

Usage:
    python main.py          Headless bootstrap: collect telemetry, run detections, print summary.
    python main.py --gui    Launch the PySide6 desktop security console.
"""

import sys

from src.collectors.monitor_service import HostMonitorService
from src.collectors.windows_event_collector import WindowsEventCollector
from src.core.config import AppConfig
from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.core.logging_utils import configure_logging, sanitized_log_event
from src.database.checkpoint_repository import CheckpointRepository
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.incident_repository import IncidentRepository
from src.database.schema import initialize_database
from src.detection.rules import DetectionEngine
from src.incidents.manager import IncidentManager


def main() -> None:
    """Bootstrap and display Mini SOC configuration, persistence, and telemetry status."""
    # --gui flag: launch the PySide6 desktop console instead of headless mode.
    if "--gui" in sys.argv:
        from src.ui.app import run_app

        sys.exit(run_app())

    config = AppConfig()
    logger = configure_logging(config.log_dir, level=20)
    logger.info(sanitized_log_event("Mini SOC bootstrap started", project_root=str(config.project_root), data_dir=str(config.data_dir)))
    print("=" * 50)
    print(f" {config.app_name} - Version {config.version}")
    print("=" * 50)
    print(f"Project root   : {config.project_root}")
    print(f"Data directory : {config.data_dir}")
    print(f"Database path  : {config.database_path}")
    print(f"Log directory  : {config.log_dir}")
    print("-" * 50)

    # Initialize SQLite database
    db_manager = DatabaseManager(config.database_path)
    schema_version = initialize_database(db_manager)
    print(f"Database initialized: Schema v{schema_version}")
    logger.info(sanitized_log_event("Database initialized", schema_version=schema_version))

    # Event repository and checkpoint repositories
    repo = EventRepository(db_manager)
    checkpoint_repo = CheckpointRepository(db_manager)
    incident_repo = IncidentRepository(db_manager)

    # Record startup event if database is fresh
    if repo.count_events() == 0:
        startup_event = SecurityEvent(
            source="system_bootstrap",
            category=EventCategory.SYSTEM,
            event_type="application_startup",
            severity=EventSeverity.INFO,
            description=f"{config.app_name} initialized successfully.",
            attributes={"version": config.version, "environment": "standalone"},
        )
        repo.add_event(startup_event)

    # Windows Event Log collection (incremental via persistent SQLite checkpoints)
    evt_collector = WindowsEventCollector(
        repository=repo,
        checkpoint_repo=checkpoint_repo,
    )
    win_events = evt_collector.collect_events()
    print(f"Windows Event Log : {len(win_events)} new events imported")
    logger.info(sanitized_log_event("Windows events imported", count=len(win_events)))

    # Host telemetry collection (processes and network connections)
    monitor = HostMonitorService(repository=repo)
    if repo.count_events() > 0:
        monitor.initialize_baselines()
    host_events = monitor.collect_once()
    print(f"Host Telemetry    : {len(host_events)} new host events observed")
    logger.info(sanitized_log_event("Host telemetry observed", count=len(host_events)))

    # Rule-based detection and alerting on recently captured events
    all_events = repo.list_events(limit=500)
    detection_engine = DetectionEngine()
    alerts = detection_engine.evaluate(all_events)
    incident_manager = IncidentManager(repository=incident_repo)
    incidents = incident_manager.create_from_alerts(alerts)
    print(f"Detections        : {len(alerts)} alerts raised")
    print(f"Open incidents    : {len(incidents)} incidents created")

    if alerts:
        for alert in alerts[:3]:
            print(f" - {alert.rule_name}: {alert.title}")

    print("-" * 50)
    print(f"Total stored events in DB: {repo.count_events()}")
    print("=" * 50)


if __name__ == "__main__":
    main()
