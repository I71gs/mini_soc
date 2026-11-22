"""Mini SOC - Standalone, local-first Windows Mini SOC.

Entry point for bootstrapping configuration, database persistence,
host telemetry, Windows Event Log collection, and the PySide6 desktop UI.

Usage:
    python main.py          Headless bootstrap: collect telemetry, run detections, print summary.
    python main.py --gui    Launch the PySide6 console, requesting UAC for process visibility.
"""

import ctypes
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.collectors.monitor_service import HostMonitorService
from src.collectors.windows_event_collector import WindowsEventCollector
from src.core.config import AppConfig
from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.core.logging_utils import configure_logging, sanitized_log_event
from src.database.checkpoint_repository import CheckpointRepository
from src.database.connection import DatabaseManager, migrate_legacy_database
from src.database.event_repository import EventRepository
from src.database.incident_repository import IncidentRepository
from src.database.schema import initialize_database
from src.detection.rules import DetectionEngine
from src.incidents.manager import IncidentManager


def _request_gui_elevation() -> bool:
    """Request a UAC-elevated GUI relaunch; return whether it was started."""
    if sys.platform != "win32":
        return False

    try:
        shell32 = ctypes.windll.shell32
        if shell32.IsUserAnAdmin():
            return False
        if not _has_filtered_admin_token():
            print(
                "No filtered administrator token is available; continuing with standard-user visibility.",
                file=sys.stderr,
            )
            return False

        shell_execute = shell32.ShellExecuteW
        shell_execute.restype = ctypes.c_void_p
        shell_execute.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        parameters = subprocess.list2cmdline(
            [str(Path(__file__).resolve()), *sys.argv[1:]]
        )
        result = shell_execute(
            None,
            "runas",
            sys.executable,
            parameters,
            None,
            1,
        )
    except (AttributeError, OSError, ctypes.ArgumentError) as err:
        print(
            f"Unable to request GUI elevation ({err}); continuing with standard-user visibility.",
            file=sys.stderr,
        )
        return False

    if result is not None and result > 32:
        return True

    print(
        "Administrator approval was declined or unavailable; continuing with standard-user visibility.",
        file=sys.stderr,
    )
    return False


def _has_filtered_admin_token() -> bool:
    """Return whether this process has a UAC-filtered local-administrator token."""
    kernel32 = ctypes.windll.kernel32
    advapi32 = ctypes.windll.advapi32
    token_query = 0x0008
    token_elevation_type = 18
    token_elevation_type_limited = 3

    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = ctypes.c_void_p
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    open_process_token.restype = ctypes.c_int
    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    get_token_information.restype = ctypes.c_int
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int

    token = ctypes.c_void_p()
    if not open_process_token(
        get_current_process(), token_query, ctypes.byref(token)
    ):
        raise ctypes.WinError()

    try:
        elevation_type = ctypes.c_uint32()
        return_length = ctypes.c_uint32()
        if not get_token_information(
            token,
            token_elevation_type,
            ctypes.byref(elevation_type),
            ctypes.sizeof(elevation_type),
            ctypes.byref(return_length),
        ):
            raise ctypes.WinError()
        return elevation_type.value == token_elevation_type_limited
    finally:
        close_handle(token)


def main() -> None:
    """Bootstrap and display Mini SOC configuration, persistence, and telemetry status."""
    # --gui flag: launch the PySide6 desktop console instead of headless mode.
    if "--gui" in sys.argv:
        if _request_gui_elevation():
            sys.exit(0)
        from src.ui.app import run_app

        sys.exit(run_app())

    config = AppConfig()
    migrated_database = migrate_legacy_database(config.legacy_database_path, config.database_path)
    logger = configure_logging(config.log_dir, level=20)
    logger.info(sanitized_log_event("Mini SOC bootstrap started", project_root=str(config.project_root), data_dir=str(config.data_dir)))
    if migrated_database:
        logger.info(sanitized_log_event(
            "Legacy database copied to user data directory",
            source=str(config.legacy_database_path),
            destination=str(migrated_database),
        ))
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
    repo.delete_events_before(datetime.now(timezone.utc) - timedelta(days=config.retention_days))

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
    print(f"  Collector status: {evt_collector.health.status}")
    if evt_collector.health.last_error:
        print(f"  Collector detail: {evt_collector.health.last_error}")
    logger.info(sanitized_log_event("Windows events imported", count=len(win_events)))

    # Host telemetry collection (processes and network connections)
    monitor = HostMonitorService(repository=repo)
    monitor.initialize_baselines()
    host_events = monitor.collect_once()
    print(f"Host Telemetry    : {len(host_events)} new host events observed")
    for name, state in monitor.health.items():
        print(f"  {name}: {state.status}")
        if state.last_error:
            print(f"    Collector detail: {state.last_error}")
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
