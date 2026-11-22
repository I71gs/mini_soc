from datetime import datetime, timedelta, timezone

from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.schema import initialize_database
from src.incidents.models import Incident
from src.reporting.exporter import ReportingExporter


def _event(source: str, event_type: str, severity: EventSeverity = EventSeverity.INFO) -> SecurityEvent:
    return SecurityEvent(
        source=source,
        category=EventCategory.SYSTEM,
        event_type=event_type,
        severity=severity,
        description=f"Sample {event_type}",
        attributes={"sample": True},
    )


def test_export_events_csv(tmp_path):
    event = _event("windows_event_log", "windows_logon_failed", EventSeverity.MEDIUM)
    event.description = "=HYPERLINK(\"https://example.invalid\")"
    events = [event, _event("process_collector", "process_started", EventSeverity.HIGH)]

    destination = tmp_path / "exports" / "events.csv"
    exported = ReportingExporter.export_events_csv(events, destination)

    assert exported.exists()
    content = exported.read_text(encoding="utf-8")
    assert "event_id" in content
    assert "windows_logon_failed" in content
    assert "process_started" in content
    assert "'=HYPERLINK" in content


def test_export_incidents_json(tmp_path):
    incidents = [
        Incident(
            incident_id="inc-1",
            title="Suspicious process",
            description="Known suspicious process started",
            severity=EventSeverity.HIGH,
            status="open",
            source="process_collector",
            related_event_ids=["evt-1"],
            attributes={"rule_name": "suspicious_process"},
        )
    ]

    destination = tmp_path / "exports" / "incidents.json"
    exported = ReportingExporter.export_incidents_json(incidents, destination)

    assert exported.exists()
    payload = exported.read_text(encoding="utf-8")
    assert "Suspicious process" in payload
    assert "suspicious_process" in payload


def test_export_summary_json(tmp_path):
    events = [_event("windows_event_log", "windows_logon_failed", EventSeverity.MEDIUM), _event("network_collector", "network_connection_observed", EventSeverity.LOW)]
    incidents = [
        Incident(
            incident_id="inc-1",
            title="Alert",
            description="Detected suspicious connection",
            severity=EventSeverity.MEDIUM,
            status="open",
            source="network_collector",
            related_event_ids=["evt-1"],
            attributes={"rule_name": "suspicious_network"},
        )
    ]

    destination = tmp_path / "exports" / "summary.json"
    exported = ReportingExporter.export_summary_json(events, incidents, destination)

    assert exported.exists()
    payload = exported.read_text(encoding="utf-8")
    assert '"total_events": 2' in payload
    assert '"total_incidents": 1' in payload


def test_event_retention_does_not_delete_exported_files(tmp_path):
    manager = DatabaseManager(tmp_path / "retention.db")
    initialize_database(manager)
    repository = EventRepository(manager)
    old_event = _event("test", "old_event")
    old_event.timestamp = datetime.now(timezone.utc) - timedelta(days=91)
    repository.add_event(old_event)

    export_path = ReportingExporter.export_events_json(
        [old_event], tmp_path / "exports" / "old-event.json"
    )
    repository.delete_events_before(datetime.now(timezone.utc) - timedelta(days=90))

    assert repository.count_events() == 0
    assert export_path.exists()
