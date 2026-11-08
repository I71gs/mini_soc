from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.detection.rules import DetectionEngine
from src.incidents.manager import IncidentManager


def _make_event(**kwargs):
    return SecurityEvent(
        source=kwargs.get("source", "test_source"),
        category=kwargs.get("category", EventCategory.SYSTEM),
        event_type=kwargs.get("event_type", "test_event"),
        severity=kwargs.get("severity", EventSeverity.INFO),
        description=kwargs.get("description", "Test event"),
        attributes=kwargs.get("attributes", {}),
    )


def test_detection_engine_flags_suspicious_process():
    event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={"name": "rundll32.exe", "pid": 1337, "exe": "C:/Windows/System32/rundll32.exe"},
    )

    alerts = DetectionEngine().evaluate([event])

    assert any(alert.rule_name == "suspicious_process" for alert in alerts)


def test_detection_engine_flags_failed_logon_spike():
    events = [
        _make_event(
            source="windows_event_log",
            event_type="windows_logon_failed",
            attributes={"account_name": "admin", "status": "0xC000006D"},
        )
        for _ in range(3)
    ]

    alerts = DetectionEngine().evaluate(events)

    assert any(alert.rule_name == "failed_logon_spike" for alert in alerts)


def test_detection_engine_ignores_benign_powershell_usage():
    event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={
            "name": "powershell.exe",
            "pid": 4567,
            "command_line": "powershell.exe -NoProfile -Command Get-ChildItem C:\\Temp",
        },
    )

    alerts = DetectionEngine().evaluate([event])

    assert not any(alert.rule_name == "suspicious_process" for alert in alerts)


def test_incident_manager_creates_incidents_from_alerts():
    event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={
            "name": "cmd.exe",
            "pid": 9999,
            "command_line": "cmd.exe /c powershell -enc ZgB1AGQAZQBzAHQAcwA==",
        },
    )
    alerts = DetectionEngine().evaluate([event])

    incidents = IncidentManager().create_from_alerts(alerts)

    assert len(incidents) == 1
    assert incidents[0].severity == EventSeverity.HIGH
    assert incidents[0].status == "open"
