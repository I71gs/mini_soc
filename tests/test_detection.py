from datetime import datetime, timedelta, timezone

from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.detection.rules import DetectionEngine
from src.incidents.manager import IncidentManager


def _make_event(**kwargs):
    return SecurityEvent(
        source=kwargs.get("source", "test_source"),
        category=kwargs.get("category", EventCategory.SYSTEM),
        event_type=kwargs.get("event_type", "test_event"),
        severity=kwargs.get("severity", EventSeverity.INFO),
        host=kwargs.get("host", "TESTHOST"),
        timestamp=kwargs.get("timestamp", datetime.now(timezone.utc)),
        description=kwargs.get("description", "Test event"),
        attributes=kwargs.get("attributes", {}),
    )


def test_detection_engine_flags_suspicious_process():
    event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={
            "name": "rundll32.exe",
            "pid": 1337,
            "exe": "C:/Windows/System32/rundll32.exe",
            "command_line": "rundll32.exe javascript:evil",
        },
    )

    alerts = DetectionEngine().evaluate([event])

    assert any(alert.rule_name == "suspicious_process" for alert in alerts)


def test_detection_engine_flags_explicit_keylogger_process_marker():
    event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={
            "name": "C:\\Users\\Public\\keylogger.exe",
            "pid": 2468,
            "exe": "C:\\Users\\Public\\keylogger.exe",
            "command_line": "keylogger.exe",
        },
    )

    alerts = [
        alert for alert in DetectionEngine().evaluate([event])
        if alert.rule_name == "possible_keylogger"
    ]

    assert len(alerts) == 1
    assert alerts[0].severity == EventSeverity.MEDIUM
    assert alerts[0].related_event_ids == [str(event.event_id)]
    assert "explicit_keylogger_marker" in alerts[0].attributes["indicators"]
    assert "cannot confirm keystroke capture" in alerts[0].description


def test_detection_engine_flags_keyboard_capture_api_and_ignores_unrelated_process():
    suspicious_event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={
            "name": "input-helper.exe",
            "pid": 2469,
            "command_line": "input-helper.exe --hook SetWindowsHookEx",
        },
    )
    benign_event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={
            "name": "notepad.exe",
            "pid": 2470,
            "command_line": "notepad.exe C:\\Temp\\notes.txt",
        },
    )

    alerts = [
        alert for alert in DetectionEngine().evaluate([suspicious_event, benign_event])
        if alert.rule_name == "possible_keylogger"
    ]

    assert len(alerts) == 1
    assert alerts[0].related_event_ids == [str(suspicious_event.event_id)]
    assert "setwindowshookex" in alerts[0].attributes["indicators"]


def test_detection_engine_flags_failed_logon_spike():
    events = [
        _make_event(
            source="windows_event_log",
            event_type="windows_logon_failed",
            attributes={
                "account_name": "admin",
                "source_ip": "203.0.113.8",
                "status": "0xC000006D",
            },
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


def test_failed_logon_spike_requires_three_failures_within_ten_minutes():
    now = datetime.now(timezone.utc)
    events = [
        _make_event(
            event_type="windows_logon_failed",
            timestamp=now - timedelta(minutes=age),
            host="HOST-A",
            attributes={"account_name": "analyst", "source_ip": "203.0.113.8"},
        )
        for age in (2, 8, 11)
    ]

    alerts = DetectionEngine().evaluate(events)

    assert not any(alert.rule_name == "failed_logon_spike" for alert in alerts)


def test_failed_logon_spike_groups_by_host_account_and_source_ip():
    now = datetime.now(timezone.utc)
    events = [
        _make_event(
            event_type="windows_logon_failed",
            timestamp=now - timedelta(minutes=age),
            host=host,
            attributes={"account_name": account, "source_ip": source_ip},
        )
        for age, host, account, source_ip in (
            (1, "HOST-A", "analyst", "203.0.113.1"),
            (2, "HOST-A", "analyst", "203.0.113.1"),
            (3, "HOST-A", "analyst", "203.0.113.1"),
            (4, "HOST-B", "analyst", "203.0.113.1"),
        )
    ]

    alerts = [
        alert for alert in DetectionEngine().evaluate(events)
        if alert.rule_name == "failed_logon_spike"
    ]

    assert len(alerts) == 1
    assert alerts[0].attributes["failed_count"] == 3
    assert alerts[0].attributes["host"] == "HOST-A"
    assert alerts[0].attributes["source_ip"] == "203.0.113.1"
    assert alerts[0].detected_at.tzinfo == timezone.utc
    assert alerts[0].alert_key == DetectionEngine().evaluate(events)[0].alert_key
    assert "missing attribution are not included" in alerts[0].description


def test_failed_logon_spike_does_not_combine_missing_or_invalid_attribution():
    now = datetime.now(timezone.utc)
    events = [
        _make_event(
            event_type="windows_logon_failed",
            timestamp=now - timedelta(minutes=age),
            host="HOST-A",
            attributes=attributes,
        )
        for age, attributes in (
            (1, {"account_name": "admin", "source_ip": "203.0.113.1"}),
            (2, {"account_name": "admin", "source_ip": "203.0.113.1"}),
            (3, {"account_name": None, "source_ip": "203.0.113.1"}),
            (4, {"account_name": "unknown", "source_ip": "203.0.113.2"}),
            (5, {"account_name": "admin", "source_ip": "-"}),
            (6, {"account_name": "admin", "source_ip": "not-an-ip"}),
        )
    ]

    alerts = [
        alert for alert in DetectionEngine().evaluate(events)
        if alert.rule_name == "failed_logon_spike"
    ]

    assert alerts == []


def test_failed_logon_spike_normalizes_account_case_and_ip_address():
    now = datetime.now(timezone.utc)
    events = [
        _make_event(
            event_type="windows_logon_failed",
            timestamp=now - timedelta(minutes=age),
            host="HOST-A",
            attributes={"account_name": account, "source_ip": source},
        )
        for age, account, source in (
            (1, "Admin", "2001:0db8::1"),
            (2, "admin", "2001:db8:0:0:0:0:0:1"),
            (3, "ADMIN", "2001:db8::1"),
        )
    ]

    alerts = [
        alert for alert in DetectionEngine().evaluate(events)
        if alert.rule_name == "failed_logon_spike"
    ]

    assert len(alerts) == 1
    assert alerts[0].attributes["failed_count"] == 3


def test_suspicious_network_rule_only_flags_established_public_connections():
    public_event = _make_event(
        event_type="network_connection_observed",
        attributes={
            "remote_ip": "8.8.8.8",
            "remote_port": 3389,
            "status": "ESTABLISHED",
            "protocol": "tcp",
        },
    )
    listening_event = _make_event(
        event_type="network_connection_observed",
        attributes={
            "remote_ip": "8.8.8.8",
            "remote_port": 3389,
            "status": "LISTEN",
        },
    )
    private_event = _make_event(
        event_type="network_connection_observed",
        attributes={
            "remote_ip": "172.20.1.1",
            "remote_port": 3389,
            "status": "ESTABLISHED",
        },
    )

    alerts = DetectionEngine().evaluate([public_event, listening_event, private_event])

    network_alerts = [alert for alert in alerts if alert.rule_name == "suspicious_network"]
    assert [alert.related_event_ids for alert in network_alerts] == [[str(public_event.event_id)]]
    assert "Direction and initiating endpoint are unknown" in network_alerts[0].description
    assert "not evidence of maliciousness" in network_alerts[0].description
    assert "Outbound" not in network_alerts[0].title


def test_suspicious_network_rule_ignores_non_risky_ports_and_non_established_connections():
    benign_port = _make_event(
        event_type="network_connection_observed",
        attributes={
            "remote_ip": "8.8.8.8",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "protocol": "tcp",
        },
    )
    pending_connection = _make_event(
        event_type="network_connection_observed",
        attributes={
            "remote_ip": "8.8.8.8",
            "remote_port": 3389,
            "status": "SYN_SENT",
            "protocol": "tcp",
        },
    )

    alerts = [
        alert for alert in DetectionEngine().evaluate([benign_port, pending_connection])
        if alert.rule_name == "suspicious_network"
    ]

    assert alerts == []


def test_suspicious_process_rule_does_not_flag_benign_dual_use_tool_command():
    event = _make_event(
        source="process_collector",
        event_type="process_started",
        attributes={
            "name": "rundll32.exe",
            "pid": 4321,
            "command_line": "rundll32.exe shell32.dll,Control_RunDLL",
        },
    )

    alerts = [
        alert for alert in DetectionEngine().evaluate([event])
        if alert.rule_name == "suspicious_process"
    ]

    assert alerts == []


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
