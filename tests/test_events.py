"""Automated tests for standardized security events."""

from datetime import datetime, timezone, timedelta
import uuid

import pytest
from pydantic import ValidationError

from src.core.events import EventCategory, EventSeverity, SecurityEvent


def test_successful_event_creation() -> None:
    """Test successful creation of a security event with explicit valid parameters."""
    now_utc = datetime.now(timezone.utc)
    custom_id = uuid.uuid4()

    event = SecurityEvent(
        event_id=custom_id,
        timestamp=now_utc,
        source="host_agent",
        category=EventCategory.PROCESS,
        event_type="process_started",
        severity=EventSeverity.HIGH,
        host="SEC-WORKSTATION-01",
        description="A suspicious powershell process was spawned.",
        attributes={"pid": 1337, "command_line": "powershell.exe -enc ..."},
        schema_version="1.0",
    )

    assert event.event_id == custom_id
    assert event.timestamp == now_utc
    assert event.source == "host_agent"
    assert event.category == EventCategory.PROCESS
    assert event.event_type == "process_started"
    assert event.severity == EventSeverity.HIGH
    assert event.host == "SEC-WORKSTATION-01"
    assert event.description == "A suspicious powershell process was spawned."
    assert event.attributes["pid"] == 1337
    assert event.schema_version == "1.0"


def test_automatic_uuid_generation() -> None:
    """Test that event_id is automatically generated as a unique UUIDv4 when omitted."""
    event1 = SecurityEvent(
        source="test_source",
        category=EventCategory.SYSTEM,
        event_type="test_event",
        description="Test event 1",
    )
    event2 = SecurityEvent(
        source="test_source",
        category=EventCategory.SYSTEM,
        event_type="test_event",
        description="Test event 2",
    )

    assert isinstance(event1.event_id, uuid.UUID)
    assert isinstance(event2.event_id, uuid.UUID)
    assert event1.event_id != event2.event_id
    assert event1.event_id.version == 4


def test_default_severity() -> None:
    """Test that severity defaults to INFO when not explicitly provided."""
    event = SecurityEvent(
        source="test_source",
        category=EventCategory.SYSTEM,
        event_type="test_event",
        description="Test default severity",
    )

    assert event.severity == EventSeverity.INFO


def test_utc_timestamp_handling() -> None:
    """Test default UTC timestamp generation and normalization of non-UTC timezone timestamps."""
    # 1. Default timestamp should be timezone-aware and set to UTC
    event = SecurityEvent(
        source="test_source",
        category=EventCategory.SYSTEM,
        event_type="test_event",
        description="Test UTC timestamp",
    )
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.tzinfo == timezone.utc

    # 2. Offset timestamp should be normalized to UTC
    # e.g., 15:30 at UTC+05:30 is 10:00 UTC
    tz_ist = timezone(timedelta(hours=5, minutes=30))
    ist_time = datetime(2026, 11, 6, 15, 30, 0, tzinfo=tz_ist)

    event_normalized = SecurityEvent(
        timestamp=ist_time,
        source="test_source",
        category=EventCategory.SYSTEM,
        event_type="test_event",
        description="Normalized timestamp event",
    )
    assert event_normalized.timestamp.tzinfo == timezone.utc
    assert event_normalized.timestamp.hour == 10
    assert event_normalized.timestamp.minute == 0


def test_rejection_of_invalid_timestamps() -> None:
    """Test that naive timestamps and invalid timestamp formats are rejected."""
    # Naive datetime object without tzinfo
    naive_dt = datetime(2026, 11, 6, 12, 0, 0)
    with pytest.raises(ValidationError, match="Timestamp must be timezone-aware"):
        SecurityEvent(
            timestamp=naive_dt,
            source="test_source",
            category=EventCategory.SYSTEM,
            event_type="test_event",
            description="Naive timestamp test",
        )

    # Naive ISO string without offset or Z
    naive_iso_str = "2026-11-06T12:00:00"
    with pytest.raises(ValidationError, match="Timestamp must be timezone-aware"):
        SecurityEvent(
            timestamp=naive_iso_str,
            source="test_source",
            category=EventCategory.SYSTEM,
            event_type="test_event",
            description="Naive ISO timestamp test",
        )

    # Completely invalid timestamp format
    with pytest.raises(ValidationError, match="Invalid ISO timestamp format"):
        SecurityEvent(
            timestamp="not-a-timestamp",
            source="test_source",
            category=EventCategory.SYSTEM,
            event_type="test_event",
            description="Malformed timestamp test",
        )


def test_rejection_of_invalid_severity() -> None:
    """Test that invalid severity values are rejected with clear validation errors."""
    with pytest.raises(ValidationError, match="Invalid severity 'UNKNOWN'"):
        SecurityEvent(
            source="test_source",
            category=EventCategory.SYSTEM,
            event_type="test_event",
            severity="UNKNOWN",
            description="Invalid severity test",
        )

    with pytest.raises(ValidationError, match="severity must be an EventSeverity enum or string"):
        SecurityEvent(
            source="test_source",
            category=EventCategory.SYSTEM,
            event_type="test_event",
            severity=999,  # type: ignore[arg-type]
            description="Non-string severity test",
        )


def test_required_field_validation() -> None:
    """Test validation of required fields and non-empty string constraints."""
    # Missing required 'source'
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(  # type: ignore[call-arg]
            category=EventCategory.SYSTEM,
            event_type="test_event",
            description="Missing source",
        )
    assert "source" in str(exc_info.value)

    # Missing required 'event_type'
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(  # type: ignore[call-arg]
            source="test_source",
            category=EventCategory.SYSTEM,
            description="Missing event_type",
        )
    assert "event_type" in str(exc_info.value)

    # Missing required 'description'
    with pytest.raises(ValidationError) as exc_info:
        SecurityEvent(  # type: ignore[call-arg]
            source="test_source",
            category=EventCategory.SYSTEM,
            event_type="test_event",
        )
    assert "description" in str(exc_info.value)

    # Empty string or whitespace-only field rejection
    with pytest.raises(ValidationError, match="source cannot be empty"):
        SecurityEvent(
            source="   ",
            category=EventCategory.SYSTEM,
            event_type="test_event",
            description="Empty source test",
        )

    with pytest.raises(ValidationError, match="description cannot be empty"):
        SecurityEvent(
            source="test_source",
            category=EventCategory.SYSTEM,
            event_type="test_event",
            description="",
        )


def test_json_serialization() -> None:
    """Test that SecurityEvent correctly serializes to valid JSON."""
    event = SecurityEvent(
        source="network_sniffer",
        category=EventCategory.NETWORK,
        event_type="port_scan_detected",
        severity=EventSeverity.MEDIUM,
        description="Multiple SYN packets received on closed ports.",
        attributes={"src_ip": "192.168.1.105", "ports": [22, 80, 443, 8080]},
    )

    json_output = event.model_dump_json()
    assert isinstance(json_output, str)
    assert str(event.event_id) in json_output
    assert "NETWORK" in json_output
    assert "MEDIUM" in json_output
    assert "192.168.1.105" in json_output


def test_json_deserialization() -> None:
    """Test that a SecurityEvent can be deserialized accurately from JSON."""
    raw_json = """{
        "event_id": "11111111-2222-3333-4444-555555555555",
        "timestamp": "2026-11-06T12:00:00Z",
        "source": "auth_manager",
        "category": "AUTHENTICATION",
        "event_type": "user_login_success",
        "severity": "LOW",
        "host": "DC-PRIMARY",
        "description": "User admin logged in successfully.",
        "attributes": {"username": "admin", "mfa_used": true},
        "schema_version": "1.0"
    }"""

    event = SecurityEvent.model_validate_json(raw_json)

    assert str(event.event_id) == "11111111-2222-3333-4444-555555555555"
    assert event.timestamp == datetime(2026, 11, 6, 12, 0, 0, tzinfo=timezone.utc)
    assert event.source == "auth_manager"
    assert event.category == EventCategory.AUTHENTICATION
    assert event.event_type == "user_login_success"
    assert event.severity == EventSeverity.LOW
    assert event.host == "DC-PRIMARY"
    assert event.description == "User admin logged in successfully."
    assert event.attributes == {"username": "admin", "mfa_used": True}
    assert event.schema_version == "1.0"


def test_additional_attributes_preservation() -> None:
    """Test that arbitrary nested attributes are preserved without core schema modification."""
    arbitrary_attributes = {
        "process": {
            "name": "cmd.exe",
            "parent_pid": 100,
            "integrity_level": "High",
        },
        "network": {
            "destination_ips": ["10.0.0.1", "10.0.0.2"],
            "bytes_out": 2048,
        },
        "flags": ["suspicious", "unusual_parent"],
    }

    event = SecurityEvent(
        source="edr_sensor",
        category=EventCategory.PROCESS,
        event_type="suspicious_process_tree",
        description="Process spawned by unusual parent",
        attributes=arbitrary_attributes,
    )

    assert event.attributes == arbitrary_attributes
    # Verify serialization preserves nested structures
    json_data = event.model_dump_json()
    reconstructed = SecurityEvent.model_validate_json(json_data)
    assert reconstructed.attributes == arbitrary_attributes


def test_database_record_conversion() -> None:
    """Test flattening and reconstruction for future SQLite persistence."""
    event = SecurityEvent(
        source="file_integrity",
        category=EventCategory.FILE,
        event_type="file_modified",
        severity=EventSeverity.CRITICAL,
        description="System file modified in System32",
        attributes={"path": "C:\\Windows\\System32\\drivers\\etc\\hosts", "change": "append"},
    )

    db_record = event.to_db_record()

    assert isinstance(db_record["event_id"], str)
    assert isinstance(db_record["timestamp"], str)
    assert isinstance(db_record["attributes"], str)
    assert db_record["category"] == "FILE"
    assert db_record["severity"] == "CRITICAL"

    restored = SecurityEvent.from_db_record(db_record)
    assert restored.event_id == event.event_id
    assert restored.timestamp == event.timestamp
    assert restored.category == event.category
    assert restored.severity == event.severity
    assert restored.attributes == event.attributes
