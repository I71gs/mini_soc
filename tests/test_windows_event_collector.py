"""Automated unit tests for WindowsEventCollector."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.collectors.windows_event_collector import (
    WindowsEventCollector,
    normalize_event,
    parse_event_xml,
)
from src.core.events import EventCategory, EventSeverity
from src.database.checkpoint_repository import CheckpointRepository
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.schema import initialize_database

SAMPLE_4624_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime='2026-11-07T08:00:00.1234567Z'/>
    <EventRecordID>10001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>SEC-WORKSTATION</Computer>
</System>
<EventData>
    <Data Name='TargetUserName'>analyst</Data>
    <Data Name='TargetDomainName'>MINISOC</Data>
    <Data Name='LogonType'>2</Data>
    <Data Name='WorkstationName'>SEC-WORKSTATION</Data>
    <Data Name='IpAddress'>127.0.0.1</Data>
    <Data Name='IpPort'>54321</Data>
    <Data Name='ProcessName'>C:\\Windows\\System32\\svchost.exe</Data>
    <Data Name='TargetLogonId'>0x3e7</Data>
</EventData>
</Event>"""

SAMPLE_4625_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime='2026-11-07T08:05:00.0000000Z'/>
    <EventRecordID>10002</EventRecordID>
    <Channel>Security</Channel>
    <Computer>SEC-WORKSTATION</Computer>
</System>
<EventData>
    <Data Name='TargetUserName'>bad_actor</Data>
    <Data Name='TargetDomainName'>MINISOC</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='Status'>0xC000006D</Data>
    <Data Name='SubStatus'>0xC000006A</Data>
    <Data Name='FailureReason'>%%2313</Data>
    <Data Name='WorkstationName'>REMOTE-HOST</Data>
    <Data Name='IpAddress'>192.168.1.100</Data>
    <Data Name='IpPort'>49152</Data>
</EventData>
</Event>"""

SAMPLE_1102_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>1102</EventID>
    <TimeCreated SystemTime='2026-11-07T08:10:00.5000000Z'/>
    <EventRecordID>10003</EventRecordID>
    <Channel>Security</Channel>
    <Computer>SEC-WORKSTATION</Computer>
</System>
<EventData>
    <Data Name='SubjectUserName'>admin_user</Data>
    <Data Name='SubjectDomainName'>MINISOC</Data>
    <Data Name='SubjectLogonId'>0x12345</Data>
</EventData>
</Event>"""

SAMPLE_7045_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
    <Provider Name='Service Control Manager'/>
    <EventID>7045</EventID>
    <TimeCreated SystemTime='2026-11-07T08:15:00.2500000Z'/>
    <EventRecordID>50001</EventRecordID>
    <Channel>System</Channel>
    <Computer>SEC-WORKSTATION</Computer>
</System>
<EventData>
    <Data Name='ServiceName'>TestBackdoorService</Data>
    <Data Name='ImagePath'>C:\\Windows\\Temp\\backdoor.exe</Data>
    <Data Name='ServiceType'>user mode service</Data>
    <Data Name='StartType'>auto start</Data>
    <Data Name='AccountName'>LocalSystem</Data>
</EventData>
</Event>"""


def test_parse_event_xml_success() -> None:
    """Test parsing well-formed Windows Event XML strings."""
    parsed = parse_event_xml(SAMPLE_4624_XML)
    assert parsed is not None
    assert parsed["event_id"] == 4624
    assert parsed["record_id"] == 10001
    assert parsed["channel"] == "Security"
    assert parsed["computer"] == "SEC-WORKSTATION"
    assert parsed["system_time"] == "2026-11-07T08:00:00.1234567Z"
    assert parsed["event_data"]["TargetUserName"] == "analyst"
    assert parsed["event_data"]["LogonType"] == "2"


def test_parse_event_xml_malformed_and_incomplete() -> None:
    """Test that malformed or incomplete XML strings return None safely."""
    # Invalid XML syntax
    assert parse_event_xml("<Event><System><broken>") is None

    # Missing System header
    assert parse_event_xml("<Event><EventData></EventData></Event>") is None

    # Missing EventID
    assert parse_event_xml("<Event><System><Channel>System</Channel></System></Event>") is None

    # Non-integer EventID
    assert parse_event_xml("<Event><System><EventID>NOT_AN_ID</EventID></System></Event>") is None


def test_event_id_mappings_and_normalization() -> None:
    """Test mapping and normalization of all 4 supported event IDs."""
    # 4624 - Successful logon
    e4624 = normalize_event(parse_event_xml(SAMPLE_4624_XML))  # type: ignore[arg-type]
    assert e4624.event_type == "windows_logon_success"
    assert e4624.category == EventCategory.AUTHENTICATION
    assert e4624.severity == EventSeverity.INFO
    assert "analyst" in e4624.description
    assert e4624.attributes["windows_event_id"] == 4624
    assert e4624.attributes["account_name"] == "analyst"
    assert e4624.attributes["logon_type"] == "2"
    assert e4624.attributes["source_ip"] == "127.0.0.1"

    # 4625 - Failed logon
    e4625 = normalize_event(parse_event_xml(SAMPLE_4625_XML))  # type: ignore[arg-type]
    assert e4625.event_type == "windows_logon_failed"
    assert e4625.category == EventCategory.AUTHENTICATION
    assert e4625.severity == EventSeverity.MEDIUM
    assert "bad_actor" in e4625.description
    assert e4625.attributes["status"] == "0xC000006D"
    assert e4625.attributes["source_ip"] == "192.168.1.100"

    # 1102 - Security audit log cleared
    e1102 = normalize_event(parse_event_xml(SAMPLE_1102_XML))  # type: ignore[arg-type]
    assert e1102.event_type == "windows_audit_log_cleared"
    assert e1102.category == EventCategory.SYSTEM
    assert e1102.severity == EventSeverity.HIGH
    assert "admin_user" in e1102.description
    assert e1102.attributes["account_name"] == "admin_user"

    # 7045 - New service installed
    e7045 = normalize_event(parse_event_xml(SAMPLE_7045_XML))  # type: ignore[arg-type]
    assert e7045.event_type == "windows_service_installed"
    assert e7045.category == EventCategory.SYSTEM
    assert e7045.severity == EventSeverity.MEDIUM
    assert "TestBackdoorService" in e7045.description
    assert e7045.attributes["service_name"] == "TestBackdoorService"
    assert e7045.attributes["image_path"] == "C:\\Windows\\Temp\\backdoor.exe"


def test_utc_timestamp_conversion() -> None:
    """Test that event timestamps are normalized to UTC with timezone awareness."""
    e = normalize_event(parse_event_xml(SAMPLE_4624_XML))  # type: ignore[arg-type]
    assert e.timestamp.tzinfo is not None
    assert str(e.timestamp.tzinfo) == "UTC"
    assert e.timestamp.hour == 8
    assert e.timestamp.minute == 0


def test_missing_optional_event_fields() -> None:
    """Test that records with sparse EventData still normalize cleanly."""
    sparse_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <EventID>7045</EventID>
        <TimeCreated SystemTime='2026-11-07T08:20:00Z'/>
        <EventRecordID>50002</EventRecordID>
        <Channel>System</Channel>
        <Computer>MINISOC-PC</Computer>
    </System>
    <EventData>
        <Data Name='ServiceName'>BareService</Data>
    </EventData>
    </Event>"""

    parsed = parse_event_xml(sparse_xml)
    assert parsed is not None
    event = normalize_event(parsed)
    assert event.attributes["service_name"] == "BareService"
    assert event.attributes["image_path"] == "unknown"


def test_duplicate_prevention_within_session() -> None:
    """Test that repeated processing of the same XML record within a session does not create duplicates."""
    collector = WindowsEventCollector()

    # Cycle 1: process 2 events
    events1 = collector.process_xml_records("Security", [SAMPLE_4624_XML, SAMPLE_4625_XML])
    assert len(events1) == 2

    # Cycle 2: identical records fed again -> 0 new events
    events2 = collector.process_xml_records("Security", [SAMPLE_4624_XML, SAMPLE_4625_XML])
    assert len(events2) == 0

    # Cycle 3: new record with higher record ID -> 1 new event
    events3 = collector.process_xml_records("Security", [SAMPLE_1102_XML])
    assert len(events3) == 1


def test_duplicate_prevention_across_restarts(tmp_path: Path) -> None:
    """Test that checkpoints saved to SQLite prevent duplicate imports across collector restarts."""
    db_file = tmp_path / "checkpoint_test.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    checkpoint_repo = CheckpointRepository(manager)
    event_repo = EventRepository(manager)

    # First instance runs and processes records up to 10002
    collector_instance_1 = WindowsEventCollector(
        repository=event_repo,
        checkpoint_repo=checkpoint_repo,
    )
    events1 = collector_instance_1.process_xml_records("Security", [SAMPLE_4624_XML, SAMPLE_4625_XML])
    assert len(events1) == 2
    assert event_repo.count_events() == 2
    assert checkpoint_repo.get_checkpoint("Security") == 10002

    # Second instance starts fresh (simulating application restart)
    collector_instance_2 = WindowsEventCollector(
        repository=event_repo,
        checkpoint_repo=checkpoint_repo,
    )
    # Feed same records plus one new record
    events2 = collector_instance_2.process_xml_records("Security", [SAMPLE_4624_XML, SAMPLE_4625_XML, SAMPLE_1102_XML])

    # Only SAMPLE_1102_XML (record 10003) should be imported
    assert len(events2) == 1
    assert events2[0].attributes["record_id"] == 10003
    assert event_repo.count_events() == 3
    assert checkpoint_repo.get_checkpoint("Security") == 10003


def test_permission_denied_handling() -> None:
    """Test that AccessDenied when querying a restricted channel does not crash the collector."""
    collector = WindowsEventCollector()

    # Mock win32evtlog.EvtQuery raising Access Denied
    with patch("src.collectors.windows_event_collector.HAS_WIN32EVTLOG", True), \
         patch("src.collectors.windows_event_collector.win32evtlog.EvtQuery", side_effect=PermissionError("Access is denied")):
        events = collector._collect_channel("Security", [4624, 4625])
        assert events == []


def test_event_repository_persistence(tmp_path: Path) -> None:
    """Test full pipeline persistence from XML processing to EventRepository."""
    db_file = tmp_path / "persist_test.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    repo = EventRepository(manager)

    collector = WindowsEventCollector(
        repository=repo,
        channels={"System": [7045]},
    )

    with patch("src.collectors.windows_event_collector.HAS_WIN32EVTLOG", True), \
         patch("src.collectors.windows_event_collector.win32evtlog.EvtQuery", return_value=123), \
         patch("src.collectors.windows_event_collector.win32evtlog.EvtNext", return_value=[456]), \
         patch("src.collectors.windows_event_collector.win32evtlog.EvtRender", return_value=SAMPLE_7045_XML):
        events = collector.collect_events()

    assert len(events) == 1
    assert repo.count_events() == 1

    stored = repo.get_event(events[0].event_id)
    assert stored is not None
    assert stored.event_type == "windows_service_installed"
    assert stored.attributes["service_name"] == "TestBackdoorService"


def test_atomic_transaction_rollback_preserves_checkpoint_and_events(tmp_path: Path) -> None:
    """Test that failure to insert an event rolls back both event persistence and checkpoint advancement."""
    import sqlite3
    from src.core.events import SecurityEvent, EventCategory

    db_file = tmp_path / "atomic_test.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    repo = EventRepository(manager)
    checkpoint_repo = CheckpointRepository(manager)

    # Establish an initial checkpoint
    checkpoint_repo.set_checkpoint("Security", 5000)
    assert checkpoint_repo.get_checkpoint("Security") == 5000

    collector = WindowsEventCollector(
        repository=repo,
        checkpoint_repo=checkpoint_repo,
    )

    # Pre-insert an existing event to trigger a primary key collision
    base_event = SecurityEvent(
        source="windows_event_log",
        category=EventCategory.AUTHENTICATION,
        event_type="windows_logon_success",
        description="Base event",
    )
    repo.add_event(base_event)
    assert repo.count_events() == 1

    # Mock normalize_event to return an event with the duplicate event_id
    duplicate_event = SecurityEvent(
        event_id=base_event.event_id,
        source="windows_event_log",
        category=EventCategory.AUTHENTICATION,
        event_type="windows_logon_failed",
        description="Colliding event",
    )

    with patch("src.collectors.windows_event_collector.normalize_event", return_value=duplicate_event):
        with pytest.raises(sqlite3.IntegrityError):
            collector.process_xml_records("Security", [SAMPLE_4624_XML])

    # Assert transaction was rolled back:
    # 1. Total events in DB remains 1
    assert repo.count_events() == 1
    # 2. Checkpoint remains at 5000, NOT advanced to 10001
    assert checkpoint_repo.get_checkpoint("Security") == 5000
    # 3. In-memory checkpoint did not advance
    assert collector.get_checkpoint("Security") == 5000


def test_malformed_event_does_not_skip_subsequent_valid_events(tmp_path: Path) -> None:
    """Test that encountering a malformed XML record does not interrupt subsequent valid records."""
    db_file = tmp_path / "malformed_resilience.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    repo = EventRepository(manager)
    checkpoint_repo = CheckpointRepository(manager)

    collector = WindowsEventCollector(repository=repo, checkpoint_repo=checkpoint_repo)

    records = [
        SAMPLE_4624_XML,           # Record 10001 (Valid)
        "<Event><broken-xml-data>", # Malformed
        SAMPLE_4625_XML,           # Record 10002 (Valid)
    ]

    events = collector.process_xml_records("Security", records)

    # Both valid events must be successfully extracted and persisted
    assert len(events) == 2
    assert events[0].attributes["record_id"] == 10001
    assert events[1].attributes["record_id"] == 10002
    assert repo.count_events() == 2
    # Checkpoint must advance to the highest valid record (10002)
    assert checkpoint_repo.get_checkpoint("Security") == 10002


def test_collection_limits_do_not_advance_checkpoint_beyond_persisted_events(tmp_path: Path) -> None:
    """Test that collection limit truncations advance the checkpoint only to the highest persisted record."""
    db_file = tmp_path / "limit_test.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    repo = EventRepository(manager)
    checkpoint_repo = CheckpointRepository(manager)

    collector = WindowsEventCollector(repository=repo, checkpoint_repo=checkpoint_repo)

    # Only feed the first event (simulating a collection limit of 1)
    events = collector.process_xml_records("Security", [SAMPLE_4624_XML])

    assert len(events) == 1
    assert events[0].attributes["record_id"] == 10001
    # Checkpoint must be exactly 10001, never anticipating future records
    assert checkpoint_repo.get_checkpoint("Security") == 10001


def test_event_log_rollover_reset_handling() -> None:
    """Test that event log rollover or clear (record ID reset) resets the checkpoint safely."""
    collector = WindowsEventCollector()

    # Artificially set a high checkpoint
    collector.set_checkpoint("System", 500000)
    assert collector.get_checkpoint("System") == 500000

    # Mock _is_channel_reset to report that the newest record in channel is 100 (< 500000)
    with patch.object(collector, "_is_channel_reset", return_value=True), \
         patch("src.collectors.windows_event_collector.HAS_WIN32EVTLOG", True), \
         patch("src.collectors.windows_event_collector.win32evtlog.EvtQuery", return_value=999), \
         patch("src.collectors.windows_event_collector.win32evtlog.EvtNext", return_value=[123]), \
         patch("src.collectors.windows_event_collector.win32evtlog.EvtRender", return_value=SAMPLE_7045_XML):
        events = collector._collect_channel("System", [7045])

    # Rollover was detected, checkpoint reset, and records collected
    assert len(events) == 1
    assert events[0].attributes["record_id"] == 50001
