"""Automated tests for SQLite persistence, connection management, schema, and repository."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import uuid

import pytest

from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.database.connection import DatabaseManager, migrate_legacy_database
from src.database.event_repository import EventRepository
from src.database.incident_repository import IncidentRepository
from src.database.schema import CURRENT_SCHEMA_VERSION, get_current_schema_version, initialize_database
from src.incidents.manager import IncidentManager
from src.incidents.models import Incident


@pytest.fixture
def temp_db_manager(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized DatabaseManager in an isolated temporary directory."""
    db_file = tmp_path / "test_minisoc.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    return manager


@pytest.fixture
def event_repo(temp_db_manager: DatabaseManager) -> EventRepository:
    """Fixture providing an EventRepository backed by a temporary initialized database."""
    return EventRepository(temp_db_manager)


def test_database_initialization(tmp_path: Path) -> None:
    """Test that database schema and indexes are created properly upon initialization."""
    db_file = tmp_path / "init_test.db"
    manager = DatabaseManager(db_path=db_file)

    version = initialize_database(manager)
    assert version == CURRENT_SCHEMA_VERSION

    with manager.get_connection() as conn:
        assert get_current_schema_version(conn) == CURRENT_SCHEMA_VERSION

        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        tables = [row["name"] for row in cursor.fetchall()]
        assert "schema_version" in tables
        assert "security_events" in tables

        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name;")
        indexes = [row["name"] for row in cursor.fetchall()]
        assert "idx_security_events_timestamp" in indexes
        assert "idx_security_events_severity" in indexes
        assert "idx_security_events_source" in indexes
        assert "idx_security_events_event_type" in indexes


def test_database_backup_is_consistent_and_does_not_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    manager = DatabaseManager(source)
    initialize_database(manager)
    repository = EventRepository(manager)
    repository.add_event(
        SecurityEvent(
            source="test",
            category=EventCategory.SYSTEM,
            event_type="backup_test",
            severity=EventSeverity.INFO,
            description="Backup evidence",
        )
    )

    destination = tmp_path / "backups" / "snapshot.db"
    assert manager.backup_to(destination) == destination.resolve()
    backup_manager = DatabaseManager(destination)
    assert EventRepository(backup_manager).count_events() == 1
    with pytest.raises(FileExistsError):
        manager.backup_to(destination)


def test_legacy_database_migration_copies_and_preserves_source(tmp_path: Path) -> None:
    legacy = tmp_path / "project" / "data" / "minisoc.db"
    legacy.parent.mkdir(parents=True)
    old_manager = DatabaseManager(legacy)
    initialize_database(old_manager)
    EventRepository(old_manager).add_event(
        SecurityEvent(
            source="test",
            category=EventCategory.SYSTEM,
            event_type="legacy_test",
            severity=EventSeverity.INFO,
            description="Existing evidence",
        )
    )

    destination = tmp_path / "local-app-data" / "minisoc.db"
    assert migrate_legacy_database(legacy, destination) == destination.resolve()
    assert legacy.exists()
    assert EventRepository(DatabaseManager(legacy)).count_events() == 1
    assert EventRepository(DatabaseManager(destination)).count_events() == 1
    assert migrate_legacy_database(legacy, destination) is None


def test_in_memory_database_persists_across_repository_connections() -> None:
    manager = DatabaseManager(":memory:")
    initialize_database(manager)
    repository = EventRepository(manager)
    event = SecurityEvent(
        source="test",
        category=EventCategory.SYSTEM,
        event_type="memory_test",
        description="shared in-memory database",
    )

    repository.add_event(event)

    assert repository.get_event(event.event_id) is not None
    assert repository.count_events() == 1
    manager.close()


def test_repeated_initialization_without_data_loss(event_repo: EventRepository, temp_db_manager: DatabaseManager) -> None:
    """Test that repeated initialization runs idempotently without corrupting or deleting data."""
    sample_event = SecurityEvent(
        source="system",
        category=EventCategory.SYSTEM,
        event_type="test_idempotency",
        description="Event before re-initialization",
    )
    event_repo.add_event(sample_event)
    assert event_repo.count_events() == 1

    # Re-run initialization multiple times
    version1 = initialize_database(temp_db_manager)
    version2 = initialize_database(temp_db_manager)

    assert version1 == CURRENT_SCHEMA_VERSION
    assert version2 == CURRENT_SCHEMA_VERSION
    assert event_repo.count_events() == 1

    retrieved = event_repo.get_event(sample_event.event_id)
    assert retrieved is not None
    assert retrieved.description == "Event before re-initialization"


def test_single_event_insertion_and_retrieval(event_repo: EventRepository) -> None:
    """Test adding a single event and retrieving it by event_id."""
    event = SecurityEvent(
        source="host_sensor",
        category=EventCategory.PROCESS,
        event_type="process_started",
        severity=EventSeverity.HIGH,
        host="SEC-NODE-01",
        description="Unusual process execution detected",
        attributes={"pid": 4096, "cmd": "whoami.exe"},
    )

    event_repo.add_event(event)

    retrieved = event_repo.get_event(event.event_id)
    assert retrieved is not None
    assert retrieved.event_id == event.event_id
    assert retrieved.source == "host_sensor"
    assert retrieved.category == EventCategory.PROCESS
    assert retrieved.event_type == "process_started"
    assert retrieved.severity == EventSeverity.HIGH
    assert retrieved.host == "SEC-NODE-01"
    assert retrieved.description == "Unusual process execution detected"
    assert retrieved.attributes == {"pid": 4096, "cmd": "whoami.exe"}
    assert retrieved.schema_version == "1.0"


def test_multiple_event_insertion(event_repo: EventRepository) -> None:
    """Test inserting multiple events in a single batch transaction."""
    events = [
        SecurityEvent(
            source=f"source_{i}",
            category=EventCategory.NETWORK,
            event_type=f"network_flow_{i}",
            description=f"Flow description {i}",
        )
        for i in range(5)
    ]

    event_repo.add_events(events)
    assert event_repo.count_events() == 5

    retrieved_list = event_repo.list_events()
    assert len(retrieved_list) == 5

    # Empty batch should do nothing safely
    event_repo.add_events([])
    assert event_repo.count_events() == 5


def test_missing_event_handling(event_repo: EventRepository) -> None:
    """Test that requesting a non-existent event returns None without errors."""
    non_existent_uuid = uuid.uuid4()
    assert event_repo.get_event(non_existent_uuid) is None
    assert event_repo.get_event("00000000-0000-0000-0000-000000000000") is None


def test_timestamp_filtering(event_repo: EventRepository) -> None:
    """Test querying events with start and end timestamp filters."""
    t1 = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 7, 11, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)

    e1 = SecurityEvent(timestamp=t1, source="src", category=EventCategory.SYSTEM, event_type="e1", description="desc1")
    e2 = SecurityEvent(timestamp=t2, source="src", category=EventCategory.SYSTEM, event_type="e2", description="desc2")
    e3 = SecurityEvent(timestamp=t3, source="src", category=EventCategory.SYSTEM, event_type="e3", description="desc3")

    event_repo.add_events([e1, e2, e3])

    # Filter >= t2
    after_t2 = event_repo.list_events(start_time=t2)
    assert [e.event_id for e in after_t2] == [e3.event_id, e2.event_id]

    # Filter <= t2
    before_t2 = event_repo.list_events(end_time=t2)
    assert [e.event_id for e in before_t2] == [e2.event_id, e1.event_id]

    # Filter range [t1, t2]
    range_events = event_repo.list_events(start_time=t1, end_time=t2)
    assert [e.event_id for e in range_events] == [e2.event_id, e1.event_id]

    # Rejection of naive filter timestamps
    with pytest.raises(ValueError, match="must be timezone-aware"):
        event_repo.list_events(start_time=datetime(2026, 11, 7, 10, 0, 0))


def test_severity_filtering(event_repo: EventRepository) -> None:
    """Test querying events filtered by severity."""
    e_info = SecurityEvent(source="src", category=EventCategory.SYSTEM, event_type="t", severity=EventSeverity.INFO, description="d")
    e_high = SecurityEvent(source="src", category=EventCategory.SYSTEM, event_type="t", severity=EventSeverity.HIGH, description="d")
    e_crit = SecurityEvent(source="src", category=EventCategory.SYSTEM, event_type="t", severity=EventSeverity.CRITICAL, description="d")

    event_repo.add_events([e_info, e_high, e_crit])

    high_events = event_repo.list_events(severity=EventSeverity.HIGH)
    assert len(high_events) == 1
    assert high_events[0].event_id == e_high.event_id

    # String-based case-insensitive severity filter
    crit_events = event_repo.list_events(severity="critical")
    assert len(crit_events) == 1
    assert crit_events[0].event_id == e_crit.event_id

    assert event_repo.count_events(severity=EventSeverity.CRITICAL) == 1
    assert event_repo.count_events(severity=EventSeverity.LOW) == 0


def test_source_filtering(event_repo: EventRepository) -> None:
    """Test querying events filtered by event source."""
    e_sysmon = SecurityEvent(source="sysmon", category=EventCategory.PROCESS, event_type="p", description="d")
    e_winevt = SecurityEvent(source="windows_event_log", category=EventCategory.SYSTEM, event_type="s", description="d")

    event_repo.add_events([e_sysmon, e_winevt])

    sysmon_events = event_repo.list_events(source="sysmon")
    assert len(sysmon_events) == 1
    assert sysmon_events[0].event_id == e_sysmon.event_id

    assert event_repo.count_events(source="windows_event_log") == 1
    assert event_repo.count_events(source="unknown_src") == 0


def test_event_type_filtering(event_repo: EventRepository) -> None:
    """Test querying events filtered by specific event type."""
    e1 = SecurityEvent(source="s", category=EventCategory.NETWORK, event_type="dns_query", description="d")
    e2 = SecurityEvent(source="s", category=EventCategory.NETWORK, event_type="tcp_connect", description="d")

    event_repo.add_events([e1, e2])

    dns_events = event_repo.list_events(event_type="dns_query")
    assert len(dns_events) == 1
    assert dns_events[0].event_id == e1.event_id


def test_result_limits(event_repo: EventRepository) -> None:
    """Test query limit parameter and error handling on negative limit."""
    events = [
        SecurityEvent(
            source="s",
            category=EventCategory.SYSTEM,
            event_type="t",
            description=f"desc {i}",
        )
        for i in range(10)
    ]
    event_repo.add_events(events)

    limited = event_repo.list_events(limit=3)
    assert len(limited) == 3

    zero_limited = event_repo.list_events(limit=0)
    assert len(zero_limited) == 0

    with pytest.raises(ValueError, match="limit must be non-negative"):
        event_repo.list_events(limit=-5)


def test_event_repository_pages_through_records_beyond_first_page(
    event_repo: EventRepository,
) -> None:
    events = [
        SecurityEvent(
            source="paging_test",
            category=EventCategory.SYSTEM,
            event_type="paging_event",
            description=f"page record {index}",
        )
        for index in range(525)
    ]
    event_repo.add_events(events)

    first_page = event_repo.list_events(limit=100, offset=0)
    later_page = event_repo.list_events(limit=100, offset=500)

    assert len(first_page) == 100
    assert len(later_page) == 25
    assert not {event.event_id for event in first_page}.intersection(
        event.event_id for event in later_page
    )
    assert event_repo.count_events(event_type="paging_event") == 525

    with pytest.raises(ValueError, match="offset must be non-negative"):
        event_repo.list_events(limit=10, offset=-1)


def test_transaction_rollback_when_insertion_fails(event_repo: EventRepository) -> None:
    """Test that a batch insertion failure triggers transaction rollback without committing partial records."""
    base_event = SecurityEvent(source="s", category=EventCategory.SYSTEM, event_type="base", description="base")
    event_repo.add_event(base_event)
    assert event_repo.count_events() == 1

    # Create batch where the second event causes IntegrityError (duplicate primary key of base_event)
    new_event1 = SecurityEvent(source="s", category=EventCategory.SYSTEM, event_type="batch1", description="batch1")
    duplicate_event = SecurityEvent(
        event_id=base_event.event_id,
        source="s",
        category=EventCategory.SYSTEM,
        event_type="duplicate",
        description="duplicate id",
    )

    with pytest.raises(sqlite3.IntegrityError):
        event_repo.add_events([new_event1, duplicate_event])

    # Count must remain exactly 1; new_event1 must NOT have been committed
    assert event_repo.count_events() == 1
    assert event_repo.get_event(new_event1.event_id) is None


def test_preservation_of_event_attributes_and_timestamps(event_repo: EventRepository) -> None:
    """Test that complex nested attributes and timezone-normalized timestamps are preserved faithfully."""
    tz_custom = timezone(timedelta(hours=5, minutes=30))
    event_time = datetime(2026, 11, 7, 18, 45, 30, tzinfo=tz_custom)

    complex_attributes = {
        "network": {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "ports": [443, 8443],
        },
        "flags": ["anomalous", "beaconing"],
        "score": 87.5,
        "is_internal": False,
    }

    event = SecurityEvent(
        timestamp=event_time,
        source="network_ids",
        category=EventCategory.NETWORK,
        event_type="beacon_detected",
        severity=EventSeverity.CRITICAL,
        description="Periodic beaconing traffic detected",
        attributes=complex_attributes,
    )

    event_repo.add_event(event)

    retrieved = event_repo.get_event(event.event_id)
    assert retrieved is not None
    assert retrieved.attributes == complex_attributes
    assert retrieved.timestamp.tzinfo == timezone.utc
    assert retrieved.timestamp == event.timestamp
    assert retrieved.severity == EventSeverity.CRITICAL


def test_database_creation_in_temporary_directory(tmp_path: Path) -> None:
    """Test database manager creates nested missing directories safely on demand."""
    nested_dir = tmp_path / "deeply" / "nested" / "storage"
    db_file = nested_dir / "minisoc.db"

    assert not nested_dir.exists()

    manager = DatabaseManager(db_path=db_file)
    assert nested_dir.exists()
    assert nested_dir.is_dir()

    initialize_database(manager)
    assert db_file.exists()
    assert db_file.is_file()


def test_checkpoint_repository(temp_db_manager: DatabaseManager) -> None:
    """Test CheckpointRepository get, set, and monotonic update behavior."""
    from src.database.checkpoint_repository import CheckpointRepository

    repo = CheckpointRepository(temp_db_manager)

    # Initial get should return None
    assert repo.get_checkpoint("Security") is None
    assert repo.list_checkpoints() == {}

    # Set checkpoint
    repo.set_checkpoint("Security", 100)
    assert repo.get_checkpoint("Security") == 100

    # Advance checkpoint
    repo.set_checkpoint("Security", 150)
    assert repo.get_checkpoint("Security") == 150

    # Setting a lower checkpoint should not regress due to MAX()
    repo.set_checkpoint("Security", 120)
    assert repo.get_checkpoint("Security") == 150

    # Track multiple channels
    repo.set_checkpoint("System", 500)
    checkpoints = repo.list_checkpoints()
    assert checkpoints == {"Security": 150, "System": 500}


def test_incident_repository_persistence(temp_db_manager: DatabaseManager) -> None:
    """Test incident persistence to SQLite and retrieval by incident_id."""
    incident_repo = IncidentRepository(temp_db_manager)
    manager = IncidentManager(repository=incident_repo)

    incident = Incident(
        incident_id="inc-123",
        title="Suspicious outbound connection",
        description="Outbound connection observed to a risky port",
        severity=EventSeverity.HIGH,
        source="network_collector",
        related_event_ids=["evt-1", "evt-2"],
        attributes={"rule_name": "suspicious_network", "remote_port": 8443},
    )

    incident_repo.add_incident(incident)

    retrieved = incident_repo.get_incident("inc-123")
    assert retrieved is not None
    assert retrieved.title == incident.title
    assert retrieved.severity == EventSeverity.HIGH
    assert retrieved.attributes["remote_port"] == 8443

    created = manager.create_from_alert(
        type("MockAlert", (), {
            "title": "Suspicious process observed",
            "description": "Process started that matches a suspicious tool list",
            "severity": EventSeverity.HIGH,
            "source": "process_collector",
            "related_event_ids": ["evt-3"],
            "attributes": {"pid": 1234, "name": "rundll32.exe"},
            "rule_name": "suspicious_process",
        })()
    )
    assert created.incident_id in {inc.incident_id for inc in manager.incidents}
    assert created.incident_id == incident_repo.get_incident(created.incident_id).incident_id


def test_incident_repository_pages_without_truncating_history(
    temp_db_manager: DatabaseManager,
) -> None:
    repository = IncidentRepository(temp_db_manager)
    incidents = [
        Incident(
            incident_id=f"incident-page-{index:04}",
            title=f"Incident {index}",
            description="Paging test",
            severity=EventSeverity.LOW,
            alert_key=f"paging-alert-{index:04}",
        )
        for index in range(525)
    ]
    repository.add_incidents(incidents)

    first_page = repository.list_incidents(limit=100, offset=0)
    later_page = repository.list_incidents(limit=100, offset=500)

    assert len(first_page) == 100
    assert len(later_page) == 25
    assert not {incident.incident_id for incident in first_page}.intersection(
        incident.incident_id for incident in later_page
    )
    assert repository.count_incidents() == 525

    manager = IncidentManager(repository=repository)
    assert len(manager.hydrate_from_repository(limit=100, offset=500)) == 25
    assert manager.count_incidents() == 525
    with pytest.raises(ValueError, match="offset must be non-negative"):
        repository.list_incidents(limit=10, offset=-1)


def test_incident_add_is_idempotent_for_alert_key(temp_db_manager: DatabaseManager) -> None:
    repository = IncidentRepository(temp_db_manager)
    incident = Incident(
        incident_id="incident-first",
        title="Detection",
        description="Evidence",
        severity=EventSeverity.HIGH,
        alert_key="stable-alert",
    )
    repository.add_incident(incident)
    duplicate = Incident(
        incident_id="incident-second",
        title="Duplicate",
        description="Repeated scan",
        severity=EventSeverity.HIGH,
        alert_key="stable-alert",
    )

    repository.add_incident(duplicate)

    assert repository.get_incident_by_alert_key("stable-alert").incident_id == "incident-first"
    assert len(repository.list_incidents()) == 1


def test_incident_manager_reuses_persisted_alert_case(temp_db_manager: DatabaseManager) -> None:
    from src.detection.rules import DetectionAlert

    repository = IncidentRepository(temp_db_manager)
    alert = DetectionAlert(
        rule_name="test_rule",
        title="Detection",
        description="Repeated scan",
        severity=EventSeverity.HIGH,
        source="test",
        related_event_ids=["event-1"],
    )
    first_manager = IncidentManager(repository=repository)
    first_incident = first_manager.create_from_alert(alert)
    restarted_manager = IncidentManager(repository=repository)
    restarted_manager.hydrate_from_repository()

    reused_incident = restarted_manager.create_from_alert(alert)

    assert reused_incident.incident_id == first_incident.incident_id
    assert len(repository.list_incidents()) == 1


def test_incident_notes_and_status_persist_and_invalid_status_is_rejected(temp_db_manager: DatabaseManager) -> None:
    repository = IncidentRepository(temp_db_manager)
    manager = IncidentManager(repository=repository)
    incident = Incident(
        incident_id="incident-state",
        title="Incident",
        description="Evidence",
        severity=EventSeverity.HIGH,
    )
    repository.add_incident(incident)
    manager.hydrate_from_repository()

    assert manager.add_note("incident-state", "Investigated process lineage")
    assert manager.update_status("incident-state", "investigating")
    with pytest.raises(ValueError, match="Invalid incident status"):
        manager.update_status("incident-state", "closed")

    saved = repository.get_incident("incident-state")
    assert saved.status == "investigating"
    assert saved.notes == ["Investigated process lineage"]


def test_event_retention_deletes_only_events_older_than_cutoff(event_repo: EventRepository) -> None:
    old_event = SecurityEvent(
        timestamp=datetime.now(timezone.utc) - timedelta(days=91),
        source="test",
        category=EventCategory.SYSTEM,
        event_type="old",
        description="old event",
    )
    recent_event = SecurityEvent(
        timestamp=datetime.now(timezone.utc) - timedelta(days=89),
        source="test",
        category=EventCategory.SYSTEM,
        event_type="recent",
        description="recent event",
    )
    event_repo.add_events([old_event, recent_event])

    removed = event_repo.delete_events_before(datetime.now(timezone.utc) - timedelta(days=90))

    assert removed == 1
    assert event_repo.get_event(old_event.event_id) is None
    assert event_repo.get_event(recent_event.event_id) is not None


def test_alert_review_state_survives_repository_recreation(temp_db_manager: DatabaseManager) -> None:
    from src.database.alert_state_repository import AlertStateRepository

    repository = AlertStateRepository(temp_db_manager)
    repository.set_reviewed("stable-alert-key", True)

    restarted_repository = AlertStateRepository(temp_db_manager)
    assert restarted_repository.list_reviewed_keys() == {"stable-alert-key"}
    restarted_repository.set_reviewed("stable-alert-key", False)
    assert restarted_repository.list_reviewed_keys() == set()
