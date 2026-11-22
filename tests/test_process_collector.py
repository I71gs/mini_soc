"""Automated unit tests for the Windows Process Collector."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import psutil
import pytest

from src.collectors.process_collector import ProcessCollector, ProcessInfo
from src.core.events import EventCategory, EventSeverity
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.schema import initialize_database


def _create_mock_process(
    pid: int,
    name: str = "test.exe",
    create_time: float = 1700000000.0,
    exe: str | None = "C:\\Windows\\test.exe",
    username: str | None = "DOMAIN\\User",
) -> MagicMock:
    """Helper to create a configured mock psutil.Process."""
    proc = MagicMock(spec=psutil.Process)
    proc.pid = pid
    proc.name.return_value = name
    proc.create_time.return_value = create_time
    proc.exe.return_value = exe
    proc.username.return_value = username
    proc.cmdline.return_value = []
    return proc


def test_successful_process_enumeration() -> None:
    """Test process snapshot creation with all metadata fields available."""
    mock_p1 = _create_mock_process(101, "app.exe", 1700000001.0, "C:\\App\\app.exe", "USER-1")
    mock_p2 = _create_mock_process(102, "service.exe", 1700000002.0, "C:\\Svc\\service.exe", "SYSTEM")

    with patch("psutil.process_iter", return_value=[mock_p1, mock_p2]):
        collector = ProcessCollector()
        snapshot = collector.get_snapshot()

    assert len(snapshot) == 2
    assert snapshot[0].pid == 101
    assert snapshot[0].name == "app.exe"
    assert snapshot[0].exe == "C:\\App\\app.exe"
    assert snapshot[0].username == "USER-1"
    assert snapshot[0].create_time == 1700000001.0

    assert snapshot[1].pid == 102
    assert snapshot[1].name == "service.exe"


def test_missing_or_inaccessible_process_information() -> None:
    """Test graceful handling when processes terminate or raise AccessDenied for optional fields."""
    # Process 1: AccessDenied on exe and username
    mock_denied = _create_mock_process(201, "protected.exe", 1700000010.0)
    mock_denied.exe.side_effect = psutil.AccessDenied(201)
    mock_denied.username.side_effect = psutil.AccessDenied(201)

    # Process 2: NoSuchProcess when accessing basic properties (vanished mid-iteration)
    mock_vanished = MagicMock(spec=psutil.Process)
    mock_vanished.pid = 202
    mock_vanished.name.side_effect = psutil.NoSuchProcess(202)

    # Process 3: ZombieProcess
    mock_zombie = MagicMock(spec=psutil.Process)
    mock_zombie.pid = 203
    mock_zombie.name.side_effect = psutil.ZombieProcess(203)

    with patch("psutil.process_iter", return_value=[mock_denied, mock_vanished, mock_zombie]):
        collector = ProcessCollector()
        snapshot = collector.get_snapshot()

    # Vanished and zombie processes are skipped; protected process is preserved with None for restricted fields
    assert len(snapshot) == 1
    assert snapshot[0].pid == 201
    assert snapshot[0].name == "protected.exe"
    assert snapshot[0].exe is None
    assert snapshot[0].username is None
    assert collector.permission_denied_count == 1


def test_access_denied_basic_metadata_counts_process_once() -> None:
    mock_process = _create_mock_process(204)
    mock_process.name.side_effect = psutil.AccessDenied(204)

    with patch("psutil.process_iter", return_value=[mock_process]):
        collector = ProcessCollector()
        snapshot = collector.get_snapshot()

    assert snapshot == []
    assert collector.permission_denied_count == 1


def test_process_start_event_generation() -> None:
    """Test SecurityEvent generation for newly observed processes."""
    mock_p1 = _create_mock_process(301, "agent.exe", 1700000020.0, "C:\\agent.exe", "Admin")

    with patch("psutil.process_iter", return_value=[mock_p1]):
        collector = ProcessCollector()
        events = collector.collect_events()

    assert len(events) == 1
    event = events[0]
    assert event.source == "process_collector"
    assert event.category == EventCategory.PROCESS
    assert event.event_type == "process_started"
    assert event.severity == EventSeverity.INFO
    assert "agent.exe" in event.description
    assert event.attributes["pid"] == 301
    assert event.attributes["name"] == "agent.exe"
    assert event.attributes["exe"] == "C:\\agent.exe"
    assert event.attributes["username"] == "Admin"
    assert event.attributes["create_time"] == 1700000020.0
    assert event.attributes["command_line"] == ""


def test_command_line_collection_redacts_common_credentials() -> None:
    mock_process = _create_mock_process(302, "powershell.exe")
    mock_process.cmdline.return_value = [
        "powershell.exe",
        "-NoProfile",
        "-enc",
        "encoded-payload",
        "--password",
        "super-secret",
    ]
    with patch("psutil.process_iter", return_value=[mock_process]):
        events = ProcessCollector().collect_events()

    command_line = events[0].attributes["command_line"]
    assert "-enc encoded-payload" in command_line
    assert "super-secret" not in command_line
    assert "[REDACTED]" in command_line


def test_no_duplicate_events_on_repeated_polls() -> None:
    """Test that repeated polling cycles do not generate duplicate events for persistent processes."""
    p1 = _create_mock_process(401, "proc1.exe", 1700000030.0)
    p2 = _create_mock_process(402, "proc2.exe", 1700000031.0)
    p3 = _create_mock_process(403, "proc3.exe", 1700000032.0)

    collector = ProcessCollector()

    # Cycle 1: p1 and p2 present
    with patch("psutil.process_iter", return_value=[p1, p2]):
        events_cycle1 = collector.collect_events()
    assert len(events_cycle1) == 2

    # Cycle 2: same p1 and p2 present -> 0 new events
    with patch("psutil.process_iter", return_value=[p1, p2]):
        events_cycle2 = collector.collect_events()
    assert len(events_cycle2) == 0

    # Cycle 3: p2 terminated, p3 started -> only p3 generates an event
    with patch("psutil.process_iter", return_value=[p1, p3]):
        events_cycle3 = collector.collect_events()
    assert len(events_cycle3) == 1
    assert events_cycle3[0].attributes["pid"] == 403


def test_pid_reuse_detection() -> None:
    """Test that PID reuse with a different create_time triggers a new process event."""
    p_orig = _create_mock_process(501, "old.exe", 1700000040.0)
    p_reused = _create_mock_process(501, "new.exe", 1700000099.0)

    collector = ProcessCollector()

    # First cycle with original process
    with patch("psutil.process_iter", return_value=[p_orig]):
        events1 = collector.collect_events()
    assert len(events1) == 1
    assert events1[0].attributes["name"] == "old.exe"

    # Second cycle with reused PID but newer create_time
    with patch("psutil.process_iter", return_value=[p_reused]):
        events2 = collector.collect_events()
    assert len(events2) == 1
    assert events2[0].attributes["name"] == "new.exe"
    assert events2[0].attributes["create_time"] == 1700000099.0


def test_process_collector_persistence_integration(tmp_path: Path) -> None:
    """Test that generated process events are persisted directly into EventRepository."""
    db_file = tmp_path / "proc_test.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    repo = EventRepository(manager)

    collector = ProcessCollector(repository=repo)

    mock_p = _create_mock_process(601, "persisted.exe", 1700000050.0)
    with patch("psutil.process_iter", return_value=[mock_p]):
        events = collector.collect_events()

    assert len(events) == 1
    assert repo.count_events() == 1

    stored_event = repo.get_event(events[0].event_id)
    assert stored_event is not None
    assert stored_event.attributes["pid"] == 601
    assert stored_event.event_type == "process_started"


def test_collector_error_handling() -> None:
    """Test that exceptions during process iteration are caught without crashing."""
    with patch("psutil.process_iter", side_effect=RuntimeError("Process table locked")):
        collector = ProcessCollector()
        snapshot = collector.get_snapshot()
        assert snapshot == []


def test_initialize_baseline() -> None:
    """Test that initialize_baseline suppresses events for pre-existing processes."""
    p1 = _create_mock_process(701, "existing.exe", 1700000060.0)

    collector = ProcessCollector()
    with patch("psutil.process_iter", return_value=[p1]):
        collector.initialize_baseline()
        events = collector.collect_events()

    assert len(events) == 0


def test_failed_snapshot_does_not_clear_process_baseline() -> None:
    process = _create_mock_process(702, "existing.exe", 1700000061.0)
    collector = ProcessCollector()
    with patch("psutil.process_iter", return_value=[process]):
        collector.initialize_baseline()

    with patch("psutil.process_iter", side_effect=RuntimeError("Process table unavailable")):
        assert collector.collect_events() == []
        assert collector.last_error == "Process table unavailable"

    with patch("psutil.process_iter", return_value=[process]):
        assert collector.collect_events() == []
