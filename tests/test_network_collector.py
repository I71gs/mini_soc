"""Automated unit tests for the Windows Network Collector and Monitor Service."""

from collections import namedtuple
from pathlib import Path
import socket
import time
from unittest.mock import MagicMock, patch
import psutil
import pytest

from src.collectors.monitor_service import HostMonitorService
from src.collectors.network_collector import NetworkCollector, NetworkConnectionInfo
from src.collectors.process_collector import ProcessCollector, ProcessInfo
from src.collectors.windows_event_collector import WindowsEventCollector
from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.database.connection import DatabaseManager
from src.database.event_repository import EventRepository
from src.database.schema import initialize_database

# Named tuple matching psutil socket address structure
MockAddr = namedtuple("MockAddr", ["ip", "port"])

# Named tuple matching psutil.net_connections return structure
MockSConn = namedtuple("MockSConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


def test_successful_network_connection_enumeration() -> None:
    """Test full parsing of active network connection with remote endpoint and PID."""
    raw_conn = MockSConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("192.168.1.50", 54321),
        raddr=MockAddr("93.184.216.34", 443),
        status="ESTABLISHED",
        pid=1234,
    )

    with patch("psutil.net_connections", return_value=[raw_conn]):
        collector = NetworkCollector()
        snapshot = collector.get_snapshot()

    assert len(snapshot) == 1
    conn = snapshot[0]
    assert conn.protocol == "tcp"
    assert conn.local_ip == "192.168.1.50"
    assert conn.local_port == 54321
    assert conn.remote_ip == "93.184.216.34"
    assert conn.remote_port == 443
    assert conn.status == "ESTABLISHED"
    assert conn.pid == 1234


def test_missing_remote_endpoints_listening_socket() -> None:
    """Test parsing of listening sockets without remote endpoints."""
    raw_conn = MockSConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("0.0.0.0", 8080),
        raddr=None,
        status="LISTEN",
        pid=5678,
    )

    with patch("psutil.net_connections", return_value=[raw_conn]):
        collector = NetworkCollector()
        snapshot = collector.get_snapshot()

    assert len(snapshot) == 1
    conn = snapshot[0]
    assert conn.protocol == "tcp"
    assert conn.local_ip == "0.0.0.0"
    assert conn.local_port == 8080
    assert conn.remote_ip is None
    assert conn.remote_port is None
    assert conn.status == "LISTEN"
    assert conn.pid == 5678


def test_missing_process_pid() -> None:
    """Test connection enumeration when the associated PID is None or inaccessible."""
    raw_conn = MockSConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_DGRAM,
        laddr=MockAddr("127.0.0.1", 53),
        raddr=None,
        status="NONE",
        pid=None,
    )

    with patch("psutil.net_connections", return_value=[raw_conn]):
        collector = NetworkCollector()
        snapshot = collector.get_snapshot()

    assert len(snapshot) == 1
    conn = snapshot[0]
    assert conn.protocol == "udp"
    assert conn.pid is None


def test_network_connection_event_generation() -> None:
    """Test SecurityEvent generation for newly observed network connections."""
    raw_conn = MockSConn(
        fd=-1,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=MockAddr("10.0.0.5", 49152),
        raddr=MockAddr("1.1.1.1", 53),
        status="ESTABLISHED",
        pid=9001,
    )

    with patch("psutil.net_connections", return_value=[raw_conn]):
        collector = NetworkCollector()
        events = collector.collect_events()

    assert len(events) == 1
    event = events[0]
    assert event.source == "network_collector"
    assert event.category == EventCategory.NETWORK
    assert event.event_type == "network_connection_observed"
    assert event.severity == EventSeverity.INFO
    assert "10.0.0.5:49152" in event.description
    assert "1.1.1.1:53" in event.description
    assert event.attributes["protocol"] == "tcp"
    assert event.attributes["local_ip"] == "10.0.0.5"
    assert event.attributes["local_port"] == 49152
    assert event.attributes["remote_ip"] == "1.1.1.1"
    assert event.attributes["remote_port"] == 53
    assert event.attributes["status"] == "ESTABLISHED"
    assert event.attributes["pid"] == 9001


def test_no_duplicate_events_on_repeated_polls() -> None:
    """Test that repeated polling cycles do not generate duplicate events for persistent connections."""
    c1 = MockSConn(-1, socket.AF_INET, socket.SOCK_STREAM, MockAddr("0.0.0.0", 80), None, "LISTEN", 100)
    c2 = MockSConn(-1, socket.AF_INET, socket.SOCK_STREAM, MockAddr("0.0.0.0", 443), None, "LISTEN", 100)
    c3 = MockSConn(-1, socket.AF_INET, socket.SOCK_STREAM, MockAddr("127.0.0.1", 5000), None, "LISTEN", 200)

    collector = NetworkCollector()

    # Cycle 1: c1 and c2 present
    with patch("psutil.net_connections", return_value=[c1, c2]):
        events1 = collector.collect_events()
    assert len(events1) == 2

    # Cycle 2: same connections present -> 0 new events
    with patch("psutil.net_connections", return_value=[c1, c2]):
        events2 = collector.collect_events()
    assert len(events2) == 0

    # Cycle 3: c2 closed, c3 opened -> only c3 generates event
    with patch("psutil.net_connections", return_value=[c1, c3]):
        events3 = collector.collect_events()
    assert len(events3) == 1
    assert events3[0].attributes["local_port"] == 5000


def test_collector_error_handling() -> None:
    """Test that AccessDenied and generic errors are safely caught."""
    # Test AccessDenied
    with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
        collector = NetworkCollector()
        assert collector.get_snapshot() == []

    # Test generic exception
    with patch("psutil.net_connections", side_effect=RuntimeError("WSAError")):
        collector = NetworkCollector()
        assert collector.get_snapshot() == []


def test_failed_snapshot_preserves_network_baseline_and_reports_health() -> None:
    connection = MockSConn(
        -1,
        socket.AF_INET,
        socket.SOCK_STREAM,
        MockAddr("10.0.0.5", 49152),
        MockAddr("1.1.1.1", 443),
        "ESTABLISHED",
        123,
    )
    collector = NetworkCollector()
    with patch("psutil.net_connections", return_value=[connection]):
        assert len(collector.collect_events()) == 1

    with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
        assert collector.collect_events() == []
        assert "Access denied" in collector.last_error

    with patch("psutil.net_connections", return_value=[connection]):
        assert collector.collect_events() == []


def test_network_collector_persistence_integration(tmp_path: Path) -> None:
    """Test that generated network events are persisted into EventRepository."""
    db_file = tmp_path / "net_test.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    repo = EventRepository(manager)

    collector = NetworkCollector(repository=repo)
    raw_conn = MockSConn(-1, socket.AF_INET, socket.SOCK_STREAM, MockAddr("127.0.0.1", 9999), None, "LISTEN", 300)

    with patch("psutil.net_connections", return_value=[raw_conn]):
        events = collector.collect_events()

    assert len(events) == 1
    assert repo.count_events() == 1

    stored = repo.get_event(events[0].event_id)
    assert stored is not None
    assert stored.attributes["local_port"] == 9999
    assert stored.category == EventCategory.NETWORK


def test_host_monitor_service_orchestration(tmp_path: Path) -> None:
    """Test orchestration of process and network collectors via HostMonitorService."""
    db_file = tmp_path / "orch_test.db"
    manager = DatabaseManager(db_path=db_file)
    initialize_database(manager)
    repo = EventRepository(manager)

    mock_proc = MagicMock(spec=psutil.Process)
    mock_proc.pid = 1111
    mock_proc.name.return_value = "orch.exe"
    mock_proc.create_time.return_value = 1700000000.0
    mock_proc.exe.return_value = "C:\\orch.exe"
    mock_proc.username.return_value = "SYSTEM"

    mock_conn = MockSConn(-1, socket.AF_INET, socket.SOCK_STREAM, MockAddr("127.0.0.1", 8088), None, "LISTEN", 1111)

    with patch("psutil.process_iter", return_value=[mock_proc]), patch("psutil.net_connections", return_value=[mock_conn]):
        service = HostMonitorService(repository=repo, poll_interval=0.1)
        events = service.collect_once()

        assert len(events) == 2
        assert repo.count_events() == 2

        # Verify background thread start and graceful stop without polling the real host.
        assert not service.is_running
        service.start()
        assert service.is_running
        time.sleep(0.05)
        service.stop(timeout=1.0)
        assert not service.is_running


def test_host_monitor_service_error_isolation() -> None:
    """Test that one failing collector does not prevent the other from completing."""
    mock_conn = MockSConn(-1, socket.AF_INET, socket.SOCK_STREAM, MockAddr("127.0.0.1", 7777), None, "LISTEN", 444)

    # Process collector fails with exception, network collector succeeds
    with patch("psutil.process_iter", side_effect=RuntimeError("Process failure")), patch("psutil.net_connections", return_value=[mock_conn]):
        service = HostMonitorService(poll_interval=1.0)
        events = service.collect_once()

    # Network collector should still have produced its event despite process failure
    assert len(events) == 1
    assert events[0].source == "network_collector"
    assert events[0].attributes["local_port"] == 7777


def test_host_monitor_service_polls_windows_events_in_background() -> None:
    event_log_collector = MagicMock(spec=WindowsEventCollector)
    event_log_collector.collect_events.return_value = []
    event_log_collector.health = MagicMock()
    service = HostMonitorService(
        poll_interval=0.01,
        windows_event_collector=event_log_collector,
    )

    service.start()
    deadline = time.monotonic() + 1.0
    while event_log_collector.collect_events.call_count == 0 and time.monotonic() < deadline:
        time.sleep(0.005)

    service.stop(timeout=1.0)

    assert event_log_collector.collect_events.call_count >= 1
    assert not service.is_running


def test_windows_event_log_failure_does_not_stop_host_collection() -> None:
    process_collector = MagicMock()
    process_collector.collect_events.return_value = []
    process_collector.last_error = None
    process_collector.permission_denied_count = 0
    host_event = SecurityEvent(
        source="network_collector",
        category=EventCategory.NETWORK,
        event_type="network_connection_observed",
        description="Observed a network connection",
    )
    network_collector = MagicMock()
    network_collector.collect_events.return_value = [host_event]
    network_collector.last_error = None
    event_log_collector = MagicMock(spec=WindowsEventCollector)
    event_log_collector.collect_events.side_effect = RuntimeError("Event Log unavailable")
    event_log_collector.health = MagicMock()
    service = HostMonitorService(
        process_collector=process_collector,
        network_collector=network_collector,
        windows_event_collector=event_log_collector,
    )

    events = service.collect_once()

    assert events == [host_event]
    event_log_collector.health.record.assert_called_once_with(0, "Event Log unavailable")


def test_partial_process_metadata_is_reported_as_limited_visibility() -> None:
    process_collector = MagicMock()
    process_collector.collect_events.return_value = []
    process_collector.last_error = None
    process_collector.permission_denied_count = 3
    network_collector = MagicMock()
    network_collector.collect_events.return_value = []
    network_collector.last_error = None
    service = HostMonitorService(
        process_collector=process_collector,
        network_collector=network_collector,
    )

    service.collect_once()

    process_health = service.health["Process Collector"]
    assert process_health.status == "healthy"
    assert process_health.last_error is None
    assert process_health.last_success_at is not None
    assert any("3 process records" in item for item in process_health.visibility_limitations)


def test_host_monitor_reports_standard_user_access_restrictions() -> None:
    with patch("psutil.process_iter", side_effect=psutil.AccessDenied(pid=4)), patch(
        "psutil.net_connections", side_effect=psutil.AccessDenied()
    ):
        service = HostMonitorService()
        service.initialize_baselines()
        service.collect_once()

    process_health = service.health["Process Collector"]
    network_health = service.health["Network Collector"]
    assert process_health.status == "degraded"
    assert process_health.last_error
    assert process_health.last_success_at is None
    assert any("active at startup" in text for text in process_health.visibility_limitations)
    assert network_health.status == "degraded"
    assert "Access denied" in (network_health.last_error or "")
    assert network_health.last_success_at is None
    assert any("active at startup" in text for text in network_health.visibility_limitations)
