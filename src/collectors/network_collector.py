"""Windows network connection telemetry collector.

Enumerates active network sockets using psutil, extracts endpoint metadata,
handles permission errors gracefully, and generates SecurityEvent records for
newly observed connections across polling cycles.
"""

from dataclasses import dataclass
import logging
import socket
from typing import Any

import psutil

from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.database.event_repository import EventRepository

logger = logging.getLogger(__name__)


def _resolve_protocol(family: int, sock_type: int) -> str:
    """Translate socket family and type integers into a readable protocol name."""
    is_ipv6 = family == getattr(socket, "AF_INET6", 23)
    suffix = "6" if is_ipv6 else ""

    if sock_type == getattr(socket, "SOCK_STREAM", 1):
        return f"tcp{suffix}"
    if sock_type == getattr(socket, "SOCK_DGRAM", 2):
        return f"udp{suffix}"
    return f"unknown{suffix}"


@dataclass(frozen=True)
class NetworkConnectionInfo:
    """Snapshot data structure representing an active network connection.

    Attributes:
        protocol: Transport protocol string (e.g., 'tcp', 'udp', 'tcp6').
        local_ip: Local network address bound to the socket.
        local_port: Local port number.
        remote_ip: Remote peer IP address if connected, or None.
        remote_port: Remote peer port number if connected, or None.
        status: Socket state (e.g. 'ESTABLISHED', 'LISTEN', 'NONE').
        pid: Associated process identifier, or None if unavailable/inaccessible.
    """

    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str | None = None
    remote_port: int | None = None
    status: str = "NONE"
    pid: int | None = None

    @property
    def connection_key(self) -> tuple[str, str, int, str | None, int | None, int | None]:
        """Unique key identifying a network connection instance."""
        return (
            self.protocol,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.pid,
        )


class NetworkCollector:
    """Monitors active network connections and emits SecurityEvents for newly observed connections."""

    def __init__(self, repository: EventRepository | None = None) -> None:
        """Initialize the network collector.

        Args:
            repository: Optional EventRepository for persisting generated events.
        """
        self.repository = repository
        self._known_connection_keys: set[tuple[str, str, int, str | None, int | None, int | None]] = set()

    def get_snapshot(self) -> list[NetworkConnectionInfo]:
        """Enumerate active network connections safely.

        Catches AccessDenied and socket-level errors gracefully to support unprivileged
        operation without crashing the monitoring service.

        Returns:
            list[NetworkConnectionInfo]: Currently active network connections.
        """
        connections: list[NetworkConnectionInfo] = []

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied as err:
            logger.warning("AccessDenied when querying network connections: %s", err)
            return []
        except Exception as err:
            logger.warning("Failed to enumerate network connections: %s", err)
            return []

        for conn in raw_conns:
            info = self._parse_connection(conn)
            if info is not None:
                connections.append(info)

        return connections

    def _parse_connection(self, conn: Any) -> NetworkConnectionInfo | None:
        """Parse a single psutil connection namedtuple into NetworkConnectionInfo."""
        try:
            # Local address is mandatory
            if not getattr(conn, "laddr", None):
                return None

            local_ip = str(conn.laddr.ip)
            local_port = int(conn.laddr.port)

            remote_ip = None
            remote_port = None
            raddr = getattr(conn, "raddr", None)
            if raddr and hasattr(raddr, "ip") and hasattr(raddr, "port"):
                remote_ip = str(raddr.ip)
                remote_port = int(raddr.port)

            protocol = _resolve_protocol(getattr(conn, "family", 2), getattr(conn, "type", 1))
            status = str(getattr(conn, "status", "NONE"))
            pid = getattr(conn, "pid", None)

            return NetworkConnectionInfo(
                protocol=protocol,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status=status,
                pid=pid,
            )
        except Exception as err:
            logger.debug("Skipping malformed connection entry: %s", err)
            return None

    def initialize_baseline(self) -> None:
        """Populate known connections from current snapshot without emitting events."""
        snapshot = self.get_snapshot()
        self._known_connection_keys = {conn.connection_key for conn in snapshot}

    def collect_events(self) -> list[SecurityEvent]:
        """Poll network connections and generate SecurityEvents for newly observed connections.

        Updates internal tracking state and optionally persists events to the repository.

        Returns:
            list[SecurityEvent]: New network_connection_observed security events.
        """
        snapshot = self.get_snapshot()
        current_keys: set[tuple[str, str, int, str | None, int | None, int | None]] = set()
        new_events: list[SecurityEvent] = []

        for conn in snapshot:
            key = conn.connection_key
            current_keys.add(key)
            if key not in self._known_connection_keys:
                remote_desc = f"{conn.remote_ip}:{conn.remote_port}" if conn.remote_ip and conn.remote_port else conn.status
                pid_desc = f" (PID: {conn.pid})" if conn.pid else ""
                event = SecurityEvent(
                    source="network_collector",
                    category=EventCategory.NETWORK,
                    event_type="network_connection_observed",
                    severity=EventSeverity.INFO,
                    description=(
                        f"Network connection observed: {conn.protocol.upper()} "
                        f"{conn.local_ip}:{conn.local_port} -> {remote_desc}{pid_desc}"
                    ),
                    attributes={
                        "protocol": conn.protocol,
                        "local_ip": conn.local_ip,
                        "local_port": conn.local_port,
                        "remote_ip": conn.remote_ip,
                        "remote_port": conn.remote_port,
                        "status": conn.status,
                        "pid": conn.pid,
                    },
                )
                new_events.append(event)

        # Update known connections to current active keys
        self._known_connection_keys = current_keys

        if self.repository is not None and new_events:
            self.repository.add_events(new_events)

        return new_events
