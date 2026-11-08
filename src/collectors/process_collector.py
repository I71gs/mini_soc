"""Windows process telemetry collector.

Enumerates active processes using psutil, captures essential metadata safely,
handles permission and lifecycle exceptions, and generates SecurityEvent records
for newly observed processes across polling cycles.
"""

from dataclasses import dataclass
import logging
from typing import Any

import psutil

from src.core.events import EventCategory, EventSeverity, SecurityEvent
from src.database.event_repository import EventRepository

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessInfo:
    """Snapshot data structure representing an active process.

    Attributes:
        pid: Process identifier.
        name: Name of the executable.
        create_time: Process start timestamp in epoch seconds.
        exe: Full path to the executable, if accessible.
        username: Name of the user running the process, if accessible.
    """

    pid: int
    name: str
    create_time: float
    exe: str | None = None
    username: str | None = None

    @property
    def process_key(self) -> tuple[int, float]:
        """Unique key identifying a process instance, resilient to PID reuse."""
        return (self.pid, self.create_time)


class ProcessCollector:
    """Monitors Windows processes and emits SecurityEvents for newly started processes."""

    def __init__(self, repository: EventRepository | None = None) -> None:
        """Initialize the process collector.

        Args:
            repository: Optional EventRepository for persisting generated events.
        """
        self.repository = repository
        self._known_process_keys: set[tuple[int, float]] = set()

    def get_snapshot(self) -> list[ProcessInfo]:
        """Enumerate all currently running processes safely.

        Catches AccessDenied, NoSuchProcess, and ZombieProcess errors to ensure
        the collection cycle does not crash when encountering protected system processes.

        Returns:
            list[ProcessInfo]: Current running processes.
        """
        processes: list[ProcessInfo] = []

        try:
            for proc in psutil.process_iter():
                info = self._extract_process_info(proc)
                if info is not None:
                    processes.append(info)
        except Exception as err:
            logger.warning("Failed during process iteration: %s", err)

        return processes

    def _extract_process_info(self, proc: psutil.Process) -> ProcessInfo | None:
        """Safely extract process details from a psutil.Process object."""
        try:
            pid = proc.pid
            name = proc.name() or "unknown"
            create_time = proc.create_time()
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            return None
        except Exception as err:
            logger.debug("Unexpected error reading basic process info for PID %s: %s", getattr(proc, "pid", "?"), err)
            return None

        # Optional attributes that frequently trigger AccessDenied on system processes
        exe = None
        try:
            exe = proc.exe()
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass

        username = None
        try:
            username = proc.username()
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass

        return ProcessInfo(
            pid=pid,
            name=name,
            create_time=create_time,
            exe=exe,
            username=username,
        )

    def initialize_baseline(self) -> None:
        """Populate known processes from current snapshot without emitting events."""
        snapshot = self.get_snapshot()
        self._known_process_keys = {proc.process_key for proc in snapshot}

    def collect_events(self) -> list[SecurityEvent]:
        """Poll running processes and generate SecurityEvents for newly observed processes.

        Updates internal tracking state and optionally persists events to the repository.

        Returns:
            list[SecurityEvent]: New process_started security events.
        """
        snapshot = self.get_snapshot()
        current_keys: set[tuple[int, float]] = set()
        new_events: list[SecurityEvent] = []

        for proc in snapshot:
            key = proc.process_key
            current_keys.add(key)
            if key not in self._known_process_keys:
                event = SecurityEvent(
                    source="process_collector",
                    category=EventCategory.PROCESS,
                    event_type="process_started",
                    severity=EventSeverity.INFO,
                    description=f"Process started: {proc.name} (PID: {proc.pid})",
                    attributes={
                        "pid": proc.pid,
                        "name": proc.name,
                        "exe": proc.exe,
                        "username": proc.username,
                        "create_time": proc.create_time,
                    },
                )
                new_events.append(event)

        # Update known processes to current active keys
        self._known_process_keys = current_keys

        if self.repository is not None and new_events:
            self.repository.add_events(new_events)

        return new_events
