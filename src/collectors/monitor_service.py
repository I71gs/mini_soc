"""Host monitoring orchestration service for Mini SOC.

Coordinates process, network, and optional Windows Event Log collectors, supports
one-time collection cycles, provides safe background polling with configurable
intervals, isolates collector failures, and ensures graceful shutdown.
"""

import logging
import threading

from src.collectors.health import CollectorHealth
from src.collectors.network_collector import NetworkCollector
from src.collectors.process_collector import ProcessCollector
from src.collectors.windows_event_collector import WindowsEventCollector
from src.core.events import SecurityEvent
from src.database.event_repository import EventRepository

logger = logging.getLogger(__name__)


class HostMonitorService:
    """Orchestrates telemetry collectors and manages polling cycles.

    Attributes:
        repository: Optional EventRepository for persisting collected events.
        poll_interval: Duration in seconds between polling cycles.
        process_collector: Active ProcessCollector instance.
        network_collector: Active NetworkCollector instance.
        windows_event_collector: Optional Windows Event Log collector.
    """

    def __init__(
        self,
        repository: EventRepository | None = None,
        poll_interval: float = 5.0,
        process_collector: ProcessCollector | None = None,
        network_collector: NetworkCollector | None = None,
        windows_event_collector: WindowsEventCollector | None = None,
    ) -> None:
        """Initialize host monitoring service.

        Args:
            repository: Optional EventRepository for event persistence.
            poll_interval: Interval between background polls in seconds. Defaults to 5.0.
            process_collector: Optional custom ProcessCollector instance.
            network_collector: Optional custom NetworkCollector instance.
            windows_event_collector: Optional Windows Event Log collector.
        """
        self.repository = repository
        self.poll_interval = poll_interval
        self.process_collector = process_collector or ProcessCollector(repository=repository)
        self.network_collector = network_collector or NetworkCollector(repository=repository)
        self.windows_event_collector = windows_event_collector

        self._is_running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._collection_lock = threading.Lock()
        self.health = {
            "Process Collector": CollectorHealth(
                "Process Collector",
                visibility_limitations=(
                    "Processes already active at startup are baselined and not emitted as events.",
                    "Processes that start and exit between polls may be missed.",
                    "Windows may restrict access to protected processes and their metadata.",
                ),
            ),
            "Network Collector": CollectorHealth(
                "Network Collector",
                visibility_limitations=(
                    "Connections already active at startup are baselined and not emitted as events.",
                    "Connections that begin and end between polls may be missed.",
                    "Windows may restrict connection enumeration or owning-process information.",
                ),
            ),
        }
        self._base_process_visibility_limitations = self.health[
            "Process Collector"
        ].visibility_limitations
        if self.windows_event_collector is not None:
            self.health["Windows Event Log"] = self.windows_event_collector.health

    @property
    def is_running(self) -> bool:
        """Return True if background monitoring is actively running."""
        return self._is_running

    def initialize_baselines(self) -> None:
        """Set baseline snapshots for both collectors without emitting events."""
        try:
            self.process_collector.initialize_baseline()
            self._record_process_health(0)
        except Exception as err:
            self.health["Process Collector"].record(0, str(err))
            logger.error("Failed to initialize process baseline: %s", err)

        try:
            self.network_collector.initialize_baseline()
            error = self.network_collector.last_error
            self.health["Network Collector"].record(0, error)
        except Exception as err:
            self.health["Network Collector"].record(0, str(err))
            logger.error("Failed to initialize network baseline: %s", err)

    def collect_once(self) -> list[SecurityEvent]:
        """Execute a single polling cycle across all collectors with failure isolation.

        If one collector fails, the error is logged and the remaining collectors
        continue operating uninterrupted.

        Returns:
            list[SecurityEvent]: Combined security events generated during this collection cycle.
        """
        with self._collection_lock:
            return self._collect_once()

    def _collect_once(self) -> list[SecurityEvent]:
        collected: list[SecurityEvent] = []

        try:
            proc_events = self.process_collector.collect_events()
            collected.extend(proc_events)
            self._record_process_health(len(proc_events))
        except Exception as err:
            self.health["Process Collector"].record(0, str(err))
            logger.error("Process collector failed during collection cycle: %s", err)

        try:
            net_events = self.network_collector.collect_events()
            collected.extend(net_events)
            self.health["Network Collector"].record(
                len(net_events), self.network_collector.last_error
            )
        except Exception as err:
            self.health["Network Collector"].record(0, str(err))
            logger.error("Network collector failed during collection cycle: %s", err)

        if self.windows_event_collector is not None:
            try:
                collected.extend(self.windows_event_collector.collect_events())
            except Exception as err:
                self.health["Windows Event Log"].record(0, str(err))
                logger.error("Windows Event Log collector failed during collection cycle: %s", err)

        return collected

    def _record_process_health(self, events_count: int) -> None:
        """Record process collection errors separately from restricted metadata."""
        state = self.health["Process Collector"]
        state.record(events_count, self.process_collector.last_error)
        limitations = self._base_process_visibility_limitations
        denied_count = self.process_collector.permission_denied_count
        if denied_count:
            limitations += (
                f"Windows denied access to one or more fields on {denied_count} process records during the latest poll.",
            )
        state.visibility_limitations = limitations

    def start(self) -> None:
        """Start background polling in a dedicated daemon thread."""
        if self._is_running:
            return

        self._is_running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="HostMonitorThread",
        )
        self._thread.start()
        logger.info("HostMonitorService started (interval: %.1fs).", self.poll_interval)

    def stop(self, timeout: float = 5.0) -> None:
        """Gracefully signal and stop the background polling thread.

        Args:
            timeout: Maximum seconds to wait for thread join before proceeding.
        """
        if not self._is_running:
            return

        self._stop_event.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                logger.error(
                    "HostMonitorService did not stop within %.1f seconds; its daemon thread is still running.",
                    timeout,
                )
                return
        self._is_running = False
        self._thread = None
        logger.info("HostMonitorService stopped.")

    def _run_loop(self) -> None:
        """Background loop executing collection cycles at configured intervals."""
        try:
            while not self._stop_event.is_set():
                self.collect_once()
                self._stop_event.wait(self.poll_interval)
        finally:
            self._is_running = False
