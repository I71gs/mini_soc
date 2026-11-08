"""Host monitoring orchestration service for Mini SOC.

Coordinates process and network collectors, supports one-time collection cycles,
provides safe background polling with configurable intervals, isolates collector
failures, and ensures graceful shutdown.
"""

import logging
import threading
from typing import Sequence

from src.collectors.network_collector import NetworkCollector
from src.collectors.process_collector import ProcessCollector
from src.core.events import SecurityEvent
from src.database.event_repository import EventRepository

logger = logging.getLogger(__name__)


class HostMonitorService:
    """Orchestrates host telemetry collectors and manages polling cycles.

    Attributes:
        repository: Optional EventRepository for persisting collected events.
        poll_interval: Duration in seconds between polling cycles.
        process_collector: Active ProcessCollector instance.
        network_collector: Active NetworkCollector instance.
    """

    def __init__(
        self,
        repository: EventRepository | None = None,
        poll_interval: float = 5.0,
        process_collector: ProcessCollector | None = None,
        network_collector: NetworkCollector | None = None,
    ) -> None:
        """Initialize host monitoring service.

        Args:
            repository: Optional EventRepository for event persistence.
            poll_interval: Interval between background polls in seconds. Defaults to 5.0.
            process_collector: Optional custom ProcessCollector instance.
            network_collector: Optional custom NetworkCollector instance.
        """
        self.repository = repository
        self.poll_interval = poll_interval
        self.process_collector = process_collector or ProcessCollector(repository=repository)
        self.network_collector = network_collector or NetworkCollector(repository=repository)

        self._is_running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def is_running(self) -> bool:
        """Return True if background monitoring is actively running."""
        return self._is_running

    def initialize_baselines(self) -> None:
        """Set baseline snapshots for both collectors without emitting events."""
        try:
            self.process_collector.initialize_baseline()
        except Exception as err:
            logger.error("Failed to initialize process baseline: %s", err)

        try:
            self.network_collector.initialize_baseline()
        except Exception as err:
            logger.error("Failed to initialize network baseline: %s", err)

    def collect_once(self) -> list[SecurityEvent]:
        """Execute a single polling cycle across all collectors with failure isolation.

        If one collector fails, the error is logged and the remaining collectors
        continue operating uninterrupted.

        Returns:
            list[SecurityEvent]: Combined security events generated during this collection cycle.
        """
        collected: list[SecurityEvent] = []

        try:
            proc_events = self.process_collector.collect_events()
            collected.extend(proc_events)
        except Exception as err:
            logger.error("Process collector failed during collection cycle: %s", err)

        try:
            net_events = self.network_collector.collect_events()
            collected.extend(net_events)
        except Exception as err:
            logger.error("Network collector failed during collection cycle: %s", err)

        return collected

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

        self._is_running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("HostMonitorService stopped.")

    def _run_loop(self) -> None:
        """Background loop executing collection cycles at configured intervals."""
        while not self._stop_event.is_set():
            self.collect_once()
            self._stop_event.wait(self.poll_interval)
