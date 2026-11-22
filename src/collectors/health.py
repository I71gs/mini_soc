"""Small runtime health record shared by telemetry collectors."""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class CollectorHealth:
    """Track whether a collector ran and whether its latest run was complete."""

    name: str
    visibility_limitations: tuple[str, ...] = ()
    status: str = "not polled"
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    events_last_run: int = 0

    def record(self, events_count: int, error: str | None = None) -> None:
        now = datetime.now(timezone.utc)
        self.last_attempt_at = now
        self.events_last_run = events_count
        self.last_error = error
        if error:
            self.status = "degraded"
        else:
            self.status = "healthy"
            self.last_success_at = now

    def mark_unavailable(self, reason: str) -> None:
        self.record(0, reason)
        self.status = "unavailable"
