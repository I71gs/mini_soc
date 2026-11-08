"""Incident model definitions for Mini SOC."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.core.events import EventSeverity


@dataclass
class Incident:
    """A triaged security incident arising from one or more detections."""

    incident_id: str
    title: str
    description: str
    severity: EventSeverity
    status: str = "open"
    source: str = "detection_engine"
    related_event_ids: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the incident to a dictionary for display or persistence."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status,
            "source": self.source,
            "related_event_ids": self.related_event_ids,
            "attributes": self.attributes,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Incident":
        """Reconstruct an Incident from a serialized dictionary."""
        created_at = raw.get("created_at")
        if isinstance(created_at, str):
            created_at_dt = datetime.fromisoformat(created_at)
            if created_at_dt.tzinfo is None:
                created_at_dt = created_at_dt.replace(tzinfo=timezone.utc)
        else:
            created_at_dt = datetime.now(timezone.utc)

        severity_value = raw.get("severity", EventSeverity.MEDIUM.value)
        if isinstance(severity_value, EventSeverity):
            severity = severity_value
        else:
            severity = EventSeverity(str(severity_value).upper())

        return cls(
            incident_id=str(raw["incident_id"]),
            title=str(raw["title"]),
            description=str(raw["description"]),
            severity=severity,
            status=str(raw.get("status", "open")),
            source=str(raw.get("source", "detection_engine")),
            related_event_ids=list(raw.get("related_event_ids") or []),
            attributes=dict(raw.get("attributes") or {}),
            notes=list(raw.get("notes") or []),
            created_at=created_at_dt,
        )
