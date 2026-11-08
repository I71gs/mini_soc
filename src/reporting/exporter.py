"""Exporters for events, detections, and incidents in Mini SOC."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from src.core.events import SecurityEvent
from src.incidents.models import Incident


class ReportingExporter:
    """Persist Mini SOC telemetry and incident records to common file formats."""

    @staticmethod
    def _ensure_path(path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    @staticmethod
    def export_events_csv(events: Sequence[SecurityEvent], destination: str | Path) -> Path:
        """Write a CSV export for security events."""
        target = ReportingExporter._ensure_path(destination)
        fieldnames = [
            "event_id",
            "timestamp",
            "source",
            "category",
            "event_type",
            "severity",
            "host",
            "description",
            "schema_version",
        ]
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                writer.writerow(
                    {
                        "event_id": str(event.event_id),
                        "timestamp": event.timestamp.isoformat(),
                        "source": event.source,
                        "category": event.category.value if hasattr(event.category, "value") else str(event.category),
                        "event_type": event.event_type,
                        "severity": event.severity.value,
                        "host": event.host,
                        "description": event.description,
                        "schema_version": event.schema_version,
                    }
                )
        return target

    @staticmethod
    def export_incidents_csv(incidents: Sequence[Incident], destination: str | Path) -> Path:
        """Write a CSV export for incidents."""
        target = ReportingExporter._ensure_path(destination)
        fieldnames = [
            "incident_id",
            "title",
            "description",
            "severity",
            "status",
            "source",
            "related_event_ids",
            "created_at",
        ]
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for incident in incidents:
                writer.writerow(
                    {
                        "incident_id": incident.incident_id,
                        "title": incident.title,
                        "description": incident.description,
                        "severity": incident.severity.value,
                        "status": incident.status,
                        "source": incident.source,
                        "related_event_ids": ";".join(incident.related_event_ids),
                        "created_at": incident.created_at.isoformat(),
                    }
                )
        return target

    @staticmethod
    def export_events_json(events: Sequence[SecurityEvent], destination: str | Path) -> Path:
        """Write a JSON export for security events."""
        target = ReportingExporter._ensure_path(destination)
        payload = [
            {
                "event_id": str(event.event_id),
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "category": event.category.value if hasattr(event.category, "value") else str(event.category),
                "event_type": event.event_type,
                "severity": event.severity.value,
                "host": event.host,
                "description": event.description,
                "attributes": event.attributes,
                "schema_version": event.schema_version,
            }
            for event in events
        ]
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return target

    @staticmethod
    def export_incidents_json(incidents: Sequence[Incident], destination: str | Path) -> Path:
        """Write a JSON export for incidents."""
        target = ReportingExporter._ensure_path(destination)
        payload = [incident.to_dict() for incident in incidents]
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return target

    @staticmethod
    def export_summary_json(
        events: Sequence[SecurityEvent],
        incidents: Sequence[Incident],
        destination: str | Path,
    ) -> Path:
        """Write a JSON summary of event and incident health."""
        target = ReportingExporter._ensure_path(destination)
        summary = {
            "total_events": len(events),
            "total_incidents": len(incidents),
            "event_severity_counts": dict(sorted(Counter(event.severity.value for event in events).items())),
            "incident_severity_counts": dict(sorted(Counter(incident.severity.value for incident in incidents).items())),
            "incident_status_counts": dict(sorted(Counter(incident.status for incident in incidents).items())),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        target.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return target
