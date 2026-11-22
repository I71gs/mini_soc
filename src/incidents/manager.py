"""Incident management utilities for generated detection alerts."""

from __future__ import annotations

from uuid import uuid4

from src.database.incident_repository import IncidentRepository
from src.detection.rules import DetectionAlert
from src.incidents.models import Incident


class IncidentManager:
    """Convert one or more detection alerts into actionable incidents."""

    VALID_STATUSES = {"open", "investigating", "mitigated", "resolved"}

    def __init__(self, repository: IncidentRepository | None = None) -> None:
        self.repository = repository
        self._incidents: list[Incident] = []

    def hydrate_from_repository(
        self,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Incident]:
        """Load incidents from the persistence layer, optionally as a page."""
        if self.repository is None:
            if limit is None:
                return list(self._incidents[offset:])
            return list(self._incidents[offset:offset + limit])
        self._incidents = self.repository.list_incidents(limit=limit, offset=offset)
        return list(self._incidents)

    def count_incidents(self, status: str | None = None) -> int:
        """Return the number of incidents available for the requested status."""
        if self.repository is not None:
            return self.repository.count_incidents(status)
        return sum(
            1 for incident in self._incidents
            if status is None or incident.status == status
        )

    def create_from_alert(self, alert: DetectionAlert) -> Incident:
        """Create a single incident from a detection alert."""
        alert_key = getattr(alert, "alert_key", None)
        existing = self.get_incident_by_alert_key(alert_key) if alert_key else None
        if existing is not None:
            return existing

        incident = Incident(
            incident_id=str(uuid4()),
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            source=alert.source,
            related_event_ids=list(alert.related_event_ids),
            alert_key=alert_key,
            attributes={
                "rule_name": alert.rule_name,
                **alert.attributes,
            },
        )
        if self.repository is not None:
            self.repository.add_incident(incident)
            if alert_key:
                existing = self.repository.get_incident_by_alert_key(alert_key)
                if existing is not None:
                    incident = existing
        if not any(item.incident_id == incident.incident_id for item in self._incidents):
            self._incidents.append(incident)
        return incident

    def create_from_alerts(self, alerts: list[DetectionAlert]) -> list[Incident]:
        """Create incidents from a list of alerts."""
        incidents: list[Incident] = []
        for alert in alerts:
            incidents.append(self.create_from_alert(alert))
        return incidents

    def get_incident(self, incident_id: str) -> Incident | None:
        """Retrieve an incident by ID."""
        for inc in self._incidents:
            if inc.incident_id == incident_id:
                return inc
        return None

    def update_status(self, incident_id: str, new_status: str) -> bool:
        """Update the status of an incident."""
        normalized_status = new_status.strip().lower()
        if normalized_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid incident status: {new_status}")
        incident = self.get_incident(incident_id)
        if incident:
            if self.repository is not None:
                self.repository.update_status(incident_id, normalized_status)
            incident.status = normalized_status
            return True
        return False

    def add_note(self, incident_id: str, note: str) -> bool:
        """Add an analyst note to an incident."""
        incident = self.get_incident(incident_id)
        if incident:
            incident.notes.append(note)
            try:
                if self.repository is not None:
                    self.repository.update_incident(incident)
            except Exception:
                incident.notes.pop()
                raise
            return True
        return False

    def get_incident_by_alert_key(self, alert_key: str) -> Incident | None:
        """Find a previously created case for a stable detection fingerprint."""
        for incident in self._incidents:
            if incident.alert_key == alert_key:
                return incident
        if self.repository is not None:
            incident = self.repository.get_incident_by_alert_key(alert_key)
            if incident is not None:
                self._incidents.append(incident)
            return incident
        return None

    @property
    def incidents(self) -> list[Incident]:
        """Return all incidents currently registered in memory."""
        return list(self._incidents)
