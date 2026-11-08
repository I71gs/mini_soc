"""Incident management utilities for generated detection alerts."""

from __future__ import annotations

from uuid import uuid4

from src.database.incident_repository import IncidentRepository
from src.detection.rules import DetectionAlert
from src.incidents.models import Incident


class IncidentManager:
    """Convert one or more detection alerts into actionable incidents."""

    def __init__(self, repository: IncidentRepository | None = None) -> None:
        self.repository = repository
        self._incidents: list[Incident] = []

    def hydrate_from_repository(self) -> list[Incident]:
        """Load incidents from the persistence layer into memory."""
        if self.repository is None:
            return list(self._incidents)
        self._incidents = self.repository.list_incidents(limit=500)
        return list(self._incidents)

    def create_from_alert(self, alert: DetectionAlert) -> Incident:
        """Create a single incident from a detection alert."""
        incident = Incident(
            incident_id=str(uuid4()),
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            source=alert.source,
            related_event_ids=list(alert.related_event_ids),
            attributes={
                "rule_name": alert.rule_name,
                **alert.attributes,
            },
        )
        self._incidents.append(incident)
        if self.repository is not None:
            self.repository.add_incident(incident)
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
        incident = self.get_incident(incident_id)
        if incident:
            incident.status = new_status
            if self.repository is not None:
                self.repository.update_status(incident_id, new_status)
            return True
        return False

    def add_note(self, incident_id: str, note: str) -> bool:
        """Add an analyst note to an incident."""
        incident = self.get_incident(incident_id)
        if incident:
            incident.notes.append(note)
            if self.repository is not None:
                self.repository.add_incident(incident)
            return True
        return False

    @property
    def incidents(self) -> list[Incident]:
        """Return all incidents currently registered in memory."""
        return list(self._incidents)
