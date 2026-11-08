"""Repository for persistent incident storage in SQLite."""

from __future__ import annotations

import json
from typing import Any

from src.database.connection import DatabaseManager
from src.incidents.models import Incident


class IncidentRepository:
    """Store and query Mini SOC incidents in SQLite."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def add_incident(self, incident: Incident) -> None:
        """Insert a single incident record."""
        record = incident.to_dict()
        query = """
            INSERT INTO incidents (
                incident_id, title, description, severity, status,
                source, related_event_ids, attributes, notes, created_at
            ) VALUES (
                :incident_id, :title, :description, :severity, :status,
                :source, :related_event_ids, :attributes, :notes, :created_at
            )
            ON CONFLICT(incident_id) DO UPDATE SET
                title = excluded.title,
                description = excluded.description,
                severity = excluded.severity,
                status = excluded.status,
                source = excluded.source,
                related_event_ids = excluded.related_event_ids,
                attributes = excluded.attributes,
                notes = excluded.notes,
                created_at = excluded.created_at;
        """
        payload = {
            "incident_id": record["incident_id"],
            "title": record["title"],
            "description": record["description"],
            "severity": record["severity"],
            "status": record["status"],
            "source": record["source"],
            "related_event_ids": json.dumps(record["related_event_ids"]),
            "attributes": json.dumps(record["attributes"]),
            "notes": json.dumps(record["notes"]),
            "created_at": record["created_at"],
        }
        with self.db_manager.get_connection() as conn:
            conn.execute(query, payload)

    def add_incidents(self, incidents: list[Incident]) -> None:
        """Insert multiple incidents in one transaction."""
        for incident in incidents:
            self.add_incident(incident)

    def get_incident(self, incident_id: str) -> Incident | None:
        """Look up an incident by ID."""
        query = "SELECT * FROM incidents WHERE incident_id = ?;"
        with self.db_manager.get_connection() as conn:
            row = conn.execute(query, (incident_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_incident(dict(row))

    def list_incidents(self, status: str | None = None, limit: int | None = None) -> list[Incident]:
        """Return incidents ordered newest first."""
        conditions: list[str] = []
        params: list[Any] = []
        if status is not None:
            conditions.append("status = ?")
            params.append(status)

        query = "SELECT * FROM incidents"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        with self.db_manager.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_incident(dict(row)) for row in rows]

    def update_status(self, incident_id: str, status: str) -> None:
        """Update the status of an incident."""
        with self.db_manager.get_connection() as conn:
            conn.execute(
                "UPDATE incidents SET status = ? WHERE incident_id = ?;",
                (status, incident_id),
            )

    @staticmethod
    def _row_to_incident(row: dict[str, Any]) -> Incident:
        """Convert a SQLite row into an Incident model."""
        payload = {
            "incident_id": row["incident_id"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "status": row["status"],
            "source": row["source"],
            "related_event_ids": json.loads(row["related_event_ids"]),
            "attributes": json.loads(row["attributes"]),
            "notes": json.loads(row["notes"]),
            "created_at": row["created_at"],
        }
        return Incident.from_dict(payload)
