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
                source, related_event_ids, attributes, notes, created_at, alert_key
            ) VALUES (
                :incident_id, :title, :description, :severity, :status,
                :source, :related_event_ids, :attributes, :notes, :created_at, :alert_key
            )
            ON CONFLICT DO NOTHING;
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
            "alert_key": record["alert_key"],
        }
        with self.db_manager.get_connection() as conn:
            conn.execute(query, payload)

    def add_incidents(self, incidents: list[Incident]) -> None:
        """Insert multiple incidents in one transaction."""
        if not incidents:
            return
        records = [incident.to_dict() for incident in incidents]
        payloads = [
            {
                **record,
                "related_event_ids": json.dumps(record["related_event_ids"]),
                "attributes": json.dumps(record["attributes"]),
                "notes": json.dumps(record["notes"]),
            }
            for record in records
        ]
        query = """
            INSERT INTO incidents (
                incident_id, title, description, severity, status, source,
                related_event_ids, attributes, notes, created_at, alert_key
            ) VALUES (
                :incident_id, :title, :description, :severity, :status, :source,
                :related_event_ids, :attributes, :notes, :created_at, :alert_key
            )
            ON CONFLICT DO NOTHING;
        """
        with self.db_manager.get_connection() as conn:
            conn.executemany(query, payloads)

    def get_incident(self, incident_id: str) -> Incident | None:
        """Look up an incident by ID."""
        query = "SELECT * FROM incidents WHERE incident_id = ?;"
        with self.db_manager.get_connection() as conn:
            row = conn.execute(query, (incident_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_incident(dict(row))

    def get_incident_by_alert_key(self, alert_key: str) -> Incident | None:
        """Find the incident already created for a detection fingerprint."""
        query = "SELECT * FROM incidents WHERE alert_key = ?;"
        with self.db_manager.get_connection() as conn:
            row = conn.execute(query, (alert_key,)).fetchone()
            return self._row_to_incident(dict(row)) if row is not None else None

    def list_incidents(
        self,
        status: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Incident]:
        """Return incidents ordered newest first."""
        if limit is not None and limit < 0:
            raise ValueError(f"limit must be non-negative, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")
        conditions: list[str] = []
        params: list[Any] = []
        if status is not None:
            conditions.append("status = ?")
            params.append(status)

        query = "SELECT * FROM incidents"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC, incident_id DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        elif offset:
            query += " LIMIT -1"
        if offset:
            query += " OFFSET ?"
            params.append(offset)

        with self.db_manager.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_incident(dict(row)) for row in rows]

    def count_incidents(self, status: str | None = None) -> int:
        """Count persisted incidents, optionally restricted to a status."""
        query = "SELECT COUNT(*) FROM incidents"
        params: tuple[str, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status,)
        with self.db_manager.get_connection() as conn:
            row = conn.execute(query, params).fetchone()
            return int(row[0]) if row else 0

    def update_status(self, incident_id: str, status: str) -> None:
        """Update the status of an incident."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute(
                "UPDATE incidents SET status = ? WHERE incident_id = ?;",
                (status, incident_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Incident not found: {incident_id}")

    def update_incident(self, incident: Incident) -> None:
        """Persist mutable analyst-maintained incident fields."""
        record = incident.to_dict()
        query = """
            UPDATE incidents SET
                title = :title,
                description = :description,
                severity = :severity,
                status = :status,
                source = :source,
                related_event_ids = :related_event_ids,
                attributes = :attributes,
                notes = :notes
            WHERE incident_id = :incident_id;
        """
        payload = {
            **record,
            "related_event_ids": json.dumps(record["related_event_ids"]),
            "attributes": json.dumps(record["attributes"]),
            "notes": json.dumps(record["notes"]),
        }
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute(query, payload)
            if cursor.rowcount == 0:
                raise ValueError(f"Incident not found: {incident.incident_id}")

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
            "alert_key": row["alert_key"],
            "attributes": json.loads(row["attributes"]),
            "notes": json.loads(row["notes"]),
            "created_at": row["created_at"],
        }
        return Incident.from_dict(payload)
