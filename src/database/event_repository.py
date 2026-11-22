"""Security event repository for SQLite persistence.

Provides high-level transactional data operations for SecurityEvent instances,
including single/batch insertion, single retrieval, parameterized query filtering,
and aggregation.
"""

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any
import uuid

from src.core.events import EventSeverity, SecurityEvent
from src.database.connection import DatabaseManager


def _normalize_filter_timestamp(timestamp_val: datetime | str, param_name: str) -> str:
    """Normalize input filter timestamp to a timezone-aware UTC ISO string."""
    if isinstance(timestamp_val, str):
        try:
            timestamp_val = datetime.fromisoformat(timestamp_val)
        except ValueError as err:
            raise ValueError(f"Invalid ISO format for {param_name}: {err}") from err

    if isinstance(timestamp_val, datetime):
        if timestamp_val.tzinfo is None or timestamp_val.tzinfo.utcoffset(timestamp_val) is None:
            raise ValueError(f"{param_name} must be timezone-aware (naive datetimes are rejected)")
        return timestamp_val.astimezone(timezone.utc).isoformat()

    raise ValueError(f"{param_name} must be a datetime or ISO string, got {type(timestamp_val).__name__}")


class EventRepository:
    """Repository for managing SecurityEvent persistence in SQLite.

    Attributes:
        db_manager: DatabaseManager handling connection lifecycles.
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        """Initialize EventRepository with an active DatabaseManager.

        Args:
            db_manager: DatabaseManager managing SQLite connections.
        """
        self.db_manager = db_manager

    def add_event(self, event: SecurityEvent) -> None:
        """Insert a single SecurityEvent into the database.

        Args:
            event: The SecurityEvent instance to insert.

        Raises:
            sqlite3.IntegrityError: If an event with the same event_id already exists.
            sqlite3.DatabaseError: On underlying SQLite execution errors.
        """
        record = event.to_db_record()
        query = """
            INSERT INTO security_events (
                event_id, timestamp, source, category, event_type,
                severity, host, description, attributes, schema_version
            ) VALUES (
                :event_id, :timestamp, :source, :category, :event_type,
                :severity, :host, :description, :attributes, :schema_version
            );
        """
        with self.db_manager.get_connection() as conn:
            conn.execute(query, record)

    def add_events(self, events: Sequence[SecurityEvent]) -> None:
        """Insert multiple SecurityEvent records in a single atomic transaction.

        If any insertion fails, the entire batch transaction is rolled back.

        Args:
            events: Sequence of SecurityEvent instances to insert.

        Raises:
            sqlite3.IntegrityError: If duplicate event IDs are encountered.
            sqlite3.DatabaseError: On underlying SQLite execution errors.
        """
        if not events:
            return

        records = [event.to_db_record() for event in events]
        query = """
            INSERT INTO security_events (
                event_id, timestamp, source, category, event_type,
                severity, host, description, attributes, schema_version
            ) VALUES (
                :event_id, :timestamp, :source, :category, :event_type,
                :severity, :host, :description, :attributes, :schema_version
            );
        """
        with self.db_manager.get_connection() as conn:
            conn.executemany(query, records)

    def save_events_with_checkpoint(
        self,
        events: Sequence[SecurityEvent],
        channel: str,
        last_record_id: int,
    ) -> None:
        """Atomically insert security events and advance a channel checkpoint in a single transaction.

        If either the event insertion or the checkpoint update fails, the entire transaction
        is rolled back, guaranteeing that checkpoints never advance beyond successfully persisted events.

        Args:
            events: Sequence of SecurityEvent instances to persist.
            channel: Event log channel name (e.g. 'Security', 'System').
            last_record_id: The new highest processed EventRecordID to record.

        Raises:
            sqlite3.IntegrityError: If duplicate event IDs or constraint violations occur.
            sqlite3.DatabaseError: On underlying SQLite execution errors.
        """
        records = [event.to_db_record() for event in events]
        event_query = """
            INSERT INTO security_events (
                event_id, timestamp, source, category, event_type,
                severity, host, description, attributes, schema_version
            ) VALUES (
                :event_id, :timestamp, :source, :category, :event_type,
                :severity, :host, :description, :attributes, :schema_version
            );
        """
        checkpoint_query = """
            INSERT INTO event_log_checkpoints (channel, last_record_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(channel) DO UPDATE SET
                last_record_id = MAX(event_log_checkpoints.last_record_id, excluded.last_record_id),
                updated_at = excluded.updated_at;
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.db_manager.get_connection() as conn:
            if records:
                conn.executemany(event_query, records)
            if last_record_id > 0:
                conn.execute(checkpoint_query, (channel, last_record_id, now_utc))

    def get_event(self, event_id: uuid.UUID | str) -> SecurityEvent | None:
        """Retrieve a single SecurityEvent by its unique identifier.

        Args:
            event_id: UUID or string representation of the event ID.

        Returns:
            SecurityEvent instance if found, or None if no matching record exists.
        """
        query = "SELECT * FROM security_events WHERE event_id = ?;"
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (str(event_id),))
            row = cursor.fetchone()
            if row is None:
                return None
            return SecurityEvent.from_db_record(dict(row))

    def list_events(
        self,
        start_time: datetime | str | None = None,
        end_time: datetime | str | None = None,
        severity: EventSeverity | str | None = None,
        source: str | None = None,
        event_type: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[SecurityEvent]:
        """Retrieve events with optional filters ordered newest first.

        Ordering is deterministic: newest timestamp first, with event_id descending
        as a secondary sort key.

        Args:
            start_time: Optional start timestamp filter (inclusive).
            end_time: Optional end timestamp filter (inclusive).
            severity: Optional severity filter (EventSeverity or string).
            source: Optional source identifier filter.
            event_type: Optional event type filter.
            limit: Optional maximum number of events to return. Must be non-negative.
            offset: Number of matching events to skip for database-backed paging.

        Returns:
            list[SecurityEvent]: Retrieved events matching the filter criteria.

        Raises:
            ValueError: If limit is negative or filter timestamps are naive/invalid.
        """
        if limit is not None and limit < 0:
            raise ValueError(f"limit must be non-negative, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")

        conditions: list[str] = []
        params: list[Any] = []

        if start_time is not None:
            normalized_start = _normalize_filter_timestamp(start_time, "start_time")
            conditions.append("timestamp >= ?")
            params.append(normalized_start)

        if end_time is not None:
            normalized_end = _normalize_filter_timestamp(end_time, "end_time")
            conditions.append("timestamp <= ?")
            params.append(normalized_end)

        if severity is not None:
            severity_str = severity.value if isinstance(severity, EventSeverity) else str(severity).upper()
            conditions.append("severity = ?")
            params.append(severity_str)

        if source is not None:
            conditions.append("source = ?")
            params.append(source)

        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type)

        query = "SELECT * FROM security_events"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC, event_id DESC"

        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        elif offset:
            query += " LIMIT -1"
        if offset:
            query += " OFFSET ?"
            params.append(offset)

        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [SecurityEvent.from_db_record(dict(row)) for row in rows]

    def count_events(
        self,
        start_time: datetime | str | None = None,
        end_time: datetime | str | None = None,
        severity: EventSeverity | str | None = None,
        source: str | None = None,
        event_type: str | None = None,
    ) -> int:
        """Count stored events matching optional filter criteria.

        Args:
            start_time: Optional start timestamp filter (inclusive).
            end_time: Optional end timestamp filter (inclusive).
            severity: Optional severity filter (EventSeverity or string).
            source: Optional source identifier filter.
            event_type: Optional event type filter.

        Returns:
            int: Number of events matching the filter criteria.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if start_time is not None:
            normalized_start = _normalize_filter_timestamp(start_time, "start_time")
            conditions.append("timestamp >= ?")
            params.append(normalized_start)

        if end_time is not None:
            normalized_end = _normalize_filter_timestamp(end_time, "end_time")
            conditions.append("timestamp <= ?")
            params.append(normalized_end)

        if severity is not None:
            severity_str = severity.value if isinstance(severity, EventSeverity) else str(severity).upper()
            conditions.append("severity = ?")
            params.append(severity_str)

        if source is not None:
            conditions.append("source = ?")
            params.append(source)

        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type)

        query = "SELECT COUNT(*) FROM security_events"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()
            return int(row[0]) if row and row[0] is not None else 0

    def delete_events_before(self, cutoff: datetime) -> int:
        """Delete telemetry older than a timezone-aware UTC retention cutoff."""
        normalized_cutoff = _normalize_filter_timestamp(cutoff, "cutoff")
        with self.db_manager.get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM security_events WHERE timestamp < ?;",
                (normalized_cutoff,),
            )
            return cursor.rowcount
