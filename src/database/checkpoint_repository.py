"""Repository for managing Windows Event Log channel checkpoints in SQLite.

Provides persistent tracking of the highest processed EventRecordID per channel,
allowing collections to resume deterministically across application restarts
without duplicate ingestion.
"""

from datetime import datetime, timezone
from src.database.connection import DatabaseManager


class CheckpointRepository:
    """Repository for Windows Event Log channel checkpoints.

    Attributes:
        db_manager: DatabaseManager handling SQLite connection lifecycles.
    """

    def __init__(self, db_manager: DatabaseManager) -> None:
        """Initialize CheckpointRepository with active DatabaseManager.

        Args:
            db_manager: Active DatabaseManager instance.
        """
        self.db_manager = db_manager

    def get_checkpoint(self, channel: str) -> int | None:
        """Retrieve the last recorded EventRecordID for a given event log channel.

        Args:
            channel: The channel name (e.g. 'Security', 'System').

        Returns:
            int | None: The highest processed record ID, or None if not yet tracked.
        """
        query = "SELECT last_record_id FROM event_log_checkpoints WHERE channel = ?;"
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (channel,))
            row = cursor.fetchone()
            if row is not None and row[0] is not None:
                return int(row[0])
            return None

    def set_checkpoint(self, channel: str, record_id: int) -> None:
        """Persist or update the checkpoint record ID for an event log channel.

        Uses UPSERT logic to ensure checkpoints monotonically advance and do not regress.

        Args:
            channel: The channel name (e.g. 'Security', 'System').
            record_id: The new highest processed EventRecordID.
        """
        query = """
            INSERT INTO event_log_checkpoints (channel, last_record_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(channel) DO UPDATE SET
                last_record_id = MAX(event_log_checkpoints.last_record_id, excluded.last_record_id),
                updated_at = excluded.updated_at;
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.db_manager.get_connection() as conn:
            conn.execute(query, (channel, record_id, now_utc))

    def list_checkpoints(self) -> dict[str, int]:
        """Retrieve all currently tracked channel checkpoints.

        Returns:
            dict[str, int]: Mapping of channel name to highest processed record ID.
        """
        query = "SELECT channel, last_record_id FROM event_log_checkpoints;"
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            return {row["channel"]: int(row["last_record_id"]) for row in rows}

    def reset_checkpoint(self, channel: str) -> None:
        """Reset the checkpoint for a given channel to 0.

        Args:
            channel: Target event log channel name.
        """
        query = """
            INSERT INTO event_log_checkpoints (channel, last_record_id, updated_at)
            VALUES (?, 0, ?)
            ON CONFLICT(channel) DO UPDATE SET
                last_record_id = 0,
                updated_at = excluded.updated_at;
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.db_manager.get_connection() as conn:
            conn.execute(query, (channel, now_utc))
