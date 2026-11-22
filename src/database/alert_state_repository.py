"""Persistence for analyst review state on detections."""

from datetime import datetime, timezone

from src.database.connection import DatabaseManager


class AlertStateRepository:
    """Store detection review state independently from transient rule evaluations."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def list_reviewed_keys(self) -> set[str]:
        with self.db_manager.get_connection() as conn:
            rows = conn.execute("SELECT alert_key FROM detection_alert_states;").fetchall()
            return {str(row["alert_key"]) for row in rows}

    def set_reviewed(self, alert_key: str, reviewed: bool) -> None:
        if not alert_key:
            raise ValueError("alert_key cannot be empty")
        with self.db_manager.get_connection() as conn:
            if reviewed:
                conn.execute(
                    """
                    INSERT INTO detection_alert_states (alert_key, reviewed_at)
                    VALUES (?, ?)
                    ON CONFLICT(alert_key) DO UPDATE SET reviewed_at = excluded.reviewed_at;
                    """,
                    (alert_key, datetime.now(timezone.utc).isoformat()),
                )
            else:
                conn.execute("DELETE FROM detection_alert_states WHERE alert_key = ?;", (alert_key,))
