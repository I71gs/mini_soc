"""Database schema definitions and version management for Mini SOC.

Defines the security_events table schema, indexes, event log checkpoints,
and an idempotent schema versioning mechanism to safely evolve the database structure over time.
"""

from datetime import datetime, timezone
import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.database.connection import DatabaseManager

CURRENT_SCHEMA_VERSION = 4

SCHEMA_V1_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL,
        description TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS security_events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        category TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        host TEXT NOT NULL,
        description TEXT NOT NULL,
        attributes TEXT NOT NULL,
        schema_version TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
    ON security_events (timestamp);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_security_events_severity
    ON security_events (severity);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_security_events_source
    ON security_events (source);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_security_events_event_type
    ON security_events (event_type);
    """,
]

SCHEMA_V2_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS event_log_checkpoints (
        channel TEXT PRIMARY KEY,
        last_record_id INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
]

SCHEMA_V3_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        source TEXT NOT NULL,
        related_event_ids TEXT NOT NULL,
        attributes TEXT NOT NULL,
        notes TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_incidents_severity
    ON incidents (severity);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON incidents (status);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_incidents_created_at
    ON incidents (created_at);
    """,
]

SCHEMA_V4_STATEMENTS = [
    "ALTER TABLE incidents ADD COLUMN alert_key TEXT;",
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_alert_key
    ON incidents (alert_key);
    """,
    """
    CREATE TABLE IF NOT EXISTS detection_alert_states (
        alert_key TEXT PRIMARY KEY,
        reviewed_at TEXT NOT NULL
    );
    """,
]


def get_current_schema_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version recorded in the database, or 0 if uninitialized.

    Args:
        conn: Active SQLite connection.

    Returns:
        int: The highest applied schema version, or 0 if schema_version table does not exist.
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';"
    )
    if cursor.fetchone() is None:
        return 0

    cursor.execute("SELECT MAX(version) FROM schema_version;")
    row = cursor.fetchone()
    if row is None or row[0] is None:
        return 0
    return int(row[0])


def initialize_schema(conn: sqlite3.Connection) -> int:
    """Initialize or migrate the database schema to the latest version.

    This function is strictly idempotent. Repeated execution on an existing database
    will not overwrite or corrupt existing tables, indexes, or records.

    Args:
        conn: Active SQLite connection.

    Returns:
        int: The resulting schema version.
    """
    current_version = get_current_schema_version(conn)

    cursor = conn.cursor()

    if current_version < 1:
        for statement in SCHEMA_V1_STATEMENTS:
            cursor.execute(statement)

        now_utc = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT OR IGNORE INTO schema_version (version, applied_at, description)
            VALUES (?, ?, ?);
            """,
            (1, now_utc, "Initial security events schema with indexes"),
        )
        current_version = 1

    if current_version < 2:
        for statement in SCHEMA_V2_STATEMENTS:
            cursor.execute(statement)

        now_utc = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT OR IGNORE INTO schema_version (version, applied_at, description)
            VALUES (?, ?, ?);
            """,
            (2, now_utc, "Added event log checkpoint tracking table"),
        )
        current_version = 2

    if current_version < 3:
        for statement in SCHEMA_V3_STATEMENTS:
            cursor.execute(statement)

        now_utc = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT OR IGNORE INTO schema_version (version, applied_at, description)
            VALUES (?, ?, ?);
            """,
            (3, now_utc, "Added incident persistence table and indexes"),
        )
        current_version = 3

    if current_version < 4:
        for statement in SCHEMA_V4_STATEMENTS:
            cursor.execute(statement)

        now_utc = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            INSERT OR IGNORE INTO schema_version (version, applied_at, description)
            VALUES (?, ?, ?);
            """,
            (4, now_utc, "Added stable detection review and incident deduplication state"),
        )
        current_version = 4

    return current_version


def initialize_database(db_manager: "DatabaseManager") -> int:
    """Initialize the schema using a DatabaseManager instance.

    Args:
        db_manager: The DatabaseManager responsible for database connections.

    Returns:
        int: The resulting schema version.
    """
    with db_manager.get_connection() as conn:
        return initialize_schema(conn)
