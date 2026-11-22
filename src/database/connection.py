"""Database connection and transaction manager for Mini SOC.

Manages SQLite connections, pragmas, transactions, and resource lifecycles
safely without holding persistent locks.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
from typing import Generator
from uuid import uuid4

from src.core.config import AppConfig


class DatabaseManager:
    """Manages SQLite database connections and transactions.

    Attributes:
        db_path: Path to the SQLite database file.
        timeout: SQLite busy timeout in seconds.
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        timeout: float = 10.0,
    ) -> None:
        """Initialize DatabaseManager with configured or custom database path.

        Args:
            db_path: Optional path to the database file. If None, uses AppConfig().database_path.
            timeout: SQLite connection timeout in seconds. Defaults to 10.0.
        """
        self._is_memory = db_path is not None and str(db_path) == ":memory:"
        self._memory_keeper: sqlite3.Connection | None = None
        if db_path is None:
            self.db_path = AppConfig().database_path
        elif self._is_memory:
            self.db_path = Path(":memory:")
        else:
            self.db_path = Path(db_path).resolve()
        assert self.db_path is not None

        self.timeout = timeout
        self._connection_target = (
            f"file:mini-soc-{uuid4().hex}?mode=memory&cache=shared"
            if self._is_memory else str(self.db_path)
        )

        # Ensure parent directory exists for file-backed databases
        if not self._is_memory:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self._memory_keeper = sqlite3.connect(
                self._connection_target,
                timeout=self.timeout,
                uri=True,
            )

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a contextual SQLite connection with foreign keys and row factory.

        Enables foreign keys, configures sqlite3.Row row factory, commits on successful completion,
        rolls back on exceptions, and closes the connection upon context exit.

        Yields:
            sqlite3.Connection: Configured active database connection.
        """
        conn = sqlite3.connect(
            self._connection_target,
            timeout=self.timeout,
            uri=self._is_memory,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def backup_to(self, destination: Path | str) -> Path:
        """Create a consistent SQLite backup without overwriting an existing file."""
        target = Path(destination).expanduser().resolve()
        if self._is_memory:
            source = None
        else:
            assert self.db_path is not None
            source = self.db_path.resolve()
        if source is not None and target == source:
            raise ValueError("Backup destination must differ from the active database")
        if target.exists():
            raise FileExistsError(f"Backup destination already exists: {target}")
        if source is not None and not source.is_file():
            raise FileNotFoundError(f"Database does not exist: {source}")

        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
        source_connection = sqlite3.connect(
            self._connection_target,
            timeout=self.timeout,
            uri=self._is_memory,
        )
        destination_connection: sqlite3.Connection | None = None
        try:
            destination_connection = sqlite3.connect(str(temporary), timeout=self.timeout)
            source_connection.backup(destination_connection)
            result = destination_connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise sqlite3.DatabaseError(f"Backup integrity check failed: {result}")
            destination_connection.close()
            destination_connection = None
            os.link(temporary, target)
            temporary.unlink()
            return target
        except Exception:
            if destination_connection is not None:
                destination_connection.close()
            temporary.unlink(missing_ok=True)
            raise
        finally:
            source_connection.close()

    def close(self) -> None:
        """Release the shared in-memory database once repository work is complete."""
        if self._memory_keeper is not None:
            self._memory_keeper.close()
            self._memory_keeper = None


def migrate_legacy_database(source: Path | str, destination: Path | str) -> Path | None:
    """Copy the historical database to a new location without deleting its source."""
    source_path = Path(source).expanduser().resolve()
    destination_path = Path(destination).expanduser().resolve()
    if source_path == destination_path or destination_path.exists() or not source_path.is_file():
        return None

    DatabaseManager(source_path).backup_to(destination_path)
    return destination_path
