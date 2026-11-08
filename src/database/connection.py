"""Database connection and transaction manager for Mini SOC.

Manages SQLite connections, pragmas, transactions, and resource lifecycles
safely without holding persistent locks.
"""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Generator

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
        if db_path is None:
            self.db_path = AppConfig().database_path
        elif isinstance(db_path, str) and db_path == ":memory:":
            self.db_path = Path(":memory:")
        else:
            self.db_path = Path(db_path).resolve()

        self.timeout = timeout

        # Ensure parent directory exists for file-backed databases
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a contextual SQLite connection with foreign keys and row factory.

        Enables foreign keys, configures sqlite3.Row row factory, commits on successful completion,
        rolls back on exceptions, and closes the connection upon context exit.

        Yields:
            sqlite3.Connection: Configured active database connection.
        """
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=self.timeout,
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
