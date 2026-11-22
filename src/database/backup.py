"""Command-line utility for making consistent Mini SOC database backups."""

import argparse
from pathlib import Path

from src.core.config import AppConfig
from src.database.connection import DatabaseManager, migrate_legacy_database


def main() -> None:
    """Create an online SQLite backup at a new destination path."""
    parser = argparse.ArgumentParser(description="Back up the configured Mini SOC database.")
    parser.add_argument("destination", type=Path, help="New backup file path (must not already exist)")
    args = parser.parse_args()

    config = AppConfig(auto_create_dirs=False)
    if config.database_path is None:
        raise RuntimeError("Application database path was not configured")
    migrate_legacy_database(config.legacy_database_path, config.database_path)
    database = DatabaseManager(config.database_path)
    print(database.backup_to(args.destination))


if __name__ == "__main__":
    main()
