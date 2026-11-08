"""Desktop application runner for Mini SOC."""

import sys
from PySide6.QtWidgets import QApplication

from src.core.config import AppConfig
from src.database.connection import DatabaseManager
from src.database.schema import initialize_database
from src.ui.main_window import MainWindow


def run_app() -> int:
    """Initialize database and start the Mini SOC PySide6 desktop interface."""
    config = AppConfig()
    db_manager = DatabaseManager(config.database_path)
    initialize_database(db_manager)

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    window = MainWindow(config=config, db_manager=db_manager)
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(run_app())
