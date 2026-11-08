"""Centralized application configuration for Mini SOC.

Defines core paths, application metadata, and directory management.
All default paths resolve relative to the project root directory rather than
the current working directory to ensure deterministic behavior across execution environments.
"""

from dataclasses import dataclass, field
from pathlib import Path

from src.core.security import validate_safe_relative_path

# Project root is 3 levels up from src/core/config.py:
# src/core/config.py -> src/core -> src -> <project_root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_APP_NAME = "Mini SOC"
DEFAULT_APP_VERSION = "0.1.0"


@dataclass
class AppConfig:
    """Central configuration for Mini SOC application.

    Attributes:
        app_name: Name of the application.
        version: Semantic version of the application.
        project_root: Root directory of the Mini SOC project.
        data_dir: Directory used for local application storage.
        database_path: File path to the SQLite database.
        log_dir: Directory used for application log files.
        auto_create_dirs: If True, creates required data directories on initialization.
    """

    app_name: str = DEFAULT_APP_NAME
    version: str = DEFAULT_APP_VERSION
    project_root: Path = field(default_factory=lambda: PROJECT_ROOT)
    data_dir: Path | None = None
    database_path: Path | None = None
    log_dir: Path | None = None
    auto_create_dirs: bool = True

    def __post_init__(self) -> None:
        """Resolve all paths relative to project root and ensure directories exist."""
        # Ensure project root is absolute and resolved
        self.project_root = self.project_root.resolve()

        if self.data_dir is None:
            self.data_dir = (self.project_root / "data").resolve()
        else:
            self.data_dir = Path(self.data_dir)
            if not self.data_dir.is_absolute():
                self.data_dir = (self.project_root / validate_safe_relative_path(str(self.data_dir))).resolve()
            else:
                self.data_dir = self.data_dir.resolve()

        if self.database_path is None:
            self.database_path = (self.data_dir / "minisoc.db").resolve()
        else:
            self.database_path = Path(self.database_path)
            if not self.database_path.is_absolute():
                self.database_path = (self.project_root / validate_safe_relative_path(str(self.database_path))).resolve()
            else:
                self.database_path = self.database_path.resolve()

        if self.log_dir is None:
            self.log_dir = (self.data_dir / "logs").resolve()
        else:
            self.log_dir = Path(self.log_dir)
            if not self.log_dir.is_absolute():
                self.log_dir = (self.project_root / validate_safe_relative_path(str(self.log_dir))).resolve()
            else:
                self.log_dir = self.log_dir.resolve()

        self._validate_paths_within_root()

        if self.auto_create_dirs:
            self.ensure_directories()

    def _validate_paths_within_root(self) -> None:
        """Ensure the configured storage paths remain under the project root."""
        for path in (self.data_dir, self.database_path, self.log_dir):
            try:
                path.relative_to(self.project_root)
            except ValueError as err:
                raise ValueError(f"Configured path escapes project root: {path}") from err

    def ensure_directories(self) -> None:
        """Safely create required application directories on disk."""
        assert self.data_dir is not None
        assert self.log_dir is not None

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
