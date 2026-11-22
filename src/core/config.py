"""Centralized application configuration for Mini SOC.

Defines core paths, application metadata, and directory management.
Default storage is per-user and OS-specific; relative overrides resolve from
the project root rather than the current working directory.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import sys

from src.core.security import validate_safe_relative_path

# Project root is 3 levels up from src/core/config.py:
# src/core/config.py -> src/core -> src -> <project_root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_APP_NAME = "Mini SOC"
DEFAULT_APP_VERSION = "0.1.0"
DATA_DIRECTORY_NAME = "Mini SOC"


def _default_data_directory() -> Path:
    """Return a per-user data path outside the project checkout by default."""
    override = os.environ.get("MINISOC_DATA_DIR")
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise ValueError("MINISOC_DATA_DIR must be an absolute path")
        return path

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
        return base / DATA_DIRECTORY_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / DATA_DIRECTORY_NAME

    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return data_home / "mini-soc"


@dataclass
class AppConfig:
    """Central configuration for Mini SOC application.

    Attributes:
        app_name: Name of the application.
        version: Semantic version of the application.
        project_root: Root directory of the Mini SOC project.
        data_dir: Directory used for local application storage. Defaults to a per-user,
            non-synchronized OS data directory; MINISOC_DATA_DIR can override it.
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
    retention_days: int = 90
    auto_create_dirs: bool = True

    def __post_init__(self) -> None:
        """Resolve all paths relative to project root and ensure directories exist."""
        if self.retention_days < 1:
            raise ValueError("retention_days must be at least 1")

        # Ensure project root is absolute and resolved
        self.project_root = self.project_root.resolve()

        if self.data_dir is None:
            self.data_dir = _default_data_directory().resolve()
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

        if self.auto_create_dirs:
            self.ensure_directories()

    @property
    def legacy_database_path(self) -> Path:
        """Return the historical repository-local database path for safe migration."""
        return (self.project_root / "data" / "minisoc.db").resolve()

    def ensure_directories(self) -> None:
        """Safely create required application directories on disk."""
        assert self.data_dir is not None
        assert self.database_path is not None
        assert self.log_dir is not None

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
