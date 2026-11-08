"""Automated tests for centralized application configuration."""

from pathlib import Path
import pytest
from src.core.config import AppConfig, DEFAULT_APP_NAME, DEFAULT_APP_VERSION, PROJECT_ROOT


def test_config_defaults() -> None:
    """Test that default configuration attributes match expected values."""
    config = AppConfig(auto_create_dirs=False)

    assert config.app_name == DEFAULT_APP_NAME
    assert config.version == DEFAULT_APP_VERSION
    assert config.project_root == PROJECT_ROOT
    assert config.data_dir == PROJECT_ROOT / "data"
    assert config.database_path == PROJECT_ROOT / "data" / "minisoc.db"
    assert config.log_dir == PROJECT_ROOT / "data" / "logs"


def test_path_resolution_independent_of_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that default paths resolve relative to project root, not current working directory."""
    # Change current working directory to an arbitrary temporary directory
    monkeypatch.chdir(tmp_path)

    config = AppConfig(auto_create_dirs=False)

    # Paths must still point to the project root, not the temporary cwd
    assert config.project_root == PROJECT_ROOT
    assert config.data_dir == PROJECT_ROOT / "data"
    assert config.database_path == PROJECT_ROOT / "data" / "minisoc.db"
    assert config.log_dir == PROJECT_ROOT / "data" / "logs"


def test_data_directory_creation(tmp_path: Path) -> None:
    """Test that required directories are created safely on initialization."""
    custom_root = tmp_path / "custom_soc"
    assert not custom_root.exists()

    config = AppConfig(project_root=custom_root, auto_create_dirs=True)

    assert config.data_dir.exists()
    assert config.data_dir.is_dir()
    assert config.log_dir.exists()
    assert config.log_dir.is_dir()


def test_manual_directory_creation(tmp_path: Path) -> None:
    """Test that ensure_directories can be called manually when auto_create_dirs is False."""
    custom_root = tmp_path / "manual_soc"
    config = AppConfig(project_root=custom_root, auto_create_dirs=False)

    assert not config.data_dir.exists()
    assert not config.log_dir.exists()

    config.ensure_directories()

    assert config.data_dir.exists()
    assert config.log_dir.exists()


def test_custom_path_overrides(tmp_path: Path) -> None:
    """Test explicit overrides for data_dir, database_path, and log_dir."""
    custom_data = tmp_path / "custom_data"
    custom_db = tmp_path / "custom_data" / "custom.db"
    custom_logs = tmp_path / "custom_logs"

    config = AppConfig(
        project_root=tmp_path,
        data_dir=custom_data,
        database_path=custom_db,
        log_dir=custom_logs,
        auto_create_dirs=True,
    )

    assert config.data_dir == custom_data.resolve()
    assert config.database_path == custom_db.resolve()
    assert config.log_dir == custom_logs.resolve()
    assert custom_data.exists()
    assert custom_logs.exists()
