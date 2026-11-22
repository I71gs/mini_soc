"""Automated tests for centralized application configuration."""

from pathlib import Path
import os
import sys
import pytest
from src.core.config import AppConfig, DEFAULT_APP_NAME, DEFAULT_APP_VERSION, PROJECT_ROOT


def test_config_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that default configuration attributes match expected values."""
    monkeypatch.delenv("MINISOC_DATA_DIR", raising=False)
    if os.name == "nt":
        expected_data_dir = tmp_path / "LocalAppData" / "Mini SOC"
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    elif sys.platform == "darwin":
        expected_data_dir = Path.home() / "Library" / "Application Support" / "Mini SOC"
    else:
        expected_data_dir = Path(
            os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
        ) / "mini-soc"

    config = AppConfig(auto_create_dirs=False)

    assert config.app_name == DEFAULT_APP_NAME
    assert config.version == DEFAULT_APP_VERSION
    assert config.project_root == PROJECT_ROOT
    assert config.data_dir == expected_data_dir.resolve()
    assert config.database_path == expected_data_dir.resolve() / "minisoc.db"
    assert config.log_dir == expected_data_dir.resolve() / "logs"


def test_path_resolution_independent_of_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that default paths resolve relative to project root, not current working directory."""
    # Change current working directory to an arbitrary temporary directory
    monkeypatch.chdir(tmp_path)
    data_dir = tmp_path / "user-storage"
    monkeypatch.setenv("MINISOC_DATA_DIR", str(data_dir))

    config = AppConfig(auto_create_dirs=False)

    # Paths must still point to the project root, not the temporary cwd
    assert config.project_root == PROJECT_ROOT
    assert config.data_dir == data_dir.resolve()
    assert config.database_path == data_dir.resolve() / "minisoc.db"
    assert config.log_dir == data_dir.resolve() / "logs"


def test_data_directory_creation(tmp_path: Path) -> None:
    """Test that required directories are created safely on initialization."""
    custom_root = tmp_path / "custom_soc"
    assert not custom_root.exists()

    config = AppConfig(
        project_root=custom_root,
        data_dir=custom_root / "data",
        auto_create_dirs=True,
    )

    assert config.data_dir.exists()
    assert config.data_dir.is_dir()
    assert config.log_dir.exists()
    assert config.log_dir.is_dir()


def test_manual_directory_creation(tmp_path: Path) -> None:
    """Test that ensure_directories can be called manually when auto_create_dirs is False."""
    custom_root = tmp_path / "manual_soc"
    config = AppConfig(
        project_root=custom_root,
        data_dir=custom_root / "data",
        auto_create_dirs=False,
    )

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


def test_environment_data_directory_must_be_absolute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MINISOC_DATA_DIR", "relative-storage")
    with pytest.raises(ValueError, match="must be an absolute path"):
        AppConfig(auto_create_dirs=False)
