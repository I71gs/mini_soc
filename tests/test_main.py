"""Tests for the Mini SOC command-line entry point."""

import ctypes
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import main as app_entry


def _mock_shell32(monkeypatch, *, is_admin: bool, result: int = 42) -> MagicMock:
    shell32 = MagicMock()
    shell32.IsUserAnAdmin.return_value = is_admin
    shell32.ShellExecuteW.return_value = result
    monkeypatch.setattr(
        app_entry.ctypes,
        "windll",
        SimpleNamespace(shell32=shell32),
        raising=False,
    )
    monkeypatch.setattr(app_entry.sys, "platform", "win32")
    monkeypatch.setattr(app_entry, "_has_filtered_admin_token", lambda: True)
    return shell32


def test_gui_elevation_relaunch_preserves_arguments(monkeypatch, tmp_path) -> None:
    shell32 = _mock_shell32(monkeypatch, is_admin=False)
    script_path = str(tmp_path / "Project Folder" / "main.py")
    monkeypatch.setattr(app_entry, "__file__", script_path)
    monkeypatch.setattr(app_entry.sys, "executable", r"C:\Python\python.exe")
    monkeypatch.setattr(
        app_entry.sys,
        "argv",
        [script_path, "--gui", "--sample-flag"],
    )

    assert app_entry._request_gui_elevation()

    call = shell32.ShellExecuteW.call_args.args
    assert call[1] == "runas"
    assert call[2] == r"C:\Python\python.exe"
    assert call[3] == subprocess.list2cmdline(
        [str(Path(script_path).resolve()), "--gui", "--sample-flag"]
    )
    assert shell32.ShellExecuteW.restype is ctypes.c_void_p


def test_gui_elevation_decline_falls_back_to_standard_user(monkeypatch, capsys) -> None:
    shell32 = _mock_shell32(monkeypatch, is_admin=False, result=5)

    assert not app_entry._request_gui_elevation()

    assert "continuing with standard-user visibility" in capsys.readouterr().err
    shell32.ShellExecuteW.assert_called_once()


def test_gui_does_not_request_elevation_when_already_admin(monkeypatch) -> None:
    shell32 = _mock_shell32(monkeypatch, is_admin=True)

    assert not app_entry._request_gui_elevation()

    shell32.ShellExecuteW.assert_not_called()


def test_gui_does_not_request_credentials_for_standard_user(monkeypatch, capsys) -> None:
    shell32 = _mock_shell32(monkeypatch, is_admin=False)
    monkeypatch.setattr(app_entry, "_has_filtered_admin_token", lambda: False)

    assert not app_entry._request_gui_elevation()

    assert "No filtered administrator token" in capsys.readouterr().err
    shell32.ShellExecuteW.assert_not_called()


def test_gui_entrypoint_exits_parent_after_elevated_relaunch(monkeypatch) -> None:
    monkeypatch.setattr(app_entry.sys, "argv", ["main.py", "--gui"])
    monkeypatch.setattr(app_entry, "_request_gui_elevation", lambda: True)

    with pytest.raises(SystemExit) as exit_info:
        app_entry.main()

    assert exit_info.value.code == 0
