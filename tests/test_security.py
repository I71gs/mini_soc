import pytest

from src.core.config import AppConfig
from src.core.security import (
    redact_sensitive_data,
    safe_json_dumps,
    spreadsheet_safe,
    validate_safe_relative_path,
)


def test_redact_sensitive_data_removes_secrets():
    payload = {
        "username": "alice",
        "password": "p@ssw0rd",
        "nested": {"token": "abcd", "status": "ok"},
        "items": ["safe", {"api_key": "secret"}],
    }

    redacted = redact_sensitive_data(payload)

    assert redacted["username"] == "alice"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["nested"]["token"] == "[REDACTED]"
    assert redacted["items"][1]["api_key"] == "[REDACTED]"


def test_safe_json_dumps_redacts_sensitive_content():
    data = {"authorization": "Bearer abc", "nested": {"password": "secret"}}
    output = safe_json_dumps(data)

    assert "[REDACTED]" in output
    assert "Bearer abc" not in output
    assert "secret" not in output


def test_spreadsheet_safe_escapes_formula_like_text():
    assert spreadsheet_safe("=HYPERLINK(\"https://example.invalid\")").startswith("'=")
    assert spreadsheet_safe(" analyst") == " analyst"


def test_validate_safe_relative_path_rejects_traversal():
    try:
        validate_safe_relative_path("../outside")
        raise AssertionError("Expected ValueError for traversal path")
    except ValueError:
        pass


def test_app_config_allows_explicit_absolute_storage_outside_project_root(tmp_path):
    outside = tmp_path / "outside"
    config = AppConfig(project_root=tmp_path / "project", data_dir=outside, auto_create_dirs=False)
    assert config.data_dir == outside.resolve()


def test_app_config_rejects_relative_storage_traversal(tmp_path):
    with pytest.raises(ValueError):
        AppConfig(project_root=tmp_path / "project", data_dir="../outside", auto_create_dirs=False)
