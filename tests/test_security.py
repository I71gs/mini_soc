from src.core.config import AppConfig
from src.core.security import redact_sensitive_data, safe_json_dumps, validate_safe_relative_path


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


def test_validate_safe_relative_path_rejects_traversal():
    try:
        validate_safe_relative_path("../outside")
        raise AssertionError("Expected ValueError for traversal path")
    except ValueError:
        pass


def test_app_config_rejects_escape_from_project_root(tmp_path):
    outside = tmp_path / "outside"
    try:
        AppConfig(data_dir=outside)
        raise AssertionError("Expected ValueError for escaping project root")
    except ValueError:
        pass
