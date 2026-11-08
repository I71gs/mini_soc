"""Helper utilities for safer logging and data handling in Mini SOC."""

from __future__ import annotations

import json
from typing import Any

SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "jwt",
    "private_key",
    "access_key",
)


def _contains_sensitive_key(key: str) -> bool:
    lower_key = str(key).lower()
    return any(keyword in lower_key for keyword in SENSITIVE_KEYWORDS)


def redact_sensitive_data(value: Any) -> Any:
    """Recursively redact sensitive fields from nested mappings/lists."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if _contains_sensitive_key(str(key)):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = redact_sensitive_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    return value


def safe_json_dumps(value: Any) -> str:
    """Serialize data to JSON with sensitive fields redacted."""
    try:
        return json.dumps(redact_sensitive_data(value), default=str, sort_keys=True)
    except TypeError:
        return json.dumps(redact_sensitive_data(str(value)), default=str, sort_keys=True)


def validate_safe_relative_path(path: str | Any) -> str:
    """Reject unsafe path values that attempt to escape the configured project root."""
    if not isinstance(path, str):
        raise ValueError(f"Path must be a string, got {type(path).__name__}")
    stripped = path.strip()
    if not stripped:
        raise ValueError("Path cannot be empty")
    if stripped in {".", ".."}:
        raise ValueError(f"Unsafe path provided: {path!r}")
    if ".." in stripped.split("/") or ".." in stripped.split("\\"):
        raise ValueError(f"Path traversal is not allowed: {path!r}")
    return stripped
