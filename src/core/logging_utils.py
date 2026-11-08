"""Operational logging utilities for Mini SOC."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.core.security import redact_sensitive_data, safe_json_dumps


def configure_logging(log_dir: str | Path, level: int = logging.INFO) -> logging.Logger:
    """Configure a project logger that writes to a local log file and emits sanitized records."""
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("mini_soc")
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)

    file_handler = logging.FileHandler(log_path / "minisoc.log", encoding="utf-8")
    file_handler.setLevel(level)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def sanitized_log_event(message: str, **context: Any) -> str:
    """Return a sanitized log entry suitable for local output."""
    safe_context = redact_sensitive_data(context)
    return f"{message} | {safe_json_dumps(safe_context)}"
