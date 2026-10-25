"""Logging for scans: off by default, opt-in with `-v`, `--log-file` or `--log-format json`.

The scanner's own report (pretty, JSON, SARIF, annotations) goes to stdout. Logs are diagnostics
about the run itself -- which lists were chosen, how long each rule took, which files were skipped
and why -- and always go to stderr or a file, never to stdout, so `mcp-sift scan -o json | jq` keeps
working with logging turned on.

Library users get the standard behaviour: every module logs to a child of the `mcp_sift` logger,
which has a NullHandler until someone configures it.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

LOGGER_NAME = "mcp_sift"
# `txt` is an alias for `text`: plain lines, one per record.
FORMATS = ("text", "txt", "json")

# Attributes every LogRecord has; anything else on a record came from `extra=` and is a field.
_STANDARD_ATTRS = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)


def _fields(record: logging.LogRecord) -> dict[str, object]:
    return {k: v for k, v in record.__dict__.items() if k not in _STANDARD_ATTRS}


class JsonFormatter(logging.Formatter):
    """One JSON object per line, so a log aggregator can parse it without a grok pattern."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        payload.update(_fields(record))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """`12:00:01.234 INFO  scan finished files=12 findings=3` -- fields as key=value."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3]
        fields = " ".join(f"{k}={v}" for k, v in _fields(record).items())
        line = f"{stamp} {record.levelname:<7} {record.getMessage()}"
        if fields:
            line += f" {fields}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def level_for(verbosity: int) -> int:
    """0 -> warnings only, 1 (`-v`) -> INFO, 2+ (`-vv`) -> DEBUG."""
    return {0: logging.WARNING, 1: logging.INFO}.get(verbosity, logging.DEBUG)


def configure(verbosity: int = 0, log_file: Path | None = None, log_format: str = "text") -> logging.Logger:
    """Attach handlers to the `mcp_sift` logger. Idempotent: earlier handlers are replaced."""
    if log_format not in FORMATS:
        raise ValueError(f"unknown log format {log_format!r} (expected one of: {', '.join(FORMATS)})")

    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter: logging.Formatter = JsonFormatter() if log_format == "json" else TextFormatter()
    handler: logging.Handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level_for(verbosity))
    logger.propagate = False
    return logger


def disable() -> None:
    """Back to the library default: silent."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.WARNING)
    logger.propagate = True
