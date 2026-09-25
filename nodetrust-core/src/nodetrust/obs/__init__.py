"""Structured logging with correlation ids and secret redaction (NT-042).

Every log line is one JSON object. `correlation_id` ties together the feed event,
scan and alert that belong to one flow. Values that look like credentials are
redacted before they are written, wherever they appear in the record.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

_correlation: contextvars.ContextVar[str | None] = contextvars.ContextVar("nodetrust_correlation", default=None)

_SECRET_PATTERNS = [
    re.compile(r"ntk_[A-Za-z0-9]+_[A-Za-z0-9_-]+"),             # NodeTrust API keys
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                   # GitHub tokens
    re.compile(r"npm_[A-Za-z0-9]{20,}"),                         # npm tokens
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)(\"?\s*[:=]\s*\"?)[^\s\",}]+"),
]
_SENSITIVE_KEYS = {"authorization", "api_key", "apikey", "password", "secret", "token", "x-api-key",
                   "smtp_password", "admin_token", "key"}


def redact(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pat in _SECRET_PATTERNS:
            if pat.groups >= 2:
                out = pat.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", out)
            elif pat.groups == 1:
                out = pat.sub(lambda m: m.group(1) + "[REDACTED]", out)
            else:
                out = pat.sub("[REDACTED]", out)
        return out
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if str(k).lower() in _SENSITIVE_KEYS else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        cid = getattr(record, "correlation_id", None) or _correlation.get()
        if cid:
            payload["correlation_id"] = cid
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(redact(payload), default=str)


_configured = False


def configure_logging(level: str = "INFO", stream=None) -> None:
    global _configured
    root = logging.getLogger("nodetrust")
    root.setLevel(level.upper())
    if not _configured:
        h = logging.StreamHandler(stream or sys.stderr)
        h.setFormatter(JsonFormatter())
        root.addHandler(h)
        root.propagate = False
        _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"nodetrust.{name}")


def log(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    logger.log(level, event, extra={"fields": fields})


@contextmanager
def correlation(cid: str | None) -> Iterator[None]:
    token = _correlation.set(cid)
    try:
        yield
    finally:
        _correlation.reset(token)


def current_correlation() -> str | None:
    return _correlation.get()
