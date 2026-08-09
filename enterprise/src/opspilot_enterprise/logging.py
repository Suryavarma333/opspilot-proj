"""Single-line JSON logging with mandatory redaction."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from .security import redact_json, redact_text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message, _ = redact_text(record.getMessage(), max_chars=20_000)
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        context = getattr(record, "context", None)
        if isinstance(context, dict):
            payload["context"] = redact_json(context)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)[:20_000]
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
