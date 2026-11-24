"""Structured JSON logs. Every message passes the redactor, including uvicorn and Celery loggers."""

import json
import logging
import sys
from datetime import UTC, datetime

from app.core.redaction import get_redactor

# Libraries that install their own non-propagating handlers.
OWN_HANDLER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "celery", "celery.task", "celery.worker")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        redact = get_redactor().redact
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in OWN_HANDLER_LOGGERS:
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True  # route through the redacting root handler
