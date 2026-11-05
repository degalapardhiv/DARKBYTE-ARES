from __future__ import annotations

import json
import logging
import sys
import time
from contextvars import ContextVar
from datetime import UTC, datetime

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_ctx.get(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key in ("event", "method", "path", "status_code", "duration_ms", "actor_id", "target_id"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, default=str)


def configure_logging(debug: bool = False) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    for noisy in ("httpx", "httpcore", "uvicorn.access", "asyncio", "dns.resolver"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


class Timer:
    def __enter__(self):
        self.started = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed_ms = round((time.perf_counter() - self.started) * 1000, 2)
        return False
