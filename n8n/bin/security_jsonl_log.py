#!/usr/bin/env python3
"""Owner-only bounded JSONL application logging with recursive redaction."""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping


SECRET_KEY_RE = re.compile(
    r"(authorization|cookie|password|secret|token|api[_-]?key|credential)",
    re.IGNORECASE,
)
SECRET_TEXT_RE = re.compile(
    r"((?:authorization|password|secret|token|api[_-]?key)\s*[=:]\s*)"
    r"[^\s,;]+",
    re.IGNORECASE,
)


def _sanitize(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[depth-limited]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return SECRET_TEXT_RE.sub(r"\1[REDACTED]", value)[:2000]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:64]:
            normalized_key = str(key)[:160]
            result[normalized_key] = (
                "[REDACTED]"
                if SECRET_KEY_RE.search(normalized_key)
                else _sanitize(item, depth + 1)
            )
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, depth + 1) for item in value[:64]]
    return str(value)[:2000]


class SecurityJsonlLogger:
    def __init__(
        self,
        path: Path,
        *,
        service: str,
        max_bytes: int = 10 * 1024 * 1024,
        backups: int = 5,
    ) -> None:
        self.path = Path(path).expanduser()
        self.service = str(service)
        self.max_bytes = max(1024 * 1024, int(max_bytes))
        self.backups = max(1, min(20, int(backups)))
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _rotate_locked(self) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size < self.max_bytes:
            return
        for index in range(self.backups - 1, 0, -1):
            source = Path(f"{self.path}.{index}")
            target = Path(f"{self.path}.{index + 1}")
            if source.exists():
                os.replace(source, target)
        if self.path.exists():
            os.replace(self.path, Path(f"{self.path}.1"))

    def log(self, level: str, event: str, **fields: Any) -> None:
        timestamp = dt.datetime.now(dt.timezone.utc)
        record = {
            "timestamp": timestamp.isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            "timestamp_epoch_ms": int(timestamp.timestamp() * 1000),
            "level": str(level or "info").lower()[:16],
            "service": self.service,
            "process_id": os.getpid(),
            "event": str(event or "application.event")[:160],
            **_sanitize(fields),
        }
        line = (
            json.dumps(record, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_RDWR,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._rotate_locked()
            output = os.open(
                self.path,
                os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                0o600,
            )
            try:
                os.fchmod(output, 0o600)
                os.write(output, line)
                os.fsync(output)
            finally:
                os.close(output)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


__all__ = ["SecurityJsonlLogger"]
