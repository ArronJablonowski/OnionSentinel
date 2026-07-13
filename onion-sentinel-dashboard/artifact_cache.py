"""Small fingerprint-aware cache for append-only runtime artifact indexes."""
from __future__ import annotations

import time
from pathlib import Path
from threading import RLock
from typing import Any


class ArtifactCache:
    """Cache computed indexes briefly and invalidate them when a directory changes."""

    def __init__(self, ttl_seconds: float = 5.0) -> None:
        self.ttl_seconds = max(0.0, float(ttl_seconds))
        self._entries: dict[str, tuple[float, tuple[str, int], Any]] = {}
        self._lock = RLock()

    @staticmethod
    def fingerprint(path: Path) -> tuple[str, int]:
        try:
            return str(path), path.stat().st_mtime_ns
        except OSError:
            return str(path), 0

    def get(self, name: str, path: Path) -> Any | None:
        with self._lock:
            cached = self._entries.get(name)
            if not cached:
                return None
            cached_at, fingerprint, value = cached
            if time.monotonic() - cached_at > self.ttl_seconds:
                return None
            return value if fingerprint == self.fingerprint(path) else None

    def put(self, name: str, path: Path, value: Any) -> Any:
        with self._lock:
            self._entries[name] = (time.monotonic(), self.fingerprint(path), value)
            return value

    def get_or_compute(self, name: str, path: Path, compute) -> Any:
        """Compute one cold artifact index instead of one per request thread."""
        with self._lock:
            cached = self.get(name, path)
            if cached is not None:
                return cached
            return self.put(name, path, compute())

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
