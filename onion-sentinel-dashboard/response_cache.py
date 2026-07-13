"""Thread-safe short-lived cache for expensive, identical API responses."""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Hashable


class ResponseCache:
    """Coalesce concurrent requests by key while keeping stale time bounded."""

    def __init__(self, ttl_seconds: float = 1.0, max_entries: int = 256, lock_stripes: int = 64) -> None:
        self.ttl_seconds = max(0.0, float(ttl_seconds))
        self.max_entries = max(1, int(max_entries))
        self._entries: dict[Hashable, tuple[float, Any]] = {}
        # Fixed stripes bound synchronization memory even when clients submit
        # many unique query strings. Distinct keys still run concurrently in
        # the common case without retaining one lock per untrusted key.
        self._locks = tuple(threading.Lock() for _ in range(max(1, int(lock_stripes))))
        self._guard = threading.Lock()

    def _key_lock(self, key: Hashable) -> threading.Lock:
        return self._locks[hash(key) % len(self._locks)]

    def _store(self, key: Hashable, value: Any) -> None:
        with self._guard:
            self._entries[key] = (time.monotonic(), value)
            overflow = len(self._entries) - self.max_entries
            if overflow > 0:
                oldest = sorted(self._entries, key=lambda item: self._entries[item][0])[:overflow]
                for item in oldest:
                    self._entries.pop(item, None)

    def get_or_compute(self, key: Hashable, compute: Callable[[], Any]) -> Any:
        lock = self._key_lock(key)
        with lock:
            with self._guard:
                cached = self._entries.get(key)
            now = time.monotonic()
            if cached and now - cached[0] <= self.ttl_seconds:
                return cached[1]
            value = compute()
            self._store(key, value)
            return value

    def clear(self) -> None:
        with self._guard:
            self._entries.clear()
