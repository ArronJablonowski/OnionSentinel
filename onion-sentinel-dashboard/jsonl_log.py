#!/usr/bin/env python3
"""Append-aware, bounded pagination for growing JSONL audit logs."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Iterator


class JsonlLogIndex:
    """Count appended records incrementally and read requested pages from EOF.

    The newest audit entries are shown first.  Keeping only a byte offset and a
    count avoids retaining the complete, indefinitely growing audit history in
    memory.  Reverse paging reads only enough tail blocks to satisfy the page.
    """

    def __init__(self, path: Path, *, block_bytes: int = 64 * 1024) -> None:
        self.path = Path(path)
        self.block_bytes = max(1024, int(block_bytes))
        self._lock = threading.RLock()
        self._identity: tuple[int, int] | None = None
        self._offset = 0
        self._pending = b""
        self._valid_records = 0

    @staticmethod
    def _decode_record(raw: bytes) -> dict | None:
        if not raw.strip():
            return None
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _reset(self, identity: tuple[int, int]) -> None:
        self._identity = identity
        self._offset = 0
        self._pending = b""
        self._valid_records = 0

    def _refresh_count(self) -> tuple[int, int]:
        """Return ``(valid_records, snapshot_size)`` for one stable snapshot."""
        try:
            stat = self.path.stat()
        except OSError:
            self._reset((0, 0))
            return 0, 0
        identity = (int(stat.st_dev), int(stat.st_ino))
        if self._identity != identity or stat.st_size < self._offset:
            self._reset(identity)

        snapshot_size = int(stat.st_size)
        if snapshot_size == self._offset:
            return self._valid_records, max(0, snapshot_size - len(self._pending))
        try:
            with self.path.open("rb") as handle:
                handle.seek(self._offset)
                new_bytes = handle.read(snapshot_size - self._offset)
        except OSError:
            return self._valid_records, self._offset

        combined = self._pending + new_bytes
        lines = combined.split(b"\n")
        self._pending = lines.pop() if lines else b""
        self._valid_records += sum(1 for line in lines if self._decode_record(line) is not None)
        self._offset = snapshot_size
        return self._valid_records, max(0, snapshot_size - len(self._pending))

    def _reverse_lines(self, snapshot_size: int) -> Iterator[bytes]:
        """Yield complete lines newest-first without loading the full file."""
        with self.path.open("rb") as handle:
            position = snapshot_size
            remainder = b""
            while position > 0:
                read_size = min(self.block_bytes, position)
                position -= read_size
                handle.seek(position)
                chunk = handle.read(read_size) + remainder
                parts = chunk.split(b"\n")
                remainder = parts.pop(0)
                for line in reversed(parts):
                    if line:
                        yield line
            if remainder:
                yield remainder

    def page(self, *, page: int, limit: int) -> tuple[int, int, list[dict]]:
        """Return total records, normalized page, and newest-first rows."""
        requested_page = max(1, int(page))
        page_size = max(1, int(limit))
        with self._lock:
            total, snapshot_size = self._refresh_count()
            total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
            normalized_page = min(requested_page, total_pages)
            skip = (normalized_page - 1) * page_size
            rows: list[dict] = []
            valid_seen = 0
            try:
                for raw in self._reverse_lines(snapshot_size):
                    value = self._decode_record(raw)
                    if value is None:
                        continue
                    if valid_seen < skip:
                        valid_seen += 1
                        continue
                    rows.append(value)
                    valid_seen += 1
                    if len(rows) >= page_size:
                        break
            except OSError:
                return total, normalized_page, []
            return total, normalized_page, rows

    def tail(self, limit: int) -> list[dict]:
        """Return the newest bounded records for static initial rendering."""
        return self.page(page=1, limit=max(1, int(limit)))[2]
