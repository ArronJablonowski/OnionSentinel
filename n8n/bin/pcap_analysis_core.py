#!/usr/bin/env python3
"""Bounded-memory primitives for untrusted packet-derived evidence.

Packet captures can contain attacker-controlled text and effectively unlimited
cardinality.  This module keeps aggregation memory bounded, produces a
deterministic representative packet sample, and strips control characters
before evidence reaches Markdown, JSON, or an LLM prompt.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable


CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def sanitize_evidence_text(value: object, max_chars: int = 1024) -> str:
    """Return display-safe text while preserving useful packet evidence.

    Newlines and tabs are normalized to spaces so packet strings cannot alter
    logs, prompts, or Markdown structure.  The value remains evidence only; it
    must never be interpreted as an instruction or command.
    """
    if max_chars <= 0:
        return ""
    text = str(value or "")
    text = ANSI_ESCAPE.sub("", text)
    text = CONTROL_CHARACTERS.sub(" ", text)
    text = " ".join(text.replace("\r", " ").replace("\n", " ").replace("\t", " ").split())
    if len(text) <= max_chars:
        return text
    return text[: max(0, max_chars - 1)] + "…"


def sanitize_evidence_value(value: Any, *, max_chars: int = 1024, max_items: int = 100) -> Any:
    """Recursively sanitize a bounded JSON-compatible evidence value."""
    if isinstance(value, dict):
        return {
            sanitize_evidence_text(key, 128): sanitize_evidence_value(item, max_chars=max_chars, max_items=max_items)
            for key, item in list(value.items())[:max_items]
        }
    if isinstance(value, list):
        return [sanitize_evidence_value(item, max_chars=max_chars, max_items=max_items) for item in value[:max_items]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize_evidence_text(value, max_chars)


class BoundedTopCounter:
    """Approximate heavy hitters with bounded memory using Space-Saving.

    Exact counters are unsafe for packet fields because every packet can carry
    a distinct hostname, URI, or tuple.  Space-Saving preserves high-frequency
    values while limiting state to ``capacity`` keys.  ``error`` exposes the
    maximum over-count introduced when a low-frequency key was replaced.
    """

    def __init__(self, capacity: int = 256) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._counts: dict[tuple[str, ...], tuple[int, int, int]] = {}
        self._heap: list[tuple[int, int, tuple[str, ...]]] = []
        self._version = 0

    def _push(self, key: tuple[str, ...], count: int, error: int) -> None:
        self._version += 1
        version = self._version
        self._counts[key] = (count, error, version)
        heapq.heappush(self._heap, (count, version, key))
        if len(self._heap) > self.capacity * 4:
            self._heap = [(item[0], item[2], key_) for key_, item in self._counts.items()]
            heapq.heapify(self._heap)

    def _pop_minimum(self) -> tuple[tuple[str, ...], int]:
        while self._heap:
            count, version, key = heapq.heappop(self._heap)
            current = self._counts.get(key)
            if current and current[0] == count and current[2] == version:
                del self._counts[key]
                return key, count
        raise RuntimeError("bounded counter heap is inconsistent")

    def add(self, values: Iterable[object]) -> None:
        key = tuple(sanitize_evidence_text(value, 512) for value in values)
        if not any(key):
            return
        current = self._counts.get(key)
        if current:
            self._push(key, current[0] + 1, current[1])
            return
        if len(self._counts) < self.capacity:
            self._push(key, 1, 0)
            return
        _, minimum = self._pop_minimum()
        self._push(key, minimum + 1, minimum)

    def most_common(self, fields: Iterable[str], limit: int = 20) -> list[dict[str, Any]]:
        field_names = tuple(fields)
        ordered = sorted(self._counts.items(), key=lambda item: (-item[1][0], item[0]))[: max(0, limit)]
        output = []
        for values, (count, error, _) in ordered:
            record: dict[str, Any] = {
                "count": count,
                **{field: value for field, value in zip(field_names, values)},
            }
            if error:
                record["count_error_max"] = error
            output.append(record)
        return output


@dataclass
class DeterministicReservoir:
    """Keep a stable, uniformly distributed sample without retaining all rows."""

    limit: int
    _heap: list[tuple[int, int, dict[str, Any]]] = field(default_factory=list)
    seen: int = 0

    def add(self, record: dict[str, Any]) -> None:
        self.seen += 1
        if self.limit <= 0:
            return
        sanitized = sanitize_evidence_value(record, max_chars=512, max_items=64)
        encoded = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        priority = int.from_bytes(hashlib.sha256(self.seen.to_bytes(8, "big") + encoded).digest()[:8], "big")
        item = (-priority, self.seen, sanitized)
        if len(self._heap) < self.limit:
            heapq.heappush(self._heap, item)
        elif priority < -self._heap[0][0]:
            heapq.heapreplace(self._heap, item)

    def records(self) -> list[dict[str, Any]]:
        return [item[2] for item in sorted(self._heap, key=lambda item: item[1])]


@dataclass
class CoverageTracker:
    """Track exact parser coverage and packet time bounds in one streaming pass."""

    total_records: int = 0
    decoded_records: int = 0
    total_bytes: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    malformed_records: int = 0

    def observe(self, *, timestamp: object = None, length: object = None, decoded: bool = True) -> None:
        self.total_records += 1
        if decoded:
            self.decoded_records += 1
        try:
            packet_bytes = int(float(str(length)))
            if packet_bytes >= 0:
                self.total_bytes += packet_bytes
        except (TypeError, ValueError):
            pass
        try:
            packet_time = float(str(timestamp))
            if math.isfinite(packet_time):
                self.first_timestamp = packet_time if self.first_timestamp is None else min(self.first_timestamp, packet_time)
                self.last_timestamp = packet_time if self.last_timestamp is None else max(self.last_timestamp, packet_time)
        except (TypeError, ValueError):
            pass

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "decoded_records": self.decoded_records,
            "undecoded_records": max(0, self.total_records - self.decoded_records),
            "decode_percent": round((self.decoded_records / self.total_records) * 100, 3) if self.total_records else 0.0,
            "total_bytes": self.total_bytes,
            "first_timestamp_epoch": self.first_timestamp,
            "last_timestamp_epoch": self.last_timestamp,
            "duration_seconds": round(max(0.0, (self.last_timestamp or 0) - (self.first_timestamp or 0)), 6)
            if self.first_timestamp is not None and self.last_timestamp is not None
            else 0.0,
            "malformed_records": self.malformed_records,
        }
