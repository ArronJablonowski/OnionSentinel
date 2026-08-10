"""Bounded selection of derived PCAP candidate records."""

from __future__ import annotations

from typing import Any


def nested(record: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def query_candidates(
    evidence: list[Any],
    operation: str,
    *,
    query_paths: dict[str, tuple[tuple[str, ...], ...]],
    max_scan_records: int,
) -> tuple[list[Any], list[str], bool]:
    candidates: list[Any] = []
    sources: list[str] = []
    scan_truncated = False
    for item in evidence:
        if not isinstance(item, dict):
            continue
        for path in query_paths[operation]:
            value = nested(item, path)
            if value is None:
                continue
            sources.append(".".join(path))
            records = value if isinstance(value, list) else [value]
            remaining = max_scan_records - len(candidates)
            if remaining <= 0:
                scan_truncated = True
                break
            candidates.extend(records[:remaining])
            if len(records) > remaining:
                scan_truncated = True
        if len(candidates) >= max_scan_records:
            scan_truncated = True
            break
    return candidates, sorted(set(sources)), scan_truncated
