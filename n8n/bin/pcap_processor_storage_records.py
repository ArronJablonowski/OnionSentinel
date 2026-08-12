"""Bounded JSONL sampling and deterministic summary helpers."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def scan_json_lines(
    path: Path,
    limit: int,
    json_module: Any,
) -> dict[str, Any]:
    """Count every valid record while retaining only a bounded sample."""
    records: list[dict[str, Any]] = []
    valid_records = 0
    invalid_lines = 0
    if not path.exists():
        return _scan_result(records, valid_records, invalid_lines)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                parsed = json_module.loads(line)
            except json_module.JSONDecodeError:
                invalid_lines += 1
                continue
            if not isinstance(parsed, dict):
                invalid_lines += 1
                continue
            valid_records += 1
            if len(records) < max(0, limit):
                records.append(parsed)
    return _scan_result(records, valid_records, invalid_lines)


def _scan_result(
    records: list[dict[str, Any]],
    valid_records: int,
    invalid_lines: int,
) -> dict[str, Any]:
    return {
        "records": records,
        "valid_records": valid_records,
        "invalid_lines": invalid_lines,
        "truncated": valid_records > len(records),
    }


def top_values(
    records: list[dict[str, Any]],
    fields: tuple[str, ...],
    counter: Any,
    limit: int,
) -> list[dict[str, Any]]:
    counts = counter()
    for record in records:
        values = tuple(str(record.get(field) or "") for field in fields)
        if any(values):
            counts[values] += 1
    return [
        {"count": count, **dict(zip(fields, values))}
        for values, count in counts.most_common(limit)
    ]
