"""Bounded recursive observation of query counts and truncation flags."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from harness_policy import MAX_EVENT_ITEMS


RETURNED_COUNT_KEYS = frozenset(
    {
        "returned",
        "returned_hits",
        "returned_rows",
        "records_returned",
        "total_hits",
        "total_rows",
    }
)


def _bounded_children(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        return [child for _key, child in list(value.items())[:MAX_EVENT_ITEMS]]
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        return list(value)[:MAX_EVENT_ITEMS]
    return []


def _explicit_returned_counts(value: Any) -> list[int]:
    if not isinstance(value, Mapping):
        return []
    counts: list[int] = []
    for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
        if str(raw_key).strip().lower() not in RETURNED_COUNT_KEYS:
            continue
        if isinstance(child, bool):
            continue
        try:
            number = int(child)
        except (TypeError, ValueError, OverflowError):
            number = -1
        if number >= 0:
            counts.append(number)
    return counts


def observed_returned_count(value: Any, *, depth: int = 0) -> int | None:
    """Find an explicit bounded result count without inventing a zero or one."""
    if depth > 8:
        return None
    counts = _explicit_returned_counts(value)
    for child in _bounded_children(value):
        nested = observed_returned_count(child, depth=depth + 1)
        if nested is not None:
            counts.append(nested)
    return max(counts) if counts else None


def _mapping_is_explicitly_truncated(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    return any(
        (key == "truncated" or key.endswith("_truncated")) and child is True
        for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]
        for key in (str(raw_key).strip().lower(),)
    )


def observed_truncation(value: Any, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if _mapping_is_explicitly_truncated(value):
        return True
    return any(
        observed_truncation(child, depth=depth + 1)
        for child in _bounded_children(value)
    )
