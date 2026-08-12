"""Bounded, secret-safe harness audit metadata projections."""
from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from harness_policy import (
    MAX_EVENT_ITEMS,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENT_STRING,
    SECRET_KEY_RE,
    SECRET_VALUE_PATTERNS,
    canonical_json,
)


def _redacted_string(value: object, maximum: int = MAX_EVENT_STRING) -> str:
    text = str(value or "")
    if any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS):
        return "[redacted-sensitive-value]"
    return text[:maximum]


def _is_metadata_scalar(value: object) -> bool:
    return value is None or isinstance(value, (bool, int, float))


def _is_metadata_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value,
        (bytes, bytearray, memoryview),
    )


def _sanitize_sequence(
    value: Sequence[Any],
    *,
    depth: int,
    item_budget: list[int],
) -> list[Any]:
    return [
        sanitize_metadata(item, depth=depth + 1, item_budget=item_budget)
        for item in list(value)[:MAX_EVENT_ITEMS]
        if item_budget[0] > 0
    ]


def sanitize_metadata(
    value: Any,
    *,
    depth: int = 0,
    item_budget: list[int] | None = None,
) -> Any:
    """Return bounded audit metadata without prompt bodies or common secrets."""
    if item_budget is None:
        item_budget = [MAX_EVENT_ITEMS]
    if depth > 8 or item_budget[0] <= 0:
        return "[truncated]"
    item_budget[0] -= 1
    if _is_metadata_scalar(value):
        return value
    if isinstance(value, str):
        return _redacted_string(value)
    if isinstance(value, Mapping):
        return _sanitize_mapping(value, depth=depth, item_budget=item_budget)
    if _is_metadata_sequence(value):
        return _sanitize_sequence(
            value,
            depth=depth,
            item_budget=item_budget,
        )
    return _redacted_string(value)


def _sanitize_mapping(
    value: Mapping[Any, Any],
    *,
    depth: int,
    item_budget: list[int],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
        if item_budget[0] <= 0:
            output["_truncated"] = True
            break
        key = _redacted_string(raw_key, 128)
        output[key] = (
            "[redacted-sensitive-field]"
            if SECRET_KEY_RE.search(key)
            else sanitize_metadata(
                child,
                depth=depth + 1,
                item_budget=item_budget,
            )
        )
    return output


def bounded_metadata(value: Any) -> dict[str, Any]:
    sanitized = sanitize_metadata(value)
    if not isinstance(sanitized, dict):
        sanitized = {"value": sanitized}
    encoded = canonical_json(sanitized).encode("utf-8")
    if len(encoded) <= MAX_EVENT_PAYLOAD_BYTES:
        return sanitized
    return {
        "payload_omitted": True,
        "original_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
