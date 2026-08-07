"""Canonical scalar and timestamp normalization for query contracts."""

from __future__ import annotations

import datetime as dt
from typing import Any, Type


def text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def positive_integer(
    value: Any, default: int, maximum: int, label: str,
    *, error_type: Type[Exception],
) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise error_type(f"{label} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise error_type(f"{label} must be an integer") from exc
    if number < 1 or number > maximum:
        raise error_type(f"{label} must be between 1 and {maximum}")
    return number


def utc(value: Any, label: str, *, error_type: Type[Exception]) -> dt.datetime:
    value_text = text(value, 64)
    if value_text.endswith("Z"):
        value_text = value_text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(value_text)
    except ValueError as exc:
        raise error_type(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise error_type(f"{label} must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def utc_text(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
