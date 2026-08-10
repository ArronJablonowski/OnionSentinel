"""Pure candidate matching for typed derived-PCAP filters."""

from __future__ import annotations

import ipaddress
import math
from typing import Any, Callable, Iterable


def iter_scalars(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from iter_scalars(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_scalars(item)
    elif value not in (None, ""):
        yield value


def field_values(value: Any, aliases: set[str]) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key) in aliases:
                found.extend(iter_scalars(item))
            if isinstance(item, (dict, list)):
                found.extend(field_values(item, aliases))
    elif isinstance(value, list):
        for item in value:
            found.extend(field_values(item, aliases))
    return found


def equals(
    candidate: Any,
    expected: Any,
    *,
    sanitize_text: Callable[[Any, int], str],
    max_text_chars: int,
) -> bool:
    if isinstance(expected, bool):
        return candidate is expected or (
            str(candidate).strip().casefold() == str(expected).casefold()
        )
    if isinstance(expected, int):
        try:
            return int(candidate) == expected and float(candidate) == expected
        except (TypeError, ValueError, OverflowError):
            return False
    return (
        sanitize_text(candidate, max_text_chars).casefold()
        == str(expected).casefold()
    )


def numeric_values(
    candidate: Any,
    field: str,
    *,
    aliases: dict[str, set[str]],
) -> list[float]:
    output: list[float] = []
    for value in field_values(candidate, aliases[field]):
        try:
            converted = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(converted):
            output.append(converted)
    return output


def filter_matches(
    candidate: Any,
    field: str,
    expected: Any,
    *,
    ip_filters: set[str],
    aliases: dict[str, set[str]],
    compare: Callable[[Any, Any], bool],
    numeric: Callable[[Any, str], list[float]],
    sanitize_text: Callable[[Any, int], str],
    max_text_chars: int,
) -> bool:
    if field in ip_filters:
        names = (
            aliases["source_ip"] | aliases["destination_ip"]
            if field == "endpoint_ip"
            else aliases[field]
        )
        return _matches_ip(candidate, names, expected)
    if field == "port":
        values = field_values(
            candidate,
            aliases["source_port"] | aliases["destination_port"],
        )
        return any(compare(value, expected) for value in values)
    if field == "uri_prefix":
        prefix = str(expected).casefold()
        return any(
            sanitize_text(value, max_text_chars).casefold().startswith(prefix)
            for value in field_values(candidate, aliases["uri"])
        )
    bounded = _matches_numeric_bound(candidate, field, expected, numeric)
    if bounded is not None:
        return bounded
    return any(
        compare(value, expected)
        for value in field_values(candidate, aliases[field])
    )


def _matches_numeric_bound(
    candidate: Any,
    field: str,
    expected: Any,
    numeric: Callable[[Any, str], list[float]],
) -> bool | None:
    if field in {"start_epoch", "end_epoch"}:
        values = numeric(candidate, field)
        if not values:
            return False
        if field == "start_epoch":
            return any(value >= expected for value in values)
        return any(value <= expected for value in values)
    if field.endswith("_min"):
        return any(value >= expected for value in numeric(candidate, field))
    if field.endswith("_max"):
        return any(value <= expected for value in numeric(candidate, field))
    return None


def _matches_ip(candidate: Any, aliases: set[str], expected: str) -> bool:
    for value in field_values(candidate, aliases):
        try:
            if str(ipaddress.ip_address(str(value).strip())) == expected:
                return True
        except ValueError:
            continue
    return False


def matches_indicator(
    value: Any,
    indicator: str,
    *,
    sanitize_text: Callable[[Any, int], str],
    max_text_chars: int,
) -> bool:
    if not indicator:
        return True
    folded = indicator.casefold()
    return any(
        sanitize_text(item, max_text_chars).casefold() == folded
        for item in iter_scalars(value)
    )
