"""Typed request validation for bounded derived-PCAP queries."""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Any, Callable


def text_filter(
    value: Any,
    field: str,
    max_chars: int,
    *,
    control_pattern: re.Pattern[str],
    error: type[ValueError],
) -> str:
    if not isinstance(value, (str, int, float)):
        raise error(f"PCAP evidence filter {field} must be a scalar")
    text = str(value).strip()
    if not text:
        raise error(f"PCAP evidence filter {field} cannot be empty")
    if len(text) > max_chars:
        raise error(
            f"PCAP evidence filter {field} exceeds {max_chars} characters"
        )
    if control_pattern.search(text):
        raise error(
            f"PCAP evidence filter {field} contains control characters"
        )
    return text


def integer_filter(
    value: Any,
    field: str,
    minimum: int,
    maximum: int,
    *,
    error: type[ValueError],
) -> int:
    if isinstance(value, bool):
        raise error(f"PCAP evidence filter {field} must be an integer")
    try:
        converted = int(value)
    except (TypeError, ValueError) as exc:
        raise error(
            f"PCAP evidence filter {field} must be an integer"
        ) from exc
    if (
        str(value).strip() not in {str(converted), f"+{converted}"}
        and not isinstance(value, int)
    ):
        raise error(f"PCAP evidence filter {field} must be an integer")
    if converted < minimum or converted > maximum:
        raise error(
            f"PCAP evidence filter {field} must be between "
            f"{minimum} and {maximum}"
        )
    return converted


def epoch_filter(
    value: Any,
    field: str,
    *,
    error: type[ValueError],
) -> float:
    if isinstance(value, bool):
        raise error(
            f"PCAP evidence filter {field} must be a finite epoch number"
        )
    try:
        converted = float(value)
    except (TypeError, ValueError) as exc:
        raise error(
            f"PCAP evidence filter {field} must be a finite epoch number"
        ) from exc
    if not math.isfinite(converted) or converted < 0 or converted > 4_102_444_800:
        raise error(
            f"PCAP evidence filter {field} must be a finite epoch "
            "between 1970 and 2100"
        )
    return converted


def normalize_filters(
    operation: str,
    raw: Any,
    *,
    filters_by_operation: dict[str, set[str]],
    ip_filters: set[str],
    integer_ranges: dict[str, tuple[int, int]],
    time_filters: set[str],
    boolean_filters: set[str],
    parse_text: Callable[[Any, str, int], str],
    parse_integer: Callable[[Any, str, int, int], int],
    parse_epoch: Callable[[Any, str], float],
    max_text_chars: int,
    error: type[ValueError],
) -> dict[str, Any]:
    if raw in (None, ""):
        return {}
    if not isinstance(raw, dict):
        raise error("PCAP evidence query filters must be an object")
    unknown = set(raw).difference(filters_by_operation[operation])
    if unknown:
        fields = ", ".join(sorted(str(item) for item in unknown))
        raise error(f"unsupported {operation} filter fields: {fields}")
    normalized = _normalize_field_values(
        raw,
        ip_filters=ip_filters,
        integer_ranges=integer_ranges,
        time_filters=time_filters,
        boolean_filters=boolean_filters,
        parse_text=parse_text,
        parse_integer=parse_integer,
        parse_epoch=parse_epoch,
        max_text_chars=max_text_chars,
        error=error,
    )
    _validate_filter_windows(normalized, error=error)
    return normalized


def _normalize_field_values(
    raw: dict[str, Any],
    *,
    ip_filters: set[str],
    integer_ranges: dict[str, tuple[int, int]],
    time_filters: set[str],
    boolean_filters: set[str],
    parse_text: Callable[[Any, str, int], str],
    parse_integer: Callable[[Any, str, int, int], int],
    parse_epoch: Callable[[Any, str], float],
    max_text_chars: int,
    error: type[ValueError],
) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for field, value in raw.items():
        if field in ip_filters:
            candidate = parse_text(value, field, 64)
            try:
                normalized[field] = str(ipaddress.ip_address(candidate))
            except ValueError as exc:
                raise error(
                    f"PCAP evidence filter {field} must be an IP address"
                ) from exc
        elif field in integer_ranges:
            normalized[field] = parse_integer(
                value, field, *integer_ranges[field]
            )
        elif field in time_filters:
            normalized[field] = parse_epoch(value, field)
        elif field in boolean_filters:
            if not isinstance(value, bool):
                raise error(
                    f"PCAP evidence filter {field} must be true or false"
                )
            normalized[field] = value
        else:
            normalized[field] = parse_text(value, field, max_text_chars)
    return normalized


def _validate_filter_windows(
    normalized: dict[str, Any],
    *,
    error: type[ValueError],
) -> None:
    start = normalized.get("start_epoch")
    end = normalized.get("end_epoch")
    if start is not None and end is not None and start > end:
        raise error("PCAP evidence start_epoch cannot be after end_epoch")
    for lower, upper in (
        ("frame_length_min", "frame_length_max"),
        ("payload_length_min", "payload_length_max"),
    ):
        if (
            lower in normalized
            and upper in normalized
            and normalized[lower] > normalized[upper]
        ):
            raise error(f"PCAP evidence {lower} cannot exceed {upper}")
