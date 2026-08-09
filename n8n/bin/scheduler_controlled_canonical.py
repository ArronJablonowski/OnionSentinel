"""Alert-store-compatible timestamp normalization and canonical JSON."""
from __future__ import annotations

import datetime as dt
import hashlib
import re

from scheduler_javascript_compat import (
    JS_WHITESPACE_CLASS,
    javascript_json_number,
    javascript_json_string,
    javascript_object_key_order,
    javascript_trim,
)


TIMESTAMP_SEPARATOR_RE = re.compile(
    rf"(\d{{4}}-\d{{2}}-\d{{2}})"
    rf"(?:T|[{JS_WHITESPACE_CLASS}]+)"
    rf"(?=\d{{2}}:\d{{2}}:\d{{2}})"
)
TIMESTAMP_RE = re.compile(
    rf"(?<![A-Za-z0-9_])\d{{4}}-\d{{2}}-\d{{2}}"
    rf"(?:T|[{JS_WHITESPACE_CLASS}]+)"
    rf"\d{{2}}:\d{{2}}:\d{{2}}"
    rf"(?:\.\d+)?(?:Z|[+-]\d{{2}}:?\d{{2}})?"
    rf"(?![A-Za-z0-9_])"
)


def controlled_parse_javascript_timestamp(
    value: str,
) -> tuple[dt.datetime, int]:
    """Parse ISO fields that JavaScript Date normalizes beyond fromisoformat."""
    matched = re.fullmatch(
        r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-"
        r"(?P<day>[0-9]{2})T(?P<hour>[0-9]{2}):"
        r"(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
        r"(?:\.(?P<fraction>[0-9]+))?"
        r"(?P<zone>Z|[+-][0-9]{2}:?[0-9]{2})",
        value,
        re.ASCII,
    )
    if not matched:
        raise ValueError("timestamp does not match JavaScript ISO fields")
    fields = _timestamp_fields(matched)
    fraction = matched.group("fraction") or ""
    _validate_timestamp_fields(fields, fraction)
    timezone = _timestamp_timezone(matched.group("zone"))
    parse_year, year_adjustment = _safe_parse_year(fields["year"])
    parsed = dt.datetime(
        parse_year,
        fields["month"],
        1,
        tzinfo=timezone,
    ) + dt.timedelta(
        days=fields["day"] - 1,
        hours=fields["hour"],
        minutes=fields["minute"],
        seconds=fields["second"],
        microseconds=int((fraction + "000000")[:6]) if fraction else 0,
    )
    return parsed, year_adjustment


def _timestamp_fields(matched: re.Match[str]) -> dict[str, int]:
    return {
        name: int(matched.group(name))
        for name in ("year", "month", "day", "hour", "minute", "second")
    }


def _validate_timestamp_fields(
    fields: dict[str, int], fraction: str
) -> None:
    if (
        fields["month"] not in range(1, 13)
        or fields["day"] not in range(1, 32)
        or fields["hour"] not in range(0, 25)
        or fields["minute"] not in range(0, 60)
        or fields["second"] not in range(0, 60)
        or _invalid_midnight_overflow(fields, fraction)
    ):
        raise ValueError("timestamp fields are outside JavaScript Date bounds")


def _invalid_midnight_overflow(
    fields: dict[str, int], fraction: str
) -> bool:
    return bool(
        fields["hour"] == 24
        and (
            fields["minute"]
            or fields["second"]
            or any(character != "0" for character in fraction)
        )
    )


def _timestamp_timezone(zone: str) -> dt.tzinfo:
    if zone == "Z":
        return dt.timezone.utc
    zone_hours = int(zone[1:3])
    zone_minutes = int(zone[-2:])
    if zone_hours > 23 or zone_minutes > 59:
        raise ValueError("timestamp offset is outside JavaScript bounds")
    direction = 1 if zone[0] == "+" else -1
    return dt.timezone(
        direction * dt.timedelta(hours=zone_hours, minutes=zone_minutes)
    )


def _safe_parse_year(year: int) -> tuple[int, int]:
    if year <= 1:
        return year + 400, -400
    if year >= 9999:
        return year - 400, 400
    return year, 0


def _format_project_timestamp(parsed: dt.datetime, adjustment: int) -> str:
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    local = parsed.astimezone()
    offset = local.utcoffset()
    if offset is None:
        raise ValueError("timestamp has no UTC offset")
    milliseconds = local.microsecond // 1000
    fractional = f".{milliseconds:03d}" if milliseconds else ""
    offset_minutes = int(offset.total_seconds() / 60)
    offset_sign = "+" if offset_minutes >= 0 else "-"
    offset_minutes = abs(offset_minutes)
    return (
        f"{local.year + adjustment}-{local.month:02d}-{local.day:02d}  "
        f"{local.hour:02d}:{local.minute:02d}:{local.second:02d}"
        f"{fractional}{offset_sign}{offset_minutes // 60:02d}:"
        f"{offset_minutes % 60:02d}"
    )


def _normalize_timestamp_match(match: re.Match[str]) -> str:
    timestamp = match.group(0)
    parseable = TIMESTAMP_SEPARATOR_RE.sub(r"\1T", timestamp, count=1)
    if not re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", parseable):
        parseable = f"{parseable}Z"
    adjustment = 0
    try:
        year = int(parseable[:4])
        if year <= 1 or year >= 9999:
            parsed, adjustment = controlled_parse_javascript_timestamp(parseable)
        else:
            parsed = dt.datetime.fromisoformat(
                parseable[:-1] + "+00:00"
                if parseable.endswith("Z")
                else parseable
            )
    except ValueError:
        try:
            parsed, adjustment = controlled_parse_javascript_timestamp(parseable)
        except ValueError:
            return TIMESTAMP_SEPARATOR_RE.sub(r"\1  ", timestamp)
    try:
        return _format_project_timestamp(parsed, adjustment)
    except (OverflowError, ValueError):
        return TIMESTAMP_SEPARATOR_RE.sub(r"\1  ", timestamp)


def controlled_normalize_timestamp(value: str) -> str | None:
    """Mirror alert-store's normalizeTimestampValue() for stored JSON."""
    if value == "":
        return None
    return TIMESTAMP_RE.sub(_normalize_timestamp_match, javascript_trim(value))


def controlled_normalize_stored_json(value: object) -> object:
    """Mirror alert-store's recursive normalizeJsonTimestamps()."""
    if isinstance(value, str):
        return controlled_normalize_timestamp(value)
    if isinstance(value, list):
        return [controlled_normalize_stored_json(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): controlled_normalize_stored_json(item)
            for key, item in value.items()
        }
    return value


def _serialize_canonical_json(item: object) -> str:
    if item is None:
        return "null"
    if item is True:
        return "true"
    if item is False:
        return "false"
    if isinstance(item, (int, float)):
        return javascript_json_number(item)
    if isinstance(item, str):
        return javascript_json_string(item)
    if isinstance(item, list):
        return "[" + ",".join(_serialize_canonical_json(entry) for entry in item) + "]"
    if isinstance(item, dict):
        keys = javascript_object_key_order(item)
        return "{" + ",".join(
            f"{javascript_json_string(key)}:{_serialize_canonical_json(item[key])}"
            for key in keys
        ) + "}"
    raise TypeError("controlled stored response contains a non-JSON value")


def controlled_storage_canonical_json(value: object) -> str:
    """Mirror alert-store canonicalJsonText() for terminal DB proof."""
    return _serialize_canonical_json(controlled_normalize_stored_json(value))


def controlled_storage_canonical_digest(value: object) -> str:
    return hashlib.sha256(
        controlled_storage_canonical_json(value).encode("utf-8")
    ).hexdigest()
