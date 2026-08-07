"""Pure timestamp parsing and display normalization for dashboard renderers."""
from __future__ import annotations

import datetime as dt
import re


ISO_DATE_TIME_SEPARATOR_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})"
)
ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:T|\s+)\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)


def parse_iso_datetime(value: str | None) -> dt.datetime | None:
    """Parse an ISO timestamp, treating a missing offset as UTC."""
    if not value:
        return None
    cleaned = value.strip().strip("\"'")
    if not cleaned:
        return None
    try:
        parseable = ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1T", cleaned).replace("Z", "+00:00")
        parsed = dt.datetime.fromisoformat(parseable)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def parse_iso_timestamp(value: str | None) -> float | None:
    """Return Unix time for a valid ISO timestamp."""
    parsed = parse_iso_datetime(value)
    return parsed.timestamp() if parsed else None


def format_project_timestamp(value: dt.datetime) -> str:
    """Render a timestamp in local time using the dashboard's two-space separator."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    local_value = value.astimezone()
    timespec = "milliseconds" if local_value.microsecond else "seconds"
    return local_value.isoformat(timespec=timespec).replace("T", "  ")


def normalize_iso_display_text(value: object) -> str:
    """Normalize every ISO timestamp embedded in arbitrary display text."""

    def replace_timestamp(match: re.Match[str]) -> str:
        parsed = parse_iso_datetime(match.group(0))
        if parsed:
            return format_project_timestamp(parsed)
        return ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1  ", match.group(0))

    return ISO_TIMESTAMP_RE.sub(replace_timestamp, str(value))
