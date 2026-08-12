"""Pure timestamp primitives shared by operational SLO policies."""

from __future__ import annotations

import datetime as dt


def parse_timestamp(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def age_seconds(value: object, now: dt.datetime) -> int | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return max(
        0,
        int(
            (
                now.astimezone(dt.timezone.utc)
                - parsed.astimezone(dt.timezone.utc)
            ).total_seconds()
        ),
    )
