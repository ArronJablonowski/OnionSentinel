"""Trusted-envelope and maximum-duration policy for investigation queries."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from typing import Any, Type

from . import primitives


@dataclass(frozen=True)
class Policy:
    maximum_duration: dt.timedelta = dt.timedelta(hours=24)


def _parse_pair(
    value: Any, prefix: str, *, exact: bool, error_type: Type[Exception],
) -> tuple[dt.datetime, dt.datetime]:
    if not isinstance(value, dict) or (exact and set(value) != {"start", "end"}):
        label = "elastic/oql window" if prefix == "elastic/oql window" else prefix
        raise error_type(f"{label} must contain exact start and end timestamps")
    start = primitives.utc(value.get("start"), f"{prefix} start", error_type=error_type)
    end = primitives.utc(value.get("end"), f"{prefix} end", error_type=error_type)
    if end <= start:
        raise error_type(f"{prefix} must be positive")
    return start, end


def _intersection(
    requested: tuple[dt.datetime, dt.datetime],
    envelope: tuple[dt.datetime, dt.datetime],
    *, error_type: Type[Exception],
) -> tuple[dt.datetime, dt.datetime]:
    start = max(requested[0], envelope[0])
    end = min(requested[1], envelope[1])
    if end <= start:
        raise error_type(
            "elastic/oql window does not overlap its trusted time envelope"
        )
    return start, end


def _clamp_nearest_center(
    start: dt.datetime, end: dt.datetime,
    envelope: tuple[dt.datetime, dt.datetime], maximum: dt.timedelta,
) -> tuple[dt.datetime, dt.datetime]:
    center = envelope[0] + (envelope[1] - envelope[0]) / 2
    if center <= start:
        return start, start + maximum
    if center >= end:
        return end - maximum, end
    clamped_start = max(start, center - maximum / 2)
    clamped_end = clamped_start + maximum
    boundary = min(end, envelope[1])
    if clamped_end > boundary:
        clamped_end = boundary
        clamped_start = clamped_end - maximum
    return clamped_start, clamped_end


def normalize(
    value: Any, *, time_envelope: Any = None,
    policy: Policy = Policy(), error_type: Type[Exception] = ValueError,
) -> tuple[dict[str, str], dict[str, Any]]:
    """Narrow a requested window to the trusted, bounded read-only envelope."""
    requested = _parse_pair(
        value, "elastic/oql window", exact=True, error_type=error_type
    )
    envelope = requested
    if time_envelope is not None:
        if (
            not isinstance(time_envelope, dict)
            or set(time_envelope) != {"start", "end"}
        ):
            raise error_type("trusted investigation time envelope is invalid")
        envelope = _parse_pair(
            time_envelope, "trusted investigation time envelope",
            exact=True, error_type=error_type,
        )
    start, end = _intersection(requested, envelope, error_type=error_type)
    reasons: list[str] = []
    if (start, end) != requested:
        reasons.append("clipped_to_trusted_time_envelope")
    if end - start > policy.maximum_duration:
        start, end = _clamp_nearest_center(
            start, end, envelope, policy.maximum_duration
        )
        reasons.append("clamped_to_24_hours_nearest_alert")
    normalized = {
        "start": primitives.utc_text(start),
        "end": primitives.utc_text(end),
    }
    audit: dict[str, Any] = {"adjusted": bool(reasons), "reasons": reasons}
    if reasons:
        audit["requested_window"] = {
            "start": primitives.utc_text(requested[0]),
            "end": primitives.utc_text(requested[1]),
        }
        audit["executed_window"] = dict(normalized)
    return normalized, audit
