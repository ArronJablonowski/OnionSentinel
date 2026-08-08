"""Pure System Health beacon-history normalization and gap policy."""
from __future__ import annotations

import datetime as dt
import re
from typing import Callable


Query = dict[str, list[str]]
ParseTimestamp = Callable[[object], dt.datetime]
FormatTimestamp = Callable[..., str]


def _window_hours(query: Query) -> int:
    try:
        return max(1, min(168, int((query.get("hours") or ["24"])[0])))
    except ValueError:
        return 24


def _timestamp(beacon: dict[str, object], parse: ParseTimestamp) -> dt.datetime | None:
    keys = ("generated_at", "history_recorded_at", "last_seen", "timestamp", "exported_at")
    for key in keys:
        if not (value := beacon.get(key)):
            continue
        try:
            parsed = parse(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.astimezone(dt.timezone.utc)
        except Exception:
            continue
    return None


def _http_status(beacon: dict[str, object]) -> object:
    previous = beacon.get("relay_previous_failure")
    if isinstance(previous, dict) and previous.get("http_status") not in (None, ""):
        return previous.get("http_status")
    status = beacon.get("status")
    if isinstance(status, int):
        return status
    if isinstance(status, str) and re.fullmatch(r"\d{3}", status.strip()):
        return int(status)
    return None


def _successful(beacon: dict[str, object]) -> bool:
    status = str(beacon.get("status") or "").lower()
    return not (
        beacon.get("ok") is False
        or beacon.get("error")
        or status in {"error", "failed", "transient_failed", "still_failed"}
    )


def _entry(
    raw: dict[str, object],
    timestamp: dt.datetime,
    format_timestamp: FormatTimestamp,
) -> dict[str, object]:
    previous = raw.get("relay_previous_failure")
    previous = previous if isinstance(previous, dict) else None
    return {
        "timestamp": format_timestamp(timestamp.astimezone(), timespec="milliseconds"),
        "timestamp_utc": format_timestamp(timestamp, timespec="milliseconds", utc_z=True),
        "successful": _successful(raw) and not previous,
        "stage": raw.get("stage") or "unknown",
        "status": raw.get("status") or "unknown",
        "message_type": raw.get("message_type") or "",
        "relay_host": raw.get("relay_host") or "",
        "alert_count": raw.get("alert_count"),
        "posted_webhook_alerts": raw.get("posted_webhook_alerts"),
        "rule_name": raw.get("rule_name") or raw.get("first_rule") or "",
        "http_status": _http_status(raw),
        "error": raw.get("error") or (previous or {}).get("summary") or "",
        "previous_failure": previous,
    }


def _entries(
    history: object,
    cutoff: dt.datetime,
    parse: ParseTimestamp,
    format_timestamp: FormatTimestamp,
) -> list[dict[str, object]]:
    entries = []
    for raw in history if isinstance(history, list) else []:
        if not isinstance(raw, dict):
            continue
        timestamp = _timestamp(raw, parse)
        if timestamp and timestamp >= cutoff:
            entries.append(_entry(raw, timestamp, format_timestamp))
    return sorted(entries, key=lambda item: str(item.get("timestamp_utc") or ""))


def _gap(
    previous: dict[str, object],
    current: dict[str, object],
    parse: ParseTimestamp,
) -> dict[str, object] | None:
    previous_ts = _timestamp({"generated_at": previous.get("timestamp_utc")}, parse)
    current_ts = _timestamp({"generated_at": current.get("timestamp_utc")}, parse)
    if not previous_ts or not current_ts:
        return None
    minutes = (current_ts - previous_ts).total_seconds() / 60
    return ({
        "start": previous.get("timestamp"), "end": current.get("timestamp"),
        "minutes": round(minutes, 1), "status": "closed",
    } if minutes > 10 else None)


def _gaps(
    successful: list[dict[str, object]],
    now: dt.datetime,
    parse: ParseTimestamp,
    format_timestamp: FormatTimestamp,
) -> list[dict[str, object]]:
    gaps = [gap for previous, current in zip(successful, successful[1:]) if (
        gap := _gap(previous, current, parse)
    )]
    if not successful:
        return gaps
    last = successful[-1]
    last_ts = _timestamp({"generated_at": last.get("timestamp_utc")}, parse)
    minutes = (now - last_ts).total_seconds() / 60 if last_ts else 0
    if minutes > 10:
        gaps.append({
            "start": last.get("timestamp"),
            "end": format_timestamp(now.astimezone(), timespec="milliseconds"),
            "minutes": round(minutes, 1), "status": "open",
        })
    return gaps


def project_beacon_history(
    query: Query,
    history: object,
    *,
    now: dt.datetime,
    generated_at: str,
    history_source: str | None,
    pcap: dict[str, object],
    pipeline: dict[str, object],
    parse_timestamp: ParseTimestamp,
    format_timestamp: FormatTimestamp,
) -> dict[str, object]:
    """Project bounded beacon records and derived outage gaps."""
    hours = _window_hours(query)
    entries = _entries(
        history, now - dt.timedelta(hours=hours), parse_timestamp, format_timestamp,
    )
    successful = [entry for entry in entries if entry.get("successful")]
    gaps = _gaps(successful, now, parse_timestamp, format_timestamp)
    return {
        "ok": True,
        "window_hours": hours,
        "generated_at": generated_at,
        "history_source": history_source,
        "entries": entries,
        "gaps": gaps,
        "pcap": pcap,
        "pipeline": pipeline,
        "summary": {
            "total": len(entries),
            "successful": len(successful),
            "unsuccessful": len(entries) - len(successful),
            "gap_count": len(gaps),
            "latest": entries[-1] if entries else None,
        },
    }
