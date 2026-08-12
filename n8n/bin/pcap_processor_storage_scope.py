"""Bounded endpoint and time attribution for selected-alert ICMP evidence."""
from __future__ import annotations

from typing import Any


def timestamp_epoch(value: object, datetime_module: Any) -> float | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime_module.datetime.fromisoformat(
            text.replace("  ", "T").replace("Z", "+00:00")
        )
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def _normalized_ip(value: object, dependencies: dict[str, Any]) -> str:
    text = dependencies["sanitize_evidence_text"](value, 64)
    try:
        return str(dependencies["ipaddress"].ip_address(text)) if text else ""
    except ValueError:
        return ""


def _window(
    request: dict[str, Any],
    dependencies: dict[str, Any],
) -> tuple[float | None, float | None]:
    first = timestamp_epoch(request.get("first_seen"), dependencies["dt"])
    last = timestamp_epoch(request.get("last_seen"), dependencies["dt"])
    if first is None or last is None:
        return None, None
    first, last = sorted((first, last))
    try:
        requested = int(request.get("max_window_seconds") or 120)
    except (TypeError, ValueError):
        requested = 120
    seconds = max(30, min(dependencies["max_window_seconds"], requested))
    duration = max(0, int(last - first))
    if duration > seconds:
        return last - seconds, last
    padding = max(0, (seconds - duration) // 2)
    return first - padding, last + padding


def icmp_evidence_scope(
    request: dict[str, Any],
    dependencies: dict[str, Any],
) -> dict[str, Any]:
    """Build the bounded endpoint/time scope used for alert-associated ICMP."""
    start, end = _window(request, dependencies)
    return {
        "selected_alert_id": dependencies["sanitize_evidence_text"](
            request.get("alert_id"), 256
        ),
        "source_ip": _normalized_ip(request.get("source_ip"), dependencies),
        "destination_ip": _normalized_ip(
            request.get("destination_ip"), dependencies
        ),
        "window_start_epoch": start,
        "window_end_epoch": end,
        "window_basis": (
            "bounded-pcap-request-window" if start is not None else "unavailable"
        ),
    }


def icmp_scope_match(
    source: str,
    destination: str,
    timestamp: float | None,
    scope: dict[str, Any],
) -> tuple[bool, str]:
    if not _endpoint_match(source, destination, scope):
        return False, "endpoint"
    return _time_match(timestamp, scope)


def _endpoint_match(
    source: str,
    destination: str,
    scope: dict[str, Any],
) -> bool:
    selected_source = str(scope.get("source_ip") or "")
    selected_destination = str(scope.get("destination_ip") or "")
    if selected_source and selected_destination:
        return {source, destination} == {selected_source, selected_destination}
    if selected_source or selected_destination:
        return (selected_source or selected_destination) in {source, destination}
    return True


def _time_match(
    timestamp: float | None,
    scope: dict[str, Any],
) -> tuple[bool, str]:
    start = scope.get("window_start_epoch")
    end = scope.get("window_end_epoch")
    if isinstance(start, (int, float)) and isinstance(end, (int, float)):
        if timestamp is None:
            return False, "missing_timestamp"
        if timestamp < float(start) or timestamp > float(end):
            return False, "time"
    return True, ""
