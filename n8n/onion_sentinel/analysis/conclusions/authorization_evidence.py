"""Canonical, digest-bound operator authorization evidence validation."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
from typing import Any, Callable, TypedDict


COVERAGE_KEYS = frozenset({
    "source_ips", "destination_ips", "rule_ids", "source_ports",
    "destination_ports", "destination_port_ranges", "transport_protocols",
    "authorization_start", "authorization_end",
})
ENTRY_KEYS = frozenset({"authorized", "source", "evidence_ref", "coverage"})
EVIDENCE_REF_RE = re.compile(r"authorized-activity:sha256:([0-9a-f]{64})")
UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class EventTuple(TypedDict):
    timestamp: dt.datetime
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int
    rule_id: str
    transport: str


def canonical_timestamp(value: Any) -> dt.datetime | None:
    text = str(value or "")
    if not UTC_RE.fullmatch(text):
        return None
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        return None
    rendered = parsed.astimezone(dt.timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    return parsed if rendered == text else None


def _alert_timestamp(alert: dict[str, Any]) -> dt.datetime | None:
    for key in ("timestamp", "last_seen", "first_seen"):
        raw = str(alert.get(key) or "").strip().replace("  ", "T", 1)
        if not raw:
            continue
        raw = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            candidate = dt.datetime.fromisoformat(raw)
        except ValueError:
            continue
        if candidate.tzinfo is not None:
            return candidate.astimezone(dt.timezone.utc)
    return None


def _address(alert: dict[str, Any], key: str) -> str | None:
    text = str(alert.get(key) or "").strip().lower()
    if not text:
        return ""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _port(alert: dict[str, Any], key: str) -> int | None:
    value = alert.get(key)
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if str(value).strip() == str(parsed) and 1 <= parsed <= 65535 else None


def _network_event_values_valid(
    timestamp: dt.datetime | None,
    source_ip: str | None,
    destination_ip: str | None,
    destination_port: int | None,
) -> bool:
    return bool(
        timestamp is not None
        and source_ip is not None
        and destination_ip is not None
        and bool(source_ip or destination_ip)
        and destination_port is not None
    )


def _event_identity_values_valid(rule_id: str, transport: str) -> bool:
    return bool(
        re.fullmatch(r"[a-z0-9_.:-]{1,128}", rule_id)
        and re.fullmatch(r"[a-z0-9_.-]{1,32}", transport)
    )


def prompt_event(prompt_package: dict[str, Any]) -> EventTuple | None:
    """Normalize the exact alert tuple used by the prompt builder."""
    alert = prompt_package.get("alert")
    if not isinstance(alert, dict):
        return None
    timestamp = _alert_timestamp(alert)
    source_ip = _address(alert, "source_ip")
    destination_ip = _address(alert, "destination_ip")
    source_port = _port(alert, "source_port")
    destination_port = _port(alert, "destination_port")
    rule_id = str(alert.get("rule_id") or "").strip().lower()
    transport = str(
        alert.get("transport_protocol") or alert.get("network_protocol") or ""
    ).strip().lower()
    valid = _network_event_values_valid(
        timestamp, source_ip, destination_ip, destination_port
    ) and _event_identity_values_valid(rule_id, transport)
    if not valid:
        return None
    return EventTuple(
        timestamp=timestamp, source_ip=source_ip, destination_ip=destination_ip,
        source_port=source_port, destination_port=destination_port,
        rule_id=rule_id, transport=transport,
    )


def _valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _canonical_string(
    item: Any,
    validator: Callable[[str], bool],
) -> str | None:
    text = str(item or "").strip().lower()
    if not text or text != item or not validator(text):
        return None
    return text


def _strings(
    value: dict[str, Any], key: str, *, maximum: int, required: bool,
    validator: Callable[[str], bool],
) -> list[str] | None:
    raw = value.get(key)
    if not isinstance(raw, list) or len(raw) > maximum or (required and not raw):
        return None
    normalized: list[str] = []
    for item in raw:
        text = _canonical_string(item, validator)
        if text is None or text in normalized:
            return None
        normalized.append(text)
    return normalized


def _ports(value: dict[str, Any], key: str, *, maximum: int) -> list[int] | None:
    raw = value.get(key)
    if not isinstance(raw, list) or len(raw) > maximum:
        return None
    normalized: list[int] = []
    for item in raw:
        if (
            isinstance(item, bool) or not isinstance(item, int)
            or not 1 <= item <= 65535 or item in normalized
        ):
            return None
        normalized.append(item)
    return normalized


def _port_range(item: Any) -> list[int] | None:
    valid = (
        isinstance(item, list)
        and len(item) == 2
        and all(
            isinstance(part, int) and not isinstance(part, bool)
            for part in item
        )
        and 1 <= item[0] <= item[1] <= 65535
    )
    return list(item) if valid else None


def _port_ranges(value: dict[str, Any]) -> list[list[int]] | None:
    raw = value.get("destination_port_ranges")
    if not isinstance(raw, list) or len(raw) > 20:
        return None
    normalized: list[list[int]] = []
    for item in raw:
        port_range = _port_range(item)
        if port_range is None or port_range in normalized:
            return None
        normalized.append(port_range)
    return normalized


def canonical_coverage(value: Any) -> dict[str, Any] | None:
    """Validate the prompt builder's exact, digest-bound coverage shape."""
    if not isinstance(value, dict) or set(value) != COVERAGE_KEYS:
        return None
    source_ips = _strings(value, "source_ips", maximum=100, required=False, validator=_valid_ip)
    destination_ips = _strings(value, "destination_ips", maximum=100, required=False, validator=_valid_ip)
    rule_ids = _strings(value, "rule_ids", maximum=100, required=True, validator=lambda item: bool(re.fullmatch(r"[a-z0-9_.:-]{1,128}", item)))
    transports = _strings(value, "transport_protocols", maximum=100, required=True, validator=lambda item: bool(re.fullmatch(r"[a-z0-9_.-]{1,32}", item)))
    source_ports = _ports(value, "source_ports", maximum=100)
    destination_ports = _ports(value, "destination_ports", maximum=100)
    ranges = _port_ranges(value)
    start = canonical_timestamp(value.get("authorization_start"))
    end = canonical_timestamp(value.get("authorization_end"))
    if not _coverage_parts_valid(
        source_ips, destination_ips, rule_ids, source_ports,
        destination_ports, ranges, transports, start, end,
    ):
        return None
    return {
        "source_ips": source_ips, "destination_ips": destination_ips,
        "rule_ids": rule_ids, "source_ports": source_ports,
        "destination_ports": destination_ports, "destination_port_ranges": ranges,
        "transport_protocols": transports,
        "authorization_start": str(value["authorization_start"]),
        "authorization_end": str(value["authorization_end"]),
    }


def _coverage_parts_valid(
    source_ips: Any, destination_ips: Any, rule_ids: Any, source_ports: Any,
    destination_ports: Any, ranges: Any, transports: Any,
    start: dt.datetime | None, end: dt.datetime | None,
) -> bool:
    return bool(
        _coverage_address_parts_valid(source_ips, destination_ips, rule_ids)
        and _coverage_port_parts_valid(
            source_ports, destination_ports, ranges, transports
        )
        and _coverage_window_valid(start, end)
    )


def _coverage_address_parts_valid(
    source_ips: Any,
    destination_ips: Any,
    rule_ids: Any,
) -> bool:
    return bool(
        source_ips is not None
        and destination_ips is not None
        and (source_ips or destination_ips)
        and rule_ids is not None
    )


def _coverage_port_parts_valid(
    source_ports: Any,
    destination_ports: Any,
    ranges: Any,
    transports: Any,
) -> bool:
    return bool(
        source_ports is not None
        and destination_ports is not None
        and ranges is not None
        and (destination_ports or ranges)
        and transports is not None
    )


def _coverage_window_valid(
    start: dt.datetime | None,
    end: dt.datetime | None,
) -> bool:
    return bool(start is not None and end is not None and end > start)


def _coverage_matches_event(coverage: dict[str, Any], event: EventTuple) -> bool:
    destination_port = event["destination_port"]
    start = canonical_timestamp(coverage["authorization_start"])
    end = canonical_timestamp(coverage["authorization_end"])
    assert start is not None and end is not None
    return bool(
        _coverage_window_matches_event(start, end, event)
        and _coverage_addresses_match_event(coverage, event)
        and event["rule_id"] in coverage["rule_ids"]
        and _coverage_ports_match_event(coverage, event, destination_port)
        and event["transport"] in coverage["transport_protocols"]
    )


def _coverage_window_matches_event(
    start: dt.datetime,
    end: dt.datetime,
    event: EventTuple,
) -> bool:
    return start <= event["timestamp"] <= end


def _coverage_addresses_match_event(
    coverage: dict[str, Any],
    event: EventTuple,
) -> bool:
    return bool(
        (not coverage["source_ips"]
         or event["source_ip"] in coverage["source_ips"])
        and (not coverage["destination_ips"]
             or event["destination_ip"] in coverage["destination_ips"])
    )


def _coverage_ports_match_event(
    coverage: dict[str, Any],
    event: EventTuple,
    destination_port: int,
) -> bool:
    return bool(
        (not coverage["source_ports"]
         or event["source_port"] in coverage["source_ports"])
        and (
            destination_port in coverage["destination_ports"]
            or any(
                lower <= destination_port <= upper
                for lower, upper in coverage["destination_port_ranges"]
            )
        )
    )


def entry_covers_event(entry: Any, event: EventTuple) -> bool:
    if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
        return False
    if entry.get("authorized") is not True or entry.get("source") != "operator_assertion":
        return False
    match = EVIDENCE_REF_RE.fullmatch(str(entry.get("evidence_ref") or ""))
    coverage = canonical_coverage(entry.get("coverage"))
    if match is None or coverage is None:
        return False
    digest = hashlib.sha256(json.dumps(
        {"coverage": coverage}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return match.group(1) == digest and _coverage_matches_event(coverage, event)


def has_structured_evidence(prompt_package: dict[str, Any] | None) -> bool:
    """Accept only canonical operator entries covering the exact alert tuple."""
    if not isinstance(prompt_package, dict):
        return False
    raw = prompt_package.get("authorization_evidence")
    entries = raw.get("entries") if isinstance(raw, dict) else None
    if (
        not isinstance(raw, dict) or raw.get("status") != "operator_authorized"
        or not isinstance(entries, list) or not 1 <= len(entries) <= 8
    ):
        return False
    event = prompt_event(prompt_package)
    return event is not None and all(entry_covers_event(entry, event) for entry in entries)
