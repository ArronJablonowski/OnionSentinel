#!/usr/bin/env python3
"""Project exact operator authorization into prompt-safe guard evidence."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import ipaddress
import json
import re
import sqlite3
from typing import Any, Callable


@dataclass(frozen=True)
class AuthorizationContextSources:
    """Trusted row, query, and parsing operations supplied by the builder."""

    row_value: Callable[[Any, str], Any]
    parse_alert_json: Callable[[str], dict]
    parse_datetime: Callable[[Any], dt.datetime | None]
    query_row: Callable[[Any, str, list[Any]], Any]
    query_rows: Callable[[Any, str, list[Any]], list[Any]]


def _normalize_exact_string(value: Any, validator: Callable[[str], bool]) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized or not validator(normalized):
        raise ValueError("authorization selector contains an invalid value")
    return normalized


def _exact_strings(
    value: Any,
    *,
    required: bool,
    validator: Callable[[str], bool],
) -> list[str]:
    if (value is None or value == []) and not required:
        return []
    if not isinstance(value, list) or not value or len(value) > 100:
        raise ValueError("authorization selector must be a bounded list")
    result: list[str] = []
    for item in value:
        normalized = _normalize_exact_string(item, validator)
        if normalized not in result:
            result.append(normalized)
    return result


def _normalize_port(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("authorization port is invalid")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("authorization port is invalid") from exc
    if str(value).strip() != str(port) or not 1 <= port <= 65535:
        raise ValueError("authorization port is invalid")
    return port


def _ports(value: Any, *, required: bool = False) -> list[int]:
    if (value is None or value == []) and not required:
        return []
    if not isinstance(value, list) or not value or len(value) > 100:
        raise ValueError("authorization port selector must be a bounded list")
    result: list[int] = []
    for item in value:
        port = _normalize_port(item)
        if port not in result:
            result.append(port)
    return result


def _port_range_parts(value: Any) -> list[Any]:
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError("authorization port range is invalid")
    if any(isinstance(part, bool) for part in value):
        raise ValueError("authorization port range is invalid")
    return value


def _normalize_port_range(value: Any) -> list[int]:
    parts = _port_range_parts(value)
    try:
        start, end = (int(part) for part in parts)
    except (TypeError, ValueError) as exc:
        raise ValueError("authorization port range is invalid") from exc
    if any(
        str(part).strip() != str(parsed)
        for part, parsed in zip(parts, (start, end))
    ):
        raise ValueError("authorization port range is invalid")
    if start < 1 or end > 65535 or start > end:
        raise ValueError("authorization port range is invalid")
    return [start, end]


def _port_ranges(value: Any) -> list[list[int]]:
    if value is None or value == []:
        return []
    if not isinstance(value, list) or not value or len(value) > 20:
        raise ValueError("authorization port ranges must be a bounded list")
    return [_normalize_port_range(item) for item in value]


def _first_timestamp(
    sources: AuthorizationContextSources,
    selected: Any,
    alert: dict,
) -> dt.datetime | None:
    for candidate in (
        alert.get("timestamp"),
        sources.row_value(selected, "timestamp"),
        sources.row_value(selected, "last_seen"),
        sources.row_value(selected, "first_seen"),
    ):
        timestamp = sources.parse_datetime(candidate)
        if timestamp is not None:
            return timestamp.astimezone(dt.timezone.utc)
    return None


def _selected_port(
    sources: AuthorizationContextSources,
    selected: Any,
    row_name: str,
    nested: Any,
) -> int | None:
    raw = sources.row_value(selected, row_name)
    raw = raw if raw is not None else nested
    if isinstance(raw, bool):
        return None
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _object_section(value: dict, key: str) -> dict:
    section = value.get(key)
    return section if isinstance(section, dict) else {}


def _first_value(*values: Any) -> Any:
    for value in values:
        if value:
            return value
    return ""


def _normalized_text(*values: Any) -> str:
    return str(_first_value(*values)).strip().lower()


def _authorization_event_tuple(
    sources: AuthorizationContextSources,
    selected: Any,
) -> dict[str, Any] | None:
    alert = sources.parse_alert_json(
        str(sources.row_value(selected, "alert_json") or "")
    )
    source = _object_section(alert, "source")
    destination = _object_section(alert, "destination")
    network = _object_section(alert, "network")
    timestamp = _first_timestamp(sources, selected, alert)
    if timestamp is None:
        return None
    return {
        "timestamp": timestamp,
        "source_ip": _normalized_text(
            sources.row_value(selected, "source_ip"), source.get("ip")
        ),
        "destination_ip": _normalized_text(
            sources.row_value(selected, "destination_ip"), destination.get("ip")
        ),
        "source_port": _selected_port(
            sources, selected, "source_port", source.get("port")
        ),
        "destination_port": _selected_port(
            sources, selected, "destination_port", destination.get("port")
        ),
        "rule_id": _normalized_text(
            sources.row_value(selected, "rule_id"), alert.get("rule_id")
        ),
        "transport": _normalized_text(
            sources.row_value(selected, "transport_protocol"),
            sources.row_value(selected, "network_protocol"),
            network.get("transport"),
            network.get("protocol"),
        ),
    }


def _policy_identity(authorization: dict, policy_id: Any) -> str:
    normalized = str(policy_id or "").strip().lower()
    stored = str(authorization.get("policy_id") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,79}", normalized) or stored != normalized:
        raise ValueError("authorization policy identity is invalid")
    return normalized


def _time_bounds(
    sources: AuthorizationContextSources,
    authorization: dict,
) -> tuple[dt.datetime, dt.datetime]:
    start = sources.parse_datetime(authorization.get("authorization_start"))
    end = sources.parse_datetime(authorization.get("authorization_end"))
    if start is None or end is None or end <= start:
        raise ValueError("authorization time bounds are invalid")
    return (
        start.astimezone(dt.timezone.utc),
        end.astimezone(dt.timezone.utc),
    )


def _normalized_coverage(
    sources: AuthorizationContextSources,
    authorization: dict,
) -> dict[str, Any]:
    ip_validator = lambda item: bool(ipaddress.ip_address(item))
    source_ips = _exact_strings(
        authorization.get("source_ips"), required=False, validator=ip_validator
    )
    destination_ips = _exact_strings(
        authorization.get("destination_ips"), required=False, validator=ip_validator
    )
    if not source_ips and not destination_ips:
        raise ValueError("authorization requires an endpoint selector")
    destination_ports = _ports(authorization.get("destination_ports"))
    destination_port_ranges = _port_ranges(
        authorization.get("destination_port_ranges")
    )
    if not destination_ports and not destination_port_ranges:
        raise ValueError("authorization requires a destination port selector")
    start, end = _time_bounds(sources, authorization)
    return {
        "source_ips": source_ips,
        "destination_ips": destination_ips,
        "rule_ids": _exact_strings(
            authorization.get("rule_ids"),
            required=True,
            validator=lambda item: bool(re.fullmatch(r"[a-z0-9_.:-]{1,128}", item)),
        ),
        "source_ports": _ports(authorization.get("source_ports")),
        "destination_ports": destination_ports,
        "destination_port_ranges": destination_port_ranges,
        "transport_protocols": _exact_strings(
            authorization.get("transport_protocols"),
            required=True,
            validator=lambda item: bool(re.fullmatch(r"[a-z0-9_.-]{1,32}", item)),
        ),
        "authorization_start": start,
        "authorization_end": end,
    }


def _destination_port_covered(event: dict, coverage: dict) -> bool:
    port = event["destination_port"]
    if not isinstance(port, int):
        return False
    return port in coverage["destination_ports"] or any(
        start <= port <= end
        for start, end in coverage["destination_port_ranges"]
    )


def _event_covered(event: dict, coverage: dict) -> bool:
    timestamp_ok = (
        coverage["authorization_start"]
        <= event["timestamp"]
        <= coverage["authorization_end"]
    )
    source_ok = not coverage["source_ips"] or event["source_ip"] in coverage["source_ips"]
    destination_ok = (
        not coverage["destination_ips"]
        or event["destination_ip"] in coverage["destination_ips"]
    )
    source_port_ok = (
        not coverage["source_ports"]
        or event["source_port"] in coverage["source_ports"]
    )
    return all(
        (
            timestamp_ok,
            source_ok,
            destination_ok,
            event["rule_id"] in coverage["rule_ids"],
            source_port_ok,
            _destination_port_covered(event, coverage),
            event["transport"] in coverage["transport_protocols"],
        )
    )


def _serialized_coverage(coverage: dict) -> dict:
    def iso_z(value: dt.datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    return {
        **coverage,
        "authorization_start": iso_z(coverage["authorization_start"]),
        "authorization_end": iso_z(coverage["authorization_end"]),
    }


def canonical_authorized_activity_entry(
    sources: AuthorizationContextSources,
    selected: Any,
    authorization: Any,
    *,
    policy_id: Any,
) -> dict[str, Any] | None:
    """Bind stored operator authorization to one exact selected event."""
    try:
        if not isinstance(authorization, dict):
            raise ValueError("authorization must be an object")
        if str(authorization.get("status") or "").strip().lower() != "operator_authorized":
            raise ValueError("authorization status is not trusted")
        _policy_identity(authorization, policy_id)
        coverage = _normalized_coverage(sources, authorization)
        event = _authorization_event_tuple(sources, selected)
        if event is None or not _event_covered(event, coverage):
            raise ValueError("authorization does not cover selected event")
    except (TypeError, ValueError):
        return None
    serialized = _serialized_coverage(coverage)
    digest = hashlib.sha256(
        json.dumps(
            {"coverage": serialized}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return {
        "authorized": True,
        "source": "operator_assertion",
        "evidence_ref": f"authorized-activity:sha256:{digest}",
        "coverage": serialized,
    }


def _campaign_projection(
    campaign: Any,
    canonical_entry: dict,
    observations: list[Any],
) -> dict:
    member_count = int(campaign["member_count"] or 0)
    return {
        "status": "operator_authorized",
        "entries": [canonical_entry],
        "campaign_id": campaign["campaign_id"],
        "policy_id": campaign["policy_id"],
        "representative_alert_id": campaign["representative_alert_id"],
        "representative_group_id": campaign["representative_group_id"],
        "campaign_window": {
            "start": campaign["bucket_start"],
            "end": campaign["bucket_end"],
        },
        "first_seen": campaign["first_seen"],
        "last_seen": campaign["last_seen"],
        "member_count": member_count,
        "distinct_target_count": int(campaign["distinct_target_count"] or 0),
        "authorization": {
            "status": "operator_authorized",
            **canonical_entry["coverage"],
        },
        "observations": [dict(item) for item in observations],
        "observations_truncated": len(observations) < member_count,
        "interpretation": (
            "This is structured operator authorization only for the exact "
            "source/destination endpoint selectors, rule, bounded port selectors, transport, and authorization "
            "time bounds recorded above. It does not authorize a different "
            "tuple and does not prove that every packet matched the approved task."
        ),
    }


def _decoded_authorization(campaign: Any) -> dict:
    try:
        value = json.loads(str(campaign["authorization_json"] or "{}"))
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def authorized_activity_context(
    sources: AuthorizationContextSources,
    connection: Any,
    selected: Any,
    limit: int = 500,
) -> dict | None:
    """Return exact operator authorization and bounded campaign observations."""
    if connection is None:
        return None
    try:
        campaign = sources.query_row(
            connection,
            """
            SELECT campaign.*
            FROM authorized_activity_campaign_members AS member
            JOIN authorized_activity_campaigns AS campaign
              ON campaign.campaign_id = member.campaign_id
            WHERE member.alert_id = ?
            ORDER BY campaign.bucket_start DESC
            LIMIT 1
            """,
            [selected["alert_id"]],
        )
    except sqlite3.OperationalError:
        return None
    if campaign is None:
        return None
    canonical_entry = canonical_authorized_activity_entry(
        sources,
        selected,
        _decoded_authorization(campaign),
        policy_id=campaign["policy_id"],
    )
    if canonical_entry is None:
        return None
    observations = sources.query_rows(
        connection,
        """
        SELECT alert_id, stable_group_id, destination_ip, destination_port,
               observed_at
        FROM authorized_activity_campaign_members
        WHERE campaign_id = ?
        ORDER BY observed_at ASC, alert_id ASC
        LIMIT ?
        """,
        [campaign["campaign_id"], max(1, min(int(limit), 500))],
    )
    return _campaign_projection(campaign, canonical_entry, observations)
