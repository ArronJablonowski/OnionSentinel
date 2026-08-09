#!/usr/bin/env python3
"""Project an alert-store row into bounded model-facing evidence."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable


SAFE_CONTENT_MODIFIERS = frozenset(
    {
        "offset",
        "depth",
        "distance",
        "within",
        "startswith",
        "endswith",
        "nocase",
        "rawbytes",
    }
)
SAFE_STATE_PRECONDITIONS = frozenset({"isset", "isnotset"})
MAX_SAFE_MESSAGE_CHARS = 2000


@dataclass(frozen=True)
class AlertProjectionSources:
    """Parsing and row operations supplied by the prompt builder facade."""

    row_value: Callable[[Any, str], Any]
    parse_alert_json: Callable[[Any], dict]
    parse_json_object: Callable[[Any], dict]
    extract_rule_context: Callable[[dict, dict, Any], dict]


def _safe_message(alert: dict) -> str | None:
    message = alert.get("message")
    if not isinstance(message, str) or len(message) > MAX_SAFE_MESSAGE_CHARS:
        return None
    return None if '"packet"' in message else message


def _safe_modifiers(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return {}
    return {
        key: value
        for key, value in raw.items()
        if key in SAFE_CONTENT_MODIFIERS
        and (
            isinstance(value, bool)
            or re.fullmatch(r"\d{1,8}", str(value or ""))
        )
    }


def _content_predicates(parsed_rule: dict) -> list[dict]:
    contents = parsed_rule.get("contents")
    if not isinstance(contents, list):
        return []
    safe: list[dict] = []
    for item in contents:
        if not isinstance(item, dict):
            continue
        safe.append(
            {
                "id": item.get("id"),
                "sha256": item.get("sha256"),
                "length": item.get("length"),
                "negated": bool(item.get("negated")),
                "modifiers": _safe_modifiers(item.get("modifiers")),
            }
        )
    return safe


def _state_preconditions(parsed_rule: dict) -> list[dict]:
    operations = parsed_rule.get("state_operations")
    if not isinstance(operations, list):
        return []
    return [
        {"kind": item.get("kind"), "operation": item.get("operation")}
        for item in operations
        if isinstance(item, dict)
        and str(item.get("operation") or "").lower() in SAFE_STATE_PRECONDITIONS
    ]


def _rule_projection(rule_context: dict, parsed_rule: dict) -> dict:
    return {
        "sid": rule_context.get("sid"),
        "record_rule_id": rule_context.get("record_rule_id"),
        "revision": rule_context.get("revision"),
        "name": rule_context.get("name"),
        "ruleset": rule_context.get("ruleset"),
        "category": rule_context.get("category"),
        "rule_sha256": parsed_rule.get("rule_sha256"),
        "deployed_rule": {
            "protocol": parsed_rule.get("protocol"),
            "packet_predicates": parsed_rule.get("predicates") or [],
            "content_predicates": _content_predicates(parsed_rule),
            "state_preconditions": _state_preconditions(parsed_rule),
            "unsupported_constraint_count": len(
                parsed_rule.get("unsupported_match_options") or []
            ),
        },
    }


def _base_projection(sources: AlertProjectionSources, record: Any, triage: dict) -> dict:
    required = lambda key: record[key]
    optional = lambda key: sources.row_value(record, key)
    return {
        "alert_id": required("alert_id"),
        "timestamp": required("timestamp"),
        "first_seen": required("first_seen"),
        "last_seen": required("last_seen"),
        "seen_count": required("seen_count"),
        "total_seen_count": optional("total_seen_count"),
        "rule_name": required("rule_name"),
        "event_dataset": required("event_dataset"),
        "severity": required("severity"),
        "severity_label": required("severity_label"),
        "source_ip": required("source_ip"),
        "source_port": optional("source_port"),
        "destination_ip": required("destination_ip"),
        "destination_port": optional("destination_port"),
        "transport_protocol": optional("transport_protocol"),
        "network_protocol": optional("network_protocol"),
        "rule_id": optional("rule_id"),
        "traffic_direction": required("traffic_direction"),
        "triage_score": required("triage_score"),
        "triage_level": required("triage_level"),
        "routing": required("routing"),
        "filter_status": required("filter_status"),
        "filter_reason": required("filter_reason"),
        "suppression_key": required("suppression_key"),
        "triage_reasons": triage.get("reasons", []),
    }


def _raw_alert_subset(alert: dict, safe_message: str | None) -> dict:
    return {
        "source": alert.get("source"),
        "destination": alert.get("destination"),
        "network": alert.get("network"),
        "event": alert.get("event"),
        "observer": alert.get("observer"),
        "message": safe_message,
        "rule_category": alert.get("rule_category"),
        "rule_ruleset": alert.get("rule_ruleset"),
        "signature_id": alert.get("signature_id"),
    }


def project_compact_alert(sources: AlertProjectionSources, record: Any) -> dict:
    """Return the bounded alert and deployed-rule context admitted to prompts."""
    alert = sources.parse_alert_json(record["alert_json"])
    triage = alert.get("triage") if isinstance(alert.get("triage"), dict) else {}
    raw_event = sources.parse_json_object(
        str(sources.row_value(record, "raw_event_json") or "")
    )
    rule_context = sources.extract_rule_context(
        alert,
        raw_event,
        sources.row_value(record, "rule_id"),
    )
    parsed_rule = (
        rule_context.get("parsed_rule")
        if isinstance(rule_context.get("parsed_rule"), dict)
        else {}
    )
    return {
        **_base_projection(sources, record, triage),
        "rule_context": _rule_projection(rule_context, parsed_rule),
        "raw_alert_subset": _raw_alert_subset(alert, _safe_message(alert)),
    }
