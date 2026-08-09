#!/usr/bin/env python3
"""Normalize collector facts and derive bounded alert relationships."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
import ipaddress
import re
import sqlite3
from typing import Any, Callable, Iterable


CORRELATION_WEIGHTS = {
    "hash": 50,
    "url": 45,
    "community_id": 45,
    "domain": 35,
    "host": 35,
    "user": 35,
    "cve": 25,
    "rule": 12,
    "dataset": 4,
    "port": 4,
    "protocol": 3,
}
CORRELATION_STRONG_RELATIONSHIP_SECONDS = 300
CORRELATION_MAX_RAW_JSON_BYTES = 256 * 1024
# Community ID v1 is a base64 SHA-1 digest. Twenty decoded bytes leave four
# significant bits in the last character; the final two pad bits must be zero
# for a canonical encoding.
COMMUNITY_ID_V1_RE = re.compile(
    r"^1:[A-Za-z0-9+/]{26}[AEIMQUYcgkosw048]=$"
)


@dataclass(frozen=True)
class CorrelationFactSources:
    """Trusted decoding ports used to project collector-owned facts."""

    row_value: Callable[..., object]
    parse_json_object: Callable[[str | None], dict]


def parse_project_datetime(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def correlation_observable_weight(observable_type: str, value: str) -> int:
    if observable_type != "ip":
        return CORRELATION_WEIGHTS.get(observable_type, 0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return 0
    return 35 if address.is_private else 25


def correlation_time_bonus(
    selected_last_seen: object,
    related_last_seen: object,
) -> tuple[int, str | None]:
    selected_time = parse_project_datetime(selected_last_seen)
    related_time = parse_project_datetime(related_last_seen)
    if not selected_time or not related_time:
        return 0, None
    seconds = abs((selected_time - related_time).total_seconds())
    if seconds <= 3600:
        return 20, "detections occurred within one hour"
    if seconds <= 86400:
        return 10, "detections occurred within 24 hours"
    if seconds <= 604800:
        return 5, "detections occurred within seven days"
    return 0, None


def _nested_alert_values(alert: dict, dotted_path: str) -> list[object]:
    """Return bounded values from an explicit path, expanding arrays safely."""
    current: list[object] = [alert]
    for part in dotted_path.split("."):
        expanded: list[object] = []
        for value in current[:64]:
            if isinstance(value, dict):
                child = value.get(part)
                if isinstance(child, list):
                    expanded.extend(child[:64])
                elif child is not None:
                    expanded.append(child)
        current = expanded[:64]
        if not current:
            break
    return current[:64]


def _normalized_ip_values(values: Iterable[object]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates[:64]:
            if isinstance(candidate, dict):
                raw_values = [
                    candidate.get("data"),
                    candidate.get("ip"),
                    candidate.get("answer"),
                ]
            else:
                raw_values = [candidate]
            for raw in raw_values:
                try:
                    text = str(ipaddress.ip_address(str(raw or "").strip()))
                except ValueError:
                    continue
                if text not in normalized:
                    normalized.append(text)
                if len(normalized) >= 32:
                    return normalized
    return normalized


def _bounded_documents(sources, row_value) -> list[dict]:
    documents = []
    for key in ("alert_json", "raw_event_json"):
        value = str(sources.row_value(row_value, key) or "")
        if not value or len(value.encode("utf-8", errors="replace")) > CORRELATION_MAX_RAW_JSON_BYTES:
            documents.append({})
        else:
            documents.append(sources.parse_json_object(value))
    alert, raw_event = documents
    event_data = raw_event.get("event_data")
    projected = [alert]
    if isinstance(event_data, dict):
        projected.append(event_data)
    return projected


def _first_path(documents: list[dict], *paths: str) -> object:
    for document in documents:
        for path in paths:
            value: object = document
            for part in path.split("."):
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if value not in (None, ""):
                return value
    return None


def _normalized_ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def _normalized_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


DNS_ANSWER_PATHS = (
    "dns.resolved_ip",
    "dns.answers",
    "dns.answers.data",
    "dns.answers.ip",
    "suricata.eve.dns.answers",
    "suricata.eve.dns.answers.data",
)


def _dns_answers(documents: list[dict]) -> list[str]:
    values: list[object] = []
    for document in documents:
        for path in DNS_ANSWER_PATHS:
            values.extend(_nested_alert_values(document, path))
    return _normalized_ip_values(values)


def _row_timestamp(sources, row_value) -> dt.datetime | None:
    return (
        parse_project_datetime(sources.row_value(row_value, "last_seen"))
        or parse_project_datetime(sources.row_value(row_value, "timestamp"))
        or parse_project_datetime(sources.row_value(row_value, "first_seen"))
    )


def _preferred(*values: object) -> object:
    return next((value for value in values if value not in (None, "")), None)


def _network_fields(sources, row_value, first_path) -> dict[str, object]:
    return {
        "source_ip": _normalized_ip(
            _preferred(
                sources.row_value(row_value, "source_ip"), first_path("source.ip")
            )
        ),
        "destination_ip": _normalized_ip(
            _preferred(
                sources.row_value(row_value, "destination_ip"),
                first_path("destination.ip"),
            )
        ),
        "source_port": _normalized_port(
            _preferred(
                sources.row_value(row_value, "source_port"),
                first_path("source.port"),
            )
        ),
        "destination_port": _normalized_port(
            _preferred(
                sources.row_value(row_value, "destination_port"),
                first_path("destination.port"),
            )
        ),
        "transport": str(
            _preferred(
                sources.row_value(row_value, "transport_protocol"),
                first_path("network.transport"),
                "",
            )
        ).strip().lower(),
        "protocol": str(
            _preferred(
                sources.row_value(row_value, "network_protocol"),
                first_path("network.protocol"),
                "",
            )
        ).strip().lower(),
    }


def correlation_row_facts(
    sources: CorrelationFactSources,
    row_value: sqlite3.Row | dict,
) -> dict[str, Any]:
    """Project only collector-owned alert fields used for deterministic joins."""
    documents = _bounded_documents(sources, row_value)
    first_path = lambda *paths: _first_path(documents, *paths)
    community_id = str(
        _preferred(first_path("network.community_id", "community_id"), "")
    ).strip()
    if not COMMUNITY_ID_V1_RE.fullmatch(community_id):
        community_id = ""
    timestamp = _row_timestamp(sources, row_value)
    return {
        **_network_fields(sources, row_value, first_path),
        "community_id": community_id,
        "dns_answers": _dns_answers(documents),
        "timestamp": timestamp,
        "timestamp_text": timestamp.isoformat() if timestamp is not None else None,
        "rule_name": str(
            _preferred(sources.row_value(row_value, "rule_name"), "")
        ).strip(),
    }


def _relationship_common(selected_facts, related_facts):
    selected_time = selected_facts.get("timestamp")
    related_time = related_facts.get("timestamp")
    delta_seconds = (
        abs((selected_time - related_time).total_seconds())
        if isinstance(selected_time, dt.datetime)
        and isinstance(related_time, dt.datetime)
        else None
    )
    return delta_seconds, {
        "source": "alert_store_trusted_alert_telemetry",
        "selected_timestamp": selected_facts.get("timestamp_text"),
        "related_timestamp": related_facts.get("timestamp_text"),
        "time_delta_seconds": round(delta_seconds, 3) if delta_seconds is not None else None,
    }


def _same_community_relationship(selected, related, common, strongly_time_bound):
    community_id = selected.get("community_id")
    if not (
        strongly_time_bound
        and community_id
        and community_id == related.get("community_id")
    ):
        return None
    return {
        **common,
        "kind": "same_community_id",
        "confidence": "high",
        "weight": 75,
        "facts": {"community_id": community_id},
        "interpretation_limit": (
            "The records carry the same canonical flow identifier within five "
            "minutes; this is a correlation lead, not proof that they are one "
            "connection instance, authorized, or malicious."
        ),
    }


def _reversed_addresses(selected, related) -> bool:
    return bool(selected.get("source_ip")) and (
        selected.get("source_ip") == related.get("destination_ip")
        and selected.get("destination_ip") == related.get("source_ip")
    )


def _reversed_ports(selected, related) -> bool:
    return (
        selected.get("source_port") is not None
        and selected.get("source_port") == related.get("destination_port")
        and selected.get("destination_port") is not None
        and selected.get("destination_port") == related.get("source_port")
    )


def _reversed_tuple_relationship(selected, related, common, strongly_time_bound):
    transport = str(selected.get("transport") or "")
    if not strongly_time_bound or not transport:
        return None
    if transport != str(related.get("transport") or ""):
        return None
    if not _reversed_addresses(selected, related):
        return None
    if not _reversed_ports(selected, related):
        return None
    return {
        **common,
        "kind": "reversed_five_tuple",
        "confidence": "high",
        "weight": 65,
        "facts": {
            "selected_source_ip": selected["source_ip"],
            "selected_source_port": selected["source_port"],
            "selected_destination_ip": selected["destination_ip"],
            "selected_destination_port": selected["destination_port"],
            "transport": transport,
        },
        "interpretation_limit": (
            "The records carry opposite directions of one exact transport tuple "
            "within five minutes; this is a correlation lead, while connection "
            "identity and protocol state still require packet or Zeek evidence."
        ),
    }


def _chronological_delta(dns_facts, network_facts) -> float | None:
    network_time = network_facts.get("timestamp")
    dns_time = dns_facts.get("timestamp")
    return (
        (network_time - dns_time).total_seconds()
        if isinstance(network_time, dt.datetime)
        and isinstance(dns_time, dt.datetime)
        else None
    )


def _likely_encrypted(network_facts) -> bool:
    return (
        network_facts.get("destination_port") == 443
        or str(network_facts.get("protocol") or "") in {"tls", "ssl", "https"}
    )


def _valid_dns_destination(dns_facts, network_facts, destination_ip, delta) -> bool:
    if not destination_ip:
        return False
    if destination_ip not in set(dns_facts.get("dns_answers") or []):
        return False
    if not dns_facts.get("source_ip"):
        return False
    if dns_facts.get("source_ip") != network_facts.get("source_ip"):
        return False
    return bool(
        _likely_encrypted(network_facts)
        and delta is not None
        and 0 <= delta <= 300
    )


def _dns_destination_relationship(dns_facts, network_facts, common, direction):
    destination_ip = network_facts.get("destination_ip")
    chronological_delta = _chronological_delta(dns_facts, network_facts)
    if not _valid_dns_destination(
        dns_facts,
        network_facts,
        destination_ip,
        chronological_delta,
    ):
        return None
    return {
        **common,
        "kind": "dns_answer_to_destination",
        "confidence": "high",
        "weight": 70,
        "direction": direction,
        "facts": {
            "client_ip": dns_facts["source_ip"],
            "resolved_ip": destination_ip,
            "subsequent_destination_port": network_facts.get("destination_port"),
            "elapsed_seconds": round(chronological_delta, 3),
        },
        "interpretation_limit": (
            "The same client contacted a DNS answer shortly afterward; the "
            "queried name and TLS SNI must be evaluated separately."
        ),
    }


def correlation_relationships(
    selected_facts: dict[str, Any],
    related_facts: dict[str, Any],
) -> list[dict[str, Any]]:
    """Describe exact, bounded relationships without inferring intent."""
    delta_seconds, common = _relationship_common(selected_facts, related_facts)
    strongly_time_bound = bool(
        delta_seconds is not None
        and delta_seconds <= CORRELATION_STRONG_RELATIONSHIP_SECONDS
    )
    candidates = (
        _same_community_relationship(
            selected_facts, related_facts, common, strongly_time_bound
        ),
        _reversed_tuple_relationship(
            selected_facts, related_facts, common, strongly_time_bound
        ),
        _dns_destination_relationship(
            selected_facts,
            related_facts,
            common,
            "selected_dns_to_related_network",
        ),
        _dns_destination_relationship(
            related_facts,
            selected_facts,
            common,
            "related_dns_to_selected_network",
        ),
    )
    return [item for item in candidates if item is not None][:6]
