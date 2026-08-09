#!/usr/bin/env python3
"""Project visible query capability and hidden broker authorization context."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class QueryContextPolicy:
    query_contract: str
    query_v2: bool
    query_packs: tuple[str, ...]
    pack_descriptions: Mapping[str, str]
    security_onion_purposes: tuple[str, ...]
    derived_operations: tuple[str, ...]
    derived_filters: Mapping[str, list[str]]
    contract_packs: Mapping[str, Mapping[str, Any]]
    event_tuple_paths: Mapping[str, tuple[str, ...]]
    pack_role_mode: Mapping[str, str]
    allowed_actor_roles: frozenset[str]
    event_tuple_atom_pattern: re.Pattern[str]
    alert_index_pattern: re.Pattern[str]
    elastic_id_pattern: re.Pattern[str]
    pivot_atom_pattern: re.Pattern[str]
    pivot_domain_pattern: re.Pattern[str]
    max_rounds: int
    max_queries_total: int
    max_queries_per_round: int


@dataclass(frozen=True)
class QueryContextSources:
    parse_alert: Callable[[str], dict]
    parse_json_object: Callable[[str], dict]
    row_value: Callable[..., object]
    nested_value: Callable[[dict, str], object]
    parse_datetime: Callable[[object], dt.datetime | None]
    now_utc: Callable[[], dt.datetime]


def _canonical_digest(value: object, length: int = 20) -> str:
    encoded = json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:length]


def _anchor_identifiers(selected, alert: dict, sources) -> tuple[str, str]:
    index_name = str(alert.get("elastic_index") or "").strip()
    document_id = str(alert.get("elastic_id") or "").strip()
    if not index_name or not document_id:
        candidate_index, separator, candidate_id = str(
            sources.row_value(selected, "alert_id") or ""
        ).rpartition(":")
        if separator:
            index_name = index_name or candidate_index
            document_id = document_id or candidate_id
    return index_name, document_id


def _elastic_anchor(selected, alert: dict, policy, sources):
    index_name, document_id = _anchor_identifiers(selected, alert, sources)
    if (
        policy.alert_index_pattern.fullmatch(index_name)
        and policy.elastic_id_pattern.fullmatch(document_id)
    ):
        return {"index": index_name, "id": document_id}
    return None


def _valid_observable(kind: str, text: str, policy) -> bool:
    if kind == "ips":
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False
    if kind == "domains":
        return bool(policy.pivot_domain_pattern.fullmatch(text))
    return bool(policy.pivot_atom_pattern.fullmatch(text))


def _add_observable(permitted, kind: str, value: object, policy) -> None:
    if isinstance(value, list):
        for item in value[:16]:
            _add_observable(permitted, kind, item, policy)
        return
    text = str(value or "").strip().rstrip(".")
    if not text or text in permitted[kind] or len(permitted[kind]) >= 16:
        return
    if not _valid_observable(kind, text, policy):
        return
    permitted[kind].append(text)


OBSERVABLE_PATHS = {
    "ips": (
        "source.ip", "source.address", "destination.ip", "client.ip",
        "server.ip", "host.ip", "dns.resolved_ip", "related.ip",
    ),
    "domains": (
        "dns.question.name", "dns.query.name", "url.domain",
        "tls.server.name", "ssl.server_name", "http.virtual_host",
        "quic.server_name", "source.domain", "destination.domain",
        "client.domain", "server.domain",
    ),
    "hosts": (
        "host.hostname", "host.name", "host.id", "agent.id",
        "agent.name", "related.hosts",
    ),
    "users": (
        "user.name", "source.user.name", "destination.user.name",
        "client.user.name", "user.id", "related.user",
    ),
}


def _collect_document_observables(permitted, documents, policy, sources):
    for document in documents:
        for kind, paths in OBSERVABLE_PATHS.items():
            for path in paths:
                _add_observable(
                    permitted,
                    kind,
                    sources.nested_value(document, path),
                    policy,
                )


def _first_value(*values: object) -> object:
    return next((value for value in values if value), None)


def _tuple_candidates(row, alert: dict, policy, sources) -> dict[str, object]:
    nested = sources.nested_value
    return {
        "source_ip": _first_value(
            sources.row_value(row, "source_ip"), nested(alert, "source.ip")
        ),
        "destination_ip": _first_value(
            sources.row_value(row, "destination_ip"),
            nested(alert, "destination.ip"),
        ),
        "source_port": _first_value(
            sources.row_value(row, "source_port"), nested(alert, "source.port")
        ),
        "destination_port": _first_value(
            sources.row_value(row, "destination_port"),
            nested(alert, "destination.port"),
        ),
        "transport": _first_value(
            sources.row_value(row, "transport_protocol"),
            nested(alert, "network.transport"),
        ),
        "protocol": _first_value(
            sources.row_value(row, "network_protocol"),
            nested(alert, "network.protocol"),
        ),
        "community_id": nested(alert, "network.community_id"),
        "rule_id": _first_value(
            sources.row_value(row, "rule_id"),
            nested(alert, "rule.id"),
            nested(alert, "rule.uuid") if policy.query_v2 else None,
            alert.get("signature_id"),
            nested(alert, "suricata.eve.alert.signature_id"),
        ),
    }


def _normalize_tuple(candidates: Mapping[str, object], policy) -> dict:
    normalized = {}
    for field, raw_value in candidates.items():
        if raw_value in (None, ""):
            continue
        if field in {"source_ip", "destination_ip"}:
            try:
                normalized[field] = str(ipaddress.ip_address(str(raw_value)))
            except ValueError:
                continue
        elif field in {"source_port", "destination_port"}:
            try:
                port = int(raw_value)
            except (TypeError, ValueError):
                continue
            if 0 <= port <= 65535:
                normalized[field] = port
        else:
            _add_normalized_atom(normalized, field, raw_value, policy)
    return normalized


def _add_normalized_atom(normalized, field, raw_value, policy) -> None:
    text = str(raw_value).strip()
    if field in {"transport", "protocol"}:
        text = text.lower()
        pattern = policy.event_tuple_atom_pattern
    elif field == "community_id":
        pattern = re.compile(r"[A-Za-z0-9_:+/=-]{1,256}")
    else:
        pattern = policy.event_tuple_atom_pattern
    if pattern.fullmatch(text):
        normalized[field] = text


def _event_dataset(alert, original_event, sources) -> str:
    return str(
        sources.nested_value(alert, "event.dataset")
        or (
            sources.nested_value(original_event, "event.dataset")
            if isinstance(original_event, dict)
            else ""
        )
        or ""
    ).strip().lower()


def _row_index(row, alert, sources) -> str:
    return str(
        alert.get("elastic_index")
        or str(sources.row_value(row, "alert_id") or "").rpartition(":")[0]
        or ""
    ).strip().lower()


def _role_semantics(row, alert, original_event, sources) -> str:
    dataset = _event_dataset(alert, original_event, sources)
    row_index = _row_index(row, alert, sources)
    if dataset == "suricata.alert" or "suricata.alerts" in row_index:
        return "packet_direction"
    if dataset.startswith("zeek.") or "logs-zeek" in row_index:
        return "zeek_originator_responder"
    return "event_native"


def _append_event_tuple(items, value: dict, semantics: str) -> None:
    if not value or len(items) >= 32:
        return
    if any(
        item["event_tuple"] == value and item["role_semantics"] == semantics
        for item in items
    ):
        return
    items.append(
        {
            "event_tuple": value,
            "role_semantics": semantics,
            "source": "trusted_context",
            "evidence_ref": f"context:event-tuple:{_canonical_digest(value)}",
        }
    )


def _append_row_times(times, row, sources) -> None:
    for column in ("timestamp", "first_seen", "last_seen"):
        parsed = sources.parse_datetime(sources.row_value(row, column))
        if parsed is not None:
            times.append(parsed.astimezone(dt.timezone.utc))


def _collect_rows(group_rows, policy, sources):
    permitted = {"ips": [], "domains": [], "hosts": [], "users": []}
    event_tuples = []
    times = []
    for row in group_rows[:5000]:
        alert = sources.parse_alert(str(sources.row_value(row, "alert_json") or ""))
        raw = sources.parse_json_object(
            str(sources.row_value(row, "raw_event_json") or "")
        )
        original = raw.get("event_data")
        documents = [alert]
        if isinstance(original, dict):
            documents.append(original)
        _add_observable(permitted, "ips", sources.row_value(row, "source_ip"), policy)
        _add_observable(permitted, "ips", sources.row_value(row, "destination_ip"), policy)
        _collect_document_observables(permitted, documents, policy, sources)
        tuple_value = _normalize_tuple(
            _tuple_candidates(row, alert, policy, sources),
            policy,
        )
        _append_event_tuple(
            event_tuples,
            tuple_value,
            _role_semantics(row, alert, original, sources),
        )
        _append_row_times(times, row, sources)
    return permitted, event_tuples, times


def _iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _selected_time(selected, times, sources) -> dt.datetime:
    selected_time = (
        sources.parse_datetime(sources.row_value(selected, "timestamp"))
        or sources.parse_datetime(sources.row_value(selected, "last_seen"))
        or sources.parse_datetime(sources.row_value(selected, "first_seen"))
    )
    if selected_time is None:
        selected_time = max(times) if times else sources.now_utc()
    return selected_time.astimezone(dt.timezone.utc)


def _local_event_tuples(event_tuples, query_v2: bool) -> list[dict]:
    if query_v2:
        return list(event_tuples)
    return [
        {
            "event_tuple": item["event_tuple"],
            "source": item["source"],
            "evidence_ref": item["evidence_ref"],
        }
        for item in event_tuples
    ]


def _local_context(
    selected,
    group_id,
    actor_role,
    anchor,
    permitted,
    event_tuples,
    times,
    policy,
    sources,
):
    normalized_role = str(actor_role or "").strip().lower().replace("-", "_")
    if normalized_role not in policy.allowed_actor_roles:
        raise ValueError(
            f"unsupported investigation-query actor role: {actor_role or 'empty'}"
        )
    selected_time = _selected_time(selected, times, sources)
    case_seed = str(group_id or sources.row_value(selected, "alert_id") or "")
    context = {
        "context_id": "context-" + hashlib.sha256(
            f"{case_seed}:{normalized_role}".encode("utf-8")
        ).hexdigest()[:32],
        "case_id": "investigation-" + hashlib.sha256(
            case_seed.encode("utf-8")
        ).hexdigest()[:32],
        "group_id": str(group_id or ""),
        "actor_role": normalized_role,
        "anchor": anchor,
        "time_envelope": {
            "start": _iso(selected_time - dt.timedelta(hours=24)),
            "end": _iso(selected_time + dt.timedelta(hours=24)),
        },
        "permitted_observables": permitted,
        "discovered_observables": [],
        "permitted_event_tuples": _local_event_tuples(
            event_tuples,
            policy.query_v2,
        ),
    }
    if policy.query_v2:
        context["anchor_time"] = _iso(selected_time)
    return context


def _event_tuple_fields(policy) -> dict[str, list[str]]:
    return {
        pack: [
            field
            for field, paths in policy.event_tuple_paths.items()
            if set(paths).intersection(policy.contract_packs[pack]["fields"])
        ]
        for pack in policy.query_packs
    }


def _security_backend(policy, enabled: bool, *, elastic: bool) -> dict:
    aggregations = ["events", "count", "timeline"]
    semantics = {
        "events": "bounded newest-first sample with an exact total hit count",
        "count": "exact full-window count; returns no event bodies",
        "timeline": "bounded chronological sample with an exact total hit count",
    }
    if elastic and policy.query_v2:
        aggregations.append("anchor_nearest")
        semantics["anchor_nearest"] = (
            "bounded events ranked nearest the trusted alert timestamp"
        )
    result = {
        "enabled": enabled,
        "packs": list(policy.query_packs),
        "pack_descriptions": dict(policy.pack_descriptions),
        "purposes": list(policy.security_onion_purposes),
        "aggregations": aggregations,
        "aggregation_semantics": semantics,
        "max_window_hours": 24,
        "max_events": 100,
        "max_queries_per_round": 4,
        "max_observables_per_query": 8,
        "max_distinct_observables_per_batch": 24,
        "event_tuple_fields_by_pack": _event_tuple_fields(policy),
    }
    if policy.query_v2:
        result["role_mode_by_pack"] = dict(policy.pack_role_mode)
    return result


def _request_schema() -> dict:
    shared = ["pack", "window", "observables", "event_tuple", "size", "aggregation"]
    return {
        "common_fields": ["query_id", "backend", "purpose", "parameters"],
        "parameters_by_backend": {
            "elastic": list(shared),
            "oql": list(shared),
            "pcap_zeek": ["operation", "filters", "indicator", "limit"],
            "osquery": ["target_alias", "query"],
            "enrichment": ["indicator_type", "indicator"],
        },
        "rule": (
            "Choose exactly one backend and include only that backend's listed "
            "parameter fields. Never merge parameter shapes."
        ),
    }


def _visible_event_tuples(event_tuples, query_v2: bool):
    if not query_v2:
        return [item["event_tuple"] for item in event_tuples]
    return [
        {
            "event_tuple": item["event_tuple"],
            "role_semantics": item["role_semantics"],
        }
        for item in event_tuples
    ]


def _restrictions(query_v2: bool) -> list[str]:
    tuple_rule = (
        "optional event_tuple values must be copied from one advertised trusted "
        "tuple; packet direction is never projected onto Zeek originator/responder "
        "roles, and cross-sensor tuples require network.community_id"
        if query_v2
        else "optional event_tuple values must be copied from one advertised "
        "trusted tuple; supplied fields are ANDed and preserve source/destination roles"
    )
    versioned = []
    if query_v2:
        versioned = [
            "rule_id is matched exactly against either ECS rule.id or rule.uuid",
            "zero rows means no matching document for only the exact authorized "
            "filters and time window; bounded samples are not proof of complete absence",
        ]
    return [
        "structured read-only broker requests only",
        "exact supplied or evidence-discovered observables only",
        tuple_rule,
        *versioned,
        "no shell, arbitrary Query DSL, parser arguments, paths, scripts, or raw packet payloads",
        "every executed query and result carries broker-owned provenance",
    ]


def _capability(local, permitted, event_tuples, pcap_available, policy) -> dict:
    security_enabled = bool(local["anchor"]) and any(permitted.values())
    capability = {
        "query_contract": policy.query_contract,
        "enabled": security_enabled or bool(pcap_available),
        "request_schema": _request_schema(),
        "backends": _backends(policy, security_enabled, pcap_available),
        "budgets": {
            "max_rounds": policy.max_rounds,
            "max_queries_total": policy.max_queries_total,
            "max_queries_per_round": policy.max_queries_per_round,
        },
        "permitted_observables": permitted,
        "permitted_event_tuples": _visible_event_tuples(
            event_tuples,
            policy.query_v2,
        ),
        "time_envelope": local["time_envelope"],
        "restrictions": _restrictions(policy.query_v2),
    }
    if policy.query_v2:
        capability["anchor_time"] = local["anchor_time"]
    return capability


def _backends(policy, security_enabled: bool, pcap_available: bool) -> dict:
    return {
        "elastic": _security_backend(policy, security_enabled, elastic=True),
        "oql": _security_backend(policy, security_enabled, elastic=False),
        "pcap_zeek": {
            "enabled": bool(pcap_available),
            "operations": list(policy.derived_operations),
            "typed_filters": policy.derived_filters,
            "derived_evidence_only": True,
            "source_semantics": (
                "Each result truthfully lists the derived Zeek/TShark views "
                "considered; this is not a raw-capture query."
            ),
            "max_queries_per_round": 4,
        },
        "osquery": {"enabled": False, "target_aliases": [], "allowed_tables": []},
        "enrichment": {
            "enabled": False,
            "indicator_types": ["ip", "domain", "url", "hash", "cve"],
            "cache_first": True,
            "orchestrator": "n8n",
            "max_queries_per_round": 4,
            "restrictions": [
                "exact authorized or provenance-bound discovered indicators only",
                "public indicators only",
                "cache-only lookup before n8n provider orchestration",
                "provider selection and rate limits are enforced by alert-store",
            ],
        },
    }


def build_investigation_query_context(
    policy: QueryContextPolicy,
    sources: QueryContextSources,
    selected: Any,
    group_rows: list[Any],
    group_id: str,
    actor_role: str,
    pcap_available: bool,
) -> tuple[dict, dict]:
    """Build model-visible capability and hidden broker authorization state."""
    selected_alert = sources.parse_alert(
        str(sources.row_value(selected, "alert_json") or "")
    )
    anchor = _elastic_anchor(selected, selected_alert, policy, sources)
    permitted, event_tuples, times = _collect_rows(group_rows, policy, sources)
    local = _local_context(
        selected,
        group_id,
        actor_role,
        anchor,
        permitted,
        event_tuples,
        times,
        policy,
        sources,
    )
    return (
        _capability(local, permitted, event_tuples, pcap_available, policy),
        local,
    )
