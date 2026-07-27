#!/usr/bin/env python3
"""Policy contract for iterative Security Onion investigation pivots.

The model-facing proposal is deliberately not an Elasticsearch or Security
Onion query language.  A model may choose only a reviewed evidence pack,
display dialect, purpose, fixed aggregation mode, exact observables, bounded
UTC window, and result size.  This module combines that proposal with a trusted
local authorization context, records the origin of every observable, and
validates the full response returned by the Security Onion forced command.

Query DSL, index patterns, fields, KQL, and OQL are always generated locally.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import ipaddress
import json
import re
from typing import Any


INVESTIGATION_QUERY_CONTRACT = "onion-sentinel-investigation-pivots-v2"
INVESTIGATION_QUERY_OPERATION = "investigation_pivots"
QUERY_PREFERENCE = "onion-sentinel-incident-evidence"
MAX_QUERIES = 4
MAX_QUERY_HITS = 100
MAX_BATCH_HITS = 400
MAX_QUERY_OBSERVABLES = 8
MAX_BATCH_OBSERVABLES = 24
MAX_WINDOW = dt.timedelta(hours=24)
MAX_AUTHORIZATION_WINDOW = dt.timedelta(days=7)
MAX_CONTEXT_OBSERVABLES_PER_KIND = 16
MAX_DISCOVERED_OBSERVABLES = 32
MAX_CONTEXT_EVENT_TUPLES = 32
ALLOWED_DIALECTS = {"elastic", "oql"}
ALLOWED_AGGREGATIONS = {"events", "count", "timeline", "anchor_nearest"}
ALLOWED_PURPOSES = {
    "validate_detection",
    "establish_timeline",
    "correlate_observable",
    "measure_prevalence",
    "identify_related_activity",
    "test_benign_hypothesis",
}
ALLOWED_ACTOR_ROLES = {
    "soc_analyst",
    "incident_responder",
    "siem_engineer",
    "cyber_threat_intel",
    "threat_hunter",
}
ALLOWED_STATUSES = {"ok", "timeout", "output_limit", "error", "invalid_response"}
ALLOWED_ROLE_SEMANTICS = {
    "event_native",
    "packet_direction",
    "zeek_originator_responder",
}
OBSERVABLE_KINDS = ("ips", "domains", "hosts", "users")
OBSERVABLE_FIELDS = {
    "ips": [
        "source.ip", "destination.ip", "client.ip", "server.ip", "host.ip",
        "dns.resolved_ip", "related.ip",
    ],
    "domains": [
        "dns.question.name", "dns.query.name", "url.domain",
        "tls.server.name", "ssl.server_name", "http.virtual_host",
        "quic.server_name", "source.domain", "destination.domain",
        "client.domain", "server.domain",
    ],
    "hosts": [
        "host.id", "host.name", "host.hostname", "agent.id", "agent.name",
        "related.hosts",
    ],
    "users": [
        "user.id", "user.name", "source.user.name", "destination.user.name",
        "client.user.name", "related.user",
    ],
}
EVENT_TUPLE_FIELDS = {
    "source_ip": "source.ip",
    "destination_ip": "destination.ip",
    "source_port": "source.port",
    "destination_port": "destination.port",
    "transport": "network.transport",
    "protocol": "network.protocol",
    "community_id": "network.community_id",
    # Security Onion maps a Suricata signature ID to ECS rule.id.
    "rule_id": "rule.id",
}
# Security Onion alert documents in the same deployment may identify a
# detection with either ECS rule.id or rule.uuid.  A trusted rule identifier is
# therefore matched against both exact keyword fields, while the public
# EVENT_TUPLE_FIELDS mapping remains backwards compatible for callers that
# render field labels.
EVENT_TUPLE_PATHS = {
    **{
        field: (path,)
        for field, path in EVENT_TUPLE_FIELDS.items()
    },
    "rule_id": ("rule.id", "rule.uuid"),
}
ALERT_INDEX_SCOPE = [
    "logs-suricata.alerts-so",
    "logs-detections.alerts-so",
]
ZEEK_PROTOCOL_BASE_FIELDS = [
    "@timestamp", "event.dataset", "event.kind", "event.category",
    "event.type", "event.action", "event.outcome", "event.duration",
    "source.ip", "source.port", "destination.ip", "destination.port",
    "client.ip", "client.port", "server.ip", "server.port",
    "network.transport", "network.protocol", "network.direction",
    "network.community_id", "network.bytes", "network.packets",
    "log.id.uid", "observer.name",
]
PACKS = {
    "alert_context": {
        "indices": ALERT_INDEX_SCOPE,
        "datasets": ["suricata.alert", "sigma.alert"],
        "fields": [
            "@timestamp", "event.dataset", "event.kind", "event.category",
            "event.type", "event.action", "event.outcome", "event.severity",
            "event.id", "event.code", "rule.id", "rule.uuid", "rule.name",
            "rule.category", "rule.ruleset", "source.ip", "source.port",
            "source.domain", "source.mac", "destination.ip",
            "destination.port", "destination.domain", "destination.mac",
            "client.ip", "client.domain", "server.ip", "server.domain",
            "host.id", "host.name", "host.hostname", "agent.id",
            "user.id", "user.name", "source.user.name",
            "destination.user.name", "client.user.name",
            "network.transport", "network.protocol", "network.direction",
            "network.community_id",
        ],
    },
    "network_flow": {
        "indices": [
            "logs-zeek-so",
            "logs-endpoint.events.network-*",
            *ALERT_INDEX_SCOPE,
        ],
        "datasets": [
            "zeek.conn", "endpoint.events.network", "suricata.alert",
            "sigma.alert",
        ],
        "fields": [
            "@timestamp", "event.dataset", "event.kind", "event.category",
            "event.type", "event.action", "event.outcome", "event.duration",
            "source.ip", "source.port", "source.domain", "source.bytes",
            "source.packets", "destination.ip", "destination.port",
            "destination.domain", "destination.bytes", "destination.packets",
            "client.ip", "client.domain", "server.ip", "server.domain",
            "network.transport", "network.protocol", "network.direction",
            "network.community_id", "network.bytes", "network.packets",
            "host.id", "host.name", "host.hostname", "agent.id", "host.ip",
            "user.id", "user.name", "source.user.name",
            "destination.user.name", "client.user.name", "process.entity_id",
            "process.name", "process.executable", "rule.id", "rule.uuid",
            "rule.name",
        ],
    },
    "dns_activity": {
        "indices": ["logs-zeek-so", "logs-endpoint.events.network-*"],
        "datasets": ["zeek.dns", "endpoint.events.network"],
        "fields": [
            "@timestamp", "event.dataset", "event.kind", "event.category",
            "event.type", "event.action", "event.outcome", "source.ip",
            "source.port", "destination.ip", "destination.port",
            "source.domain", "destination.domain", "client.ip",
            "client.domain", "server.ip", "server.domain", "url.domain",
            "tls.server.name", "dns.query.name", "dns.query.type",
            "dns.query.class", "dns.response.code", "dns.response.code_name",
            "dns.highest_registered_domain", "dns.parent_domain",
            "dns.top_level_domain",
            "network.transport", "network.protocol", "network.community_id",
            "dns.id", "dns.question.name", "dns.question.type",
            "dns.question.class", "dns.response_code", "dns.resolved_ip",
            "dns.answers.type", "host.id", "host.name", "host.hostname",
            "agent.id", "host.ip", "user.id", "user.name",
            "source.user.name", "destination.user.name", "client.user.name",
            "process.entity_id", "process.name", "process.executable",
        ],
    },
    "system_auth": {
        "indices": ["logs-system.auth-*"],
        "datasets": ["system.auth"],
        "fields": [
            "@timestamp", "event.dataset", "event.kind", "event.category",
            "event.type", "event.action", "event.outcome", "event.id",
            "source.ip", "source.port", "source.address", "host.id",
            "host.name", "host.hostname", "host.ip", "agent.id",
            "agent.name", "user.id", "user.name", "related.ip",
            "related.hosts", "related.user", "process.pid", "process.name",
            "system.auth.ssh.event", "log.syslog.appname",
        ],
    },
    "zeek_tls": {
        "indices": ["logs-zeek-so"],
        "datasets": ["zeek.ssl"],
        "fields": [
            *ZEEK_PROTOCOL_BASE_FIELDS,
            "ssl.cipher", "ssl.curve", "ssl.established",
            "ssl.server_name", "ssl.validation_status", "ssl.version",
            "hash.ja3", "hash.ja3s", "hash.ja4",
            "tls.server.hash.sha256",
        ],
    },
    "zeek_http": {
        "indices": ["logs-zeek-so"],
        "datasets": ["zeek.http"],
        "fields": [
            *ZEEK_PROTOCOL_BASE_FIELDS,
            "http.method", "http.status_code", "http.status_message",
            "http.trans_depth", "http.uri", "http.useragent",
            "http.version", "http.virtual_host",
            "http.request.body.length", "http.response.body.length",
            "file.resp_mime_types", "log.id.resp_fuids",
        ],
    },
    "zeek_files": {
        "indices": ["logs-zeek-so"],
        "datasets": ["zeek.file"],
        "fields": [
            *ZEEK_PROTOCOL_BASE_FIELDS,
            "log.id.fuid", "file.analyzer", "file.bytes.missing",
            "file.bytes.overflow", "file.bytes.seen", "file.bytes.total",
            "file.depth", "file.local_orig", "file.mime_type",
            "file.source", "hash.md5", "hash.sha1", "hash.sha256",
        ],
    },
    "zeek_ssh": {
        "indices": ["logs-zeek-so"],
        "datasets": ["zeek.ssh"],
        "fields": [
            *ZEEK_PROTOCOL_BASE_FIELDS,
            "hash.hassh", "ssh.authentication.attempts",
            "ssh.authentication.success", "ssh.cipher_algorithm",
            "ssh.client", "ssh.compression_algorithm",
            "ssh.hassh_algorithms", "ssh.hassh_server",
            "ssh.hassh_server_algorithms", "ssh.hassh_version",
            "ssh.host_key_algorithm", "ssh.kex_algorithm",
            "ssh.mac_algorithm", "ssh.server", "ssh.version",
        ],
    },
    "zeek_stun": {
        "indices": ["logs-zeek-so"],
        "datasets": ["zeek.stun", "zeek.stun_nat"],
        "fields": [
            *ZEEK_PROTOCOL_BASE_FIELDS,
            "stun.attribute.types", "stun.attribute.values",
            "stun.class", "stun.id", "stun.method",
            "stun.lan.addresses", "stun.wan.addresses",
            "stun.wan.ports",
        ],
    },
    "zeek_quic": {
        "indices": ["logs-zeek-so"],
        "datasets": ["zeek.quic"],
        "fields": [
            *ZEEK_PROTOCOL_BASE_FIELDS,
            "quic.client_initial_dcid", "quic.client_protocol",
            "quic.client_scid", "quic.history", "quic.server_name",
            "quic.server_scid", "quic.version",
        ],
    },
    "zeek_anomalies": {
        "indices": ["logs-zeek-so"],
        "datasets": ["zeek.notice", "zeek.weird", "zeek.analyzer"],
        "fields": [
            *ZEEK_PROTOCOL_BASE_FIELDS,
            "notice.action", "notice.note", "notice.suppress_for",
            "weird.name", "weird.peer", "error.reason",
        ],
    },
    "osquery_history": {
        "indices": [
            "logs-endpoint.events.process-*",
            "logs-endpoint.events.file-*",
            "logs-endpoint.events.network-*",
            "logs-osquery_manager.result-default",
            "logs-osquery_manager.action.responses-default",
        ],
        "datasets": [
            "endpoint.events.process", "endpoint.events.file",
            "endpoint.events.network", "osquery_manager.result",
            "osquery_manager.action.responses",
        ],
        "fields": [
            "@timestamp", "event.dataset", "event.kind", "event.category",
            "event.type", "event.action", "event.outcome", "event.id",
            "host.id", "host.name", "host.ip", "user.id", "user.name",
            "process.entity_id", "process.pid", "process.parent.pid",
            "process.name", "process.executable", "file.name", "file.path",
            "file.extension", "file.hash.sha256", "source.ip", "source.port",
            "source.domain", "destination.ip", "destination.port",
            "destination.domain", "client.ip", "client.domain", "server.ip",
            "server.domain", "url.domain", "dns.question.name",
            "dns.resolved_ip", "network.transport", "network.protocol",
        ],
    },
    "cross_sensor_timeline": {
        "indices": [
            *ALERT_INDEX_SCOPE,
            "logs-zeek-so",
            "logs-endpoint.events.network-*",
            "logs-endpoint.events.process-*",
            "logs-endpoint.events.file-*",
        ],
        "datasets": [
            "suricata.alert", "sigma.alert", "zeek.conn", "zeek.dns",
            "endpoint.events.network", "endpoint.events.process",
            "endpoint.events.file",
        ],
        "fields": [
            "@timestamp", "event.dataset", "event.kind", "event.category",
            "event.type", "event.action", "event.outcome", "event.severity",
            "event.id", "rule.id", "rule.uuid", "rule.name", "source.ip",
            "source.port",
            "source.domain", "destination.ip", "destination.port",
            "destination.domain", "client.ip", "client.domain", "server.ip",
            "server.domain", "url.domain", "tls.server.name",
            "network.transport", "network.protocol",
            "network.direction", "network.community_id", "dns.id",
            "dns.question.name", "dns.question.type", "dns.response_code",
            "dns.resolved_ip", "host.id", "host.name", "host.hostname",
            "host.ip", "agent.id", "user.id", "user.name",
            "source.user.name", "destination.user.name", "client.user.name",
            "process.entity_id", "process.pid",
            "process.parent.pid", "process.name", "process.executable",
            "file.name", "file.path", "file.hash.sha256",
        ],
    },
}

# Source/destination in Zeek are connection originator/responder fields, while
# a Suricata alert can describe the direction of the individual packet that
# matched.  Do not silently project one meaning onto the other.  Community ID
# is the reviewed cross-sensor join key because Security Onion enables it in
# both Zeek and Suricata.
PACK_ROLE_MODE = {
    "alert_context": "event_native",
    "network_flow": "cross_sensor",
    "dns_activity": "cross_sensor",
    "system_auth": "event_native",
    "zeek_tls": "zeek_originator_responder",
    "zeek_http": "zeek_originator_responder",
    "zeek_files": "zeek_originator_responder",
    "zeek_ssh": "zeek_originator_responder",
    "zeek_stun": "zeek_originator_responder",
    "zeek_quic": "zeek_originator_responder",
    "zeek_anomalies": "zeek_originator_responder",
    "osquery_history": "event_native",
    "cross_sensor_timeline": "cross_sensor",
}

SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:@+=-]{1,128}$")
SAFE_ELASTIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:@+=-]{1,512}$")
SAFE_ELASTIC_INDEX_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
SAFE_ATOM_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,255}$")
SAFE_DOMAIN_RE = re.compile(
    r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
SAFE_EVIDENCE_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/+=#-]{1,256}$")
SAFE_COMMUNITY_ID_RE = re.compile(r"^[A-Za-z0-9_:+/=-]{1,256}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class InvestigationQueryContractError(ValueError):
    """An investigation request or result crossed its policy boundary."""


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvestigationQueryContractError(f"{label} must be an object")
    return value


def _require_exact_keys(
    value: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        raise InvestigationQueryContractError(
            f"{label} is missing required fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise InvestigationQueryContractError(
            f"{label} contains unsupported fields: {', '.join(sorted(unknown))}"
        )


def _safe_id(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not SAFE_ID_RE.fullmatch(text):
        raise InvestigationQueryContractError(f"{label} is invalid")
    return text


def _parse_utc(value: object, label: str) -> dt.datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvestigationQueryContractError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise InvestigationQueryContractError(f"{label} must use UTC")
    return parsed.astimezone(dt.timezone.utc)


def _iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _normalize_window(
    value: object,
    *,
    label: str,
    max_duration: dt.timedelta,
) -> tuple[dict[str, str], dt.datetime, dt.datetime]:
    window = _require_mapping(value, label)
    _require_exact_keys(
        window,
        allowed={"start", "end"},
        required={"start", "end"},
        label=label,
    )
    start = _parse_utc(window["start"], f"{label} start")
    end = _parse_utc(window["end"], f"{label} end")
    if end <= start or end - start > max_duration:
        raise InvestigationQueryContractError(
            f"{label} must be positive and no longer than {max_duration}"
        )
    return {"start": _iso_utc(start), "end": _iso_utc(end)}, start, end


def _normalize_observable(kind: str, value: object) -> str:
    text = str(value or "").strip().rstrip(".")
    if kind == "ips":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise InvestigationQueryContractError("invalid exact IP observable") from exc
    if kind == "domains":
        if not SAFE_DOMAIN_RE.fullmatch(text):
            raise InvestigationQueryContractError("invalid exact domain observable")
        return text.lower()
    if kind in {"hosts", "users"} and SAFE_ATOM_RE.fullmatch(text):
        return text
    raise InvestigationQueryContractError(f"invalid exact {kind} observable")


def _normalize_observables(
    value: object,
    *,
    per_kind_limit: int,
    total_limit: int,
    require_one: bool,
    label: str,
) -> dict[str, list[str]]:
    data = _require_mapping(value, label)
    if set(data) - set(OBSERVABLE_KINDS):
        raise InvestigationQueryContractError(f"{label} contains an unsupported kind")
    normalized: dict[str, list[str]] = {}
    for kind in OBSERVABLE_KINDS:
        items = data.get(kind, [])
        if not isinstance(items, list) or len(items) > per_kind_limit:
            raise InvestigationQueryContractError(
                f"{label}.{kind} exceeds its {per_kind_limit}-value limit"
            )
        clean: list[str] = []
        for item in items:
            candidate = _normalize_observable(kind, item)
            if candidate not in clean:
                clean.append(candidate)
        normalized[kind] = clean
    count = sum(len(items) for items in normalized.values())
    if require_one and count == 0:
        raise InvestigationQueryContractError(f"{label} requires an exact observable")
    if count > total_limit:
        raise InvestigationQueryContractError(
            f"{label} exceeds its {total_limit}-value total limit"
        )
    return normalized


def _normalize_event_tuple(value: object, *, label: str) -> dict[str, Any]:
    """Normalize one exact, role-preserving ECS event constraint tuple."""
    data = _require_mapping(value, label)
    unknown = set(data) - set(EVENT_TUPLE_FIELDS)
    if unknown:
        raise InvestigationQueryContractError(
            f"{label} contains unsupported fields: {', '.join(sorted(unknown))}"
        )
    if not data:
        raise InvestigationQueryContractError(f"{label} must not be empty")
    clean: dict[str, Any] = {}
    for field in EVENT_TUPLE_FIELDS:
        if field not in data:
            continue
        raw = data[field]
        if field in {"source_ip", "destination_ip"}:
            clean[field] = _normalize_observable("ips", raw)
        elif field in {"source_port", "destination_port"}:
            if isinstance(raw, bool):
                raise InvestigationQueryContractError(f"{label}.{field} is invalid")
            try:
                port = int(raw)
            except (TypeError, ValueError) as exc:
                raise InvestigationQueryContractError(
                    f"{label}.{field} is invalid"
                ) from exc
            if port < 0 or port > 65535:
                raise InvestigationQueryContractError(
                    f"{label}.{field} is outside the port range"
                )
            clean[field] = port
        elif field in {"transport", "protocol"}:
            protocol = str(raw or "").strip().lower()
            if not SAFE_ATOM_RE.fullmatch(protocol):
                raise InvestigationQueryContractError(f"{label}.{field} is invalid")
            clean[field] = protocol
        elif field == "community_id":
            community_id = str(raw or "").strip()
            if not SAFE_COMMUNITY_ID_RE.fullmatch(community_id):
                raise InvestigationQueryContractError(
                    f"{label}.community_id is invalid"
                )
            clean[field] = community_id
        else:
            rule_id = str(raw or "").strip()
            if not SAFE_ATOM_RE.fullmatch(rule_id):
                raise InvestigationQueryContractError(f"{label}.rule_id is invalid")
            clean[field] = rule_id
    return clean


def _normalize_context_event_tuples(
    value: object,
    *,
    limit: int = MAX_CONTEXT_EVENT_TUPLES,
    reject_duplicates: bool = False,
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > limit:
        raise InvestigationQueryContractError(
            "authorization permitted_event_tuples exceeds its limit"
        )
    clean: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item = _require_mapping(raw, f"authorization event tuple {index}")
        _require_exact_keys(
            item,
            allowed={
                "event_tuple", "role_semantics", "source", "evidence_ref",
            },
            required={
                "event_tuple", "role_semantics", "source", "evidence_ref",
            },
            label=f"authorization event tuple {index}",
        )
        source = str(item["source"] or "")
        role_semantics = str(item["role_semantics"] or "")
        evidence_ref = str(item["evidence_ref"] or "")
        if source not in {"trusted_context", "prior_evidence"}:
            raise InvestigationQueryContractError(
                "authorization event tuple source is unsupported"
            )
        if role_semantics not in ALLOWED_ROLE_SEMANTICS:
            raise InvestigationQueryContractError(
                "authorization event tuple role semantics are unsupported"
            )
        if not SAFE_EVIDENCE_REF_RE.fullmatch(evidence_ref):
            raise InvestigationQueryContractError(
                "authorization event tuple evidence_ref is invalid"
            )
        normalized = {
            "event_tuple": _normalize_event_tuple(
                item["event_tuple"],
                label=f"authorization event tuple {index}.event_tuple",
            ),
            "role_semantics": role_semantics,
            "source": source,
            "evidence_ref": evidence_ref,
        }
        if normalized in clean:
            if reject_duplicates:
                raise InvestigationQueryContractError(
                    "authorization event tuple is duplicated"
                )
            continue
        clean.append(normalized)
    return clean


def _index_matches_scope(index_name: str, index_scope: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(index_name, pattern)
        or fnmatch.fnmatchcase(index_name, f".ds-{pattern}-*")
        for pattern in index_scope
    )


def _normalize_anchor(value: object) -> dict[str, str]:
    anchor = _require_mapping(value, "authorization anchor")
    _require_exact_keys(
        anchor,
        allowed={"index", "id"},
        required={"index", "id"},
        label="authorization anchor",
    )
    index_name = str(anchor["index"] or "").strip()
    document_id = str(anchor["id"] or "").strip()
    if (
        not index_name
        or not SAFE_ELASTIC_INDEX_RE.fullmatch(index_name)
        or not _index_matches_scope(index_name, ALERT_INDEX_SCOPE)
    ):
        raise InvestigationQueryContractError(
            "authorization anchor index is outside the reviewed alert scope"
        )
    if not SAFE_ELASTIC_ID_RE.fullmatch(document_id):
        raise InvestigationQueryContractError("authorization anchor id is invalid")
    return {"index": index_name, "id": document_id}


def _normalize_authorization_context(value: object) -> dict[str, Any]:
    context = _require_mapping(value, "authorization context")
    _require_exact_keys(
        context,
        allowed={
            "context_id", "case_id", "group_id", "actor_role", "anchor",
            "anchor_time", "time_envelope", "permitted_observables",
            "discovered_observables", "permitted_event_tuples",
        },
        required={
            "context_id", "case_id", "actor_role", "anchor", "anchor_time",
            "time_envelope", "permitted_observables",
        },
        label="authorization context",
    )
    envelope, envelope_start, envelope_end = _normalize_window(
        context["time_envelope"],
        label="authorization time envelope",
        max_duration=MAX_AUTHORIZATION_WINDOW,
    )
    actor_role = str(context["actor_role"] or "").strip()
    if actor_role not in ALLOWED_ACTOR_ROLES:
        raise InvestigationQueryContractError("authorization actor_role is unsupported")
    anchor_time = _parse_utc(
        context["anchor_time"],
        "authorization anchor_time",
    )
    if anchor_time < envelope_start or anchor_time > envelope_end:
        raise InvestigationQueryContractError(
            "authorization anchor_time escapes its time envelope"
        )
    permitted = _normalize_observables(
        context["permitted_observables"],
        per_kind_limit=MAX_CONTEXT_OBSERVABLES_PER_KIND,
        total_limit=MAX_CONTEXT_OBSERVABLES_PER_KIND * len(OBSERVABLE_KINDS),
        require_one=True,
        label="authorization permitted_observables",
    )
    discoveries = context.get("discovered_observables", [])
    if not isinstance(discoveries, list) or len(discoveries) > MAX_DISCOVERED_OBSERVABLES:
        raise InvestigationQueryContractError(
            "authorization discovered_observables exceeds its limit"
        )
    normalized_discoveries: list[dict[str, str]] = []
    for index, item in enumerate(discoveries):
        discovery = _require_mapping(item, f"discovered observable {index}")
        _require_exact_keys(
            discovery,
            allowed={"kind", "value", "evidence_ref"},
            required={"kind", "value", "evidence_ref"},
            label=f"discovered observable {index}",
        )
        kind = str(discovery["kind"] or "").strip()
        if kind not in OBSERVABLE_KINDS:
            raise InvestigationQueryContractError("discovered observable kind is unsupported")
        evidence_ref = str(discovery["evidence_ref"] or "").strip()
        if not SAFE_EVIDENCE_REF_RE.fullmatch(evidence_ref):
            raise InvestigationQueryContractError("discovered observable evidence_ref is invalid")
        normalized = {
            "kind": kind,
            "value": _normalize_observable(kind, discovery["value"]),
            "evidence_ref": evidence_ref,
        }
        if normalized not in normalized_discoveries:
            normalized_discoveries.append(normalized)
    normalized = {
        "context_id": _safe_id(context["context_id"], "authorization context_id"),
        "case_id": _safe_id(context["case_id"], "authorization case_id"),
        "group_id": (
            _safe_id(context["group_id"], "authorization group_id")
            if context.get("group_id")
            else ""
        ),
        "actor_role": actor_role,
        "anchor": _normalize_anchor(context["anchor"]),
        "anchor_time": _iso_utc(anchor_time),
        "time_envelope": envelope,
        "permitted_observables": permitted,
        "discovered_observables": normalized_discoveries,
        "permitted_event_tuples": _normalize_context_event_tuples(
            context.get("permitted_event_tuples")
        ),
    }
    normalized["_envelope_start"] = envelope_start
    normalized["_envelope_end"] = envelope_end
    return normalized


def _observable_authorizations(context: dict[str, Any]) -> dict[tuple[str, str], dict[str, str]]:
    authorized: dict[tuple[str, str], dict[str, str]] = {}
    context_id = context["context_id"]
    for kind, values in context["permitted_observables"].items():
        for value in values:
            authorized[(kind, value)] = {
                "kind": kind,
                "value": value,
                "source": "trusted_context",
                "evidence_ref": f"context:{context_id}:{kind}",
            }
    for item in context["discovered_observables"]:
        authorized[(item["kind"], item["value"])] = {
            "kind": item["kind"],
            "value": item["value"],
            "source": "prior_evidence",
            "evidence_ref": item["evidence_ref"],
        }
    return authorized


def pack_event_tuple_fields(pack_name: str) -> dict[str, str]:
    """Return tuple constraints that can also be authenticated in hit sources."""
    projected = set(PACKS[pack_name]["fields"])
    return {
        key: EVENT_TUPLE_FIELDS[key]
        for key, paths in EVENT_TUPLE_PATHS.items()
        if projected.intersection(paths)
    }


def validate_pack_observables(
    observables: dict[str, list[str]],
    pack_name: str,
    *,
    label: str,
) -> None:
    """Reject values that the selected pack cannot possibly represent."""
    fields_by_kind = pack_observable_fields(pack_name)
    unsupported = sorted(
        kind
        for kind, values in observables.items()
        if values and not fields_by_kind.get(kind)
    )
    if unsupported:
        raise InvestigationQueryContractError(
            f"{label} uses observable kind(s) unsupported by pack "
            f"{pack_name}: {', '.join(unsupported)}"
        )
    if not any(
        values and fields_by_kind.get(kind)
        for kind, values in observables.items()
    ):
        raise InvestigationQueryContractError(
            f"{label} has no queryable observable in pack {pack_name}"
        )


def tuple_match_semantics(
    pack_name: str,
    event_tuple: dict[str, Any] | None,
    role_semantics: str | None,
) -> str:
    """Return the exact role/correlation interpretation used by the broker."""
    if not event_tuple:
        return "observable_exact_any_field"
    mode = PACK_ROLE_MODE[pack_name]
    role = str(role_semantics or "")
    if mode == "cross_sensor" or (
        mode == "zeek_originator_responder"
        and role != "zeek_originator_responder"
    ):
        return "community_id_cross_sensor"
    if mode == "zeek_originator_responder":
        return "zeek_originator_responder_exact"
    if role == "packet_direction":
        return "packet_direction_exact"
    return "event_native_exact"


def _validate_tuple_role_compatibility(
    event_tuple: dict[str, Any],
    *,
    pack_name: str,
    role_semantics: str,
    label: str,
) -> None:
    mode = PACK_ROLE_MODE[pack_name]
    if mode == "cross_sensor":
        if "community_id" not in event_tuple:
            raise InvestigationQueryContractError(
                f"{label} requires community_id for deterministic "
                f"cross-sensor correlation in pack {pack_name}"
            )
        return
    if (
        mode == "zeek_originator_responder"
        and role_semantics != "zeek_originator_responder"
        and "community_id" not in event_tuple
    ):
        raise InvestigationQueryContractError(
            f"{label} cannot project {role_semantics or 'unknown'} roles onto "
            "Zeek originator/responder fields without community_id"
        )


def _event_tuple_authorization(
    requested: dict[str, Any],
    context: dict[str, Any],
    *,
    pack_name: str,
    observables: dict[str, list[str]],
    label: str,
) -> dict[str, Any]:
    unsupported = set(requested) - set(pack_event_tuple_fields(pack_name))
    if unsupported:
        raise InvestigationQueryContractError(
            f"{label} uses fields unavailable in pack {pack_name}: "
            + ", ".join(sorted(unsupported))
        )
    for field in ("source_ip", "destination_ip"):
        if field in requested and requested[field] not in observables["ips"]:
            raise InvestigationQueryContractError(
                f"{label}.{field} must also be an authorized IP observable"
            )
    matches = [
        entry
        for entry in context["permitted_event_tuples"]
        if all(
            entry["event_tuple"].get(field) == value
            for field, value in requested.items()
        )
    ]
    if not matches:
        raise InvestigationQueryContractError(
            f"{label} does not match one trusted role-aware event tuple"
        )
    # A subset can match duplicate group rows. Select deterministically and
    # carry the complete trusted tuple as provenance; caller values never
    # become authority merely by being present in the proposal.
    selected = min(
        matches,
        key=lambda item: canonical_digest(item),
    )
    if (
        {"source_ip", "destination_ip"}.intersection(
            selected["event_tuple"]
        )
        and not {"source_ip", "destination_ip"}.intersection(requested)
    ):
        raise InvestigationQueryContractError(
            f"{label} must retain a trusted source or destination IP role"
        )
    _validate_tuple_role_compatibility(
        requested,
        pack_name=pack_name,
        role_semantics=selected["role_semantics"],
        label=label,
    )
    return selected


def authorize_investigation_query_request(
    proposal: object,
    authorization_context: object,
) -> dict[str, Any]:
    """Combine an untrusted model proposal with a trusted local context."""
    proposed = _require_mapping(proposal, "investigation query proposal")
    _require_exact_keys(
        proposed,
        allowed={"query_contract", "batch_id", "queries"},
        required={"batch_id", "queries"},
        label="investigation query proposal",
    )
    if (
        "query_contract" in proposed
        and proposed["query_contract"] != INVESTIGATION_QUERY_CONTRACT
    ):
        raise InvestigationQueryContractError("investigation query contract is unsupported")
    queries = proposed["queries"]
    if not isinstance(queries, list) or not queries or len(queries) > MAX_QUERIES:
        raise InvestigationQueryContractError(
            f"investigation query proposal must contain 1-{MAX_QUERIES} queries"
        )
    context = _normalize_authorization_context(authorization_context)
    authorized_values = _observable_authorizations(context)
    normalized_queries: list[dict[str, Any]] = []
    query_ids: set[str] = set()
    batch_value_keys: set[tuple[str, str]] = set()
    total_hit_budget = 0
    total_window = dt.timedelta()
    used_authorizations: dict[tuple[str, str], dict[str, str]] = {}
    used_event_tuple_authorizations: list[dict[str, Any]] = []
    for index, raw_query in enumerate(queries):
        query = _require_mapping(raw_query, f"investigation query {index}")
        _require_exact_keys(
            query,
            allowed={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "event_tuple", "size", "aggregation",
            },
            required={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "size", "aggregation",
            },
            label=f"investigation query {index}",
        )
        query_id = _safe_id(query["query_id"], f"investigation query {index} query_id")
        if query_id in query_ids:
            raise InvestigationQueryContractError("investigation query ids must be unique")
        query_ids.add(query_id)
        dialect = str(query["dialect"] or "").strip()
        pack = str(query["pack"] or "").strip()
        purpose = str(query["purpose"] or "").strip()
        aggregation = str(query["aggregation"] or "").strip()
        if dialect not in ALLOWED_DIALECTS:
            raise InvestigationQueryContractError("investigation dialect is unsupported")
        if pack not in PACKS:
            raise InvestigationQueryContractError("investigation pack is unsupported")
        if purpose not in ALLOWED_PURPOSES:
            raise InvestigationQueryContractError("investigation purpose is unsupported")
        if aggregation not in ALLOWED_AGGREGATIONS:
            raise InvestigationQueryContractError("investigation aggregation is unsupported")
        window, start, end = _normalize_window(
            query["window"],
            label=f"investigation query {query_id} window",
            max_duration=MAX_WINDOW,
        )
        if start < context["_envelope_start"] or end > context["_envelope_end"]:
            raise InvestigationQueryContractError(
                f"investigation query {query_id} escapes its trusted time envelope"
            )
        total_window += end - start
        observables = _normalize_observables(
            query["observables"],
            per_kind_limit=MAX_QUERY_OBSERVABLES,
            total_limit=MAX_QUERY_OBSERVABLES,
            require_one=True,
            label=f"investigation query {query_id} observables",
        )
        validate_pack_observables(
            observables,
            pack,
            label=f"investigation query {query_id}",
        )
        provenance: dict[str, list[dict[str, str]]] = {
            kind: [] for kind in OBSERVABLE_KINDS
        }
        for kind, values in observables.items():
            for observable in values:
                key = (kind, observable)
                authorization = authorized_values.get(key)
                if authorization is None:
                    raise InvestigationQueryContractError(
                        f"investigation query {query_id} uses an observable "
                        "outside its trusted authorization context"
                    )
                provenance[kind].append(dict(authorization))
                used_authorizations[key] = dict(authorization)
                batch_value_keys.add(key)
        event_tuple = None
        event_tuple_provenance = None
        if "event_tuple" in query:
            event_tuple = _normalize_event_tuple(
                query["event_tuple"],
                label=f"investigation query {query_id} event_tuple",
            )
            event_tuple_provenance = _event_tuple_authorization(
                event_tuple,
                context,
                pack_name=pack,
                observables=observables,
                label=f"investigation query {query_id} event_tuple",
            )
            if event_tuple_provenance not in used_event_tuple_authorizations:
                used_event_tuple_authorizations.append(event_tuple_provenance)
        if aggregation == "anchor_nearest" and dialect != "elastic":
            raise InvestigationQueryContractError(
                "anchor_nearest is available only through compiled Elastic DSL"
            )
        try:
            size = int(query["size"])
        except (TypeError, ValueError) as exc:
            raise InvestigationQueryContractError("investigation size must be an integer") from exc
        if isinstance(query["size"], bool) or size < 1 or size > MAX_QUERY_HITS:
            raise InvestigationQueryContractError(
                f"investigation size must be between 1 and {MAX_QUERY_HITS}"
            )
        total_hit_budget += 0 if aggregation == "count" else size
        normalized_query = {
            "query_id": query_id,
            "dialect": dialect,
            "pack": pack,
            "purpose": purpose,
            "window": window,
            "observables": observables,
            "observable_provenance": provenance,
            "size": size,
            "aggregation": aggregation,
            "match_semantics": tuple_match_semantics(
                pack,
                event_tuple,
                (
                    event_tuple_provenance.get("role_semantics")
                    if event_tuple_provenance
                    else None
                ),
            ),
        }
        if aggregation == "anchor_nearest":
            normalized_query["anchor_time"] = context["anchor_time"]
        if event_tuple is not None:
            normalized_query["event_tuple"] = event_tuple
            normalized_query["event_tuple_provenance"] = dict(
                event_tuple_provenance or {}
            )
        normalized_queries.append(normalized_query)
    if len(batch_value_keys) > MAX_BATCH_OBSERVABLES:
        raise InvestigationQueryContractError(
            f"investigation batch exceeds {MAX_BATCH_OBSERVABLES} distinct observables"
        )
    if total_hit_budget > MAX_BATCH_HITS:
        raise InvestigationQueryContractError(
            f"investigation batch exceeds its {MAX_BATCH_HITS}-hit budget"
        )
    if total_window > dt.timedelta(hours=96):
        raise InvestigationQueryContractError(
            "investigation batch exceeds its cumulative 96-hour window budget"
        )
    context_for_digest = {
        key: value
        for key, value in context.items()
        if not key.startswith("_")
    }
    authorization = {
        "context_id": context["context_id"],
        "case_id": context["case_id"],
        "group_id": context["group_id"],
        "actor_role": context["actor_role"],
        "anchor": context["anchor"],
        "anchor_time": context["anchor_time"],
        "time_envelope": context["time_envelope"],
        "context_digest": canonical_digest(context_for_digest),
        "observables": sorted(
            used_authorizations.values(),
            key=lambda item: (item["kind"], item["value"], item["evidence_ref"]),
        ),
    }
    if used_event_tuple_authorizations:
        authorization["event_tuples"] = sorted(
            used_event_tuple_authorizations,
            key=canonical_digest,
        )
    authorization["manifest_digest"] = canonical_digest(authorization)
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "operation": INVESTIGATION_QUERY_OPERATION,
        "batch_id": _safe_id(proposed["batch_id"], "investigation batch_id"),
        "authorization": authorization,
        "queries": normalized_queries,
    }


def validate_investigation_query_request(
    payload: object,
    *,
    authorization_context: object | None = None,
    allowed_observables: object | None = None,
    allowed_windows: object | None = None,
) -> dict[str, Any]:
    """Public request validator used by both SOC and Incident Response.

    `authorization_context` is the preferred interface.  The two legacy-style
    keyword names are accepted only together and are converted into a minimal
    trusted context for adapters that landed before this contract.
    """
    if authorization_context is not None:
        return authorize_investigation_query_request(payload, authorization_context)
    if allowed_observables is not None or allowed_windows is not None:
        if allowed_observables is None or not isinstance(allowed_windows, list) or not allowed_windows:
            raise InvestigationQueryContractError(
                "allowed_observables and allowed_windows must be supplied together"
            )
        first = _require_mapping(allowed_windows[0], "allowed window")
        last = _require_mapping(allowed_windows[-1], "allowed window")
        first_start = _parse_utc(first.get("start"), "allowed window start")
        last_end = _parse_utc(last.get("end"), "allowed window end")
        authorization_context = {
            "context_id": "adapter-context",
            "case_id": "adapter-case",
            "actor_role": "incident_responder",
            "anchor": {
                "index": "logs-suricata.alerts-so",
                "id": "adapter-anchor",
            },
            "anchor_time": _iso_utc(
                first_start + (last_end - first_start) / 2
            ),
            "time_envelope": {"start": first.get("start"), "end": last.get("end")},
            "permitted_observables": allowed_observables,
            "discovered_observables": [],
        }
        return authorize_investigation_query_request(payload, authorization_context)
    return validate_authorized_investigation_query_request(payload)


def validate_authorized_investigation_query_request(payload: object) -> dict[str, Any]:
    """Validate and normalize the already-authorized forced-command payload."""
    request = _require_mapping(payload, "authorized investigation request")
    _require_exact_keys(
        request,
        allowed={"query_contract", "operation", "batch_id", "authorization", "queries"},
        required={"query_contract", "operation", "batch_id", "authorization", "queries"},
        label="authorized investigation request",
    )
    if request["query_contract"] != INVESTIGATION_QUERY_CONTRACT:
        raise InvestigationQueryContractError("investigation query contract is unsupported")
    if request["operation"] != INVESTIGATION_QUERY_OPERATION:
        raise InvestigationQueryContractError("investigation query operation is unsupported")
    authorization = _require_mapping(request["authorization"], "authorization manifest")
    _require_exact_keys(
        authorization,
        allowed={
            "context_id", "case_id", "group_id", "actor_role", "anchor",
            "anchor_time", "time_envelope", "context_digest", "observables",
            "manifest_digest", "event_tuples",
        },
        required={
            "context_id", "case_id", "group_id", "actor_role", "anchor",
            "anchor_time", "time_envelope", "context_digest", "observables",
            "manifest_digest",
        },
        label="authorization manifest",
    )
    expected_manifest_digest = canonical_digest({
        key: value for key, value in authorization.items() if key != "manifest_digest"
    })
    if (
        not SHA256_RE.fullmatch(str(authorization["manifest_digest"] or ""))
        or authorization["manifest_digest"] != expected_manifest_digest
    ):
        raise InvestigationQueryContractError("authorization manifest digest is invalid")
    if not SHA256_RE.fullmatch(str(authorization["context_digest"] or "")):
        raise InvestigationQueryContractError("authorization context digest is invalid")
    envelope, envelope_start, envelope_end = _normalize_window(
        authorization["time_envelope"],
        label="authorization time envelope",
        max_duration=MAX_AUTHORIZATION_WINDOW,
    )
    actor_role = str(authorization["actor_role"] or "")
    if actor_role not in ALLOWED_ACTOR_ROLES:
        raise InvestigationQueryContractError("authorization actor role is unsupported")
    anchor_time = _parse_utc(
        authorization["anchor_time"],
        "authorization anchor_time",
    )
    if anchor_time < envelope_start or anchor_time > envelope_end:
        raise InvestigationQueryContractError(
            "authorization anchor_time escapes its time envelope"
        )
    authorized_entries = authorization["observables"]
    if not isinstance(authorized_entries, list) or len(authorized_entries) > MAX_BATCH_OBSERVABLES:
        raise InvestigationQueryContractError("authorization observable manifest exceeds its limit")
    authorized_values: dict[tuple[str, str], dict[str, str]] = {}
    clean_entries: list[dict[str, str]] = []
    for index, item in enumerate(authorized_entries):
        entry = _require_mapping(item, f"authorization observable {index}")
        _require_exact_keys(
            entry,
            allowed={"kind", "value", "source", "evidence_ref"},
            required={"kind", "value", "source", "evidence_ref"},
            label=f"authorization observable {index}",
        )
        kind = str(entry["kind"] or "")
        source = str(entry["source"] or "")
        evidence_ref = str(entry["evidence_ref"] or "")
        if kind not in OBSERVABLE_KINDS or source not in {"trusted_context", "prior_evidence"}:
            raise InvestigationQueryContractError("authorization observable metadata is invalid")
        if not SAFE_EVIDENCE_REF_RE.fullmatch(evidence_ref):
            raise InvestigationQueryContractError("authorization evidence_ref is invalid")
        clean = {
            "kind": kind,
            "value": _normalize_observable(kind, entry["value"]),
            "source": source,
            "evidence_ref": evidence_ref,
        }
        key = (kind, clean["value"])
        if key in authorized_values and authorized_values[key] != clean:
            raise InvestigationQueryContractError("authorization observable provenance conflicts")
        authorized_values[key] = clean
        if clean not in clean_entries:
            clean_entries.append(clean)
    authorized_event_tuples = _normalize_context_event_tuples(
        authorization.get("event_tuples"),
        limit=MAX_QUERIES,
        reject_duplicates=True,
    )
    queries = request["queries"]
    if not isinstance(queries, list) or not queries or len(queries) > MAX_QUERIES:
        raise InvestigationQueryContractError(
            f"authorized request must contain 1-{MAX_QUERIES} queries"
        )
    clean_queries: list[dict[str, Any]] = []
    query_ids: set[str] = set()
    total_hits = 0
    total_window = dt.timedelta()
    used_values: set[tuple[str, str]] = set()
    used_event_tuple_digests: set[str] = set()
    for index, raw_query in enumerate(queries):
        query = _require_mapping(raw_query, f"authorized query {index}")
        _require_exact_keys(
            query,
            allowed={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "observable_provenance", "size", "aggregation",
                "event_tuple", "event_tuple_provenance", "match_semantics",
                "anchor_time",
            },
            required={
                "query_id", "dialect", "pack", "purpose", "window",
                "observables", "observable_provenance", "size", "aggregation",
                "match_semantics",
            },
            label=f"authorized query {index}",
        )
        query_id = _safe_id(query["query_id"], f"authorized query {index} query_id")
        if query_id in query_ids:
            raise InvestigationQueryContractError("authorized query ids must be unique")
        query_ids.add(query_id)
        dialect = str(query["dialect"] or "")
        pack = str(query["pack"] or "")
        purpose = str(query["purpose"] or "")
        aggregation = str(query["aggregation"] or "")
        if dialect not in ALLOWED_DIALECTS or pack not in PACKS:
            raise InvestigationQueryContractError("authorized query dialect or pack is invalid")
        if purpose not in ALLOWED_PURPOSES or aggregation not in ALLOWED_AGGREGATIONS:
            raise InvestigationQueryContractError("authorized query purpose or aggregation is invalid")
        window, start, end = _normalize_window(
            query["window"],
            label=f"authorized query {query_id} window",
            max_duration=MAX_WINDOW,
        )
        if start < envelope_start or end > envelope_end:
            raise InvestigationQueryContractError("authorized query escapes its time envelope")
        total_window += end - start
        observables = _normalize_observables(
            query["observables"],
            per_kind_limit=MAX_QUERY_OBSERVABLES,
            total_limit=MAX_QUERY_OBSERVABLES,
            require_one=True,
            label=f"authorized query {query_id} observables",
        )
        validate_pack_observables(
            observables,
            pack,
            label=f"authorized query {query_id}",
        )
        provenance = _require_mapping(
            query["observable_provenance"],
            f"authorized query {query_id} observable_provenance",
        )
        if set(provenance) != set(OBSERVABLE_KINDS):
            raise InvestigationQueryContractError(
                "authorized query observable provenance kinds are incomplete"
            )
        clean_provenance: dict[str, list[dict[str, str]]] = {}
        for kind in OBSERVABLE_KINDS:
            entries = provenance[kind]
            if not isinstance(entries, list):
                raise InvestigationQueryContractError(
                    "authorized query observable provenance must be arrays"
                )
            expected = []
            for value in observables[kind]:
                entry = authorized_values.get((kind, value))
                if entry is None:
                    raise InvestigationQueryContractError(
                        "authorized query uses an observable absent from its manifest"
                    )
                expected.append(entry)
                used_values.add((kind, value))
            if entries != expected:
                raise InvestigationQueryContractError(
                    "authorized query observable provenance does not match its manifest"
                )
            clean_provenance[kind] = [dict(item) for item in entries]
        event_tuple = None
        event_tuple_provenance = None
        tuple_fields_present = {
            field
            for field in ("event_tuple", "event_tuple_provenance")
            if field in query
        }
        if tuple_fields_present and tuple_fields_present != {
            "event_tuple", "event_tuple_provenance"
        }:
            raise InvestigationQueryContractError(
                "authorized query event tuple and provenance must be supplied together"
            )
        if tuple_fields_present:
            event_tuple = _normalize_event_tuple(
                query["event_tuple"],
                label=f"authorized query {query_id} event_tuple",
            )
            unsupported = set(event_tuple) - set(pack_event_tuple_fields(pack))
            if unsupported:
                raise InvestigationQueryContractError(
                    f"authorized query {query_id} event tuple is unsupported by its pack"
                )
            for field in ("source_ip", "destination_ip"):
                if field in event_tuple and event_tuple[field] not in observables["ips"]:
                    raise InvestigationQueryContractError(
                        "authorized query role-aware IP is absent from observables"
                    )
            event_tuple_provenance = _require_mapping(
                query["event_tuple_provenance"],
                f"authorized query {query_id} event_tuple_provenance",
            )
            if (
                event_tuple_provenance not in authorized_event_tuples
                or not all(
                    event_tuple_provenance["event_tuple"].get(field) == value
                    for field, value in event_tuple.items()
                )
            ):
                raise InvestigationQueryContractError(
                    "authorized query event tuple provenance does not match its manifest"
                )
            if (
                {"source_ip", "destination_ip"}.intersection(
                    event_tuple_provenance["event_tuple"]
                )
                and not {"source_ip", "destination_ip"}.intersection(event_tuple)
            ):
                raise InvestigationQueryContractError(
                    "authorized query event tuple dropped its trusted IP role"
                )
            _validate_tuple_role_compatibility(
                event_tuple,
                pack_name=pack,
                role_semantics=event_tuple_provenance["role_semantics"],
                label=f"authorized query {query_id} event_tuple",
            )
            used_event_tuple_digests.add(canonical_digest(event_tuple_provenance))
        expected_match_semantics = tuple_match_semantics(
            pack,
            event_tuple,
            (
                event_tuple_provenance.get("role_semantics")
                if event_tuple_provenance
                else None
            ),
        )
        if query["match_semantics"] != expected_match_semantics:
            raise InvestigationQueryContractError(
                f"authorized query {query_id} match semantics are invalid"
            )
        if aggregation == "anchor_nearest":
            if dialect != "elastic":
                raise InvestigationQueryContractError(
                    "anchor_nearest is available only through compiled Elastic DSL"
                )
            if query.get("anchor_time") != _iso_utc(anchor_time):
                raise InvestigationQueryContractError(
                    f"authorized query {query_id} anchor_time is invalid"
                )
        elif "anchor_time" in query:
            raise InvestigationQueryContractError(
                f"authorized query {query_id} unexpectedly supplied anchor_time"
            )
        try:
            size = int(query["size"])
        except (TypeError, ValueError) as exc:
            raise InvestigationQueryContractError("authorized query size is invalid") from exc
        if isinstance(query["size"], bool) or size < 1 or size > MAX_QUERY_HITS:
            raise InvestigationQueryContractError("authorized query size is out of bounds")
        total_hits += 0 if aggregation == "count" else size
        clean_query = {
            "query_id": query_id,
            "dialect": dialect,
            "pack": pack,
            "purpose": purpose,
            "window": window,
            "observables": observables,
            "observable_provenance": clean_provenance,
            "size": size,
            "aggregation": aggregation,
            "match_semantics": expected_match_semantics,
        }
        if aggregation == "anchor_nearest":
            clean_query["anchor_time"] = _iso_utc(anchor_time)
        if event_tuple is not None:
            clean_query["event_tuple"] = event_tuple
            clean_query["event_tuple_provenance"] = dict(
                event_tuple_provenance or {}
            )
        clean_queries.append(clean_query)
    if used_values != set(authorized_values):
        raise InvestigationQueryContractError(
            "authorization manifest contains unused or missing observable entries"
        )
    if used_event_tuple_digests != {
        canonical_digest(item) for item in authorized_event_tuples
    }:
        raise InvestigationQueryContractError(
            "authorization event tuple manifest contains unused or missing entries"
        )
    if total_hits > MAX_BATCH_HITS:
        raise InvestigationQueryContractError("authorized request exceeds its hit budget")
    if total_window > dt.timedelta(hours=96):
        raise InvestigationQueryContractError("authorized request exceeds its window budget")
    clean_authorization = {
        "context_id": _safe_id(authorization["context_id"], "authorization context_id"),
        "case_id": _safe_id(authorization["case_id"], "authorization case_id"),
        "group_id": (
            _safe_id(authorization["group_id"], "authorization group_id")
            if authorization["group_id"]
            else ""
        ),
        "actor_role": actor_role,
        "anchor": _normalize_anchor(authorization["anchor"]),
        "anchor_time": _iso_utc(anchor_time),
        "time_envelope": envelope,
        "context_digest": str(authorization["context_digest"]),
        "observables": clean_entries,
    }
    if authorized_event_tuples:
        clean_authorization["event_tuples"] = authorized_event_tuples
    clean_authorization["manifest_digest"] = canonical_digest(clean_authorization)
    if clean_authorization["manifest_digest"] != authorization["manifest_digest"]:
        raise InvestigationQueryContractError(
            "normalized authorization manifest does not match its digest"
        )
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "operation": INVESTIGATION_QUERY_OPERATION,
        "batch_id": _safe_id(request["batch_id"], "investigation batch_id"),
        "authorization": clean_authorization,
        "queries": clean_queries,
    }


def pack_observable_fields(pack_name: str) -> dict[str, list[str]]:
    """Return only observable paths that the reviewed pack also projects."""
    projected = set(PACKS[pack_name]["fields"])
    return {
        kind: [field for field in fields if field in projected]
        for kind, fields in OBSERVABLE_FIELDS.items()
    }


def observable_clause(
    observables: dict[str, list[str]],
    pack_name: str,
) -> dict[str, Any]:
    should: list[dict[str, Any]] = []
    for kind, fields in pack_observable_fields(pack_name).items():
        for value in observables.get(kind, []):
            should.extend({"term": {field: value}} for field in fields)
    if not should:
        raise InvestigationQueryContractError(
            f"pack {pack_name} produced no observable query clauses"
        )
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _event_tuple_query_fields(query: dict[str, Any]) -> list[str]:
    event_tuple = query.get("event_tuple") or {}
    if query.get("match_semantics") == "community_id_cross_sensor":
        return ["community_id"]
    return list(event_tuple)


def _event_tuple_term_clause(field: str, value: Any) -> dict[str, Any]:
    paths = EVENT_TUPLE_PATHS[field]
    if len(paths) == 1:
        return {"term": {paths[0]: value}}
    return {
        "bool": {
            "should": [
                {"term": {path: value}}
                for path in paths
            ],
            "minimum_should_match": 1,
        }
    }


def event_tuple_clause(query: dict[str, Any]) -> dict[str, Any]:
    """Compile only role-compatible trusted tuple constraints."""
    event_tuple = query.get("event_tuple") or {}
    fields = _event_tuple_query_fields(query)
    if not fields:
        raise InvestigationQueryContractError(
            "event tuple produced no role-compatible query clauses"
        )
    return {
        "bool": {
            "filter": [
                _event_tuple_term_clause(field, event_tuple[field])
                for field in fields
            ]
        }
    }


def dataset_clause(datasets: list[str]) -> dict[str, Any]:
    if not datasets:
        raise InvestigationQueryContractError(
            "reviewed query pack has no datasets"
        )
    return {
        "bool": {
            "should": [
                {"term": {"event.dataset": dataset}}
                for dataset in datasets
            ],
            "minimum_should_match": 1,
        }
    }


def build_query_dsl(query: dict[str, Any]) -> dict[str, Any]:
    pack = PACKS[query["pack"]]
    filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": query["window"]["start"],
                    "lte": query["window"]["end"],
                }
            }
        },
        dataset_clause(pack["datasets"]),
        observable_clause(query["observables"], query["pack"]),
        *(
            [event_tuple_clause(query)]
            if query.get("event_tuple")
            else []
        ),
    ]
    filtered_query: dict[str, Any] = {"bool": {"filter": filters}}
    if query["aggregation"] == "anchor_nearest":
        start = _parse_utc(query["window"]["start"], "query window start")
        end = _parse_utc(query["window"]["end"], "query window end")
        scale_seconds = max(1, round((end - start).total_seconds() / 2))
        compiled_query: dict[str, Any] = {
            "function_score": {
                "query": filtered_query,
                "gauss": {
                    "@timestamp": {
                        "origin": query["anchor_time"],
                        "scale": f"{scale_seconds}s",
                        "decay": 0.5,
                    }
                },
                "boost_mode": "replace",
            }
        }
    else:
        compiled_query = filtered_query
    body: dict[str, Any] = {
        "size": 0 if query["aggregation"] == "count" else query["size"],
        "track_total_hits": True,
        "timeout": "30s",
        "_source": False if query["aggregation"] == "count" else pack["fields"],
        "query": compiled_query,
    }
    if query["aggregation"] != "count":
        if query["aggregation"] == "anchor_nearest":
            body["sort"] = [
                {"_score": "desc"},
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                "_shard_doc",
            ]
        else:
            order = "asc" if query["aggregation"] == "timeline" else "desc"
            body["sort"] = [
                {"@timestamp": {"order": order, "unmapped_type": "date"}},
                "_shard_doc",
            ]
    return body


def _quote(value: str) -> str:
    # All observable validators exclude quotes and backslashes.
    return f'"{value}"'


def _event_tuple_filter_value(field: str, value: Any) -> str:
    if field in {"source_port", "destination_port"}:
        return str(value)
    return _quote(str(value))


def _render_event_tuple_filter(
    query: dict[str, Any],
    *,
    separator: str,
    field_separator: str,
) -> str:
    event_tuple = query.get("event_tuple") or {}
    clauses: list[str] = []
    for field in _event_tuple_query_fields(query):
        value = _event_tuple_filter_value(field, event_tuple[field])
        alternatives = [
            f"{path}{field_separator}{value}"
            for path in EVENT_TUPLE_PATHS[field]
        ]
        clauses.append(
            alternatives[0]
            if len(alternatives) == 1
            else "(" + f" {separator} ".join(alternatives) + ")"
        )
    return f" {separator.replace('or', 'and').replace('OR', 'AND')} ".join(clauses)


def kql_equivalent(query: dict[str, Any]) -> str:
    datasets = " or ".join(
        f"event.dataset : {_quote(value)}" for value in PACKS[query["pack"]]["datasets"]
    )
    observables: list[str] = []
    for kind, fields in pack_observable_fields(query["pack"]).items():
        for value in query["observables"].get(kind, []):
            observables.append(
                "(" + " or ".join(f"{field} : {_quote(value)}" for field in fields) + ")"
            )
    rendered = (
        f'@timestamp >= {_quote(query["window"]["start"])} and '
        f'@timestamp <= {_quote(query["window"]["end"])} and '
        f"({datasets}) and (" + " or ".join(observables) + ")"
    )
    if query.get("event_tuple"):
        rendered += " and (" + _render_event_tuple_filter(
            query,
            separator="or",
            field_separator=" : ",
        ) + ")"
    return rendered


def oql_equivalent(query: dict[str, Any]) -> str:
    """Render Security Onion Hunt OQL (Lucene filters plus safe pipeline sort).

    The wrapper executes a locally compiled, semantically equivalent Query DSL
    request through ``so-elasticsearch-query``; it does not claim to call the
    SOC Hunt API.
    """
    datasets = " OR ".join(
        f"event.dataset:{_quote(value)}" for value in PACKS[query["pack"]]["datasets"]
    )
    observables: list[str] = []
    for kind, fields in pack_observable_fields(query["pack"]).items():
        for value in query["observables"].get(kind, []):
            observables.append(
                "(" + " OR ".join(f"{field}:{_quote(value)}" for field in fields) + ")"
            )
    rendered = (
        f'@timestamp:[{_quote(query["window"]["start"])} TO '
        f'{_quote(query["window"]["end"])}] AND '
        f"({datasets}) AND (" + " OR ".join(observables) + ")"
    )
    if query.get("event_tuple"):
        rendered += " AND (" + _render_event_tuple_filter(
            query,
            separator="OR",
            field_separator=":",
        ) + ")"
    if query["aggregation"] == "timeline":
        rendered += " | sortby @timestamp^"
    return rendered


def query_endpoint(index_scope: list[str]) -> str:
    return (
        f"{','.join(index_scope)}/_search"
        f"?ignore_unavailable=true&expand_wildcards=open&preference={QUERY_PREFERENCE}"
    )


def _expected_execution_digest(
    query_dsl: dict[str, Any],
    index_scope: list[str],
    endpoint: str,
) -> str:
    return canonical_digest({
        "index_scope": index_scope,
        "query_endpoint": endpoint,
        "query_dsl": query_dsl,
    })


def _leaf_items(value: object, prefix: str = "") -> list[tuple[str, object]]:
    """Flatten source leaves while preserving ECS paths through arrays."""
    leaves: list[tuple[str, object]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            leaves.extend(_leaf_items(child, path))
    elif isinstance(value, list):
        for child in value:
            leaves.extend(_leaf_items(child, prefix))
    else:
        leaves.append((prefix, value))
    return leaves


def _path_values(source: dict[str, Any], path: str) -> list[object]:
    current: list[object] = [source]
    for part in path.split("."):
        following: list[object] = []
        for item in current:
            if isinstance(item, dict) and part in item:
                value = item[part]
                following.extend(value if isinstance(value, list) else [value])
            elif isinstance(item, list):
                for child in item:
                    if isinstance(child, dict) and part in child:
                        value = child[part]
                        following.extend(value if isinstance(value, list) else [value])
        current = following
    return [
        item
        for item in current
        if not isinstance(item, (dict, list))
    ]


def _observable_matches(kind: str, expected: str, candidate: object) -> bool:
    try:
        return _normalize_observable(kind, candidate) == expected
    except InvestigationQueryContractError:
        return False


def _event_tuple_value_matches(field: str, expected: Any, candidate: object) -> bool:
    try:
        normalized = _normalize_event_tuple(
            {field: candidate},
            label="investigation hit event tuple",
        )
    except InvestigationQueryContractError:
        return False
    return normalized.get(field) == expected


def _validate_hit_source(
    source: object,
    expected_query: dict[str, Any],
) -> None:
    source_map = _require_mapping(source, "investigation hit source")
    allowed_fields = set(PACKS[expected_query["pack"]]["fields"])
    leaves = _leaf_items(source_map)
    if any(path not in allowed_fields for path, _value in leaves):
        raise InvestigationQueryContractError(
            "investigation hit source contains a field outside its reviewed projection"
        )
    timestamp_values = _path_values(source_map, "@timestamp")
    if len(timestamp_values) != 1:
        raise InvestigationQueryContractError(
            "investigation hit source has no singular timestamp"
        )
    timestamp = _parse_utc(timestamp_values[0], "investigation hit timestamp")
    start = _parse_utc(expected_query["window"]["start"], "investigation window start")
    end = _parse_utc(expected_query["window"]["end"], "investigation window end")
    if timestamp < start or timestamp > end:
        raise InvestigationQueryContractError(
            "investigation hit timestamp escaped its authorized window"
        )
    datasets = [
        str(item)
        for item in _path_values(source_map, "event.dataset")
    ]
    allowed_datasets = PACKS[expected_query["pack"]]["datasets"]
    if len(datasets) != 1 or datasets[0] not in allowed_datasets:
        raise InvestigationQueryContractError(
            "investigation hit dataset escaped its reviewed pack"
        )
    observable_match = False
    for kind, fields in pack_observable_fields(expected_query["pack"]).items():
        for expected in expected_query["observables"].get(kind, []):
            if any(
                _observable_matches(kind, expected, candidate)
                for field in fields
                for candidate in _path_values(source_map, field)
            ):
                observable_match = True
                break
        if observable_match:
            break
    if not observable_match:
        raise InvestigationQueryContractError(
            "investigation hit does not contain an authorized matching observable"
        )
    event_tuple = expected_query.get("event_tuple") or {}
    for field in _event_tuple_query_fields(expected_query):
        expected = event_tuple[field]
        if not any(
            _event_tuple_value_matches(field, expected, candidate)
            for path in EVENT_TUPLE_PATHS[field]
            for candidate in _path_values(source_map, path)
        ):
            raise InvestigationQueryContractError(
                "investigation hit does not match its authorized event tuple"
            )


def result_coverage(
    query: dict[str, Any],
    *,
    status: str,
    total_hits: int,
    total_hits_relation: str,
    returned_hits: int,
) -> dict[str, Any]:
    """Describe bounded evidence coverage without treating zero as absence."""
    exact_total = status == "ok" and total_hits_relation == "eq"
    if status != "ok":
        coverage_status = "partial"
        interpretation = "query_execution_incomplete"
    elif not exact_total:
        coverage_status = "partial"
        interpretation = "lower_bound_only"
    elif query["aggregation"] == "count":
        coverage_status = "exact_aggregate"
        interpretation = "exact_count_for_authorized_filter_and_window"
    elif total_hits == 0:
        coverage_status = "exact_zero"
        interpretation = (
            "no_matching_documents_for_authorized_filter_and_window"
        )
    elif returned_hits < total_hits:
        coverage_status = "bounded_sample"
        interpretation = "sample_only_not_complete_event_set"
    else:
        coverage_status = "complete_events"
        interpretation = "complete_matching_event_set"
    strategy = {
        "events": "newest_first",
        "timeline": "chronological",
        "anchor_nearest": "anchor_nearest",
        "count": "exact_count",
    }[query["aggregation"]]
    return {
        "coverage_status": coverage_status,
        "match_semantics": query["match_semantics"],
        "sample_strategy": strategy,
        "scope": "authorized_exact_filters_and_time_window",
        "exact_total_hits": exact_total,
        "zero_hits": exact_total and total_hits == 0,
        "event_bodies_complete": (
            exact_total
            and query["aggregation"] != "count"
            and returned_hits == total_hits
        ),
        "interpretation": interpretation,
    }


def _validate_pivot_result(
    result: object,
    expected_query: dict[str, Any],
) -> bool:
    value = _require_mapping(result, f"result {expected_query['query_id']}")
    for field in (
        "query_id", "dialect", "pack", "purpose", "window", "observables",
        "observable_provenance", "size", "aggregation", "match_semantics",
    ):
        if value.get(field) != expected_query[field]:
            raise InvestigationQueryContractError(
                f"result {expected_query['query_id']} changed its authorized {field}"
            )
    for field in ("event_tuple", "event_tuple_provenance", "anchor_time"):
        if value.get(field) != expected_query.get(field):
            raise InvestigationQueryContractError(
                f"result {expected_query['query_id']} changed its authorized {field}"
            )
    expected_dsl = build_query_dsl(expected_query)
    expected_scope = PACKS[expected_query["pack"]]["indices"]
    expected_endpoint = query_endpoint(expected_scope)
    if value.get("query_dsl") != expected_dsl:
        raise InvestigationQueryContractError("result query DSL was not generated from its pack")
    if value.get("index_scope") != expected_scope:
        raise InvestigationQueryContractError("result index scope is not reviewed")
    if value.get("query_endpoint") != expected_endpoint:
        raise InvestigationQueryContractError("result query endpoint is not reviewed")
    if value.get("query_digest") != canonical_digest(expected_dsl):
        raise InvestigationQueryContractError("result query digest is invalid")
    if value.get("execution_digest") != _expected_execution_digest(
        expected_dsl, expected_scope, expected_endpoint
    ):
        raise InvestigationQueryContractError("result execution digest is invalid")
    expected_kql = kql_equivalent(expected_query)
    expected_oql = oql_equivalent(expected_query)
    if value.get("kql_equivalent") != expected_kql:
        raise InvestigationQueryContractError("result KQL representation is invalid")
    if value.get("oql_equivalent") != expected_oql:
        raise InvestigationQueryContractError("result OQL representation is invalid")
    if value.get("kql_digest") != hashlib.sha256(expected_kql.encode()).hexdigest():
        raise InvestigationQueryContractError("result KQL digest is invalid")
    if value.get("oql_digest") != hashlib.sha256(expected_oql.encode()).hexdigest():
        raise InvestigationQueryContractError("result OQL digest is invalid")
    if value.get("request_item_digest") != canonical_digest(expected_query):
        raise InvestigationQueryContractError("result request-item digest is invalid")
    expected_semantics = (
        "compiled_oql_equivalent"
        if expected_query["dialect"] == "oql"
        else "compiled_elastic_pack"
    )
    if (
        value.get("execution_backend") != "so-elasticsearch-query"
        or value.get("execution_semantics") != expected_semantics
    ):
        raise InvestigationQueryContractError("result execution semantics are mislabeled")
    status = str(value.get("status") or "")
    if status not in ALLOWED_STATUSES:
        raise InvestigationQueryContractError("result status is unsupported")
    hits = value.get("hits")
    if not isinstance(hits, list):
        raise InvestigationQueryContractError("result hits must be an array")
    body_size = expected_dsl["size"]
    if len(hits) > body_size:
        raise InvestigationQueryContractError("result exceeds its authorized hit limit")
    for hit in hits:
        item = _require_mapping(hit, "investigation hit")
        if not SAFE_ELASTIC_ID_RE.fullmatch(str(item.get("id") or "")):
            raise InvestigationQueryContractError("investigation hit id is invalid")
        index_name = str(item.get("index") or "")
        if not _index_matches_scope(index_name, expected_scope):
            raise InvestigationQueryContractError("investigation hit escaped its index scope")
        _validate_hit_source(item.get("source"), expected_query)
    for field in ("returned_hits", "total_hits"):
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvestigationQueryContractError(f"result {field} is invalid")
    if value["returned_hits"] != len(hits) or value["total_hits"] < len(hits):
        raise InvestigationQueryContractError("result hit counts are inconsistent")
    relation = value.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise InvestigationQueryContractError("result total-hits relation is invalid")
    expected_truncated = (
        relation != "eq"
        or (
            expected_query["aggregation"] != "count"
            and value["total_hits"] > len(hits)
        )
    )
    if value.get("truncated") is not expected_truncated:
        raise InvestigationQueryContractError("result truncation flag is inconsistent")
    expected_coverage = result_coverage(
        expected_query,
        status=status,
        total_hits=value["total_hits"],
        total_hits_relation=relation,
        returned_hits=value["returned_hits"],
    )
    if value.get("result_coverage") != expected_coverage:
        raise InvestigationQueryContractError(
            "result evidence coverage semantics are inconsistent"
        )
    if expected_query["aggregation"] == "count" and hits:
        raise InvestigationQueryContractError("count aggregation returned event bodies")
    for field in ("duration_ms", "took_ms"):
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvestigationQueryContractError(f"result {field} is invalid")
    if not isinstance(value.get("timed_out"), bool):
        raise InvestigationQueryContractError("result timed_out is invalid")
    shards = _require_mapping(value.get("shards"), "result shard metadata")
    for field in ("total", "successful", "skipped", "failed"):
        count = shards.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvestigationQueryContractError("result shard metadata is invalid")
    failures = shards.get("failures")
    if not isinstance(failures, list) or len(failures) > 20:
        raise InvestigationQueryContractError("result shard failures are invalid")
    if (
        shards["failed"] > shards["total"]
        or shards["successful"] > shards["total"]
        or shards["skipped"] > shards["successful"]
    ):
        raise InvestigationQueryContractError("result shard counts are inconsistent")
    semantic_valid = value.get("semantic_valid")
    expected_ok = status == "ok"
    if semantic_valid is not expected_ok:
        raise InvestigationQueryContractError("result semantic validity contradicts its status")
    if expected_ok:
        if (
            value["timed_out"]
            or shards["total"] == 0
            or shards["successful"] != shards["total"]
            or shards["failed"] != 0
        ):
            raise InvestigationQueryContractError("successful result has invalid shard coverage")
    elif hits:
        raise InvestigationQueryContractError("failed result retained unauthenticated hits")
    return expected_ok


def _validate_control(
    value: object,
    *,
    anchor: dict[str, str],
    positive: bool,
) -> bool:
    control_name = "positive anchor" if positive else "negative filter"
    result = _require_mapping(value, f"investigation {control_name} control")
    _require_exact_keys(
        result,
        allowed={
            "passed", "query_dsl", "query_digest", "index_scope",
            "query_endpoint", "execution_digest", "status", "semantic_valid",
            "total_hits", "total_hits_relation", "returned_hits", "truncated",
            "duration_ms", "timed_out", "took_ms", "shards", "hits", "error",
        },
        required={
            "passed", "query_dsl", "query_digest", "index_scope",
            "query_endpoint", "execution_digest", "status", "semantic_valid",
            "total_hits", "total_hits_relation", "returned_hits", "truncated",
            "duration_ms", "timed_out", "took_ms", "shards", "hits",
        },
        label=f"investigation {control_name} control",
    )
    if not isinstance(result["passed"], bool):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control passed flag is invalid"
        )
    expected_dsl: dict[str, Any]
    if positive:
        expected_dsl = {
            "size": 1,
            "track_total_hits": True,
            "timeout": "30s",
            "_source": ["@timestamp", "event.dataset"],
            "query": {"ids": {"values": [anchor["id"]]}},
        }
    else:
        expected_dsl = {
            "size": 1,
            "track_total_hits": True,
            "timeout": "30s",
            "_source": ["@timestamp", "event.dataset"],
            "query": {
                "bool": {
                    "filter": [{"ids": {"values": [anchor["id"]]}}],
                    "must_not": [{"ids": {"values": [anchor["id"]]}}],
                }
            },
        }
    expected_scope = [anchor["index"]] if positive else ALERT_INDEX_SCOPE
    if result.get("query_dsl") != expected_dsl:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control DSL is invalid"
        )
    if result.get("index_scope") != expected_scope:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control index scope is invalid"
        )
    expected_endpoint = query_endpoint(expected_scope)
    if result.get("query_endpoint") != expected_endpoint:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control endpoint is invalid"
        )
    if result.get("query_digest") != canonical_digest(expected_dsl):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control digest is invalid"
        )
    if result.get("execution_digest") != _expected_execution_digest(
        expected_dsl,
        expected_scope,
        expected_endpoint,
    ):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control execution digest is invalid"
        )

    status = str(result.get("status") or "")
    if status not in ALLOWED_STATUSES:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control status is unsupported"
        )
    if result.get("semantic_valid") is not (status == "ok"):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control semantic validity is invalid"
        )
    hits = result.get("hits")
    if not isinstance(hits, list):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hits are invalid"
        )
    for field in ("total_hits", "returned_hits", "duration_ms", "took_ms"):
        item = result.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control {field} is invalid"
            )
    if result["returned_hits"] != len(hits) or result["total_hits"] < len(hits):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hit counts are inconsistent"
        )
    relation = result.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control total-hits relation is invalid"
        )
    expected_truncated = relation != "eq" or result["total_hits"] > len(hits)
    if result.get("truncated") is not expected_truncated:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control truncation flag is invalid"
        )
    if not isinstance(result.get("timed_out"), bool):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control timed_out flag is invalid"
        )
    shards = _require_mapping(
        result.get("shards"),
        f"investigation {control_name} control shards",
    )
    _require_exact_keys(
        shards,
        allowed={"total", "successful", "skipped", "failed", "failures"},
        required={"total", "successful", "skipped", "failed", "failures"},
        label=f"investigation {control_name} control shards",
    )
    for field in ("total", "successful", "skipped", "failed"):
        item = shards.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control shard metadata is invalid"
            )
    if (
        shards["failed"] > shards["total"]
        or shards["successful"] > shards["total"]
        or shards["skipped"] > shards["successful"]
    ):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control shard counts are inconsistent"
        )
    if not isinstance(shards["failures"], list) or len(shards["failures"]) > 20:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control shard failures are invalid"
        )
    if status == "ok":
        if (
            result["timed_out"]
            or shards["total"] == 0
            or shards["successful"] != shards["total"]
            or shards["failed"] != 0
        ):
            raise InvestigationQueryContractError(
                f"investigation {control_name} control shard coverage is invalid"
            )
    elif hits:
        raise InvestigationQueryContractError(
            f"failed investigation {control_name} control retained hits"
        )

    for hit in hits:
        item = _require_mapping(hit, f"investigation {control_name} control hit")
        _require_exact_keys(
            item,
            allowed={"id", "index", "source"},
            required={"id", "index", "source"},
            label=f"investigation {control_name} control hit",
        )
        if not SAFE_ELASTIC_ID_RE.fullmatch(str(item["id"] or "")):
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit id is invalid"
            )
        index_name = str(item["index"] or "")
        if not _index_matches_scope(index_name, expected_scope):
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit escaped its index scope"
            )
        source = _require_mapping(
            item["source"],
            f"investigation {control_name} control hit source",
        )
        if any(
            path not in {"@timestamp", "event.dataset"}
            for path, _item in _leaf_items(source)
        ):
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit projection is invalid"
            )
        timestamp_values = _path_values(source, "@timestamp")
        datasets = [str(item) for item in _path_values(source, "event.dataset")]
        if len(timestamp_values) != 1 or len(datasets) != 1:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit source is incomplete"
            )
        _parse_utc(
            timestamp_values[0],
            f"investigation {control_name} control hit timestamp",
        )
        if datasets[0] not in {"suricata.alert", "sigma.alert"}:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit dataset is invalid"
            )

    if positive:
        exact = [
            hit for hit in hits
            if isinstance(hit, dict)
            and hit.get("id") == anchor["id"]
            and hit.get("index") == anchor["index"]
        ]
        logical_pass = (
            status == "ok"
            and relation == "eq"
            and len(exact) == 1
            and result["total_hits"] == 1
            and result["returned_hits"] == 1
        )
    else:
        logical_pass = (
            status == "ok"
            and relation == "eq"
            and not hits
            and result["total_hits"] == 0
            and result["returned_hits"] == 0
        )
    if result["passed"] is not logical_pass:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control passed flag contradicts its result"
        )
    return logical_pass


def validate_investigation_query_response(
    response: object,
    request: object,
) -> dict[str, Any]:
    """Authenticate the forced-command response against the exact request."""
    expected_request = validate_authorized_investigation_query_request(request)
    value = _require_mapping(response, "investigation query response")
    if value.get("query_contract") != INVESTIGATION_QUERY_CONTRACT:
        raise InvestigationQueryContractError("response query contract is unsupported")
    if value.get("batch_id") != expected_request["batch_id"]:
        raise InvestigationQueryContractError("response batch id does not match")
    if value.get("request_digest") != canonical_digest(expected_request):
        raise InvestigationQueryContractError("response request digest does not match")
    if value.get("read_only") is not True or value.get("ok") is not True:
        raise InvestigationQueryContractError("response is not a successful read-only protocol result")
    results = value.get("results")
    if not isinstance(results, list) or len(results) != len(expected_request["queries"]):
        raise InvestigationQueryContractError("response result coverage is incomplete")
    query_valid = [
        _validate_pivot_result(result, query)
        for result, query in zip(results, expected_request["queries"])
    ]
    controls = _require_mapping(value.get("controls"), "investigation controls")
    if controls.get("anchor") != expected_request["authorization"]["anchor"]:
        raise InvestigationQueryContractError("response control anchor does not match")
    control_validity: list[bool] = []
    control_errors: list[str] = []
    for field, positive in (("positive_anchor", True), ("negative_filter", False)):
        try:
            control_validity.append(_validate_control(
                controls.get(field),
                anchor=expected_request["authorization"]["anchor"],
                positive=positive,
            ))
        except InvestigationQueryContractError as exc:
            control_validity.append(False)
            control_errors.append(f"{field}: {exc}")
    if control_errors:
        raise InvestigationQueryContractError(
            "investigation query controls are invalid: " + "; ".join(control_errors)
        )
    controls_valid = all(control_validity)
    complete = all(query_valid) and controls_valid
    if value.get("complete") is not complete or value.get("partial") is not (not complete):
        raise InvestigationQueryContractError("response completion flags are inconsistent")
    semantic = _require_mapping(
        value.get("semantic_validity"),
        "response semantic_validity",
    )
    if (
        semantic.get("transport_valid") is not True
        or semantic.get("controls_valid") is not controls_valid
        or semantic.get("query_execution_valid") is not all(query_valid)
        or semantic.get("semantic_valid") is not complete
    ):
        raise InvestigationQueryContractError("response semantic validity is inconsistent")
    return value


__all__ = [
    "ALLOWED_AGGREGATIONS",
    "ALLOWED_DIALECTS",
    "ALLOWED_PURPOSES",
    "EVENT_TUPLE_FIELDS",
    "EVENT_TUPLE_PATHS",
    "INVESTIGATION_QUERY_CONTRACT",
    "InvestigationQueryContractError",
    "SAFE_ATOM_RE",
    "authorize_investigation_query_request",
    "build_query_dsl",
    "canonical_digest",
    "kql_equivalent",
    "oql_equivalent",
    "pack_event_tuple_fields",
    "result_coverage",
    "tuple_match_semantics",
    "validate_pack_observables",
    "validate_authorized_investigation_query_request",
    "validate_investigation_query_request",
    "validate_investigation_query_response",
]
