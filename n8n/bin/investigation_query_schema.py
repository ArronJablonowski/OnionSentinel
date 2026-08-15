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
        "related.hosts", "osquery.hostname", "osquery.uuid",
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

_HISTORICAL_OSQUERY_SCHEMA_CONTRACT = (
    "onion-sentinel-historical-osquery-schema-v1"
)
_HISTORICAL_OSQUERY_BASE_FIELDS = [
    "@timestamp", "event.dataset", "event.kind", "event.category",
    "event.type", "event.action", "event.outcome", "event.id",
    "host.id", "host.name", "host.hostname", "host.ip",
    "agent.id", "agent.name", "user.id", "user.name",
    "process.entity_id", "process.pid", "process.parent.pid",
    "process.name", "process.executable", "file.name", "file.path",
    "file.extension", "file.hash.sha256", "source.ip", "source.port",
    "source.domain", "destination.ip", "destination.port",
    "destination.domain", "client.ip", "client.domain", "server.ip",
    "server.domain", "url.domain", "dns.question.name",
    "dns.resolved_ip", "network.transport", "network.protocol",
]
_HISTORICAL_OSQUERY_SCHEMA_PROFILES = {
    "ecs-endpoint-events-v1": {
        "datasets": [
            "endpoint.events.process", "endpoint.events.file",
            "endpoint.events.network",
        ],
        "identity_fields": [
            "host.id", "host.name", "host.hostname", "agent.id",
        ],
        "marker_fields": [
            "process.entity_id", "process.pid", "file.path",
            "network.transport",
        ],
        "fields": [],
    },
    "elastic-osquery-manager-flat-v1": {
        "datasets": ["osquery_manager.result"],
        "identity_fields": [
            "host.id", "host.name", "host.hostname", "agent.id",
            "agent.name", "osquery.hostname", "osquery.uuid",
        ],
        "marker_fields": [
            "osquery.name", "osquery.path", "osquery.pid",
            "osquery.bundle_identifier",
        ],
        "fields": [
            "action_id", "schedule_id", "pack_id", "pack_name",
            "query_name", "response_id", "schedule_execution_count",
            "planned_schedule_time", "osquery.hostname", "osquery.uuid",
            "osquery.name", "osquery.path", "osquery.pid", "osquery.parent",
            "osquery.uid", "osquery.gid", "osquery.username",
            "osquery.groupname", "osquery.start_time", "osquery.address",
            "osquery.port", "osquery.protocol", "osquery.filename",
            "osquery.directory", "osquery.mtime", "osquery.ctime",
            "osquery.atime", "osquery.sha256", "osquery.bundle_identifier",
            "osquery.bundle_name", "osquery.bundle_short_version",
            "osquery.bundle_version", "osquery.category", "osquery.version",
            "osquery.source", "osquery.arch", "osquery.release",
        ],
    },
    "elastic-osquery-manager-action-responses-v1": {
        "datasets": ["osquery_manager.action.responses"],
        "identity_fields": [
            "host.id", "host.name", "host.hostname", "agent.id",
            "agent.name",
        ],
        "marker_fields": [
            "action_id", "schedule_id", "response_id",
            "action_response.osquery.count",
        ],
        "fields": [
            "action_id", "schedule_id", "pack_id", "pack_name",
            "query_name", "response_id", "schedule_execution_count",
            "planned_schedule_time", "action_input_type", "agent_id",
            "started_at", "completed_at", "count",
            "action_response.osquery.count",
        ],
    },
}


def _ordered_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


_HISTORICAL_OSQUERY_PROJECTION_FIELDS = _ordered_unique([
    *_HISTORICAL_OSQUERY_BASE_FIELDS,
    *(
        field
        for profile in _HISTORICAL_OSQUERY_SCHEMA_PROFILES.values()
        for field in profile["fields"]
    ),
])
_HISTORICAL_OSQUERY_IDENTITY_FIELDS = frozenset(
    field
    for profile in _HISTORICAL_OSQUERY_SCHEMA_PROFILES.values()
    for field in profile["identity_fields"]
)
_HISTORICAL_OSQUERY_SCHEMA_STATUSES = frozenset({
    "ok", "timeout", "output_limit", "error", "invalid_response",
})

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
        "fields": _HISTORICAL_OSQUERY_PROJECTION_FIELDS,
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
