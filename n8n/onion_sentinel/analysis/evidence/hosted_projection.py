"""Positive projection and disclosure controls for hosted model evidence."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Pattern


TOKEN_KEY = re.compile(
    r"(?:^|[_-])(?:access[_-]?token|api[_-]?(?:key|token)|authorization|cookie|"
    r"credential|password|secret|session[_-]?id|set[_-]?cookie)(?:$|[_-])",
    re.IGNORECASE,
)
SENSITIVE_KEYS = frozenset({
    "args", "argv", "cmdline", "command", "command_line", "content",
    "data", "environment", "env", "filename", "headers", "key",
    "message", "original", "path", "raw", "referrer", "request_body",
    "response_body", "uri", "user_agent",
})
ELASTIC_SOURCE_PATHS = frozenset({
    "@timestamp", "event.dataset", "event.kind", "event.category",
    "event.type", "event.action", "event.outcome", "event.severity",
    "event.id", "event.code", "event.duration", "rule.id", "rule.name",
    "rule.category", "rule.ruleset", "source.ip", "source.port",
    "source.domain", "source.mac", "source.bytes", "source.packets",
    "destination.ip", "destination.port", "destination.domain",
    "destination.mac", "destination.bytes", "destination.packets",
    "client.ip", "client.port", "client.domain", "server.ip", "server.port",
    "server.domain", "network.transport", "network.protocol",
    "network.direction", "network.community_id", "network.bytes",
    "network.packets", "dns.id", "dns.question.name", "dns.question.type",
    "dns.question.class", "dns.query.name", "dns.query.type",
    "dns.query.class", "dns.response_code", "dns.response.code",
    "dns.response.code_name", "dns.resolved_ip", "dns.answers.type",
    "dns.highest_registered_domain", "dns.parent_domain",
    "dns.top_level_domain", "tls.server.name", "ssl.server_name",
    "ssl.cipher", "ssl.curve", "ssl.established", "ssl.validation_status",
    "ssl.version", "url.domain", "http.method", "http.status_code",
    "http.trans_depth", "http.virtual_host", "http.request.body.length",
    "http.response.body.length", "file.resp_mime_types", "host.id",
    "host.name", "host.hostname", "host.ip", "agent.id", "agent.name",
    "related.ip", "related.hosts", "related.user", "source.address",
    "user.id", "user.name", "source.user.name", "destination.user.name",
    "client.user.name", "process.entity_id", "process.pid",
    "process.parent.pid", "process.name", "system.auth.ssh.event",
    "log.syslog.appname", "log.id.uid", "log.id.fuid",
    "log.id.resp_fuids", "observer.name", "hash.ja3", "hash.ja3s",
    "hash.ja4", "hash.hassh", "hash.md5", "hash.sha1", "hash.sha256",
    "tls.server.hash.sha256", "file.extension", "file.hash.sha256",
    "file.analyzer", "file.bytes.missing", "file.bytes.overflow",
    "file.bytes.seen", "file.bytes.total", "file.depth", "file.local_orig",
    "file.mime_type", "file.source", "ssh.authentication.attempts",
    "ssh.authentication.success", "ssh.cipher_algorithm", "ssh.client",
    "ssh.compression_algorithm", "ssh.hassh_algorithms", "ssh.hassh_server",
    "ssh.hassh_server_algorithms", "ssh.hassh_version",
    "ssh.host_key_algorithm", "ssh.kex_algorithm", "ssh.mac_algorithm",
    "ssh.server", "ssh.version", "stun.attribute.types",
    "stun.attribute.values", "stun.class", "stun.id", "stun.method",
    "stun.lan.addresses", "stun.wan.addresses", "stun.wan.ports",
    "quic.client_initial_dcid", "quic.client_protocol", "quic.client_scid",
    "quic.history", "quic.server_name", "quic.server_scid", "quic.version",
    "notice.action", "notice.note", "notice.suppress_for", "weird.name",
    "weird.peer", "error.reason",
})
PCAP_RECORD_FIELDS = frozenset({
    "timestamp", "ts", "start_time", "end_time", "first_seen", "last_seen",
    "duration", "count", "count_error_max", "uid", "fuid", "source_ip",
    "destination_ip", "endpoint_ip", "src_ip", "dst_ip", "source_port",
    "destination_port", "src_port", "dst_port", "port", "transport",
    "protocol", "service", "connection_state", "conn_state", "source_bytes",
    "destination_bytes", "bytes", "orig_bytes", "resp_bytes",
    "source_packets", "destination_packets", "packets", "orig_pkts",
    "resp_pkts", "missed_bytes", "rejected", "query", "query_name",
    "dns_query", "dns_queries", "qtype", "qtype_name", "dns_qtypes",
    "rcode", "rcode_name", "dns_rcodes", "answer", "answer_type",
    "dns_answers", "sni", "server_name", "tls_sni", "version",
    "tls_versions", "cipher", "curve", "resumed", "established",
    "next_protocol", "ja3", "ja3s", "method", "host", "http_host",
    "request_body_len", "response_body_len", "status_code", "mime_type",
    "seen_bytes", "total_bytes", "missing_bytes", "overflow_bytes", "md5",
    "sha1", "sha256", "icmp_family", "icmp_type", "icmp_code",
    "icmp_identifier", "icmp_sequence", "icmp_payload_length",
    "frame_length_min", "frame_length_max", "payload_length_min",
    "payload_length_max", "selected_scope_match", "country_iso_code", "asn",
    "latitude", "longitude",
})
OSQUERY_ROW_FIELDS = frozenset({
    "address", "arch", "cpu_brand", "cpu_logical_cores",
    "cpu_physical_cores", "gid", "hardware_model", "hardware_vendor",
    "host", "hostname", "interface", "local_address", "local_port", "name",
    "parent", "physical_memory", "pid", "port", "protocol",
    "remote_address", "remote_port", "release", "start_time", "status",
    "time", "tty", "type", "uid", "user", "uuid", "version",
})
SENSITIVE_VALUE = re.compile(
    r"(?i)(?:\bauthorization\s*[:=]|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]{8,}|"
    r"\b(?:password|passwd|secret|token|api[_ -]?key|cookie|credential)"
    r"\b\s*[:=]\s*\S+)"
)
HOST_PATH = re.compile(r"(?i)(?:^|[/\\])(?:Users|home)[/\\][^/\\\s]+[/\\]")
SENSITIVE_QUERY = re.compile(
    r"(?i)(?:[?&](?:access_token|api_key|authorization|cookie|password|"
    r"secret|session|token)=)"
)
_UNHANDLED = object()


@dataclass(frozen=True)
class Policy:
    provenance_schema: str
    columns: tuple[str, ...]
    maximum_queries: int
    list_path_sentinel: object
    maximum_projected_rows: int = 600
    maximum_nested_items: int = 2000
    maximum_positive_list_items: int = 200
    token_key: Pattern[str] = TOKEN_KEY
    sensitive_value: Pattern[str] = SENSITIVE_VALUE


@dataclass(frozen=True)
class Dependencies:
    exact_columnar_envelope: Callable[..., bool]
    prompt_json_bytes: Callable[[Any], bytes]


def positive_project_paths(
    value: Any,
    allowed_paths: frozenset[str],
    *,
    maximum_list_items: int,
    path: tuple[str, ...] = (),
) -> Any:
    """Project a nested document using exact reviewed leaf paths."""
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            child_path = (*path, key)
            dotted = ".".join(child_path)
            if not _path_is_admitted(dotted, allowed_paths):
                continue
            projected = positive_project_paths(
                child, allowed_paths,
                maximum_list_items=maximum_list_items, path=child_path,
            )
            if projected not in ({}, [], None):
                output[key] = projected
        return output
    if isinstance(value, list):
        return [
            positive_project_paths(
                item, allowed_paths,
                maximum_list_items=maximum_list_items, path=path,
            )
            for item in value[:maximum_list_items]
        ]
    return value if ".".join(path) in allowed_paths else None


def _path_is_admitted(path: str, allowed_paths: frozenset[str]) -> bool:
    return any(allowed == path or allowed.startswith(path + ".") for allowed in allowed_paths)


def project_result_rows(key: str, value: list[Any], policy: Policy) -> list[Any]:
    projected: list[Any] = []
    for raw in value[:policy.maximum_projected_rows]:
        if not isinstance(raw, dict):
            continue
        if key == "hits":
            projected.append(_project_hit(raw, policy))
            continue
        allowed = PCAP_RECORD_FIELDS if key == "records" else OSQUERY_ROW_FIELDS
        projected.append({
            str(field): child for field, child in raw.items()
            if str(field).lower() in allowed
        })
    return projected


def _project_hit(raw: dict[str, Any], policy: Policy) -> dict[str, Any]:
    item = {field: raw[field] for field in ("id", "index") if field in raw}
    source = raw.get("source")
    if isinstance(source, dict):
        item["source"] = positive_project_paths(
            source, ELASTIC_SOURCE_PATHS,
            maximum_list_items=policy.maximum_positive_list_items,
        )
    return item


def prune_empty(value: Any) -> Any:
    """Remove empty projection shells while preserving explicit empty results."""
    if isinstance(value, dict):
        return _prune_mapping(value)
    if isinstance(value, list):
        return [projected for child in value
                if not _empty(projected := prune_empty(child))]
    return value


def _prune_mapping(value: dict[Any, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for raw_key, child in value.items():
        projected = prune_empty(child)
        normalized = _normalized_key(raw_key)
        if isinstance(projected, list) and not projected and normalized in _ROW_KEYS:
            output[str(raw_key)] = []
        elif not _empty(projected):
            output[str(raw_key)] = projected
    return output


def _empty(value: Any) -> bool:
    return isinstance(value, (dict, list)) and not value


_ROW_KEYS = frozenset({"hits", "records", "rows"})
_COLUMNAR_TABLE_KEYS = frozenset({
    "backend_values", "status_values", "semantics_values",
    "result_summary_values",
})


def reviewed_sha256_path(path: tuple[object, ...], policy: Policy) -> bool:
    """Allow SHA-256 only at positively projected Elastic source paths."""
    if not path or path[0] != "investigation_query_results":
        return False
    anchor = ("hits", policy.list_path_sentinel, "source")
    suffixes = {("hash",), ("file", "hash"), ("tls", "server", "hash")}
    for position in range(max(0, len(path) - len(anchor) + 1)):
        if path[position:position + len(anchor)] == anchor:
            return path[position + len(anchor):] in suffixes
    return False


def sanitize(
    value: Any,
    *,
    path: tuple[str, ...] = (),
    preserve_columnar_rows: bool = False,
    policy: Policy,
) -> Any:
    """Keep allowlisted evidence facts while removing hosted-sensitive values."""
    if isinstance(value, dict):
        return _sanitize_mapping(value, path, preserve_columnar_rows, policy)
    if isinstance(value, list):
        return [
            sanitize(
                item, path=path, preserve_columnar_rows=preserve_columnar_rows,
                policy=policy,
            )
            for item in value[:policy.maximum_nested_items]
        ]
    return _sanitize_string(value, policy) if isinstance(value, str) else value


def _sanitize_mapping(
    value: dict[Any, Any],
    path: tuple[str, ...],
    preserve_columnar_rows: bool,
    policy: Policy,
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    columnar = _is_exact_columnar_context(value, path, preserve_columnar_rows, policy)
    for raw_key, item in value.items():
        key = str(raw_key)
        normalized = _normalized_key(key)
        special = _sanitize_columnar_item(normalized, item, path, columnar, policy)
        if special is not _UNHANDLED:
            output[key] = special
            continue
        admitted, projected = _sanitize_regular_item(
            normalized, item, path, preserve_columnar_rows, columnar, policy
        )
        if admitted:
            output[key] = projected
    return output


def _is_exact_columnar_context(
    value: dict[Any, Any],
    path: tuple[str, ...],
    preserve: bool,
    policy: Policy,
) -> bool:
    return bool(
        preserve
        and path == ("investigation_query_results", "rounds")
        and value.get("schema") == policy.provenance_schema
        and value.get("prompt_projection")
        == "columnar_provenance_due_to_cumulative_byte_budget"
        and value.get("columns") == list(policy.columns)
    )


def _sanitize_columnar_item(
    key: str,
    item: Any,
    path: tuple[str, ...],
    columnar: bool,
    policy: Policy,
) -> Any:
    if columnar and key in _COLUMNAR_TABLE_KEYS and isinstance(item, list):
        return _sanitize_columnar_table(item, (*path, key), policy)
    if columnar and key == "rows" and isinstance(item, list):
        return _sanitize_columnar_rows(item, (*path, key), policy)
    return _UNHANDLED


def _sanitize_columnar_table(
    values: list[Any], path: tuple[str, ...], policy: Policy
) -> list[Any]:
    output = []
    for child in values[:policy.maximum_queries]:
        sanitized = sanitize(child, path=path, preserve_columnar_rows=True, policy=policy)
        output.append("[r]" if sanitized != child else sanitized)
    return output


def _sanitize_columnar_rows(
    rows: list[Any], path: tuple[str, ...], policy: Policy
) -> list[list[Any]]:
    output: list[list[Any]] = []
    reference_index = policy.columns.index("evidence_ref_or_empty")
    for raw_row in rows[:policy.maximum_queries]:
        if not isinstance(raw_row, list):
            continue
        sanitized = [
            sanitize(child, path=path, preserve_columnar_rows=True, policy=policy)
            for child in raw_row
        ]
        if len(sanitized) == len(policy.columns) and sanitized[reference_index] != raw_row[reference_index]:
            sanitized[reference_index] = ""
        output.append(sanitized)
    return output


def _sanitize_regular_item(
    key: str,
    item: Any,
    path: tuple[str, ...],
    preserve: bool,
    columnar: bool,
    policy: Policy,
) -> tuple[bool, Any]:
    result_rows = key in _ROW_KEYS and isinstance(item, list) and not (
        columnar and key == "rows"
    )
    if result_rows:
        item = project_result_rows(key, item, policy)
    if _invalid_sha256(key, item) or _sensitive_key(path, key, item, policy):
        return False, None
    projected = sanitize(item, path=(*path, key), preserve_columnar_rows=preserve, policy=policy)
    return True, prune_empty(projected) if result_rows else projected


def _invalid_sha256(key: str, value: Any) -> bool:
    return bool(
        key == "sha256"
        and (not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value))
    )


def _sensitive_key(
    path: tuple[str, ...], key: str, value: Any, policy: Policy
) -> bool:
    parent = _normalized_key(path[-1]) if path else ""
    token_like = bool(policy.token_key.search(key)) and not key.endswith("_digest")
    return token_like or _path_sensitive(parent, key) or key in SENSITIVE_KEYS


def _path_sensitive(parent: str, key: str) -> bool:
    fields = {
        "event": {"original"},
        "process": {"args", "command_line"},
        "url": {"query"},
        "file": {"content", "data"},
    }
    return key in fields.get(parent, set())


def _sanitize_string(value: str, policy: Policy) -> str:
    if policy.sensitive_value.search(value):
        return "[redacted-sensitive-value]"
    if HOST_PATH.search(value):
        return "[redacted-host-path]"
    if SENSITIVE_QUERY.search(value):
        return value.split("?", 1)[0] + "?[redacted-query]"
    return value


def _normalized_key(value: Any) -> str:
    return str(value).lower().replace("-", "_")


def refinalize_columnar(
    value: Any,
    *,
    maximum_passes: int,
    dependencies: Dependencies,
) -> Any:
    """Refresh columnar self-accounting after hosted string redaction."""
    if not dependencies.exact_columnar_envelope(
        value, require_encoded_accounting=False
    ):
        return value
    projection = value["prompt_projection"]
    projection["encoded_bytes"] = 0
    for _ in range(maximum_passes):
        actual_bytes = len(dependencies.prompt_json_bytes(value))
        if projection["encoded_bytes"] == actual_bytes:
            break
        projection["encoded_bytes"] = actual_bytes
    return value
