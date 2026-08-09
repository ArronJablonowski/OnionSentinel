#!/usr/bin/env python3
"""Typed, allowlisted pivots over sanitized, derived PCAP evidence.

The investigation runtime may ask for a narrower view of facts already
produced by Zeek or TShark. Model text is never translated into a display
filter, script, command, parser argument, path, regular expression, or raw
packet access. Every request is a small declarative object whose fields are
validated here and compared in Python against a bounded local evidence index.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from typing import Any, Iterable

from pcap_analysis_core import sanitize_evidence_text, sanitize_evidence_value


MAX_QUERY_REQUESTS = 4
MAX_QUERY_LIMIT = 20
MAX_QUERY_RESULT_BYTES = 32 * 1024
MAX_QUERY_SCAN_RECORDS = 4096
MAX_REQUEST_TEXT_CHARS = 512
QUERY_CONTRACT = "onion-sentinel-derived-pcap-pivots-v2"

# Paths point only at derived JSON. No path is supplied by the caller and no
# operation invokes a parser, opens a capture, or reaches the network.
QUERY_PATHS = {
    "coverage": (("coverage",), ("zeek", "coverage"), ("tshark", "coverage")),
    "connections": (
        ("_local_query_index", "connections"),
        ("zeek", "_local_query_index", "connections"),
        ("tshark", "_local_query_index", "connections"),
        ("tshark", "_local_query_index", "packet_facts"),
        ("zeek", "top_connections"),
        ("tshark", "top_conversations"),
    ),
    "dns": (
        ("_local_query_index", "dns_records"),
        ("zeek", "_local_query_index", "dns"),
        ("tshark", "_local_query_index", "dns_records"),
        ("_local_query_index", "dns"),
        ("tshark", "_local_query_index", "dns"),
        ("zeek", "dns_queries"),
        ("tshark", "dns_activity", "query_names"),
        ("tshark", "dns_activity", "answers"),
        ("tshark", "dns_activity", "response_codes"),
    ),
    "tls": (
        ("_local_query_index", "tls_records"),
        ("zeek", "_local_query_index", "tls"),
        ("tshark", "_local_query_index", "tls_records"),
        ("_local_query_index", "tls"),
        ("zeek", "tls_sni"),
    ),
    "http": (
        ("_local_query_index", "http_records"),
        ("zeek", "_local_query_index", "http"),
        ("tshark", "_local_query_index", "http_records"),
        ("_local_query_index", "http"),
        ("zeek", "http_hosts"),
    ),
    "files": (
        ("_local_query_index", "files"),
        ("zeek", "_local_query_index", "files"),
        ("zeek", "files"),
    ),
    "notices": (
        ("_local_query_index", "notices"),
        ("zeek", "_local_query_index", "notices"),
        ("zeek", "notices"),
    ),
    "weird": (
        ("_local_query_index", "weird"),
        ("zeek", "_local_query_index", "weird"),
        ("zeek", "weird"),
    ),
    "protocols": (
        ("_local_query_index", "protocols"),
        ("tshark", "_local_query_index", "protocols"),
        ("tshark", "protocol_counts"),
    ),
    "packet_facts": (
        ("_local_query_index", "packet_facts"),
        ("tshark", "_local_query_index", "packet_facts"),
        ("_local_query_index", "packet_samples"),
        ("tshark", "_local_query_index", "packet_samples"),
        ("tshark", "packet_samples"),
    ),
    # Retained for compatibility. It has the same payload-free projection as
    # packet_facts; the name does not grant access to raw packet bytes.
    "packet_samples": (
        ("_local_query_index", "packet_facts"),
        ("tshark", "_local_query_index", "packet_facts"),
        ("_local_query_index", "packet_samples"),
        ("tshark", "_local_query_index", "packet_samples"),
        ("tshark", "packet_samples"),
    ),
    "icmp_facts": (
        ("_local_query_index", "icmp_facts"),
        ("tshark", "_local_query_index", "icmp_facts"),
        ("_local_query_index", "icmp_anomalies"),
        ("tshark", "_local_query_index", "icmp_anomalies"),
        ("tshark", "icmp_size_review", "top_abnormal_flows"),
        ("tshark", "icmp_size_review", "representative_samples"),
    ),
    "icmp_anomalies": (
        ("_local_query_index", "icmp_facts"),
        ("tshark", "_local_query_index", "icmp_facts"),
        ("_local_query_index", "icmp_anomalies"),
        ("tshark", "_local_query_index", "icmp_anomalies"),
        ("tshark", "icmp_size_review", "top_abnormal_flows"),
    ),
    "user_agents": (
        ("_local_query_index", "user_agents"),
        ("tshark", "_local_query_index", "user_agents"),
        ("tshark", "http_user_agents", "values"),
    ),
    "tls_versions": (
        ("_local_query_index", "tls_versions"),
        ("tshark", "_local_query_index", "tls_versions"),
        ("tshark", "tls_versions", "versions"),
    ),
    "geoip": (
        ("_local_query_index", "geoip"),
        ("tshark", "_local_query_index", "geoip"),
        ("tshark", "geoip", "records"),
    ),
}

FLOW_FILTERS = {
    "source_ip",
    "destination_ip",
    "endpoint_ip",
    "source_port",
    "destination_port",
    "port",
    "transport",
    "transport_scope_status",
    "protocol",
    "start_epoch",
    "end_epoch",
}
FILTERS_BY_OPERATION = {
    "coverage": set(),
    "connections": FLOW_FILTERS | {"service", "connection_state"},
    "dns": FLOW_FILTERS | {"query", "answer", "answer_type", "qtype", "rcode"},
    "tls": FLOW_FILTERS | {"sni", "version", "cipher", "established"},
    "http": FLOW_FILTERS | {"host", "uri", "uri_prefix", "method", "status_code", "user_agent"},
    "files": FLOW_FILTERS | {"mime_type", "filename", "sha256"},
    "notices": FLOW_FILTERS | {"note", "message"},
    "weird": FLOW_FILTERS | {"name", "additional"},
    "protocols": {"protocol"},
    "packet_facts": FLOW_FILTERS
    | {
        "query",
        "answer",
        "rcode",
        "sni",
        "version",
        "host",
        "uri",
        "uri_prefix",
        "user_agent",
        "frame_length_min",
        "frame_length_max",
        "icmp_type",
        "icmp_code",
    },
    "packet_samples": FLOW_FILTERS
    | {
        "query",
        "answer",
        "rcode",
        "sni",
        "version",
        "host",
        "uri",
        "uri_prefix",
        "user_agent",
        "frame_length_min",
        "frame_length_max",
        "icmp_type",
        "icmp_code",
    },
    "icmp_facts": FLOW_FILTERS
    | {
        "family",
        "icmp_type",
        "icmp_code",
        "identifier",
        "sequence",
        "frame_length_min",
        "frame_length_max",
        "payload_length_min",
        "payload_length_max",
        "selected_scope_match",
    },
    "icmp_anomalies": FLOW_FILTERS
    | {
        "family",
        "icmp_type",
        "icmp_code",
        "identifier",
        "sequence",
        "frame_length_min",
        "frame_length_max",
        "payload_length_min",
        "payload_length_max",
        "selected_scope_match",
    },
    "user_agents": {"user_agent", "http_version"},
    "tls_versions": {"version", "version_source"},
    "geoip": {"ip", "country_iso_code", "asn"},
}

IP_FILTERS = {"source_ip", "destination_ip", "endpoint_ip", "ip"}
PORT_FILTERS = {"source_port", "destination_port", "port"}
INTEGER_FILTER_RANGES = {
    "source_port": (0, 65535),
    "destination_port": (0, 65535),
    "port": (0, 65535),
    "status_code": (0, 999),
    "icmp_type": (0, 255),
    "icmp_code": (0, 255),
    "identifier": (0, 2**32 - 1),
    "sequence": (0, 2**32 - 1),
    "frame_length_min": (0, 2**32 - 1),
    "frame_length_max": (0, 2**32 - 1),
    "payload_length_min": (0, 2**32 - 1),
    "payload_length_max": (0, 2**32 - 1),
    "asn": (0, 2**32 - 1),
}
BOOLEAN_FILTERS = {"established", "selected_scope_match"}
TIME_FILTERS = {"start_epoch", "end_epoch"}

# Canonical filters may be represented by different parser field names.
FILTER_FIELD_ALIASES = {
    "source_ip": {"source_ip", "id.orig_h", "src"},
    "destination_ip": {"destination_ip", "id.resp_h", "dst"},
    "source_port": {"source_port", "id.orig_p"},
    "destination_port": {"destination_port", "id.resp_p"},
    "transport": {"transport", "proto"},
    "protocol": {"protocol"},
    "service": {"service"},
    "connection_state": {"connection_state", "conn_state"},
    "query": {"query", "dns_query", "dns_queries"},
    "answer": {"answer", "dns_answers"},
    "answer_type": {"answer_type"},
    "qtype": {"qtype", "qtype_name", "dns_qtype", "dns_qtypes", "dns_query_type"},
    "rcode": {"rcode", "rcode_name", "dns_rcode", "dns_rcodes"},
    "sni": {"sni", "server_name", "tls_sni"},
    "version": {"version", "tls_version", "tls_versions"},
    "version_source": {"version_source", "source"},
    "cipher": {"cipher"},
    "established": {"established"},
    "host": {"host", "http_host"},
    "uri": {"uri", "http_uri"},
    "method": {"method"},
    "status_code": {"status_code"},
    "user_agent": {"user_agent", "http_user_agent", "http_user_agents"},
    "http_version": {"http_version"},
    "mime_type": {"mime_type"},
    "filename": {"filename"},
    "sha256": {"sha256"},
    "note": {"note"},
    "message": {"message", "msg"},
    "name": {"name"},
    "additional": {"additional", "addl"},
    "family": {"family", "icmp_family"},
    "icmp_type": {"icmp_type", "type"},
    "icmp_code": {"icmp_code", "code"},
    "identifier": {"identifier", "icmp_identifier"},
    "sequence": {"sequence", "icmp_sequence"},
    "frame_length_min": {"frame_length", "frame_bytes"},
    "frame_length_max": {"frame_length", "frame_bytes"},
    "payload_length_min": {"payload_length", "payload_bytes", "icmp_payload_length"},
    "payload_length_max": {"payload_length", "payload_bytes", "icmp_payload_length"},
    "selected_scope_match": {"selected_scope_match"},
    "ip": {"ip"},
    "country_iso_code": {"country_iso_code"},
    "asn": {"asn", "autonomous_system_number"},
    "start_epoch": {"timestamp_epoch", "ts"},
    "end_epoch": {"timestamp_epoch", "ts"},
}

BASE_OUTPUT_FIELDS = {
    "source",
    "record_type",
    "count",
    "count_error_max",
    "timestamp_epoch",
    "ts",
    "frame_number",
    "frame_length",
    "frame_bytes",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "transport",
    "transport_scope_status",
    "protocol",
}
OUTPUT_FIELDS_BY_OPERATION = {
    "connections": BASE_OUTPUT_FIELDS
    | {
        "uid",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "connection_state",
        "history",
        "missed_bytes",
        "id.orig_h",
        "id.resp_h",
        "id.orig_p",
        "id.resp_p",
        "proto",
    },
    "dns": BASE_OUTPUT_FIELDS
    | {
        "uid",
        "query",
        "dns_query",
        "dns_queries",
        "qtype",
        "qtype_name",
        "dns_qtypes",
        "rcode",
        "rcode_name",
        "dns_rcodes",
        "answer",
        "answer_type",
        "dns_answers",
        "rejected",
    },
    "tls": BASE_OUTPUT_FIELDS
    | {
        "uid",
        "sni",
        "server_name",
        "tls_sni",
        "version",
        "tls_versions",
        "cipher",
        "curve",
        "resumed",
        "established",
        "next_protocol",
        "ja3",
        "ja3s",
    },
    "http": BASE_OUTPUT_FIELDS
    | {
        "uid",
        "method",
        "host",
        "http_host",
        "uri",
        "http_uri",
        "referrer",
        "version",
        "user_agent",
        "http_user_agents",
        "request_body_len",
        "response_body_len",
        "status_code",
        "status_message",
    },
    "files": BASE_OUTPUT_FIELDS
    | {
        "uid",
        "fuid",
        "source_name",
        "mime_type",
        "filename",
        "seen_bytes",
        "total_bytes",
        "missing_bytes",
        "overflow_bytes",
        "md5",
        "sha1",
        "sha256",
    },
    "notices": BASE_OUTPUT_FIELDS | {"uid", "note", "message", "sub", "dropped"},
    "weird": BASE_OUTPUT_FIELDS | {"uid", "name", "additional", "notice"},
    "protocols": {"count", "count_error_max", "protocol"},
    "packet_facts": BASE_OUTPUT_FIELDS
    | {
        "dns_query",
        "dns_queries",
        "dns_qtypes",
        "dns_rcodes",
        "dns_answers",
        "tls_sni",
        "tls_versions",
        "http_host",
        "http_uri",
        "http_user_agents",
        "icmp_family",
        "icmp_type",
        "icmp_code",
        "icmp_identifier",
        "icmp_sequence",
        "icmp_payload_length",
        "selected_scope_match",
        "scope_exclusion_reason",
    },
    "packet_samples": BASE_OUTPUT_FIELDS
    | {
        "dns_query",
        "dns_queries",
        "dns_qtypes",
        "dns_rcodes",
        "dns_answers",
        "tls_sni",
        "tls_versions",
        "http_host",
        "http_uri",
        "http_user_agents",
        "icmp_family",
        "icmp_type",
        "icmp_code",
        "icmp_identifier",
        "icmp_sequence",
        "icmp_payload_length",
        "selected_scope_match",
        "scope_exclusion_reason",
    },
    "icmp_facts": BASE_OUTPUT_FIELDS
    | {
        "family",
        "type",
        "code",
        "identifier",
        "sequence",
        "payload_length",
        "icmp_family",
        "icmp_type",
        "icmp_code",
        "icmp_identifier",
        "icmp_sequence",
        "icmp_payload_length",
        "selected_scope_match",
        "scope_exclusion_reason",
    },
    "icmp_anomalies": BASE_OUTPUT_FIELDS
    | {
        "family",
        "type",
        "code",
        "identifier",
        "sequence",
        "payload_length",
        "icmp_family",
        "icmp_type",
        "icmp_code",
        "icmp_identifier",
        "icmp_sequence",
        "icmp_payload_length",
        "selected_scope_match",
        "scope_exclusion_reason",
    },
    "user_agents": {"count", "count_error_max", "http_version", "user_agent"},
    "tls_versions": {"count", "count_error_max", "source", "version_source", "raw_version", "version"},
    "geoip": {
        "ip",
        "roles",
        "packet_observations",
        "continent",
        "country_iso_code",
        "country",
        "registered_country_iso_code",
        "subdivision",
        "city",
        "time_zone",
        "accuracy_radius_km",
        "latitude",
        "longitude",
        "autonomous_system_number",
        "autonomous_system_organization",
        "database_sources",
    },
}
FORBIDDEN_OUTPUT_KEYS = {
    "payload",
    "raw_payload",
    "data_payload",
    "raw_packet",
    "packet_bytes",
    "display_filter",
    "bpf_filter",
    "command",
    "commands",
    "script",
    "parser_args",
    "arguments",
    "stdout",
    "stderr",
    "path",
    "paths",
    "analysis_dir",
    "tool_paths",
}
NESTED_OUTPUT_FIELDS = {
    "dns_answers": {"answer_type", "answer"},
    "tls_versions": {"version_source", "raw_version", "version"},
    "http_user_agents": {"http_version", "user_agent"},
}
COVERAGE_SCALAR_FIELDS = {
    "total_records",
    "decoded_records",
    "undecoded_records",
    "decode_percent",
    "total_bytes",
    "first_timestamp_epoch",
    "last_timestamp_epoch",
    "duration_seconds",
    "malformed_records",
    "pcap_files_total",
    "pcap_files_processed",
    "records_aggregated",
    "complete",
    "ok",
}
CONTROL_OR_ESCAPE = re.compile(r"[\x00-\x1f\x7f\x1b]")


class PcapEvidenceQueryError(ValueError):
    """The requested operation violated the derived-evidence query contract."""


def _nested(record: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _text(value: Any, field: str, max_chars: int = MAX_REQUEST_TEXT_CHARS) -> str:
    if not isinstance(value, (str, int, float)):
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be a scalar")
    text = str(value).strip()
    if not text:
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} cannot be empty")
    if len(text) > max_chars:
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} exceeds {max_chars} characters")
    if CONTROL_OR_ESCAPE.search(text):
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} contains control characters")
    return text


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be an integer")
    try:
        converted = int(value)
    except (TypeError, ValueError) as exc:
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be an integer") from exc
    if str(value).strip() not in {str(converted), f"+{converted}"} and not isinstance(value, int):
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be an integer")
    if converted < minimum or converted > maximum:
        raise PcapEvidenceQueryError(
            f"PCAP evidence filter {field} must be between {minimum} and {maximum}"
        )
    return converted


def _epoch(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be a finite epoch number")
    try:
        converted = float(value)
    except (TypeError, ValueError) as exc:
        raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be a finite epoch number") from exc
    if not math.isfinite(converted) or converted < 0 or converted > 4_102_444_800:
        raise PcapEvidenceQueryError(
            f"PCAP evidence filter {field} must be a finite epoch between 1970 and 2100"
        )
    return converted


def _normalize_filters(operation: str, raw: Any) -> dict[str, Any]:
    if raw in (None, ""):
        return {}
    if not isinstance(raw, dict):
        raise PcapEvidenceQueryError("PCAP evidence query filters must be an object")
    unknown = set(raw).difference(FILTERS_BY_OPERATION[operation])
    if unknown:
        raise PcapEvidenceQueryError(
            f"unsupported {operation} filter fields: {', '.join(sorted(str(item) for item in unknown))}"
        )
    normalized: dict[str, Any] = {}
    for field, value in raw.items():
        if field in IP_FILTERS:
            text = _text(value, field, 64)
            try:
                normalized[field] = str(ipaddress.ip_address(text))
            except ValueError as exc:
                raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be an IP address") from exc
        elif field in INTEGER_FILTER_RANGES:
            normalized[field] = _integer(value, field, *INTEGER_FILTER_RANGES[field])
        elif field in TIME_FILTERS:
            normalized[field] = _epoch(value, field)
        elif field in BOOLEAN_FILTERS:
            if not isinstance(value, bool):
                raise PcapEvidenceQueryError(f"PCAP evidence filter {field} must be true or false")
            normalized[field] = value
        else:
            normalized[field] = _text(value, field)
    start = normalized.get("start_epoch")
    end = normalized.get("end_epoch")
    if start is not None and end is not None and start > end:
        raise PcapEvidenceQueryError("PCAP evidence start_epoch cannot be after end_epoch")
    for lower, upper in (
        ("frame_length_min", "frame_length_max"),
        ("payload_length_min", "payload_length_max"),
    ):
        if lower in normalized and upper in normalized and normalized[lower] > normalized[upper]:
            raise PcapEvidenceQueryError(f"PCAP evidence {lower} cannot exceed {upper}")
    return normalized


def _iter_scalars(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_scalars(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_scalars(item)
    elif value not in (None, ""):
        yield value


def _field_values(value: Any, aliases: set[str]) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key) in aliases:
                found.extend(_iter_scalars(item))
            if isinstance(item, (dict, list)):
                found.extend(_field_values(item, aliases))
    elif isinstance(value, list):
        for item in value:
            found.extend(_field_values(item, aliases))
    return found


def _equals(candidate: Any, expected: Any) -> bool:
    if isinstance(expected, bool):
        return candidate is expected or str(candidate).strip().casefold() == str(expected).casefold()
    if isinstance(expected, int):
        try:
            return int(candidate) == expected and float(candidate) == expected
        except (TypeError, ValueError, OverflowError):
            return False
    return sanitize_evidence_text(candidate, MAX_REQUEST_TEXT_CHARS).casefold() == str(expected).casefold()


def _numeric_values(candidate: Any, field: str) -> list[float]:
    values = _field_values(candidate, FILTER_FIELD_ALIASES[field])
    output: list[float] = []
    for value in values:
        try:
            converted = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(converted):
            output.append(converted)
    return output


def _filter_matches(candidate: Any, field: str, expected: Any) -> bool:
    if field in IP_FILTERS:
        if field == "endpoint_ip":
            aliases = FILTER_FIELD_ALIASES["source_ip"] | FILTER_FIELD_ALIASES["destination_ip"]
        else:
            aliases = FILTER_FIELD_ALIASES[field]
        values = _field_values(candidate, aliases)
        for value in values:
            try:
                if str(ipaddress.ip_address(str(value).strip())) == expected:
                    return True
            except ValueError:
                continue
        return False
    if field == "port":
        values = _field_values(
            candidate,
            FILTER_FIELD_ALIASES["source_port"] | FILTER_FIELD_ALIASES["destination_port"],
        )
        return any(_equals(value, expected) for value in values)
    if field in {"start_epoch", "end_epoch"}:
        timestamps = _numeric_values(candidate, field)
        if not timestamps:
            # A time-bounded query must not silently admit timeless aggregate
            # rows; only records with explicit timestamps can satisfy it.
            return False
        return any(value >= expected for value in timestamps) if field == "start_epoch" else any(
            value <= expected for value in timestamps
        )
    if field.endswith("_min"):
        return any(value >= expected for value in _numeric_values(candidate, field))
    if field.endswith("_max"):
        return any(value <= expected for value in _numeric_values(candidate, field))
    if field == "uri_prefix":
        values = _field_values(candidate, FILTER_FIELD_ALIASES["uri"])
        prefix = str(expected).casefold()
        return any(sanitize_evidence_text(value, MAX_REQUEST_TEXT_CHARS).casefold().startswith(prefix) for value in values)
    values = _field_values(candidate, FILTER_FIELD_ALIASES[field])
    return any(_equals(value, expected) for value in values)


def _matches_indicator(value: Any, indicator: str) -> bool:
    if not indicator:
        return True
    return any(
        sanitize_evidence_text(item, MAX_REQUEST_TEXT_CHARS).casefold() == indicator.casefold()
        for item in _iter_scalars(value)
    )


def _scrub_nested(value: Any, container: str = "") -> Any:
    """Defend in depth against raw/parser fields inside an approved container."""
    if isinstance(value, dict):
        allowed = NESTED_OUTPUT_FIELDS.get(container)
        return {
            sanitize_evidence_text(key, 128): _scrub_nested(item, str(key))
            for key, item in value.items()
            if not _forbidden_output_key(key)
            and (allowed is None or str(key) in allowed)
        }
    if isinstance(value, list):
        return [_scrub_nested(item, container) for item in value[:64]]
    return sanitize_evidence_value(value, max_chars=512, max_items=64)


def _forbidden_output_key(key: Any) -> bool:
    lowered = str(key).strip().lower()
    if lowered in FORBIDDEN_OUTPUT_KEYS:
        return True
    # Length/count facts are safe; payload contents are not.
    return "payload" in lowered and not lowered.endswith(("_length", "_bytes", "_count"))


def _project_coverage(value: Any) -> Any:
    """Keep coverage telemetry without trusting arbitrary coverage keys."""
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in COVERAGE_SCALAR_FIELDS:
                output[key_text] = sanitize_evidence_value(item, max_chars=128, max_items=16)
            elif key_text == "per_log" and isinstance(item, dict):
                output[key_text] = {
                    sanitize_evidence_text(log_name, 40): _project_coverage(log_coverage)
                    for log_name, log_coverage in list(item.items())[:16]
                }
            elif key_text == "per_file" and isinstance(item, list):
                output[key_text] = [_project_coverage(record) for record in item[:256]]
        return output
    return {}


def _project_record(operation: str, candidate: Any) -> Any:
    if operation == "coverage":
        return _project_coverage(candidate)
    output_operation = "packet_facts" if operation == "packet_samples" else (
        "icmp_facts" if operation == "icmp_anomalies" else operation
    )
    allowed = OUTPUT_FIELDS_BY_OPERATION[output_operation]
    if not isinstance(candidate, dict):
        return {}
    projected = {
        sanitize_evidence_text(key, 128): _scrub_nested(value, str(key))
        for key, value in candidate.items()
        if str(key) in allowed
        and not _forbidden_output_key(key)
    }
    return projected


def _query_candidates(
    evidence: list[Any],
    operation: str,
) -> tuple[list[Any], list[str], bool]:
    candidates: list[Any] = []
    sources: list[str] = []
    scan_truncated = False
    for item in evidence:
        if not isinstance(item, dict):
            continue
        for path in QUERY_PATHS[operation]:
            value = _nested(item, path)
            if value is None:
                continue
            sources.append(".".join(path))
            records = value if isinstance(value, list) else [value]
            remaining = MAX_QUERY_SCAN_RECORDS - len(candidates)
            if remaining <= 0:
                scan_truncated = True
                break
            candidates.extend(records[:remaining])
            if len(records) > remaining:
                scan_truncated = True
        if len(candidates) >= MAX_QUERY_SCAN_RECORDS:
            scan_truncated = True
            break
    return candidates, sorted(set(sources)), scan_truncated


def query_derived_pcap_evidence(pcap_context: dict[str, Any], requests: Any) -> dict[str, Any]:
    """Execute typed read-only pivots and return bounded audit metadata."""
    if requests in (None, ""):
        return {"executed": [], "results": []}
    if not isinstance(pcap_context, dict):
        raise PcapEvidenceQueryError("PCAP evidence context must be an object")
    if not isinstance(requests, list):
        raise PcapEvidenceQueryError("pcap_query_requests must be an array")
    if len(requests) > MAX_QUERY_REQUESTS:
        raise PcapEvidenceQueryError(f"at most {MAX_QUERY_REQUESTS} PCAP evidence queries are allowed")
    evidence = pcap_context.get("parsed_evidence") if isinstance(pcap_context.get("parsed_evidence"), list) else []
    executed: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for raw in requests:
        if not isinstance(raw, dict):
            raise PcapEvidenceQueryError("each PCAP evidence query must be an object")
        operation = str(raw.get("operation") or "").strip().lower()
        if operation not in QUERY_PATHS:
            raise PcapEvidenceQueryError(f"unsupported PCAP evidence operation: {operation or 'missing'}")
        unknown = set(raw).difference({"operation", "indicator", "filters", "limit"})
        if unknown:
            raise PcapEvidenceQueryError(
                f"unsupported PCAP evidence query fields: {', '.join(sorted(str(item) for item in unknown))}"
            )
        indicator = ""
        if raw.get("indicator") not in (None, ""):
            indicator = _text(raw.get("indicator"), "indicator", 253)
        filters = _normalize_filters(operation, raw.get("filters"))
        limit = _integer(raw.get("limit", 10), "limit", 1, MAX_QUERY_LIMIT)

        candidates, source_views, scan_truncated = _query_candidates(evidence, operation)
        found: list[Any] = []
        seen: set[str] = set()
        matched = 0
        for candidate in candidates:
            if not _matches_indicator(candidate, indicator):
                continue
            if not all(_filter_matches(candidate, field, expected) for field, expected in filters.items()):
                continue
            sanitized = _project_record(operation, candidate)
            if sanitized in ({}, [], None, ""):
                continue
            fingerprint = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            matched += 1
            if len(found) < limit:
                found.append(sanitized)

        request = {"operation": operation, "filters": filters, "indicator": indicator, "limit": limit}
        query_digest = hashlib.sha256(
            json.dumps(
                {"contract": QUERY_CONTRACT, "request": request},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        result_digest = hashlib.sha256(
            json.dumps(found, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        executed.append(request)
        results.append(
            {
                "query": request,
                "query_digest": query_digest,
                "result_digest": result_digest,
                "evidence_ref": f"derived-pcap-zeek:{query_digest[:20]}",
                "records": found,
                "audit": {
                    "candidate_records_scanned": len(candidates),
                    "unique_records_matched": matched,
                    "records_returned": len(found),
                    "result_truncated": matched > len(found),
                    "index_scan_truncated": scan_truncated,
                    "derived_views_considered": source_views,
                    "time_filter_requires_timestamped_record": bool(
                        {"start_epoch", "end_epoch"}.intersection(filters)
                    ),
                },
            }
        )
    payload = {
        "schema": QUERY_CONTRACT,
        "executed": executed,
        "results": results,
        "source": "sanitized-derived-pcap-evidence",
        "provenance": {
            "raw_pcap_access": False,
            "raw_payloads_included": False,
            "parser_or_shell_invocation": False,
            "network_access": False,
            "evidence_scope": "bounded-derived-index; sampled or aggregated records are investigative leads, not completeness proof",
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_QUERY_RESULT_BYTES:
        raise PcapEvidenceQueryError("PCAP evidence query result exceeded its output budget")
    return payload
