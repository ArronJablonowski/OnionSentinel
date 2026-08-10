#!/usr/bin/env python3
"""Typed, allowlisted pivots over sanitized, derived PCAP evidence.

The investigation runtime may ask for a narrower view of facts already
produced by Zeek or TShark. Model text is never translated into a display
filter, script, command, parser argument, path, regular expression, or raw
packet access. Every request is a small declarative object whose fields are
validated here and compared in Python against a bounded local evidence index.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from pcap_analysis_core import sanitize_evidence_text, sanitize_evidence_value
import pcap_evidence_query_matching as _matching
import pcap_evidence_query_projection as _projection
import pcap_evidence_query_response as _response
import pcap_evidence_query_selection as _selection
import pcap_evidence_query_validation as _validation


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
    return _selection.nested(record, path)


def _text(value: Any, field: str, max_chars: int = MAX_REQUEST_TEXT_CHARS) -> str:
    return _validation.text_filter(
        value,
        field,
        max_chars,
        control_pattern=CONTROL_OR_ESCAPE,
        error=PcapEvidenceQueryError,
    )


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    return _validation.integer_filter(
        value,
        field,
        minimum,
        maximum,
        error=PcapEvidenceQueryError,
    )


def _epoch(value: Any, field: str) -> float:
    return _validation.epoch_filter(
        value,
        field,
        error=PcapEvidenceQueryError,
    )


def _normalize_filters(operation: str, raw: Any) -> dict[str, Any]:
    return _validation.normalize_filters(
        operation,
        raw,
        filters_by_operation=FILTERS_BY_OPERATION,
        ip_filters=IP_FILTERS,
        integer_ranges=INTEGER_FILTER_RANGES,
        time_filters=TIME_FILTERS,
        boolean_filters=BOOLEAN_FILTERS,
        parse_text=_text,
        parse_integer=_integer,
        parse_epoch=_epoch,
        max_text_chars=MAX_REQUEST_TEXT_CHARS,
        error=PcapEvidenceQueryError,
    )


def _iter_scalars(value: Any):
    return _matching.iter_scalars(value)


def _field_values(value: Any, aliases: set[str]) -> list[Any]:
    return _matching.field_values(value, aliases)


def _equals(candidate: Any, expected: Any) -> bool:
    return _matching.equals(
        candidate,
        expected,
        sanitize_text=sanitize_evidence_text,
        max_text_chars=MAX_REQUEST_TEXT_CHARS,
    )


def _numeric_values(candidate: Any, field: str) -> list[float]:
    return _matching.numeric_values(
        candidate,
        field,
        aliases=FILTER_FIELD_ALIASES,
    )


def _filter_matches(candidate: Any, field: str, expected: Any) -> bool:
    return _matching.filter_matches(
        candidate,
        field,
        expected,
        ip_filters=IP_FILTERS,
        aliases=FILTER_FIELD_ALIASES,
        compare=_equals,
        numeric=_numeric_values,
        sanitize_text=sanitize_evidence_text,
        max_text_chars=MAX_REQUEST_TEXT_CHARS,
    )


def _matches_indicator(value: Any, indicator: str) -> bool:
    return _matching.matches_indicator(
        value,
        indicator,
        sanitize_text=sanitize_evidence_text,
        max_text_chars=MAX_REQUEST_TEXT_CHARS,
    )


def _scrub_nested(value: Any, container: str = "") -> Any:
    """Defend in depth against raw/parser fields inside an approved container."""
    return _projection.scrub_nested(
        value,
        container,
        nested_output_fields=NESTED_OUTPUT_FIELDS,
        forbidden=_forbidden_output_key,
        sanitize_text=sanitize_evidence_text,
        sanitize_value=sanitize_evidence_value,
    )


def _forbidden_output_key(key: Any) -> bool:
    return _projection.forbidden_output_key(key, FORBIDDEN_OUTPUT_KEYS)


def _project_coverage(value: Any) -> Any:
    """Keep coverage telemetry without trusting arbitrary coverage keys."""
    return _projection.project_coverage(
        value,
        scalar_fields=COVERAGE_SCALAR_FIELDS,
        sanitize_text=sanitize_evidence_text,
        sanitize_value=sanitize_evidence_value,
    )


def _project_record(operation: str, candidate: Any) -> Any:
    return _projection.project_record(
        operation,
        candidate,
        output_fields=OUTPUT_FIELDS_BY_OPERATION,
        project_coverage_record=_project_coverage,
        scrub=_scrub_nested,
        forbidden=_forbidden_output_key,
        sanitize_text=sanitize_evidence_text,
    )


def _query_candidates(
    evidence: list[Any],
    operation: str,
) -> tuple[list[Any], list[str], bool]:
    return _selection.query_candidates(
        evidence,
        operation,
        query_paths=QUERY_PATHS,
        max_scan_records=MAX_QUERY_SCAN_RECORDS,
    )


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
        request = _normalize_request(raw)
        executed.append(request)
        results.append(_execute_request(evidence, request))
    return _response.compose_payload(
        contract=QUERY_CONTRACT,
        executed=executed,
        results=results,
        max_result_bytes=MAX_QUERY_RESULT_BYTES,
        error=PcapEvidenceQueryError,
    )


def _normalize_request(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PcapEvidenceQueryError(
            "each PCAP evidence query must be an object"
        )
    operation = str(raw.get("operation") or "").strip().lower()
    if operation not in QUERY_PATHS:
        raise PcapEvidenceQueryError(
            f"unsupported PCAP evidence operation: {operation or 'missing'}"
        )
    unknown = set(raw).difference(
        {"operation", "indicator", "filters", "limit"}
    )
    if unknown:
        fields = ", ".join(sorted(str(item) for item in unknown))
        raise PcapEvidenceQueryError(
            f"unsupported PCAP evidence query fields: {fields}"
        )
    indicator = ""
    if raw.get("indicator") not in (None, ""):
        indicator = _text(raw.get("indicator"), "indicator", 253)
    return {
        "operation": operation,
        "filters": _normalize_filters(operation, raw.get("filters")),
        "indicator": indicator,
        "limit": _integer(raw.get("limit", 10), "limit", 1, MAX_QUERY_LIMIT),
    }


def _execute_request(
    evidence: list[Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    candidates, source_views, scan_truncated = _query_candidates(
        evidence,
        request["operation"],
    )
    return _response.execute_request(
        request,
        candidates,
        source_views=source_views,
        scan_truncated=scan_truncated,
        contract=QUERY_CONTRACT,
        matches_indicator=_matches_indicator,
        filter_matches=_filter_matches,
        project_record=_project_record,
    )
