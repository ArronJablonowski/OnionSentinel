"""Declarative security policy for sanitized derived-PCAP pivots."""
from __future__ import annotations

import re


MAX_QUERY_REQUESTS = 4
MAX_QUERY_LIMIT = 20
MAX_QUERY_RESULT_BYTES = 32 * 1024
MAX_QUERY_SCAN_RECORDS = 4096
MAX_REQUEST_TEXT_CHARS = 512
QUERY_CONTRACT = "onion-sentinel-derived-pcap-pivots-v2"

# Fixed paths point only at derived JSON. Callers cannot supply a path.
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
    "source_ip", "destination_ip", "endpoint_ip", "source_port",
    "destination_port", "port", "transport", "protocol", "start_epoch",
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
    "packet_facts": FLOW_FILTERS | {
        "query", "answer", "rcode", "sni", "version", "host", "uri",
        "uri_prefix", "user_agent", "frame_length_min", "frame_length_max",
        "icmp_type", "icmp_code",
    },
    "packet_samples": FLOW_FILTERS | {
        "query", "answer", "rcode", "sni", "version", "host", "uri",
        "uri_prefix", "user_agent", "frame_length_min", "frame_length_max",
        "icmp_type", "icmp_code",
    },
    "icmp_facts": FLOW_FILTERS | {
        "family", "icmp_type", "icmp_code", "identifier", "sequence",
        "frame_length_min", "frame_length_max", "payload_length_min",
        "payload_length_max", "selected_scope_match",
    },
    "icmp_anomalies": FLOW_FILTERS | {
        "family", "icmp_type", "icmp_code", "identifier", "sequence",
        "frame_length_min", "frame_length_max", "payload_length_min",
        "payload_length_max", "selected_scope_match",
    },
    "user_agents": {"user_agent", "http_version"},
    "tls_versions": {"version", "version_source"},
    "geoip": {"ip", "country_iso_code", "asn"},
}

IP_FILTERS = {"source_ip", "destination_ip", "endpoint_ip", "ip"}
PORT_FILTERS = {"source_port", "destination_port", "port"}
INTEGER_FILTER_RANGES = {
    "source_port": (0, 65535), "destination_port": (0, 65535),
    "port": (0, 65535), "status_code": (0, 999), "icmp_type": (0, 255),
    "icmp_code": (0, 255), "identifier": (0, 2**32 - 1),
    "sequence": (0, 2**32 - 1), "frame_length_min": (0, 2**32 - 1),
    "frame_length_max": (0, 2**32 - 1), "payload_length_min": (0, 2**32 - 1),
    "payload_length_max": (0, 2**32 - 1), "asn": (0, 2**32 - 1),
}
BOOLEAN_FILTERS = {"established", "selected_scope_match"}
TIME_FILTERS = {"start_epoch", "end_epoch"}

FILTER_FIELD_ALIASES = {
    "source_ip": {"source_ip", "id.orig_h", "src"},
    "destination_ip": {"destination_ip", "id.resp_h", "dst"},
    "source_port": {"source_port", "id.orig_p"},
    "destination_port": {"destination_port", "id.resp_p"},
    "transport": {"transport", "proto"}, "protocol": {"protocol"},
    "service": {"service"},
    "connection_state": {"connection_state", "conn_state"},
    "query": {"query", "dns_query", "dns_queries"},
    "answer": {"answer", "dns_answers"}, "answer_type": {"answer_type"},
    "qtype": {"qtype", "qtype_name", "dns_qtype", "dns_qtypes", "dns_query_type"},
    "rcode": {"rcode", "rcode_name", "dns_rcode", "dns_rcodes"},
    "sni": {"sni", "server_name", "tls_sni"},
    "version": {"version", "tls_version", "tls_versions"},
    "version_source": {"version_source", "source"}, "cipher": {"cipher"},
    "established": {"established"}, "host": {"host", "http_host"},
    "uri": {"uri", "http_uri"}, "method": {"method"},
    "status_code": {"status_code"},
    "user_agent": {"user_agent", "http_user_agent", "http_user_agents"},
    "http_version": {"http_version"}, "mime_type": {"mime_type"},
    "filename": {"filename"}, "sha256": {"sha256"}, "note": {"note"},
    "message": {"message", "msg"}, "name": {"name"},
    "additional": {"additional", "addl"}, "family": {"family", "icmp_family"},
    "icmp_type": {"icmp_type", "type"}, "icmp_code": {"icmp_code", "code"},
    "identifier": {"identifier", "icmp_identifier"},
    "sequence": {"sequence", "icmp_sequence"},
    "frame_length_min": {"frame_length", "frame_bytes"},
    "frame_length_max": {"frame_length", "frame_bytes"},
    "payload_length_min": {"payload_length", "payload_bytes", "icmp_payload_length"},
    "payload_length_max": {"payload_length", "payload_bytes", "icmp_payload_length"},
    "selected_scope_match": {"selected_scope_match"}, "ip": {"ip"},
    "country_iso_code": {"country_iso_code"},
    "asn": {"asn", "autonomous_system_number"},
    "start_epoch": {"timestamp_epoch", "ts"},
    "end_epoch": {"timestamp_epoch", "ts"},
}

BASE_OUTPUT_FIELDS = {
    "source", "record_type", "count", "count_error_max", "timestamp_epoch",
    "ts", "frame_number", "frame_length", "frame_bytes", "source_ip",
    "destination_ip", "source_port", "destination_port", "transport", "protocol",
}
OUTPUT_FIELDS_BY_OPERATION = {
    "connections": BASE_OUTPUT_FIELDS | {
        "uid", "service", "duration", "orig_bytes", "resp_bytes",
        "connection_state", "history", "missed_bytes", "id.orig_h", "id.resp_h",
        "id.orig_p", "id.resp_p", "proto",
    },
    "dns": BASE_OUTPUT_FIELDS | {
        "uid", "query", "dns_query", "dns_queries", "qtype", "qtype_name",
        "dns_qtypes", "rcode", "rcode_name", "dns_rcodes", "answer",
        "answer_type", "dns_answers", "rejected",
    },
    "tls": BASE_OUTPUT_FIELDS | {
        "uid", "sni", "server_name", "tls_sni", "version", "tls_versions",
        "cipher", "curve", "resumed", "established", "next_protocol", "ja3", "ja3s",
    },
    "http": BASE_OUTPUT_FIELDS | {
        "uid", "method", "host", "http_host", "uri", "http_uri", "referrer",
        "version", "user_agent", "http_user_agents", "request_body_len",
        "response_body_len", "status_code", "status_message",
    },
    "files": BASE_OUTPUT_FIELDS | {
        "uid", "fuid", "source_name", "mime_type", "filename", "seen_bytes",
        "total_bytes", "missing_bytes", "overflow_bytes", "md5", "sha1", "sha256",
    },
    "notices": BASE_OUTPUT_FIELDS | {"uid", "note", "message", "sub", "dropped"},
    "weird": BASE_OUTPUT_FIELDS | {"uid", "name", "additional", "notice"},
    "protocols": {"count", "count_error_max", "protocol"},
    "packet_facts": BASE_OUTPUT_FIELDS | {
        "dns_query", "dns_queries", "dns_qtypes", "dns_rcodes", "dns_answers",
        "tls_sni", "tls_versions", "http_host", "http_uri", "http_user_agents",
        "icmp_family", "icmp_type", "icmp_code", "icmp_identifier", "icmp_sequence",
        "icmp_payload_length", "selected_scope_match", "scope_exclusion_reason",
    },
    "packet_samples": BASE_OUTPUT_FIELDS | {
        "dns_query", "dns_queries", "dns_qtypes", "dns_rcodes", "dns_answers",
        "tls_sni", "tls_versions", "http_host", "http_uri", "http_user_agents",
        "icmp_family", "icmp_type", "icmp_code", "icmp_identifier", "icmp_sequence",
        "icmp_payload_length", "selected_scope_match", "scope_exclusion_reason",
    },
    "icmp_facts": BASE_OUTPUT_FIELDS | {
        "family", "type", "code", "identifier", "sequence", "payload_length",
        "icmp_family", "icmp_type", "icmp_code", "icmp_identifier", "icmp_sequence",
        "icmp_payload_length", "selected_scope_match", "scope_exclusion_reason",
    },
    "icmp_anomalies": BASE_OUTPUT_FIELDS | {
        "family", "type", "code", "identifier", "sequence", "payload_length",
        "icmp_family", "icmp_type", "icmp_code", "icmp_identifier", "icmp_sequence",
        "icmp_payload_length", "selected_scope_match", "scope_exclusion_reason",
    },
    "user_agents": {"count", "count_error_max", "http_version", "user_agent"},
    "tls_versions": {"count", "count_error_max", "source", "version_source", "raw_version", "version"},
    "geoip": {
        "ip", "roles", "packet_observations", "continent", "country_iso_code",
        "country", "registered_country_iso_code", "subdivision", "city", "time_zone",
        "accuracy_radius_km", "latitude", "longitude", "autonomous_system_number",
        "autonomous_system_organization", "database_sources",
    },
}
FORBIDDEN_OUTPUT_KEYS = {
    "payload", "raw_payload", "data_payload", "raw_packet", "packet_bytes",
    "display_filter", "bpf_filter", "command", "commands", "script", "parser_args",
    "arguments", "stdout", "stderr", "path", "paths", "analysis_dir", "tool_paths",
}
NESTED_OUTPUT_FIELDS = {
    "dns_answers": {"answer_type", "answer"},
    "tls_versions": {"version_source", "raw_version", "version"},
    "http_user_agents": {"http_version", "user_agent"},
}
COVERAGE_SCALAR_FIELDS = {
    "total_records", "decoded_records", "undecoded_records", "decode_percent",
    "total_bytes", "first_timestamp_epoch", "last_timestamp_epoch", "duration_seconds",
    "malformed_records", "pcap_files_total", "pcap_files_processed",
    "records_aggregated", "complete", "ok",
}
CONTROL_OR_ESCAPE = re.compile(r"[\x00-\x1f\x7f\x1b]")

__all__ = (
    "MAX_QUERY_REQUESTS", "MAX_QUERY_LIMIT", "MAX_QUERY_RESULT_BYTES",
    "MAX_QUERY_SCAN_RECORDS", "MAX_REQUEST_TEXT_CHARS", "QUERY_CONTRACT",
    "QUERY_PATHS", "FLOW_FILTERS", "FILTERS_BY_OPERATION", "IP_FILTERS",
    "PORT_FILTERS", "INTEGER_FILTER_RANGES", "BOOLEAN_FILTERS", "TIME_FILTERS",
    "FILTER_FIELD_ALIASES", "BASE_OUTPUT_FIELDS", "OUTPUT_FIELDS_BY_OPERATION",
    "FORBIDDEN_OUTPUT_KEYS", "NESTED_OUTPUT_FIELDS", "COVERAGE_SCALAR_FIELDS",
    "CONTROL_OR_ESCAPE",
)
