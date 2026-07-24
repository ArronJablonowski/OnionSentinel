#!/usr/bin/env python3
"""Allowlisted follow-up queries over sanitized, derived PCAP evidence.

The analyst can ask for a narrower view of evidence already produced by Zeek
or TShark.  It cannot submit display filters, paths, shell text, or commands,
so model output never becomes executable parser input.
"""
from __future__ import annotations

import json
from typing import Any

from pcap_analysis_core import sanitize_evidence_text, sanitize_evidence_value


MAX_QUERY_REQUESTS = 4
MAX_QUERY_LIMIT = 20
MAX_QUERY_RESULT_BYTES = 32 * 1024
QUERY_PATHS = {
    "coverage": (("coverage",), ("zeek", "coverage"), ("tshark", "coverage")),
    "connections": (
        ("_local_query_index", "connections"),
        ("zeek", "_local_query_index", "connections"),
        ("tshark", "_local_query_index", "connections"),
        ("zeek", "top_connections"),
        ("tshark", "top_conversations"),
    ),
    "dns": (
        ("_local_query_index", "dns"),
        ("zeek", "_local_query_index", "dns"),
        ("tshark", "_local_query_index", "dns"),
        ("zeek", "dns_queries"),
        ("tshark", "dns_activity", "query_names"),
    ),
    "tls": (("_local_query_index", "tls"), ("zeek", "_local_query_index", "tls"), ("zeek", "tls_sni")),
    "http": (("_local_query_index", "http"), ("zeek", "_local_query_index", "http"), ("zeek", "http_hosts")),
    "files": (("_local_query_index", "files"), ("zeek", "_local_query_index", "files"), ("zeek", "files")),
    "notices": (("_local_query_index", "notices"), ("zeek", "_local_query_index", "notices"), ("zeek", "notices")),
    "weird": (("_local_query_index", "weird"), ("zeek", "_local_query_index", "weird"), ("zeek", "weird")),
    "protocols": (("_local_query_index", "protocols"), ("tshark", "_local_query_index", "protocols"), ("tshark", "protocol_counts")),
    "packet_samples": (("_local_query_index", "packet_samples"), ("tshark", "_local_query_index", "packet_samples"), ("tshark", "packet_samples")),
    "icmp_anomalies": (
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
    "geoip": (("_local_query_index", "geoip"), ("tshark", "_local_query_index", "geoip"), ("tshark", "geoip", "records")),
}


class PcapEvidenceQueryError(ValueError):
    """The requested operation violated the derived-evidence query contract."""


def _nested(record: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = record
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _matches_indicator(value: Any, indicator: str) -> bool:
    if not indicator:
        return True
    if isinstance(value, dict):
        return any(_matches_indicator(item, indicator) for item in value.values())
    if isinstance(value, list):
        return any(_matches_indicator(item, indicator) for item in value)
    return sanitize_evidence_text(value, 512).casefold() == indicator.casefold()


def query_derived_pcap_evidence(pcap_context: dict[str, Any], requests: Any) -> dict[str, Any]:
    """Execute validated read-only queries and return bounded audit metadata."""
    if requests in (None, ""):
        return {"executed": [], "results": []}
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
        unknown = set(raw).difference({"operation", "indicator", "limit"})
        if unknown:
            raise PcapEvidenceQueryError(f"unsupported PCAP evidence query fields: {', '.join(sorted(unknown))}")
        indicator = sanitize_evidence_text(raw.get("indicator"), 253)
        try:
            limit = int(raw.get("limit", 10))
        except (TypeError, ValueError) as exc:
            raise PcapEvidenceQueryError("PCAP evidence query limit must be an integer") from exc
        if limit < 1 or limit > MAX_QUERY_LIMIT:
            raise PcapEvidenceQueryError(f"PCAP evidence query limit must be 1-{MAX_QUERY_LIMIT}")
        found: list[Any] = []
        seen: set[str] = set()
        for item in evidence:
            if not isinstance(item, dict):
                continue
            for path in QUERY_PATHS[operation]:
                value = _nested(item, path)
                candidates = value if isinstance(value, list) else [value] if value is not None else []
                for candidate in candidates:
                    if _matches_indicator(candidate, indicator):
                        sanitized = sanitize_evidence_value(candidate, max_chars=512, max_items=64)
                        fingerprint = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str)
                        if fingerprint in seen:
                            continue
                        seen.add(fingerprint)
                        found.append(sanitized)
                        if len(found) >= limit:
                            break
                if len(found) >= limit:
                    break
            if len(found) >= limit:
                break
        request = {"operation": operation, "indicator": indicator, "limit": limit}
        executed.append(request)
        results.append({"query": request, "records": found})
    payload = {"executed": executed, "results": results, "source": "sanitized-derived-pcap-evidence"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_QUERY_RESULT_BYTES:
        raise PcapEvidenceQueryError("PCAP evidence query result exceeded its output budget")
    return payload
