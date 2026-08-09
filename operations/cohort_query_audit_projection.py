#!/usr/bin/env python3
"""Project bounded query-audit metadata without query text or result rows."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


AUDIT_KEYS = (
    "_incident_query_audit",
    "_incident_osquery_audit",
    "_incident_live_osquery_audit",
    "_incident_pcap_audit",
    "_incident_zeek_audit",
    "_investigation_query_audit",
)
QUERY_FIELDS = (
    "pack",
    "query_id",
    "backend",
    "dialect",
    "target_alias",
    "status",
    "query_digest",
    "request_digest",
    "result_digest",
    "evidence_ref",
    "total_hits",
    "returned_hits",
    "total_rows",
    "returned_rows",
    "truncated",
    "partial",
)
TRUSTED_QUERY_FIELDS = tuple(field for field in QUERY_FIELDS if field != "target_alias")
ROUND_RESULT_FIELDS = ("query_id", "backend", "status", "query_digest")
TOOL_BINDING_FIELDS = (
    "call_id",
    "round_number",
    "query_id",
    "backend",
    "status",
    "request_digest",
    "result_digest",
    "read_only",
)
AUDIT_FIELDS = (
    "trusted_source",
    "read_only",
    "complete",
    "partial",
    "query_contract",
    "provider_neutral",
    "rounds_completed",
    "queries_admitted",
    "successful_read_only_queries",
    "planning_retry_attempted",
    "planning_retry_produced_requests",
    "all_tool_call_bindings_read_only",
    "evaluation_requirement_satisfied",
)
SCALAR_TYPES = (str, int, float, bool, type(None))
MAX_RECORDS = 500
MAX_ROUNDS = 10


def _safe_record(
    value: Mapping[str, Any], fields: Sequence[str]
) -> dict[str, Any]:
    return {
        field: value.get(field)
        for field in fields
        if isinstance(value.get(field), SCALAR_TYPES)
    }


def _safe_records(value: Any, fields: Sequence[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [_safe_record(item, fields) for item in value if isinstance(item, dict)]


def _round_metadata(
    audit: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    queries: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    fallback_bindings: list[dict[str, Any]] = []
    rounds = audit.get("rounds") if isinstance(audit.get("rounds"), list) else []
    for item in rounds[:MAX_ROUNDS]:
        if not isinstance(item, dict):
            continue
        queries.extend(_safe_records(item.get("trusted_queries"), TRUSTED_QUERY_FIELDS))
        results.extend(_safe_records(item.get("results"), ROUND_RESULT_FIELDS))
        fallback_bindings.extend(
            binding
            for binding in (
                item.get("tool_call_bindings")
                if isinstance(item.get("tool_call_bindings"), list)
                else []
            )
            if isinstance(binding, dict)
        )
    raw_bindings = (
        audit.get("tool_call_bindings")
        if isinstance(audit.get("tool_call_bindings"), list)
        else fallback_bindings
    )
    return queries, results, _safe_records(raw_bindings, TOOL_BINDING_FIELDS)


def project_query_audit(response: Mapping[str, Any]) -> dict[str, Any]:
    """Return coverage/provenance metadata and exclude sensitive query content."""
    output: dict[str, Any] = {}
    for key in AUDIT_KEYS:
        audit = response.get(key)
        if not isinstance(audit, dict):
            continue
        queries = _safe_records(audit.get("queries"), QUERY_FIELDS)[:MAX_RECORDS]
        round_results: list[dict[str, Any]] = []
        tool_bindings: list[dict[str, Any]] = []
        if key == "_investigation_query_audit":
            round_queries, round_results, tool_bindings = _round_metadata(audit)
            queries.extend(round_queries)
        projected = _safe_record(audit, AUDIT_FIELDS)
        projected["queries"] = queries[:MAX_RECORDS]
        if key == "_investigation_query_audit":
            projected["round_results"] = round_results[:MAX_RECORDS]
            projected["tool_call_bindings"] = tool_bindings[:MAX_RECORDS]
        output[key] = projected
    return output
