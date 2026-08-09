#!/usr/bin/env python3
"""Route, tool-ledger, and query-audit evidence for cohort proof gates."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


ROUTE_FAILURE_FIELDS = (
    "authorization_failure_count",
    "authorization_denied_event_count",
    "authorization_malformed_event_count",
    "authorization_orphan_event_count",
    "authorization_unverified_call_count",
    "observation_denied_event_count",
    "observation_malformed_event_count",
    "observation_orphan_event_count",
    "identity_mismatch_count",
    "identity_unverified_call_count",
)


@dataclass(frozen=True)
class ToolExecutionEvidence:
    tool_call_count: int
    successful_tool_call_count: int
    read_only_tool_call_count: int
    trace_bindings: list[dict[str, Any]] | Any
    trace_binding_digest: str
    query_audit: Mapping[str, Any]
    failures: tuple[str, ...]


def _integer(source: Mapping[str, Any], field: str) -> int:
    return int(source.get(field) or 0)


def _route_failures(routes: Mapping[str, Any]) -> list[str]:
    failures = [
        f"harness-route-{field}"
        for field in ROUTE_FAILURE_FIELDS
        if _integer(routes, field)
    ]
    if routes.get("contract_available") is not True:
        failures.append("harness-route-contract-unavailable")
    return failures


def _tool_ledger_failures(
    tool_calls: int,
    successful_calls: int,
    read_only_calls: int,
    tools: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    if tool_calls < 1:
        failures.append("harness-tool-call-ledger-missing")
    if successful_calls < 1:
        failures.append("harness-successful-tool-call-missing")
    if read_only_calls != tool_calls:
        failures.append("harness-read-only-tool-ledger-incomplete")
    if _integer(tools, "read_only_violation_count"):
        failures.append("harness-non-read-only-tool-call")
    return failures


def _collector_query_failures(
    role: str,
    audit: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    if (
        int(audit["queried_section_count"]) > 0
        and audit["read_only_verified"] is not True
    ):
        failures.append("collector-query-audit-not-read-only")
    incident_query_valid = (
        int(audit["security_onion_query_count"]) >= 1
        and audit["security_onion_read_only"] is True
    )
    if role == "incident-responder" and not incident_query_valid:
        failures.append("incident-security-onion-query-audit-missing-or-unverified")
    return failures


def _dynamic_query_valid(
    audit: Mapping[str, Any],
    bindings: Any,
) -> bool:
    checks = (
        audit["dynamic_read_only"] is True,
        audit["dynamic_all_tool_call_bindings_read_only"] is True,
        audit["dynamic_evaluation_requirement_satisfied"] is True,
        int(audit["dynamic_successful_read_only_queries"]) >= 1,
        int(audit["dynamic_query_count"]) >= 1,
        int(audit["dynamic_tool_call_binding_count"]) >= 1,
        int(audit["dynamic_invalid_tool_call_binding_count"]) == 0,
        int(audit["dynamic_duplicate_tool_call_binding_count"]) == 0,
        bool(bindings),
        int(audit["dynamic_successful_read_only_queries"]) == len(bindings),
    )
    return all(checks)


def _binding_valid(
    trace_bindings: Any,
    dynamic_bindings: Any,
    successful_calls: int,
    trace_digest: str,
    sha256_value: Callable[[Any], str],
) -> bool:
    checks = (
        isinstance(trace_bindings, list),
        trace_bindings == dynamic_bindings,
        len(dynamic_bindings) == successful_calls,
        trace_digest == sha256_value(dynamic_bindings),
    )
    return all(checks)


def evaluate_tool_execution(
    trace: Mapping[str, Any],
    routes: Mapping[str, Any],
    tools: Mapping[str, Any],
    query_audit: Mapping[str, Any],
    *,
    role: str,
    sha256_value: Callable[[Any], str],
) -> ToolExecutionEvidence:
    counts = trace.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    tool_calls = _integer(counts, "tool_calls")
    successful_calls = _integer(tools, "successful_call_count")
    read_only_calls = _integer(tools, "read_only_call_count")
    failures = _route_failures(routes)
    failures.extend(
        _tool_ledger_failures(
            tool_calls, successful_calls, read_only_calls, tools
        )
    )
    failures.extend(_collector_query_failures(role, query_audit))
    dynamic_bindings = query_audit["dynamic_successful_read_only_tool_bindings"]
    if not _dynamic_query_valid(query_audit, dynamic_bindings):
        failures.append("dynamic-query-audit-missing-or-incomplete")
    trace_bindings = tools.get("successful_read_only_call_bindings")
    trace_digest = str(
        tools.get("successful_read_only_call_bindings_sha256") or ""
    )
    if not _binding_valid(
        trace_bindings,
        dynamic_bindings,
        successful_calls,
        trace_digest,
        sha256_value,
    ):
        failures.append("dynamic-query-tool-ledger-binding-mismatch")
    return ToolExecutionEvidence(
        tool_call_count=tool_calls,
        successful_tool_call_count=successful_calls,
        read_only_tool_call_count=read_only_calls,
        trace_bindings=trace_bindings,
        trace_binding_digest=trace_digest,
        query_audit=query_audit,
        failures=tuple(failures),
    )
