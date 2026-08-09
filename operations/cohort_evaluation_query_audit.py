#!/usr/bin/env python3
"""Normalize content-free cohort query-audit and tool-binding proof."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class QueryAuditPolicy:
    successful_statuses: frozenset[str]
    sha256_pattern: Pattern[str]
    sha256_value: Callable[[Any], str]


@dataclass
class _BindingState:
    invalid: int = 0
    duplicate: int = 0
    seen_call_ids: set[str] | None = None
    successful_read_only: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        self.seen_call_ids = self.seen_call_ids or set()
        self.successful_read_only = self.successful_read_only or []


def query_audit_summary(analysis: Mapping[str, Any]) -> dict[str, Any]:
    """Project bounded read-only, partial, incomplete, and query counts."""
    query_audit = _audit_sections(analysis)
    section_count = explicit_non_read_only = partial = incomplete = query_count = 0
    for audit in query_audit.values():
        if not isinstance(audit, dict):
            continue
        section_count += 1
        explicit_non_read_only += int(audit.get("read_only") is False)
        partial += int(audit.get("partial") is True)
        incomplete += int(audit.get("complete") is False)
        queries = audit.get("queries")
        if isinstance(queries, list):
            query_count += len(queries)
            partial += sum(
                isinstance(query, dict) and query.get("partial") is True
                for query in queries
            )
    return {
        "audit_section_count": section_count,
        "query_count": query_count,
        "explicit_non_read_only_count": explicit_non_read_only,
        "partial_or_incomplete_count": partial + incomplete,
        "read_only_verified": section_count > 0 and explicit_non_read_only == 0,
    }


def query_audit_execution_binding(
    analysis: Mapping[str, Any], policy: QueryAuditPolicy
) -> dict[str, Any]:
    """Recompute the export's collector-owned query-provenance binding."""
    query_audit = _audit_sections(analysis)
    section_counts = _section_counts(query_audit)
    security_onion = _section(query_audit, "_incident_query_audit")
    dynamic = _section(query_audit, "_investigation_query_audit")
    raw_bindings = _list(dynamic.get("tool_call_bindings"))
    binding_state = _normalize_bindings(raw_bindings, policy)
    successful_queries = _integer_or_negative(
        dynamic.get("successful_read_only_queries")
    )
    return {
        "query_audit_sha256": policy.sha256_value(query_audit),
        **section_counts,
        "read_only_verified": (
            section_counts["queried_section_count"] > 0
            and section_counts["read_only_queried_section_count"]
            == section_counts["queried_section_count"]
        ),
        "security_onion_query_count": len(_list(security_onion.get("queries"))),
        "security_onion_read_only": security_onion.get("read_only") is True,
        "dynamic_query_count": len(_list(dynamic.get("queries"))),
        "dynamic_tool_call_binding_count": len(raw_bindings),
        "dynamic_invalid_tool_call_binding_count": binding_state.invalid,
        "dynamic_duplicate_tool_call_binding_count": binding_state.duplicate,
        "dynamic_read_only": dynamic.get("read_only") is True,
        "dynamic_complete": dynamic.get("complete") is True,
        "dynamic_all_tool_call_bindings_read_only": (
            dynamic.get("all_tool_call_bindings_read_only") is True
        ),
        "dynamic_evaluation_requirement_satisfied": (
            dynamic.get("evaluation_requirement_satisfied") is True
        ),
        "dynamic_successful_read_only_queries": successful_queries,
        "dynamic_successful_read_only_tool_bindings": binding_state.successful_read_only,
        "dynamic_successful_read_only_tool_bindings_sha256": policy.sha256_value(
            binding_state.successful_read_only
        ),
    }


def _audit_sections(analysis: Mapping[str, Any]) -> dict[str, Any]:
    value = analysis.get("query_audit")
    return value if isinstance(value, dict) else {}


def _section(query_audit: Mapping[str, Any], name: str) -> dict[str, Any]:
    value = query_audit.get(name)
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _section_counts(query_audit: Mapping[str, Any]) -> dict[str, int]:
    sections = [section for section in query_audit.values() if isinstance(section, dict)]
    query_lists = [_list(section.get("queries")) for section in sections]
    queried = [
        (section, queries)
        for section, queries in zip(sections, query_lists, strict=True)
        if queries
    ]
    return {
        "section_count": len(sections),
        "queried_section_count": len(queried),
        "query_count": sum(map(len, query_lists)),
        "read_only_queried_section_count": sum(
            section.get("read_only") is True for section, _queries in queried
        ),
    }


def _normalize_bindings(
    raw_bindings: list[Any], policy: QueryAuditPolicy
) -> _BindingState:
    state = _BindingState()
    for raw in raw_bindings:
        binding = _normalize_binding(raw, policy)
        if binding is None:
            state.invalid += 1
            continue
        call_id = binding["call_id"]
        if call_id in state.seen_call_ids:
            state.duplicate += 1
            continue
        state.seen_call_ids.add(call_id)
        if (
            binding["status"] in policy.successful_statuses
            and binding["read_only"] is True
        ):
            state.successful_read_only.append(binding)
    state.successful_read_only.sort(
        key=lambda item: (int(item["round_number"]), str(item["call_id"]))
    )
    return state


def _normalize_binding(
    raw: object, policy: QueryAuditPolicy
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    round_number = _integer_or_negative(raw.get("round_number"))
    binding = {
        "call_id": str(raw.get("call_id") or ""),
        "round_number": round_number,
        "query_id": str(raw.get("query_id") or ""),
        "backend": str(raw.get("backend") or ""),
        "status": str(raw.get("status") or "").strip().lower().replace("_", "-"),
        "request_digest": str(raw.get("request_digest") or ""),
        "result_digest": str(raw.get("result_digest") or ""),
        "read_only": raw.get("read_only"),
    }
    return binding if _binding_valid(binding, policy) else None


def _binding_valid(
    binding: Mapping[str, Any], policy: QueryAuditPolicy
) -> bool:
    round_number = binding["round_number"]
    query_id = binding["query_id"]
    return bool(
        round_number >= 1
        and query_id
        and binding["backend"]
        and binding["status"]
        and binding["call_id"] == f"round-{round_number}-{query_id}"[:128]
        and policy.sha256_pattern.fullmatch(binding["request_digest"]) is not None
        and policy.sha256_pattern.fullmatch(binding["result_digest"]) is not None
        and isinstance(binding["read_only"], bool)
    )


def _integer_or_negative(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return -1
