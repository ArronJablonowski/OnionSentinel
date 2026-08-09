#!/usr/bin/env python3
"""Validate bounded harness counters, query proof, and response digests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class HarnessGatePolicy:
    sha256_pattern: Pattern[str]
    hash_value: Callable[[Any], str]
    bounded_model_call_proof_valid: Callable[[Mapping[str, Any]], bool]


def _count(source: Mapping[str, Any], key: str) -> int:
    return int(source.get(key) or 0)


def _model_invariants_valid(
    harness: Mapping[str, Any],
    policy: HarnessGatePolicy,
) -> bool:
    purposes = _count(harness, "model_purpose_count")
    successful = _count(harness, "successful_model_call_count")
    repairs = _count(harness, "exact_reviewer_repair_count")
    superseded = _count(harness, "superseded_validation_failure_count")
    reviewer = harness.get("reviewer_completion")
    reviewer = reviewer if isinstance(reviewer, dict) else {}
    checks = (
        policy.bounded_model_call_proof_valid(harness),
        _count(harness, "successful_primary_model_call_count") >= 1,
        _count(reviewer, "model_call_count") >= 1,
        purposes >= 1,
        _count(harness, "terminally_successful_model_purpose_count") == purposes,
        _count(harness, "incomplete_model_purpose_count") == 0,
        successful == purposes,
        _count(harness, "model_call_count") == successful + superseded,
        repairs == superseded,
        repairs in {0, 1},
        _count(harness, "unexpected_unsuccessful_model_call_count") == 0,
        _count(harness, "malformed_model_purpose_sequence_count") == 0,
        _count(harness, "route_authorization_failure_count") == 0,
        _count(harness, "route_identity_mismatch_count") == 0,
    )
    return all(checks)


def _tool_ledger_valid(
    harness: Mapping[str, Any],
    audit: Mapping[str, Any],
    policy: HarnessGatePolicy,
) -> tuple[bool, list[Any]]:
    dynamic = audit["dynamic_successful_read_only_tool_bindings"]
    trace = harness.get("successful_read_only_tool_call_bindings")
    if not isinstance(dynamic, list) or not isinstance(trace, list):
        return False, []
    tool_calls = _count(harness, "tool_call_count")
    successful = _count(harness, "successful_tool_call_count")
    checks = (
        tool_calls >= 1,
        successful >= 1,
        _count(harness, "read_only_tool_call_count") == tool_calls,
        _count(harness, "read_only_violation_count") == 0,
        trace == dynamic,
        len(dynamic) == successful,
        str(harness.get("successful_read_only_tool_call_bindings_sha256") or "")
        == policy.hash_value(dynamic),
    )
    return all(checks), dynamic


def _query_audit_valid(
    audit: Mapping[str, Any],
    dynamic: list[Any],
    role: str,
) -> bool:
    queried_sections = int(audit["queried_section_count"])
    dynamic_successes = int(audit["dynamic_successful_read_only_queries"])
    checks = (
        queried_sections <= 0 or audit["read_only_verified"] is True,
        audit["dynamic_read_only"] is True,
        audit["dynamic_all_tool_call_bindings_read_only"] is True,
        audit["dynamic_evaluation_requirement_satisfied"] is True,
        dynamic_successes >= 1,
        int(audit["dynamic_query_count"]) >= 1,
        int(audit["dynamic_tool_call_binding_count"]) >= 1,
        int(audit["dynamic_invalid_tool_call_binding_count"]) == 0,
        int(audit["dynamic_duplicate_tool_call_binding_count"]) == 0,
        dynamic_successes == len(dynamic),
    )
    if role == "incident-responder":
        checks += (
            int(audit["security_onion_query_count"]) >= 1,
            audit["security_onion_read_only"] is True,
        )
    return all(checks)


def _digest_invariants_valid(
    harness: Mapping[str, Any],
    canonical_response_sha256: str,
    policy: HarnessGatePolicy,
) -> bool:
    submitted = str(harness.get("submitted_response_sha256") or "")
    response = str(harness.get("response_canonical_sha256") or "")
    chain_head = str(harness.get("chain_head_sha256") or "")
    return bool(
        policy.sha256_pattern.fullmatch(submitted)
        and response == canonical_response_sha256
        and policy.sha256_pattern.fullmatch(chain_head)
    )


def validate_harness_gate(
    *,
    harness: Mapping[str, Any],
    query_audit: Mapping[str, Any],
    role: str,
    canonical_response_sha256: str,
    label: str,
    policy: HarnessGatePolicy,
    error: type[RuntimeError],
) -> None:
    """Require the exact model, tool, query, route, and digest invariants."""
    tool_valid, dynamic = _tool_ledger_valid(harness, query_audit, policy)
    checks = (
        harness.get("chain_valid") is True,
        harness.get("ledger_manifest_bound") is True,
        harness.get("memory_frozen") is True,
        _model_invariants_valid(harness, policy),
        tool_valid,
        _query_audit_valid(query_audit, dynamic, role),
        _digest_invariants_valid(harness, canonical_response_sha256, policy),
    )
    if not all(checks):
        raise error(f"{label} harness trace/route/read-only/freeze gate failed")
