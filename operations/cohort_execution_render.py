#!/usr/bin/env python3
"""Canonical public rendering for a validated cohort execution proof."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from cohort_execution_models import ModelExecutionEvidence
from cohort_execution_tools import ToolExecutionEvidence


@dataclass(frozen=True)
class ExecutionProofView:
    analysis_id: str
    analysis_generated_at: str
    release_id: str
    role: str
    trace: Mapping[str, Any]
    integrity: Mapping[str, Any]
    skill_selection: Mapping[str, Any]
    model_execution: ModelExecutionEvidence
    tool_execution: ToolExecutionEvidence
    submitted_response_sha256: str
    response_canonical_sha256: str


def _text(source: Mapping[str, Any], field: str) -> str:
    value = source.get(field)
    return str(value) if value is not None else ""


def _model_projection(view: ExecutionProofView) -> dict[str, Any]:
    evidence = view.model_execution
    return {
        "model_call_count": evidence.model_call_count,
        "successful_model_call_count": evidence.successful_model_call_count,
        "successful_primary_model_call_count": int(
            (view.trace.get("models") or {}).get("successful_primary_call_count")
            or 0
        ),
        "model_purpose_count": evidence.model_purpose_count,
        "terminally_successful_model_purpose_count": (
            evidence.terminally_successful_model_purpose_count
        ),
        "incomplete_model_purpose_count": evidence.incomplete_model_purpose_count,
        "exact_reviewer_repair_count": evidence.exact_reviewer_repair_count,
        "exact_adjudication_repair_count": evidence.exact_adjudication_repair_count,
        "superseded_validation_failure_count": (
            evidence.superseded_validation_failure_count
        ),
        "unexpected_unsuccessful_model_call_count": (
            evidence.unexpected_unsuccessful_model_call_count
        ),
        "malformed_model_purpose_sequence_count": (
            evidence.malformed_model_purpose_sequence_count
        ),
        "model_call_contract": evidence.model_call_contract,
        "reviewer_completion": evidence.reviewer_completion,
    }


def _tool_projection(view: ExecutionProofView) -> dict[str, Any]:
    evidence = view.tool_execution
    return {
        "route_authorization_failure_count": 0,
        "route_identity_mismatch_count": 0,
        "tool_call_count": evidence.tool_call_count,
        "successful_tool_call_count": evidence.successful_tool_call_count,
        "read_only_tool_call_count": evidence.read_only_tool_call_count,
        "read_only_violation_count": 0,
        "successful_read_only_tool_call_bindings": evidence.trace_bindings,
        "successful_read_only_tool_call_bindings_sha256": (
            evidence.trace_binding_digest
        ),
        "query_audit": evidence.query_audit,
    }


def _harness_projection(view: ExecutionProofView) -> dict[str, Any]:
    trace = view.trace
    integrity = view.integrity
    return {
        "run_id": view.analysis_id,
        "trace_id": _text(trace, "trace_id"),
        "stable_group_id": _text(trace, "correlation_id"),
        "representative_alert_id": _text(trace, "alert_id"),
        "status": "succeeded",
        "stage": "complete",
        "role": view.role,
        "task_kind": _text(trace, "task_kind"),
        "policy_mode": _text(trace, "policy_mode"),
        "assigned_route": _text(trace, "assigned_route"),
        "assigned_reviewer_route": _text(trace, "assigned_reviewer_route"),
        "started_at": _text(trace, "started_at"),
        "completed_at": _text(trace, "completed_at"),
        "chain_valid": True,
        "chain_head_sha256": _text(integrity, "head_sha256"),
        "ledger_manifest_bound": True,
        "ledger_manifest_schema": _text(integrity, "ledger_manifest_schema"),
        "skill_selection_attestation_validated": True,
        "skill_selection_attestation": dict(view.skill_selection),
        **_model_projection(view),
        **_tool_projection(view),
        "memory_frozen": True,
        "submitted_response_sha256": view.submitted_response_sha256,
        "response_canonical_sha256": view.response_canonical_sha256,
    }


def render_execution_proof(
    view: ExecutionProofView,
    sha256_value: Callable[[Any], str],
) -> dict[str, Any]:
    proof = {
        "status": "passed",
        "fresh_analysis": True,
        "dispatch_accepted_once": True,
        "analysis_id": view.analysis_id,
        "analysis_generated_at": view.analysis_generated_at,
        "release_id": view.release_id,
        "harness": _harness_projection(view),
    }
    proof["proof_sha256"] = sha256_value(proof)
    return proof
