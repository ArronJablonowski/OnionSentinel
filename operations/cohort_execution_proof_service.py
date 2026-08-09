#!/usr/bin/env python3
"""Build one sealed cohort execution proof from a fresh result and trace."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

from cohort_execution_models import ModelExecutionPolicy, evaluate_model_execution
from cohort_execution_render import ExecutionProofView, render_execution_proof
from cohort_execution_result import ResultExecutionPolicy, evaluate_result_execution
from cohort_execution_skills import SkillAttestationPolicy, validate_skill_attestation
from cohort_execution_tools import evaluate_tool_execution
from cohort_execution_trace import (
    TraceExecutionExpectation,
    TraceExecutionPolicy,
    evaluate_trace_execution,
)


@dataclass(frozen=True)
class ExecutionProofPolicy:
    error: type[RuntimeError]
    parse_timestamp: Callable[[Any, str], Any]
    sha256_pattern: Pattern[str]
    skill_id_pattern: Pattern[str]
    maximum_selected_skills: int
    model_call_contract_schema: str
    maximum_model_calls: int
    sha256_value: Callable[[Any], str]


@dataclass(frozen=True)
class _TraceSections:
    trace_report: Mapping[str, Any]
    trace: Mapping[str, Any]
    routes: Mapping[str, Any]
    tools: Mapping[str, Any]
    models: Mapping[str, Any]
    reviewer: Mapping[str, Any]
    model_call_contract: Mapping[str, Any]
    skill_attestation: Mapping[str, Any]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _load_trace(
    database_path: Path,
    analysis_id: str,
    load_trace_evaluator: Callable[[], Any],
    error: type[RuntimeError],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    evaluator = load_trace_evaluator()
    try:
        report = evaluator.evaluate_database(database_path, analysis_id)
    except Exception as exc:
        raise error(
            f"harness trace evaluation failed for {analysis_id}: "
            f"{type(exc).__name__}"
        ) from exc
    runs = report.get("runs") if isinstance(report, dict) else None
    if not isinstance(runs, list) or len(runs) != 1:
        raise error(f"harness trace for {analysis_id} is not exactly one run")
    trace = runs[0]
    if not isinstance(trace, dict):
        raise error(f"harness trace for {analysis_id} is malformed")
    return report, trace


def _trace_sections(
    database_path: Path,
    analysis_id: str,
    load_trace_evaluator: Callable[[], Any],
    error: type[RuntimeError],
) -> _TraceSections:
    report, trace = _load_trace(
        database_path, analysis_id, load_trace_evaluator, error
    )
    models = _mapping(trace.get("models"))
    return _TraceSections(
        trace_report=report,
        trace=trace,
        routes=_mapping(models.get("route_consistency")),
        tools=_mapping(trace.get("tools")),
        models=models,
        reviewer=_mapping(trace.get("reviewer")),
        model_call_contract=_mapping(models.get("model_call_contract")),
        skill_attestation=_mapping(trace.get("skill_selection_attestation")),
    )


def _skill_summary(
    sections: _TraceSections,
    failures: list[str],
    policy: ExecutionProofPolicy,
) -> Mapping[str, Any]:
    summary, valid = validate_skill_attestation(
        sections.skill_attestation,
        SkillAttestationPolicy(
            skill_id_pattern=policy.skill_id_pattern,
            sha256_pattern=policy.sha256_pattern,
            maximum_selected=policy.maximum_selected_skills,
        ),
    )
    if not valid:
        failures.append("harness-skill-selection-attestation-invalid")
    return summary


def _trace_execution(
    result: Any,
    sections: _TraceSections,
    member: Mapping[str, Any],
    expected_task_kind: Callable[[str, str], str],
    policy: ExecutionProofPolicy,
) -> Any:
    dispatch_kind = str(result.dispatch.get("kind") or "")
    expectation = TraceExecutionExpectation(
        analysis_id=result.analysis_id,
        role=result.role,
        task_kind=expected_task_kind(result.role, dispatch_kind),
        stable_group_id=str(member.get("stable_group_id") or ""),
        representative_alert_id=str(member.get("representative_alert_id") or ""),
        harness_mode=str(result.contract.get("harness_mode") or ""),
        assigned_route=result.expected_route,
        reviewer_route=result.expected_reviewer_route,
    )
    return evaluate_trace_execution(
        sections.trace_report,
        sections.trace,
        sections.models,
        result.analysis,
        expectation,
        TraceExecutionPolicy(
            timestamp_error=policy.error,
            parse_timestamp=policy.parse_timestamp,
            sha256_pattern=policy.sha256_pattern,
        ),
        dispatch_started=result.dispatch_started,
        analysis_generated=result.analysis_generated,
    )


def _model_execution(
    result: Any,
    sections: _TraceSections,
    policy: ExecutionProofPolicy,
) -> Any:
    return evaluate_model_execution(
        sections.trace,
        sections.models,
        sections.reviewer,
        sections.model_call_contract,
        reviewer_required=result.contract.get("reviewer_required") is True,
        policy=ModelExecutionPolicy(
            contract_schema=policy.model_call_contract_schema,
            maximum_model_calls=policy.maximum_model_calls,
            sha256_value=policy.sha256_value,
        ),
    )


def _tool_execution(
    result: Any,
    sections: _TraceSections,
    query_audit_binding: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    policy: ExecutionProofPolicy,
) -> Any:
    return evaluate_tool_execution(
        sections.trace,
        sections.routes,
        sections.tools,
        query_audit_binding(result.analysis),
        role=result.role,
        sha256_value=policy.sha256_value,
    )


def _render_proof(
    result: Any,
    sections: _TraceSections,
    trace_execution: Any,
    skill_summary: Mapping[str, Any],
    model_execution: Any,
    tool_execution: Any,
    policy: ExecutionProofPolicy,
) -> dict[str, Any]:
    view = ExecutionProofView(
        analysis_id=result.analysis_id,
        analysis_generated_at=str(result.analysis.get("generated_at") or ""),
        release_id=str(result.contract.get("expected_release_id") or ""),
        role=result.role,
        trace=sections.trace,
        integrity=trace_execution.integrity,
        skill_selection=skill_summary,
        model_execution=model_execution,
        tool_execution=tool_execution,
        submitted_response_sha256=trace_execution.submitted_response_sha256,
        response_canonical_sha256=trace_execution.canonical_response_sha256,
    )
    return render_execution_proof(view, policy.sha256_value)


def _require_success(
    analysis_id: str,
    failures: list[str],
    error: type[RuntimeError],
) -> None:
    if failures:
        raise error(
            f"execution gate failed for {analysis_id}: "
            + ", ".join(sorted(set(failures)))
        )


def build_execution_proof(
    *,
    harness_database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    monitor: Mapping[str, Any],
    load_trace_evaluator: Callable[[], Any],
    expected_task_kind: Callable[[str, str], str],
    query_audit_binding: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    policy: ExecutionProofPolicy,
) -> dict[str, Any]:
    """Fail closed unless one fresh result has one valid successful trace."""
    result = evaluate_result_execution(
        manifest,
        member,
        monitor,
        ResultExecutionPolicy(
            cohort_error=policy.error,
            parse_timestamp=policy.parse_timestamp,
        ),
    )
    failures = list(result.failures)
    sections = _trace_sections(
        harness_database_path,
        result.analysis_id,
        load_trace_evaluator,
        policy.error,
    )
    skill_summary = _skill_summary(sections, failures, policy)
    trace_execution = _trace_execution(
        result, sections, member, expected_task_kind, policy
    )
    failures.extend(trace_execution.failures)
    model_execution = _model_execution(result, sections, policy)
    failures.extend(model_execution.failures)
    tool_execution = _tool_execution(
        result, sections, query_audit_binding, policy
    )
    failures.extend(tool_execution.failures)
    _require_success(result.analysis_id, failures, policy.error)
    return _render_proof(
        result,
        sections,
        trace_execution,
        skill_summary,
        model_execution,
        tool_execution,
        policy,
    )
