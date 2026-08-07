"""Evidence-source completeness scoring for Incident Responder conclusions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    is_incident_responder: Callable[[dict[str, Any] | None], bool]
    safe_nonnegative_int: Callable[[Any], int]
    success_statuses: frozenset[str]
    report_text_fields: frozenset[str]
    confidence_high_threshold: float


@dataclass
class Caps:
    maximum_score: float = 1.0
    reasons: list[str] = field(default_factory=list)

    def cap(self, value: float, reason: str) -> None:
        self.maximum_score = min(self.maximum_score, value)
        if reason not in self.reasons:
            self.reasons.append(reason)


def _report_validation(response: dict[str, Any], caps: Caps, deps: Dependencies) -> None:
    validation = response.get("_incident_response_report_validation")
    if not isinstance(validation, dict) or validation.get("valid"):
        return
    critical = set(validation.get("missing_fields") or []).intersection(
        deps.report_text_fields
    )
    invalid = set(validation.get("invalid_fields") or [])
    if not validation.get("model_report_present") or critical or "incident_response_report" in invalid:
        caps.cap(0.39, "required_incident_response_report_incomplete")
    else:
        caps.cap(0.69, "incident_response_report_schema_defect")


def _collector_result(result: Any, caps: Caps, deps: Dependencies) -> None:
    if not isinstance(result, dict):
        caps.cap(0.69, "incident_evidence_result_malformed")
        return
    if _collector_result_failed(result):
        caps.cap(0.69, "incident_evidence_query_failed_or_partial")
    shards = result.get("shards")
    if isinstance(shards, dict) and deps.safe_nonnegative_int(shards.get("failed")):
        caps.cap(0.69, "incident_evidence_failed_shards")
    if result.get("truncated") is True or _collector_projection_truncated(result, deps):
        caps.cap(0.79, "incident_evidence_query_truncated")


def _collector_result_failed(result: dict[str, Any]) -> bool:
    return (
        str(result.get("status") or "").strip().lower() != "ok"
        or result.get("semantic_valid") is False
        or result.get("timed_out") is True
    )


def _collector_projection_truncated(result: dict[str, Any], deps: Dependencies) -> bool:
    projection = result.get("prompt_projection")
    if not isinstance(projection, dict):
        return False
    return (
        projection.get("source_truncated") is True
        or deps.safe_nonnegative_int(projection.get("source_returned_hits"))
        > deps.safe_nonnegative_int(projection.get("retained_hits"))
    )


def _semantic_validity(semantic: Any, caps: Caps) -> None:
    if not isinstance(semantic, dict):
        return
    if semantic.get("controls_valid") is not True:
        caps.cap(0.39, "incident_evidence_controls_invalid")
    elif semantic.get("semantic_valid") is not True:
        caps.cap(0.69, "incident_evidence_semantically_incomplete")


def _security_onion_evidence(prompt_package: dict[str, Any], caps: Caps, deps: Dependencies) -> None:
    evidence = prompt_package.get("incident_response_evidence")
    if not isinstance(evidence, dict):
        caps.cap(0.39, "required_incident_evidence_missing")
        return
    coverage = str(evidence.get("coverage_note") or "").strip().lower()
    if any(marker in coverage for marker in ("bounded", "gap", "fallback")):
        caps.cap(0.79, "incident_evidence_temporal_coverage_limited")
    security_onion = evidence.get("security_onion_response")
    if not isinstance(security_onion, dict):
        caps.cap(0.39, "incident_evidence_response_missing")
        return
    if security_onion.get("complete") is not True or security_onion.get("partial") is True:
        caps.cap(0.69, "incident_evidence_partial")
    _semantic_validity(security_onion.get("semantic_validity"), caps)
    results = security_onion.get("results")
    for result in results if isinstance(results, list) else []:
        _collector_result(result, caps, deps)


def _unresolved_attempts(outcomes: Any, deps: Dependencies) -> int:
    if not isinstance(outcomes, dict):
        return 0
    if "unresolved_non_success_attempts" in outcomes:
        return deps.safe_nonnegative_int(outcomes.get("unresolved_non_success_attempts"))
    return sum(
        deps.safe_nonnegative_int(outcomes.get(key))
        for key in ("partial_queries", "rejected_queries", "error_queries", "timeout_queries")
    )


def _pivot_outcomes(outcomes: Any, unresolved: int, caps: Caps, deps: Dependencies) -> set[str]:
    if not isinstance(outcomes, dict):
        return set()
    if outcomes.get("zero_success") is True:
        caps.cap(0.69, "investigation_pivots_zero_success")
    elif unresolved or deps.safe_nonnegative_int(outcomes.get("unreported_queries")):
        caps.cap(0.79, "investigation_pivots_incomplete")
    values = outcomes.get("resolved_retry_query_ids")
    return {
        str(item).strip() for item in values if str(item).strip()
    } if isinstance(values, list) else set()


def _pivot_evidence_result(result: Any, caps: Caps) -> None:
    if not isinstance(result, dict):
        caps.cap(0.69, "investigation_pivot_result_malformed")
        return
    if (
        str(result.get("status") or "").strip().lower() != "ok"
        or result.get("semantic_valid") is False
    ):
        caps.cap(0.69, "investigation_pivot_failed_or_partial")
    if any(result.get(key) is True for key in (
        "truncated", "model_projection_truncated", "hits_prompt_truncated",
        "rows_prompt_truncated", "records_prompt_truncated",
    )):
        caps.cap(0.79, "investigation_pivot_evidence_truncated")


def _pivot_model_evidence(evidence: Any, caps: Caps) -> None:
    if not isinstance(evidence, dict):
        return
    if evidence.get("controls_valid") is False:
        caps.cap(0.39, "investigation_pivot_controls_invalid")
    if _pivot_evidence_partial(evidence):
        caps.cap(0.69, "investigation_pivot_evidence_partial")
    if _pivot_evidence_truncated(evidence):
        caps.cap(0.79, "investigation_pivot_evidence_truncated")
    results = evidence.get("results")
    for result in results if isinstance(results, list) else []:
        _pivot_evidence_result(result, caps)


def _pivot_evidence_partial(evidence: dict[str, Any]) -> bool:
    return (
        evidence.get("partial") is True
        or evidence.get("complete") is False
        or bool(evidence.get("evidence_gaps"))
    )


def _pivot_evidence_truncated(evidence: dict[str, Any]) -> bool:
    return (
        evidence.get("truncated") is True
        or evidence.get("model_projection_truncated") is True
        or evidence.get("prompt_projection") == "omitted_due_to_cumulative_byte_budget"
    )


def _pivot_status_limiter(status: str, unresolved: int, resolved_failure: bool, caps: Caps) -> None:
    if resolved_failure or not unresolved:
        return
    if status in {"partial", "error", "timeout", "output_limit"}:
        caps.cap(0.69, "investigation_pivot_failed_or_partial")
    elif status in {"rejected", "invalid_response"}:
        caps.cap(0.79, "investigation_pivot_rejected")


def _trusted_audit_truncated(result: dict[str, Any]) -> bool:
    trusted = result.get("trusted_query_audit")
    if not isinstance(trusted, list):
        return False
    return any(
        isinstance(item, dict)
        and any(item.get(key) is True for key in (
            "truncated", "result_truncated", "index_scan_truncated", "audit_truncated",
        ))
        for item in trusted
    )


def _pivot_result(
    result: Any,
    resolved_ids: set[str],
    unresolved: int,
    caps: Caps,
    deps: Dependencies,
) -> None:
    if not isinstance(result, dict):
        return
    status = str(result.get("status") or "").strip().lower()
    query_id = str(result.get("query_id") or "").strip()
    resolved_failure = bool(
        query_id and query_id in resolved_ids and status not in deps.success_statuses
    )
    _pivot_status_limiter(status, unresolved, resolved_failure, caps)
    _pivot_model_evidence(result.get("evidence"), caps)
    if _trusted_audit_truncated(result):
        caps.cap(0.79, "investigation_pivot_result_truncated")


def _iterative_evidence(prompt_package: dict[str, Any], caps: Caps, deps: Dependencies) -> None:
    iterative = prompt_package.get("investigation_query_results")
    if not isinstance(iterative, dict):
        return
    outcomes = iterative.get("outcomes")
    unresolved = _unresolved_attempts(outcomes, deps)
    resolved_ids = _pivot_outcomes(outcomes, unresolved, caps, deps)
    projection = iterative.get("prompt_projection")
    if isinstance(projection, dict) and projection.get("truncated") is True:
        caps.cap(0.79, "investigation_pivot_prompt_projection_truncated")
    rounds = iterative.get("rounds")
    for round_item in rounds if isinstance(rounds, list) else []:
        if not isinstance(round_item, dict):
            continue
        results = round_item.get("results")
        for result in results if isinstance(results, list) else []:
            _pivot_result(result, resolved_ids, unresolved, caps, deps)


def _live_osquery_evidence(prompt_package: dict[str, Any], caps: Caps) -> None:
    evidence = prompt_package.get("_live_osquery_evidence_accumulator")
    if not isinstance(evidence, dict):
        evidence = prompt_package.get("live_osquery_evidence")
    if not isinstance(evidence, dict):
        return
    if evidence.get("complete") is not True:
        caps.cap(0.69, "live_endpoint_osquery_incomplete")
    results = evidence.get("results")
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        if str(result.get("status") or "").strip().lower() != "ok":
            caps.cap(0.69, "live_endpoint_osquery_query_failed")
        if result.get("truncated") is True:
            caps.cap(0.79, "live_endpoint_osquery_result_truncated")


def apply(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Cap confidence when any required evidence source is incomplete."""
    if not deps.is_incident_responder(prompt_package):
        return response
    assert isinstance(prompt_package, dict)
    caps = Caps()
    _report_validation(response, caps, deps)
    _security_onion_evidence(prompt_package, caps, deps)
    _iterative_evidence(prompt_package, caps, deps)
    _live_osquery_evidence(prompt_package, caps)
    score = round(caps.maximum_score, 3)
    response["_incident_evidence_completeness"] = {
        "version": 1,
        "complete_for_high_confidence": caps.maximum_score >= deps.confidence_high_threshold,
        "maximum_confidence_score": score,
        "confidence_cap": score if caps.maximum_score < 1.0 else None,
        "limiters": caps.reasons,
    }
    return response
