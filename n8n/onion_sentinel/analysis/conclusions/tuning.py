"""Deterministic coherence policy for advisory detection tuning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    bounded_text_list: Callable[..., list[str]]
    has_authorization_evidence: Callable[[dict[str, Any] | None], bool]
    control_tuning_values: frozenset[str]


def material_evidence_gap_signals(
    response: dict[str, Any], deps: Dependencies
) -> list[str]:
    """Return bounded, non-sensitive signals that make control tuning unsafe."""
    signals: list[str] = []

    def add(signal: str) -> None:
        if signal not in signals and len(signals) < 12:
            signals.append(signal)

    if deps.bounded_text_list(response.get("evidence_gaps"), limit=1):
        add("reported_evidence_gaps")
    report = response.get("incident_response_report")
    if isinstance(report, dict) and (
        deps.bounded_text_list(report.get("evidence_gaps"), limit=1)
        or deps.bounded_text_list(report.get("constraints"), limit=1)
    ):
        add("incident_report_evidence_gaps")
    completeness = response.get("_incident_evidence_completeness")
    if isinstance(completeness, dict) and (
        completeness.get("complete_for_high_confidence") is False
        or bool(completeness.get("limiters"))
    ):
        add("incident_evidence_incomplete")
    reference_validation = response.get("_evidence_reference_validation")
    if isinstance(reference_validation, dict) and bool(reference_validation.get("invalid_refs")):
        add("invalid_evidence_references")
    verdict_validation = response.get("_verdict_validation")
    if isinstance(verdict_validation, dict) and verdict_validation.get("material_contradiction"):
        add("material_evidence_contradiction")
    return signals


def unresolved_reviewer_material_disagreement(response: dict[str, Any]) -> bool:
    """Treat shadow reviewer disagreement as unresolved until a human decides."""
    second_opinion = response.get("_second_opinion")
    comparison = second_opinion.get("comparison") if isinstance(
        second_opinion, dict
    ) and isinstance(second_opinion.get("comparison"), dict) else {}
    return bool(comparison.get("material_disagreement"))


def _requested_tuning(response: dict[str, Any], deps: Dependencies) -> str:
    previous = response.get("_tuning_coherence_guard")
    previous = dict(previous) if isinstance(previous, dict) else {}
    current = str(response.get("tuning_recommendation") or "").strip().lower()
    prior = str(previous.get("requested_tuning") or "").strip().lower()
    if current in deps.control_tuning_values:
        return current
    return prior if prior in deps.control_tuning_values else ""


def _blocking_reasons(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    signals: list[str],
    reviewer_disagreement: bool,
    deps: Dependencies,
) -> tuple[list[str], bool]:
    reasons: list[str] = []
    if str(response.get("detection_validity") or "unknown").strip().lower() == "unknown":
        reasons.append("detection_validity_unknown")
    if str(response.get("activity_disposition") or "unknown").strip().lower() == "unknown":
        reasons.append("activity_disposition_unknown")
    if signals:
        reasons.append("material_evidence_gaps")
    authorized = deps.has_authorization_evidence(prompt_package)
    if not authorized:
        reasons.append("structured_authorization_missing")
    if reviewer_disagreement:
        reasons.append("reviewer_material_disagreement_unresolved")
    return reasons, authorized


def _automation_controls(response: dict[str, Any]) -> None:
    controls = dict(response.get("_automation_controls")) if isinstance(
        response.get("_automation_controls"), dict
    ) else {}
    controls.update({
        "tuning_blocked": True,
        "automatic_tuning_authorized": False,
        "tuning_requires_human_approval": True,
        "requires_human_review": True,
    })
    if not str(controls.get("reason") or "").strip():
        controls["reason"] = (
            "suppress/drop tuning is advisory and requires explicit human approval"
        )
    response["_automation_controls"] = controls


def _record_downgrade(response: dict[str, Any], deps: Dependencies) -> None:
    response["tuning_recommendation"] = "needs_more_data"
    response["recommended_tuning_actions"] = []
    response["tuning_reason"] = (
        "Suppress/drop tuning was downgraded because deterministic coherence "
        "requirements were not met; resolve the recorded evidence, authorization, "
        "and review blockers before proposing a human-approved detection change."
    )
    gap = (
        "Suppress/drop tuning is not decision-ready because deterministic coherence "
        "checks found unresolved evidence, authorization, or independent-review requirements."
    )
    gaps = deps.bounded_text_list(response.get("evidence_gaps"), limit=49, item_limit=4000)
    if gap not in gaps:
        gaps.append(gap)
    response["evidence_gaps"] = gaps[:50]


def _warning(response: dict[str, Any], downgraded: bool, deps: Dependencies) -> None:
    validation = dict(response.get("_verdict_validation")) if isinstance(
        response.get("_verdict_validation"), dict
    ) else {}
    warnings = deps.bounded_text_list(
        validation.get("warnings"), limit=49, item_limit=1000
    )
    warning = (
        "suppress/drop tuning was downgraded by the deterministic coherence guard"
        if downgraded else
        "suppress/drop tuning remains advisory; automatic application is blocked"
    )
    if warning not in warnings:
        warnings.append(warning)
    validation["warnings"] = warnings[:50]
    response["_verdict_validation"] = validation


def apply(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Keep suppress/drop evidence-complete, advisory, and human-controlled."""
    requested = _requested_tuning(response, deps)
    if not requested:
        return response
    signals = material_evidence_gap_signals(response, deps)
    reviewer_disagreement = unresolved_reviewer_material_disagreement(response)
    reasons, authorized = _blocking_reasons(
        response, prompt_package, signals, reviewer_disagreement, deps
    )
    downgraded = bool(reasons)
    if downgraded:
        _record_downgrade(response, deps)
    _automation_controls(response)
    _warning(response, downgraded, deps)
    response["_tuning_coherence_guard"] = {
        "schema": "onion-sentinel-tuning-coherence-guard-v1",
        "version": 1,
        "control_requested": True,
        "requested_tuning": requested,
        "resulting_tuning": str(response.get("tuning_recommendation") or "needs_more_data")[:40],
        "downgrade_applied": downgraded,
        "invalid_for_context": downgraded,
        "blocking_reasons": reasons[:8],
        "material_evidence_gap_signals": signals[:12],
        "structured_authorization_present": authorized,
        "reviewer_material_disagreement_unresolved": reviewer_disagreement,
        "automatic_tuning_authorized": False,
        "human_approval_required": True,
    }
    return response
