"""Pure evidence-quality confidence calibration policy."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Collection, Mapping


@dataclass
class Caps:
    maximum: float = 1.0
    reasons: list[str] = field(default_factory=list)

    def apply(self, value: float, reason: str) -> None:
        self.maximum = min(self.maximum, value)
        if reason not in self.reasons:
            self.reasons.append(reason)


def label(score: float, *, low_threshold: float, high_threshold: float) -> str:
    if score < low_threshold:
        return "low"
    if score < high_threshold:
        return "medium"
    return "high"


def _model_score(
    response: Mapping[str, Any],
    *,
    confidence_values: Collection[str],
    score_by_label: Mapping[str, float],
) -> tuple[str, float, bool, str]:
    raw_label = str(response.get("confidence") or "low").strip().lower()
    if raw_label not in confidence_values:
        raw_label = "low"
    supplied = response.get("confidence_score")
    if supplied in (None, ""):
        return raw_label, score_by_label[raw_label], False, "legacy_label_mapping"
    try:
        score = float(supplied)
    except (TypeError, ValueError, OverflowError):
        return raw_label, score_by_label[raw_label], True, "invalid_model_score_fallback"
    if not 0.0 <= score <= 1.0:
        return raw_label, score_by_label[raw_label], True, "invalid_model_score_fallback"
    return raw_label, score, False, "model_score"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _evidence(response: Mapping[str, Any]) -> dict[str, Any]:
    used = _list(response.get("evidence_used"))
    references = _dict(response.get("_evidence_reference_validation"))
    raw_corroborating = references.get("corroborating_refs")
    corroborating = raw_corroborating if isinstance(raw_corroborating, list) else used
    raw_source_classes = references.get("corroborating_source_classes")
    source_classes = raw_source_classes if isinstance(raw_source_classes, list) else corroborating
    correlation = _dict(response.get("correlation_assessment"))
    schema_repair = _dict(response.get("_schema_repair"))
    missing = {str(item) for item in _list(schema_repair.get("missing_keys"))}
    return {
        "used": used,
        "corroborating": corroborating,
        "source_classes": source_classes,
        "invalid_refs": _list(references.get("invalid_refs")),
        "gaps": _list(response.get("evidence_gaps")),
        "contradictions": _list(correlation.get("contradicting_evidence")),
        "verdict": _dict(response.get("_verdict_validation")),
        "missing": missing,
        "incident": _dict(response.get("_incident_evidence_completeness")),
    }


def _apply_embedded_cap(caps: Caps, value: Any, reasons: Any, fallback: str) -> None:
    if not isinstance(value, (int, float)):
        return
    normalized_reasons = reasons if isinstance(reasons, list) and reasons else [fallback]
    for reason in normalized_reasons:
        caps.apply(float(value), str(reason)[:200])


def _apply_structural_caps(
    caps: Caps,
    response: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    invalid_score: bool,
    critical_keys: Collection[str],
) -> list[str]:
    if "_invalid_confidence" in response:
        caps.apply(0.39, "invalid_confidence_label")
    if invalid_score:
        caps.apply(0.39, "invalid_confidence_score")
    critical_missing = sorted(set(evidence["missing"]) & set(critical_keys))
    if critical_missing:
        caps.apply(0.39, "critical_schema_repair:" + ",".join(critical_missing))
    verdict = evidence["verdict"]
    if verdict.get("material_contradiction"):
        caps.apply(0.39, "material_verdict_contradiction")
    if verdict.get("invalid_fields"):
        caps.apply(0.39, "invalid_factored_verdict")
    if evidence["invalid_refs"]:
        caps.apply(0.39, "invalid_evidence_references")
    guard = _dict(verdict.get("deterministic_evidence_guard"))
    _apply_embedded_cap(
        caps, guard.get("confidence_cap"), guard.get("confidence_cap_reasons"),
        "deterministic_evidence_guard",
    )
    incident = evidence["incident"]
    _apply_embedded_cap(
        caps, incident.get("confidence_cap"), incident.get("limiters"),
        "incident_evidence_incomplete",
    )
    return critical_missing


def _apply_evidence_caps(
    caps: Caps,
    evidence: Mapping[str, Any],
    response: Mapping[str, Any],
    *,
    raw_label: str,
    raw_score: float,
    outcome_normalizer: Callable[[Any], str],
    consequential_outcomes: Collection[str],
    label_for_score: Callable[[float], str],
) -> None:
    sources = evidence["source_classes"]
    if not sources:
        caps.apply(0.69, "no_valid_corroborating_evidence")
    elif len(set(sources)) == 1:
        caps.apply(0.79, "single_valid_corroborating_evidence_source")
    if evidence["contradictions"]:
        caps.apply(0.69, "unresolved_contradicting_evidence")
    outcome = outcome_normalizer(response.get("detection_outcome"))
    consequential = set(consequential_outcomes) | {"true_positive_malicious", "false_negative"}
    if evidence["gaps"] and outcome in consequential:
        caps.apply(0.79, "consequential_outcome_with_evidence_gaps")
    if label_for_score(raw_score) != raw_label:
        caps.apply(0.79, "model_confidence_label_score_mismatch")


def calibrate(
    response: dict[str, Any],
    *,
    confidence_values: Collection[str],
    score_by_label: Mapping[str, float],
    calibration_version: str,
    critical_keys: Collection[str],
    consequential_outcomes: Collection[str],
    outcome_normalizer: Callable[[Any], str],
    label_for_score: Callable[[float], str],
) -> dict[str, Any]:
    """Apply deterministic caps and record every evidence-quality limiter."""
    raw_label, raw_score, invalid_score, score_source = _model_score(
        response, confidence_values=confidence_values, score_by_label=score_by_label,
    )
    evidence = _evidence(response)
    caps = Caps()
    critical_missing = _apply_structural_caps(
        caps, response, evidence, invalid_score=invalid_score,
        critical_keys=critical_keys,
    )
    _apply_evidence_caps(
        caps, evidence, response, raw_label=raw_label, raw_score=raw_score,
        outcome_normalizer=outcome_normalizer,
        consequential_outcomes=consequential_outcomes,
        label_for_score=label_for_score,
    )
    calibrated_score = round(min(max(raw_score, 0.0), caps.maximum), 3)
    calibrated_label = label_for_score(calibrated_score)
    response["confidence_score"] = calibrated_score
    response["confidence"] = calibrated_label
    response["_confidence_calibration"] = {
        "version": calibration_version, "score_source": score_source,
        "model_confidence": raw_label, "model_confidence_score": round(raw_score, 3),
        "calibrated_confidence": calibrated_label,
        "calibrated_confidence_score": calibrated_score,
        "maximum_confidence_score": round(caps.maximum, 3), "limiters": caps.reasons,
        "evidence_signals": {
            "cited_evidence_count": len(evidence["used"]),
            "corroborating_evidence_count": len(evidence["corroborating"]),
            "corroborating_evidence_source_count": len(set(evidence["source_classes"])),
            "invalid_evidence_reference_count": len(evidence["invalid_refs"]),
            "evidence_gap_count": len(evidence["gaps"]),
            "contradicting_evidence_count": len(evidence["contradictions"]),
            "critical_schema_repair_keys": critical_missing,
        },
    }
    return response
