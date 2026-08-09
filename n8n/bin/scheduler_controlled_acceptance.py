"""Immutable alert-store acceptance projection and comparison."""
from __future__ import annotations

from typing import Any

from scheduler_controlled_canonical import controlled_normalize_timestamp
from scheduler_javascript_compat import javascript_safe_string, javascript_truthy


FIELD_LIMITS = {
    "model": 200,
    "model_path": 100,
    "detection_outcome": 100,
    "bluf": 4000,
    "summary": 8000,
    "confidence": 16,
    "artifact_path": 2048,
    "evidence_hash": 128,
}


def controlled_expected_accepted_fields(
    payload: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, str | None]:
    """Rebuild recordAiAnalysisResult's immutable acceptance projection."""
    payload_model = payload.get("model")
    payload_model_path = payload.get("model_path")
    generated_at = javascript_safe_string(payload.get("generated_at"), 64)
    return {
        "generated_at": generated_at or None,
        "model": javascript_safe_string(
            payload_model
            if javascript_truthy(payload_model)
            else response.get("_analysis_model"),
            FIELD_LIMITS["model"],
        ),
        "model_path": javascript_safe_string(
            payload_model_path
            if javascript_truthy(payload_model_path)
            else response.get("_analysis_model_path"),
            FIELD_LIMITS["model_path"],
        ),
        "detection_outcome": javascript_safe_string(
            response.get("detection_outcome"),
            FIELD_LIMITS["detection_outcome"],
        ),
        "bluf": javascript_safe_string(response.get("bluf"), FIELD_LIMITS["bluf"]),
        "summary": javascript_safe_string(
            response.get("summary"), FIELD_LIMITS["summary"]
        ),
        "confidence": javascript_safe_string(
            response.get("confidence"), FIELD_LIMITS["confidence"]
        ).lower(),
        "artifact_path": javascript_safe_string(
            payload.get("artifact_path"), FIELD_LIMITS["artifact_path"]
        ),
        "evidence_hash": javascript_safe_string(
            payload.get("evidence_hash"), FIELD_LIMITS["evidence_hash"]
        ).lower(),
    }


def controlled_accepted_fields_match(
    accepted: Any,
    expected: dict[str, str | None],
) -> bool:
    """Match every immutable field checked by result replay."""
    expected_generated_at = expected.get("generated_at")
    if not isinstance(expected_generated_at, str):
        return False
    actual_generated_at = javascript_safe_string(accepted["generated_at"], 64)
    if controlled_normalize_timestamp(
        actual_generated_at
    ) != controlled_normalize_timestamp(expected_generated_at):
        return False
    for field, limit in FIELD_LIMITS.items():
        actual = javascript_safe_string(accepted[field], limit)
        if field in {"confidence", "evidence_hash"}:
            actual = actual.lower()
        if actual != expected.get(field):
            return False
    return True
