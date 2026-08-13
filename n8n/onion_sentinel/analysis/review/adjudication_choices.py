"""Identity and closed-choice validation for disagreement adjudication."""

from __future__ import annotations

from typing import Any


_CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})


def validate_identity(
    response: dict[str, Any],
    contract: dict[str, Any],
    errors: list[str],
) -> None:
    """Append contract-identity errors in public validation order."""
    _append_mismatch(
        response,
        contract,
        "adjudication_case_id",
        "case_id",
        "adjudication_case_id does not match the contract",
        errors,
    )
    _append_mismatch(
        response,
        contract,
        "adjudication_evidence_hash",
        "evidence_hash",
        "adjudication_evidence_hash does not match the contract",
        errors,
    )


def normalized_decision(
    response: dict[str, Any],
    contract: dict[str, Any],
    errors: list[str],
) -> str:
    """Normalize and validate the contract-defined decision vocabulary."""
    decision = _normalized_choice(response.get("decision"))
    allowed = set(contract.get("allowed_decisions") or [])
    if decision not in allowed:
        errors.append("decision is outside the closed vocabulary")
    return decision


def normalized_confidence(
    response: dict[str, Any],
    errors: list[str],
) -> str:
    """Normalize and validate the fixed confidence vocabulary."""
    confidence = _normalized_choice(response.get("confidence"))
    if confidence not in _CONFIDENCE_LEVELS:
        errors.append("confidence is outside the closed vocabulary")
    return confidence


def normalized_confidence_score(
    response: dict[str, Any],
    errors: list[str],
) -> float:
    """Coerce and validate the inclusive confidence-score range."""
    score = _float_or_sentinel(response.get("confidence_score"))
    if not 0.0 <= score <= 1.0:
        errors.append("confidence_score must be between 0 and 1")
    return score


def _append_mismatch(
    response: dict[str, Any],
    contract: dict[str, Any],
    response_key: str,
    contract_key: str,
    message: str,
    errors: list[str],
) -> None:
    if str(response.get(response_key) or "") != str(contract.get(contract_key) or ""):
        errors.append(message)


def _normalized_choice(value: Any) -> str:
    return str(value or "").strip().lower()


def _float_or_sentinel(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return -1.0
