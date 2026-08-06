"""Bounded package and validation policy for disagreement adjudication."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable


@dataclass(frozen=True)
class PackageDependencies:
    independent_package: Callable[..., dict[str, Any]]
    case_id: Callable[[dict[str, Any]], str]
    model_safe_copy: Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class ValidationDependencies:
    error_type: type[Exception]
    bounded_reference: Callable[[Any], str]


def build_package(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
    *,
    hosted: bool,
    deps: PackageDependencies,
) -> dict[str, Any]:
    """Build a route-safe package containing two immutable disputed positions."""
    package = deps.independent_package(prompt_package, hosted=hosted)
    package.pop("second_opinion_review", None)
    package.pop("review_contract", None)
    disputed = [
        item for item in comparison.get("disputed_fields", [])
        if isinstance(item, dict) and str(item.get("field") or "")
    ][:16]
    package["adjudication_positions"] = {
        "primary": _position(primary_response, comparison.get("primary")),
        "reviewer": _position(reviewer_response, comparison.get("reviewer")),
        "disputed_fields": disputed,
    }
    package["response_schema"] = _response_schema()
    contract = _contract(disputed, deps.case_id(package))
    package["adjudication_contract"] = contract
    digest_payload = deps.model_safe_copy(package, reviewer_safe=True)
    digest_contract = dict(digest_payload.get("adjudication_contract") or {})
    digest_contract.pop("evidence_hash", None)
    digest_payload["adjudication_contract"] = digest_contract
    contract["evidence_hash"] = hashlib.sha256(
        json.dumps(
            digest_payload, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
    ).hexdigest()
    return package


def _position(response: dict[str, Any], comparison: Any) -> dict[str, Any]:
    return {
        **dict(comparison or {}),
        "bluf": str(response.get("bluf") or "")[:4000],
        "summary": str(response.get("summary") or "")[:8000],
        "evidence_used": list(response.get("evidence_used") or [])[:100],
        "evidence_gaps": list(response.get("evidence_gaps") or [])[:50],
    }


def _response_schema() -> dict[str, Any]:
    return {
        "adjudication_case_id": "exact adjudication_contract.case_id",
        "adjudication_evidence_hash": "exact adjudication_contract.evidence_hash",
        "decision": "primary_supported|reviewer_supported|unresolved",
        "confidence": "low|medium|high",
        "confidence_score": "number from 0.0 through 1.0",
        "resolved_fields": ["exact field names from adjudication_contract.disputed_fields"],
        "remaining_disagreements": ["exact field names from adjudication_contract.disputed_fields"],
        "evidence_used": ["exact evidence_reference_contract ref strings"],
        "rationale": "bounded explanation tied to cited evidence",
        "additional_evidence_needed": ["bounded evidence needed to resolve remaining disagreement"],
    }


def _contract(disputed: list[dict[str, Any]], case_id: str) -> dict[str, Any]:
    return {
        "schema": "onion-sentinel-disagreement-adjudication-v1",
        "mode": "shadow",
        "case_id": case_id,
        "disputed_fields": [str(item["field"]) for item in disputed],
        "material_fields": [
            str(item["field"]) for item in disputed if item.get("material") is True
        ],
        "allowed_decisions": ["primary_supported", "reviewer_supported", "unresolved"],
        "maximum_model_calls": 2,
        "automation_authorized": False,
        "requirements": [
            "Choose one allowed decision; never synthesize a third position.",
            "Use only exact disputed field names and evidence refs.",
            "A supported decision must resolve every material field.",
            "Unresolved must retain at least one material disagreement.",
            "Shadow adjudication never authorizes an operational action.",
        ],
    }


def _identity_and_choices(
    response: dict[str, Any], contract: dict[str, Any], errors: list[str]
) -> tuple[str, str, float]:
    if str(response.get("adjudication_case_id") or "") != str(contract.get("case_id") or ""):
        errors.append("adjudication_case_id does not match the contract")
    if str(response.get("adjudication_evidence_hash") or "") != str(contract.get("evidence_hash") or ""):
        errors.append("adjudication_evidence_hash does not match the contract")
    decision = str(response.get("decision") or "").strip().lower()
    if decision not in set(contract.get("allowed_decisions") or []):
        errors.append("decision is outside the closed vocabulary")
    confidence = str(response.get("confidence") or "").strip().lower()
    if confidence not in {"low", "medium", "high"}:
        errors.append("confidence is outside the closed vocabulary")
    try:
        confidence_score = float(response.get("confidence_score"))
    except (TypeError, ValueError, OverflowError):
        confidence_score = -1.0
    if not 0.0 <= confidence_score <= 1.0:
        errors.append("confidence_score must be between 0 and 1")
    return decision, confidence, confidence_score


def _field_partition(
    response: dict[str, Any],
    contract: dict[str, Any],
    decision: str,
    errors: list[str],
) -> dict[str, list[str]]:
    allowed = {str(item) for item in contract.get("disputed_fields") or []}
    material = {str(item) for item in contract.get("material_fields") or []}
    normalized = {
        key: _normalized_field_list(response, key, allowed, errors)
        for key in ("resolved_fields", "remaining_disagreements")
    }
    resolved = set(normalized["resolved_fields"])
    remaining = set(normalized["remaining_disagreements"])
    _partition_errors(resolved, remaining, allowed, material, decision, errors)
    return normalized


def _normalized_field_list(
    response: dict[str, Any],
    key: str,
    allowed: set[str],
    errors: list[str],
) -> list[str]:
    value = response.get(key)
    if not isinstance(value, list) or len(value) > 16:
        errors.append(f"{key} must be a bounded array")
        return []
    normalized = list(dict.fromkeys(str(item or "").strip() for item in value))
    if any(not item or item not in allowed for item in normalized):
        errors.append(f"{key} contains a field outside the contract")
    return normalized


def _partition_errors(
    resolved: set[str],
    remaining: set[str],
    allowed: set[str],
    material: set[str],
    decision: str,
    errors: list[str],
) -> None:
    if resolved.intersection(remaining):
        errors.append("a field cannot be both resolved and remaining")
    if resolved.union(remaining) != allowed:
        errors.append("resolved and remaining fields must partition every disagreement")
    if decision in {"primary_supported", "reviewer_supported"} and material.intersection(remaining):
        errors.append("a supported position must resolve every material field")
    if decision == "unresolved" and material and not material.intersection(remaining):
        errors.append("unresolved must retain at least one material field")


def _evidence_catalog(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    contract = package.get("evidence_reference_contract")
    references = contract.get("references") if isinstance(contract, dict) else []
    return {
        str(item.get("ref") or ""): item for item in references
        if isinstance(references, list)
        and isinstance(item, dict)
        and str(item.get("ref") or "")
    }


def _evidence(
    response: dict[str, Any],
    package: dict[str, Any],
    decision: str,
    errors: list[str],
    deps: ValidationDependencies,
) -> list[str]:
    catalog = _evidence_catalog(package)
    cited = response.get("evidence_used")
    if not isinstance(cited, list) or len(cited) > 100:
        errors.append("evidence_used must be a bounded array")
        valid: list[str] = []
    else:
        valid = list(dict.fromkeys(deps.bounded_reference(item) for item in cited))
        if any(not item or item not in catalog for item in valid):
            errors.append("evidence_used contains a reference outside the contract")
    if decision in {"primary_supported", "reviewer_supported"} and not any(
        catalog.get(item, {}).get("corroborating") is True for item in valid
    ):
        errors.append("a supported position requires current corroborating evidence")
    return valid


def _narrative(response: dict[str, Any], errors: list[str]) -> tuple[str, list[str]]:
    rationale = re.sub(r"\s+", " ", str(response.get("rationale") or "")).strip()
    if not rationale or len(rationale) > 4000:
        errors.append("rationale must be a non-empty bounded string")
    needed = response.get("additional_evidence_needed")
    if not isinstance(needed, list) or len(needed) > 16:
        errors.append("additional_evidence_needed must be a bounded array")
        return rationale, []
    normalized = [
        re.sub(r"\s+", " ", str(item or "")).strip()[:1000]
        for item in needed if str(item or "").strip()
    ]
    return rationale, normalized


def validate(
    response: Any,
    package: dict[str, Any],
    deps: ValidationDependencies,
) -> dict[str, Any]:
    """Validate identity, closed choices, disputed fields, and evidence citations."""
    if not isinstance(response, dict):
        raise deps.error_type("adjudicator response must be an object")
    contract = package.get("adjudication_contract")
    if not isinstance(contract, dict):
        raise deps.error_type("adjudication contract is missing")
    errors: list[str] = []
    decision, confidence, score = _identity_and_choices(response, contract, errors)
    fields = _field_partition(response, contract, decision, errors)
    evidence = _evidence(response, package, decision, errors, deps)
    rationale, needed = _narrative(response, errors)
    if errors:
        raise deps.error_type("; ".join(errors)[:2000])
    return {
        "adjudication_case_id": str(contract.get("case_id") or ""),
        "adjudication_evidence_hash": str(contract.get("evidence_hash") or ""),
        "decision": decision,
        "confidence": confidence,
        "confidence_score": round(score, 3),
        "resolved_fields": fields["resolved_fields"],
        "remaining_disagreements": fields["remaining_disagreements"],
        "evidence_used": evidence,
        "rationale": rationale,
        "additional_evidence_needed": needed,
        "_adjudication_contract_validation": {
            "schema": "onion-sentinel-disagreement-adjudication-validation-v1",
            "valid": True,
            "mode": "shadow",
            "automation_authorized": False,
        },
    }
