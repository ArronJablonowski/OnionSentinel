"""Closed claim-to-evidence graph normalization and validation."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Mapping


SCHEMA = "onion-sentinel-claim-evidence-graph-v1"
CLAIM_KINDS = frozenset({
    "observation", "inference", "hypothesis", "negative_evidence",
    "unavailable_telemetry", "final_determination",
})
CERTAINTIES = frozenset({
    "confirmed", "supported", "tentative", "unknown", "contradicted",
    "unavailable",
})
CLAIM_SCOPES = frozenset({
    "event_occurrence", "detection_validity", "activity_disposition",
    "handling", "correlation", "attribution", "malware_attribution",
    "scope", "evidence_quality", "other",
})
MATERIAL_REPORT_FIELDS = frozenset({
    "event_status", "detection_validity", "activity_disposition", "handling",
    "duplicate_of", "detection_outcome", "confidence", "confidence_score",
    "escalation_needed", "tuning_recommendation",
})
SUCCESS_STATUSES = frozenset({"ok", "success", "completed", "executed"})
BEHAVIORAL_SCORE_CLASSES = frozenset({
    "ac_hunter", "ac_hunter_behavioral_score", "behavioral_score",
    "behavioral_triage",
})
MAX_CLAIMS = 100
MAX_REFS = 100
MAX_MISSING = 20


@dataclass(frozen=True)
class Dependencies:
    error_type: type[Exception]
    bounded_reference: Callable[[Any], str]


def _text(value: Any, limit: int) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _identifier(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-")[:64]


def _list(value: Any, key: str, limit: int, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{key} must be an array")
        return []
    if len(value) > limit:
        errors.append(f"{key} exceeds the maximum of {limit} entries")
    return value[:limit]


def _text_list(value: Any, key: str, limit: int, errors: list[str]) -> list[str]:
    raw = _list(value, key, limit, errors)
    result = [_text(item, 1000) for item in raw]
    if any(not item for item in result):
        errors.append(f"{key} contains an empty value")
    return list(dict.fromkeys(item for item in result if item))


def _references(
    value: Any, key: str, catalog: Mapping[str, dict[str, Any]],
    errors: list[str], deps: Dependencies,
) -> list[str]:
    raw = _list(value, key, MAX_REFS, errors)
    result = list(dict.fromkeys(deps.bounded_reference(item) for item in raw))
    if any(not item for item in result):
        errors.append(f"{key} contains an empty evidence reference")
    foreign = [item for item in result if item and item not in catalog]
    if foreign:
        errors.append(f"{key} contains a reference outside the evidence contract")
    return [item for item in result if item]


def _catalog(package: Mapping[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    contract = package.get("evidence_reference_contract")
    references = contract.get("references") if isinstance(contract, dict) else None
    if not isinstance(references, list):
        errors.append("evidence_reference_contract.references is unavailable")
        return {}
    return {
        str(item.get("ref") or ""): item
        for item in references
        if isinstance(item, dict) and str(item.get("ref") or "")
    }


def _normalize_claim(
    raw: Any, index: int, catalog: Mapping[str, dict[str, Any]],
    errors: list[str], deps: Dependencies,
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        errors.append(f"claim {index} must be an object")
        return None
    identifier = _identifier(raw.get("id"))
    kind = _text(raw.get("kind"), 40).lower()
    statement = _text(raw.get("statement"), 4000)
    certainty = _text(raw.get("certainty"), 40).lower()
    scope = _text(raw.get("claim_scope"), 80).lower()
    material = raw.get("material")
    if not identifier:
        errors.append(f"claim {index} id is required")
    if not statement:
        errors.append(f"claim {identifier or index} statement is required")
    if kind not in CLAIM_KINDS:
        errors.append(f"claim {identifier or index} kind is unsupported")
    if certainty not in CERTAINTIES:
        errors.append(f"claim {identifier or index} certainty is unsupported")
    if scope not in CLAIM_SCOPES:
        errors.append(f"claim {identifier or index} scope is unsupported")
    if not isinstance(material, bool):
        errors.append(f"claim {identifier or index} material must be boolean")
        material = False
    fields = _text_list(
        raw.get("report_fields"), f"claim {identifier} report_fields", 20, errors,
    )
    if any(field not in MATERIAL_REPORT_FIELDS for field in fields):
        errors.append(f"claim {identifier} report_fields contains an unsupported field")
    supporting = _references(
        raw.get("supporting_evidence_refs"),
        f"claim {identifier} supporting_evidence_refs", catalog, errors, deps,
    )
    contradicting = _references(
        raw.get("contradicting_evidence_refs"),
        f"claim {identifier} contradicting_evidence_refs", catalog, errors, deps,
    )
    missing = _text_list(
        raw.get("decisive_missing_evidence"),
        f"claim {identifier} decisive_missing_evidence", MAX_MISSING, errors,
    )
    supersedes = _identifier(raw.get("supersedes_claim_id"))
    correction = _text(raw.get("correction_reason"), 2000)
    return {
        "id": identifier, "kind": kind, "statement": statement,
        "material": material, "claim_scope": scope, "report_fields": fields,
        "certainty": certainty, "supporting_evidence_refs": supporting,
        "contradicting_evidence_refs": contradicting,
        "decisive_missing_evidence": missing,
        "supersedes_claim_id": supersedes or None,
        "correction_reason": correction,
    }


def _returned(item: Mapping[str, Any]) -> int | None:
    value = item.get("returned")
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _corroborating(
    claim: Mapping[str, Any], catalog: Mapping[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        catalog[ref] for ref in claim["supporting_evidence_refs"]
        if ref in catalog and catalog[ref].get("corroborating") is True
    ]


def _semantic_errors(
    claim: Mapping[str, Any], catalog: Mapping[str, dict[str, Any]],
    errors: list[str],
) -> None:
    identifier = claim["id"]
    edges = claim["supporting_evidence_refs"] + claim["contradicting_evidence_refs"]
    if claim["material"] and not edges:
        errors.append(f"material claim {identifier} has no evidence edge")
    support = [catalog[ref] for ref in claim["supporting_evidence_refs"] if ref in catalog]
    corroborating = _corroborating(claim, catalog)
    if claim["certainty"] == "confirmed" and not corroborating:
        errors.append(f"confirmed claim {identifier} lacks corroborating evidence")
    if claim["kind"] == "observation" and support and not corroborating:
        if all(_returned(item) == 0 for item in support):
            errors.append(f"observation claim {identifier} uses only zero-row evidence")
    if claim["kind"] == "negative_evidence":
        if any(
            _returned(item) != 0
            or str(item.get("status") or "").lower() not in SUCCESS_STATUSES
            or item.get("scope_exact") is not True
            for item in support
        ):
            errors.append(
                f"negative-evidence claim {identifier} is not bound to an exact successful zero-row result"
            )
    if claim["kind"] == "unavailable_telemetry":
        if not claim["decisive_missing_evidence"]:
            errors.append(f"unavailable-telemetry claim {identifier} omits the decisive gap")
        if support and all(
            str(item.get("status") or "").lower() in SUCCESS_STATUSES for item in support
        ):
            errors.append(f"unavailable-telemetry claim {identifier} cites only successful results")
    if claim["kind"] == "hypothesis" and claim["certainty"] in {"tentative", "unknown"}:
        if not claim["decisive_missing_evidence"]:
            errors.append(f"unresolved hypothesis {identifier} omits decisive missing evidence")
    if claim["claim_scope"] == "malware_attribution" and support:
        classes = {str(item.get("source_class") or "").lower() for item in support}
        if classes and classes.issubset(BEHAVIORAL_SCORE_CLASSES):
            errors.append("behavioral scores alone cannot support malware attribution")


def _identity_errors(claims: list[dict[str, Any]], errors: list[str]) -> None:
    identifiers = [claim["id"] for claim in claims]
    if len(identifiers) != len(set(identifiers)):
        errors.append("claim ids must be unique")
    known = set(identifiers)
    for claim in claims:
        supersedes = claim["supersedes_claim_id"]
        if supersedes and supersedes not in known:
            errors.append(f"claim {claim['id']} superseded claim is absent")
        if supersedes == claim["id"]:
            errors.append(f"claim {claim['id']} cannot supersede itself")
        if supersedes and not claim["correction_reason"]:
            errors.append(f"claim {claim['id']} correction reason is required")
        if not supersedes and claim["correction_reason"]:
            errors.append(f"claim {claim['id']} correction reason lacks an original claim")


def _coverage_errors(
    claims: list[dict[str, Any]], response: Mapping[str, Any], errors: list[str],
) -> list[str]:
    covered = sorted({
        field for claim in claims if claim["material"]
        for field in claim["report_fields"]
    })
    required = sorted(MATERIAL_REPORT_FIELDS.intersection(response))
    missing = sorted(set(required).difference(covered))
    if missing:
        errors.append("material report fields lack claim evidence: " + ",".join(missing))
    return covered


def validate(
    value: Any,
    response: Mapping[str, Any],
    prompt_package: Mapping[str, Any],
    deps: Dependencies,
) -> dict[str, Any]:
    """Return one normalized closed graph or fail with bounded public errors."""
    errors: list[str] = []
    graph = value if isinstance(value, dict) else {}
    if graph.get("schema") != SCHEMA:
        errors.append("claim-evidence graph schema is missing or unsupported")
    catalog = _catalog(prompt_package, errors)
    raw_claims = _list(graph.get("claims"), "claim-evidence graph claims", MAX_CLAIMS, errors)
    claims = [
        normalized for index, raw in enumerate(raw_claims, 1)
        if (normalized := _normalize_claim(raw, index, catalog, errors, deps)) is not None
    ]
    if not claims:
        errors.append("claim-evidence graph must contain at least one claim")
    _identity_errors(claims, errors)
    for item in claims:
        _semantic_errors(item, catalog, errors)
    covered = _coverage_errors(claims, response, errors)
    if errors:
        raise deps.error_type("; ".join(dict.fromkeys(errors))[:4000])
    return {
        "schema": SCHEMA,
        "claims": claims,
        "validation": {
            "schema": "onion-sentinel-claim-evidence-validation-v1",
            "valid": True,
            "claim_count": len(claims),
            "material_claim_count": sum(bool(item["material"]) for item in claims),
            "covered_report_fields": covered,
        },
    }
