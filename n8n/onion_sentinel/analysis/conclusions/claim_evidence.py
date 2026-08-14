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


def _identity_required_errors(
    identifier: str, statement: str, material: Any, index: int, errors: list[str],
) -> bool:
    if not identifier:
        errors.append(f"claim {index} id is required")
    if not statement:
        errors.append(f"claim {identifier or index} statement is required")
    if not isinstance(material, bool):
        errors.append(f"claim {identifier or index} material must be boolean")
        return False
    return material


def _identity_enum_errors(
    identifier: str, index: int, kind: str, certainty: str, scope: str,
    errors: list[str],
) -> None:
    if kind not in CLAIM_KINDS:
        errors.append(f"claim {identifier or index} kind is unsupported")
    if certainty not in CERTAINTIES:
        errors.append(f"claim {identifier or index} certainty is unsupported")
    if scope not in CLAIM_SCOPES:
        errors.append(f"claim {identifier or index} scope is unsupported")


def _claim_identity(
    raw: Mapping[str, Any], index: int, errors: list[str],
) -> tuple[str, str, str, str, str, bool]:
    identifier = _identifier(raw.get("id"))
    kind = _text(raw.get("claim_kind"), 40).lower()
    statement = _text(raw.get("statement"), 4000)
    certainty = _text(raw.get("certainty"), 40).lower()
    scope = _text(raw.get("claim_scope"), 80).lower()
    material = _identity_required_errors(
        identifier, statement, raw.get("material"), index, errors,
    )
    _identity_enum_errors(identifier, index, kind, certainty, scope, errors)
    return identifier, kind, statement, certainty, scope, material


def _claim_edges(
    raw: Mapping[str, Any], identifier: str,
    catalog: Mapping[str, dict[str, Any]], errors: list[str], deps: Dependencies,
) -> tuple[list[str], list[str], list[str], list[str]]:
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
    return fields, supporting, contradicting, missing


def _normalize_claim(
    raw: Any, index: int, catalog: Mapping[str, dict[str, Any]],
    errors: list[str], deps: Dependencies,
) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        errors.append(f"claim {index} must be an object")
        return None
    identity = _claim_identity(raw, index, errors)
    identifier, kind, statement, certainty, scope, material = identity
    fields, supporting, contradicting, missing = _claim_edges(
        raw, identifier, catalog, errors, deps,
    )
    supersedes = _identifier(raw.get("supersedes_claim_id"))
    correction = _text(raw.get("correction_reason"), 2000)
    return {
        "id": identifier, "claim_kind": kind, "statement": statement,
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


def _edge_errors(
    claim: Mapping[str, Any], catalog: Mapping[str, dict[str, Any]],
    errors: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    identifier = claim["id"]
    edges = claim["supporting_evidence_refs"] + claim["contradicting_evidence_refs"]
    if claim["material"] and not edges:
        errors.append(f"material claim {identifier} has no evidence edge")
    support = [catalog[ref] for ref in claim["supporting_evidence_refs"] if ref in catalog]
    corroborating = _corroborating(claim, catalog)
    if set(claim["supporting_evidence_refs"]).intersection(
        claim["contradicting_evidence_refs"]
    ):
        errors.append(f"claim {identifier} uses one result as both support and contradiction")
    if claim["certainty"] == "confirmed" and not corroborating:
        errors.append(f"confirmed claim {identifier} lacks corroborating evidence")
    if _unsupported_supported_certainty(claim, corroborating):
        errors.append(f"supported claim {identifier} lacks corroborating evidence")
    return support, corroborating


def _unsupported_supported_certainty(
    claim: Mapping[str, Any], corroborating: list[dict[str, Any]],
) -> bool:
    return (
        claim["certainty"] == "supported"
        and claim["claim_kind"] not in {"negative_evidence", "unavailable_telemetry"}
        and not corroborating
    )


def _negative_evidence_is_exact(support: list[dict[str, Any]]) -> bool:
    return bool(support) and all(
        _returned(item) == 0
        and str(item.get("status") or "").lower() in SUCCESS_STATUSES
        and item.get("scope_exact", True) is True
        for item in support
    )


def _kind_errors(
    claim: Mapping[str, Any], support: list[dict[str, Any]],
    corroborating: list[dict[str, Any]], errors: list[str],
) -> None:
    identifier = claim["id"]
    if claim["claim_kind"] == "observation" and support and not corroborating:
        if all(_returned(item) == 0 for item in support):
            errors.append(f"observation claim {identifier} uses only zero-row evidence")
    if claim["claim_kind"] == "negative_evidence" and not _negative_evidence_is_exact(support):
        errors.append(
            f"negative-evidence claim {identifier} is not bound to an exact successful zero-row result"
        )


def _gap_kind_errors(
    claim: Mapping[str, Any], support: list[dict[str, Any]], errors: list[str],
) -> None:
    identifier = claim["id"]
    if claim["claim_kind"] == "unavailable_telemetry":
        if not claim["decisive_missing_evidence"]:
            errors.append(f"unavailable-telemetry claim {identifier} omits the decisive gap")
        if support and all(
            str(item.get("status") or "").lower() in SUCCESS_STATUSES for item in support
        ):
            errors.append(f"unavailable-telemetry claim {identifier} cites only successful results")
    if claim["claim_kind"] == "hypothesis" and claim["certainty"] in {"tentative", "unknown"}:
        if not claim["decisive_missing_evidence"]:
            errors.append(f"unresolved hypothesis {identifier} omits decisive missing evidence")


def _attribution_errors(
    claim: Mapping[str, Any], support: list[dict[str, Any]],
    corroborating: list[dict[str, Any]], response: Mapping[str, Any],
    errors: list[str],
) -> None:
    identifier = claim["id"]
    if _behavioral_only_attribution(claim, support):
        errors.append("behavioral scores alone cannot support malware attribution")
    if _consequential_final_without_corroboration(claim, response, corroborating):
        errors.append(f"consequential final claim {identifier} lacks corroborating evidence")


def _behavioral_only_attribution(
    claim: Mapping[str, Any], support: list[dict[str, Any]],
) -> bool:
    classes = {str(item.get("source_class") or "").lower() for item in support}
    return bool(
        claim["claim_scope"] == "malware_attribution"
        and classes
        and classes.issubset(BEHAVIORAL_SCORE_CLASSES)
    )


def _consequential_final_without_corroboration(
    claim: Mapping[str, Any], response: Mapping[str, Any],
    corroborating: list[dict[str, Any]],
) -> bool:
    consequential = (
        str(response.get("activity_disposition") or "").lower() == "malicious"
        or str(response.get("confidence") or "").lower() == "high"
    )
    return bool(
        consequential and claim["claim_kind"] == "final_determination"
        and claim["claim_scope"] in {"activity_disposition", "malware_attribution"}
        and not corroborating
    )


def _semantic_errors(
    claim: Mapping[str, Any], catalog: Mapping[str, dict[str, Any]],
    response: Mapping[str, Any], errors: list[str],
) -> None:
    support, corroborating = _edge_errors(claim, catalog, errors)
    _kind_errors(claim, support, corroborating, errors)
    _gap_kind_errors(claim, support, errors)
    _attribution_errors(claim, support, corroborating, response, errors)


def _supersession_errors(
    claim: Mapping[str, Any], known: set[str], errors: list[str],
) -> None:
    supersedes = claim["supersedes_claim_id"]
    if supersedes and supersedes not in known:
        errors.append(f"claim {claim['id']} superseded claim is absent")
    if supersedes == claim["id"]:
        errors.append(f"claim {claim['id']} cannot supersede itself")
    if supersedes and not claim["correction_reason"]:
        errors.append(f"claim {claim['id']} correction reason is required")
    if not supersedes and claim["correction_reason"]:
        errors.append(f"claim {claim['id']} correction reason lacks an original claim")


def _identity_errors(claims: list[dict[str, Any]], errors: list[str]) -> None:
    identifiers = [claim["id"] for claim in claims]
    if len(identifiers) != len(set(identifiers)):
        errors.append("claim ids must be unique")
    known = set(identifiers)
    for claim in claims:
        _supersession_errors(claim, known, errors)


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


def _hypothesis_edge_errors(
    raw: Mapping[str, Any], graph_claim: Mapping[str, Any], errors: list[str],
) -> None:
    identifier = graph_claim["id"]
    for key, graph_key in (
        ("supporting_evidence", "supporting_evidence_refs"),
        ("contradicting_evidence", "contradicting_evidence_refs"),
    ):
        raw_refs = raw.get(key)
        raw_refs = [str(item) for item in raw_refs] if isinstance(raw_refs, list) else []
        if raw_refs != graph_claim[graph_key]:
            errors.append(f"hypothesis {identifier} {key} does not match graph evidence")


def _hypothesis_item_errors(
    raw: Any, graph_hypotheses: Mapping[str, dict[str, Any]], errors: list[str],
) -> None:
    if not isinstance(raw, dict):
        return
    identifier = _identifier(raw.get("id"))
    graph_claim = graph_hypotheses.get(identifier)
    if identifier and graph_claim is None:
        errors.append(f"hypothesis {identifier} is absent from the claim-evidence graph")
        return
    if graph_claim is None:
        return
    if _text(raw.get("statement"), 4000) != graph_claim["statement"]:
        errors.append(f"hypothesis {identifier} statement does not match its graph claim")
    status = str(raw.get("status") or "unresolved").strip().lower()
    allowed_certainty = {
        "supported": {"supported", "confirmed"},
        "contradicted": {"contradicted"},
        "unresolved": {"tentative", "unknown"},
    }.get(status, set())
    if graph_claim["certainty"] not in allowed_certainty:
        errors.append(f"hypothesis {identifier} status does not match graph certainty")
    _hypothesis_edge_errors(raw, graph_claim, errors)


def _hypothesis_errors(
    claims: list[dict[str, Any]], response: Mapping[str, Any], errors: list[str],
) -> None:
    hypotheses = response.get("hypotheses")
    if not isinstance(hypotheses, list):
        return
    graph_hypotheses = {
        claim["id"]: claim for claim in claims if claim["claim_kind"] == "hypothesis"
    }
    for raw in hypotheses:
        _hypothesis_item_errors(raw, graph_hypotheses, errors)
    unresolved = [
        claim for claim in graph_hypotheses.values()
        if claim["certainty"] in {"tentative", "unknown"}
    ]
    if any(not claim["decisive_missing_evidence"] for claim in unresolved):
        errors.append("an unresolved graph hypothesis omits decisive missing evidence")


def _final_claim_errors(
    claims: list[dict[str, Any]], response: Mapping[str, Any], errors: list[str],
) -> None:
    if MATERIAL_REPORT_FIELDS.intersection(response) and not any(
        claim["claim_kind"] == "final_determination" and claim["material"]
        for claim in claims
    ):
        errors.append("material report fields require a final-determination claim")


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
        _semantic_errors(item, catalog, response, errors)
    covered = _coverage_errors(claims, response, errors)
    _hypothesis_errors(claims, response, errors)
    _final_claim_errors(claims, response, errors)
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


def required(response: Mapping[str, Any], prompt_package: Mapping[str, Any] | None) -> bool:
    """Recognize the versioned contract without imposing it on legacy fixtures."""
    schema = prompt_package.get("response_schema") if isinstance(prompt_package, dict) else None
    return "claim_evidence_graph" in response or (
        isinstance(schema, dict) and "claim_evidence_graph" in schema
    )


def _record_failure(response: dict[str, Any], message: str) -> None:
    response["claim_evidence_graph"] = {
        "schema": SCHEMA,
        "claims": [],
        "validation": {
            "schema": "onion-sentinel-claim-evidence-validation-v1",
            "valid": False,
            "reason": _text(message, 2000),
        },
    }
    response["_claim_evidence_validation"] = dict(
        response["claim_evidence_graph"]["validation"]
    )
    gap = "Material conclusions were not bound to a valid claim-evidence graph."
    gaps = response.get("evidence_gaps")
    gaps = list(gaps) if isinstance(gaps, list) else []
    if gap not in gaps:
        gaps.append(gap)
    response["evidence_gaps"] = gaps
    verdict = response.get("_verdict_validation")
    verdict = dict(verdict) if isinstance(verdict, dict) else {}
    contradictions = verdict.get("contradictions")
    contradictions = list(contradictions) if isinstance(contradictions, list) else []
    contradiction = "material conclusions lack valid claim-to-evidence bindings"
    if contradiction not in contradictions:
        contradictions.append(contradiction)
    verdict["contradictions"] = contradictions
    verdict["material_contradiction"] = True
    response["_verdict_validation"] = verdict
    controls = response.get("_automation_controls")
    controls = dict(controls) if isinstance(controls, dict) else {}
    controls.update({
        "requires_human_review": True,
        "reason": "invalid claim-evidence graph",
    })
    response["_automation_controls"] = controls


def apply(
    response: dict[str, Any],
    prompt_package: Mapping[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Validate configured graphs while safely retaining legacy responses."""
    if not required(response, prompt_package):
        return response
    try:
        graph = validate(
            response.get("claim_evidence_graph"), response,
            prompt_package if isinstance(prompt_package, dict) else {}, deps,
        )
    except deps.error_type as exc:
        _record_failure(response, str(exc))
        return response
    response["claim_evidence_graph"] = graph
    response["_claim_evidence_validation"] = dict(graph["validation"])
    return response
