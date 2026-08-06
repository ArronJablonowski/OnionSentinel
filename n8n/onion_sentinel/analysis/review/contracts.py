"""Independent-review identity binding and secret-safe repair guidance."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable


def validation_failure(
    *,
    attempt: int,
    call_id: str,
    error: Exception,
    input_value: Any,
    response: dict[str, Any],
    schema: str,
    message_max: int,
    digest_json: Callable[[Any], str],
) -> dict[str, Any]:
    """Return bounded validator telemetry without retaining model output."""
    message = str(error).strip()[:message_max]
    return {
        "schema": schema,
        "attempt": int(attempt),
        "call_id": str(call_id)[:128],
        "status": "validation-failed",
        "message": message or "reviewer validation failed",
        "input_digest": digest_json(input_value),
        "output_digest": digest_json(response),
    }


def repair_guidance(validation_message: str, *, message_max: int) -> list[str]:
    """Translate validation output into bounded field-specific repair steps."""
    message = str(validation_message or "")[:message_max]
    guidance = [
        "Return a fresh complete object and correct only against response_schema, review_contract, and evidence_reference_contract."
    ]
    if "foreign community ID value(s)" in message:
        guidance.append(
            "Community ID correction: use only exact values whose kind is community_id in review_contract.allowed_observables. Elastic index/document identifiers, including rollover-number and document-ID text separated by a colon, are record identifiers, not Community IDs; do not add them to observables_used or describe them as Community IDs. Cite the matching evidence reference instead."
        )
    observable_markers = (
        "foreign observables", "omitted from observables_used",
        "foreign domain or FQDN", "foreign IP address", "foreign community ID",
    )
    if any(marker in message for marker in observable_markers):
        guidance.append(
            "Observable correction: enumerate each material IP, domain, FQDN, or Community ID exactly once using its exact kind and value from review_contract.allowed_observables; omit every other value. Do not repeat, quote, negate, or discuss any rejected observable."
        )
    if "outside the current contract" in message or "no current corroborating" in message:
        guidance.append(
            "Evidence correction: evidence_used may contain only exact refs from evidence_reference_contract and must include current corroborating collector-owned evidence."
        )
    if "review_case_id" in message or "review_evidence_hash" in message:
        guidance.append(
            "Identity correction: copy review_contract.case_id and review_contract.evidence_hash byte-for-byte into their matching response fields."
        )
    return guidance[:4]


def repair_error_category(validation_message: str, *, message_max: int) -> str:
    """Classify a failure without echoing rejected observable values."""
    message = str(validation_message or "")[:message_max]
    foreign_markers = (
        "foreign observables", "foreign domain or FQDN",
        "foreign IP address", "foreign community ID",
    )
    if any(marker in message for marker in foreign_markers):
        return (
            "The response referenced one or more observables outside review_contract.allowed_observables. Use only exact allowlisted kind/value pairs and do not quote or discuss rejected values."
        )
    if "omitted from observables_used" in message:
        return (
            "The response omitted one or more material allowlisted observables from observables_used. Rebuild the ledger only from review_contract.allowed_observables."
        )
    if "outside the current contract" in message or "no current corroborating" in message:
        return (
            "The response referenced evidence outside the current evidence_reference_contract. Use only exact current evidence refs."
        )
    if "review_case_id" in message or "review_evidence_hash" in message:
        return "The response identity fields did not exactly match review_contract."
    return (
        "The response failed deterministic validation. Rebuild one complete object using only response_schema, review_contract, and evidence_reference_contract."
    )


def case_id(
    prompt_package: dict[str, Any],
    *,
    bounded_reference: Callable[[Any], str],
    model_safe_copy: Callable[..., Any],
) -> str:
    local = prompt_package.get("_local_investigation_query_context")
    incident = prompt_package.get("incident_response_evidence")
    alert = prompt_package.get("alert")
    candidates = (
        local.get("case_id") if isinstance(local, dict) else "",
        incident.get("case_id") if isinstance(incident, dict) else "",
        alert.get("alert_id") if isinstance(alert, dict) else "",
    )
    for value in candidates:
        bounded = bounded_reference(value)
        if bounded:
            return bounded
    seed = json.dumps(
        model_safe_copy(prompt_package, reviewer_safe=True),
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return "review-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def evidence_hash(
    review_package: dict[str, Any],
    *,
    model_safe_copy: Callable[..., Any],
) -> str:
    """Bind a response to its exact blind model-visible evidence package."""
    payload: dict[str, Any] = {}
    for key, value in review_package.items():
        if key == "review_contract_repair":
            continue
        if key == "review_contract":
            if isinstance(value, dict):
                contract = dict(value)
                contract.pop("evidence_hash", None)
                payload[key] = contract
            continue
        payload[key] = value
    encoded = json.dumps(
        model_safe_copy(payload, reviewer_safe=True),
        sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
