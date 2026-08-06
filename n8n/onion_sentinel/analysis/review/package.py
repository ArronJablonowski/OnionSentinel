"""Construction of blind, route-safe independent-review packages."""
from __future__ import annotations

from typing import Any, Callable


def _remove_anchoring_instructions(package: dict[str, Any]) -> None:
    instructions = package.get("instructions")
    if not isinstance(instructions, dict):
        return
    instructions.pop("role", None)
    grounding = instructions.get("grounding")
    if isinstance(grounding, list):
        markers = ("prior_analyses", "previous_correlation", "earlier conclusion")
        instructions["grounding"] = [
            item for item in grounding
            if not any(marker in str(item).lower() for marker in markers)
        ]


def _remove_prior_correlations(package: dict[str, Any]) -> None:
    correlation = package.get("correlated_alert_context")
    if not isinstance(correlation, dict):
        return
    candidates = correlation.get("candidates")
    if not isinstance(candidates, list):
        return
    sanitized: list[Any] = []
    for raw in candidates:
        if not isinstance(raw, dict):
            sanitized.append(raw)
            continue
        candidate = dict(raw)
        candidate.pop("prior_analysis", None)
        candidate.pop("previous_correlation", None)
        reasons = candidate.get("correlation_reasons")
        if isinstance(reasons, list):
            candidate["correlation_reasons"] = [
                reason for reason in reasons
                if str(reason).strip().lower() != "previous correlation record exists"
            ]
        sanitized.append(candidate)
    correlation["candidates"] = sanitized


def _retain_confirmed_memory(package: dict[str, Any]) -> None:
    memory = package.get("agent_memory")
    if not isinstance(memory, dict):
        return
    for key in ("role_memory", "shared_memory"):
        context = memory.get(key)
        if not isinstance(context, dict):
            continue
        records = context.get("records")
        if isinstance(records, list):
            context["records"] = [
                record for record in records
                if isinstance(record, dict)
                and str(record.get("status") or "").strip().lower() == "operator-confirmed"
            ]
    memory["usage_guidance"] = (
        "Use only operator-authored notes and operator-confirmed memory as context. "
        "Corroborate every material conclusion with current collector-owned evidence."
    )


def _response_schema(package: dict[str, Any]) -> dict[str, Any]:
    schema = dict(package.get("response_schema")) if isinstance(package.get("response_schema"), dict) else {}
    schema.update({
        "review_case_id": "exact string from review_contract.case_id",
        "review_evidence_hash": "exact lowercase SHA-256 from review_contract.evidence_hash",
        "observables_used": [{
            "kind": "ip|domain|host|user|community_id",
            "value": "exact value from review_contract.allowed_observables",
        }],
    })
    return schema


def _review_metadata(hosted: bool, max_queries: int) -> dict[str, Any]:
    return {
        "mode": "blind_independent",
        "evidence_boundary": "hosted-redacted" if hosted else "local",
        "primary_conclusion_withheld": True,
        "excluded_context": [
            "current primary response", "prior AI analyses",
            "prior model correlation hypotheses", "unconfirmed model-observed memory",
        ],
        "supplemental_pivot_policy": {
            "allowed": True, "maximum_rounds": 1, "maximum_queries": max_queries,
            "requirements": [
                "Request supplemental evidence only for a material unresolved discriminator.",
                "Use only investigation_query_requests and the advertised read-only capabilities.",
                "Do not widen the supplied authorization envelope or introduce a new observable.",
                "Do not request supplemental evidence when the current evidence already resolves the conclusion.",
            ],
        },
    }


def _contract(
    *, case_id: str, observables: list[dict[str, str]],
    taxonomy: list[str], artifacts: list[str], rule_shorthands: list[str],
) -> dict[str, Any]:
    return {
        "schema": "onion-sentinel-independent-review-v1",
        "case_id": case_id, "allowed_observables": observables,
        "allowed_non_domain_taxonomy_tokens": taxonomy,
        "allowed_non_domain_artifact_tokens": artifacts,
        "allowed_non_domain_rule_shorthand_tokens": rule_shorthands,
        "requirements": [
            "Echo case_id and evidence_hash exactly in review_case_id and review_evidence_hash.",
            "List every material IPv4 address, domain, FQDN, dotted host, and community_id used in observables_used.",
            "List a bare host or user only when deliberately using that exact allowed value as an identity, never because the same word appears as ordinary prose.",
            "Use only exact allowed_observables and exact evidence_reference_contract refs.",
            "Treat Elastic index/document identifiers as record identifiers, not Community IDs; never add them to observables_used as community_id.",
            "Treat exact allowed_non_domain_taxonomy_tokens as dataset or module labels, not domain observables.",
            "Treat exact allowed_non_domain_rule_shorthand_tokens as current detection-rule labels, not domain observables.",
            "Do not repeat boilerplate or introduce facts from another case.",
        ],
    }


def _attach_supplemental(
    package: dict[str, Any], source: dict[str, Any], max_queries: int,
) -> bool:
    context = source.get("reviewer_supplemental_context")
    if not isinstance(context, dict):
        return False
    package["reviewer_supplemental_reconciliation"] = {
        "schema": "onion-sentinel-reviewer-supplemental-reconciliation-v1",
        "round": 1, "maximum_rounds": 1, "maximum_queries": max_queries,
        "instruction": (
            "Reassess the case using the complete blind evidence package, including the newly returned supplemental query evidence. "
            "Return a final independent conclusion and do not request another query round. Preserve unresolved gaps explicitly."
        ),
        "initial_review_sha256": str(context.get("initial_review_sha256") or ""),
    }
    return True


def build(
    prompt_package: dict[str, Any],
    *,
    hosted: bool,
    max_queries: int,
    model_safe_copy: Callable[..., dict[str, Any]],
    attach_evidence_contract: Callable[[dict[str, Any]], Any],
    case_id: Callable[[dict[str, Any]], str],
    observable_catalog: Callable[[dict[str, Any]], list[dict[str, str]]],
    taxonomy_catalog: Callable[[dict[str, Any]], list[str]],
    artifact_catalog: Callable[[dict[str, Any]], list[str]],
    rule_shorthand_catalog: Callable[[dict[str, Any]], list[str]],
    evidence_hash: Callable[[dict[str, Any]], str],
) -> dict[str, Any]:
    """Build the exact blind package after applying its transport boundary."""
    package = model_safe_copy(prompt_package, hosted=hosted, reviewer_safe=True)
    package.pop("prior_analyses", None)
    _remove_anchoring_instructions(package)
    _remove_prior_correlations(package)
    _retain_confirmed_memory(package)
    attach_evidence_contract(package)
    package["response_schema"] = _response_schema(package)
    package["second_opinion_review"] = _review_metadata(hosted, max_queries)
    package["review_contract"] = _contract(
        case_id=case_id(package), observables=observable_catalog(package),
        taxonomy=taxonomy_catalog(package), artifacts=artifact_catalog(package),
        rule_shorthands=rule_shorthand_catalog(package),
    )
    package["review_contract"]["evidence_hash"] = evidence_hash(package)
    if _attach_supplemental(package, prompt_package, max_queries):
        package["review_contract"]["evidence_hash"] = evidence_hash(package)
    return package
