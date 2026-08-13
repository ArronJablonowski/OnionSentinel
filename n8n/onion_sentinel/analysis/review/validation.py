"""Fail-closed admission and normalization of independent-review output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Pattern


Catalog = Callable[[dict[str, Any]], list[str]]


@dataclass(frozen=True)
class Dependencies:
    """Runtime-owned policy and callbacks used by the validation boundary."""

    error_type: type[Exception]
    evidence_hash: Callable[[dict[str, Any]], str]
    taxonomy_catalog: Catalog
    artifact_catalog: Catalog
    rule_shorthand_catalog: Catalog
    bounded_reference: Callable[[Any], str]
    response_strings: Callable[[Any], list[str]]
    repetition_reasons: Callable[[dict[str, Any]], list[str]]
    ipv4_re: Pattern[str]
    domain_re: Pattern[str]
    community_id_re: Pattern[str]
    known_field_paths: frozenset[str]
    non_domain_suffixes: frozenset[str]
    required_keys: frozenset[str]
    observable_max: int
    evidence_used_max: int
    hypotheses_max: int


def _contract_errors(
    response: dict[str, Any],
    review_package: dict[str, Any],
    contract: dict[str, Any],
    deps: Dependencies,
) -> list[str]:
    errors: list[str] = []
    if str(contract.get("evidence_hash") or "") != deps.evidence_hash(review_package):
        errors.append("review contract evidence hash did not match the current review package")
    if str(response.get("review_case_id") or "") != str(contract.get("case_id") or ""):
        errors.append("review_case_id did not echo the current case")
    if str(response.get("review_evidence_hash") or "") != str(contract.get("evidence_hash") or ""):
        errors.append("review_evidence_hash did not echo the current evidence")
    missing = sorted(deps.required_keys.difference(response))
    if missing:
        errors.append("missing required reviewer fields: " + ",".join(missing))
    return errors


def _allowed_observables(contract: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (str(item.get("kind") or ""), str(item.get("value") or ""))
        for item in (
            contract.get("allowed_observables")
            if isinstance(contract.get("allowed_observables"), list)
            else []
        )
        if isinstance(item, dict)
    }


def _observable_key(item: Any) -> tuple[str, str] | None:
    if not isinstance(item, dict) or set(item) != {"kind", "value"}:
        return None
    if not isinstance(item.get("kind"), str):
        return None
    if not isinstance(item.get("value"), str):
        return None
    return str(item.get("kind") or ""), str(item.get("value") or "")


def _admit_model_observables(
    response: dict[str, Any],
    allowed: set[tuple[str, str]],
    errors: list[str],
    deps: Dependencies,
) -> tuple[list[Any], list[tuple[str, str]]]:
    observables = response.get("observables_used")
    if not isinstance(observables, list):
        errors.append("observables_used must be an array")
        observables = []
    elif len(observables) > deps.observable_max:
        raise deps.error_type(
            "observables_used exceeds the maximum of "
            f"{deps.observable_max} entries"
        )
    foreign: list[str] = []
    admitted: list[tuple[str, str]] = []
    for item in observables:
        key = _observable_key(item)
        if key is None:
            foreign.append("malformed observable")
            continue
        if key not in allowed:
            foreign.append(f"{key[0]}:{key[1]}"[:300])
            continue
        admitted.append(key)
    if foreign:
        errors.append("reviewer used foreign observables: " + ",".join(foreign[:10]))
    return observables, admitted


def _contracted_catalog(contract: dict[str, Any], key: str) -> set[str]:
    values = contract.get(key)
    return {
        str(value).strip().lower()
        for value in values if str(value).strip()
    } if isinstance(values, list) else set()


def _catalogs(
    review_package: dict[str, Any],
    contract: dict[str, Any],
    errors: list[str],
    deps: Dependencies,
) -> tuple[set[str], set[str], set[str]]:
    specifications = (
        (
            "allowed_non_domain_taxonomy_tokens",
            deps.taxonomy_catalog,
            "review contract non-domain taxonomy catalog did not match collector-owned evidence",
        ),
        (
            "allowed_non_domain_artifact_tokens",
            deps.artifact_catalog,
            "review contract non-domain artifact catalog did not match collector-owned evidence",
        ),
        (
            "allowed_non_domain_rule_shorthand_tokens",
            deps.rule_shorthand_catalog,
            "review contract non-domain rule shorthand catalog did not match collector-owned evidence",
        ),
    )
    catalogs: list[set[str]] = []
    for key, collector, mismatch_error in specifications:
        contracted = _contracted_catalog(contract, key)
        collected = set(collector(review_package))
        if contracted != collected:
            errors.append(mismatch_error)
        catalogs.append(collected)
    return catalogs[0], catalogs[1], catalogs[2]


def _narrative_ips(
    response_text: str,
    allowed: set[tuple[str, str]],
    errors: list[str],
    deps: Dependencies,
) -> tuple[set[str], set[str]]:
    allowed_ips = {value for kind, value in allowed if kind == "ip"}
    narrative_ips = set(deps.ipv4_re.findall(response_text))
    foreign_ips = sorted(narrative_ips.difference(allowed_ips))
    if foreign_ips:
        errors.append("reviewer introduced foreign IP address(es): " + ",".join(foreign_ips[:10]))
    return narrative_ips, allowed_ips


def _narrative_domains(
    response_text: str,
    allowed: set[tuple[str, str]],
    catalogs: tuple[set[str], set[str], set[str]],
    errors: list[str],
    deps: Dependencies,
) -> tuple[set[str], set[str]]:
    allowed_domains = _allowed_domains(allowed)
    taxonomy, artifacts, rule_shorthands = catalogs
    narrative_domains = {
        candidate.lower()
        for candidate in deps.domain_re.findall(response_text)
        if _is_narrative_domain(
            candidate, taxonomy, artifacts, rule_shorthands, deps
        )
    }
    foreign_domains = sorted(narrative_domains.difference(allowed_domains))
    if foreign_domains:
        errors.append(
            "reviewer introduced foreign domain or FQDN value(s): "
            + ",".join(foreign_domains[:10])
        )
    return narrative_domains, allowed_domains


def _allowed_domains(allowed: set[tuple[str, str]]) -> set[str]:
    return {
        value.lower() for kind, value in allowed
        if kind == "domain" or (kind == "host" and "." in value)
    }


def _is_narrative_domain(
    candidate: str,
    taxonomy: set[str],
    artifacts: set[str],
    rule_shorthands: set[str],
    deps: Dependencies,
) -> bool:
    normalized = candidate.lower()
    excluded = (
        deps.known_field_paths,
        taxonomy,
        artifacts,
        rule_shorthands,
    )
    suffix = candidate.rsplit(".", 1)[-1].lower()
    return (
        all(normalized not in catalog for catalog in excluded)
        and suffix not in deps.non_domain_suffixes
    )


def _narrative_community_ids(
    response_text: str,
    allowed: set[tuple[str, str]],
    errors: list[str],
    deps: Dependencies,
) -> tuple[set[str], set[str]]:
    allowed_community_ids = {value for kind, value in allowed if kind == "community_id"}
    narrative_community_ids = set(deps.community_id_re.findall(response_text))
    foreign_community_ids = sorted(narrative_community_ids.difference(allowed_community_ids))
    if foreign_community_ids:
        errors.append(
            "reviewer introduced foreign community ID value(s): "
            + ",".join(foreign_community_ids[:10])
        )
    return narrative_community_ids, allowed_community_ids


def _material_observables(
    allowed: set[tuple[str, str]],
    narrative_ips: set[str],
    allowed_ips: set[str],
    narrative_domains: set[str],
    allowed_domains: set[str],
    narrative_community_ids: set[str],
    allowed_community_ids: set[str],
) -> set[tuple[str, str]]:
    material: set[tuple[str, str]] = {
        ("ip", value) for value in narrative_ips.intersection(allowed_ips)
    }

    for value in narrative_domains.intersection(allowed_domains):
        material.update(
            (kind, allowed_value)
            for kind, allowed_value in allowed
            if kind in {"domain", "host"}
            and allowed_value.lower() == value
            and (kind == "domain" or "." in allowed_value)
        )
    material.update(
        ("community_id", value)
        for value in narrative_community_ids.intersection(allowed_community_ids)
    )
    return material


def _narrative_observables(
    response: dict[str, Any],
    review_package: dict[str, Any],
    contract: dict[str, Any],
    allowed: set[tuple[str, str]],
    errors: list[str],
    deps: Dependencies,
) -> tuple[set[tuple[str, str]], set[str], set[str], set[str]]:
    excluded = {"evidence_used", "observables_used", "review_case_id", "review_evidence_hash"}
    narrative = {key: value for key, value in response.items() if key not in excluded}
    response_text = "\n".join(deps.response_strings(narrative))
    catalogs = _catalogs(review_package, contract, errors, deps)
    narrative_ips, allowed_ips = _narrative_ips(response_text, allowed, errors, deps)
    narrative_domains, allowed_domains = _narrative_domains(
        response_text, allowed, catalogs, errors, deps
    )
    narrative_ids, allowed_ids = _narrative_community_ids(
        response_text, allowed, errors, deps
    )
    material = _material_observables(
        allowed, narrative_ips, allowed_ips, narrative_domains, allowed_domains,
        narrative_ids, allowed_ids,
    )
    return material, catalogs[0], catalogs[1], catalogs[2]


def _normalize_observables(
    admitted: list[tuple[str, str]],
    material: set[tuple[str, str]],
    deps: Dependencies,
) -> tuple[set[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    used = set(admitted)
    bounded = {
        (kind, value) for kind, value in used
        if kind in {"ip", "domain", "community_id"} or (kind == "host" and "." in value)
    }
    discarded = sorted(bounded.difference(material))
    explicit_bare = sorted(used.difference(bounded))
    used.difference_update(discarded)
    derived = sorted(material.difference(used))
    used.update(derived)
    if len(used) > deps.observable_max:
        raise deps.error_type(
            "canonical observables_used exceeds the maximum of "
            f"{deps.observable_max} entries"
        )
    return used, discarded, explicit_bare, derived


def _evidence_catalog(review_package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    evidence_contract = review_package.get("evidence_reference_contract")
    return {
        str(item.get("ref") or ""): item
        for item in (
            evidence_contract.get("references")
            if isinstance(evidence_contract, dict)
            and isinstance(evidence_contract.get("references"), list)
            else []
        )
        if isinstance(item, dict) and str(item.get("ref") or "")
    }


def _resolve_evidence(
    cited: list[Any], catalog: dict[str, dict[str, Any]], deps: Dependencies
) -> tuple[list[str], list[str]]:
    invalid: list[str] = []
    corroborating: list[str] = []
    for raw in cited:
        reference = deps.bounded_reference(raw)
        item = catalog.get(reference)
        if item is None:
            invalid.append(reference or "empty reference")
        elif item.get("corroborating") is True and reference not in corroborating:
            corroborating.append(reference)
    return invalid, corroborating


def _admit_evidence(
    response: dict[str, Any],
    review_package: dict[str, Any],
    errors: list[str],
    deps: Dependencies,
) -> tuple[list[Any], list[str]]:
    cited = response.get("evidence_used")
    if not isinstance(cited, list):
        errors.append("evidence_used must be an array")
        cited = []
    elif len(cited) > deps.evidence_used_max:
        raise deps.error_type(
            "evidence_used exceeds the maximum of "
            f"{deps.evidence_used_max} entries"
        )
    invalid, corroborating = _resolve_evidence(
        cited, _evidence_catalog(review_package), deps
    )
    if invalid:
        errors.append(
            "reviewer cited evidence outside the current contract: "
            + ",".join(invalid[:10])
        )
    if not corroborating:
        errors.append("reviewer cited no current corroborating collector-owned evidence")
    return cited, corroborating


def _validate_hypotheses(
    response: dict[str, Any], errors: list[str], deps: Dependencies
) -> None:
    hypotheses = response.get("hypotheses")
    if not isinstance(hypotheses, list):
        errors.append("hypotheses must be an array")
    elif len(hypotheses) > deps.hypotheses_max:
        errors.append(
            "hypotheses exceeds the maximum of "
            f"{deps.hypotheses_max} entries"
        )
    elif any(not isinstance(item, dict) for item in hypotheses):
        errors.append("every hypotheses entry must be an object")


def validate(
    response: dict[str, Any],
    review_package: dict[str, Any],
    deps: Dependencies,
) -> dict[str, Any]:
    """Fail closed on stale, foreign, repetitive, or ungrounded output."""
    if not isinstance(response, dict):
        raise deps.error_type("reviewer response must be an object")
    contract = review_package.get("review_contract")
    if not isinstance(contract, dict):
        raise deps.error_type("review contract is unavailable")
    errors = _contract_errors(response, review_package, contract, deps)
    allowed = _allowed_observables(contract)
    observables, admitted = _admit_model_observables(response, allowed, errors, deps)
    material, taxonomy, artifacts, rule_shorthands = _narrative_observables(
        response, review_package, contract, allowed, errors, deps
    )
    used, discarded, explicit_bare, derived = _normalize_observables(
        admitted, material, deps
    )
    cited, corroborating = _admit_evidence(response, review_package, errors, deps)
    _validate_hypotheses(response, errors, deps)
    errors.extend(deps.repetition_reasons(response))
    if errors:
        raise deps.error_type("; ".join(errors)[:2000])

    normalized = [{"kind": kind, "value": value} for kind, value in sorted(used)]
    validated = dict(response)
    validated["observables_used"] = normalized
    admitted_set = set(admitted)
    validated["_review_contract_validation"] = {
        "schema": "onion-sentinel-independent-review-validation-v1",
        "valid": True,
        "case_id": contract.get("case_id"),
        "evidence_hash": contract.get("evidence_hash"),
        "observable_count": len(normalized),
        "observable_normalization": {
            "schema": "onion-sentinel-reviewer-observable-normalization-v1",
            "model_supplied_count": len(observables),
            "canonical_model_supplied_count": len(admitted_set),
            "retained_model_supplied_count": len(admitted_set.difference(discarded)),
            "duplicate_count": len(admitted) - len(admitted_set),
            "discarded_unused_bounded_count": len(discarded),
            "discarded_unused_bounded_observables": [
                {"kind": kind, "value": value} for kind, value in discarded
            ],
            "explicit_bare_model_observable_count": len(explicit_bare),
            "explicit_bare_model_observables": [
                {"kind": kind, "value": value} for kind, value in explicit_bare
            ],
            "derived_count": len(derived),
            "derived_observables": [
                {"kind": kind, "value": value} for kind, value in derived
            ],
            "normalization_applied": normalized != observables,
            "allowed_non_domain_taxonomy_count": len(taxonomy),
            "allowed_non_domain_artifact_count": len(artifacts),
            "allowed_non_domain_rule_shorthand_count": len(rule_shorthands),
        },
        "evidence_reference_count": len(cited),
        "corroborating_evidence_count": len(corroborating),
    }
    return validated
