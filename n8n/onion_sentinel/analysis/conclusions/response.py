"""Ordered response normalization and conclusion-guard composition."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class Policy:
    required_keys: frozenset[str]
    strict_required_keys: frozenset[str]
    default_values: Mapping[str, Any]
    strict_default_values: Mapping[str, Any]
    list_keys: frozenset[str]
    confidence_values: frozenset[str]
    tuning_values: frozenset[str]
    detection_outcome_values: frozenset[str]
    legacy_detection_outcomes: frozenset[str]


@dataclass(frozen=True)
class Dependencies:
    boolean_setting: Callable[[Any], bool]
    coerce_list: Callable[[Any], list[Any]]
    normalize_correlation: Callable[[Any], dict[str, Any]]
    normalize_memory: Callable[[Any], list[Any]]
    normalize_hypotheses: Callable[[Any], list[Any]]
    is_incident_responder: Callable[[dict[str, Any] | None], bool]
    validate_report_shape: Callable[[Any], dict[str, Any]]
    normalize_report: Callable[[Any], dict[str, Any]]
    normalize_factored: Callable[[dict[str, Any]], dict[str, Any]]
    guards: tuple[
        Callable[[dict[str, Any], dict[str, Any] | None], dict[str, Any]], ...
    ]
    normalize_scope: Callable[
        [dict[str, Any], dict[str, Any] | None], dict[str, Any]
    ]
    calibrate_confidence: Callable[[dict[str, Any]], dict[str, Any]]
    reconcile_report: Callable[
        [dict[str, Any], dict[str, Any] | None], dict[str, Any]
    ]


def _strict_contract(
    prompt_package: dict[str, Any] | None,
    policy: Policy,
    dependencies: Dependencies,
) -> bool:
    if not isinstance(prompt_package, dict):
        return False
    schema = prompt_package.get("response_schema")
    return bool(
        isinstance(prompt_package.get("review_contract"), dict)
        or dependencies.is_incident_responder(prompt_package)
        or (
            isinstance(schema, dict)
            and policy.strict_required_keys.issubset(schema)
        )
    )


def _strip_intermediate_protocol(normalized: dict[str, Any]) -> None:
    for key in (
        "investigation_query_requests", "pcap_query_requests",
        "live_osquery_requests",
    ):
        normalized.pop(key, None)


def _repair_missing(
    normalized: dict[str, Any],
    strict: bool,
    policy: Policy,
) -> None:
    required = set(policy.required_keys)
    if strict:
        required.update(policy.strict_required_keys)
    missing = sorted(required.difference(normalized))
    for key in missing:
        normalized[key] = policy.default_values.get(
            key, policy.strict_default_values.get(key, "n/a")
        )
    if missing:
        normalized["_schema_repair"] = {
            "missing_keys": missing,
            "repair_note": (
                "Filled safe defaults so the alert still receives local AI analysis."
            ),
        }


def _normalize_core(
    normalized: dict[str, Any],
    strict: bool,
    policy: Policy,
    dependencies: Dependencies,
) -> None:
    for key in policy.list_keys:
        normalized[key] = dependencies.coerce_list(normalized.get(key))
    for key in (
        "detection_outcome", "bluf", "summary", "likely_meaning",
        "severity_reasoning", "alert_frequency_assessment", "tuning_reason",
    ):
        normalized[key] = str(normalized[key])
    normalized["confidence"] = str(normalized["confidence"]).lower()
    normalized["tuning_recommendation"] = str(
        normalized["tuning_recommendation"]
    ).lower()
    normalized["escalation_needed"] = dependencies.boolean_setting(
        normalized["escalation_needed"]
    )
    normalized["hosted_second_opinion_recommended"] = dependencies.boolean_setting(
        normalized["hosted_second_opinion_recommended"]
    )
    normalized["second_opinion_recommended"] = dependencies.boolean_setting(
        normalized.get("second_opinion_recommended", False)
    )
    normalized["second_opinion_reason"] = str(
        normalized.get("second_opinion_reason") or ""
    )[:1000]
    normalized["correlation_assessment"] = dependencies.normalize_correlation(
        normalized.get("correlation_assessment")
    )
    normalized["memory_candidates"] = dependencies.normalize_memory(
        normalized.get("memory_candidates")
    )
    if strict or "hypotheses" in normalized:
        normalized["hypotheses"] = dependencies.normalize_hypotheses(
            normalized.get("hypotheses")
        )


def _report_repair(
    normalized: dict[str, Any],
    validation: dict[str, Any],
) -> None:
    repair = (
        dict(normalized.get("_schema_repair"))
        if isinstance(normalized.get("_schema_repair"), dict) else {}
    )
    existing = repair.get("missing_keys")
    repaired_keys = {
        str(item) for item in existing if isinstance(existing, list)
    }
    repaired_keys.update(
        f"incident_response_report.{key}"
        for key in validation["missing_fields"]
    )
    if not validation["model_report_present"]:
        repaired_keys.add("incident_response_report")
    repair["missing_keys"] = sorted(repaired_keys)
    repair["repair_note"] = (
        "Filled safe defaults and marked the Incident Responder output "
        "for human review because its required report was incomplete."
    )
    normalized["_schema_repair"] = repair


def _normalize_incident_report(
    normalized: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    dependencies: Dependencies,
) -> None:
    if dependencies.is_incident_responder(prompt_package):
        raw = normalized.get("incident_response_report")
        validation = dependencies.validate_report_shape(raw)
        normalized["incident_response_report"] = dependencies.normalize_report(raw)
        normalized["_incident_response_report_validation"] = validation
        if not validation["valid"]:
            _report_repair(normalized, validation)
        return
    if "incident_response_report" in normalized:
        normalized["incident_response_report"] = dependencies.normalize_report(
            normalized.get("incident_response_report")
        )
        normalized["incident_response_report"].pop("confidence_score", None)


def _validate_vocabularies(normalized: dict[str, Any], policy: Policy) -> None:
    if normalized["confidence"] not in policy.confidence_values:
        normalized["_invalid_confidence"] = normalized["confidence"]
        normalized["confidence"] = "low"
    if normalized["tuning_recommendation"] not in policy.tuning_values:
        normalized["_invalid_tuning_recommendation"] = normalized[
            "tuning_recommendation"
        ]
        normalized["tuning_recommendation"] = "needs_more_data"
    outcome = re.sub(
        r"[^a-z0-9]+", "_", normalized["detection_outcome"].strip().lower()
    ).strip("_")
    if (
        outcome not in policy.detection_outcome_values
        and outcome not in policy.legacy_detection_outcomes
    ):
        normalized["_invalid_detection_outcome"] = normalized[
            "detection_outcome"
        ]


def normalize(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Normalize one response and apply every conclusion guard in fixed order."""
    normalized = dict(response)
    _strip_intermediate_protocol(normalized)
    strict = _strict_contract(prompt_package, policy, dependencies)
    _repair_missing(normalized, strict, policy)
    _normalize_core(normalized, strict, policy, dependencies)
    _normalize_incident_report(normalized, prompt_package, dependencies)
    _validate_vocabularies(normalized, policy)
    normalized = dependencies.normalize_factored(normalized)
    for guard in dependencies.guards:
        normalized = guard(normalized, prompt_package)
    normalized = dependencies.normalize_scope(normalized, prompt_package)
    normalized = dependencies.calibrate_confidence(normalized)
    normalized = dependencies.reconcile_report(normalized, prompt_package)
    normalized.setdefault("final_disposition_status", "primary_unreviewed")
    return normalized
