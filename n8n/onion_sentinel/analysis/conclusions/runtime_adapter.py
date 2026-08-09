"""Concrete conclusion normalization and guard bindings."""
from __future__ import annotations

import re
from typing import Any, Mapping


def coerce_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return [] if value in (None, "") else [str(value)]


def bounded_text(value: Any, limit: int = 8000) -> str:
    return str(value or "")[:limit]


def bounded_text_list(
    value: Any, limit: int = 50, item_limit: int = 4000,
) -> list[str]:
    return [bounded_text(item, item_limit) for item in coerce_list(value)[:limit]]


def normalize_hypotheses(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output: list[dict[str, Any]] = []
    for item in value[:20]:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unresolved").strip().lower()
        if status not in {"supported", "contradicted", "unresolved"}:
            status = "unresolved"
        identifier = re.sub(
            r"[^A-Za-z0-9._-]+", "-",
            str(item.get("id") or f"hypothesis-{len(output) + 1}"),
        ).strip("-")[:64]
        statement = bounded_text(item.get("statement"), 2000)
        if not identifier or not statement:
            continue
        output.append({
            "id": identifier, "statement": statement, "status": status,
            "supporting_evidence": bounded_text_list(
                item.get("supporting_evidence"), limit=20, item_limit=500),
            "contradicting_evidence": bounded_text_list(
                item.get("contradicting_evidence"), limit=20, item_limit=500),
            "next_discriminator": bounded_text(
                item.get("next_discriminator"), 1000),
        })
    return output


def safe_nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def normalize_correlation(b: Mapping[str, Any], value: Any) -> dict[str, Any]:
    return b["_conclusion_correlation"]().normalize(
        value, confidence_values=frozenset(b["CONFIDENCE_VALUES"]))


def normalized_outcome(b: Mapping[str, Any], value: Any) -> str:
    return b["_conclusion_verdict"]().normalize_outcome(
        value, allowed=b["DETECTION_OUTCOME_VALUES"])


def legacy_factors(
    b: Mapping[str, Any], outcome: str, *, escalation_needed: bool = False,
) -> dict[str, Any]:
    return b["_conclusion_verdict"]().legacy_factors(
        outcome, escalation_needed=escalation_needed)


def derive_outcome(b: Mapping[str, Any], factors: dict[str, Any]) -> str:
    return b["_conclusion_verdict"]().derive_outcome(factors)


def normalize_verdict(
    b: Mapping[str, Any], response: dict[str, Any],
) -> dict[str, Any]:
    return b["_conclusion_verdict"]().normalize(
        response, outcome_values=b["DETECTION_OUTCOME_VALUES"],
        event_status_values=b["EVENT_STATUS_VALUES"],
        validity_values=b["DETECTION_VALIDITY_VALUES"],
        disposition_values=b["ACTIVITY_DISPOSITION_VALUES"],
        handling_values=b["HANDLING_VALUES"],
        factored_keys=b["FACTORED_VERDICT_KEYS"],
        boolean_setting=b["boolean_setting"])


def normalize_scope(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any] | None,
) -> dict[str, Any]:
    return b["_conclusion_scope"]().normalize(
        response, package, policy=b["_conclusion_scope_policy"](),
        dependencies=b["_conclusion_scope_dependencies"]())


def has_trusted_endpoint_evidence(
    b: Mapping[str, Any], package: dict[str, Any] | None,
) -> bool:
    return b["_evidence_endpoint"]().has_trusted_evidence(
        package, policy=b["_evidence_endpoint_policy"](),
        dependencies=b["_evidence_endpoint_dependencies"]())


def trusted_endpoint_fields(
    b: Mapping[str, Any], package: dict[str, Any] | None,
) -> set[str]:
    return b["_evidence_endpoint"]().trusted_fields(
        package, policy=b["_evidence_endpoint_policy"]())


def remove_supplied_executable_path_gap(text: Any) -> tuple[str, bool]:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    if not value or not re.search(
        r"\b(?:process\.)?executable path(?:s)?\b", value, re.IGNORECASE
    ):
        return value, False
    rewritten = re.sub(
        r"\b(?:process\.)?executable path(?:s)?\s*,\s*", "", value,
        count=1, flags=re.IGNORECASE)
    if rewritten != value:
        return re.sub(r"\s+", " ", rewritten).strip(), True
    markers = (
        "missing", "absent", "unavailable", "not supplied", "not provided",
        "not present", "not available", "required", "needed", "obtain", "collect")
    return ("", True) if any(m in value.lower() for m in markers) else (value, False)


def reconcile_endpoint_gaps(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any] | None,
) -> dict[str, Any]:
    if "process.executable" not in b["_trusted_endpoint_evidence_fields"](package):
        return response
    rewritten_count = 0
    removed_count = 0

    def reconcile(container: dict[str, Any], key: str) -> None:
        nonlocal rewritten_count, removed_count
        values = container.get(key)
        if not isinstance(values, list):
            return
        normalized: list[Any] = []
        for item in values:
            if not isinstance(item, str):
                normalized.append(item)
                continue
            rewritten, changed = b["_remove_supplied_executable_path_gap"](item)
            if not changed:
                normalized.append(item)
            elif rewritten:
                normalized.append(rewritten)
                rewritten_count += 1
            else:
                removed_count += 1
        container[key] = normalized

    reconcile(response, "evidence_gaps")
    reconcile(response, "additional_evidence_needed")
    report = response.get("incident_response_report")
    if isinstance(report, dict):
        reconcile(report, "evidence_gaps")
        reconcile(report, "constraints")
    if rewritten_count or removed_count:
        response["_endpoint_evidence_gap_reconciliation"] = {
            "schema": "onion-sentinel-endpoint-evidence-gap-reconciliation-v1",
            "executable_path_supplied": True,
            "rewritten_gap_count": rewritten_count,
            "removed_gap_count": removed_count,
        }
    return response


def consequential(b: Mapping[str, Any], response: dict[str, Any]) -> bool:
    return b["_conclusion_evidence_guard"]().consequential(
        response, b["_evidence_guard_dependencies"]())


def evidence_guard(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any] | None,
) -> dict[str, Any]:
    return b["_conclusion_evidence_guard"]().apply(
        response, package, b["_evidence_guard_dependencies"]())


def confidence_label(b: Mapping[str, Any], score: float) -> str:
    return b["_conclusion_confidence"]().label(
        score, low_threshold=b["CONFIDENCE_LOW_THRESHOLD"],
        high_threshold=b["CONFIDENCE_HIGH_THRESHOLD"])


def calibrate_confidence(
    b: Mapping[str, Any], response: dict[str, Any],
) -> dict[str, Any]:
    return b["_conclusion_confidence"]().calibrate(
        response, confidence_values=b["CONFIDENCE_VALUES"],
        score_by_label=b["CONFIDENCE_SCORE_BY_LABEL"],
        calibration_version=b["CONFIDENCE_CALIBRATION_VERSION"],
        critical_keys=b["DECISION_CRITICAL_KEYS"],
        consequential_outcomes=b["CONSEQUENTIAL_CLOSURE_OUTCOMES"],
        outcome_normalizer=b["normalized_detection_outcome"],
        label_for_score=b["confidence_label_for_score"])


def is_incident_responder(package: dict[str, Any] | None) -> bool:
    if not isinstance(package, dict):
        return False
    role = str(package.get("agent_role") or "").strip().lower().replace("_", "-")
    return role == "incident-responder"


def has_authorization_evidence(
    b: Mapping[str, Any], package: dict[str, Any] | None,
) -> bool:
    return b["_conclusion_authorization_evidence"]().has_structured_evidence(package)


def tuning_guard(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any] | None,
) -> dict[str, Any]:
    return b["_conclusion_tuning"]().apply(
        response, package, b["_tuning_guard_dependencies"]())


def authorization_guard(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any] | None,
    *, policy_sensitive: bool,
) -> dict[str, Any]:
    module = b["_conclusion_authorization"]()
    operation = module.apply_policy_sensitive if policy_sensitive else module.apply_authorized_benign
    return operation(response, package, b["_authorization_guard_dependencies"]())


def validate_report_shape(b: Mapping[str, Any], value: Any) -> dict[str, Any]:
    return b["_conclusion_incident_report"]().validate_shape(
        value, b["_incident_report_dependencies"]())


def normalize_report(b: Mapping[str, Any], value: Any) -> dict[str, Any]:
    return b["_conclusion_incident_report"]().normalize(
        value, b["_incident_report_dependencies"]())


def completeness_guard(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any] | None,
) -> dict[str, Any]:
    return b["_conclusion_incident_completeness"]().apply(
        response, package, b["_incident_completeness_dependencies"]())


def reconcile_report(
    b: Mapping[str, Any], response: dict[str, Any], package: dict[str, Any] | None,
) -> dict[str, Any]:
    return b["_conclusion_incident_report"]().reconcile(
        response, package, b["_incident_report_dependencies"]())
