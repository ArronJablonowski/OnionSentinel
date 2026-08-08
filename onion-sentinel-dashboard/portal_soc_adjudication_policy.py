"""Pure validation policy for human SOC and incident adjudications."""
from __future__ import annotations

import re


SOC_ANALYST_ADJUDICATION_OUTCOMES = frozenset({
    "true_positive_malicious",
    "true_positive_suspicious",
    "true_positive_authorized_benign",
    "false_positive_logic_rule",
    "false_positive_data_parser",
    "false_positive_bad_intel_ioc",
    "false_negative",
    "duplicate",
    "informational_no_action",
    "inconclusive",
})
SOC_ANALYST_EVENT_STATUSES = frozenset({"observed", "not_observed", "unknown"})
SOC_ANALYST_DETECTION_VALIDITIES = frozenset({
    "matched_intent", "logic_error", "parser_error", "intel_error",
    "not_applicable", "unknown",
})
SOC_ANALYST_ACTIVITY_DISPOSITIONS = frozenset({
    "malicious", "suspicious", "authorized_benign", "benign", "unknown",
})
SOC_ANALYST_HANDLING_VALUES = frozenset({
    "contain", "escalate", "investigate", "monitor", "no_action",
})
FACTORED_FIELDS = {
    "event_status": SOC_ANALYST_EVENT_STATUSES,
    "detection_validity": SOC_ANALYST_DETECTION_VALIDITIES,
    "activity_disposition": SOC_ANALYST_ACTIVITY_DISPOSITIONS,
    "handling": SOC_ANALYST_HANDLING_VALUES,
}
LEGACY_FACTORS = {
    "true_positive_malicious": (
        "observed", "matched_intent", "malicious", "contain",
    ),
    "true_positive_suspicious": (
        "observed", "matched_intent", "suspicious", "investigate",
    ),
    "true_positive_authorized_benign": (
        "observed", "matched_intent", "authorized_benign", "no_action",
    ),
    "false_positive_logic_rule": (
        "observed", "logic_error", "unknown", "monitor",
    ),
    "false_positive_data_parser": (
        "unknown", "parser_error", "unknown", "investigate",
    ),
    "false_positive_bad_intel_ioc": (
        "observed", "intel_error", "unknown", "monitor",
    ),
    "false_negative": (
        "observed", "not_applicable", "malicious", "escalate",
    ),
    "duplicate": ("observed", "unknown", "unknown", "no_action"),
    "informational_no_action": (
        "observed", "not_applicable", "benign", "no_action",
    ),
    "inconclusive": ("unknown", "unknown", "unknown", "investigate"),
}


def legacy_verdict_factors(outcome: str) -> dict[str, str | None]:
    event_status, validity, disposition, handling = LEGACY_FACTORS[outcome]
    return {
        "event_status": event_status,
        "detection_validity": validity,
        "activity_disposition": disposition,
        "handling": handling,
        "duplicate_of": None,
    }


def derive_legacy_detection_outcome(factors: dict[str, str | None]) -> str:
    duplicate_of = str(factors.get("duplicate_of") or "").strip()
    validity = str(factors.get("detection_validity") or "unknown")
    event_status = str(factors.get("event_status") or "unknown")
    disposition = str(factors.get("activity_disposition") or "unknown")
    handling = str(factors.get("handling") or "investigate")
    if duplicate_of:
        return "duplicate"
    errors = {
        "parser_error": "false_positive_data_parser",
        "logic_error": "false_positive_logic_rule",
        "intel_error": "false_positive_bad_intel_ioc",
    }
    if validity in errors:
        return errors[validity]
    return _activity_outcome(validity, event_status, disposition, handling)


def _activity_outcome(
    validity: str,
    event_status: str,
    disposition: str,
    handling: str,
) -> str:
    if event_status != "observed":
        return "inconclusive"
    direct = {
        ("matched_intent", "malicious"): "true_positive_malicious",
        ("matched_intent", "suspicious"): "true_positive_suspicious",
        ("matched_intent", "authorized_benign"): (
            "true_positive_authorized_benign"
        ),
        ("not_applicable", "malicious"): "false_negative",
    }.get((validity, disposition))
    if direct:
        return direct
    informational = disposition in {"benign", "authorized_benign"} and (
        validity in {"matched_intent", "not_applicable"}
        and handling == "no_action"
    )
    return "informational_no_action" if informational else "inconclusive"


def _factor_semantic_contradictions(factors: dict[str, str | None]) -> list[str]:
    contradictions = []
    event_status = str(factors["event_status"])
    validity = str(factors["detection_validity"])
    disposition = str(factors["activity_disposition"])
    handling = str(factors["handling"])
    duplicate_of = str(factors.get("duplicate_of") or "").strip()
    if event_status == "not_observed" and validity == "matched_intent":
        contradictions.append(
            "an unobserved event cannot be a validated detection-intent match"
        )
    if disposition == "malicious" and handling in {"monitor", "no_action"}:
        contradictions.append(
            "malicious activity cannot use monitor/no_action handling"
        )
    if disposition in {"authorized_benign", "benign"} and handling == "contain":
        contradictions.append(
            "benign or authorized activity cannot use contain handling"
        )
    if duplicate_of and handling in {"contain", "escalate"}:
        contradictions.append(
            "a duplicate record cannot independently authorize containment "
            "or escalation"
        )
    return contradictions


def _false_positive_contradictions(
    outcome: str,
    factors: dict[str, str | None],
) -> list[str]:
    if not outcome.startswith("false_positive_"):
        return []
    contradictions = []
    disposition = str(factors["activity_disposition"])
    handling = str(factors["handling"])
    if disposition in {"malicious", "suspicious"}:
        contradictions.append(
            "a false-positive label cannot authoritatively classify the "
            "activity as malicious or suspicious"
        )
    if handling in {"contain", "escalate"}:
        contradictions.append(
            "a false-positive label cannot independently authorize "
            "containment or escalation"
        )
    return contradictions


def adjudication_verdict_contradictions(
    outcome: str,
    explicit_factors: dict[str, str | None],
) -> list[str]:
    supplied = {
        key: value for key, value in explicit_factors.items()
        if value not in (None, "")
    }
    if not supplied:
        return []
    factors = legacy_verdict_factors(outcome)
    factors.update(supplied)
    contradictions = []
    derived = derive_legacy_detection_outcome(factors)
    if derived != outcome:
        contradictions.append(f"factored verdict derives {derived}, not {outcome}")
    contradictions.extend(_factor_semantic_contradictions(factors))
    contradictions.extend(_false_positive_contradictions(outcome, factors))
    return contradictions


def _factored_values(payload: dict) -> tuple[dict[str, str | None], str]:
    values: dict[str, str | None] = {}
    for field, allowed in FACTORED_FIELDS.items():
        value = str(payload.get(field) or "").strip().lower()
        if value and value not in allowed:
            return {}, f"Select a valid {field.replace('_', ' ')}."
        values[field] = value or None
    return values, ""


def _duplicate_of(payload: dict) -> tuple[bool, str | None, str]:
    value = payload.get("duplicate_of")
    if value is None:
        return True, None, ""
    if not isinstance(value, str):
        return False, None, "duplicate_of must be a string identifier or null."
    duplicate = value.strip()[:256]
    if not duplicate:
        return False, None, (
            "duplicate_of must be a non-empty string identifier or null."
        )
    return True, duplicate, ""


def _error(message: str) -> tuple[bool, dict]:
    return False, {"ok": False, "error": message}


def _normalized_identifiers(group_id: str, case_id: str) -> tuple[str, str, str]:
    group = str(group_id or "").strip().lower()
    case = str(case_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", group):
        return "", "", "Invalid SOC alert group id"
    if case and not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case):
        return "", "", "Invalid incident case id"
    return group, case, ""


def _review_fields(current: dict) -> dict:
    return {
        "outcome": str(current.get("outcome_override") or "").strip().lower(),
        "confidence": str(current.get("confidence") or "").strip().lower(),
        "reviewer": str(current.get("reviewer") or "").strip()[:100],
        "rationale": str(current.get("rationale") or "").strip()[:4000],
        "resolution_reason": str(
            current.get("case_resolution_reason") or ""
        ).strip()[:2000],
    }


def _review_field_error(fields: dict) -> str:
    if fields["outcome"] not in SOC_ANALYST_ADJUDICATION_OUTCOMES:
        return "Select a valid analyst outcome."
    if fields["confidence"] not in {"low", "medium", "high"}:
        return "Select low, medium, or high confidence."
    if not fields["rationale"] or not fields["reviewer"]:
        return "Reviewer and rationale are required."
    return ""


def _resolution_type_error(current: dict) -> str:
    if "resolve_case" in current and not isinstance(
        current.get("resolve_case"), bool
    ):
        return "resolve_case must be a JSON boolean."
    return ""


def _resolution_requirement_error(
    current: dict,
    case_id: str,
    reason: str,
) -> str:
    if current.get("resolve_case") is True and (not case_id or not reason):
        return "A case resolution reason is required when resolving a case."
    return ""


def _factored_and_duplicate(
    current: dict,
) -> tuple[dict[str, str | None], str | None, str]:
    factored, error = _factored_values(current)
    if error:
        return {}, None, error
    valid, duplicate_of, error = _duplicate_of(current)
    return (factored, duplicate_of, error) if valid else ({}, None, error)


def _semantic_review_error(
    fields: dict,
    factored: dict[str, str | None],
    duplicate_of: str | None,
) -> str:
    error = _review_field_error(fields)
    if error:
        return error
    contradictions = adjudication_verdict_contradictions(
        fields["outcome"], {**factored, "duplicate_of": duplicate_of}
    )
    if not contradictions:
        return ""
    return (
        "Analyst outcome conflicts with the explicit verdict factors: "
        + "; ".join(contradictions)
    )[:1000]


def _normalized_adjudication(
    current: dict,
    group_id: str,
    case_id: str,
    fields: dict,
    factored: dict[str, str | None],
    duplicate_of: str | None,
) -> dict:
    return {
        "group_id": group_id,
        "case_id": case_id or None,
        "analysis_id": str(current.get("analysis_id") or "").strip()[:160],
        "outcome_override": fields["outcome"],
        "confidence": fields["confidence"],
        "rationale": fields["rationale"],
        "evidence_gap": str(current.get("evidence_gap") or "").strip()[:4000],
        "next_action": str(current.get("next_action") or "").strip()[:4000],
        "reviewer": fields["reviewer"],
        **factored,
        "duplicate_of": duplicate_of,
        "resolve_case": current.get("resolve_case") is True,
        "case_resolution_reason": fields["resolution_reason"],
    }


def normalize_soc_adjudication_payload(
    payload: dict | None,
    *,
    group_id: str,
    case_id: str = "",
) -> tuple[bool, dict]:
    current = payload if isinstance(payload, dict) else {}
    normalized_group, normalized_case, identifier_error = (
        _normalized_identifiers(group_id, case_id)
    )
    if identifier_error:
        return _error(identifier_error)
    fields = _review_fields(current)
    resolution_error = _resolution_type_error(current)
    if resolution_error:
        return _error(resolution_error)
    factored, duplicate_of, component_error = _factored_and_duplicate(current)
    if component_error:
        return _error(component_error)
    semantic_error = _semantic_review_error(fields, factored, duplicate_of)
    if semantic_error:
        return _error(semantic_error)
    resolution_error = _resolution_requirement_error(
        current, normalized_case, fields["resolution_reason"]
    )
    if resolution_error:
        return _error(resolution_error)
    return True, _normalized_adjudication(
        current,
        normalized_group,
        normalized_case,
        fields,
        factored,
        duplicate_of,
    )
