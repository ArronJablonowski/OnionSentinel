"""Pure normalization of orthogonal verdict dimensions and legacy outcomes."""
from __future__ import annotations

import re
from typing import Any, Callable, Collection, Mapping


ALIASES = {
    "true_positive_benign": "true_positive_authorized_benign",
    "authorized_benign": "true_positive_authorized_benign",
    "false_positive_rule_logic": "false_positive_logic_rule",
    "false_positive_parser": "false_positive_data_parser",
    "false_positive_intel": "false_positive_bad_intel_ioc",
}


def _token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def normalize_outcome(value: Any, *, allowed: Collection[str]) -> str:
    """Return a canonical compatibility outcome or ``inconclusive``."""
    outcome = ALIASES.get(_token(value), _token(value))
    return outcome if outcome in allowed else "inconclusive"


def legacy_factors(outcome: str, *, escalation_needed: bool = False) -> dict[str, Any]:
    """Map a compatibility outcome into orthogonal verdict dimensions."""
    handling_for_risk = "escalate" if escalation_needed else "investigate"
    mapping: dict[str, tuple[str, str, str, str]] = {
        "true_positive_malicious": ("observed", "matched_intent", "malicious", "contain"),
        "true_positive_suspicious": ("observed", "matched_intent", "suspicious", handling_for_risk),
        "true_positive_authorized_benign": ("observed", "matched_intent", "authorized_benign", "no_action"),
        "false_positive_logic_rule": ("observed", "logic_error", "unknown", "monitor"),
        "false_positive_data_parser": ("unknown", "parser_error", "unknown", "investigate"),
        "false_positive_bad_intel_ioc": ("observed", "intel_error", "unknown", "monitor"),
        "false_negative": ("observed", "not_applicable", "malicious", "escalate"),
        "duplicate": ("observed", "unknown", "unknown", "no_action"),
        "informational_no_action": ("observed", "not_applicable", "benign", "no_action"),
        "inconclusive": ("unknown", "unknown", "unknown", "investigate"),
    }
    event_status, validity, disposition, handling = mapping.get(outcome, mapping["inconclusive"])
    return {
        "event_status": event_status,
        "detection_validity": validity,
        "activity_disposition": disposition,
        "handling": handling,
        "duplicate_of": None,
    }


def _factor_text(
    factors: Mapping[str, Any],
    key: str,
    default: str,
) -> str:
    return str(factors.get(key) or default)


def derive_outcome(factors: Mapping[str, Any]) -> str:
    """Derive the compatibility outcome from normalized dimensions."""
    duplicate_of = _factor_text(factors, "duplicate_of", "").strip()
    validity = _factor_text(factors, "detection_validity", "unknown")
    event_status = _factor_text(factors, "event_status", "unknown")
    disposition = _factor_text(factors, "activity_disposition", "unknown")
    handling = _factor_text(factors, "handling", "investigate")
    if duplicate_of:
        return "duplicate"
    error_outcomes = {
        "parser_error": "false_positive_data_parser",
        "logic_error": "false_positive_logic_rule",
        "intel_error": "false_positive_bad_intel_ioc",
    }
    if validity in error_outcomes:
        return error_outcomes[validity]
    if event_status != "observed":
        return "inconclusive"
    direct = {
        ("matched_intent", "malicious"): "true_positive_malicious",
        ("matched_intent", "suspicious"): "true_positive_suspicious",
        ("matched_intent", "authorized_benign"): "true_positive_authorized_benign",
        ("not_applicable", "malicious"): "false_negative",
    }.get((validity, disposition))
    if direct:
        return direct
    informational = {
        ("matched_intent", "benign", "no_action"),
        ("not_applicable", "benign", "no_action"),
        ("not_applicable", "authorized_benign", "no_action"),
    }
    return (
        "informational_no_action"
        if (validity, disposition, handling) in informational
        else "inconclusive"
    )


def _apply_supplied(
    response: Mapping[str, Any],
    factors: dict[str, Any],
    *,
    enum_fields: Mapping[str, Collection[str]],
) -> tuple[list[str], dict[str, Any]]:
    supplied: list[str] = []
    invalid: dict[str, Any] = {}
    for key, allowed in enum_fields.items():
        if key not in response:
            continue
        supplied.append(key)
        normalized = _token(response.get(key))
        if normalized in allowed:
            factors[key] = normalized
        else:
            invalid[key] = response.get(key)
    if "duplicate_of" in response:
        supplied.append("duplicate_of")
        duplicate = response.get("duplicate_of")
        if duplicate in (None, ""):
            factors["duplicate_of"] = None
        elif isinstance(duplicate, (str, int)):
            factors["duplicate_of"] = str(duplicate).strip()[:256] or None
        else:
            invalid["duplicate_of"] = duplicate
    return supplied, invalid


def _contradictions(factors: Mapping[str, Any], canonical: str) -> list[str]:
    rules = (
        (
            factors["event_status"] == "not_observed"
            and factors["detection_validity"] == "matched_intent",
            "an unobserved event cannot be a validated detection-intent match",
        ),
        (
            factors["activity_disposition"] == "malicious"
            and factors["handling"] in {"monitor", "no_action"},
            "malicious activity cannot use monitor/no_action handling",
        ),
        (
            factors["activity_disposition"] in {"authorized_benign", "benign"}
            and factors["handling"] == "contain",
            "benign or authorized activity cannot use contain handling",
        ),
        (
            factors["duplicate_of"]
            and factors["handling"] in {"contain", "escalate"},
            "a duplicate record cannot independently authorize containment or escalation",
        ),
        (
            canonical == "duplicate" and not factors["duplicate_of"],
            "a duplicate outcome must identify the canonical alert or group in duplicate_of",
        ),
    )
    return [message for contradicted, message in rules if contradicted]


def normalize(
    response: dict[str, Any],
    *,
    outcome_values: Collection[str],
    event_status_values: Collection[str],
    validity_values: Collection[str],
    disposition_values: Collection[str],
    handling_values: Collection[str],
    factored_keys: Collection[str],
    boolean_setting: Callable[[Any], bool],
) -> dict[str, Any]:
    """Normalize factored fields and reconcile the compatibility outcome."""
    raw_outcome = response.get("detection_outcome")
    canonical = normalize_outcome(raw_outcome, allowed=outcome_values)
    invalid = _outcome_invalid(raw_outcome, outcome_values)
    factors = legacy_factors(
        canonical,
        escalation_needed=boolean_setting(response.get("escalation_needed")),
    )
    supplied, supplied_invalid = _apply_supplied(
        response,
        factors,
        enum_fields=_enum_fields(
            event_status_values, validity_values,
            disposition_values, handling_values,
        ),
    )
    invalid.update(supplied_invalid)
    derived = derive_outcome(factors)
    contradictions = _contradictions(factors, canonical)
    warnings = _mismatch_findings(
        supplied, derived, canonical, factored_keys, invalid, contradictions
    )
    source, canonical_outcome = _verdict_source_and_outcome(
        supplied, factored_keys, derived, canonical
    )
    response.update(factors)
    response["detection_outcome"] = canonical_outcome
    response["_verdict_validation"] = _validation_projection(
        source, raw_outcome, canonical_outcome, derived,
        supplied, invalid, contradictions, warnings,
    )
    return response


def _validation_projection(
    source: str,
    raw_outcome: Any,
    canonical_outcome: str,
    derived: str,
    supplied: list[str],
    invalid: Mapping[str, Any],
    contradictions: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    return {
        "version": 1,
        "source": source,
        "model_detection_outcome": raw_outcome,
        "canonical_legacy_outcome": canonical_outcome,
        "derived_legacy_outcome": derived,
        "supplied_factored_fields": sorted(supplied),
        "invalid_fields": invalid,
        "contradictions": contradictions,
        "warnings": warnings,
        "material_contradiction": bool(contradictions or invalid),
    }


def _outcome_invalid(
    raw_outcome: Any,
    outcome_values: Collection[str],
) -> dict[str, Any]:
    if _token(raw_outcome) not in set(outcome_values) | set(ALIASES):
        return {"detection_outcome": raw_outcome}
    return {}


def _enum_fields(
    event_status_values: Collection[str],
    validity_values: Collection[str],
    disposition_values: Collection[str],
    handling_values: Collection[str],
) -> dict[str, Collection[str]]:
    return {
        "event_status": event_status_values,
        "detection_validity": validity_values,
        "activity_disposition": disposition_values,
        "handling": handling_values,
    }


def _verdict_source_and_outcome(
    supplied: list[str],
    factored_keys: Collection[str],
    derived: str,
    canonical: str,
) -> tuple[str, str]:
    source = "legacy_derived" if not supplied else (
        "model_factored" if len(supplied) == len(factored_keys) else "hybrid"
    )
    return source, derived if supplied else canonical


def _mismatch_findings(
    supplied: list[str],
    derived: str,
    canonical: str,
    factored_keys: Collection[str],
    invalid: Mapping[str, Any],
    contradictions: list[str],
) -> list[str]:
    warnings: list[str] = []
    if supplied and derived != canonical:
        mismatch = f"factored verdict derives {derived}, but model supplied {canonical}"
        if len(supplied) == len(factored_keys) and not invalid:
            warnings.append(mismatch)
        else:
            contradictions.insert(0, mismatch)
    return warnings
