"""Pure contradiction policy for authoritative analyst adjudications."""
from __future__ import annotations

from typing import Any


def _normalized_factors(
    factors: dict[str, Any],
) -> tuple[str, str, str, str, str]:
    event_status = str(factors.get("event_status") or "unknown")
    validity = str(factors.get("detection_validity") or "unknown")
    disposition = str(factors.get("activity_disposition") or "unknown")
    handling = str(factors.get("handling") or "investigate")
    duplicate_of = str(factors.get("duplicate_of") or "").strip()
    return event_status, validity, disposition, handling, duplicate_of


def _append_event(
    contradictions: list[str], event_status: str, validity: str,
) -> None:
    if event_status == "not_observed" and validity == "matched_intent":
        contradictions.append(
            "an unobserved event cannot be a validated detection-intent match"
        )


def _append_disposition(
    contradictions: list[str], disposition: str, handling: str,
) -> None:
    if disposition == "malicious" and handling in {"monitor", "no_action"}:
        contradictions.append(
            "malicious activity cannot use monitor/no_action handling"
        )
    if disposition in {"authorized_benign", "benign"} and handling == "contain":
        contradictions.append("benign or authorized activity cannot use contain handling")


def _append_duplicate(
    contradictions: list[str], duplicate_of: str, handling: str,
) -> None:
    if duplicate_of and handling in {"contain", "escalate"}:
        contradictions.append(
            "a duplicate record cannot independently authorize containment or escalation"
        )


def _append_false_positive(
    contradictions: list[str],
    outcome: str,
    disposition: str,
    handling: str,
) -> None:
    if outcome.startswith("false_positive_"):
        if disposition in {"malicious", "suspicious"}:
            contradictions.append(
                "a false-positive label cannot classify activity as malicious or suspicious"
            )
        if handling in {"contain", "escalate"}:
            contradictions.append(
                "a false-positive label cannot authorize containment or escalation"
            )


def verdict_contradictions(
    runner: Any,
    outcome: str,
    explicit_factors: dict[str, Any],
) -> list[str]:
    supplied = {
        key: value
        for key, value in explicit_factors.items()
        if value not in (None, "")
    }
    if not supplied:
        return []
    factors = dict(runner.legacy_verdict_factors(outcome))
    factors.update(supplied)
    derived = runner.derive_legacy_detection_outcome(factors)
    contradictions: list[str] = []
    if derived != outcome:
        contradictions.append(f"factored verdict derives {derived}, not {outcome}")
    event_status, validity, disposition, handling, duplicate_of = (
        _normalized_factors(factors)
    )
    _append_event(contradictions, event_status, validity)
    _append_disposition(contradictions, disposition, handling)
    _append_duplicate(contradictions, duplicate_of, handling)
    _append_false_positive(contradictions, outcome, disposition, handling)
    return contradictions
