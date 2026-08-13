"""Durable Incident Responder report schema and narrative reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import re
from typing import Any, Callable


_INVALID_TIMELINE_ITEM = object()


@dataclass(frozen=True)
class Dependencies:
    is_incident_responder: Callable[[dict[str, Any] | None], bool]
    bounded_text: Callable[[Any, int], str]
    bounded_text_list: Callable[..., list[str]]
    normalized_outcome: Callable[[Any], str]
    outcome_labels: dict[str, str]
    confidence_values: frozenset[str]
    confidence_score_by_label: dict[str, float]
    required_fields: frozenset[str]
    text_fields: frozenset[str]
    list_fields: frozenset[str]


def timeline_timestamp(value: Any) -> dt.datetime | None:
    """Parse a timeline timestamp for deterministic ordering."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _timeline_validation(
    timeline: Any, confidence_values: frozenset[str]
) -> tuple[int, int, bool]:
    invalid = 0
    unparseable = 0
    instants: list[dt.datetime] = []
    if isinstance(timeline, list):
        for item in timeline[:200]:
            item_invalid, instant = _timeline_item_validation(
                item, confidence_values
            )
            if item_invalid:
                invalid += 1
            if instant is _INVALID_TIMELINE_ITEM:
                continue
            if instant is None:
                unparseable += 1
            else:
                instants.append(instant)
    out_of_order = any(later < earlier for earlier, later in zip(instants, instants[1:]))
    return invalid, unparseable, out_of_order


def _timeline_item_validation(
    item: Any,
    confidence_values: frozenset[str],
) -> tuple[bool, Any]:
    if not isinstance(item, dict):
        return True, _INVALID_TIMELINE_ITEM
    if any(
        not isinstance(item.get(key), str)
        or not str(item.get(key) or "").strip()
        for key in ("timestamp", "event", "source_pack")
    ):
        return True, _INVALID_TIMELINE_ITEM
    invalid = (
        str(item.get("confidence") or "").strip().lower()
        not in confidence_values
    )
    return invalid, timeline_timestamp(item.get("timestamp"))


def _field_validation(report: dict[str, Any], deps: Dependencies) -> list[str]:
    return [
        *_invalid_text_fields(report, deps.text_fields),
        *_invalid_list_fields(report, deps.list_fields),
    ]


def _invalid_text_fields(
    report: dict[str, Any],
    text_fields: frozenset[str],
) -> list[str]:
    invalid: list[str] = []
    for key in text_fields:
        if key in report and (
            not isinstance(report.get(key), str) or not str(report.get(key) or "").strip()
        ):
            invalid.append(key)
    return invalid


def _invalid_list_fields(
    report: dict[str, Any],
    list_fields: frozenset[str],
) -> list[str]:
    invalid: list[str] = []
    for key in list_fields:
        if key not in report:
            continue
        items = report.get(key)
        if not isinstance(items, list):
            invalid.append(key)
        elif key != "factual_timeline" and any(
            not isinstance(item, str) or not item.strip() for item in items
        ):
            invalid.append(f"{key}[]")
    return invalid


def _confidence_validation(report: dict[str, Any], deps: Dependencies) -> list[str]:
    invalid: list[str] = []
    confidence = str(report.get("confidence") or "").strip().lower()
    if "confidence" in report and confidence not in deps.confidence_values:
        invalid.append("confidence")
    score = report.get("confidence_score")
    if "confidence_score" in report and (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0.0 <= score <= 1.0
    ):
        invalid.append("confidence_score")
    return invalid


def validate_shape(value: Any, deps: Dependencies) -> dict[str, Any]:
    """Describe missing or malformed responder fields without trusting prose."""
    report = value if isinstance(value, dict) else {}
    missing = sorted(deps.required_fields.difference(report))
    invalid = _field_validation(report, deps)
    if not isinstance(value, dict):
        invalid.append("incident_response_report")
    timeline = report.get("factual_timeline")
    bad_timeline, unparseable, out_of_order = _timeline_validation(
        timeline, deps.confidence_values
    )
    invalid.extend(_confidence_validation(report, deps))
    invalid = sorted(set(invalid))
    return {
        "required": True,
        "model_report_present": isinstance(value, dict),
        "valid": not missing and not invalid and bad_timeline == 0 and unparseable == 0,
        "missing_fields": missing,
        "invalid_fields": invalid,
        "timeline_entries_received": len(timeline) if isinstance(timeline, list) else 0,
        "invalid_timeline_entries": bad_timeline,
        "unparseable_timeline_entries": unparseable,
        "timeline_out_of_order": out_of_order,
        "timeline_reordering_required": out_of_order,
    }


def _confidence(report: dict[str, Any], deps: Dependencies) -> tuple[str, float]:
    confidence = deps.bounded_text(report.get("confidence") or "low", 20).lower()
    if confidence not in deps.confidence_values:
        confidence = "low"
    try:
        score = float(report.get("confidence_score"))
    except (TypeError, ValueError, OverflowError):
        score = deps.confidence_score_by_label[confidence]
    if not 0.0 <= score <= 1.0:
        score = deps.confidence_score_by_label[confidence]
    return confidence, score


def _timeline(report: dict[str, Any], deps: Dependencies) -> list[dict[str, str]]:
    timeline: list[dict[str, str]] = []
    raw = report.get("factual_timeline")
    if isinstance(raw, list):
        for item in raw[:200]:
            if not isinstance(item, dict):
                continue
            confidence = deps.bounded_text(item.get("confidence") or "low", 20).lower()
            if confidence not in deps.confidence_values:
                confidence = "low"
            timeline.append({
                "timestamp": deps.bounded_text(item.get("timestamp"), 100),
                "event": deps.bounded_text(item.get("event"), 4000),
                "source_pack": deps.bounded_text(item.get("source_pack"), 200),
                "query_digest": deps.bounded_text(item.get("query_digest"), 128),
                "confidence": confidence,
            })
    maximum = dt.datetime.max.replace(tzinfo=dt.timezone.utc)
    return [
        item for _, item in sorted(
            enumerate(timeline),
            key=lambda pair: (
                timeline_timestamp(pair[1].get("timestamp")) is None,
                timeline_timestamp(pair[1].get("timestamp")) or maximum,
                pair[0],
            ),
        )
    ]


def normalize(value: Any, deps: Dependencies) -> dict[str, Any]:
    """Normalize and bound a durable responder report."""
    report = value if isinstance(value, dict) else {}
    confidence, score = _confidence(report, deps)
    methodology = report.get("methodology")
    if not methodology and report.get("confirmed_facts"):
        methodology = [
            "Reviewed the supplied alert, enrichment, packet, and Security Onion evidence."
        ]
    text = deps.bounded_text
    values = deps.bounded_text_list
    return {
        "executive_bluf": text(report.get("executive_bluf") or report.get("case_summary"), 8000),
        "detection_outcome_reasoning": text(report.get("detection_outcome_reasoning"), 8000),
        "scope": text(report.get("scope"), 8000),
        "affected_systems": values(report.get("affected_systems")),
        "constraints": values(report.get("constraints")),
        "methodology": values(methodology),
        "factual_timeline": _timeline(report, deps),
        "security_onion_findings": values(report.get("security_onion_findings")),
        "osquery_findings": values(report.get("osquery_findings")),
        "pcap_findings": values(report.get("pcap_findings")),
        "host_findings": values(report.get("host_findings")),
        "correlation_findings": values(report.get("correlation_findings")),
        "containment_recommendations": values(report.get("containment_recommendations")),
        "eradication_recommendations": values(report.get("eradication_recommendations")),
        "recovery_recommendations": values(report.get("recovery_recommendations")),
        "follow_up_queries": values(report.get("follow_up_queries")),
        "evidence_gaps": values(report.get("evidence_gaps") or report.get("constraints")),
        "conclusion": text(report.get("conclusion") or report.get("case_summary"), 8000),
        "confidence": confidence,
        "confidence_score": round(score, 3),
    }


def canonical_disposition(response: dict[str, Any], deps: Dependencies) -> str:
    outcome = deps.normalized_outcome(response.get("detection_outcome"))
    label = deps.outcome_labels.get(outcome, "Inconclusive")
    return (
        f"{label}: the canonical runtime disposition records "
        f"event_status={response.get('event_status') or 'unknown'}, "
        f"detection_validity={response.get('detection_validity') or 'unknown'}, "
        f"activity_disposition={response.get('activity_disposition') or 'unknown'}, "
        f"and handling={response.get('handling') or 'investigate'}."
    )


def human_review_actions(response: dict[str, Any]) -> dict[str, list[str]]:
    """Replace superseded action prose with canonical, non-automatic guidance."""
    handling = str(response.get("handling") or "investigate").strip().lower()
    if handling == "contain":
        containment = (
            "Do not execute containment steps from the superseded model report automatically. "
            "Canonical handling=contain requires a human incident responder to validate scope "
            "and approve proportionate containment."
        )
    elif handling == "escalate":
        containment = (
            "Do not initiate containment from the superseded model report automatically. "
            "Canonical handling=escalate requires prompt human review and an explicit "
            "containment decision."
        )
    else:
        containment = (
            "Do not initiate containment from the superseded model report. "
            f"Canonical handling={handling} does not authorize automatic containment; "
            "complete human review before changing host or network state."
        )
    return {
        "containment_recommendations": [containment],
        "eradication_recommendations": [
            "Do not execute eradication steps from the superseded model report. "
            "Preserve evidence and require a human responder to confirm compromise, "
            "scope, and the approved remediation plan first."
        ],
        "recovery_recommendations": [
            "Do not execute recovery steps from the superseded model report. "
            "A human responder must confirm impact and approve recovery criteria "
            "after any validated containment or eradication work."
        ],
    }


def requests_containment(report: dict[str, Any], deps: Dependencies) -> bool:
    for item in deps.bounded_text_list(
        report.get("containment_recommendations"), limit=20, item_limit=1000
    ):
        text = re.sub(r"\s+", " ", item.strip().lower())
        if not text:
            continue
        if any(marker in text for marker in (
            "no containment", "do not ", "does not justify", "not justified",
            "not indicated", "defer containment", "containment is unnecessary",
        )):
            continue
        if re.search(r"\b(contain|isolate|quarantine|block|disable|revoke|terminate)\b", text):
            return True
    return False


def _reconciliation_reason(
    response: dict[str, Any],
    report: dict[str, Any],
    validation: dict[str, Any],
    verdict_validation: dict[str, Any],
    guard: dict[str, Any],
    controls: dict[str, Any],
    deps: Dependencies,
) -> str:
    if guard.get("override_applied"):
        return "deterministic evidence guard changed the model verdict"
    if verdict_validation.get("material_contradiction"):
        return "runtime factored-verdict validation found a material contradiction"
    if not validation.get("valid"):
        return "the model omitted or malformed required responder report fields"
    if str(response.get("final_disposition_status") or "").startswith("review_required_"):
        return "the required independent review was unavailable or invalid"
    if controls.get("containment_blocked") and requests_containment(report, deps):
        return "runtime safety controls blocked model-authored containment"
    return ""


def _before_reconciliation(
    response: dict[str, Any], report: dict[str, Any], deps: Dependencies
) -> dict[str, Any]:
    return {
        "top_level_before_reconciliation": {
            key: deps.bounded_text(response.get(key), 2000)
            for key in ("bluf", "summary", "likely_meaning")
        },
        "model_narrative_before_reconciliation": {
            key: deps.bounded_text(report.get(key), 2000)
            for key in ("executive_bluf", "detection_outcome_reasoning", "conclusion")
        },
        "model_actions_before_reconciliation": {
            key: deps.bounded_text_list(report.get(key), limit=20, item_limit=1000)
            for key in (
                "containment_recommendations", "eradication_recommendations",
                "recovery_recommendations",
            )
        },
    }


def _reconcile_narrative(
    response: dict[str, Any],
    report: dict[str, Any],
    validation: dict[str, Any],
    guard: dict[str, Any],
    reason: str,
    deps: Dependencies,
) -> None:
    validation.update(_before_reconciliation(response, report, deps))
    canonical = canonical_disposition(response, deps)
    report["executive_bluf"] = canonical
    if guard.get("rule_intent_match") == "mismatch":
        report["detection_outcome_reasoning"] = (
            "Collector-owned detection validation recorded rule_intent_match=mismatch. "
            "The runtime therefore set detection_validity=logic_error and did not allow "
            "the detection name alone to support malicious attribution or containment."
        )
    else:
        report["detection_outcome_reasoning"] = (
            f"{canonical} The displayed disposition was reconciled because {reason}."
        )
    report.update(human_review_actions(response))
    report["conclusion"] = (
        f"{canonical} Human review is required before relying on superseded "
        "model-authored narrative."
    )
    constraint = (
        "The runtime replaced contradictory or incomplete responder narrative "
        f"because {reason}."
    )
    constraints = deps.bounded_text_list(report.get("constraints"))
    if constraint not in constraints:
        constraints.append(constraint)
    report["constraints"] = constraints
    validation["narrative_reconciled"] = True
    validation["reconciliation_reason"] = reason
    response["bluf"] = report["executive_bluf"]
    response["summary"] = report["conclusion"]
    response["likely_meaning"] = report["detection_outcome_reasoning"]


def reconcile(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Align the durable responder narrative with runtime-owned verdict fields."""
    if not deps.is_incident_responder(prompt_package):
        return response
    report = response.get("incident_response_report")
    if not isinstance(report, dict):
        report = normalize({}, deps)
        response["incident_response_report"] = report
    report["confidence"] = str(response.get("confidence") or "low")
    report["confidence_score"] = response.get("confidence_score")
    validation = dict(response.get("_incident_response_report_validation")) if isinstance(
        response.get("_incident_response_report_validation"), dict
    ) else validate_shape(report, deps)
    verdict_validation = response.get("_verdict_validation") if isinstance(
        response.get("_verdict_validation"), dict
    ) else {}
    guard = verdict_validation.get("deterministic_evidence_guard") if isinstance(
        verdict_validation.get("deterministic_evidence_guard"), dict
    ) else {}
    controls = response.get("_automation_controls") if isinstance(
        response.get("_automation_controls"), dict
    ) else {}
    reason = _reconciliation_reason(
        response, report, validation, verdict_validation, guard, controls, deps
    )
    if reason:
        _reconcile_narrative(response, report, validation, guard, reason, deps)
    else:
        validation["narrative_reconciled"] = False
        validation["reconciliation_reason"] = ""
    validation["canonical_confidence"] = report["confidence"]
    validation["canonical_confidence_score"] = report["confidence_score"]
    response["_incident_response_report_validation"] = validation
    return response
