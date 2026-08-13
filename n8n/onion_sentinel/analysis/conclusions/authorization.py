"""Authorization-sensitive deterministic conclusion guards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    is_incident_responder: Callable[[dict[str, Any] | None], bool]
    has_authorization_evidence: Callable[[dict[str, Any] | None], bool]
    has_trusted_endpoint_evidence: Callable[[dict[str, Any] | None], bool]
    derive_legacy_outcome: Callable[[dict[str, Any]], str]
    control_tuning_values: frozenset[str]
    factored_verdict_keys: frozenset[str]


def _verdict_snapshot(response: dict[str, Any]) -> dict[str, Any]:
    return {
        key: response.get(key)
        for key in (
            "detection_outcome", "activity_disposition", "handling",
            "tuning_recommendation",
        )
    }


def _downgrade_tuning(response: dict[str, Any], reason: str, deps: Dependencies) -> None:
    tuning = str(response.get("tuning_recommendation") or "").strip().lower()
    if tuning not in deps.control_tuning_values:
        return
    response["tuning_recommendation"] = "needs_more_data"
    response["recommended_tuning_actions"] = []
    response["tuning_reason"] = reason


def _derive_outcome(response: dict[str, Any], deps: Dependencies) -> None:
    response["detection_outcome"] = deps.derive_legacy_outcome(
        {key: response.get(key) for key in deps.factored_verdict_keys}
    )


def _append_gap(response: dict[str, Any], gap: str) -> None:
    gaps = list(response.get("evidence_gaps")) if isinstance(
        response.get("evidence_gaps"), list
    ) else []
    if gap not in gaps:
        gaps.append(gap)
    response["evidence_gaps"] = gaps


def _append_warning(response: dict[str, Any], warning: str) -> None:
    validation = dict(response.get("_verdict_validation")) if isinstance(
        response.get("_verdict_validation"), dict
    ) else {}
    warnings = list(validation.get("warnings")) if isinstance(
        validation.get("warnings"), list
    ) else []
    if warning not in warnings:
        warnings.append(warning)
    validation["warnings"] = warnings
    validation["canonical_legacy_outcome"] = response["detection_outcome"]
    validation["derived_legacy_outcome"] = response["detection_outcome"]
    response["_verdict_validation"] = validation


def _authorization_audit(supported: bool) -> dict[str, Any]:
    return {
        "version": 1,
        "authorization_supported": supported,
        "override_applied": False,
        "required_sources": [
            "approved_change",
            "human_adjudication",
            "operator_assertion",
            "policy_exception",
        ],
    }


def apply_authorized_benign(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Remove unsupported authorization and no-action claims from IR cases."""
    if not deps.is_incident_responder(prompt_package):
        return response
    if str(response.get("activity_disposition") or "").strip().lower() != "authorized_benign":
        return response
    supported = deps.has_authorization_evidence(prompt_package)
    audit = _authorization_audit(supported)
    if supported:
        response["_authorization_evidence_guard"] = audit
        return response

    original = _verdict_snapshot(response)
    response["activity_disposition"] = "benign"
    if str(response.get("handling") or "").strip().lower() == "no_action":
        response["handling"] = "monitor"
    _downgrade_tuning(
        response,
        "Suppress/drop tuning is blocked because no structured operator "
        "authorization evidence covers the selected activity.",
        deps,
    )
    _derive_outcome(response, deps)
    _append_gap(
        response,
        "No structured operator authorization evidence covers the selected "
        "activity; benign context cannot establish authorized_benign.",
    )
    _append_warning(
        response,
        "unsupported authorized_benign claim was downgraded to benign/monitor",
    )
    audit.update({
        "override_applied": True,
        "original_verdict": original,
        "guarded_verdict": _verdict_snapshot(response),
    })
    response["_authorization_evidence_guard"] = audit
    return response


def _policy_class(prompt_package: dict[str, Any]) -> str:
    alert = prompt_package.get("alert") if isinstance(
        prompt_package.get("alert"), dict
    ) else {}
    rule_name = str(alert.get("rule_name") or "").strip().lower()
    return next(
        (marker for marker in ("dns over https", "discord") if marker in rule_name),
        "",
    )


def apply_policy_sensitive(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Keep unattributed policy-sensitive application detections unresolved."""
    if not deps.is_incident_responder(prompt_package):
        return response
    assert isinstance(prompt_package, dict)
    policy_class = _policy_class(prompt_package)
    if not policy_class:
        return response
    if str(response.get("activity_disposition") or "").strip().lower() != "benign":
        return response

    authorized = deps.has_authorization_evidence(prompt_package)
    endpoint = deps.has_trusted_endpoint_evidence(prompt_package)
    audit: dict[str, Any] = {
        "version": 1,
        "policy_class": policy_class,
        "authorization_supported": authorized,
        "endpoint_attribution_supported": endpoint,
        "override_applied": False,
    }
    if authorized:
        response["_policy_sensitive_activity_guard"] = audit
        return response

    original = _verdict_snapshot(response)
    if not endpoint:
        response["activity_disposition"] = "unknown"
    if str(response.get("handling") or "").strip().lower() == "no_action":
        response["handling"] = "monitor"
    _downgrade_tuning(
        response,
        "Suppress/drop tuning is blocked because the policy-sensitive "
        "activity lacks structured local authorization evidence.",
        deps,
    )
    _derive_outcome(response, deps)
    gap = (
        "Policy-sensitive application activity lacks trusted endpoint "
        "attribution and structured local authorization evidence; "
        "benign/no-action is not established."
        if not endpoint else
        "Policy-sensitive application activity has endpoint attribution "
        "but no structured local authorization evidence; no-action is not established."
    )
    _append_gap(response, gap)
    _append_warning(
        response,
        "unsupported policy-sensitive benign/no_action claim was downgraded",
    )
    audit.update({
        "override_applied": True,
        "original_verdict": original,
        "guarded_verdict": _verdict_snapshot(response),
    })
    response["_policy_sensitive_activity_guard"] = audit
    return response
