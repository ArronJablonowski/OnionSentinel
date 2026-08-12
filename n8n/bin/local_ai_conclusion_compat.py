"""Legacy conclusion normalization and response-validation delegates."""
from __future__ import annotations

from live_osquery_client import (
    DEFAULT_CONFIG_FILE as DEFAULT_LIVE_OSQUERY_CONFIG_FILE,
)

def coerce_list(value: Any) -> list[str]:
    return _conclusion_runtime_adapter().coerce_list(value)


def normalize_correlation_assessment(value: Any) -> dict[str, Any]:
    """Compatibility delegate for bounded correlation assessment policy."""
    return _conclusion_runtime_adapter().normalize_correlation(globals(), value)


def bounded_text(value: Any, limit: int = 8000) -> str:
    return _conclusion_runtime_adapter().bounded_text(value, limit)


def bounded_text_list(value: Any, limit: int = 50, item_limit: int = 4000) -> list[str]:
    return _conclusion_runtime_adapter().bounded_text_list(
        value, limit, item_limit
    )


def normalize_hypotheses(value: Any) -> list[dict[str, Any]]:
    """Keep a bounded, structured hypothesis ledger instead of stringifying it."""
    return _conclusion_runtime_adapter().normalize_hypotheses(value)


def safe_nonnegative_int(value: Any) -> int:
    """Coerce untrusted collector/model metadata without breaking artifact writes."""
    return _conclusion_runtime_adapter().safe_nonnegative_int(value)


def normalized_detection_outcome(value: Any) -> str:
    """Return the canonical legacy outcome code or ``inconclusive``."""
    return _conclusion_runtime_adapter().normalized_outcome(globals(), value)


def legacy_verdict_factors(
    outcome: str,
    *,
    escalation_needed: bool = False,
) -> dict[str, Any]:
    """Map a legacy disposition into the orthogonal verdict dimensions."""
    return _conclusion_runtime_adapter().legacy_factors(
        globals(), outcome, escalation_needed=escalation_needed
    )


def derive_legacy_detection_outcome(factors: dict[str, Any]) -> str:
    """Derive the compatibility outcome from normalized verdict dimensions."""
    return _conclusion_runtime_adapter().derive_outcome(globals(), factors)


def normalize_factored_verdict(response: dict[str, Any]) -> dict[str, Any]:
    """Normalize factored verdict fields and reconcile the legacy outcome."""
    return _conclusion_runtime_adapter().normalize_verdict(globals(), response)


def normalize_scope_dispositions(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compatibility delegate for selected-event and group dispositions."""
    return _conclusion_runtime_adapter().normalize_scope(
        globals(), response, prompt_package
    )


def _has_trusted_endpoint_evidence(prompt_package: dict[str, Any] | None) -> bool:
    """Return whether a collector supplied relevant, positive endpoint facts."""
    return _conclusion_runtime_adapter().has_trusted_endpoint_evidence(
        globals(), prompt_package
    )


def _trusted_endpoint_evidence_fields(
    prompt_package: dict[str, Any] | None,
) -> set[str]:
    """Return endpoint fields actually present in trusted pivot result rows.

    Query definitions can name ``process.executable`` even when no event was
    returned, so this deliberately inspects only successful, read-only result
    bodies.  It currently exposes the one field needed by the deterministic
    evidence-gap reconciler and can be extended as other grounded-field
    contradictions are observed.
    """
    return _conclusion_runtime_adapter().trusted_endpoint_fields(
        globals(), prompt_package
    )


def _remove_supplied_executable_path_gap(text: Any) -> tuple[str, bool]:
    """Remove only a false executable-path absence from one gap string."""
    return _conclusion_runtime_adapter().remove_supplied_executable_path_gap(text)


def reconcile_supplied_endpoint_evidence_gaps(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Prevent model-authored gap lists from denying supplied endpoint facts."""
    return _conclusion_runtime_adapter().reconcile_endpoint_gaps(
        globals(), response, prompt_package
    )


def _consequential_model_conclusion(response: dict[str, Any]) -> bool:
    return _conclusion_runtime_adapter().consequential(globals(), response)


def apply_deterministic_evidence_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Reconcile model conclusions with collector-owned rule-intent evidence."""
    return _conclusion_runtime_adapter().evidence_guard(
        globals(), response, prompt_package
    )


def confidence_label_for_score(score: float) -> str:
    return _conclusion_runtime_adapter().confidence_label(globals(), score)


def calibrate_response_confidence(response: dict[str, Any]) -> dict[str, Any]:
    """Apply deterministic evidence caps to the model confidence claim."""
    return _conclusion_runtime_adapter().calibrate_confidence(globals(), response)


def _is_incident_responder_package(prompt_package: dict[str, Any] | None) -> bool:
    return _conclusion_runtime_adapter().is_incident_responder(prompt_package)


def _has_structured_authorization_evidence(
    prompt_package: dict[str, Any] | None,
) -> bool:
    return _conclusion_runtime_adapter().has_authorization_evidence(
        globals(), prompt_package
    )


def apply_tuning_coherence_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Keep suppress/drop evidence-complete, advisory, and human-controlled."""
    return _conclusion_runtime_adapter().tuning_guard(
        globals(), response, prompt_package
    )


def apply_authorized_benign_evidence_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Remove unsupported authorization and no-action claims from IR cases."""
    return _conclusion_runtime_adapter().authorization_guard(
        globals(), response, prompt_package, policy_sensitive=False
    )


def apply_policy_sensitive_activity_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Keep unattributed policy-sensitive application detections unresolved."""
    return _conclusion_runtime_adapter().authorization_guard(
        globals(), response, prompt_package, policy_sensitive=True
    )


def validate_incident_response_report_shape(value: Any) -> dict[str, Any]:
    return _conclusion_runtime_adapter().validate_report_shape(globals(), value)


def normalize_incident_response_report(value: Any) -> dict[str, Any]:
    return _conclusion_runtime_adapter().normalize_report(globals(), value)


def apply_incident_evidence_completeness_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Cap confidence when required Incident Responder evidence is incomplete."""
    return _conclusion_runtime_adapter().completeness_guard(
        globals(), response, prompt_package
    )


def reconcile_incident_response_report(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    return _conclusion_runtime_adapter().reconcile_report(
        globals(), response, prompt_package
    )


def incident_query_audit(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Compatibility delegate for immutable Security Onion query provenance."""
    return _reporting_runtime_adapter().security_onion_audit(
        globals(), prompt_package)


def incident_osquery_audit(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Compatibility delegate for trusted appliance OSQuery provenance."""
    return _reporting_runtime_adapter().appliance_osquery_audit(
        globals(), prompt_package)


def incident_live_osquery_audit(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Compatibility delegate for bounded endpoint audit projection."""
    return _reporting_runtime_adapter().live_osquery_audit(
        globals(), prompt_package)


def prepare_live_osquery_context(
    prompt_package: dict[str, Any],
    agent_role: str,
    config_path: Path = DEFAULT_LIVE_OSQUERY_CONFIG_FILE,
) -> dict[str, Any] | None:
    """Load deployment config and delegate model-safe capability projection."""
    return _reporting_runtime_adapter().prepare_live_osquery(
        globals(), prompt_package, agent_role, config_path
    )


def live_osquery_case_id(prompt_package: dict[str, Any]) -> str:
    """Compatibility delegate for the stable endpoint case token."""
    return _reporting_runtime_adapter().live_osquery_case_id(
        globals(), prompt_package)


def validate_response(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize a model response without letting minor schema drift jam the queue.

    Local models occasionally omit a low-risk field such as tuning_reason. The
    dashboard still needs an artifact for every unique alert, so use explicit
    defaults for missing fields and preserve the model output that was present.
    """
    return _conclusion_response().normalize(
        response,
        prompt_package,
        policy=_conclusion_response_policy(),
        dependencies=_conclusion_response_dependencies(),
    )


def markdown_list(items: list[str]) -> str:
    return _reporting_runtime_adapter().markdown_list(globals(), items)

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)
