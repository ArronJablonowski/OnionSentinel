"""Legacy conclusion and independent-review dependency bindings."""
from __future__ import annotations

def _conclusion_authorization_evidence():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import authorization_evidence
    return authorization_evidence


def _conclusion_evidence_guard():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import evidence_guard
    return evidence_guard


def _conclusion_tuning():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import tuning
    return tuning


def _conclusion_incident_report():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import incident_report
    return incident_report


def _conclusion_incident_completeness():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import incident_completeness
    return incident_completeness


def _conclusion_response():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import response
    return response


def _conclusion_correlation():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import correlation
    return correlation


def _conclusion_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import runtime_adapter
    return runtime_adapter


def _conclusion_scope():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import scope
    return scope


def _conclusion_scope_policy():
    return _conclusion_scope().Policy(
        disposition_values=frozenset(ACTIVITY_DISPOSITION_VALUES),
        handling_values=frozenset(HANDLING_VALUES),
    )


def _conclusion_scope_dependencies():
    return _conclusion_scope().Dependencies(
        bounded_text_list=bounded_text_list,
    )


def _conclusion_response_policy():
    module = _conclusion_response()
    return module.Policy(
        required_keys=frozenset(REQUIRED_KEYS),
        strict_required_keys=frozenset(STRICT_FACTORED_REQUIRED_KEYS),
        default_values=DEFAULT_RESPONSE_VALUES,
        strict_default_values=STRICT_RESPONSE_VALUES,
        list_keys=frozenset(LIST_KEYS),
        confidence_values=frozenset(CONFIDENCE_VALUES),
        tuning_values=frozenset(TUNING_VALUES),
        detection_outcome_values=frozenset(DETECTION_OUTCOME_VALUES),
        legacy_detection_outcomes=frozenset({
            "true_positive_benign", "authorized_benign",
            "false_positive_rule_logic", "false_positive_parser",
            "false_positive_intel",
        }),
    )


def _conclusion_response_dependencies():
    module = _conclusion_response()
    return module.Dependencies(
        boolean_setting=boolean_setting,
        coerce_list=coerce_list,
        normalize_correlation=normalize_correlation_assessment,
        normalize_memory=normalize_memory_candidates,
        normalize_hypotheses=normalize_hypotheses,
        is_incident_responder=_is_incident_responder_package,
        validate_report_shape=validate_incident_response_report_shape,
        normalize_report=normalize_incident_response_report,
        normalize_factored=normalize_factored_verdict,
        guards=(
            apply_deterministic_evidence_guard,
            apply_authorized_benign_evidence_guard,
            apply_policy_sensitive_activity_guard,
            apply_incident_evidence_completeness_guard,
            reconcile_supplied_endpoint_evidence_gaps,
            validate_evidence_references,
            apply_tuning_coherence_guard,
        ),
        normalize_scope=normalize_scope_dispositions,
        calibrate_confidence=calibrate_response_confidence,
        reconcile_report=reconcile_incident_response_report,
    )


def _incident_completeness_dependencies():
    module = _conclusion_incident_completeness()
    return module.Dependencies(
        is_incident_responder=_is_incident_responder_package,
        safe_nonnegative_int=safe_nonnegative_int,
        success_statuses=frozenset(INVESTIGATION_QUERY_SUCCESS_STATUSES),
        report_text_fields=frozenset(INCIDENT_RESPONSE_REPORT_TEXT_FIELDS),
        confidence_high_threshold=CONFIDENCE_HIGH_THRESHOLD,
    )


def _incident_report_dependencies():
    module = _conclusion_incident_report()
    return module.Dependencies(
        is_incident_responder=_is_incident_responder_package,
        bounded_text=bounded_text,
        bounded_text_list=bounded_text_list,
        normalized_outcome=normalized_detection_outcome,
        outcome_labels=dict(DETECTION_OUTCOME_LABELS),
        confidence_values=frozenset(CONFIDENCE_VALUES),
        confidence_score_by_label=dict(CONFIDENCE_SCORE_BY_LABEL),
        required_fields=frozenset(INCIDENT_RESPONSE_REPORT_REQUIRED_FIELDS),
        text_fields=frozenset(INCIDENT_RESPONSE_REPORT_TEXT_FIELDS),
        list_fields=frozenset(INCIDENT_RESPONSE_REPORT_LIST_FIELDS),
    )


def _tuning_guard_dependencies():
    module = _conclusion_tuning()
    return module.Dependencies(
        bounded_text_list=bounded_text_list,
        has_authorization_evidence=_has_structured_authorization_evidence,
        control_tuning_values=frozenset(CONTROL_TUNING_VALUES),
    )


def _evidence_guard_dependencies():
    module = _conclusion_evidence_guard()
    return module.Dependencies(
        bounded_text=bounded_text,
        bounded_text_list=bounded_text_list,
        normalized_outcome=normalized_detection_outcome,
        has_trusted_endpoint_evidence=_has_trusted_endpoint_evidence,
        derive_legacy_outcome=derive_legacy_detection_outcome,
        control_tuning_values=frozenset(CONTROL_TUNING_VALUES),
        factored_verdict_keys=frozenset(FACTORED_VERDICT_KEYS),
    )


def _authorization_guard_dependencies():
    module = _conclusion_authorization()
    return module.Dependencies(
        is_incident_responder=_is_incident_responder_package,
        has_authorization_evidence=_has_structured_authorization_evidence,
        has_trusted_endpoint_evidence=_has_trusted_endpoint_evidence,
        derive_legacy_outcome=derive_legacy_detection_outcome,
        control_tuning_values=frozenset(CONTROL_TUNING_VALUES),
        factored_verdict_keys=frozenset(FACTORED_VERDICT_KEYS),
    )


def _review_comparison():
    _provider_routing()
    from onion_sentinel.analysis.review import comparison
    return comparison


def _review_adjudication():
    _provider_routing()
    from onion_sentinel.analysis.review import adjudication
    return adjudication


def _review_adjudication_workflow():
    _provider_routing()
    from onion_sentinel.analysis.review import adjudication_workflow
    return adjudication_workflow


def _review_adjudication_workflow_dependencies():
    module = _review_adjudication_workflow()
    return module.Dependencies(
        route_identity=model_route_identity,
        notify_phase=notify_analysis_phase,
        build_package=disagreement_adjudication_package,
        route_is_hosted=model_route_is_hosted,
        analyze_route=analyze_model_route,
        validate=validate_disagreement_adjudication,
        reconcile_endpoint_gaps=reconcile_supplied_endpoint_evidence_gaps,
        monotonic=time.monotonic,
        validation_error=DisagreementAdjudicationValidationError,
    )


def _review_authorization():
    _provider_routing()
    from onion_sentinel.analysis.review import authorization
    return authorization


def _review_authorization_dependencies():
    module = _review_authorization()
    return module.Dependencies(
        confidence_high_threshold=CONFIDENCE_HIGH_THRESHOLD,
        control_tuning_values=frozenset(CONTROL_TUNING_VALUES),
        consequential_conclusion=_consequential_model_conclusion,
    )


def _review_disagreement():
    _provider_routing()
    from onion_sentinel.analysis.review import disagreement
    return disagreement


def _review_projection():
    _provider_routing()
    from onion_sentinel.analysis.review import projection
    return projection


def _review_gates():
    _provider_routing()
    from onion_sentinel.analysis.review import gates
    return gates


def _review_contracts():
    _provider_routing()
    from onion_sentinel.analysis.review import contracts
    return contracts


def _review_package():
    _provider_routing()
    from onion_sentinel.analysis.review import package
    return package


def _review_catalogs():
    _provider_routing()
    from onion_sentinel.analysis.review import catalogs
    return catalogs


def _review_catalog_policy():
    return _review_runtime_adapter().catalog_policy(globals())


def _review_catalog_dependencies():
    return _review_runtime_adapter().catalog_dependencies(globals())


def _review_text():
    _provider_routing()
    from onion_sentinel.analysis.review import text
    return text


def _review_validation():
    _provider_routing()
    from onion_sentinel.analysis.review import validation
    return validation


def _review_supplemental():
    _provider_routing()
    from onion_sentinel.analysis.review import supplemental
    return supplemental


def _review_workflow():
    _provider_routing()
    from onion_sentinel.analysis.review import workflow
    return workflow


def _review_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.review import runtime_adapter
    return runtime_adapter


def _review_workflow_dependencies():
    module = _review_workflow()
    return module.Dependencies(
        trigger=second_opinion_trigger,
        notify_phase=notify_analysis_phase,
        route_identity=model_route_identity,
        role_prompt_file=role_second_opinion_prompt_file,
        route_is_hosted=model_route_is_hosted,
        independent_package=independent_reviewer_package,
        monotonic=time.monotonic,
        warning=lambda message: print(message, file=sys.stderr),
        analyze_route=analyze_model_route,
        validate_reviewer=validate_reviewer_response,
        reviewer_validation_error=ReviewerValidationError,
        validation_failure=reviewer_validation_failure,
        repair_error_category=reviewer_repair_error_category,
        repair_guidance=reviewer_repair_guidance,
        validate_response=validate_response,
        supplemental_pivot=apply_reviewer_supplemental_pivot,
        compare=compare_analysis_results,
        automation_authorization=reviewer_automation_authorization,
        adjudicate=run_bounded_disagreement_adjudication,
        apply_adjudication_projection=apply_analytical_adjudication_projection,
        reconcile_report=reconcile_incident_response_report,
        apply_disagreement_gate=apply_material_disagreement_gate,
        apply_completed_gate=apply_review_completed_automation_gate,
        apply_required_gate=apply_review_required_gate,
        apply_tuning_guard=apply_tuning_coherence_guard,
    )


def _review_supplemental_dependencies():
    module = _review_supplemental()
    return module.Dependencies(
        pop_query_requests=pop_investigation_query_requests,
        canonical_digest=canonical_payload_digest,
        independent_package=independent_reviewer_package,
        route_is_hosted=model_route_is_hosted,
        analyze_route=analyze_model_route,
        validate_reviewer=validate_reviewer_response,
        validate_response=validate_response,
        apply_query_loop=apply_investigation_query_loop,
        max_queries_per_round=MAX_INVESTIGATION_QUERIES_PER_ROUND,
    )


def normalized_model_roster(value: Any) -> list[str]:
    return _provider_routing().normalized_model_roster(value)


def boolean_setting(value: Any, default: bool = False) -> bool:
    return _provider_routing().boolean_setting(value, default)

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)

