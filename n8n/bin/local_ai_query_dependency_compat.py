"""Legacy investigation-query package, policy, and dependency bindings."""
from __future__ import annotations

def _query_primitives():
    _provider_routing()
    from onion_sentinel.analysis.query import primitives
    return primitives


def _query_capability():
    from onion_sentinel.analysis.query import capability

    return capability


def _query_request():
    _provider_routing()
    from onion_sentinel.analysis.query import request
    return request


def _query_request_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.query import request_runtime_adapter
    return request_runtime_adapter


def _query_semantic_identity():
    _provider_routing()
    from onion_sentinel.analysis.query import semantic_identity
    return semantic_identity


def _query_semantic_identity_dependencies():
    return _query_semantic_identity().Dependencies(
        normalize_live_query=normalize_live_osquery_query,
    )


def _query_repair():
    _provider_routing()
    from onion_sentinel.analysis.query import repair
    return repair


def _query_observables():
    _provider_routing()
    from onion_sentinel.analysis.query import observables
    return observables


def _query_observable_validation_policy():
    module = _query_observables()
    return module.ValidationPolicy(
        safe_domain_pattern=INVESTIGATION_SAFE_DOMAIN_RE,
        safe_atom_pattern=INVESTIGATION_SAFE_ATOM_RE,
        maximum_queries_per_round=MAX_INVESTIGATION_QUERIES_PER_ROUND,
    )


def _query_observable_validation_dependencies():
    module = _query_observables()
    return module.ValidationDependencies(
        text=_query_text,
        evidence_ref_component=_evidence_ref_component,
    )


def _query_deterministic_planning():
    _provider_routing()
    from onion_sentinel.analysis.query import deterministic_planning
    return deterministic_planning


def _query_deterministic_planning_policy():
    module = _query_deterministic_planning()
    return module.Policy(pack_role_modes=dict(PACK_ROLE_MODE))


def _query_deterministic_planning_dependencies():
    module = _query_deterministic_planning()
    return module.Dependencies(
        is_incident_responder=_is_incident_responder_package,
        canonical_digest=investigation_query_canonical_digest,
        parse_utc=_query_utc,
        utc_text=_query_utc_text,
        pack_event_tuple_fields=pack_event_tuple_fields,
        query_error=InvestigationQueryError,
    )


def _query_audit():
    _provider_routing()
    from onion_sentinel.analysis.query import audit
    return audit


def _query_audit_policy():
    module = _query_audit()
    return module.Policy(
        maximum_queries_per_round=MAX_INVESTIGATION_QUERIES_PER_ROUND,
        success_statuses=frozenset(INVESTIGATION_QUERY_SUCCESS_STATUSES),
        nonexecution_statuses=frozenset(
            INVESTIGATION_QUERY_NONEXECUTION_STATUSES
        ),
    )


def _query_audit_dependencies():
    module = _query_audit()
    return module.Dependencies(
        digest_json=harness_digest_json,
        resolve_binding=resolve_query_binding,
    )


def _query_outcomes():
    _provider_routing()
    from onion_sentinel.analysis.query import outcomes
    return outcomes


def _query_outcomes_policy():
    return _query_outcomes().Policy(
        success_statuses=frozenset(INVESTIGATION_QUERY_SUCCESS_STATUSES),
    )


def _query_prompt_errors():
    _provider_routing()
    from onion_sentinel.analysis.query import prompt_errors
    return prompt_errors


def _query_prompt_compaction():
    _provider_routing()
    from onion_sentinel.analysis.query import prompt_compaction
    return prompt_compaction


def _query_prompt_compaction_dependencies():
    return _query_prompt_compaction().Dependencies(
        error_category=investigation_query_prompt_error_category,
        error_digest=investigation_query_prompt_error_digest,
    )


def _query_prompt_budget():
    _provider_routing()
    from onion_sentinel.analysis.query import prompt_budget
    return prompt_budget


def _query_prompt_budget_dependencies():
    return _query_prompt_budget().Dependencies(
        project_rows=lambda value, state: _prompt_project_investigation_rows(
            value, state
        ),
        compact_audit=_compact_prompt_trusted_query_audit,
        columnar_payload=lambda rounds, maximum_bytes: (
            _columnar_investigation_prompt_payload(
                rounds, maximum_bytes=maximum_bytes
            )
        ),
    )


def _query_prompt_admission():
    _provider_routing()
    from onion_sentinel.analysis.query import prompt_admission
    return prompt_admission


def _query_prompt_admission_dependencies():
    return _query_prompt_admission().Dependencies(
        projection=lambda rounds, maximum_bytes: _investigation_prompt_payload(
            rounds, maximum_bytes=maximum_bytes
        ),
        attach_contract=attach_evidence_reference_contract,
        synchronize_hosted=synchronize_hosted_investigation_contract,
        model_safe_copy=lambda value, hosted: model_safe_copy(
            value, hosted=hosted
        ),
    )


def _query_prompt_facts():
    _provider_routing()
    from onion_sentinel.analysis.query import prompt_facts
    return prompt_facts


def _query_prompt_facts_policy():
    return _query_prompt_facts().Policy(
        maximum_result_count=MAX_INVESTIGATION_RESULT_COUNT,
    )


def _query_prompt_provenance():
    _provider_routing()
    from onion_sentinel.analysis.query import prompt_provenance
    return prompt_provenance


def _query_prompt_provenance_policy():
    module = _query_prompt_provenance()
    return module.Policy(
        maximum_queries=MAX_INVESTIGATION_QUERIES_TOTAL,
        success_statuses=INVESTIGATION_QUERY_SUCCESS_STATUSES,
        result_schema=INVESTIGATION_QUERY_RESULT_SCHEMA,
        columnar_schema=INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA,
        columns=INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS,
        empty_ref_instruction=INVESTIGATION_COLUMNAR_EMPTY_REF_INSTRUCTION,
        facts=_query_prompt_facts_policy(),
    )


def _query_prompt_provenance_dependencies():
    return _query_prompt_provenance().Dependencies(
        result_bound_reference=result_bound_query_reference,
    )


def _query_repair_dependencies():
    module = _query_repair()
    return module.Dependencies(
        normalize_request=normalize_investigation_query_request,
        normalize_event_tuple=normalize_investigation_event_tuple,
        pack_event_tuple_fields=pack_event_tuple_fields,
        prompt_error_category=investigation_query_prompt_error_category,
        prompt_error_digest=investigation_query_prompt_error_digest,
        canonical_digest=investigation_query_canonical_digest,
    )


def _query_request_policy():
    module = _query_request()
    return module.Policy(
        backends=frozenset(INVESTIGATION_QUERY_BACKENDS),
        parameter_keys=INVESTIGATION_PARAMETER_KEYS,
        query_id_pattern=INVESTIGATION_QUERY_ID_RE,
    )


def _query_event_tuple():
    _provider_routing()
    from onion_sentinel.analysis.query import event_tuple
    return event_tuple


def _query_enrichment():
    _provider_routing()
    from onion_sentinel.analysis.query import enrichment
    return enrichment


def _query_execution_enrichment():
    _provider_routing()
    from onion_sentinel.analysis.query.execution import enrichment
    return enrichment


def _query_execution_derived():
    _provider_routing()
    from onion_sentinel.analysis.query.execution import derived
    return derived


def _query_execution_endpoint():
    _provider_routing()
    from onion_sentinel.analysis.query.execution import endpoint
    return endpoint


def _query_execution_security_onion():
    _provider_routing()
    from onion_sentinel.analysis.query.execution import security_onion
    return security_onion


def _query_execution_batch():
    _provider_routing()
    from onion_sentinel.analysis.query.execution import batch
    return batch


def _query_execution_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.query import execution_runtime_adapter
    return execution_runtime_adapter


def _query_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.query import runtime_adapter
    return runtime_adapter


def _query_invocation_adapter():
    _provider_routing()
    from onion_sentinel.analysis.query import invocation_adapter
    return invocation_adapter


def _query_derived():
    _provider_routing()
    from onion_sentinel.analysis.query import derived
    return derived


def _query_endpoint():
    _provider_routing()
    from onion_sentinel.analysis.query import endpoint
    return endpoint


def _query_live_endpoint():
    _provider_routing()
    from onion_sentinel.analysis.query import live_endpoint
    return live_endpoint


def _query_live_endpoint_policy():
    return _query_live_endpoint().Policy(
        schema=LIVE_OSQUERY_SCHEMA,
        support_schema="onion-sentinel-live-osquery-support-v1",
        maximum_rounds=MAX_INVESTIGATION_QUERY_ROUNDS,
        maximum_queries=MAX_INVESTIGATION_QUERIES_TOTAL,
    )


def _query_live_endpoint_dependencies():
    return _query_live_endpoint().Dependencies(
        text=_query_text,
        normalize_query=normalize_live_osquery_query,
        now=project_now,
        client_error=LiveOsqueryClientError,
    )


def _query_live_workflow():
    _provider_routing()
    from onion_sentinel.analysis.query import live_workflow
    return live_workflow


def _query_live_workflow_policy():
    return _query_live_workflow().Policy(
        schema=LIVE_OSQUERY_SCHEMA,
        supported_roles=frozenset({"soc-analyst", "incident-responder"}),
    )


def _query_live_workflow_dependencies():
    return _query_live_workflow().Dependencies(
        capability_descriptor=live_osquery_capability_descriptor,
        collect=lambda case_id, requests, config: collect_live_osquery(
            case_id=case_id,
            requests=requests,
            config=config,
            persist=True,
        ),
        now=project_now,
        canonical_model_route=canonical_model_route,
        analyze_model_route=analyze_model_route,
        collection_errors=(
            LiveOsqueryClientError, LiveOsqueryContractError, OSError,
        ),
        client_error=LiveOsqueryClientError,
    )


def _query_derived_policy():
    module = _query_derived()
    return module.Policy(
        operations=frozenset(INVESTIGATION_DERIVED_OPERATIONS),
        filters_by_operation=PCAP_FILTERS_BY_OPERATION,
    )


def _query_derived_dependencies():
    module = _query_derived()
    return module.Dependencies(
        normalize_filters=normalize_pcap_filters,
        filter_error=PcapEvidenceQueryError,
        positive_integer=_positive_query_int,
    )


def _query_derived_integrity_policy():
    return _query_derived().IntegrityPolicy(contract=PCAP_QUERY_CONTRACT)


def _query_derived_integrity_dependencies():
    return _query_derived().IntegrityDependencies(
        text=_query_text,
        error_type=InvestigationQueryError,
    )


def _query_event_tuple_dependencies():
    module = _query_event_tuple()
    return module.Dependencies(
        canonical_digest=investigation_query_canonical_digest,
        pack_fields=pack_event_tuple_fields,
        match_semantics=tuple_match_semantics,
    )


def _query_security_onion():
    _provider_routing()
    from onion_sentinel.analysis.query import security_onion
    return security_onion


def _query_security_onion_policy():
    module = _query_security_onion()
    return module.Policy(
        purposes=frozenset(INVESTIGATION_SECURITY_ONION_PURPOSES),
        packs=frozenset(INVESTIGATION_QUERY_PACKS),
        aggregations=frozenset(INVESTIGATION_QUERY_AGGREGATIONS),
    )


def _query_security_onion_dependencies():
    module = _query_security_onion()
    return module.Dependencies(
        normalize_window=lambda value, envelope: (
            normalize_investigation_query_window(
                value, time_envelope=envelope
            )
        ),
        project_event_tuple=lambda value, pack, context: (
            project_investigation_event_tuple(
                value, pack=pack, authorization_context=context
            )
        ),
        positive_integer=_positive_query_int,
    )


def _query_window():
    _provider_routing()
    from onion_sentinel.analysis.query import window
    return window

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)

