"""Legacy provider, reporting, execution, and evidence dependency bindings."""
from __future__ import annotations

def _provider_routing():
    if str(BIN_DIR.parent) not in sys.path:
        sys.path.insert(0, str(BIN_DIR.parent))
    from onion_sentinel.analysis.providers import routing
    return routing


def _ollama_provider():
    _provider_routing()
    from onion_sentinel.analysis.providers import ollama
    return ollama


def _codex_provider():
    _provider_routing()
    from onion_sentinel.analysis.providers import codex
    return codex


def _cli_common_provider():
    _provider_routing()
    from onion_sentinel.analysis.providers import cli_common
    return cli_common


def _provider_artifacts():
    _provider_routing()
    from onion_sentinel.analysis.providers import artifacts
    return artifacts


def _openclaw_provider():
    _provider_routing()
    from onion_sentinel.analysis.providers import openclaw
    return openclaw


def _hermes_provider():
    _provider_routing()
    from onion_sentinel.analysis.providers import hermes
    return hermes


def _provider_registry():
    _provider_routing()
    from onion_sentinel.analysis.providers import registry
    return registry


def _provider_settings_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.providers import runtime_adapter
    return runtime_adapter


def _provider_execution_adapter():
    _provider_routing()
    from onion_sentinel.analysis.providers import execution_adapter
    return execution_adapter


def _reporting_incident():
    _provider_routing()
    from onion_sentinel.analysis.reporting import incident
    return incident


def _reporting_evidence_audits():
    _provider_routing()
    from onion_sentinel.analysis.reporting import evidence_audits
    return evidence_audits


def _reporting_evidence_audit_policy():
    return _reporting_evidence_audits().Policy()


def _reporting_evidence_audit_dependencies():
    return _reporting_evidence_audits().Dependencies(
        bounded_text=bounded_text,
        safe_nonnegative_int=safe_nonnegative_int,
    )


def _reporting_live_osquery():
    _provider_routing()
    from onion_sentinel.analysis.reporting import live_osquery
    return live_osquery


def _reporting_live_osquery_policy():
    return _reporting_live_osquery().Policy(
        support_schema="onion-sentinel-live-osquery-support-v1",
    )


def _reporting_live_osquery_dependencies():
    return _reporting_live_osquery().Dependencies(
        bounded_text=bounded_text,
        safe_nonnegative_int=safe_nonnegative_int,
    )


def _reporting_markdown():
    _provider_routing()
    from onion_sentinel.analysis.reporting import markdown
    return markdown


def _reporting_publication():
    _provider_routing()
    from onion_sentinel.analysis.reporting import publication
    return publication


def _reporting_run_log():
    _provider_routing()
    from onion_sentinel.analysis.reporting import run_log
    return run_log


def _reporting_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.reporting import runtime_adapter
    return runtime_adapter


def _reporting_run_log_dependencies():
    return _reporting_run_log().Dependencies(
        enabled_routes=enabled_agent_model_routes,
        canonical_route=canonical_model_route,
        assigned_metadata=assigned_model_metadata,
    )


def _primary_execution():
    _provider_routing()
    from onion_sentinel.analysis import primary_execution
    return primary_execution


def _primary_execution_dependencies():
    module = _primary_execution()
    return module.Dependencies(
        attach_evidence_contract=attach_evidence_reference_contract,
        canonical_route=canonical_model_route,
        notify_phase=notify_analysis_phase,
        analyze_route=analyze_model_route,
        monotonic=time.monotonic,
        warning=lambda message: print(message, file=sys.stderr),
        route_error=InvestigationQueryError,
    )


def _conclusion_verdict():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import verdict
    return verdict


def _conclusion_confidence():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import confidence
    return confidence


def _conclusion_authorization():
    _provider_routing()
    from onion_sentinel.analysis.conclusions import authorization
    return authorization


def _evidence_references():
    _provider_routing()
    from onion_sentinel.analysis.evidence import references
    return references


def _evidence_runtime_adapter():
    _provider_routing()
    from onion_sentinel.analysis.evidence import runtime_adapter
    return runtime_adapter


def _evidence_reference_policy():
    return _evidence_runtime_adapter().reference_policy(globals())


def _evidence_validation():
    _provider_routing()
    from onion_sentinel.analysis.evidence import validation
    return validation


def _evidence_registry():
    _provider_routing()
    from onion_sentinel.analysis.evidence import registry
    return registry


def _evidence_registry_instance():
    return _evidence_runtime_adapter().registry_instance(globals())


def _evidence_columnar():
    _provider_routing()
    from onion_sentinel.analysis.evidence import columnar
    return columnar


def _evidence_columnar_policy():
    return _evidence_runtime_adapter().columnar_policy(globals())


def _evidence_columnar_dependencies():
    return _evidence_runtime_adapter().columnar_dependencies(globals())


def _evidence_hosted_projection():
    _provider_routing()
    from onion_sentinel.analysis.evidence import hosted_projection
    return hosted_projection


def _evidence_hosted_projection_policy():
    return _evidence_runtime_adapter().hosted_projection_policy(globals())


def _evidence_hosted_projection_dependencies():
    return _evidence_runtime_adapter().hosted_projection_dependencies(globals())


def _evidence_transport():
    _provider_routing()
    from onion_sentinel.analysis.evidence import transport
    return transport


def _evidence_transport_policy():
    return _evidence_runtime_adapter().transport_policy(globals())


def _evidence_transport_dependencies():
    return _evidence_runtime_adapter().transport_dependencies(globals())


def _evidence_endpoint():
    _provider_routing()
    from onion_sentinel.analysis.evidence import endpoint
    return endpoint


def _evidence_endpoint_policy():
    return _evidence_runtime_adapter().endpoint_policy(globals())


def _evidence_endpoint_dependencies():
    return _evidence_runtime_adapter().endpoint_dependencies(globals())


def _evidence_traversal():
    _provider_routing()
    from onion_sentinel.analysis.evidence import traversal
    return traversal


def _evidence_traversal_policy():
    return _evidence_runtime_adapter().traversal_policy(globals())


def _evidence_traversal_dependencies():
    return _evidence_runtime_adapter().traversal_dependencies(globals())


def _evidence_contract():
    _provider_routing()
    from onion_sentinel.analysis.evidence import contract
    return contract


def _evidence_contract_dependencies():
    return _evidence_runtime_adapter().contract_dependencies(globals())

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)
