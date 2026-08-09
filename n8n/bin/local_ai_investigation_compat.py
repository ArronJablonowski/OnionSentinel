"""Legacy investigation-query execution and prompt compatibility delegates."""
from __future__ import annotations

from investigation_query_contract import MAX_DISCOVERED_OBSERVABLES
from local_ai_runtime_contract import *  # noqa: F403

class InvestigationQueryError(ValueError):
    """A model-proposed pivot violated the provider-neutral query contract."""


def _query_text(value: Any, limit: int) -> str:
    return _query_primitives().text(value, limit)


def _positive_query_int(value: Any, default: int, maximum: int, label: str) -> int:
    return _query_primitives().positive_integer(
        value, default, maximum, label,
        error_type=InvestigationQueryError,
    )




def _query_utc(value: Any, label: str) -> dt.datetime:
    return _query_primitives().utc(
        value, label, error_type=InvestigationQueryError
    )


def _query_utc_text(value: dt.datetime) -> str:
    return _query_primitives().utc_text(value)


def normalize_investigation_event_tuple(value: Any) -> dict[str, Any]:
    return _query_event_tuple().normalize(
        value, error_type=InvestigationQueryError
    )


def project_investigation_event_tuple(
    value: Any,
    *,
    pack: str,
    authorization_context: Any = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Project a trusted model tuple onto fields authenticated by ``pack``.

    The model-visible capability currently exposes complete role-aware tuples.
    A model may therefore copy an alert-only field such as ``rule_id`` into a
    Zeek request even though that field is not available in the selected pack.
    Projection is safe only after every supplied value matches one collector-
    owned tuple.  Audit metadata contains field names and provenance digests,
    never the hidden tuple values that established authority.

    ``authorization_context=None`` preserves the standalone normalizer API for
    callers that perform broker authorization later.  The iterative runner
    always supplies its trusted local context and therefore always takes the
    provenance-checked path.
    """
    return _query_event_tuple().project(
        value,
        pack=pack,
        authorization_context=authorization_context,
        dependencies=_query_event_tuple_dependencies(),
        error_type=InvestigationQueryError,
    )


def normalize_investigation_query_window(
    value: Any, *, time_envelope: Any = None,
) -> tuple[dict[str, str], dict[str, Any]]:
    return _query_window().normalize(
        value, time_envelope=time_envelope,
        error_type=InvestigationQueryError,
    )


def _normalize_investigation_backend_parameters(
    backend: str, parameters: dict[str, Any], purpose: str,
    time_envelope: Any, authorization_context: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return _query_request_runtime_adapter().normalize_backend_parameters(
        globals(), backend, parameters, purpose, time_envelope,
        authorization_context)


def normalize_investigation_query_request(
    raw: Any, *, round_number: int, position: int,
    time_envelope: Any = None, authorization_context: Any = None,
) -> dict[str, Any]:
    return _query_request_runtime_adapter().normalize_request(
        globals(), raw, round_number=round_number, position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context)


def pop_investigation_query_requests(response: dict[str, Any]) -> list[Any]:
    """Consume the unified protocol and translate two legacy request fields."""
    return _query_request_runtime_adapter().pop_requests(globals(), response)


_PIVOT_COLLECTOR_MODULE: Any = None


def _load_pivot_collector() -> Any:
    """Load the hyphenated collector lazily so deployments can fail closed."""
    global _PIVOT_COLLECTOR_MODULE
    if _PIVOT_COLLECTOR_MODULE is not None:
        return _PIVOT_COLLECTOR_MODULE
    path = BIN_DIR / "collect-investigation-pivots.py"
    if not path.is_file():
        raise InvestigationQueryError("Security Onion investigation pivot collector is unavailable")
    spec = importlib.util.spec_from_file_location(
        "onion_sentinel_collect_investigation_pivots",
        path,
    )
    if spec is None or spec.loader is None:
        raise InvestigationQueryError("Security Onion investigation pivot collector could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if not callable(getattr(module, "collect_investigation_pivots", None)):
        raise InvestigationQueryError("Security Onion investigation pivot collector has no callable adapter")
    _PIVOT_COLLECTOR_MODULE = module
    return module


def collect_security_onion_pivots(
    proposal: dict[str, Any],
    authorization_context: dict[str, Any],
    *,
    config_path: Path = DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
    out_dir: Path = DEFAULT_INVESTIGATION_PIVOT_DIR,
) -> dict[str, Any]:
    """Invoke the restricted broker without giving a model transport access."""
    module = _load_pivot_collector()
    return module.collect_investigation_pivots(
        proposal,
        authorization_context,
        config_path=config_path,
        out_dir=out_dir,
        persist=True,
    )


def _safe_audit_summary(value: Any) -> dict[str, Any]:
    return _query_execution_runtime_adapter().safe_audit_summary(globals(), value)




def _bounded_trusted_query_audit(raw: Any) -> list[dict[str, Any]]:
    """Retain exact broker-rendered queries without carrying full result hits."""
    return _query_execution_runtime_adapter().bounded_trusted_query_audit(
        globals(), raw, TRUSTED_QUERY_AUDIT_FIELDS)


def validate_derived_query_evidence(
    value: Any,
    expected_requests: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bind each derived result to the exact normalized request and digests."""
    return _query_derived().validate_evidence(
        value, expected_requests,
        policy=_query_derived_integrity_policy(),
        dependencies=_query_derived_integrity_dependencies(),
    )


def _derived_evidence_source_digest(pcap_context: dict[str, Any]) -> str:
    """Bind a pivot to the capture artifacts represented by the local index."""
    return _query_derived().source_digest(
        pcap_context,
        policy=_query_derived_integrity_policy(),
        dependencies=_query_derived_integrity_dependencies(),
    )


def _live_osquery_target_bound_to_case(
    prompt_package: dict[str, Any],
    target_alias: Any,
    config: dict[str, Any],
) -> bool:
    """Compatibility delegate for trusted target binding."""
    return _query_live_endpoint().target_bound(
        prompt_package,
        target_alias,
        config,
        dependencies=_query_live_endpoint_dependencies(),
    )


def _live_osquery_support_bindings(
    prompt_package: dict[str, Any],
    result: dict[str, Any],
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compatibility delegate for positive endpoint evidence bindings."""
    return _query_live_endpoint().support_bindings(
        prompt_package,
        result,
        config,
        policy=_query_live_endpoint_policy(),
        dependencies=_query_live_endpoint_dependencies(),
    )


def accumulate_live_osquery_evidence(
    prompt_package: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    """Compatibility delegate for collector-validated endpoint evidence."""
    _query_live_endpoint().accumulate_evidence(
        prompt_package,
        evidence,
        policy=_query_live_endpoint_policy(),
        dependencies=_query_live_endpoint_dependencies(),
    )


def accumulate_live_osquery_failure(
    prompt_package: dict[str, Any],
    *,
    case_id: str,
    requests: list[dict[str, Any]],
    error: str,
    dispatch_possible: bool,
) -> None:
    """Compatibility delegate for failed endpoint collection attempts."""
    _query_live_endpoint().accumulate_failure(
        prompt_package,
        case_id=case_id,
        requests=requests,
        error=error,
        dispatch_possible=dispatch_possible,
        policy=_query_live_endpoint_policy(),
        dependencies=_query_live_endpoint_dependencies(),
    )


def _runtime_env_value(name: str) -> str:
    return _query_execution_runtime_adapter().runtime_env_value(globals(), name)


def prepare_investigation_enrichment_context(
    prompt_package: dict[str, Any],
    agent_role: str,
    alert_store_url: str,
) -> dict[str, Any]:
    return _query_execution_runtime_adapter().prepare_enrichment_context(
        globals(), prompt_package, agent_role, alert_store_url)


def _post_investigation_enrichment_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    return _query_execution_runtime_adapter().post_enrichment_json(
        globals(), url, payload, headers, timeout)


def _project_investigation_enrichment_record(record: Any) -> dict[str, Any]:
    return _query_execution_runtime_adapter().project_enrichment_record(record)


def collect_investigation_enrichment(
    request: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    return _query_execution_runtime_adapter().collect_enrichment(
        globals(), request, config)


def security_onion_authorization_context(value: Any) -> dict[str, Any]:
    """Project local-only policy data out of the restricted broker contract."""
    return _query_execution_runtime_adapter().security_onion_authorization_context(
        globals(), value)


def _execute_security_query_backend(
    requests: list[dict[str, Any]], context: dict[str, Any],
    round_number: int, executor: Callable[..., dict[str, Any]],
):
    return _query_execution_runtime_adapter().execute_security_backend(
        globals(), requests, context, round_number, executor)


def _execute_endpoint_query_backend(
    requests: list[dict[str, Any]], prompt_package: dict[str, Any],
    config: dict[str, Any] | None, executor: Callable[..., dict[str, Any]],
):
    return _query_execution_runtime_adapter().execute_endpoint_backend(
        globals(), requests, prompt_package, config, executor)


def _execute_derived_query_backend(
    requests: list[dict[str, Any]], prompt_package: dict[str, Any],
    executor: Callable[..., dict[str, Any]],
):
    return _query_execution_runtime_adapter().execute_derived_backend(
        globals(), requests, prompt_package, executor)


def _execute_enrichment_query_backend(
    requests: list[dict[str, Any]], config: dict[str, Any] | None,
    executor: Callable[..., dict[str, Any]],
):
    return _query_execution_runtime_adapter().execute_enrichment_backend(
        globals(), requests, config, executor)


def _evidence_ref_component(value: Any, maximum: int = 40) -> str:
    """Return a compact collision-resistant component for an authorization ref."""
    return _query_runtime_adapter().evidence_ref_component(
        globals(), value, maximum)


def _validated_discovered_observables(
    results: Any,
    *,
    limit: int = MAX_DISCOVERED_OBSERVABLES,
) -> list[dict[str, str]]:
    """Extract pivots only from provenance-bound broker hits or derived records."""
    return _query_runtime_adapter().validated_discovered_observables(
        globals(), results, limit=limit)


def investigation_query_prompt_error_category(reason: Any) -> str:
    return _query_runtime_adapter().prompt_error_category(globals(), reason)


def investigation_query_prompt_error_digest(reason: Any) -> str:
    return _query_runtime_adapter().prompt_error_digest(globals(), reason)


def _prompt_project_investigation_rows(
    value: Any,
    state: dict[str, int | bool],
) -> Any:
    return _query_runtime_adapter().prompt_project_rows(globals(), value, state)


def _investigation_prompt_json_bytes(value: Any) -> bytes:
    return _query_runtime_adapter().prompt_json_bytes(globals(), value)


def _compact_prompt_trusted_query_audit(
    value: Any,
) -> dict[str, Any]:
    return _query_runtime_adapter().compact_prompt_audit(globals(), value)


def _canonical_investigation_count(value: Any) -> int | None:
    return _query_runtime_adapter().canonical_investigation_count(
        globals(), value)


def _columnar_investigation_prompt_payload(
    rounds: list[dict[str, Any]],
    *,
    maximum_bytes: int,
) -> dict[str, Any] | None:
    return _query_runtime_adapter().columnar_prompt_payload(
        globals(), rounds, maximum_bytes=maximum_bytes)


def _investigation_prompt_payload(
    rounds: list[dict[str, Any]],
    *,
    maximum_bytes: int = MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES,
) -> dict[str, Any]:
    return _query_runtime_adapter().prompt_payload(
        globals(), rounds, maximum_bytes=maximum_bytes)

def _admit_investigation_query_prompt(
    prompt_package: dict[str, Any],
    rounds: list[dict[str, Any]],
    *,
    maximum_prompt_bytes: int,
    hosted: bool,
) -> int:
    return _query_runtime_adapter().admit_prompt(
        globals(), prompt_package, rounds,
        maximum_prompt_bytes=maximum_prompt_bytes, hosted=hosted)

def _investigation_round_audit(round_result: dict[str, Any]) -> dict[str, Any]:
    return _query_runtime_adapter().round_audit(globals(), round_result)



def investigation_query_binding_summary(
    bindings: list[dict[str, Any]],
    *,
    queries_admitted: int,
) -> dict[str, Any]:
    return _query_runtime_adapter().binding_summary(
        globals(), bindings, queries_admitted=queries_admitted)


def investigation_query_outcome_summary(
    rounds: list[dict[str, Any]],
    *,
    queries_admitted: int,
) -> dict[str, Any]:
    return _query_runtime_adapter().outcome_summary(
        globals(), rounds, queries_admitted=queries_admitted)


def _append_investigation_evidence_gaps(
    response: dict[str, Any],
    gaps: list[str],
) -> None:
    _query_runtime_adapter().append_evidence_gaps(globals(), response, gaps)


def investigation_backend_available(
    prompt_package: dict[str, Any],
    backend: str,
    *,
    live_osquery_config: dict[str, Any] | None,
) -> bool:
    """Compatibility delegate for trusted backend capability policy."""
    return _query_runtime_adapter().backend_available(
        globals(), prompt_package, backend,
        live_osquery_config=live_osquery_config)


def investigation_request_semantic_digest(request: dict[str, Any]) -> str:
    """Identify an equivalent execution independently of model labels/purpose."""
    return _query_runtime_adapter().semantic_digest(globals(), request)


def investigation_query_repair_scope(
    raw: Any,
    *,
    round_number: int,
    position: int,
    time_envelope: Any = None,
    authorization_context: Any = None,
) -> dict[str, Any] | None:
    return _query_runtime_adapter().repair_scope(
        globals(), raw, round_number=round_number, position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context)


def validate_investigation_query_repair_scope(
    request: dict[str, Any],
    scope: dict[str, Any],
) -> None:
    _query_runtime_adapter().validate_repair(globals(), request, scope)


def investigation_query_request_from_repair_scope(
    scope: dict[str, Any],
) -> dict[str, Any]:
    return _query_runtime_adapter().request_from_repair(globals(), scope)


def investigation_query_repair_failures(
    round_result: Any,
) -> dict[str, str]:
    return _query_runtime_adapter().repair_failures(globals(), round_result)


def investigation_query_repair_prompt_entry(
    scope: dict[str, Any],
    *,
    reason: str,
    trigger: str,
) -> dict[str, Any]:
    return _query_runtime_adapter().repair_prompt_entry(
        globals(), scope, reason=reason, trigger=trigger)


def deterministic_incident_pivot_requests(
    prompt_package: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compile a repeatable protocol-first plan from trusted local context."""
    return _query_runtime_adapter().deterministic_requests(
        globals(), prompt_package)


def _query_runtime_dependencies(module: Any) -> Any:
    return _query_runtime_adapter().legacy_dependencies(globals(), module)


__all__ = (
    *(name for name, value in globals().items()
      if getattr(value, "__module__", None) == __name__),
    "_PIVOT_COLLECTOR_MODULE",
)
