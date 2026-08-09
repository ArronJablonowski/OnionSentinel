#!/usr/bin/env python3
"""Run local AI analysis for a curated Security Onion prompt package.

This script is the bridge between deterministic alert handling and model-based
analysis. It intentionally accepts only the bounded prompt package produced by
build-ai-investigation-prompt.py, validates the model response contract, and
writes both JSON and Markdown notes into the local SOC Alerts corpus.
"""
from __future__ import annotations

import argparse
import collections
import copy
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, NoReturn
BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from agent_memory import (  # noqa: E402
    normalize_memory_candidates,
    persist_memory_candidates,
    role_prompt_file,
    role_second_opinion_prompt_file,
)
from bounded_http import BoundedHttpError, read_bounded_json  # noqa: E402
from bounded_process import BoundedProcessError, run_bounded_command  # noqa: E402
from controlled_evaluation_isolation import (  # noqa: E402
    ControlledEvaluationIsolationError,
    pin_controlled_tmpdir,
    validate_controlled_incident_evidence_route,
)
from incident_evidence_contract import validate_incident_evidence_artifact  # noqa: E402
from investigation_query_contract import (  # noqa: E402
    INVESTIGATION_QUERY_CONTRACT,
    MAX_DISCOVERED_OBSERVABLES,
    PACKS as INVESTIGATION_QUERY_PACK_DEFINITIONS,
    SAFE_ATOM_RE as INVESTIGATION_SAFE_ATOM_RE,
    SAFE_DOMAIN_RE as INVESTIGATION_SAFE_DOMAIN_RE,
    InvestigationQueryContractError,
    authorize_investigation_query_request,
    canonical_digest as investigation_query_canonical_digest,
    pack_event_tuple_fields,
)
try:  # The pinned compatibility-v1 runtime predates role-aware semantics.
    from investigation_query_contract import (  # noqa: E402
        PACK_ROLE_MODE,
        tuple_match_semantics,
    )
except ImportError:  # pragma: no cover - exercised through the v1 runtime test
    PACK_ROLE_MODE = {
        "network_flow": "cross_sensor",
        "dns_activity": "cross_sensor",
        "cross_sensor_timeline": "cross_sensor",
        "zeek_tls": "zeek_originator_responder",
        "zeek_http": "zeek_originator_responder",
        "zeek_files": "zeek_originator_responder",
        "zeek_ssh": "zeek_originator_responder",
        "zeek_stun": "zeek_originator_responder",
        "zeek_quic": "zeek_originator_responder",
        "zeek_anomalies": "zeek_originator_responder",
    }

    def tuple_match_semantics(
        _pack_name: str,
        event_tuple: dict[str, Any] | None,
        _role_semantics: str | None,
    ) -> str:
        return (
            "event_native_exact"
            if event_tuple
            else "observable_exact_any_field"
        )
from live_osquery_client import (  # noqa: E402
    DEFAULT_CONFIG_FILE as DEFAULT_LIVE_OSQUERY_CONFIG_FILE,
    LiveOsqueryClientError,
    capability_descriptor as live_osquery_capability_descriptor,
    collect_live_osquery,
    harness_operator_approved as live_osquery_harness_operator_approved,
    load_live_osquery_config,
)
from live_osquery_contract import (  # noqa: E402
    SCHEMA as LIVE_OSQUERY_SCHEMA,
    LiveOsqueryContractError,
    normalize_query as normalize_live_osquery_query,
    validate_result_artifact as validate_live_osquery_result_artifact,
)
from pcap_evidence_query import (  # noqa: E402
    FILTERS_BY_OPERATION as PCAP_FILTERS_BY_OPERATION,
    PcapEvidenceQueryError,
    QUERY_CONTRACT as PCAP_QUERY_CONTRACT,
    _normalize_filters as normalize_pcap_filters,
    query_derived_pcap_evidence,
)
from onion_sentinel_harness import (  # noqa: E402
    DEFAULT_DB_PATH as DEFAULT_INVESTIGATION_HARNESS_DB,
    DEFAULT_POLICY_PATH as DEFAULT_INVESTIGATION_HARNESS_POLICY,
    HarnessRun as OnionSentinelHarnessRun,
    digest_json as harness_digest_json,
    external_agent_harness_provider,
    load_policy as load_investigation_harness_policy,
    policy_decision_is_effective,
    query_backend_capability,
    query_backend_is_approval_gated,
    resolve_query_binding,
    should_start_onion_sentinel_harness,
    start_harness_run,
)
from local_ai_runtime_contract import *  # noqa: F403
from local_ai_analysis_contract import *  # noqa: F403
import local_ai_conclusion_review_dependency_compat as _conclusion_review_compat
import local_ai_dependency_compat as _dependency_compat
import local_ai_evaluation_routing_compat as _evaluation_routing_compat
import local_ai_query_dependency_compat as _query_dependency_compat
import local_ai_runtime_compat as _runtime_compat
from local_ai_compatibility_facade import install_facade_functions


install_facade_functions(
    globals(),
    _runtime_compat,
    _dependency_compat,
    _query_dependency_compat,
    _conclusion_review_compat,
    _evaluation_routing_compat,
)


def parse_args() -> argparse.Namespace:
    """Compatibility delegate for the versioned analysis CLI contract."""
    module = _analysis_entrypoint()
    return module.parse(
        module.Defaults(
            prompt_dir=DEFAULT_PROMPT_DIR,
            out_dir=DEFAULT_OUT_DIR,
            ai_settings_file=DEFAULT_AI_SETTINGS_FILE,
            harness_policy=DEFAULT_INVESTIGATION_HARNESS_POLICY,
            harness_db=DEFAULT_INVESTIGATION_HARNESS_DB,
            system_prompt_file=DEFAULT_SYSTEM_PROMPT_FILE,
            second_opinion_prompt_file=DEFAULT_SECOND_OPINION_PROMPT_FILE,
            adjudicator_prompt_file=DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT_FILE,
            live_osquery_config=DEFAULT_LIVE_OSQUERY_CONFIG_FILE,
            incident_evidence_config=DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
            investigation_pivot_dir=DEFAULT_INVESTIGATION_PIVOT_DIR,
            max_response_bytes=DEFAULT_OLLAMA_MAX_RESPONSE_BYTES,
            max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES,
        ),
        os.environ,
    )


class SystemResourceMonitor:
    """Lazy compatibility factory preserving package-free v1 runner import."""

    def __new__(cls, interval_seconds: float = 5.0):
        module = _system_resources()
        return module.SystemResourceMonitor(
            interval_seconds,
            read_mactop=lambda **kwargs: read_mactop_system_sample(**kwargs),
            read_gpu=lambda **kwargs: read_gpu_temperature_celsius(**kwargs),
        )


def _redact_unshared_asset_owners(asset_context: Any) -> Any:
    """Remove owner aliases that operators did not approve for external review."""
    return _evidence_runtime_adapter().redact_unshared_asset_owners(asset_context)


def _reviewed_hosted_sha256_evidence_path(
    path: tuple[object, ...],
) -> bool:
    """Allow SHA-256 only at positively projected Elastic source paths."""
    return _evidence_runtime_adapter().reviewed_sha256_path(globals(), path)


def _exact_hosted_columnar_envelope(
    value: Any,
    *,
    require_encoded_accounting: bool,
) -> bool:
    """Recognize only the runtime-owned top-level columnar envelope."""
    return _evidence_runtime_adapter().exact_hosted_columnar_envelope(
        globals(), value, require_encoded_accounting=require_encoded_accounting)


def _refinalize_hosted_columnar_envelope(value: Any) -> Any:
    """Refresh self-accounting after hosted string redaction."""
    return _evidence_runtime_adapter().refinalize_hosted_columnar_envelope(
        globals(), value)


def _sanitize_hosted_investigation_evidence(
    value: Any,
    path: tuple[str, ...] = (),
    *,
    preserve_columnar_rows: bool = False,
) -> Any:
    """Keep safe facts/query provenance while removing hosted-sensitive values."""
    return _evidence_runtime_adapter().sanitize_hosted_evidence(
        globals(), value, path, preserve_columnar_rows=preserve_columnar_rows)


def model_safe_copy(
    value: Any,
    *,
    hosted: bool = False,
    reviewer_safe: bool = False,
    _path: tuple[object, ...] = (),
) -> Any:
    """Copy model evidence while enforcing transport-specific disclosure rules.

    ``detection_validation`` is deterministic collector evidence and remains
    available on every route. Asset owner aliases are more sensitive: a hosted
    model or independent reviewer receives them only when that individual asset
    record explicitly opts in.
    """
    return _evidence_runtime_adapter().model_safe_copy(
        globals(), value, hosted=hosted, reviewer_safe=reviewer_safe,
        path=_path)


def synchronize_hosted_investigation_contract(
    prompt_package: dict[str, Any],
) -> dict[str, Any]:
    """Bind validation to a verified fixed point of hosted redaction.

    Work on an isolated top-level copy and mutate the caller only after a
    bounded convergence check. This keeps prompt admission transactional if a
    future transport rule is accidentally non-idempotent.
    """
    return _evidence_runtime_adapter().synchronize_hosted_contract(
        globals(), prompt_package)




def _bounded_reference(value: Any) -> str:
    return _evidence_runtime_adapter().bounded_reference(globals(), value)


def evidence_source_class(source: Any) -> str:
    """Group multiple citations from one underlying source into one signal."""
    return _evidence_runtime_adapter().source_class(globals(), source)


def result_bound_query_reference(
    query_digest: Any,
    result_digest: Any = "",
    *,
    namespace: str = "query",
    label: Any = "",
) -> tuple[str, str]:
    """Return an immutable query evidence ref and its strongest safe digest.

    A query digest identifies the statement, not the returned snapshot. When a
    collector supplies a result digest, include it in the reference so a later
    execution of the same query cannot collide with or silently reuse evidence
    from a different result set.
    """
    return _evidence_runtime_adapter().result_bound_reference(
        globals(), query_digest, result_digest,
        namespace=namespace, label=label)


def evidence_reference_contract(prompt_package: dict[str, Any]) -> dict[str, Any]:
    return _evidence_runtime_adapter().reference_contract(
        globals(), prompt_package)


def attach_evidence_reference_contract(
    prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return _evidence_runtime_adapter().attach_reference_contract(
        globals(), prompt_package)


def validate_evidence_references(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    return _evidence_runtime_adapter().validate_references(
        globals(), response, prompt_package)


def reviewer_observable_catalog(prompt_package: dict[str, Any]) -> list[dict[str, str]]:
    """Return exact observables that an independent reviewer may mention."""
    return _review_runtime_adapter().observable_catalog(globals(), prompt_package)


def reviewer_non_domain_taxonomy_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return collector-typed dotted dataset/module labels, not DNS names."""
    return _review_runtime_adapter().taxonomy_catalog(globals(), prompt_package)


def reviewer_non_domain_artifact_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return exact script-like names from collector-owned command/path fields."""
    return _review_runtime_adapter().artifact_catalog(globals(), prompt_package)


def reviewer_non_domain_rule_shorthand_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return collector-typed detector-rule shorthands such as ET.BPFDoor."""
    return _review_runtime_adapter().rule_shorthand_catalog(
        globals(), prompt_package)


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


def execute_investigation_query_batch(
    prompt_package: dict[str, Any],
    requests: list[dict[str, Any]],
    *,
    round_number: int,
    live_osquery_config: dict[str, Any] | None = None,
    security_onion_executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    | None = None,
    osquery_executor: Callable[..., dict[str, Any]] | None = None,
    derived_executor: Callable[[dict[str, Any], Any], dict[str, Any]] | None = None,
    enrichment_executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Path = DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
    investigation_pivot_dir: Path = DEFAULT_INVESTIGATION_PIVOT_DIR,
) -> dict[str, Any]:
    """Execute one mixed, read-only query batch through deterministic adapters."""
    return _query_execution_runtime_adapter().execute_batch(
        globals(), prompt_package, requests, round_number=round_number,
        live_osquery_config=live_osquery_config,
        security_onion_executor=security_onion_executor,
        osquery_executor=osquery_executor, derived_executor=derived_executor,
        enrichment_executor=enrichment_executor,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
    )


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


def apply_investigation_query_loop(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
    *,
    live_osquery_config: dict[str, Any] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Path = DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
    investigation_pivot_dir: Path = DEFAULT_INVESTIGATION_PIVOT_DIR,
    harness_runtime: OnionSentinelHarnessRun | None = None,
    model_executor: Callable[..., dict[str, Any]] | None = None,
    query_executor: Callable[..., dict[str, Any]] | None = None,
    route_override: str = "",
    max_rounds_override: int | None = None,
    max_queries_total_override: int | None = None,
    include_deterministic_requests: bool = True,
    model_input_builder: Callable[[dict[str, Any], int], dict[str, Any]] | None = None,
    model_call_id_prefix: str = "primary-followup",
    model_call_purpose_prefix: str = "primary investigation follow-up round",
    model_call_independent_review: bool = False,
    query_round_offset: int = 0,
) -> dict[str, Any]:
    """Compose runtime ports for the package-owned query coordinator."""
    module = _query_invocation_adapter()
    return module.run(
        globals(), prompt_package, primary_response, args, settings, agent_role,
        module.Options(
            live_osquery_config=live_osquery_config,
            enrichment_config=enrichment_config,
            security_onion_config_path=security_onion_config_path,
            investigation_pivot_dir=investigation_pivot_dir,
            harness_runtime=harness_runtime,
            model_executor=model_executor,
            query_executor=query_executor,
            route_override=route_override,
            max_rounds_override=max_rounds_override,
            max_queries_total_override=max_queries_total_override,
            include_deterministic_requests=include_deterministic_requests,
            model_input_builder=model_input_builder,
            model_call_id_prefix=model_call_id_prefix,
            model_call_purpose_prefix=model_call_purpose_prefix,
            model_call_independent_review=model_call_independent_review,
            query_round_offset=query_round_offset,
        ),
    )


def _ollama_request(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    task: str,
    *,
    system_prompt_file: Path | None = None,
) -> dict[str, Any]:
    return _provider_execution_adapter().ollama_request(
        globals(), prompt_package, args, settings, task,
        system_prompt_file=system_prompt_file,
    )


def _unload_ollama_model(
    settings: dict[str, Any],
    model: str,
    *,
    timeout: float,
) -> None:
    _provider_execution_adapter().unload_ollama_model(
        globals(), settings, model, timeout=timeout
    )


def _ollama_chat_for_model_unlocked(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    model: str,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().ollama_chat_unlocked(
        globals(), prompt_package, args, settings, model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def _ollama_chat_for_model(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    model: str,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().ollama_chat(
        globals(), prompt_package, args, settings, model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def summarize_codex_cli_failure(stderr: str, returncode: int) -> str:
    return _codex_provider().summarize_failure(stderr, returncode)




def response_output_json_schema(template: dict[str, Any]) -> dict[str, Any]:
    return _provider_execution_adapter().response_schema(globals(), template)


def canonical_cli_system_prompt_file(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> Path:
    return _provider_execution_adapter().canonical_system_prompt_file(
        globals(), prompt_package, args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def load_canonical_cli_system_prompt(path: Path, agent_role: str) -> str:
    return _provider_execution_adapter().load_canonical_system_prompt(
        globals(), path, agent_role
    )


def cli_analysis_payload(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    hosted: bool,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().cli_analysis_payload(
        globals(), prompt_package, args,
        hosted=hosted,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def prepare_codex_cli_transport(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> tuple[dict[str, Any], str]:
    return _provider_execution_adapter().prepare_codex_transport(
        globals(), prompt_package, args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def cloud_cli_chat(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str | None = None,
    reasoning_effort: str | None = None,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().codex_chat(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def sanitized_cli_harness_env(
    executable: str,
    *,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    return _provider_execution_adapter().sanitized_cli_environment(
        globals(), executable, extra=extra
    )


def summarize_cli_harness_failure(
    label: str,
    stderr: str,
    returncode: int,
) -> str:
    return _provider_execution_adapter().summarize_cli_failure(
        globals(), label, stderr, returncode
    )


def _load_bounded_regular_json(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    required_mode: int | None = None,
) -> dict[str, Any]:
    """Compatibility delegate for descriptor-verified provider artifacts."""
    return _provider_execution_adapter().load_bounded_json(
        globals(), path, max_bytes=max_bytes, label=label,
        required_mode=required_mode,
    )


def _load_dedicated_hermes_auth(path: Path) -> dict[str, Any]:
    return _provider_execution_adapter().load_hermes_auth(globals(), path)


def _write_dedicated_hermes_auth(
    path: Path,
    auth_store: dict[str, Any],
) -> None:
    _provider_execution_adapter().write_hermes_auth(globals(), path, auth_store)


def _verified_hermes_usage(
    path: Path,
    *,
    expected_model: str,
) -> dict[str, Any]:
    return _provider_execution_adapter().verify_hermes_usage(
        globals(), path, expected_model=expected_model
    )


def hermes_agent_chat(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().hermes_chat(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def _openclaw_infer_unlocked(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().openclaw_infer_unlocked(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def openclaw_infer_chat(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    model: str,
    reasoning_effort: str,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().openclaw_chat(
        globals(), prompt_package, args, settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def analyze_model_route(
    route: str,
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _provider_execution_adapter().dispatch(
        globals(), route, prompt_package, args, settings,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
    )


def model_route_identity(
    route: Any,
    settings: dict[str, Any] | None = None,
) -> str:
    return _provider_routing().model_route_identity(route, settings)


class ReviewerValidationError(ValueError):
    """An independent review failed its identity or evidence-isolation contract."""


def reviewer_validation_failure(
    *, attempt: int, call_id: str, error: ReviewerValidationError,
    input_value: Any, response: dict[str, Any],
) -> dict[str, Any]:
    """Return bounded validator telemetry without retaining model output."""
    return _review_runtime_adapter().validation_failure(
        globals(), attempt=attempt, call_id=call_id, error=error,
        input_value=input_value, response=response,
    )


def reviewer_repair_guidance(validation_message: str) -> list[str]:
    """Translate validator output into bounded field-specific repair steps."""
    return _review_runtime_adapter().repair_guidance(globals(), validation_message)


def reviewer_repair_error_category(validation_message: str) -> str:
    """Classify a validator failure without echoing rejected observables."""
    return _review_runtime_adapter().repair_error_category(
        globals(), validation_message
    )



class ControlledEvaluationReviewerGateError(RuntimeError):
    """A controlled evaluation cannot commit without its reviewer decision."""


def reviewer_case_id(prompt_package: dict[str, Any]) -> str:
    return _review_runtime_adapter().case_id(globals(), prompt_package)


def reviewer_evidence_hash(review_package: dict[str, Any]) -> str:
    """Bind the reviewer response to its blind model-visible package."""
    return _review_runtime_adapter().evidence_hash(globals(), review_package)


def independent_reviewer_package(
    prompt_package: dict[str, Any],
    *, hosted: bool = False,
) -> dict[str, Any]:
    """Build the exact route-safe blind evidence view sent to the reviewer."""
    return _review_runtime_adapter().independent_package(
        globals(), prompt_package, hosted=hosted
    )


def _response_strings(value: Any) -> list[str]:
    return _review_text().response_strings(value)


def _review_repetition_reasons(response: dict[str, Any]) -> list[str]:
    """Detect repeated unrelated boilerplate without policing ordinary prose."""
    return _review_text().repetition_reasons(response)


def validate_reviewer_response(
    response: dict[str, Any],
    review_package: dict[str, Any],
) -> dict[str, Any]:
    """Fail closed on stale, foreign, repetitive, or ungrounded reviewer output."""
    return _review_runtime_adapter().validate_reviewer(
        globals(), response, review_package
    )


def apply_reviewer_supplemental_pivot(
    prompt_package: dict[str, Any],
    reviewer_response: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
    route: str,
    reviewer_prompt: Path,
    *,
    live_osquery_config: dict[str, Any] | None,
    enrichment_config: dict[str, Any] | None,
    security_onion_config_path: Path,
    investigation_pivot_dir: Path,
    harness_runtime: OnionSentinelHarnessRun | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return _review_runtime_adapter().supplemental_pivot(
        globals(), prompt_package, reviewer_response, args, settings,
        agent_role, route, reviewer_prompt,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
    )


def second_opinion_trigger(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None = None,
) -> str:
    """Return the deterministic reason an independent review is warranted."""
    return _review_runtime_adapter().trigger(globals(), response, prompt_package)


def compare_analysis_results(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
) -> dict[str, Any]:
    """Compare independent conclusions without model self-arbitration."""
    return _review_runtime_adapter().compare(
        globals(), primary_response, reviewer_response
    )



class DisagreementAdjudicationValidationError(ValueError):
    """A bounded adjudicator response violated its closed decision contract."""


def disagreement_adjudication_package(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
    *,
    hosted: bool,
) -> dict[str, Any]:
    """Build a route-safe package containing two immutable disputed positions."""
    return _review_runtime_adapter().adjudication_package(
        globals(), prompt_package, primary_response, reviewer_response,
        comparison, hosted=hosted,
    )


def validate_disagreement_adjudication(
    response: Any,
    package: dict[str, Any],
) -> dict[str, Any]:
    """Validate identity, closed choices, disputed fields, and evidence citations."""
    return _review_runtime_adapter().validate_adjudication(
        globals(), response, package
    )


def run_bounded_disagreement_adjudication(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
    phase_callback: Callable[[str, str, str], None] | None = None,
    harness_runtime: OnionSentinelHarnessRun | None = None,
) -> dict[str, Any]:
    """Run at most two validation-bounded adjudicator calls in shadow mode."""
    return _review_runtime_adapter().run_adjudication(
        globals(), prompt_package, primary_response, reviewer_response,
        comparison, args, settings, agent_role,
        phase_callback=phase_callback, harness_runtime=harness_runtime,
    )


def second_opinion_memory_eligibility(second_opinion: Any) -> tuple[bool, str]:
    return _review_authorization().memory_eligibility(second_opinion)


def reviewer_automation_authorization(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    return _review_runtime_adapter().automation_authorization(
        globals(), primary_response, reviewer_response, comparison
    )


def apply_material_disagreement_gate(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    return _review_disagreement().apply(
        primary_response, reviewer_response, comparison
    )


def apply_analytical_adjudication_projection(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    adjudication: Any,
) -> bool:
    return _review_projection().apply(
        primary_response, reviewer_response, adjudication
    )


def memory_writeback_plan(
    candidates: Any,
    *,
    allowed: bool,
    eligibility_reason: str,
) -> dict[str, Any]:
    """Describe a commit-gated memory operation without changing memory."""
    return _persistence_runtime_adapter().memory_writeback_plan(
        globals(), candidates, allowed=allowed,
        eligibility_reason=eligibility_reason)


def persist_postcommit_memory_writeback(
    *,
    analysis_id: str,
    agent_role: str,
    role_memory_file: Path,
    shared_memory_file: Path,
    source_artifact: str,
    primary_candidates: Any,
    primary_allowed: bool,
    primary_reason: str,
    reviewer_candidates: Any,
    reviewer_allowed: bool,
    reviewer_reason: str,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
) -> tuple[dict[str, Any], Path | None]:
    """Persist eligible memory only after the alert store has committed.

    Candidate text is never copied into the receipt or harness trace. A failed
    post-commit write is supplemental and must not invalidate the authoritative
    analysis or cause the model job to be retried.
    """

    return _persistence_runtime_adapter().persist_postcommit_memory_writeback(
        globals(), analysis_id=analysis_id, agent_role=agent_role,
        role_memory_file=role_memory_file, shared_memory_file=shared_memory_file,
        source_artifact=source_artifact, primary_candidates=primary_candidates,
        primary_allowed=primary_allowed, primary_reason=primary_reason,
        reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed, reviewer_reason=reviewer_reason,
        receipt_dir=receipt_dir)


def apply_review_required_gate(
    response: dict[str, Any], *, status: str, reason: str,
) -> dict[str, Any]:
    return _review_gates().required(
        response, status=status, reason=reason
    )


def apply_review_completed_automation_gate(
    response: dict[str, Any], *, reason: str,
) -> dict[str, Any]:
    return _review_gates().completed(response, reason=reason)


def apply_saved_response_review_gate(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
) -> dict[str, Any]:
    """Keep offline primary fixtures from bypassing a required live review.

    ``--response-json`` deliberately suppresses model calls, so a caller-
    supplied reviewer result is not independently executed or validated by
    this run. Consequential primary output remains useful for manual testing,
    but it cannot authorize automation or memory promotion.
    """
    return _review_runtime_adapter().saved_response_gate(
        globals(), prompt_package, primary_response
    )


def sanitize_saved_response_input(response: dict[str, Any]) -> dict[str, Any]:
    """Remove caller-supplied runtime attestations from an offline fixture."""
    return _review_runtime_adapter().sanitize_saved_response(response)


def apply_configured_second_opinion(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
    phase_callback: Callable[[str, str, str], None] | None = None,
    harness_runtime: OnionSentinelHarnessRun | None = None,
    force_review_reason: str = "",
    live_osquery_config: dict[str, Any] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Path = DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
    investigation_pivot_dir: Path = DEFAULT_INVESTIGATION_PIVOT_DIR,
) -> dict[str, Any]:
    """Run the configured independent-review workflow through injected ports."""
    return _review_runtime_adapter().configured_second_opinion(
        globals(), prompt_package, primary_response, args, settings, agent_role,
        phase_callback=phase_callback, harness_runtime=harness_runtime,
        force_review_reason=force_review_reason,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
    )


def precommit_controlled_evaluation_reviewer_gate(
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    settings: dict[str, Any],
    agent_role: str,
    *,
    trigger_reason: str,
    freeze_enabled: bool,
) -> dict[str, Any] | None:
    """Require one validated reviewer decision before evaluation persistence.

    Production deliberately retains its advisory reviewer behavior. A frozen
    controlled evaluation is different: when an independently configured
    reviewer was triggered, a primary-only result would be incomplete yet
    could otherwise reach the artifact and alert-store commit boundary.
    Revalidate the single retained reviewer response and its bounded repair
    grammar before the caller records the decision in the harness ledger.
    """
    return _review_runtime_adapter().precommit_reviewer_gate(
        globals(), prompt_package, response, settings, agent_role,
        trigger_reason=trigger_reason,
        freeze_enabled=freeze_enabled,
    )


def analyze_with_config(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    agent_role: str = "soc-analyst",
    settings: dict[str, Any] | None = None,
    live_osquery_config: dict[str, Any] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Path = DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
    investigation_pivot_dir: Path = DEFAULT_INVESTIGATION_PIVOT_DIR,
    phase_callback: Callable[[str, str, str], None] | None = None,
    harness_runtime: OnionSentinelHarnessRun | None = None,
) -> dict[str, Any]:
    """Run exactly the model assigned to the requested cyber-security agent.

    Provider-level enablement defines the approved model roster; the agent map
    owns execution. Avoiding implicit failover prevents a run from silently
    changing its model, cost, privacy boundary, or analytical behavior.
    """
    settings = settings or effective_ai_settings(args)
    evaluation_harness_run = bool(
        harness_runtime is not None
        and boolean_setting(os.environ.get(EVALUATION_FREEZE_MEMORY_ENV))
    )
    module = _primary_execution()
    primary = module.execute(
        prompt_package, args, settings, agent_role,
        phase_callback=phase_callback,
        harness_runtime=harness_runtime,
        policy=module.Policy(
            agent_roles=frozenset(CYBER_SECURITY_AGENT_ROLES),
            evaluation_harness_run=evaluation_harness_run,
        ),
        dependencies=_primary_execution_dependencies(),
    )
    return apply_investigation_query_loop(
        prompt_package,
        primary,
        args,
        settings,
        agent_role,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
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


def main() -> int:
    import local_ai_pipeline_adapters as legacy_adapters
    from onion_sentinel import legacy_pipeline
    return legacy_pipeline.run(globals(), legacy_adapters)


if __name__ == "__main__":
    if str(BIN_DIR.parent) not in sys.path:
        sys.path.insert(0, str(BIN_DIR.parent))
    from onion_sentinel.composition import invoke_legacy_entrypoint

    raise SystemExit(invoke_legacy_entrypoint(globals()))
