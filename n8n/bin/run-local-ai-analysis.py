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
import local_ai_evidence_compat as _evidence_compat
import local_ai_evaluation_routing_compat as _evaluation_routing_compat
import local_ai_investigation_compat as _investigation_compat
import local_ai_provider_compat as _provider_compat
import local_ai_query_dependency_compat as _query_dependency_compat
import local_ai_review_compat as _review_compat
from local_ai_review_compat import analyze_with_config
import local_ai_runtime_compat as _runtime_compat
from local_ai_compatibility_facade import install_facade_functions


install_facade_functions(
    globals(),
    _runtime_compat,
    _dependency_compat,
    _query_dependency_compat,
    _conclusion_review_compat,
    _evaluation_routing_compat,
    _evidence_compat,
    _investigation_compat,
    _provider_compat,
    _review_compat,
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
