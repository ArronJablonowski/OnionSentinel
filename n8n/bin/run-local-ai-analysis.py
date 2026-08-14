#!/usr/bin/env python3
"""Compatibility CLI for bounded, package-owned local AI analysis."""
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
    attach_agent_memory_context_contract, normalize_memory_candidates,
    persist_memory_candidates, rebind_agent_memory_context_contract,
    refresh_selected_memory_snapshot, role_prompt_file,
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
from local_ai_conclusion_compat import validate_response
from local_ai_review_compat import analyze_with_config
from local_ai_compatibility_facade import install_facade_functions
from local_ai_compatibility_modules import COMPATIBILITY_MODULES


install_facade_functions(globals(), *COMPATIBILITY_MODULES)


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


def main() -> int:
    import local_ai_pipeline_adapters as legacy_adapters
    from onion_sentinel import legacy_pipeline
    return legacy_pipeline.run(globals(), legacy_adapters)


if __name__ == "__main__":
    if str(BIN_DIR.parent) not in sys.path:
        sys.path.insert(0, str(BIN_DIR.parent))
    from onion_sentinel.composition import invoke_legacy_entrypoint

    raise SystemExit(invoke_legacy_entrypoint(globals()))
