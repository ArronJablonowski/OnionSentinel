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
HOME = Path.home()
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_OUT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_LLM_LOG_DIR = HOME / "n8n-local" / "soc-alerts" / "llm-analysis-logs"
DEFAULT_LLM_LOG_FILE = DEFAULT_LLM_LOG_DIR / "llm-analysis-log.jsonl"
DEFAULT_LLM_CURRENT_FILE = DEFAULT_LLM_LOG_DIR / "current-analysis.json"
DEFAULT_LLM_ACTIVE_DIR = DEFAULT_LLM_LOG_DIR / "active"
DEFAULT_ANALYSIS_INDEX_QUEUE_DIR = DEFAULT_LLM_LOG_DIR / "analysis-index-pending"
DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR = (
    DEFAULT_LLM_LOG_DIR / "analysis-index-quarantine"
)
DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR = (
    DEFAULT_LLM_LOG_DIR / "memory-writeback-receipts"
)
DEFAULT_MEMORY_WRITEBACK_PENDING_DIR = (
    DEFAULT_LLM_LOG_DIR / "memory-writeback-pending"
)
DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR = (
    DEFAULT_LLM_LOG_DIR / "memory-writeback-committed"
)
EVALUATION_FREEZE_MEMORY_ENV = (
    "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY"
)
CONTROLLED_EVALUATION_MODE_ENV = "ONION_SENTINEL_EVALUATION_MODE"
CONTROLLED_EVALUATION_RUNTIME_DIR_ENV = (
    "ONION_SENTINEL_EVALUATION_RUNTIME_DIR"
)
CONTROLLED_EVALUATION_TOKEN_ENV = "ONION_SENTINEL_EVALUATION_TOKEN"
CONTROLLED_EVALUATION_TOKEN_HEADER = (
    "X-Onion-Sentinel-Evaluation-Token"
)
CONTROLLED_EVALUATION_TOKEN_RE = re.compile(r"[a-f0-9]{64}")
_CONTROLLED_EVALUATION_TMPDIR: Path | None = None
CONTROLLED_RESULT_ENVIRONMENT = {
    "job_id": "ONION_SENTINEL_EVALUATION_JOB_ID",
    "job_type": "ONION_SENTINEL_EVALUATION_JOB_TYPE",
    "lease_token": "ONION_SENTINEL_EVALUATION_LEASE_TOKEN",
    "cohort_id": "ONION_SENTINEL_EVALUATION_COHORT_ID",
    "dispatch_id": "ONION_SENTINEL_EVALUATION_DISPATCH_ID",
    "representative_alert_id": (
        "ONION_SENTINEL_EVALUATION_REPRESENTATIVE_ALERT_ID"
    ),
    "stable_group_id": "ONION_SENTINEL_EVALUATION_STABLE_GROUP_ID",
    "stable_group_key": "ONION_SENTINEL_EVALUATION_STABLE_GROUP_KEY",
    "agent_role": "ONION_SENTINEL_EVALUATION_AGENT_ROLE",
    "reanalysis_attempt_id": (
        "ONION_SENTINEL_EVALUATION_REANALYSIS_ATTEMPT_ID"
    ),
    "release_id": "ONION_SENTINEL_EVALUATION_RELEASE_ID",
    "expected_assigned_route": (
        "ONION_SENTINEL_EVALUATION_EXPECTED_ASSIGNED_ROUTE"
    ),
    "expected_reviewer_route": (
        "ONION_SENTINEL_EVALUATION_EXPECTED_REVIEWER_ROUTE"
    ),
    "reviewer_required": "ONION_SENTINEL_EVALUATION_REVIEWER_REQUIRED",
}
MEMORY_WRITEBACK_TASK_SCHEMA = "onion-sentinel-memory-writeback-task-v1"
MAX_MEMORY_WRITEBACK_TASK_BYTES = 256 * 1024
DEFAULT_SYSTEM_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
DEFAULT_SECOND_OPINION_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_second_opinion_prompt.md"
DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT_FILE = (
    HOME / "n8n-local" / "config" / "disagreement_adjudicator_system_prompt.md"
)
DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE = (
    HOME / "n8n-local" / "config" / "incident-evidence.json"
)
DEFAULT_INVESTIGATION_PIVOT_DIR = (
    HOME / "n8n-local" / "soc-alerts" / "investigation-pivots"
)
DEFAULT_AI_SETTINGS_FILE = HOME / "n8n-local" / "config" / "ai_model_settings.json"
DEFAULT_HERMES_AUTH_FILE = (
    HOME / "n8n-local" / "private" / "hermes-agent" / "auth.json"
)
DEFAULT_OLLAMA_INFERENCE_LOCK = Path(
    os.environ.get(
        "OLLAMA_INFERENCE_LOCK_PATH",
        HOME / "n8n-local" / "run" / "ollama-inference.lock",
    )
)
DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("SOC_AI_MODEL", "")
FALLBACK_OLLAMA_MODEL = "devstral:latest"
CYBER_SECURITY_AGENT_ROLES = (
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
)
DEFAULT_OLLAMA_MAX_RESPONSE_BYTES = int(os.environ.get("SOC_AI_MAX_RESPONSE_BYTES", str(8 * 1024 * 1024)))
DEFAULT_MAX_PROMPT_BYTES = max(
    256 * 1024,
    int(os.environ.get("SOC_AI_MAX_PROMPT_PACKAGE_BYTES", str(4 * 1024 * 1024))),
)
DEFAULT_MAX_JSON_ARTIFACT_BYTES = max(
    DEFAULT_MAX_PROMPT_BYTES,
    int(os.environ.get("SOC_AI_MAX_JSON_ARTIFACT_BYTES", str(16 * 1024 * 1024))),
)
DEFAULT_MAX_SYSTEM_PROMPT_BYTES = max(
    4096,
    int(os.environ.get("SOC_AI_MAX_SYSTEM_PROMPT_BYTES", str(64 * 1024))),
)
DEFAULT_MAX_SETTINGS_BYTES = max(
    4096,
    int(os.environ.get("SOC_AI_MAX_SETTINGS_BYTES", str(256 * 1024))),
)
ANALYSIS_INDEX_MAX_RESPONSE_BYTES = 1024 * 1024
CONTROLLED_RESULT_SUBMISSION_ATTEMPTS = 3
CONTROLLED_RESULT_SUBMISSION_INDETERMINATE = (
    "controlled analysis result submission remains indeterminate"
)
_CONTROLLED_EVALUATION_TOKEN = ""
SAVED_RESPONSE_INPUT_MODE = "saved_response"
DEFAULT_CLOUD_MAX_STDERR_BYTES = int(os.environ.get("SOC_AI_CLOUD_MAX_STDERR_BYTES", str(1024 * 1024)))
CODEX_CLI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
CODEX_CLI_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CODEX_CLI_MODEL_CATALOG = (
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
)
CONTROLLED_MODEL_ROUTE_RE = re.compile(
    r"codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):"
    r"(?:low|medium|high|xhigh)"
)
# The builder is held below the complete Codex transport ceiling so runtime
# citation contracts and the one authoritative role prompt still have bounded
# room.  The final invariant is enforced against the exact compact stdin, not
# merely the saved prompt package.
CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES = 384 * 1024
CODEX_CLI_MAX_STDIN_BYTES = 448 * 1024
CLI_HARNESS_MODEL_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$"
)
OPENCLAW_OLLAMA_PROVIDER_PREFIX = "ollama/"
OPENCLAW_SUPPORTED_OLLAMA_URLS = frozenset({
    "http://127.0.0.1:11434",
    "http://localhost:11434",
})
OPENCLAW_MAX_PROMPT_ARGUMENT_BYTES = 700 * 1024
HERMES_MAX_PROMPT_ARGUMENT_BYTES = 700 * 1024
HERMES_MAX_AUTH_BYTES = 2 * 1024 * 1024
HERMES_MAX_USAGE_BYTES = 64 * 1024
HERMES_AGENT_REASONING_EFFORT = "medium"
INVESTIGATION_QUERY_RESULT_SCHEMA = "onion-sentinel-investigation-query-results-v1"
INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA = (
    "onion-sentinel-investigation-columnar-provenance-v1"
)
INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS = (
    "round",
    "query_id",
    "backend_index",
    "status_index",
    "read_only",
    "query_digest",
    "result_digest",
    "evidence_ref_or_empty",
    "returned",
    "semantics_index",
    "result_summary_index",
)
INVESTIGATION_COLUMNAR_EMPTY_REF_INSTRUCTION = (
    "canonical query reference derived from query_digest and result_digest"
)
INVESTIGATION_QUERY_SUCCESS_STATUSES = frozenset(
    {"ok", "success", "completed", "complete", "succeeded"}
)
MAX_INVESTIGATION_RESULT_COUNT = (2**63) - 1
MAX_INVESTIGATION_QUERY_ROUNDS = 3
MAX_INVESTIGATION_QUERIES_TOTAL = 12
MAX_INVESTIGATION_QUERIES_PER_ROUND = 4
MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES = 1024 * 1024
MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS = 1_200
INVESTIGATION_QUERY_BACKENDS = frozenset(
    {"elastic", "oql", "osquery", "pcap_zeek", "enrichment"}
)
INVESTIGATION_QUERY_PACKS = frozenset(
    {
        "alert_context",
        "network_flow",
        "dns_activity",
        "system_auth",
        "zeek_tls",
        "zeek_http",
        "zeek_files",
        "zeek_ssh",
        "zeek_stun",
        "zeek_quic",
        "zeek_anomalies",
        "osquery_history",
        "cross_sensor_timeline",
    }
)
INVESTIGATION_QUERY_V2 = (
    INVESTIGATION_QUERY_CONTRACT
    == "onion-sentinel-investigation-pivots-v2"
)
INVESTIGATION_SECURITY_ONION_AUTHORIZATION_CONTEXT_FIELDS = (
    "context_id",
    "case_id",
    "group_id",
    "actor_role",
    "anchor",
    *(("anchor_time",) if INVESTIGATION_QUERY_V2 else ()),
    "time_envelope",
    "permitted_observables",
    "discovered_observables",
    "permitted_event_tuples",
)
INVESTIGATION_LOCAL_ONLY_AUTHORIZATION_CONTEXT_FIELDS = frozenset(
    {"permitted_enrichment_indicators"}
)
INVESTIGATION_QUERY_AGGREGATIONS = frozenset(
    {
        "events",
        "count",
        "timeline",
        *(["anchor_nearest"] if INVESTIGATION_QUERY_V2 else []),
    }
)
INVESTIGATION_SECURITY_ONION_PURPOSES = frozenset(
    {
        "validate_detection",
        "establish_timeline",
        "correlate_observable",
        "measure_prevalence",
        "identify_related_activity",
        "test_benign_hypothesis",
    }
)
INVESTIGATION_DERIVED_OPERATIONS = frozenset(
    {
        "coverage",
        "connections",
        "dns",
        "tls",
        "http",
        "files",
        "notices",
        "weird",
        "protocols",
        "packet_facts",
        "icmp_facts",
        "icmp_anomalies",
        "user_agents",
        "tls_versions",
        "geoip",
    }
)
INVESTIGATION_QUERY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DEFAULT_SYSTEM_PROMPT = (
    "You are a careful SOC analyst. Use only the supplied evidence. "
    "Return one valid JSON object and no prose outside JSON."
)
class RuntimeArtifactError(RuntimeError):
    """A local runtime artifact violated its type, size, or encoding contract."""


class AnalysisIndexSubmissionError(RuntimeError):
    """A classified alert-store result submission failure."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        status_code: int | None = None,
        response_sha256: str = "",
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code
        self.response_sha256 = response_sha256

REQUIRED_KEYS = {
    "detection_outcome",
    "bluf",
    "summary",
    "likely_meaning",
    "severity_reasoning",
    "alert_frequency_assessment",
    "public_enrichment_findings",
    "pcap_analysis_findings",
    "false_positive_possibilities",
    "recommended_next_steps",
    "evidence_used",
    "evidence_gaps",
    "confidence",
    "escalation_needed",
    "hosted_second_opinion_recommended",
    "tuning_recommendation",
    "tuning_reason",
    "recommended_tuning_actions",
    "correlation_assessment",
    "memory_candidates",
}
DEFAULT_RESPONSE_VALUES = {
    "detection_outcome": "Inconclusive",
    "bluf": "Inconclusive - Needs More Data: The local model did not provide a BLUF classification.",
    "alert_frequency_assessment": "The local model did not explicitly assess alert frequency.",
    "public_enrichment_findings": [],
    "pcap_analysis_findings": [],
    "false_positive_possibilities": [],
    "recommended_next_steps": ["Review the raw alert, related alerts, and endpoint/network context."],
    "evidence_used": [],
    "evidence_gaps": ["The local model response did not provide this field explicitly."],
    "confidence": "low",
    "escalation_needed": False,
    "hosted_second_opinion_recommended": False,
    "second_opinion_recommended": False,
    "second_opinion_reason": "",
    "tuning_recommendation": "needs_more_data",
    "tuning_reason": "The local model did not provide a tuning reason.",
    "recommended_tuning_actions": ["Review grouped alert count and disposition before changing tuning rules."],
    "correlation_assessment": {
        "correlation_found": False,
        "confidence": "low",
        "related_groups": [],
        "shared_evidence": [],
        "contradicting_evidence": [],
        "attack_chain_hypothesis": "No supported cross-alert correlation was identified.",
        "recommended_pivots": [],
    },
    "memory_candidates": [],
}
STRICT_FACTORED_REQUIRED_KEYS = {
    "event_status",
    "detection_validity",
    "activity_disposition",
    "handling",
    "duplicate_of",
    "confidence_score",
    "hypotheses",
}
STRICT_RESPONSE_VALUES = {
    "event_status": "unknown",
    "detection_validity": "unknown",
    "activity_disposition": "unknown",
    "handling": "investigate",
    "duplicate_of": None,
    "confidence_score": 0.3,
    "hypotheses": [],
}
LIST_KEYS = {
    "false_positive_possibilities",
    "public_enrichment_findings",
    "pcap_analysis_findings",
    "recommended_next_steps",
    "evidence_used",
    "evidence_gaps",
    "recommended_tuning_actions",
}
CONFIDENCE_VALUES = {"low", "medium", "high"}
TUNING_VALUES = {"none", "suppress", "drop", "raise_score", "lower_score", "needs_more_data"}
DETECTION_OUTCOME_VALUES = {
    "true_positive_malicious",
    "true_positive_suspicious",
    "true_positive_authorized_benign",
    "false_positive_logic_rule",
    "false_positive_data_parser",
    "false_positive_bad_intel_ioc",
    "false_negative",
    "duplicate",
    "informational_no_action",
    "inconclusive",
}
EVENT_STATUS_VALUES = {"observed", "not_observed", "unknown"}
DETECTION_VALIDITY_VALUES = {
    "matched_intent",
    "logic_error",
    "parser_error",
    "intel_error",
    "not_applicable",
    "unknown",
}
ACTIVITY_DISPOSITION_VALUES = {
    "malicious",
    "suspicious",
    "authorized_benign",
    "benign",
    "unknown",
}
HANDLING_VALUES = {"contain", "escalate", "investigate", "monitor", "no_action"}
NON_ESCALATORY_HANDLING_VALUES = {"monitor", "no_action"}
FACTORED_VERDICT_KEYS = {
    "event_status",
    "detection_validity",
    "activity_disposition",
    "handling",
    "duplicate_of",
}
CONFIDENCE_SCORE_BY_LABEL = {"low": 0.3, "medium": 0.65, "high": 0.9}
CONFIDENCE_CALIBRATION_VERSION = "evidence-caps-v2"
CONFIDENCE_HIGH_THRESHOLD = 0.8
CONFIDENCE_LOW_THRESHOLD = 0.4
DECISION_CRITICAL_KEYS = {
    "event_status",
    "detection_validity",
    "activity_disposition",
    "handling",
    "duplicate_of",
    "detection_outcome",
    "bluf",
    "summary",
    "evidence_used",
    "evidence_gaps",
    "confidence",
    "confidence_score",
    "escalation_needed",
}
CONTROL_TUNING_VALUES = {"suppress", "drop"}
CONSEQUENTIAL_CLOSURE_OUTCOMES = {
    "true_positive_authorized_benign",
    "false_positive_logic_rule",
    "false_positive_data_parser",
    "false_positive_bad_intel_ioc",
    "duplicate",
    "informational_no_action",
}
INCIDENT_RESPONSE_REPORT_TEXT_FIELDS = (
    "executive_bluf",
    "detection_outcome_reasoning",
    "scope",
    "conclusion",
)
INCIDENT_RESPONSE_REPORT_LIST_FIELDS = (
    "affected_systems",
    "constraints",
    "methodology",
    "factual_timeline",
    "security_onion_findings",
    "osquery_findings",
    "pcap_findings",
    "host_findings",
    "correlation_findings",
    "containment_recommendations",
    "eradication_recommendations",
    "recovery_recommendations",
    "follow_up_queries",
    "evidence_gaps",
)
INCIDENT_RESPONSE_REPORT_REQUIRED_FIELDS = frozenset(
    {
        *INCIDENT_RESPONSE_REPORT_TEXT_FIELDS,
        *INCIDENT_RESPONSE_REPORT_LIST_FIELDS,
        "confidence",
        "confidence_score",
    }
)
DETECTION_OUTCOME_LABELS = {
    "true_positive_malicious": "True Positive - Malicious",
    "true_positive_suspicious": "True Positive - Suspicious",
    "true_positive_authorized_benign": "True Positive - Authorized/Benign",
    "false_positive_logic_rule": "False Positive - Logic/Rule",
    "false_positive_data_parser": "False Positive - Data/Parser",
    "false_positive_bad_intel_ioc": "False Positive - Bad Intelligence/IOC",
    "false_negative": "False Negative - Missed Detection",
    "duplicate": "Duplicate",
    "informational_no_action": "Informational - No Action",
    "inconclusive": "Inconclusive",
}


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


def _analysis_entrypoint():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis import entrypoint
    return entrypoint


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def filename_timestamp(value: str) -> str:
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$", value)
    if match:
        year, month, day, hour, minute, second, zone = match.groups()
        return f"{year}{month}{day}-{hour}{minute}{second}{zone.replace(':', '')}"
    return safe_filename(value)


def safe_filename(value: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "alert")).strip("-")
    return (cleaned or "alert")[:120]


def _system_resources():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis import system_resources
    return system_resources


def _runtime_io():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis import runtime_io
    return runtime_io


def _persistence_runtime_adapter():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis.persistence import runtime_adapter
    return runtime_adapter


def _startup_runtime_adapter():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel import startup_runtime_adapter
    return startup_runtime_adapter


def _system_resource_dependencies():
    module = _system_resources()
    return module.Dependencies(
        environment=os.environ,
        path_exists=lambda path: path.exists(),
        run_command=run_bounded_command,
        process_error=BoundedProcessError,
    )


def read_mactop_system_sample(
    *,
    cancel_event: threading.Event | None = None,
) -> tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    str,
]:
    return _system_resources().read_mactop_system_sample(
        dependencies=_system_resource_dependencies(),
        cancel_event=cancel_event,
    )


def read_gpu_temperature_celsius(
    *,
    cancel_event: threading.Event | None = None,
) -> tuple[float | None, str]:
    return _system_resources().read_gpu_temperature_celsius(
        dependencies=_system_resource_dependencies(),
        cancel_event=cancel_event,
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


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    _runtime_io().atomic_write_json(path, data)


def atomic_write_private_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically write owner-only runtime state."""
    _runtime_io().atomic_write_private_json(path, data)


def canonical_payload_digest(value: Any) -> str:
    return _runtime_io().canonical_payload_digest(value)


def active_analysis_record_path(run_id: object, active_dir: Path | None = None) -> Path:
    return _runtime_io().active_analysis_record_path(run_id, active_dir if active_dir is not None else DEFAULT_LLM_ACTIVE_DIR)


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    _runtime_io().append_jsonl(path, data)


def best_effort_warning(message: str) -> None:
    """Report supplemental failures without risking the committed job result."""
    _runtime_io().best_effort_warning(message)


def analysis_index_payload(
    analysis_id: str,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    reanalysis_attempt_id: str,
    analysis_started_at: str,
    generated_at: str,
    artifact_path: Path,
) -> dict[str, Any]:
    return _persistence_runtime_adapter().build_analysis_index_payload(
        globals(), analysis_id, prompt_package, response,
        reanalysis_attempt_id, analysis_started_at, generated_at, artifact_path)


def post_analysis_index(
    payload: dict[str, Any],
    alert_store_url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    return _persistence_runtime_adapter().post_analysis_index(
        globals(), payload, alert_store_url, timeout)


def post_controlled_analysis_index(
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    attempts: int = CONTROLLED_RESULT_SUBMISSION_ATTEMPTS,
) -> dict[str, Any]:
    """Retry one immutable controlled result while its exact lease is live."""
    return _persistence_runtime_adapter().post_controlled_analysis_index(
        globals(), payload, alert_store_url, attempts)


def queue_analysis_index(payload: dict[str, Any], queue_dir: Path = DEFAULT_ANALYSIS_INDEX_QUEUE_DIR) -> Path:
    return _persistence_runtime_adapter().queue_analysis_index(
        globals(), payload, queue_dir)


def stage_memory_writeback_task(
    *,
    analysis_id: str,
    response_digest: str,
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
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
) -> Path | None:
    """Durably stage eligible memory intent before the authoritative commit."""
    return _persistence_runtime_adapter().stage_memory_writeback_task(
        globals(), analysis_id=analysis_id, response_digest=response_digest,
        agent_role=agent_role, role_memory_file=role_memory_file,
        shared_memory_file=shared_memory_file, source_artifact=source_artifact,
        primary_candidates=primary_candidates, primary_allowed=primary_allowed,
        primary_reason=primary_reason, reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed, reviewer_reason=reviewer_reason,
        pending_dir=pending_dir)


def mark_memory_writeback_committed(
    analysis_id: str,
    *,
    expected_response_digest: str = "",
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
    committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
) -> Path | None:
    """Move a staged task across the commit boundary atomically."""
    return _persistence_runtime_adapter().mark_memory_writeback_committed(
        globals(), analysis_id,
        expected_response_digest=expected_response_digest,
        pending_dir=pending_dir, committed_dir=committed_dir)


def process_committed_memory_writeback(
    task_path: Path,
    *,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
) -> tuple[dict[str, Any], Path | None]:
    """Replay one post-commit task; successful lanes are analysis-idempotent."""
    return _persistence_runtime_adapter().process_committed_memory_writeback(
        globals(), task_path, receipt_dir=receipt_dir)


def resume_committed_memory_writebacks(
    *,
    committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
    limit: int = 100,
) -> tuple[int, int]:
    return _persistence_runtime_adapter().resume_committed_memory_writebacks(
        globals(), committed_dir=committed_dir,
        receipt_dir=receipt_dir, limit=limit)


def discard_pending_memory_writeback(
    analysis_id: str,
    *,
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
) -> None:
    _persistence_runtime_adapter().discard_pending_memory_writeback(
        globals(), analysis_id, pending_dir=pending_dir)


def quarantine_analysis_index(
    path: Path,
    payload: dict[str, Any],
    error: AnalysisIndexSubmissionError,
    *,
    quarantine_dir: Path = DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR,
) -> Path:
    """Atomically remove one deterministic rejection from the ordered spool."""
    return _persistence_runtime_adapter().quarantine_analysis_index(
        globals(), path, payload, error, quarantine_dir=quarantine_dir)


def flush_analysis_index_queue(
    alert_store_url: str,
    queue_dir: Path = DEFAULT_ANALYSIS_INDEX_QUEUE_DIR,
    quarantine_dir: Path = DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR,
    memory_pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
    memory_committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
    memory_receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
    limit: int = 100,
    memory_writeback_enabled: bool = True,
) -> tuple[int, int, int]:
    return _persistence_runtime_adapter().flush_analysis_index_queue(
        globals(), alert_store_url, queue_dir=queue_dir,
        quarantine_dir=quarantine_dir, memory_pending_dir=memory_pending_dir,
        memory_committed_dir=memory_committed_dir,
        memory_receipt_dir=memory_receipt_dir, limit=limit,
        memory_writeback_enabled=memory_writeback_enabled)


def build_llm_log_record(
    *,
    run_id: str,
    status: str,
    started_at: str,
    finished_at: str | None,
    runtime_seconds: float | None,
    prompt_path: Path | None,
    prompt_package: dict[str, Any],
    settings: dict[str, Any],
    response: dict[str, Any] | None,
    json_path: Path | None,
    md_path: Path | None,
    resource_monitor: SystemResourceMonitor,
    error: str = "",
    runtime_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility delegate for the pure operational run-log projection."""
    return _reporting_runtime_adapter().build_log_record(
        globals(), run_id=run_id, status=status, started_at=started_at,
        finished_at=finished_at, runtime_seconds=runtime_seconds,
        prompt_path=prompt_path, prompt_package=prompt_package,
        settings=settings, response=response, json_path=json_path,
        markdown_path=md_path, resource_monitor=resource_monitor,
        error=error, runtime_observation=runtime_observation,
    )


def latest_prompt(prompt_dir: Path) -> Path:
    return _startup_runtime_adapter().latest_prompt(prompt_dir)


def generate_prompt(args: argparse.Namespace) -> Path:
    """Call the existing prompt builder and return the newly written file path."""
    return _startup_runtime_adapter().generate_prompt(globals(), args)


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a runtime file only while it remains inside its admission limit."""
    return _runtime_io().read_bytes_bounded(
        path, max_bytes, error_type=RuntimeArtifactError)


def load_json(path: Path, max_bytes: int = DEFAULT_MAX_JSON_ARTIFACT_BYTES) -> dict[str, Any]:
    return _runtime_io().load_json(
        path, max_bytes, error_type=RuntimeArtifactError)


def load_system_prompt(path: Path) -> str:
    """Read the editable SOC Analyst prompt, falling back to a safe default."""
    return _runtime_io().load_system_prompt(
        path, max_bytes=DEFAULT_MAX_SYSTEM_PROMPT_BYTES,
        default_prompt=DEFAULT_SYSTEM_PROMPT,
        error_type=RuntimeArtifactError)


def default_ai_settings() -> dict[str, Any]:
    """Return safe local-first AI routing defaults."""
    return _provider_settings_runtime_adapter().default_ai_settings(globals())


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


def _evaluation_runtime_isolation():
    _provider_routing()
    from onion_sentinel.evaluation import runtime_isolation
    return runtime_isolation


def _evaluation_runtime_adapter():
    _provider_routing()
    from onion_sentinel.evaluation import runtime_adapter
    return runtime_adapter


def _evaluation_reviewer_gate():
    _provider_routing()
    from onion_sentinel.evaluation import reviewer_gate
    return reviewer_gate


def _evaluation_reviewer_gate_dependencies():
    module = _evaluation_reviewer_gate()
    return module.Dependencies(
        route_identity=model_route_identity,
        route_is_hosted=model_route_is_hosted,
        build_review_package=independent_reviewer_package,
        validate_reviewer=validate_reviewer_response,
        validate_response=validate_response,
        validation_errors=(ReviewerValidationError, SystemExit, TypeError, ValueError),
        gate_error=ControlledEvaluationReviewerGateError,
    )


def _evaluation_runtime_isolation_policy():
    return _evaluation_runtime_adapter().isolation_policy(
        globals(), _evaluation_runtime_isolation()
    )


def _evaluation_runtime_isolation_dependencies():
    return _evaluation_runtime_adapter().isolation_dependencies(
        globals(), _evaluation_runtime_isolation()
    )


def _evaluation_result_identity():
    _provider_routing()
    from onion_sentinel.evaluation import result_identity
    return result_identity


def _evaluation_result_identity_policy():
    return _evaluation_runtime_adapter().result_policy(
        globals(), _evaluation_result_identity()
    )


def _evaluation_result_identity_dependencies():
    return _evaluation_runtime_adapter().result_dependencies(
        globals(), _evaluation_result_identity()
    )


def controlled_evaluation_runtime(
    runtime: argparse.Namespace | str,
) -> tuple[bool, Path | None]:
    """Resolve an owner-only spool root for one controlled evaluation."""
    return _evaluation_runtime_adapter().resolve_runtime(
        globals(), _evaluation_runtime_isolation(), runtime
    )


def controlled_evaluation_output_dir(
    out_dir: Path,
    runtime_root: Path,
) -> Path:
    """Keep direct controlled output inside its owner-only evaluation root."""
    return _evaluation_runtime_adapter().output_directory(out_dir, runtime_root)


def consume_controlled_evaluation_token(enabled: bool) -> str:
    """Remove the mutation credential before invoking any model subprocess."""
    return _evaluation_runtime_adapter().consume_token(globals(), enabled)


def controlled_evaluation_result_identity(
    enabled: bool,
    *,
    reanalysis_attempt_id: str,
) -> dict[str, Any] | None:
    """Compatibility delegate for server-owned durable lease identity."""
    return _evaluation_runtime_adapter().result_identity(
        globals(),
        _evaluation_result_identity(),
        enabled,
        reanalysis_attempt_id=reanalysis_attempt_id,
    )


def controlled_evaluation_claim_digest(identity: dict[str, Any]) -> str:
    """Hash lease lineage without persisting the bearer token itself."""
    return _evaluation_runtime_adapter().claim_digest(identity)


def require_controlled_evaluation_routes(
    identity: dict[str, Any] | None,
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
) -> None:
    """Compatibility delegate for frozen controlled route admission."""
    _evaluation_runtime_adapter().require_routes(
        globals(),
        _evaluation_result_identity(),
        identity,
        args,
        settings,
        agent_role,
    )


def require_controlled_evaluation_result_routes(
    identity: dict[str, Any] | None,
    response: dict[str, Any],
) -> None:
    """Reject a controlled result unless both frozen routes actually ran."""
    _evaluation_runtime_adapter().require_result_routes(
        identity,
        response,
        gate_error=ControlledEvaluationReviewerGateError,
    )


def apply_evaluation_memory_freeze(
    allowed: bool,
    reason: str,
    *,
    freeze_enabled: bool,
) -> tuple[bool, str]:
    """Disable only memory persistence during a controlled evaluation run."""
    return _evaluation_runtime_adapter().apply_memory_freeze(
        allowed, reason, freeze_enabled=freeze_enabled
    )


def parse_cli_harness_route(
    route: str,
    provider: str,
) -> tuple[str, str] | None:
    return _provider_routing().parse_cli_harness_route(route, provider)


def openclaw_model_uses_ollama_runtime(model: str) -> bool:
    return _provider_routing().openclaw_model_uses_ollama_runtime(model)


def validate_isolated_openclaw_route(
    model: str,
    settings: dict[str, Any],
) -> None:
    return _openclaw_provider().validate_route(
        model,
        settings,
        model_pattern=CLI_HARNESS_MODEL_PATTERN,
        uses_ollama_runtime=openclaw_model_uses_ollama_runtime,
        provider_prefix=OPENCLAW_OLLAMA_PROVIDER_PREFIX,
        supported_urls=OPENCLAW_SUPPORTED_OLLAMA_URLS,
        default_url=DEFAULT_OLLAMA_URL,
    )


def model_route_is_hosted(route: str, settings: dict[str, Any]) -> bool:
    """Return the evidence boundary for an exact configured route."""
    normalized = canonical_model_route(route, enabled_agent_model_routes(settings))
    if normalized.startswith(("codex-cli:", "hermes-agent:")):
        return True
    if parse_cli_harness_route(normalized, "openclaw"):
        # OpenClaw is a third-party harness boundary even when its selected
        # provider happens to be a host-local Ollama runtime. Evidence
        # redaction therefore never depends on the model provider prefix.
        return True
    return False


def enabled_agent_model_routes(settings: dict[str, Any]) -> list[str]:
    return _provider_routing().enabled_agent_model_routes(settings)


def canonical_model_route(value: Any, routes: list[str] | None = None) -> str:
    return _provider_routing().canonical_model_route(value, routes)


def parse_codex_cli_route(route: str) -> tuple[str, str] | None:
    return _provider_routing().parse_codex_cli_route(route)


def assigned_model_metadata(
    settings: dict[str, Any],
    agent_role: str,
) -> tuple[str, str, str]:
    return _provider_routing().assigned_model_metadata(settings, agent_role)


def model_route_metadata(
    settings: dict[str, Any],
    route: str,
) -> tuple[str, str, str, str]:
    return _provider_routing().model_route_metadata(settings, route)


def attest_model_route_response(
    settings: dict[str, Any],
    route: str,
    response: dict[str, Any],
) -> dict[str, Any]:
    return _provider_registry().attest_response(
        settings,
        route,
        response,
        route_metadata=model_route_metadata,
    )


def current_analysis_phase_record(
    current_record: dict[str, Any],
    settings: dict[str, Any],
    *,
    phase: str,
    model_route: str = "",
    trigger_reason: str = "",
) -> dict[str, Any]:
    """Return live-only execution metadata without changing primary log fields."""
    return _reporting_runtime_adapter().phase_record(
        globals(), current_record, settings, phase=phase,
        model_route=model_route, trigger_reason=trigger_reason,
    )


def publish_current_analysis_phase(
    current_record: dict[str, Any],
    settings: dict[str, Any],
    *,
    phase: str,
    model_route: str = "",
    trigger_reason: str = "",
    active_record_path: Path | None = None,
) -> dict[str, Any]:
    """Atomically publish one transient phase for this analysis run."""
    return _reporting_runtime_adapter().publish_phase(
        globals(), current_record, settings, phase=phase,
        model_route=model_route, trigger_reason=trigger_reason,
        active_record_path=active_record_path,
    )


def notify_analysis_phase(
    callback: Callable[[str, str, str], None] | None,
    phase: str,
    model_route: str = "",
    trigger_reason: str = "",
) -> None:
    """Publish optional live status without allowing telemetry to fail analysis."""
    _reporting_runtime_adapter().notify_phase(
        callback, phase, model_route, trigger_reason
    )


def normalize_agent_models(value: Any, routes: list[str]) -> dict[str, str]:
    """Give every agent one valid assignment, falling back deterministically.

    A disabled or removed route must never survive into execution. The first
    enabled route is intentionally used as a predictable fail-safe so roster
    maintenance cannot leave an agent without an analysis backend.
    """
    return _provider_settings_runtime_adapter().normalize_agent_models(
        globals(), value, routes)


def normalize_agent_second_opinion_models(
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
) -> dict[str, str]:
    """Keep optional secondary routes enabled, distinct, and fail-closed."""
    return _provider_settings_runtime_adapter().normalize_agent_second_opinion_models(
        globals(), value, routes, primary_assignments)


def normalize_agent_adjudicator_models(
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
    reviewer_assignments: dict[str, str],
    settings: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Keep adjudicators optional, enabled, and independent of both positions."""
    return _provider_settings_runtime_adapter().normalize_agent_adjudicator_models(
        globals(), value, routes, primary_assignments,
        reviewer_assignments, settings)


def apply_model_roster(settings: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """Migrate legacy single-model settings and derive the compatibility mode."""
    return _provider_settings_runtime_adapter().apply_model_roster(
        globals(), settings, raw)


def normalize_codex_cli_settings(settings: dict[str, Any], raw: dict[str, Any]) -> None:
    """Normalize the fixed Codex adapter without accepting shell fragments."""
    _provider_settings_runtime_adapter().normalize_codex_cli_settings(
        globals(), settings, raw)


def _normalize_harness_executable(value: Any, basename: str) -> str:
    """Validate an exact executable path without accepting flags or shell text."""
    return _provider_settings_runtime_adapter().normalize_harness_executable(
        globals(), value, basename)


def normalize_cli_harness_settings(
    settings: dict[str, Any],
    raw: dict[str, Any],
) -> None:
    """Normalize the two optional, independently enabled agent harnesses."""
    _provider_settings_runtime_adapter().normalize_cli_harness_settings(
        globals(), settings, raw)


def load_ai_settings(path: Path) -> dict[str, Any]:
    """Load model routing settings written by the SOC Settings page."""
    return _provider_settings_runtime_adapter().load_ai_settings(globals(), path)


def resolve_codex_cli(settings: dict[str, Any]) -> str:
    """Resolve only the operator-approved Codex executable."""
    return _provider_settings_runtime_adapter().resolve_codex_cli(
        globals(), settings)


def resolve_cli_harness(
    settings: dict[str, Any],
    *,
    setting_key: str,
    basename: str,
    label: str,
) -> str:
    """Resolve only the operator-approved exact third-party executable."""
    return _provider_settings_runtime_adapter().resolve_cli_harness(
        globals(), settings, setting_key=setting_key,
        basename=basename, label=label)


def effective_ai_settings(args: argparse.Namespace) -> dict[str, Any]:
    """Merge settings file, environment defaults, and explicit CLI overrides."""
    return _provider_settings_runtime_adapter().effective_ai_settings(
        globals(), args)


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse strict JSON, fenced JSON, or the first complete object in output.

    Local models occasionally append a second object or a short explanation.
    ``raw_decode`` accepts the first complete JSON value without broad regex
    repair, preserving the fail-closed contract for malformed evidence.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", stripped):
        try:
            parsed, _ = decoder.raw_decode(stripped, match.start())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    raise SystemExit("model output did not contain a valid JSON object")


MODEL_INTERNAL_KEYS = {
    "analysis_artifact",
    "analysis_dir",
    "tool_paths",
    "system_prompt_file",
    "second_opinion_system_prompt_file",
    "agent_memory_file",
    "shared_memory_file",
    "sha256",
    "_live_osquery_evidence_accumulator",
}
HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES = 8
_MODEL_LIST_PATH_SENTINEL = object()
HOSTED_FORBIDDEN_KEYS = {
    "packet_samples",
    "field_sample_tsv",
    "pcap_follow_up_results",
    "pcap_query_requests",
    "raw_packet_payload",
    "raw_packet_payloads",
    "raw_payload",
    "payload",
    "live_osquery_requests",
    "hex",
    "printable",
    "raw_rule",
    "rule_text",
}


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


EVIDENCE_REFERENCE_MAX = 400
EVIDENCE_REFERENCE_TEXT_MAX = 256
REVIEW_OBSERVABLE_MAX = 256
REVIEW_EVIDENCE_USED_MAX = 100
REVIEW_HYPOTHESES_MAX = 20
REVIEW_VALIDATION_MESSAGE_MAX = 1000
REVIEW_VALIDATION_FAILURE_SCHEMA = (
    "onion-sentinel-reviewer-validation-failure-v1"
)
REVIEW_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![A-Za-z0-9])"
)
REVIEW_DOMAIN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![A-Za-z0-9_-])"
)
REVIEW_COMMUNITY_ID_RE = re.compile(
    # Community ID v1 is the literal version prefix plus a base64-encoded
    # SHA-1 digest: 27 data characters and one padding character. Requiring
    # that exact shape prevents Elasticsearch document-ID suffixes such as
    # ``000535:XuBJm58BIwAfe8Cpckf6`` from becoming foreign observables.
    # Twenty input bytes leave four significant bits in the final base64
    # character, so its two pad bits must be zero for the canonical encoding.
    r"(?<![A-Za-z0-9_])1:[A-Za-z0-9+/]{26}[AEIMQUYcgkosw048]="
    r"(?![A-Za-z0-9_+/=])"
)
REVIEW_OBSERVABLE_KINDS = frozenset({"ip", "domain", "host", "user", "community_id"})
REVIEW_NON_DOMAIN_SUFFIXES = frozenset(
    {
        "csv", "html", "json", "log", "md", "pcap", "pcapng", "py", "toml",
        "txt", "yaml", "yml",
    }
)
def _review_known_field_paths() -> frozenset[str]:
    """Return reviewed dotted field paths and their non-domain prefixes."""
    paths = {
        "dns.question.name", "event.dataset", "event.module", "host.name",
        "network.community_id", "process.name", "rule.id", "rule.name",
        "rule.uuid", "suricata.flags", "source.ip", "destination.ip", "user.name",
    }
    for pack in INVESTIGATION_QUERY_PACK_DEFINITIONS.values():
        for field in pack.get("fields", []):
            parts = str(field).lower().split(".")
            paths.update(".".join(parts[:length]) for length in range(2, len(parts) + 1))
    return frozenset(paths)


REVIEW_KNOWN_FIELD_PATHS = _review_known_field_paths()
REVIEW_TAXONOMY_FIELD_PATHS = frozenset(
    {
        "data_stream_dataset",
        "data_stream_type",
        "event_dataset",
        "event_module",
    }
)
REVIEW_ARTIFACT_FIELD_PATHS = frozenset(
    {
        "command",
        "executable",
        "path",
        "process_command_line",
        "process_executable",
        "process_path",
        "script",
    }
)
REVIEW_ARTIFACT_SUFFIXES = frozenset({"sh"})
REVIEW_RULE_LABEL_FIELD_PATHS = frozenset(
    {
        "alert_signature",
        "rule_name",
        "signature",
    }
)


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


INVESTIGATION_PARAMETER_KEYS = {
    "elastic": frozenset({
        "pack", "window", "observables", "event_tuple", "size", "aggregation",
    }),
    "oql": frozenset({
        "pack", "window", "observables", "event_tuple", "size", "aggregation",
    }),
    "osquery": frozenset({"target_alias", "query"}),
    "pcap_zeek": frozenset({"operation", "filters", "indicator", "limit"}),
    "enrichment": frozenset({"indicator_type", "indicator"}),
}


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


TRUSTED_QUERY_AUDIT_FIELDS = frozenset(
    {
        "query_id",
        "dialect",
        "backend",
        "pack",
        "purpose",
        "aggregation",
        "window",
        "observables",
        "observable_provenance",
        "event_tuple",
        "event_tuple_provenance",
        "requested_size",
        "match_semantics",
        "anchor_time",
        "result_coverage",
        "execution_backend",
        "semantics",
        "index_scope",
        "query_endpoint",
        "endpoint",
        "query_dsl",
        "query",
        "query_digest",
        "result_digest",
        "execution_digest",
        "request_digest",
        "item_digest",
        "kql_equivalent",
        "kql_digest",
        "oql_equivalent",
        "oql_digest",
        "target_alias",
        "operation",
        "filters",
        "indicator",
        "limit",
        "status",
        "semantic_valid",
        "total_hits",
        "returned_hits",
        "total_rows",
        "returned_rows",
        "candidate_records_scanned",
        "unique_records_matched",
        "records_returned",
        "truncated",
        "result_truncated",
        "index_scan_truncated",
        "derived_views_considered",
        "duration_ms",
        "timed_out",
        "took_ms",
        "shards",
        "error",
        "evidence_summary",
        "evidence_ref",
    }
)


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

INVESTIGATION_QUERY_NONEXECUTION_STATUSES = frozenset(
    {"rejected", "denied", "blocked", "unauthorized", "forbidden"}
)


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


STRUCTURED_ENUMS: dict[str, list[str]] = {
    "event_status": sorted(EVENT_STATUS_VALUES),
    "detection_validity": sorted(DETECTION_VALIDITY_VALUES),
    "activity_disposition": sorted(ACTIVITY_DISPOSITION_VALUES),
    "handling": sorted(HANDLING_VALUES),
    "detection_outcome": sorted(DETECTION_OUTCOME_VALUES),
    "confidence": sorted(CONFIDENCE_VALUES),
    "tuning_recommendation": sorted(TUNING_VALUES),
    "scope": ["agent", "shared"],
    "status": ["supported", "contradicted", "unresolved"],
    "kind": sorted(REVIEW_OBSERVABLE_KINDS),
}
STRUCTURED_BOOLEAN_KEYS = frozenset(
    {
        "escalation_needed",
        "hosted_second_opinion_recommended",
        "second_opinion_recommended",
        "correlation_found",
    }
)


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
    from onion_sentinel import pipeline as pipeline_module
    from onion_sentinel import preparation as preparation_module
    from onion_sentinel import startup as startup_module
    from onion_sentinel.analysis.persistence import memory_policy as memory_policy_module
    from onion_sentinel.analysis.persistence import postcommit as postcommit_module
    from onion_sentinel.analysis.persistence import transaction as transaction_module
    from onion_sentinel.analysis.query import audit as query_audit_module
    args = parse_args()
    bootstrap = legacy_adapters.bootstrap_pipeline(
        globals(), startup_module, pipeline_module, args)
    if bootstrap.exit_code is not None:
        return bootstrap.exit_code
    controlled_evaluation = bootstrap.controlled
    runtime_paths = bootstrap.runtime_paths
    evaluation_memory_frozen = bootstrap.memory_frozen
    controlled_result_identity = bootstrap.controlled_identity
    prompt_path: Path | None = args.prompt_package
    prompt_package: dict[str, Any] = {}
    settings: dict[str, Any] = {}
    response: dict[str, Any] | None = None
    json_path: Path | None = None
    md_path: Path | None = None
    running_record: dict[str, Any] = {}
    started_at = project_now()
    started_monotonic = time.monotonic()
    run_id = hashlib.sha1(f"{started_at}:{prompt_path or ''}:{os.getpid()}".encode("utf-8")).hexdigest()[:16]
    pipeline_context = pipeline_module.RuntimeContext(
        run_id,
        arguments=args,
        controlled_evaluation=controlled_evaluation,
        runtime_dir=bootstrap.runtime_dir,
        paths=runtime_paths,
        prompt_path=prompt_path,
    )
    active_record_path = active_analysis_record_path(
        run_id, active_dir=runtime_paths.active_dir)
    resource_monitor = SystemResourceMonitor()
    status, error, monitor_started = "failure", "", False
    harness_runtime: OnionSentinelHarnessRun | None = None
    prepared: preparation_module.PreparedRuntime | None = None

    try:
        startup_module.reconcile_deferred_results(
            controlled=controlled_evaluation,
            memory_frozen=evaluation_memory_frozen,
            alert_store_url=args.alert_store_url,
            flush_queue=lambda url, enabled: flush_analysis_index_queue(
                url, memory_writeback_enabled=enabled),
        )
        attested = _startup_runtime_adapter().load_and_attest(
            globals(), startup_module, pipeline_context, args,
            controlled_result_identity)
        prompt_path = attested.prompt_path
        prompt_package = attested.prompt_package
        agent_role = attested.agent_role
        settings = attested.settings
        live_osquery_config = attested.live_osquery_config
        enrichment_config = attested.enrichment_config
        prepared = legacy_adapters.prepare_runtime(
            globals(), preparation_module, pipeline_context, args=args, run_id=run_id,
            prompt_path=prompt_path, prompt_package=prompt_package,
            settings=settings, agent_role=agent_role,
            memory_frozen=evaluation_memory_frozen, started_at=started_at,
            active_record_path=active_record_path,
            resource_monitor=resource_monitor,
        )
        harness_runtime = prepared.harness
        running_record = prepared.running_record
        monitor_started = prepared.monitor_started
        observe_harness = prepared.observe
        update_current_phase = prepared.update_phase
        analysis_review = pipeline_module.run_analysis_review(
            pipeline_context,
            policy=pipeline_module.AnalysisReviewPolicy(
                saved_response=bool(args.response_json),
                controlled_reviewer_required=bool(
                    controlled_result_identity is not None
                    and controlled_result_identity.get("reviewer_required") is True
                ),
                freeze_enabled=evaluation_memory_frozen,
            ),
            ports=legacy_adapters.analysis_review_ports(
                globals(), pipeline_module, args=args, prompt_package=prompt_package,
                settings=settings, agent_role=agent_role,
                live_osquery_config=live_osquery_config,
                enrichment_config=enrichment_config,
                controlled_identity=controlled_result_identity,
                harness_runtime=harness_runtime,
                observe_harness=observe_harness,
                update_phase=update_current_phase),
        )
        response = analysis_review.response
        query_audit_module.attach_incident_attestation(
            response, prompt_package, agent_role=agent_role,
            dependencies=query_audit_module.IncidentAttestationDependencies(
                query_audit=incident_query_audit,
                osquery_audit=incident_osquery_audit,
                live_osquery_audit=incident_live_osquery_audit,
            ),
        )
        memory_guards = memory_policy_module.apply_memory_guards(
            response,
            policy=memory_policy_module.MemoryGuardPolicy(
                evaluation_memory_frozen, controlled_result_identity),
            ports=legacy_adapters.memory_guard_ports(
                globals(), memory_policy_module, harness_runtime, observe_harness),
        )
        raw_memory_candidates = memory_guards.primary_candidates
        primary_memory_allowed = memory_guards.primary_allowed
        primary_memory_reason = memory_guards.primary_reason
        reviewer_memory_candidates = memory_guards.reviewer_candidates
        reviewer_memory_allowed = memory_guards.reviewer_allowed
        reviewer_memory_reason = memory_guards.reviewer_reason
        role_memory_file = Path(
            str(prompt_package.get("agent_memory_file") or "")
        ).expanduser()
        shared_memory_file = Path(
            str(prompt_package.get("shared_memory_file") or "")
        ).expanduser()
        # All enforce-mode runtime checks finish before artifact or alert-store
        # persistence creates a production side effect. Memory remains a staged
        # plan until the authoritative analysis commit succeeds.
        observe_harness(
            lambda: harness_runtime.preflight_completion(
                operation_id="pre-side-effects",
            )
            if harness_runtime is not None
            else None
        )
        observe_harness(
            lambda: harness_runtime.record_response(
                response,
                decision_id="final",
                decision_type="post-review-analysis",
                hypothesis_revision=100,
            )
            if harness_runtime is not None
            else None
        )
        pipeline_context.advance(pipeline_module.Stage.DETERMINISTIC_GUARDS, "final guards applied")
        submitted_response_sha256 = canonical_payload_digest(response)
        staged_memory_task = stage_memory_writeback_task(
            analysis_id=run_id,
            response_digest=submitted_response_sha256,
            agent_role=agent_role,
            role_memory_file=role_memory_file,
            shared_memory_file=shared_memory_file,
            source_artifact=str(prompt_path),
            primary_candidates=raw_memory_candidates,
            primary_allowed=primary_memory_allowed,
            primary_reason=primary_memory_reason,
            reviewer_candidates=reviewer_memory_candidates,
            reviewer_allowed=reviewer_memory_allowed,
            reviewer_reason=reviewer_memory_reason,
            pending_dir=runtime_paths.memory_pending_dir,
        )
        pipeline_context.advance(pipeline_module.Stage.VALIDATE, "commit inputs validated")
        publication = transaction_module.publish(
            policy=transaction_module.PublicationPolicy(
                controlled=controlled_evaluation,
                controlled_identity=controlled_result_identity,
                submission_error=AnalysisIndexSubmissionError,
                indeterminate_message=CONTROLLED_RESULT_SUBMISSION_INDETERMINATE,
            ),
            ports=legacy_adapters.publication_ports(
                globals(), transaction_module, args=args, run_id=run_id,
                prompt_path=prompt_path, prompt_package=prompt_package,
                response=response, started_at=started_at,
                runtime_paths=runtime_paths, harness=harness_runtime,
                observe=observe_harness),
        )
        json_path = publication.json_path
        md_path = publication.markdown_path
        index_payload = publication.index_payload
        pending_index_path = publication.pending_index_path
        commit_receipt = publication.commit_receipt
        # The alert store now owns the committed success. A subsequent audit
        # finalization problem must be visible, but must not turn that durable
        # success into a failed model job that gets retried.
        status = "success"
        pipeline_context.artifacts = (json_path, md_path)
        pipeline_context.advance(pipeline_module.Stage.COMMIT, "analysis index committed")
        memory_promotion = transaction_module.promote_memory(
            analysis_id=run_id,
            staged_task=staged_memory_task,
            pending_index_path=pending_index_path,
            ports=legacy_adapters.memory_promotion_ports(
                globals(), transaction_module, run_id=run_id,
                response_digest=submitted_response_sha256,
                runtime_paths=runtime_paths, agent_role=agent_role,
                role_memory_file=role_memory_file,
                shared_memory_file=shared_memory_file,
                prompt_path=prompt_path, guards=memory_guards),
        )
        memory_receipt = memory_promotion.receipt
        memory_receipt_path = memory_promotion.receipt_path
        legacy_adapters.finalize_harness_completion(
            globals(), postcommit_module, harness_runtime, run_id=run_id,
            response_digest=submitted_response_sha256,
            commit_receipt=commit_receipt, json_path=json_path, md_path=md_path,
            response=response, memory_frozen=evaluation_memory_frozen,
            memory_receipt=memory_receipt,
            memory_receipt_path=memory_receipt_path)
        pipeline_context.advance(pipeline_module.Stage.POST_COMMIT, "post-commit work finalized")
        legacy_adapters.print_committed_outputs(
            globals(), md_path, json_path, response, args.stdout)
        pipeline_context.advance(pipeline_module.Stage.COMPLETE, "analysis pipeline completed")
        return 0
    except SystemExit as exc:
        error = str(exc) if str(exc) else f"SystemExit({exc.code})"
        pipeline_context.fail_if_active(error)
        raise
    except Exception as exc:
        error = str(exc)
        pipeline_context.fail_if_active(error)
        raise
    finally:
        from onion_sentinel import telemetry as telemetry_module
        legacy_adapters.finalize_pipeline_telemetry(
            globals(), telemetry_module, status=status, error=error,
            monitor_started=monitor_started, harness=harness_runtime,
            resource_monitor=resource_monitor, started_at=started_at,
            started_monotonic=started_monotonic, run_id=run_id,
            prompt_path=prompt_path, prompt_package=prompt_package,
            settings=settings, args=args, response=response,
            json_path=json_path, md_path=md_path, runtime_paths=runtime_paths,
            running_record=(prepared.running_record if prepared else running_record),
            active_record_path=active_record_path)


if __name__ == "__main__":
    if str(BIN_DIR.parent) not in sys.path:
        sys.path.insert(0, str(BIN_DIR.parent))
    from onion_sentinel.composition import invoke_legacy_entrypoint

    raise SystemExit(invoke_legacy_entrypoint(globals()))
