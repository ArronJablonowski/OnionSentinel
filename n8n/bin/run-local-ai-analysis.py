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
import shlex
import shutil
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, NoReturn
from urllib.parse import urlparse
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
    parser = argparse.ArgumentParser(description="Run local AI analysis for a SOC alert prompt package")
    parser.add_argument("--prompt-package", type=Path, help="Prompt package JSON to analyze")
    parser.add_argument("--prompt-dir", type=Path, default=DEFAULT_PROMPT_DIR, help="Directory containing prompt packages")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Directory for AI analysis JSON/Markdown output")
    parser.add_argument("--ai-settings-file", type=Path, default=DEFAULT_AI_SETTINGS_FILE, help="AI model routing settings JSON")
    parser.add_argument(
        "--investigation-harness-policy",
        type=Path,
        default=DEFAULT_INVESTIGATION_HARNESS_POLICY,
        help="Versioned Onion Sentinel investigation harness policy",
    )
    parser.add_argument(
        "--investigation-harness-db",
        type=Path,
        default=DEFAULT_INVESTIGATION_HARNESS_DB,
        help="Owner-only durable investigation harness event store",
    )
    parser.add_argument("--analysis-mode", choices=("ollama", "cloud", "hybrid"), help="Override configured analysis mode")
    parser.add_argument(
        "--model",
        help="Override the configured Ollama roster with one model for this invocation",
    )
    parser.add_argument(
        "--ollama-url",
        help="Override the configured Ollama base URL for this invocation",
    )
    parser.add_argument("--system-prompt-file", type=Path, default=DEFAULT_SYSTEM_PROMPT_FILE, help="Editable SOC Analyst system prompt file")
    parser.add_argument(
        "--second-opinion-prompt-file",
        type=Path,
        default=DEFAULT_SECOND_OPINION_PROMPT_FILE,
        help="Independent second-opinion system prompt file",
    )
    parser.add_argument(
        "--disagreement-adjudicator-prompt-file",
        type=Path,
        default=DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT_FILE,
        help="Bounded shadow-mode disagreement adjudicator system prompt file",
    )
    parser.add_argument(
        "--live-osquery-config",
        type=Path,
        default=DEFAULT_LIVE_OSQUERY_CONFIG_FILE,
        help="Explicit live OSQuery capability configuration",
    )
    parser.add_argument(
        "--incident-evidence-config",
        type=Path,
        default=DEFAULT_INCIDENT_EVIDENCE_CONFIG_FILE,
        help="Explicit restricted read-only Relay evidence transport config",
    )
    parser.add_argument(
        "--investigation-pivot-dir",
        type=Path,
        default=DEFAULT_INVESTIGATION_PIVOT_DIR,
        help="Directory for restricted dynamic-investigation pivot artifacts",
    )
    parser.add_argument("--timeout", type=int, default=600, help="Ollama request timeout in seconds")
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=DEFAULT_OLLAMA_MAX_RESPONSE_BYTES,
        help="Maximum bytes accepted from one local or cloud model response",
    )
    parser.add_argument(
        "--max-prompt-bytes",
        type=int,
        default=DEFAULT_MAX_PROMPT_BYTES,
        help="Maximum serialized prompt-package bytes admitted to a model call",
    )
    parser.add_argument(
        "--max-predict-tokens",
        type=int,
        default=4096,
        help="Maximum output tokens for one bounded local analysis",
    )
    parser.add_argument("--temperature", type=float, default=0.1, help="Low temperature keeps SOC analysis repeatable")
    parser.add_argument("--response-json", type=Path, help="Use an existing model response JSON instead of calling Ollama")
    parser.add_argument("--generate-prompt", action="store_true", help="Generate a fresh prompt package before analysis")
    parser.add_argument("--levels", default="critical,high,medium,low,informational", help="Levels passed to prompt generation")
    parser.add_argument("--hours", type=int, default=24, help="Lookback hours passed to prompt generation")
    parser.add_argument("--related-limit", type=int, default=8, help="Related alert limit passed to prompt generation")
    parser.add_argument("--correlation-limit", type=int, default=8, help="Correlation candidate limit passed to prompt generation")
    parser.add_argument("--correlation-min-score", type=int, default=15, help="Minimum deterministic correlation score")
    parser.add_argument("--alert-store-url", default=os.environ.get("ALERT_STORE_URL", "http://127.0.0.1:8787"), help="Alert-store URL for durable analysis indexing")
    parser.add_argument(
        "--reanalysis-attempt-id",
        default="",
        help="Non-secret immutable Incident Responder lease fingerprint",
    )
    parser.add_argument(
        "--flush-index-only",
        action="store_true",
        help="Publish deferred analysis indexes and exit without invoking a model",
    )
    parser.add_argument("--stdout", action="store_true", help="Print paths and response JSON after writing files")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_predict_tokens <= 0:
        parser.error("--max-predict-tokens must be positive")
    if args.max_response_bytes <= 0:
        parser.error("--max-response-bytes must be positive")
    if args.max_prompt_bytes < 256 * 1024:
        parser.error("--max-prompt-bytes must be at least 262144")
    if args.correlation_limit <= 0:
        parser.error("--correlation-limit must be positive")
    if args.correlation_min_score < 0 or args.correlation_min_score > 100:
        parser.error("--correlation-min-score must be between 0 and 100")
    if args.reanalysis_attempt_id and not re.fullmatch(
        r"ira-[a-f0-9]{40}",
        args.reanalysis_attempt_id,
    ):
        parser.error("--reanalysis-attempt-id is invalid")
    return args


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


def prompt_alert_summary(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Return bounded alert metadata suitable for an operational LLM run log."""
    alert = prompt_package.get("alert") if isinstance(prompt_package.get("alert"), dict) else {}
    grouped = prompt_package.get("grouped_alert_context") if isinstance(prompt_package.get("grouped_alert_context"), dict) else {}
    timeline = grouped.get("timeline") if isinstance(grouped.get("timeline"), list) else []
    alert_ids: list[str] = []
    for item in timeline[:25]:
        if isinstance(item, dict) and item.get("alert_id"):
            alert_ids.append(str(item.get("alert_id")))
    primary_alert_id = str(alert.get("alert_id") or "").strip()
    if primary_alert_id and primary_alert_id not in alert_ids:
        alert_ids.insert(0, primary_alert_id)
    alert_count = grouped.get("raw_alert_rows") or grouped.get("total_observations") or alert.get("seen_count") or len(alert_ids) or 1
    try:
        alert_count = max(1, int(alert_count))
    except (TypeError, ValueError):
        alert_count = 1
    return {
        "primary_alert_id": primary_alert_id,
        "alert_ids": alert_ids,
        "alert_ids_truncated": max(0, len(timeline) - len(alert_ids)),
        "alert_count": alert_count,
        "rule_name": str(alert.get("rule_name") or "Security Onion Alert"),
        "triage_level": str(alert.get("triage_level") or "unknown"),
        "triage_score": alert.get("triage_score"),
        "source_ip": str(alert.get("source_ip") or ""),
        "destination_ip": str(alert.get("destination_ip") or ""),
        "destination_port": str(alert.get("destination_port") or ""),
        "first_seen": str(grouped.get("first_seen") or alert.get("first_seen") or ""),
        "last_seen": str(grouped.get("last_seen") or alert.get("last_seen") or ""),
        "total_observations": grouped.get("total_observations", alert.get("seen_count")),
    }


def prompt_pcap_size_bytes(prompt_package: dict[str, Any]) -> int:
    pcap_evidence = prompt_package.get("pcap_evidence") if isinstance(prompt_package.get("pcap_evidence"), dict) else {}
    parsed = pcap_evidence.get("parsed_evidence") if isinstance(pcap_evidence.get("parsed_evidence"), list) else []
    total = 0
    seen: set[tuple[str, str]] = set()
    for record in parsed:
        if not isinstance(record, dict):
            continue
        request_id = str(record.get("request_id") or "")
        files = record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else []
        for item in files:
            if not isinstance(item, dict):
                continue
            key = (request_id, str(item.get("sha256") or item.get("name") or ""))
            if key in seen:
                continue
            seen.add(key)
            try:
                total += max(0, int(item.get("size_bytes") or 0))
            except (TypeError, ValueError):
                continue
    return total


def prompt_alert_context_size_bytes(prompt_package: dict[str, Any]) -> int:
    context = {
        "alert": prompt_package.get("alert"),
        "grouped_alert_context": prompt_package.get("grouped_alert_context"),
        "public_enrichment": prompt_package.get("public_enrichment"),
        "analyst_state": prompt_package.get("analyst_state"),
        "pcap_evidence": prompt_package.get("pcap_evidence"),
    }
    return len(json.dumps(context, sort_keys=True, default=str).encode("utf-8"))


def parse_gpu_temperature(output: str) -> float | None:
    """Extract a GPU temperature from common macOS sensor command output."""
    matches = re.findall(r"(?im)\bgpu\b[^\n:]*[:=]?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:°\s*)?c\b", output)
    if not matches:
        matches = re.findall(r"(?im)\bgpu\b.*?([0-9]+(?:\.[0-9]+)?)\s*(?:°\s*)?c\b", output)
    if not matches:
        return None
    values = [float(value) for value in matches]
    return max(values) if values else None


def mactop_command() -> list[str] | None:
    custom = os.environ.get("SOC_MACTOP_COMMAND", "").strip()
    if custom:
        return shlex.split(custom)
    for path in (
        "/opt/homebrew/bin/mactop",
        "/usr/local/bin/mactop",
        "mactop",
    ):
        if path.startswith("/") and not Path(path).exists():
            continue
        return [path]
    return None


def parse_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def parse_mactop_sample(
    output: str,
) -> tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
]:
    """Return max-relevant system metrics from mactop JSON for one sample."""
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None, None, None, None, None, None, None
    sample = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(sample, dict):
        return None, None, None, None, None, None, None
    soc_metrics = sample.get("soc_metrics") if isinstance(sample.get("soc_metrics"), dict) else {}
    gpu_metrics = sample.get("gpu_metrics") if isinstance(sample.get("gpu_metrics"), dict) else {}
    gpu_temp_value = parse_float(soc_metrics.get("gpu_temp"))
    gpu_percent = parse_float(gpu_metrics.get("active_percent"))
    if gpu_percent is None:
        gpu_percent = parse_float(sample.get("gpu_usage"))
    if gpu_percent is None:
        gpu_percent = parse_float(soc_metrics.get("gpu_active"))
    cpu_temp_value = parse_float(soc_metrics.get("cpu_temp"))
    soc_temp_value = parse_float(soc_metrics.get("soc_temp"))
    power_watts = parse_float(soc_metrics.get("total_power"))
    if power_watts is None:
        power_watts = parse_float(soc_metrics.get("system_power"))
    cpu_percent = parse_float(sample.get("cpu_usage"))

    memory = sample.get("memory") if isinstance(sample.get("memory"), dict) else {}
    used = memory.get("used")
    total = memory.get("total")
    try:
        memory_percent = (float(used) / float(total)) * 100 if used is not None and total else None
    except (TypeError, ValueError, ZeroDivisionError):
        memory_percent = None
    return gpu_temp_value, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp_value, soc_temp_value


class ResourceSamplingCancelled(RuntimeError):
    """Raised inside a bounded sampler when its owning monitor is stopping."""


def _raise_if_resource_sampling_cancelled(
    cancel_event: threading.Event | None,
) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ResourceSamplingCancelled("system resource sampling cancelled")


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
    command = mactop_command()
    if not command:
        return None, None, None, None, None, None, None, "mactop not found"
    if cancel_event is not None and cancel_event.is_set():
        return None, None, None, None, None, None, None, "mactop sampling cancelled"
    try:
        proc = run_bounded_command(
            [*command, "--headless", "--format", "json", "--count", "1"],
            timeout_seconds=8,
            max_stdout_bytes=2 * 1024 * 1024,
            max_stderr_bytes=256 * 1024,
            progress_callback=(
                lambda: _raise_if_resource_sampling_cancelled(cancel_event)
                if cancel_event is not None
                else None
            ),
            progress_interval_seconds=0.1,
        )
    except ResourceSamplingCancelled:
        return None, None, None, None, None, None, None, "mactop sampling cancelled"
    except FileNotFoundError:
        return None, None, None, None, None, None, None, f"{command[0]} not found"
    except BoundedProcessError as exc:
        return None, None, None, None, None, None, None, f"{command[0]} unavailable: {exc}"
    except Exception as exc:
        return None, None, None, None, None, None, None, f"{command[0]} failed: {exc}"
    if proc.returncode != 0 and not proc.stdout.strip():
        detail = (proc.stderr or "").strip().splitlines()
        return None, None, None, None, None, None, None, f"{command[0]} unavailable" + (f": {detail[-1][:120]}" if detail else "")
    gpu_temp, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp, soc_temp = parse_mactop_sample(proc.stdout)
    if any(value is not None for value in (gpu_temp, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp, soc_temp)):
        return gpu_temp, memory_percent, power_watts, cpu_percent, gpu_percent, cpu_temp, soc_temp, "mactop sampled"
    return None, None, None, None, None, None, None, f"{command[0]} returned no parseable mactop metrics"


def read_gpu_temperature_celsius(
    *,
    cancel_event: threading.Event | None = None,
) -> tuple[float | None, str]:
    """Read GPU temperature if the Mac exposes it to an unprivileged command."""
    commands: list[list[str]] = []
    custom = os.environ.get("SOC_GPU_TEMP_COMMAND", "").strip()
    if custom:
        commands.append(shlex.split(custom))
    commands.extend([
        ["powermetrics", "--samplers", "smc", "-n", "1", "-i", "500"],
        ["/usr/bin/powermetrics", "--samplers", "smc", "-n", "1", "-i", "500"],
    ])
    notes: list[str] = []
    for command in commands:
        if cancel_event is not None and cancel_event.is_set():
            return None, "GPU temperature sampling cancelled"
        try:
            proc = run_bounded_command(
                command,
                timeout_seconds=4,
                max_stdout_bytes=2 * 1024 * 1024,
                max_stderr_bytes=256 * 1024,
                progress_callback=(
                    lambda: _raise_if_resource_sampling_cancelled(cancel_event)
                    if cancel_event is not None
                    else None
                ),
                progress_interval_seconds=0.1,
            )
        except ResourceSamplingCancelled:
            return None, "GPU temperature sampling cancelled"
        except FileNotFoundError:
            notes.append(f"{command[0]} not found")
            continue
        except BoundedProcessError as exc:
            notes.append(f"{command[0]} unavailable: {exc}")
            continue
        except Exception as exc:
            notes.append(f"{command[0]} failed: {exc}")
            continue
        output = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
        value = parse_gpu_temperature(output)
        if value is not None:
            return value, "GPU temperature sampled"
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        notes.append(f"{command[0]} unavailable" + (f": {detail[-1][:120]}" if detail else ""))
    return None, "; ".join(notes[:3]) or "GPU temperature unavailable"


class SystemResourceMonitor:
    """Best-effort mactop sampler for max system metrics per run."""

    def __init__(self, interval_seconds: float = 5.0) -> None:
        self.interval_seconds = interval_seconds
        self.max_gpu_celsius: float | None = None
        self.max_memory_percent: float | None = None
        self.max_power_watts: float | None = None
        self.max_cpu_percent: float | None = None
        self.max_gpu_percent: float | None = None
        self.max_cpu_celsius: float | None = None
        self.max_soc_celsius: float | None = None
        self.note = "system metrics not sampled"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("system resource monitor was already started")
        self._stop.clear()
        self._sample_once()
        self._thread = threading.Thread(
            target=self._run,
            name="system-resource-monitor",
            daemon=False,
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(self.interval_seconds):
                break
            self._sample_once()

    def _sample_once(self) -> None:
        if self._stop.is_set():
            return
        gpu_value, memory_value, power_value, cpu_value, gpu_percent, cpu_temp, soc_temp, note = read_mactop_system_sample(
            cancel_event=self._stop,
        )
        if self._stop.is_set():
            return
        if gpu_value is None:
            gpu_value, fallback_note = read_gpu_temperature_celsius(
                cancel_event=self._stop,
            )
            if self._stop.is_set():
                return
            if gpu_value is not None:
                note = f"{note}; {fallback_note}"
        self.note = note
        if gpu_value is not None:
            self.max_gpu_celsius = gpu_value if self.max_gpu_celsius is None else max(self.max_gpu_celsius, gpu_value)
        if memory_value is not None:
            self.max_memory_percent = memory_value if self.max_memory_percent is None else max(self.max_memory_percent, memory_value)
        if power_value is not None:
            self.max_power_watts = power_value if self.max_power_watts is None else max(self.max_power_watts, power_value)
        if cpu_value is not None:
            self.max_cpu_percent = cpu_value if self.max_cpu_percent is None else max(self.max_cpu_percent, cpu_value)
        if gpu_percent is not None:
            self.max_gpu_percent = gpu_percent if self.max_gpu_percent is None else max(self.max_gpu_percent, gpu_percent)
        if cpu_temp is not None:
            self.max_cpu_celsius = cpu_temp if self.max_cpu_celsius is None else max(self.max_cpu_celsius, cpu_temp)
        if soc_temp is not None:
            self.max_soc_celsius = soc_temp if self.max_soc_celsius is None else max(self.max_soc_celsius, soc_temp)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is None:
            return
        thread.join(timeout=12)
        if thread.is_alive():
            raise RuntimeError(
                "system resource monitor did not terminate after cancellation"
            )
        self._thread = None


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def atomic_write_private_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically write owner-only runtime state."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, stat.S_IRWXU)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        tmp.unlink(missing_ok=True)


def canonical_payload_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def active_analysis_record_path(run_id: object, active_dir: Path | None = None) -> Path:
    directory = active_dir if active_dir is not None else DEFAULT_LLM_ACTIVE_DIR
    safe_run_id = re.sub(r"[^A-Za-z0-9_-]+", "-", str(run_id or "analysis")).strip("-_")
    return directory / f"{(safe_run_id or 'analysis')[:120]}.json"


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=True) + "\n")


def best_effort_warning(message: str) -> None:
    """Report supplemental failures without risking the committed job result."""
    try:
        sys.stderr.write(f"warning: {message}\n")
        sys.stderr.flush()
    except Exception:
        pass


def analysis_index_payload(
    analysis_id: str,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    reanalysis_attempt_id: str,
    analysis_started_at: str,
    generated_at: str,
    artifact_path: Path,
) -> dict[str, Any]:
    return _analysis_index_persistence().build_payload(
        analysis_id,
        prompt_package,
        response,
        reanalysis_attempt_id,
        analysis_started_at,
        generated_at,
        artifact_path,
    )


def post_analysis_index(
    payload: dict[str, Any],
    alert_store_url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    return _analysis_index_persistence().post(
        payload,
        alert_store_url,
        timeout=timeout,
        max_response_bytes=ANALYSIS_INDEX_MAX_RESPONSE_BYTES,
        read_bounded_json=read_bounded_json,
        submission_error=AnalysisIndexSubmissionError,
        environment=os.environ,
        evaluation_mode_env=CONTROLLED_EVALUATION_MODE_ENV,
        evaluation_token_env=CONTROLLED_EVALUATION_TOKEN_ENV,
        evaluation_token_header=CONTROLLED_EVALUATION_TOKEN_HEADER,
        evaluation_token_pattern=CONTROLLED_EVALUATION_TOKEN_RE,
        fallback_evaluation_token=_CONTROLLED_EVALUATION_TOKEN,
    )


def post_controlled_analysis_index(
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    attempts: int = CONTROLLED_RESULT_SUBMISSION_ATTEMPTS,
) -> dict[str, Any]:
    """Retry one immutable controlled result while its exact lease is live."""
    return _analysis_index_persistence().post_with_retry(
        payload,
        alert_store_url,
        post_result=post_analysis_index,
        submission_error=AnalysisIndexSubmissionError,
        attempts=attempts,
    )


def queue_analysis_index(payload: dict[str, Any], queue_dir: Path = DEFAULT_ANALYSIS_INDEX_QUEUE_DIR) -> Path:
    return _analysis_index_persistence().queue(
        payload,
        queue_dir,
        safe_filename=safe_filename,
        load_json=load_json,
        canonical_digest=canonical_payload_digest,
        atomic_write_private_json=atomic_write_private_json,
    )


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
    return _memory_journal_persistence().stage(
        analysis_id=analysis_id, response_digest=response_digest,
        agent_role=agent_role, role_memory_file=role_memory_file,
        shared_memory_file=shared_memory_file, source_artifact=source_artifact,
        primary_candidates=primary_candidates, primary_allowed=primary_allowed,
        primary_reason=primary_reason, reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed, reviewer_reason=reviewer_reason,
        pending_dir=pending_dir, schema=MEMORY_WRITEBACK_TASK_SCHEMA,
        max_bytes=MAX_MEMORY_WRITEBACK_TASK_BYTES,
        normalize_candidates=normalize_memory_candidates,
        canonical_digest=canonical_payload_digest, safe_filename=safe_filename,
        load_json=load_json, atomic_write_private_json=atomic_write_private_json,
    )


def mark_memory_writeback_committed(
    analysis_id: str,
    *,
    expected_response_digest: str = "",
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
    committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
) -> Path | None:
    """Move a staged task across the commit boundary atomically."""
    return _memory_journal_persistence().mark_committed(
        analysis_id, expected_response_digest=expected_response_digest,
        pending_dir=pending_dir, committed_dir=committed_dir,
        max_bytes=MAX_MEMORY_WRITEBACK_TASK_BYTES, safe_filename=safe_filename,
        load_json=load_json, canonical_digest=canonical_payload_digest,
    )


def process_committed_memory_writeback(
    task_path: Path,
    *,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
) -> tuple[dict[str, Any], Path | None]:
    """Replay one post-commit task; successful lanes are analysis-idempotent."""
    return _memory_journal_persistence().process_committed(
        task_path, receipt_dir=receipt_dir, schema=MEMORY_WRITEBACK_TASK_SCHEMA,
        max_bytes=MAX_MEMORY_WRITEBACK_TASK_BYTES, safe_filename=safe_filename,
        load_json=load_json, canonical_digest=canonical_payload_digest,
        persist=persist_postcommit_memory_writeback,
    )


def resume_committed_memory_writebacks(
    *,
    committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
    limit: int = 100,
) -> tuple[int, int]:
    return _memory_journal_persistence().resume(
        committed_dir=committed_dir, receipt_dir=receipt_dir, limit=limit,
        process=process_committed_memory_writeback,
    )


def discard_pending_memory_writeback(
    analysis_id: str,
    *,
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
) -> None:
    _memory_journal_persistence().discard(
        analysis_id, pending_dir=pending_dir, safe_filename=safe_filename,
    )


def quarantine_analysis_index(
    path: Path,
    payload: dict[str, Any],
    error: AnalysisIndexSubmissionError,
    *,
    quarantine_dir: Path = DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR,
) -> Path:
    """Atomically remove one deterministic rejection from the ordered spool."""
    return _analysis_index_persistence().quarantine(
        path,
        payload,
        error,
        quarantine_dir=quarantine_dir,
        atomic_write_json=atomic_write_json,
        now=project_now,
    )


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
    return _analysis_index_persistence().flush(
        alert_store_url,
        queue_dir=queue_dir,
        quarantine_dir=quarantine_dir,
        memory_pending_dir=memory_pending_dir,
        memory_committed_dir=memory_committed_dir,
        memory_receipt_dir=memory_receipt_dir,
        limit=limit,
        memory_writeback_enabled=memory_writeback_enabled,
        submission_error=AnalysisIndexSubmissionError,
        load_json=load_json,
        post_result=post_analysis_index,
        canonical_digest=canonical_payload_digest,
        mark_memory_committed=mark_memory_writeback_committed,
        process_committed_memory=process_committed_memory_writeback,
        resume_committed_memory=resume_committed_memory_writebacks,
        quarantine_result=quarantine_analysis_index,
        discard_pending_memory=discard_pending_memory_writeback,
    )


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
    alert_summary = prompt_alert_summary(prompt_package) if prompt_package else {}
    agent_role = str(prompt_package.get("agent_role") or "soc-analyst")
    enabled_routes = enabled_agent_model_routes(settings)
    model_route = canonical_model_route(
        (settings.get("agent_models") or {}).get(agent_role),
        enabled_routes,
    )
    assigned_model, assigned_model_path, assigned_mode = assigned_model_metadata(
        settings,
        agent_role,
    )
    observed = runtime_observation if isinstance(runtime_observation, dict) else {}
    model_path = str((response or {}).get("_analysis_model_path") or "").strip()
    model = str((response or {}).get("_analysis_model") or "").strip()
    observed_route = model_route if model and model_path else ""
    if not model and status != "running":
        active_phase = str(observed.get("active_phase") or "").strip().lower()
        active_model = str(observed.get("active_model") or "").strip()
        active_model_path = str(observed.get("active_model_path") or "").strip()
        active_model_route = str(observed.get("active_model_route") or "").strip()
        if (
            active_phase in {"primary_analysis", "live_follow_up", "second_opinion"}
            and active_model
        ):
            model = active_model
            model_path = active_model_path
            observed_route = active_model_route
    response_provider = str((response or {}).get("_analysis_provider") or "").strip()
    mode = (
        "codex-cli"
        if model_path == "frontier-codex-cli"
        else "hermes-agent"
        if model_path == "hermes-agent"
        else "openclaw"
        if model_path == "openclaw"
        else "ollama"
        if model_path == "ollama"
        else response_provider
    )
    input_mode = str((response or {}).get("_analysis_input_mode") or "").strip()
    record = {
        "log_id": run_id,
        "status": status,
        "success": status == "success",
        "started_at": started_at,
        "finished_at": finished_at,
        "runtime_seconds": round(runtime_seconds, 3) if runtime_seconds is not None else None,
        "mode": mode,
        "model": model,
        "model_path": model_path,
        "provider": response_provider,
        "harness": str((response or {}).get("_analysis_harness") or "").strip(),
        "agent_role": agent_role,
        "model_route": observed_route,
        "model_started": bool(model and (model_path or observed_route)),
        "input_mode": input_mode,
        "assigned_model": assigned_model,
        "assigned_model_path": assigned_model_path,
        "assigned_mode": assigned_mode,
        "assigned_model_route": model_route,
        "prompt_package": str(prompt_path) if prompt_path else "",
        "analysis_json": str(json_path) if json_path else "",
        "analysis_markdown": str(md_path) if md_path else "",
        "gpu_temperature_celsius_max": resource_monitor.max_gpu_celsius,
        "gpu_utilization_percent_max": resource_monitor.max_gpu_percent,
        "cpu_temperature_celsius_max": resource_monitor.max_cpu_celsius,
        "soc_temperature_celsius_max": resource_monitor.max_soc_celsius,
        "memory_used_percent_max": resource_monitor.max_memory_percent,
        "power_watts_max": resource_monitor.max_power_watts,
        "cpu_used_percent_max": resource_monitor.max_cpu_percent,
        "system_metrics_note": resource_monitor.note,
        "gpu_temperature_note": resource_monitor.note,
        "pcap_total_size_bytes": prompt_pcap_size_bytes(prompt_package) if prompt_package else 0,
        "alert_context_size_bytes": prompt_alert_context_size_bytes(prompt_package) if prompt_package else 0,
        "error": error,
        "alert": alert_summary,
    }
    if status == "running":
        record.update({
            "active_phase": "preparing",
            "active_phase_started_at": started_at,
            "active_model": "",
            "active_model_path": "",
            "active_model_route": "",
            "active_provider": "",
            "second_opinion_trigger": "",
        })
    return record


def latest_prompt(prompt_dir: Path) -> Path:
    files = sorted(prompt_dir.glob("*-ai-prompt.json"))
    if not files:
        raise SystemExit(f"no prompt packages found in {prompt_dir}")
    return files[-1]


def generate_prompt(args: argparse.Namespace) -> Path:
    """Call the existing prompt builder and return the newly written file path."""
    builder = Path(__file__).with_name("build-ai-investigation-prompt.py")
    if not builder.exists():
        raise SystemExit(f"prompt builder not found: {builder}")
    cmd = [
        sys.executable,
        str(builder),
        "--levels",
        args.levels,
        "--hours",
        str(args.hours),
        "--related-limit",
        str(args.related_limit),
        "--correlation-limit",
        str(args.correlation_limit),
        "--correlation-min-score",
        str(args.correlation_min_score),
        "--max-package-bytes",
        str(args.max_prompt_bytes),
        "--out-dir",
        str(args.prompt_dir),
    ]
    try:
        proc = run_bounded_command(
            cmd,
            timeout_seconds=min(max(30, args.timeout), 300),
            max_stdout_bytes=16 * 1024,
            max_stderr_bytes=256 * 1024,
        )
    except BoundedProcessError as exc:
        raise SystemExit(f"prompt builder exceeded its runtime contract: {exc}") from exc
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        raise SystemExit(f"prompt builder failed with rc={proc.returncode}")
    path_text = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    prompt_path = Path(path_text)
    if not prompt_path.exists():
        raise SystemExit(f"prompt builder did not return a valid path: {path_text}")
    return prompt_path


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a runtime file only while it remains inside its admission limit."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RuntimeArtifactError(f"cannot stat {path}: {exc}") from exc
    if size > max_bytes:
        raise RuntimeArtifactError(f"runtime artifact exceeds {max_bytes} byte limit: {path}")
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError as exc:
        raise RuntimeArtifactError(f"cannot read {path}: {exc}") from exc
    if len(data) > max_bytes:
        raise RuntimeArtifactError(f"runtime artifact grew beyond {max_bytes} byte limit: {path}")
    return data


def load_json(path: Path, max_bytes: int = DEFAULT_MAX_JSON_ARTIFACT_BYTES) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes_bounded(path, max_bytes).decode("utf-8", errors="strict"))
    except (RuntimeArtifactError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeArtifactError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeArtifactError(f"JSON root must be an object: {path}")
    return value


def load_system_prompt(path: Path) -> str:
    """Read the editable SOC Analyst prompt, falling back to a safe default."""
    if not path.exists():
        return DEFAULT_SYSTEM_PROMPT
    prompt = read_bytes_bounded(path, DEFAULT_MAX_SYSTEM_PROMPT_BYTES).decode(
        "utf-8", errors="replace"
    ).strip()
    return prompt or DEFAULT_SYSTEM_PROMPT


def default_ai_settings() -> dict[str, Any]:
    """Return safe local-first AI routing defaults."""
    default_model = os.environ.get("SOC_AI_MODEL") or FALLBACK_OLLAMA_MODEL
    return {
        "mode": "ollama",
        "ollama_model": default_model,
        "enabled_ollama_models": [default_model],
        "ollama_url": os.environ.get("OLLAMA_URL") or DEFAULT_OLLAMA_URL,
        "cloud_provider": "codex-cli",
        "cloud_model": "gpt-5.5",
        "cloud_command": "",
        "codex_cli_path": "codex",
        "codex_cli_model": "gpt-5.5",
        "codex_cli_reasoning_effort": "medium",
        "codex_cli_models": [
            {"model": model, "reasoning_effort": "medium", "enabled": False}
            for model in CODEX_CLI_MODEL_CATALOG
        ],
        "gpt_cli_enabled": False,
        "hermes_agent_enabled": False,
        "hermes_agent_path": "hermes",
        "hermes_agent_model": "gpt-5.5",
        "hermes_agent_reasoning_effort": "medium",
        "openclaw_enabled": False,
        "openclaw_path": "openclaw",
        "openclaw_model": "ollama/gemma4:26b-mlx",
        "openclaw_reasoning_effort": "medium",
        "hybrid_policy": "cloud_for_critical_high_or_recommended",
        "agent_models": {
            role: f"ollama:{default_model}" for role in CYBER_SECURITY_AGENT_ROLES
        },
        "agent_second_opinion_models": {
            role: "" for role in CYBER_SECURITY_AGENT_ROLES
        },
        "agent_adjudicator_models": {
            role: "" for role in CYBER_SECURITY_AGENT_ROLES
        },
    }


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


def _reporting_incident():
    _provider_routing()
    from onion_sentinel.analysis.reporting import incident
    return incident


def _reporting_markdown():
    _provider_routing()
    from onion_sentinel.analysis.reporting import markdown
    return markdown


def _reporting_publication():
    _provider_routing()
    from onion_sentinel.analysis.reporting import publication
    return publication


def _analysis_index_persistence():
    _provider_routing()
    from onion_sentinel.analysis.persistence import analysis_index
    return analysis_index


def _memory_journal_persistence():
    _provider_routing()
    from onion_sentinel.analysis.persistence import memory_journal
    return memory_journal


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


def _evidence_reference_policy():
    return _evidence_references().Policy(
        maximum_text_length=EVIDENCE_REFERENCE_TEXT_MAX,
    )


def _evidence_validation():
    _provider_routing()
    from onion_sentinel.analysis.evidence import validation
    return validation


def _evidence_registry():
    _provider_routing()
    from onion_sentinel.analysis.evidence import registry
    return registry


def _evidence_registry_instance():
    module = _evidence_registry()
    return module.Registry(
        maximum_references=EVIDENCE_REFERENCE_MAX,
        deps=module.Dependencies(
            bounded_reference=_bounded_reference,
            source_class=evidence_source_class,
            canonical_count=_canonical_investigation_count,
        ),
    )


def _evidence_columnar():
    _provider_routing()
    from onion_sentinel.analysis.evidence import columnar
    return columnar


def _evidence_columnar_policy():
    module = _evidence_columnar()
    return module.Policy(
        result_schema=INVESTIGATION_QUERY_RESULT_SCHEMA,
        provenance_schema=INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA,
        columns=tuple(INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS),
        empty_ref_instruction=INVESTIGATION_COLUMNAR_EMPTY_REF_INSTRUCTION,
        success_statuses=frozenset(INVESTIGATION_QUERY_SUCCESS_STATUSES),
        maximum_queries=MAX_INVESTIGATION_QUERIES_TOTAL,
        maximum_rounds=MAX_INVESTIGATION_QUERY_ROUNDS,
    )


def _evidence_columnar_dependencies():
    module = _evidence_columnar()
    return module.Dependencies(
        prompt_json_bytes=_investigation_prompt_json_bytes,
        canonical_count=_canonical_investigation_count,
        result_bound_reference=result_bound_query_reference,
    )


def _evidence_hosted_projection():
    _provider_routing()
    from onion_sentinel.analysis.evidence import hosted_projection
    return hosted_projection


def _evidence_hosted_projection_policy():
    module = _evidence_hosted_projection()
    return module.Policy(
        provenance_schema=INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA,
        columns=tuple(INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS),
        maximum_queries=MAX_INVESTIGATION_QUERIES_TOTAL,
        list_path_sentinel=_MODEL_LIST_PATH_SENTINEL,
    )


def _evidence_hosted_projection_dependencies():
    module = _evidence_hosted_projection()
    return module.Dependencies(
        exact_columnar_envelope=_exact_hosted_columnar_envelope,
        prompt_json_bytes=_investigation_prompt_json_bytes,
    )


def _evidence_traversal():
    _provider_routing()
    from onion_sentinel.analysis.evidence import traversal
    return traversal


def _evidence_traversal_policy():
    module = _evidence_traversal()
    return module.Policy(
        success_statuses=frozenset(INVESTIGATION_QUERY_SUCCESS_STATUSES),
        columnar_schema=INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA,
    )


def _evidence_traversal_dependencies():
    module = _evidence_traversal()
    return module.Dependencies(
        bounded_reference=_bounded_reference,
        result_bound_reference=result_bound_query_reference,
    )


def _evidence_contract():
    _provider_routing()
    from onion_sentinel.analysis.evidence import contract
    return contract


def _evidence_contract_dependencies():
    module = _evidence_contract()
    return module.Dependencies(
        registry_factory=_evidence_registry_instance,
        traverse=lambda value, path, sink: _evidence_traversal().visit(
            value, path, sink, _evidence_traversal_policy(),
            _evidence_traversal_dependencies(),
        ),
        process_columnar=lambda value, sink: _evidence_columnar().process(
            value, sink, _evidence_columnar_policy(),
            _evidence_columnar_dependencies(),
        ),
        has_structured_authorization=_has_structured_authorization_evidence,
    )


def _query_primitives():
    _provider_routing()
    from onion_sentinel.analysis.query import primitives
    return primitives


def _query_request():
    _provider_routing()
    from onion_sentinel.analysis.query import request
    return request


def _query_state():
    _provider_routing()
    from onion_sentinel.analysis.query import state
    return state


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


def _query_derived():
    _provider_routing()
    from onion_sentinel.analysis.query import derived
    return derived


def _query_endpoint():
    _provider_routing()
    from onion_sentinel.analysis.query import endpoint
    return endpoint
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


def controlled_evaluation_runtime(
    runtime: argparse.Namespace | str,
) -> tuple[bool, Path | None]:
    """Resolve an owner-only spool root for one controlled evaluation."""
    global _CONTROLLED_EVALUATION_TMPDIR
    _CONTROLLED_EVALUATION_TMPDIR = None
    runtime_args = None if isinstance(runtime, str) else runtime
    alert_store_url = (
        runtime
        if isinstance(runtime, str)
        else str(runtime.alert_store_url or "")
    )
    mode_value = str(
        os.environ.get(CONTROLLED_EVALUATION_MODE_ENV) or ""
    ).strip()
    if mode_value not in {"", "0", "1"}:
        raise SystemExit(
            f"{CONTROLLED_EVALUATION_MODE_ENV} must be unset, 0, or 1"
        )
    if mode_value != "1":
        return False, None
    if (
        runtime_args is not None
        and str(getattr(runtime_args, "model", "") or "").strip()
    ):
        raise SystemExit(
            "controlled evaluation forbids --model and SOC_AI_MODEL overrides"
        )
    if runtime_args is not None and bool(
        getattr(runtime_args, "generate_prompt", False)
    ):
        raise SystemExit(
            "controlled evaluation forbids --generate-prompt; use the frozen prompt"
        )
    evaluation_token = str(
        os.environ.get(CONTROLLED_EVALUATION_TOKEN_ENV) or ""
    ).strip()
    if not CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(evaluation_token):
        raise SystemExit(
            "controlled evaluation requires an exact ephemeral "
            "authorization token"
        )
    try:
        alert_store_origin = urlparse(str(alert_store_url or ""))
        alert_store_port = alert_store_origin.port
    except ValueError as exc:
        raise SystemExit(
            "controlled evaluation alert-store origin is unsafe"
        ) from exc
    if (
        alert_store_origin.scheme != "http"
        or alert_store_origin.hostname != "127.0.0.1"
        or alert_store_port is None
        or alert_store_port < 1
        or alert_store_port == 8787
        or alert_store_origin.username is not None
        or alert_store_origin.password is not None
        or alert_store_origin.path not in {"", "/"}
        or alert_store_origin.params
        or alert_store_origin.query
        or alert_store_origin.fragment
    ):
        raise SystemExit(
            "controlled evaluation requires one alternate loopback "
            "alert-store origin"
        )
    raw_root = str(
        os.environ.get(CONTROLLED_EVALUATION_RUNTIME_DIR_ENV) or ""
    ).strip()
    if not raw_root:
        raise SystemExit(
            "controlled evaluation runtime directory is required"
        )
    root = Path(raw_root).expanduser()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
        expected_parent = (
            HOME / "n8n-local" / "harness-evaluations"
        ).resolve(strict=True)
        resolved.relative_to(expected_parent)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise SystemExit(
            f"controlled evaluation runtime directory is unsafe: {exc}"
        ) from exc
    if (
        not root.is_absolute()
        or resolved != root
        or root.is_symlink()
        or not root.is_dir()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SystemExit(
            "controlled evaluation runtime directory must be owner-only"
        )
    try:
        controlled_tmpdir = pin_controlled_tmpdir(resolved)
    except ControlledEvaluationIsolationError as exc:
        raise SystemExit(f"controlled evaluation {exc}") from exc
    if runtime_args is not None:
        def owner_private_path(
            candidate: Path,
            *,
            label: str,
            kind: str,
            inside_runtime: bool = True,
        ) -> Path:
            candidate = candidate.expanduser()
            try:
                candidate_metadata = candidate.lstat()
                resolved_candidate = candidate.resolve(strict=True)
                if inside_runtime:
                    resolved_candidate.relative_to(resolved)
            except (FileNotFoundError, OSError, ValueError) as exc:
                location = " inside the evaluation runtime" if inside_runtime else ""
                raise SystemExit(
                    f"controlled evaluation {label} must be a canonical "
                    f"owner-private {kind}{location}"
                ) from exc
            expected_kind = (
                candidate.is_file() if kind == "file" else candidate.is_dir()
            )
            if (
                not candidate.is_absolute()
                or resolved_candidate != candidate
                or candidate.is_symlink()
                or not expected_kind
                or candidate_metadata.st_uid != os.getuid()
                or stat.S_IMODE(candidate_metadata.st_mode) & 0o077
            ):
                location = " inside the evaluation runtime" if inside_runtime else ""
                raise SystemExit(
                    f"controlled evaluation {label} must be a canonical "
                    f"owner-private {kind}{location}"
                )
            return resolved_candidate

        for label, candidate in {
            "prompt directory": runtime_args.prompt_dir,
            "analysis output directory": runtime_args.out_dir,
            "investigation-pivot directory": runtime_args.investigation_pivot_dir,
        }.items():
            owner_private_path(candidate, label=label, kind="directory")
        runtime_files = {
            "prompt package": runtime_args.prompt_package,
            "AI settings": runtime_args.ai_settings_file,
            "harness policy": runtime_args.investigation_harness_policy,
            "primary system prompt": runtime_args.system_prompt_file,
            "reviewer system prompt": runtime_args.second_opinion_prompt_file,
            "disagreement prompt": runtime_args.disagreement_adjudicator_prompt_file,
            "live OSQuery config": runtime_args.live_osquery_config,
        }
        if runtime_args.response_json is not None:
            runtime_files["saved response"] = runtime_args.response_json
        for label, candidate in runtime_files.items():
            if candidate is None:
                raise SystemExit(
                    f"controlled evaluation requires an explicit {label}"
                )
            owner_private_path(candidate, label=label, kind="file")

        try:
            validate_controlled_incident_evidence_route(
                runtime_args.incident_evidence_config,
                resolved,
                expected_home=HOME,
            )
        except ControlledEvaluationIsolationError as exc:
            raise SystemExit(
                f"controlled evaluation {exc}"
            ) from exc

        try:
            live_osquery_document = json.loads(
                runtime_args.live_osquery_config.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SystemExit(
                "controlled evaluation live OSQuery config is invalid"
            ) from exc
        if (
            not isinstance(live_osquery_document, dict)
            or live_osquery_document.get("enabled") is not False
        ):
            raise SystemExit(
                "controlled evaluation requires live OSQuery to be explicitly disabled"
            )
    _CONTROLLED_EVALUATION_TMPDIR = controlled_tmpdir
    return True, resolved


def controlled_evaluation_output_dir(
    out_dir: Path,
    runtime_root: Path,
) -> Path:
    """Keep direct controlled output inside its owner-only evaluation root."""
    candidate = out_dir.expanduser()
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(runtime_root)
    except (OSError, ValueError) as exc:
        raise SystemExit(
            "controlled evaluation out_dir must stay inside its runtime "
            "directory"
        ) from exc
    if not candidate.is_absolute() or resolved != candidate:
        raise SystemExit(
            "controlled evaluation out_dir must stay inside its runtime "
            "directory"
        )
    return resolved


def consume_controlled_evaluation_token(enabled: bool) -> str:
    """Remove the mutation credential before invoking any model subprocess."""
    global _CONTROLLED_EVALUATION_TOKEN
    supplied = str(
        os.environ.pop(CONTROLLED_EVALUATION_TOKEN_ENV, "") or ""
    ).strip()
    if enabled:
        if not CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(supplied):
            raise SystemExit(
                "controlled evaluation requires an exact ephemeral "
                "authorization token"
            )
        _CONTROLLED_EVALUATION_TOKEN = supplied
    else:
        _CONTROLLED_EVALUATION_TOKEN = ""
    return _CONTROLLED_EVALUATION_TOKEN


def controlled_evaluation_result_identity(
    enabled: bool,
    *,
    reanalysis_attempt_id: str,
) -> dict[str, Any] | None:
    """Bind an evaluation result to the exact server-owned durable lease."""
    supplied = {
        field: str(os.environ.get(environment_key) or "")
        for field, environment_key in CONTROLLED_RESULT_ENVIRONMENT.items()
    }
    for environment_key in CONTROLLED_RESULT_ENVIRONMENT.values():
        os.environ.pop(environment_key, None)
    if not enabled:
        if any(supplied.values()):
            raise SystemExit(
                "controlled result identity requires controlled evaluation mode"
            )
        return None
    if any(
        not value
        for field, value in supplied.items()
        if field != "reanalysis_attempt_id"
    ):
        raise SystemExit("controlled evaluation result identity is incomplete")
    try:
        job_id = int(supplied["job_id"])
    except ValueError as exc:
        raise SystemExit(
            "controlled evaluation job identity is invalid"
        ) from exc
    job_type = supplied["job_type"]
    expected_role = {
        "ai_analysis": "soc-analyst",
        "incident_response_analysis": "incident-responder",
    }.get(job_type)
    attempt_id = supplied["reanalysis_attempt_id"]
    assigned_route = supplied["expected_assigned_route"]
    reviewer_route = supplied["expected_reviewer_route"]
    stable_group_key = supplied["stable_group_key"]
    try:
        stable_group_key_bytes = stable_group_key.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SystemExit(
            "controlled evaluation stable group key is invalid"
        ) from exc
    if (
        job_id < 1
        or expected_role is None
        or supplied["agent_role"] != expected_role
        or not re.fullmatch(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-"
            r"[89ab][a-f0-9]{3}-[a-f0-9]{12}",
            supplied["lease_token"],
        )
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}",
            supplied["cohort_id"],
        )
        or not re.fullmatch(r"[a-f0-9]{64}", supplied["dispatch_id"])
        or not re.fullmatch(
            r"[A-Za-z0-9._:@=-]{1,256}",
            supplied["representative_alert_id"],
        )
        or not re.fullmatch(r"[a-f0-9]{20}", supplied["stable_group_id"])
        or not stable_group_key
        or "\x00" in stable_group_key
        or len(stable_group_key_bytes) > 2048
        or (
            job_type == "ai_analysis"
            and attempt_id
        )
        or (
            job_type == "incident_response_analysis"
            and not re.fullmatch(r"ira-[a-f0-9]{40}", attempt_id)
        )
        or attempt_id != str(reanalysis_attempt_id or "")
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(assigned_route)
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(reviewer_route)
        or assigned_route.rsplit(":", 1)[0]
        == reviewer_route.rsplit(":", 1)[0]
        or supplied["reviewer_required"] != "1"
    ):
        raise SystemExit(
            "controlled evaluation result identity is invalid"
        )
    runtime_release_id = str(
        os.environ.get("ONION_SENTINEL_RELEASE_ID") or ""
    ).strip()
    if (
        not re.fullmatch(r"[a-f0-9]{40}", runtime_release_id)
        or supplied["release_id"] != runtime_release_id
    ):
        raise SystemExit(
            "controlled evaluation release identity is invalid"
        )
    return {
        **supplied,
        "job_id": job_id,
        "release_id": runtime_release_id,
        "reviewer_required": True,
    }


def controlled_evaluation_claim_digest(identity: dict[str, Any]) -> str:
    """Hash lease lineage without persisting the bearer token itself."""
    return hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def require_controlled_evaluation_routes(
    identity: dict[str, Any] | None,
    args: argparse.Namespace,
    settings: dict[str, Any],
    agent_role: str,
) -> None:
    """Recheck frozen route assignments before any Relay or model call."""

    if identity is None:
        return
    assigned_route = identity.get("expected_assigned_route")
    reviewer_route = identity.get("expected_reviewer_route")
    if (
        identity.get("reviewer_required") is not True
        or identity.get("agent_role") != agent_role
        or not isinstance(assigned_route, str)
        or not isinstance(reviewer_route, str)
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(assigned_route)
        or not CONTROLLED_MODEL_ROUTE_RE.fullmatch(reviewer_route)
        or assigned_route.rsplit(":", 1)[0]
        == reviewer_route.rsplit(":", 1)[0]
    ):
        raise SystemExit(
            "controlled evaluation route identity is invalid"
        )
    settings_path = Path(
        getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS_FILE)
    )
    try:
        if (
            not settings_path.is_file()
            or settings_path.stat().st_size > DEFAULT_MAX_SETTINGS_BYTES
        ):
            raise ValueError("settings file is missing or oversized")
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise SystemExit(
            "controlled evaluation route settings are unavailable"
        ) from exc
    raw_assigned = raw.get("agent_models") if isinstance(raw, dict) else None
    raw_reviewers = (
        raw.get("agent_second_opinion_models")
        if isinstance(raw, dict)
        else None
    )
    enabled_routes = enabled_agent_model_routes(settings)
    if (
        not isinstance(raw_assigned, dict)
        or raw_assigned.get(agent_role) != assigned_route
        or not isinstance(raw_reviewers, dict)
        or raw_reviewers.get(agent_role) != reviewer_route
        or (settings.get("agent_models") or {}).get(agent_role)
        != assigned_route
        or (settings.get("agent_second_opinion_models") or {}).get(agent_role)
        != reviewer_route
        or assigned_route not in enabled_routes
        or reviewer_route not in enabled_routes
    ):
        raise SystemExit(
            "controlled evaluation routes do not exactly match enabled settings"
        )


def require_controlled_evaluation_result_routes(
    identity: dict[str, Any] | None,
    response: dict[str, Any],
) -> None:
    """Reject a controlled result unless both frozen routes actually ran."""

    if identity is None:
        return
    assigned_route = identity["expected_assigned_route"]
    reviewer_route = identity["expected_reviewer_route"]
    second_opinion = response.get("_second_opinion")
    reviewer_response = (
        second_opinion.get("response")
        if isinstance(second_opinion, dict)
        else None
    )
    if (
        response.get("_analysis_model_route") != assigned_route
        or not isinstance(second_opinion, dict)
        or second_opinion.get("status") != "completed"
        or second_opinion.get("model_route") != reviewer_route
        or not isinstance(reviewer_response, dict)
        or reviewer_response.get("_analysis_model_route") != reviewer_route
    ):
        raise ControlledEvaluationReviewerGateError(
            "controlled evaluation result does not attest both frozen routes"
        )


def apply_evaluation_memory_freeze(
    allowed: bool,
    reason: str,
    *,
    freeze_enabled: bool,
) -> tuple[bool, str]:
    """Disable only memory persistence during a controlled evaluation run."""
    if freeze_enabled:
        return (
            False,
            "controlled harness evaluation froze memory writeback",
        )
    return allowed, reason


def codex_cli_route(model: str, effort: str) -> str:
    return _provider_routing().codex_cli_route(model, effort)


def cli_harness_route(provider: str, model: str, effort: str) -> str:
    return _provider_routing().cli_harness_route(provider, model, effort)


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


def normalized_codex_cli_models(
    value: Any,
    *,
    legacy_model: str,
    legacy_effort: str,
    legacy_enabled: bool,
) -> list[dict[str, Any]]:
    """Return validated settings for the fixed Codex CLI model catalog."""
    raw_entries = value if isinstance(value, list) else [
        {
            "model": legacy_model,
            "reasoning_effort": legacy_effort,
            "enabled": legacy_enabled,
        }
    ]
    if len(raw_entries) > len(CODEX_CLI_MODEL_CATALOG):
        raise RuntimeArtifactError("Codex CLI model roster contains too many entries")
    configured: dict[str, dict[str, Any]] = {}
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise RuntimeArtifactError("Codex CLI model roster entries must be objects")
        model = str(raw.get("model") or "").strip()
        effort = str(raw.get("reasoning_effort") or "medium").strip().lower()
        if model not in CODEX_CLI_MODEL_CATALOG:
            raise RuntimeArtifactError("Codex CLI model is not in the supported catalog")
        if effort not in CODEX_CLI_REASONING_EFFORTS:
            raise RuntimeArtifactError(
                "Codex CLI reasoning effort must be low, medium, high, or xhigh"
            )
        if model in configured:
            raise RuntimeArtifactError("Codex CLI model roster contains a duplicate model")
        configured[model] = {
            "model": model,
            "reasoning_effort": effort,
            "enabled": boolean_setting(raw.get("enabled")),
        }
    return [
        configured.get(model, {
            "model": model,
            "reasoning_effort": "medium",
            "enabled": False,
        })
        for model in CODEX_CLI_MODEL_CATALOG
    ]


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
    updated = dict(current_record)
    updated["active_phase"] = phase
    updated["active_phase_started_at"] = project_now()
    updated["second_opinion_trigger"] = trigger_reason
    if model_route:
        canonical, model, model_path, provider = model_route_metadata(settings, model_route)
        updated.update({
            "active_model": model,
            "active_model_path": model_path,
            "active_model_route": canonical,
            "active_provider": provider,
        })
    else:
        updated.update({
            "active_model": "",
            "active_model_path": "",
            "active_model_route": "",
            "active_provider": "",
        })
    return updated


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
    updated = current_analysis_phase_record(
        current_record,
        settings,
        phase=phase,
        model_route=model_route,
        trigger_reason=trigger_reason,
    )
    target = active_record_path or active_analysis_record_path(updated.get("log_id"))
    atomic_write_json(target, updated)
    return updated


def notify_analysis_phase(
    callback: Callable[[str, str, str], None] | None,
    phase: str,
    model_route: str = "",
    trigger_reason: str = "",
) -> None:
    """Publish optional live status without allowing telemetry to fail analysis."""
    if callback is None:
        return
    try:
        callback(phase, model_route, trigger_reason)
    except Exception:
        return


def normalize_agent_models(value: Any, routes: list[str]) -> dict[str, str]:
    """Give every agent one valid assignment, falling back deterministically.

    A disabled or removed route must never survive into execution. The first
    enabled route is intentionally used as a predictable fail-safe so roster
    maintenance cannot leave an agent without an analysis backend.
    """
    source = value if isinstance(value, dict) else {}
    fallback = routes[0] if routes else ""
    return {
        role: route if (route := canonical_model_route(source.get(role), routes)) in routes else fallback
        for role in CYBER_SECURITY_AGENT_ROLES
    }


def normalize_agent_second_opinion_models(
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
) -> dict[str, str]:
    """Keep optional secondary routes enabled, distinct, and fail-closed."""
    source = value if isinstance(value, dict) else {}
    return {
        role: route
        if (
            (route := canonical_model_route(source.get(role), routes)) in routes
            and route != primary_assignments.get(role)
        )
        else ""
        for role in CYBER_SECURITY_AGENT_ROLES
    }


def normalize_agent_adjudicator_models(
    value: Any,
    routes: list[str],
    primary_assignments: dict[str, str],
    reviewer_assignments: dict[str, str],
    settings: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Keep adjudicators optional, enabled, and independent of both positions."""
    source = value if isinstance(value, dict) else {}
    assignments: dict[str, str] = {}
    for role in CYBER_SECURITY_AGENT_ROLES:
        route = canonical_model_route(source.get(role), routes)
        route_identity = model_route_identity(route, settings)
        excluded = {
            model_route_identity(primary_assignments.get(role), settings),
            model_route_identity(reviewer_assignments.get(role), settings),
        }
        assignments[role] = (
            route
            if route in routes and route_identity and route_identity not in excluded
            else ""
        )
    return assignments


def apply_model_roster(settings: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """Migrate legacy single-model settings and derive the compatibility mode."""
    legacy_mode = str(raw.get("mode") or settings.get("mode") or "ollama").strip().lower()
    if legacy_mode not in {"ollama", "cloud", "hybrid"}:
        legacy_mode = "ollama"
    if "enabled_ollama_models" in raw:
        enabled_models = normalized_model_roster(raw.get("enabled_ollama_models"))
    else:
        legacy_model = str(raw.get("ollama_model") or settings.get("ollama_model") or FALLBACK_OLLAMA_MODEL).strip()
        enabled_models = [] if legacy_mode == "cloud" else normalized_model_roster([legacy_model])
    codex_enabled = any(
        isinstance(entry, dict) and entry.get("enabled") is True
        for entry in settings.get("codex_cli_models", [])
    )
    hermes_enabled = boolean_setting(settings.get("hermes_agent_enabled"))
    openclaw_enabled = boolean_setting(settings.get("openclaw_enabled"))
    if not enabled_models and not codex_enabled and not hermes_enabled and not openclaw_enabled:
        raise RuntimeArtifactError("AI settings must enable at least one analysis model route")
    openclaw_ollama = (
        openclaw_enabled
        and openclaw_model_uses_ollama_runtime(
            str(settings.get("openclaw_model") or "")
        )
    )
    local_enabled = bool(enabled_models) or openclaw_ollama
    hosted_enabled = (
        codex_enabled
        or hermes_enabled
        or (openclaw_enabled and not openclaw_ollama)
    )
    settings["enabled_ollama_models"] = enabled_models
    settings["gpt_cli_enabled"] = codex_enabled
    settings["mode"] = (
        "hybrid"
        if local_enabled and hosted_enabled
        else ("cloud" if hosted_enabled else "ollama")
    )
    if enabled_models:
        settings["ollama_model"] = enabled_models[0]
    settings["agent_models"] = normalize_agent_models(
        raw.get("agent_models"),
        enabled_agent_model_routes(settings),
    )
    settings["agent_second_opinion_models"] = normalize_agent_second_opinion_models(
        raw.get("agent_second_opinion_models"),
        enabled_agent_model_routes(settings),
        settings["agent_models"],
    )
    settings["agent_adjudicator_models"] = normalize_agent_adjudicator_models(
        raw.get("agent_adjudicator_models"),
        enabled_agent_model_routes(settings),
        settings["agent_models"],
        settings["agent_second_opinion_models"],
        settings,
    )
    return settings


def normalize_codex_cli_settings(settings: dict[str, Any], raw: dict[str, Any]) -> None:
    """Normalize the fixed Codex adapter without accepting shell fragments."""
    executable = str(raw.get("codex_cli_path") or settings.get("codex_cli_path") or "codex").strip()
    model = str(
        raw.get("codex_cli_model")
        or raw.get("cloud_model")
        or settings.get("codex_cli_model")
        or "gpt-5.5"
    ).strip()
    effort = str(
        raw.get("codex_cli_reasoning_effort")
        or settings.get("codex_cli_reasoning_effort")
        or "medium"
    ).strip().lower()
    for label, value, limit in (
        ("Codex CLI path", executable, 1024),
        ("Codex CLI model", model, 240),
    ):
        if not value or len(value) > limit or re.search(r"[\x00-\x1f\x7f]", value):
            raise RuntimeArtifactError(f"{label} is invalid")
    if Path(executable).is_absolute():
        if (
            Path(executable).name != "codex"
            or not re.fullmatch(r"/[A-Za-z0-9._/+-]+", executable)
        ):
            raise RuntimeArtifactError("Codex CLI path must resolve from an executable named codex")
    elif executable != "codex":
        raise RuntimeArtifactError("Codex CLI path must be 'codex' or an absolute path ending in /codex")
    if effort not in CODEX_CLI_REASONING_EFFORTS:
        raise RuntimeArtifactError(
            "Codex CLI reasoning effort must be low, medium, high, or xhigh"
        )
    legacy_mode = str(raw.get("mode") or settings.get("mode") or "ollama").strip().lower()
    legacy_enabled = (
        boolean_setting(raw.get("gpt_cli_enabled"))
        if "gpt_cli_enabled" in raw
        else legacy_mode in {"cloud", "hybrid"}
    )
    codex_models = normalized_codex_cli_models(
        raw.get("codex_cli_models") if "codex_cli_models" in raw else None,
        legacy_model=model,
        legacy_effort=effort,
        legacy_enabled=legacy_enabled,
    )
    selected = next(
        (entry for entry in codex_models if entry["enabled"]),
        codex_models[0] if codex_models else {
            "model": model,
            "reasoning_effort": effort,
        },
    )
    model = selected["model"]
    effort = selected["reasoning_effort"]
    settings["codex_cli_path"] = executable
    settings["codex_cli_model"] = model
    settings["codex_cli_reasoning_effort"] = effort
    settings["codex_cli_models"] = codex_models
    # Compatibility fields remain readable during rolling deploys, but the
    # legacy arbitrary command is never executed.
    settings["cloud_provider"] = "codex-cli"
    settings["cloud_model"] = model
    settings["cloud_command"] = ""


def _normalize_harness_executable(value: Any, basename: str) -> str:
    """Validate an exact executable path without accepting flags or shell text."""
    executable = str(value or basename).strip()
    label = "Hermes Agent" if basename == "hermes" else "OpenClaw"
    if (
        not executable
        or len(executable) > 1024
        or re.search(r"[\x00-\x1f\x7f]", executable)
    ):
        raise RuntimeArtifactError(f"{label} executable path is invalid")
    if Path(executable).is_absolute():
        if (
            Path(executable).name != basename
            or not re.fullmatch(r"/[A-Za-z0-9._/+-]+", executable)
        ):
            raise RuntimeArtifactError(f"{label} path must end in /{basename}")
    elif executable != basename:
        raise RuntimeArtifactError(
            f"{label} path must be '{basename}' or an absolute path ending in /{basename}"
        )
    return executable


def normalize_cli_harness_settings(
    settings: dict[str, Any],
    raw: dict[str, Any],
) -> None:
    """Normalize the two optional, independently enabled agent harnesses."""
    hermes_model = str(
        raw.get("hermes_agent_model")
        or settings.get("hermes_agent_model")
        or "gpt-5.5"
    ).strip()
    hermes_effort = str(
        raw.get("hermes_agent_reasoning_effort")
        or settings.get("hermes_agent_reasoning_effort")
        or "medium"
    ).strip().lower()
    openclaw_model = str(
        raw.get("openclaw_model")
        or settings.get("openclaw_model")
        or "ollama/gemma4:26b-mlx"
    ).strip()
    openclaw_effort = str(
        raw.get("openclaw_reasoning_effort")
        or settings.get("openclaw_reasoning_effort")
        or "medium"
    ).strip().lower()
    if hermes_model not in CODEX_CLI_MODEL_CATALOG:
        raise RuntimeArtifactError(
            "Hermes Agent model is not in the supported Codex model catalog"
        )
    if (
        not CLI_HARNESS_MODEL_PATTERN.fullmatch(openclaw_model)
        or not openclaw_model_uses_ollama_runtime(openclaw_model)
        or len(openclaw_model) <= len(OPENCLAW_OLLAMA_PROVIDER_PREFIX)
    ):
        raise RuntimeArtifactError(
            "OpenClaw currently supports explicit ollama/<model> routes only; "
            "hosted OpenClaw credentials are not admitted into the isolated runtime"
        )
    if hermes_effort != HERMES_AGENT_REASONING_EFFORT:
        raise RuntimeArtifactError(
            "Hermes Agent one-shot runtime supports medium reasoning effort only"
        )
    if openclaw_effort not in CODEX_CLI_REASONING_EFFORTS:
        raise RuntimeArtifactError(
            "OpenClaw reasoning effort must be low, medium, high, or xhigh"
        )
    settings.update({
        "hermes_agent_enabled": boolean_setting(raw.get("hermes_agent_enabled")),
        "hermes_agent_path": _normalize_harness_executable(
            raw.get("hermes_agent_path") or settings.get("hermes_agent_path"),
            "hermes",
        ),
        "hermes_agent_model": hermes_model,
        "hermes_agent_reasoning_effort": hermes_effort,
        "openclaw_enabled": boolean_setting(raw.get("openclaw_enabled")),
        "openclaw_path": _normalize_harness_executable(
            raw.get("openclaw_path") or settings.get("openclaw_path"),
            "openclaw",
        ),
        "openclaw_model": openclaw_model,
        "openclaw_reasoning_effort": openclaw_effort,
    })


def load_ai_settings(path: Path) -> dict[str, Any]:
    """Load model routing settings written by the SOC Settings page."""
    settings = default_ai_settings()
    if not path.exists():
        return settings
    try:
        data = json.loads(read_bytes_bounded(path, DEFAULT_MAX_SETTINGS_BYTES).decode("utf-8", errors="strict"))
    except (RuntimeArtifactError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeArtifactError(f"invalid AI settings in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeArtifactError(f"AI settings root must be an object: {path}")
    for key, value in data.items():
        if key in {
            "enabled_ollama_models",
            "codex_cli_models",
            "gpt_cli_enabled",
            "hermes_agent_enabled",
            "openclaw_enabled",
            "agent_models",
            "agent_second_opinion_models",
            "agent_adjudicator_models",
        }:
            continue
        if key in settings and value is not None:
            settings[key] = str(value).strip() if isinstance(value, str) else value
    normalize_codex_cli_settings(settings, data)
    normalize_cli_harness_settings(settings, data)
    apply_model_roster(settings, data)
    if settings.get("hybrid_policy") not in {"cloud_for_critical_high_or_recommended", "cloud_when_recommended_only"}:
        settings["hybrid_policy"] = "cloud_for_critical_high_or_recommended"
    settings["ollama_model"] = str(settings.get("ollama_model") or FALLBACK_OLLAMA_MODEL).strip()
    settings["ollama_url"] = str(settings.get("ollama_url") or DEFAULT_OLLAMA_URL).strip()
    return settings


def resolve_codex_cli(settings: dict[str, Any]) -> str:
    """Resolve only the operator-approved Codex executable."""
    configured = str(settings.get("codex_cli_path") or "codex").strip()
    if Path(configured).is_absolute():
        candidates = [Path(configured).expanduser()]
    else:
        discovered = shutil.which("codex")
        candidates = []
        if discovered:
            candidates.append(Path(discovered))
        candidates.extend([
            Path.home() / ".local" / "bin" / "codex",
            Path("/opt/homebrew/bin/codex"),
            Path("/usr/local/bin/codex"),
        ])
    for candidate in candidates:
        if candidate.name == "codex" and candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    checked = ", ".join(str(candidate) for candidate in candidates)
    raise SystemExit(f"Codex CLI executable is unavailable; checked: {checked}")


def resolve_cli_harness(
    settings: dict[str, Any],
    *,
    setting_key: str,
    basename: str,
    label: str,
) -> str:
    """Resolve only the operator-approved exact third-party executable."""
    configured = _normalize_harness_executable(
        settings.get(setting_key) or basename,
        basename,
    )
    if Path(configured).is_absolute():
        candidates = [Path(configured).expanduser()]
    else:
        candidates: list[Path] = []
        if discovered := shutil.which(basename):
            candidates.append(Path(discovered))
        candidates.extend([
            Path.home() / ".local" / "bin" / basename,
            Path("/opt/homebrew/bin") / basename,
            Path("/usr/local/bin") / basename,
        ])
    for candidate in candidates:
        if (
            candidate.name == basename
            and candidate.is_file()
            and os.access(candidate, os.X_OK)
        ):
            return str(candidate)
    checked = ", ".join(str(candidate) for candidate in candidates)
    raise SystemExit(f"{label} executable is unavailable; checked: {checked}")


def effective_ai_settings(args: argparse.Namespace) -> dict[str, Any]:
    """Merge settings file, environment defaults, and explicit CLI overrides."""
    settings = load_ai_settings(args.ai_settings_file)
    if args.analysis_mode:
        settings["mode"] = args.analysis_mode
        settings["gpt_cli_enabled"] = args.analysis_mode in {"cloud", "hybrid"}
        if args.analysis_mode in {"ollama", "hybrid"} and not settings.get("enabled_ollama_models"):
            settings["enabled_ollama_models"] = [settings.get("ollama_model") or FALLBACK_OLLAMA_MODEL]
    if args.model:
        settings["ollama_model"] = args.model
        settings["enabled_ollama_models"] = [args.model]
        settings["agent_models"]["soc-analyst"] = f"ollama:{args.model}"
    if args.ollama_url:
        settings["ollama_url"] = args.ollama_url
    settings["agent_models"] = normalize_agent_models(
        settings.get("agent_models"),
        enabled_agent_model_routes(settings),
    )
    settings["agent_second_opinion_models"] = normalize_agent_second_opinion_models(
        settings.get("agent_second_opinion_models"),
        enabled_agent_model_routes(settings),
        settings["agent_models"],
    )
    settings["agent_adjudicator_models"] = normalize_agent_adjudicator_models(
        settings.get("agent_adjudicator_models"),
        enabled_agent_model_routes(settings),
        settings["agent_models"],
        settings["agent_second_opinion_models"],
        settings,
    )
    return settings


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
    if not isinstance(asset_context, dict):
        return asset_context
    sanitized = dict(asset_context)
    matched_assets = sanitized.get("matched_assets")
    if not isinstance(matched_assets, list):
        return sanitized
    sanitized_assets: list[Any] = []
    for raw_asset in matched_assets:
        if not isinstance(raw_asset, dict):
            sanitized_assets.append(raw_asset)
            continue
        asset = dict(raw_asset)
        if asset.get("share_with_hosted_models") is not True:
            asset.pop("owner_ref", None)
        sanitized_assets.append(asset)
    sanitized["matched_assets"] = sanitized_assets
    return sanitized


def _positive_project_paths(
    value: Any,
    allowed_paths: frozenset[str],
    path: tuple[str, ...] = (),
) -> Any:
    """Project a nested document using exact reviewed leaf paths."""
    return _evidence_hosted_projection().positive_project_paths(
        value,
        allowed_paths,
        maximum_list_items=200,
        path=path,
    )


def _project_hosted_result_rows(key: str, value: list[Any]) -> list[Any]:
    return _evidence_hosted_projection().project_result_rows(
        key,
        value,
        _evidence_hosted_projection_policy(),
    )


def _prune_empty_hosted_projection(value: Any) -> Any:
    """Remove empty shells while preserving explicit zero-result collections."""
    return _evidence_hosted_projection().prune_empty(value)


def _reviewed_hosted_sha256_evidence_path(
    path: tuple[object, ...],
) -> bool:
    """Allow SHA-256 only at positively projected Elastic source paths."""
    return _evidence_hosted_projection().reviewed_sha256_path(
        path,
        _evidence_hosted_projection_policy(),
    )


def _exact_hosted_columnar_envelope(
    value: Any,
    *,
    require_encoded_accounting: bool,
) -> bool:
    """Recognize only the runtime-owned top-level columnar envelope."""
    return _evidence_columnar().exact_hosted_envelope(
        value,
        require_encoded_accounting=require_encoded_accounting,
        policy=_evidence_columnar_policy(),
        deps=_evidence_columnar_dependencies(),
    )


def _refinalize_hosted_columnar_envelope(value: Any) -> Any:
    """Refresh self-accounting after hosted string redaction."""
    return _evidence_hosted_projection().refinalize_columnar(
        value,
        maximum_passes=HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES,
        dependencies=_evidence_hosted_projection_dependencies(),
    )


def _sanitize_hosted_investigation_evidence(
    value: Any,
    path: tuple[str, ...] = (),
    *,
    preserve_columnar_rows: bool = False,
) -> Any:
    """Keep safe facts/query provenance while removing hosted-sensitive values."""
    return _evidence_hosted_projection().sanitize(
        value,
        path=path,
        preserve_columnar_rows=preserve_columnar_rows,
        policy=_evidence_hosted_projection_policy(),
    )


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
    if isinstance(value, dict):
        output = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            item_path = (*_path, key)
            hosted_projected_evidence = hosted and key in {
                "investigation_query_results",
                "live_osquery_evidence",
            }
            preserve_columnar_rows = False
            reviewed_hosted_sha256 = (
                key == "sha256"
                and hosted
                and _reviewed_hosted_sha256_evidence_path(_path)
            )
            if (
                key.startswith("_local_")
                or (
                    key in MODEL_INTERNAL_KEYS
                    and not reviewed_hosted_sha256
                )
            ):
                continue
            if (
                reviewed_hosted_sha256
                and (
                    not isinstance(item, str)
                    or not re.fullmatch(r"[a-fA-F0-9]{64}", item)
                )
            ):
                continue
            if hosted and (key in HOSTED_FORBIDDEN_KEYS or key.startswith("_pcap_query_")):
                continue
            if hosted_projected_evidence:
                preserve_columnar_rows = (
                    item_path == ("investigation_query_results",)
                    and _exact_hosted_columnar_envelope(
                        item,
                        require_encoded_accounting=True,
                    )
                )
                item = _sanitize_hosted_investigation_evidence(
                    item,
                    item_path,
                    preserve_columnar_rows=preserve_columnar_rows,
                )
            output[key] = model_safe_copy(
                item,
                hosted=hosted,
                reviewer_safe=reviewer_safe,
                _path=item_path,
            )
        if (hosted or reviewer_safe) and "asset_context" in output:
            output["asset_context"] = _redact_unshared_asset_owners(
                output["asset_context"]
            )
        if (
            hosted
            and not _path
            and "investigation_query_results" in output
        ):
            output["investigation_query_results"] = (
                _refinalize_hosted_columnar_envelope(
                    output["investigation_query_results"]
                )
            )
            output["evidence_reference_contract"] = (
                evidence_reference_contract(output)
            )
        return output
    if isinstance(value, list):
        return [
            model_safe_copy(
                item,
                hosted=hosted,
                reviewer_safe=reviewer_safe,
                _path=(*_path, _MODEL_LIST_PATH_SENTINEL),
            )
            for item in value
        ]
    return value


def synchronize_hosted_investigation_contract(
    prompt_package: dict[str, Any],
) -> dict[str, Any]:
    """Bind validation to a verified fixed point of hosted redaction.

    Work on an isolated top-level copy and mutate the caller only after a
    bounded convergence check. This keeps prompt admission transactional if a
    future transport rule is accidentally non-idempotent.
    """
    working = copy.deepcopy(prompt_package)
    seen_transport_digests: set[str] = set()
    for _ in range(HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES):
        transported = model_safe_copy(working, hosted=True)
        transported_bytes = _investigation_prompt_json_bytes(transported)
        transported_digest = hashlib.sha256(transported_bytes).hexdigest()
        if transported_digest in seen_transport_digests:
            raise InvestigationQueryError(
                "hosted investigation transport did not reach a fixed point "
                "(projection cycle)"
            )
        seen_transport_digests.add(transported_digest)
        candidate = copy.deepcopy(working)
        if "investigation_query_results" in transported:
            candidate["investigation_query_results"] = transported[
                "investigation_query_results"
            ]
        else:
            candidate.pop("investigation_query_results", None)
        if "evidence_reference_contract" in transported:
            candidate["evidence_reference_contract"] = transported[
                "evidence_reference_contract"
            ]
        else:
            candidate.pop("evidence_reference_contract", None)
        verified = model_safe_copy(candidate, hosted=True)
        if _investigation_prompt_json_bytes(verified) == transported_bytes:
            prompt_package.pop("investigation_query_results", None)
            prompt_package.pop("evidence_reference_contract", None)
            if "investigation_query_results" in candidate:
                prompt_package["investigation_query_results"] = candidate[
                    "investigation_query_results"
                ]
            if "evidence_reference_contract" in candidate:
                prompt_package["evidence_reference_contract"] = candidate[
                    "evidence_reference_contract"
                ]
            return prompt_package
        working = candidate
    raise InvestigationQueryError(
        "hosted investigation transport did not reach a fixed point"
    )


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
        "dns.question.name",
        "event.dataset",
        "event.module",
        "host.name",
        "network.community_id",
        "process.name",
        "rule.id",
        "rule.name",
        "rule.uuid",
        "suricata.flags",
        "source.ip",
        "destination.ip",
        "user.name",
    }
    for pack in INVESTIGATION_QUERY_PACK_DEFINITIONS.values():
        for field in pack.get("fields", []):
            parts = str(field).lower().split(".")
            for length in range(2, len(parts) + 1):
                paths.add(".".join(parts[:length]))
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
    return _evidence_references().bounded(
        value, _evidence_reference_policy()
    )


def evidence_source_class(source: Any) -> str:
    """Group multiple citations from one underlying source into one signal."""
    return _evidence_references().source_class(source)


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
    return _evidence_references().result_bound(
        query_digest, result_digest, namespace=namespace, label=label,
        policy=_evidence_reference_policy(),
    )


def evidence_reference_contract(prompt_package: dict[str, Any]) -> dict[str, Any]:
    return _evidence_contract().build(
        prompt_package, _evidence_contract_dependencies()
    )


def attach_evidence_reference_contract(
    prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return _evidence_contract().attach(
        prompt_package, _evidence_contract_dependencies()
    )


def validate_evidence_references(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    return _evidence_validation().apply(
        response, prompt_package,
        _evidence_validation().Dependencies(
            bounded_reference=_bounded_reference,
        ),
    )


def reviewer_observable_catalog(prompt_package: dict[str, Any]) -> list[dict[str, str]]:
    """Return exact observables that an independent reviewer may mention."""
    found: set[tuple[str, str]] = set()

    def add(kind: str, value: Any) -> None:
        text = _bounded_reference(value)
        if (
            kind in REVIEW_OBSERVABLE_KINDS
            and text
            and len(found) < REVIEW_OBSERVABLE_MAX
        ):
            found.add((kind, text.lower() if kind in {"domain", "host", "user"} else text))

    local = prompt_package.get("_local_investigation_query_context")
    if isinstance(local, dict):
        permitted = local.get("permitted_observables")
        if isinstance(permitted, dict):
            for plural, kind in (
                ("ips", "ip"),
                ("domains", "domain"),
                ("hosts", "host"),
                ("users", "user"),
            ):
                values = permitted.get(plural)
                for value in values if isinstance(values, list) else []:
                    add(kind, value)
        for tuple_item in (
            local.get("permitted_event_tuples")
            if isinstance(local.get("permitted_event_tuples"), list)
            else []
        ):
            event_tuple = (
                tuple_item.get("event_tuple")
                if isinstance(tuple_item, dict)
                else None
            )
            if not isinstance(event_tuple, dict):
                continue
            for key, kind in (
                ("source_ip", "ip"),
                ("destination_ip", "ip"),
                ("community_id", "community_id"),
            ):
                add(kind, event_tuple.get(key))

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, str(child_key).lower().replace("-", "_"))
        elif isinstance(value, list):
            for child in value[:1000]:
                visit(child, key)
        elif isinstance(value, (str, int)):
            text = str(value).strip()
            if key in {
                "source_ip", "destination_ip", "src_ip", "dest_ip",
                "client_ip", "server_ip", "ip", "address",
            }:
                for match in REVIEW_IPV4_RE.findall(text):
                    add("ip", match)
            elif key in {"domain", "domain_name", "dns_query", "sni", "server_name"}:
                add("domain", text)
            elif key in {"host", "hostname", "host_name", "observer_name"}:
                add("host", text)
            elif key in {"user", "username", "user_name"}:
                add("user", text)
            elif key == "community_id":
                add("community_id", text)

    for section in (
        "alert",
        "grouped_alert_context",
        "correlated_alert_context",
        "public_enrichment",
        "pcap_evidence",
        "detection_validation",
        "asset_context",
        "analyst_state",
        "incident_response_evidence",
        "investigation_query_capability",
        "investigation_query_results",
        "live_osquery_evidence",
    ):
        visit(prompt_package.get(section))
    # IPs may also occur in bounded narrative projections under non-standard
    # field names. They are safe identifiers and provide a robust foreign-fact
    # allowlist without admitting arbitrary prose as an observable.
    serialized = json.dumps(
        model_safe_copy(prompt_package, reviewer_safe=True),
        sort_keys=True,
        default=str,
    )
    for match in REVIEW_IPV4_RE.findall(serialized):
        add("ip", match)
    return [
        {"kind": kind, "value": value}
        for kind, value in sorted(found)
    ]


def reviewer_non_domain_taxonomy_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return exact dotted dataset/module labels that are not DNS names.

    Dataset and module values such as ``suricata.alert`` share the lexical
    shape of an FQDN.  They are safe to exempt from the narrative domain check
    only when a collector-owned, semantically typed field in the current
    evidence package supplies that exact value.  Arbitrary dotted prose and
    values under unrelated keys never enter this catalog.
    """
    found: set[str] = set()

    def field_segment(value: Any) -> str:
        return re.sub(
            r"[^a-z0-9]+",
            "_",
            str(value or "").strip().lower(),
        ).strip("_")

    def add(value: Any) -> None:
        text = _bounded_reference(value).lower()
        if text and REVIEW_DOMAIN_RE.fullmatch(text):
            found.add(text)

    def visit(value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            for raw_key, child in value.items():
                segment = field_segment(raw_key)
                child_path = path + ((segment,) if segment else ())
                semantic_path = "_".join(child_path[-2:])
                if (
                    isinstance(child, (str, int))
                    and (
                        segment in REVIEW_TAXONOMY_FIELD_PATHS
                        or semantic_path in REVIEW_TAXONOMY_FIELD_PATHS
                    )
                ):
                    add(child)
                else:
                    visit(child, child_path)
        elif isinstance(value, list):
            for child in value[:1000]:
                visit(child, path)

    for section in (
        "alert",
        "grouped_alert_context",
        "correlated_alert_context",
        "pcap_evidence",
        "detection_validation",
        "incident_response_evidence",
        "investigation_query_results",
        "live_osquery_evidence",
    ):
        visit(prompt_package.get(section), ())
    return sorted(found)


def reviewer_non_domain_artifact_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return exact script-like names from collector-owned command/path fields."""
    found: set[str] = set()

    def field_segment(value: Any) -> str:
        return re.sub(
            r"[^a-z0-9]+",
            "_",
            str(value or "").strip().lower(),
        ).strip("_")

    def add(value: Any) -> None:
        for candidate in REVIEW_DOMAIN_RE.findall(str(value or "")):
            text = candidate.lower()
            if text.rsplit(".", 1)[-1] in REVIEW_ARTIFACT_SUFFIXES:
                found.add(text)

    def visit(value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            for raw_key, child in value.items():
                segment = field_segment(raw_key)
                child_path = path + ((segment,) if segment else ())
                semantic_path = "_".join(child_path[-2:])
                if (
                    isinstance(child, str)
                    and (
                        segment in REVIEW_ARTIFACT_FIELD_PATHS
                        or semantic_path in REVIEW_ARTIFACT_FIELD_PATHS
                    )
                ):
                    add(child)
                else:
                    visit(child, child_path)
        elif isinstance(value, list):
            for child in value[:1000]:
                visit(child, path)

    for section in (
        "alert",
        "grouped_alert_context",
        "correlated_alert_context",
        "pcap_evidence",
        "detection_validation",
        "incident_response_evidence",
        "investigation_query_results",
        "live_osquery_evidence",
    ):
        visit(prompt_package.get(section))
    return sorted(found)


def reviewer_non_domain_rule_shorthand_catalog(
    prompt_package: dict[str, Any],
) -> list[str]:
    """Return bounded detector-rule shorthands such as ``ET.BPFDoor``.

    Review prose sometimes joins the uppercase detector namespace and a rule
    token with a dot.  That looks like an FQDN lexically, but it is not a
    foreign network observable when both components came from the current,
    semantically typed rule label.  Only an uppercase 2-8 character namespace
    at the start of that label may create these shorthands, and an exact dotted
    value already present in the label is deliberately excluded so real DNS
    names continue through the domain-observable validator.
    """
    found: set[str] = set()

    def field_segment(value: Any) -> str:
        return re.sub(
            r"[^a-z0-9]+",
            "_",
            str(value or "").strip().lower(),
        ).strip("_")

    def add(value: Any) -> None:
        raw = _bounded_reference(value)
        tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9_-]{1,62}", raw)
        if len(tokens) < 2 or not re.fullmatch(r"[A-Z0-9]{2,8}", tokens[0]):
            return
        namespace = tokens[0].lower()
        raw_lower = raw.lower()
        for token in tokens[1:32]:
            candidate = f"{namespace}.{token.lower()}"
            if (
                candidate not in raw_lower
                and REVIEW_DOMAIN_RE.fullmatch(candidate)
            ):
                found.add(candidate)

    def visit(value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            for raw_key, child in value.items():
                segment = field_segment(raw_key)
                child_path = path + ((segment,) if segment else ())
                semantic_path = "_".join(child_path[-2:])
                if (
                    isinstance(child, str)
                    and (
                        segment in REVIEW_RULE_LABEL_FIELD_PATHS
                        or semantic_path in REVIEW_RULE_LABEL_FIELD_PATHS
                    )
                ):
                    add(child)
                else:
                    visit(child, child_path)
        elif isinstance(value, list):
            for child in value[:1000]:
                visit(child, path)

    for section in (
        "alert",
        "grouped_alert_context",
        "correlated_alert_context",
        "detection_validation",
        "incident_response_evidence",
        "investigation_query_results",
    ):
        visit(prompt_package.get(section))
    return sorted(found)


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


def project_investigation_parameters(
    backend: str,
    parameters: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    return _query_request().project_parameters(
        backend, parameters, policy=_query_request_policy(),
        error_type=InvestigationQueryError,
    )


def _normalize_investigation_backend_parameters(
    backend: str, parameters: dict[str, Any], purpose: str,
    time_envelope: Any, authorization_context: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if backend in {"elastic", "oql"}:
        return _query_security_onion().normalize(
            parameters,
            purpose=purpose,
            backend=backend,
            time_envelope=time_envelope,
            authorization_context=authorization_context,
            policy=_query_security_onion_policy(),
            dependencies=_query_security_onion_dependencies(),
            error_type=InvestigationQueryError,
        )
    if backend == "osquery":
        module = _query_endpoint()
        normalized = module.normalize(
            parameters, dependencies=module.Dependencies(
                normalize_query=normalize_live_osquery_query,
                query_error=LiveOsqueryContractError),
            error_type=InvestigationQueryError,
        )
        return normalized, {}
    if backend == "enrichment":
        normalized = _query_enrichment().normalize(
            parameters,
            authorization_context=authorization_context,
            error_type=InvestigationQueryError,
        )
        return normalized, {}
    normalized = _query_derived().normalize(
        parameters,
        policy=_query_derived_policy(),
        dependencies=_query_derived_dependencies(),
        error_type=InvestigationQueryError,
    )
    return normalized, {}


def normalize_investigation_query_request(
    raw: Any, *, round_number: int, position: int,
    time_envelope: Any = None, authorization_context: Any = None,
) -> dict[str, Any]:
    module = _query_request()
    return module.normalize(
        raw,
        round_number=round_number,
        position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context,
        policy=_query_request_policy(),
        dependencies=module.Dependencies(
            normalize_parameters=_normalize_investigation_backend_parameters
        ),
        error_type=InvestigationQueryError,
    )


def pop_investigation_query_requests(response: dict[str, Any]) -> list[Any]:
    """Consume the unified protocol and translate two legacy request fields."""
    unified = response.pop("investigation_query_requests", [])
    requests = list(unified) if isinstance(unified, list) else [unified]
    legacy_pcap = response.pop("pcap_query_requests", [])
    if isinstance(legacy_pcap, list):
        for index, item in enumerate(legacy_pcap, 1):
            if not isinstance(item, dict):
                requests.append(item)
                continue
            requests.append(
                {
                    "query_id": f"legacy-pcap-{index}",
                    "backend": "pcap_zeek",
                    "purpose": "Resolve the model's requested bounded PCAP evidence gap.",
                    "parameters": item,
                }
            )
    legacy_osquery = response.pop("live_osquery_requests", [])
    if isinstance(legacy_osquery, list):
        for index, item in enumerate(legacy_osquery, 1):
            if not isinstance(item, dict):
                requests.append(item)
                continue
            requests.append(
                {
                    "query_id": f"legacy-osquery-{index}",
                    "backend": "osquery",
                    "purpose": _query_text(item.get("purpose"), 500)
                    or "Resolve the model's requested endpoint evidence gap.",
                    "parameters": {
                        "target_alias": item.get("target_alias"),
                        "query": item.get("query"),
                    },
                }
            )
    return requests


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
    encoded = json.dumps(
        value if isinstance(value, (dict, list)) else {},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    source = value if isinstance(value, dict) else {}
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "query_contract": _query_text(
            source.get("query_contract") or source.get("schema"),
            128,
        ),
        "authorized_request_digest": _query_text(
            source.get("authorized_request_digest")
            or source.get("request_digest"),
            128,
        ),
        "authorization_context_digest": _query_text(
            source.get("authorization_context_digest")
            or source.get("authorization_digest"),
            128,
        ),
        "security_onion_response_digest": _query_text(
            source.get("security_onion_response_digest"),
            128,
        ),
        "complete": bool(source.get("complete")),
    }


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
    if not isinstance(raw, list):
        return []
    output: list[dict[str, Any]] = []
    for item in raw[:MAX_INVESTIGATION_QUERIES_PER_ROUND]:
        if not isinstance(item, dict):
            continue
        selected = {
            str(key): model_safe_copy(value)
            for key, value in item.items()
            if str(key) in TRUSTED_QUERY_AUDIT_FIELDS
        }
        # Executed queries are normally only a few KiB. Fail closed rather than
        # letting a result-derived value bloat the durable analysis artifact.
        encoded = json.dumps(
            selected,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        if len(encoded) > 64 * 1024:
            selected = {
                key: value
                for key, value in selected.items()
                if key
                not in {
                    "query_dsl",
                    "observables",
                    "observable_provenance",
                    "shards",
                }
            }
            selected["audit_truncated"] = True
        output.append(selected)
    return output


def validate_derived_query_evidence(
    value: Any,
    expected_requests: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bind each derived result to the exact normalized request and digests."""
    if not isinstance(value, dict) or value.get("schema") != PCAP_QUERY_CONTRACT:
        raise InvestigationQueryError("derived PCAP/Zeek result schema is invalid")
    executed = value.get("executed")
    results = value.get("results")
    if (
        not isinstance(executed, list)
        or not isinstance(results, list)
        or len(executed) != len(expected_requests)
        or len(results) != len(expected_requests)
    ):
        raise InvestigationQueryError(
            "derived PCAP/Zeek result count does not match the request"
        )
    for index, expected in enumerate(expected_requests):
        if executed[index] != expected:
            raise InvestigationQueryError(
                "derived PCAP/Zeek executed query does not match the normalized request"
            )
        result = results[index]
        if not isinstance(result, dict) or result.get("query") != expected:
            raise InvestigationQueryError(
                "derived PCAP/Zeek result query does not match the normalized request"
            )
        records = result.get("records")
        if not isinstance(records, list):
            raise InvestigationQueryError("derived PCAP/Zeek records must be an array")
        query_digest = hashlib.sha256(
            json.dumps(
                {"contract": PCAP_QUERY_CONTRACT, "request": expected},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        result_digest = hashlib.sha256(
            json.dumps(
                records,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if (
            result.get("query_digest") != query_digest
            or result.get("result_digest") != result_digest
        ):
            raise InvestigationQueryError(
                "derived PCAP/Zeek query or result digest is invalid"
            )
        if not isinstance(result.get("audit"), dict):
            raise InvestigationQueryError("derived PCAP/Zeek audit is missing")
    return value


def _derived_evidence_source_digest(pcap_context: dict[str, Any]) -> str:
    """Bind a pivot to the capture artifacts represented by the local index."""
    parsed = (
        pcap_context.get("parsed_evidence")
        if isinstance(pcap_context.get("parsed_evidence"), list)
        else []
    )
    identities: list[dict[str, Any]] = []
    for record in parsed[:20]:
        if not isinstance(record, dict):
            continue
        artifacts = [
            {
                "name": _query_text(item.get("name"), 255),
                "sha256": _query_text(item.get("sha256"), 64),
                "size_bytes": item.get("size_bytes"),
            }
            for item in (
                record.get("pcap_files")
                if isinstance(record.get("pcap_files"), list)
                else []
            )[:20]
            if isinstance(item, dict)
            and re.fullmatch(r"[a-f0-9]{64}", _query_text(item.get("sha256"), 64))
        ]
        if not artifacts:
            continue
        identities.append(
            {
                "artifacts": sorted(
                    artifacts,
                    key=lambda item: (
                        item["sha256"],
                        item["name"],
                        str(item["size_bytes"]),
                    ),
                ),
                "request_id": _query_text(record.get("request_id"), 160),
                "group_id": _query_text(record.get("group_id"), 160),
                "generated_at": _query_text(record.get("generated_at"), 100),
            }
        )
    if not identities:
        raise InvestigationQueryError(
            "derived PCAP/Zeek evidence has no capture-bound artifact identity"
        )
    identities.sort(
        key=lambda item: json.dumps(
            item,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    )
    return hashlib.sha256(
        json.dumps(
            identities,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _trusted_live_osquery_case_observables(
    prompt_package: dict[str, Any],
) -> dict[str, set[str]]:
    """Return only collector-owned observables authorized for this case."""
    import ipaddress

    values: dict[str, set[str]] = {
        "ips": set(),
        "hosts": set(),
        "domains": set(),
        "users": set(),
        "ports": set(),
    }
    local = prompt_package.get("_local_investigation_query_context")
    if not isinstance(local, dict):
        return values
    permitted = local.get("permitted_observables")
    if isinstance(permitted, dict):
        for key in ("ips", "hosts", "domains", "users"):
            raw_values = permitted.get(key)
            for raw in raw_values if isinstance(raw_values, list) else []:
                text = str(raw or "").strip().rstrip(".")
                if not text:
                    continue
                if key == "ips":
                    try:
                        text = str(ipaddress.ip_address(text))
                    except ValueError:
                        continue
                else:
                    text = text.lower()
                values[key].add(text)
    tuples = local.get("permitted_event_tuples")
    for entry in tuples if isinstance(tuples, list) else []:
        event_tuple = (
            entry.get("event_tuple")
            if isinstance(entry, dict)
            else None
        )
        if not isinstance(event_tuple, dict):
            continue
        for field in ("source_ip", "destination_ip"):
            try:
                values["ips"].add(
                    str(ipaddress.ip_address(str(event_tuple.get(field)).strip()))
                )
            except ValueError:
                pass
        for field in ("source_port", "destination_port"):
            raw_port = event_tuple.get(field)
            if isinstance(raw_port, bool) or raw_port in (None, ""):
                continue
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if 0 <= port <= 65535:
                values["ports"].add(str(port))
    return values


def _live_osquery_target_bound_to_case(
    prompt_package: dict[str, Any],
    target_alias: Any,
    config: dict[str, Any],
) -> bool:
    """Require the opaque target alias to match this alert's trusted asset."""
    alias = _query_text(target_alias, 64).lower()
    bindings = config.get("target_bindings")
    binding = bindings.get(alias) if isinstance(bindings, dict) else None
    if not isinstance(binding, dict):
        return False
    observables = _trusted_live_osquery_case_observables(prompt_package)
    bound_ips = {
        str(item).strip()
        for item in binding.get("ips", [])
        if str(item).strip()
    }
    bound_hosts = {
        str(item).strip().lower().rstrip(".")
        for item in binding.get("hosts", [])
        if str(item).strip()
    }
    return bool(
        bound_ips.intersection(observables["ips"])
        or bound_hosts.intersection(observables["hosts"])
    )


def _live_osquery_support_bindings(
    prompt_package: dict[str, Any],
    result: dict[str, Any],
    config: dict[str, Any],
) -> list[dict[str, Any]]:
    """Bind positive rows to trusted case observables without copying values."""
    if not _live_osquery_target_bound_to_case(
        prompt_package,
        result.get("target_alias"),
        config,
    ):
        return []
    query = str(result.get("query") or "")
    match = re.search(
        r"\bfrom\s+([A-Za-z_][A-Za-z0-9_]*)",
        query,
        re.IGNORECASE,
    )
    table = match.group(1).lower() if match else ""
    column_kinds = {
        "remote_address": "ips",
        "local_address": "ips",
        "address": "ips",
        "source_ip": "ips",
        "destination_ip": "ips",
        "remote_port": "ports",
        "local_port": "ports",
        "port": "ports",
        "hostname": "hosts",
        "host": "hosts",
        "domain": "domains",
        "query": "domains",
        "username": "users",
        "user": "users",
    }
    table_kinds = {
        "process_open_sockets": {"ips", "ports"},
        "listening_ports": {"ips", "ports"},
        "logged_in_users": {"users"},
        "users": {"users"},
    }
    permitted_kinds = table_kinds.get(table, set())
    if not permitted_kinds:
        return []
    observables = _trusted_live_osquery_case_observables(prompt_package)
    bindings: list[dict[str, Any]] = []
    rows = result.get("rows")
    for row_index, row in enumerate(rows if isinstance(rows, list) else []):
        if not isinstance(row, dict):
            continue
        for raw_column, raw_value in row.items():
            column = str(raw_column or "").strip().lower()
            kind = column_kinds.get(column)
            if kind not in permitted_kinds:
                continue
            value = str(raw_value or "").strip().rstrip(".")
            if kind in {"hosts", "domains", "users"}:
                value = value.lower()
            if value not in observables[kind]:
                continue
            bindings.append(
                {
                    "schema": "onion-sentinel-live-osquery-support-v1",
                    "target_alias": _query_text(
                        result.get("target_alias"),
                        64,
                    ),
                    "query_digest": _query_text(
                        result.get("query_digest"),
                        64,
                    ),
                    "table": table,
                    "row_index": row_index,
                    "column": column,
                    "observable_kind": kind[:-1],
                    "observable_digest": hashlib.sha256(
                        f"{kind}\0{value}".encode("utf-8")
                    ).hexdigest(),
                    "source": "trusted-investigation-context",
                    "temporal_scope": "collection_snapshot",
                }
            )
            if len(bindings) >= 16:
                return bindings
    return bindings


def _append_live_osquery_audit_batch(
    prompt_package: dict[str, Any],
    *,
    case_id: str,
    generated_at: str,
    results: list[dict[str, Any]],
    complete: bool,
    partial: bool,
    validated: bool,
    control_plane_write_status: str,
    collection_error: str = "",
) -> None:
    """Append one runtime-owned endpoint attempt to the private final audit."""
    key = "_live_osquery_evidence_accumulator"
    current = prompt_package.get(key)
    if current is None:
        current = {
            "schema": LIVE_OSQUERY_SCHEMA,
            "case_id": case_id,
            "generated_at": "",
            "read_only": True,
            "control_plane_writes": False,
            "control_plane_write_status": "none",
            "complete": True,
            "partial": False,
            "collection_error": "",
            "batches": [],
            "results": [],
        }
        prompt_package[key] = current
    if (
        not isinstance(current, dict)
        or current.get("schema") != LIVE_OSQUERY_SCHEMA
        or current.get("case_id") != case_id
        or current.get("read_only") is not True
        or not isinstance(current.get("batches"), list)
        or not isinstance(current.get("results"), list)
    ):
        raise LiveOsqueryClientError(
            "existing live OSQuery evidence accumulator is invalid"
        )
    if len(current["batches"]) >= MAX_INVESTIGATION_QUERY_ROUNDS:
        raise LiveOsqueryClientError(
            "live OSQuery evidence accumulator exceeded the round limit"
        )
    batch_results = copy.deepcopy(results)
    if (
        len(current["results"]) + len(batch_results)
        > MAX_INVESTIGATION_QUERIES_TOTAL
    ):
        raise LiveOsqueryClientError(
            "live OSQuery evidence accumulator exceeded the query limit"
        )
    result_start = len(current["results"])
    current["results"].extend(batch_results)
    current["batches"].append(
        {
            "batch": len(current["batches"]) + 1,
            "generated_at": _query_text(generated_at, 100),
            "complete": complete is True,
            "partial": partial is True,
            "validated": validated is True,
            "collection_error": _query_text(collection_error, 1000),
            "result_start": result_start,
            "result_count": len(batch_results),
        }
    )
    current["generated_at"] = _query_text(generated_at, 100)
    if control_plane_write_status not in {"none", "possible", "confirmed"}:
        raise LiveOsqueryClientError(
            "invalid live OSQuery control-plane write status"
        )
    current_status = str(
        current.get("control_plane_write_status") or "none"
    )
    status_rank = {"none": 0, "possible": 1, "confirmed": 2}
    if status_rank[control_plane_write_status] > status_rank.get(
        current_status,
        0,
    ):
        current["control_plane_write_status"] = control_plane_write_status
    current["control_plane_writes"] = (
        current.get("control_plane_write_status") != "none"
    )
    current["complete"] = all(
        item.get("complete") is True and item.get("validated") is True
        for item in current["batches"]
        if isinstance(item, dict)
    )
    current["partial"] = not current["complete"]
    errors = [
        _query_text(item.get("collection_error"), 1000)
        for item in current["batches"]
        if isinstance(item, dict) and item.get("collection_error")
    ]
    current["collection_error"] = "; ".join(errors)[-2000:]


def accumulate_live_osquery_evidence(
    prompt_package: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    """Retain a collector-validated endpoint evidence batch for the final audit."""
    if (
        evidence.get("schema") != LIVE_OSQUERY_SCHEMA
        or evidence.get("read_only") is not True
        or not isinstance(evidence.get("results"), list)
    ):
        raise LiveOsqueryClientError(
            "live OSQuery evidence accumulator received an invalid artifact"
        )
    case_id = _query_text(evidence.get("case_id"), 160)
    if not case_id:
        raise LiveOsqueryClientError(
            "live OSQuery evidence accumulator received no case identity"
        )
    _append_live_osquery_audit_batch(
        prompt_package,
        case_id=case_id,
        generated_at=_query_text(evidence.get("generated_at"), 100),
        results=evidence["results"],
        complete=evidence.get("complete") is True,
        partial=evidence.get("partial") is True,
        validated=True,
        control_plane_write_status="confirmed",
    )


def accumulate_live_osquery_failure(
    prompt_package: dict[str, Any],
    *,
    case_id: str,
    requests: list[dict[str, Any]],
    error: str,
    dispatch_possible: bool,
) -> None:
    """Record an attempted collector batch that failed before validation."""
    failure_results: list[dict[str, Any]] = []
    for request in requests:
        query = normalize_live_osquery_query(request.get("query"))
        failure_results.append(
            {
                "target_alias": _query_text(request.get("target_alias"), 64),
                "query": query,
                "purpose": _query_text(request.get("purpose"), 500),
                "query_digest": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "status": "error",
                "rows": [],
                "total_rows": 0,
                "truncated": False,
                "duration_ms": 0,
                "error": _query_text(error, 1000),
            }
        )
    _append_live_osquery_audit_batch(
        prompt_package,
        case_id=case_id,
        generated_at=project_now(),
        results=failure_results,
        complete=False,
        partial=True,
        validated=False,
        control_plane_write_status=(
            "possible" if dispatch_possible else "none"
        ),
        collection_error=error,
    )


def _runtime_env_value(name: str) -> str:
    if (
        str(os.environ.get(CONTROLLED_EVALUATION_MODE_ENV) or "").strip()
        == "1"
    ):
        # Controlled evaluations have no credential-bearing runtime input.
        # In particular, never discover production secrets through the real
        # user's ~/n8n-local/.env while exercising an isolated database.
        return ""
    direct = str(os.environ.get(name) or "").strip()
    if direct:
        return direct
    env_file = Path.home() / "n8n-local" / ".env"
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == name:
                return value.strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def prepare_investigation_enrichment_context(
    prompt_package: dict[str, Any],
    agent_role: str,
    alert_store_url: str,
) -> dict[str, Any]:
    token = _runtime_env_value("N8N_POST_COMMIT_TOKEN")
    enabled = agent_role in {"soc-analyst", "incident-responder"} and len(token) >= 32
    config = {
        "enabled": enabled,
        "token": token,
        "alert_store_url": alert_store_url.rstrip("/"),
        "n8n_url": str(
            os.environ.get("N8N_INVESTIGATION_ENRICHMENT_URL")
            or "http://127.0.0.1:5678/webhook/onion-sentinel-investigation-enrichment"
        ).rstrip("/"),
        "timeout": 120,
    }
    capability = prompt_package.get("investigation_query_capability")
    if isinstance(capability, dict):
        backends = capability.get("backends")
        if isinstance(backends, dict) and isinstance(backends.get("enrichment"), dict):
            backends["enrichment"]["enabled"] = enabled
        if enabled:
            capability["enabled"] = True
    return config


def _post_investigation_enrichment_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = read_bounded_json(response, max_bytes=8 * 1024 * 1024)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise InvestigationQueryError("enrichment service returned an unsuccessful response")
    return result


def _project_investigation_enrichment_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    raw = record.get("raw_response")
    serialized = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str)
    raw_bytes = serialized.encode("utf-8")
    digest = str(record.get("raw_response_sha256") or "") or hashlib.sha256(raw_bytes).hexdigest()
    return {
        key: record.get(key)
        for key in (
            "source", "indicator", "indicator_type", "verdict", "confidence",
            "tags", "first_seen", "last_seen", "cached_at", "expires_at",
            "cache_state",
        )
    } | {
        "provider_evidence": {
            "response_sha256": digest,
            "response_size_bytes": int(record.get("raw_response_size_bytes") or len(raw_bytes)),
            "cache_response_complete": record.get("raw_response_complete", True) is True,
            "prompt_projection_complete": len(raw_bytes) <= 32 * 1024,
            **(
                {"response": raw}
                if len(raw_bytes) <= 32 * 1024
                else {"response_json_prefix": raw_bytes[: 32 * 1024].decode("utf-8", "ignore")}
            ),
        }
    }


def collect_investigation_enrichment(
    request: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    parameters = request.get("parameters") if isinstance(request.get("parameters"), dict) else {}
    payload = {
        "indicator_type": parameters.get("indicator_type"),
        "indicator": parameters.get("indicator"),
    }
    token = str(config.get("token") or "")
    timeout = int(config.get("timeout") or 120)
    cache = _post_investigation_enrichment_json(
        str(config["alert_store_url"]) + "/investigations/enrichment/cache",
        payload,
        {"X-Onion-Sentinel-Asset-Token": token},
        timeout,
    )
    n8n_invoked = not bool(cache.get("cache_complete"))
    source = cache
    if n8n_invoked:
        source = _post_investigation_enrichment_json(
            str(config["n8n_url"]),
            payload,
            {"X-Relay-Token": token},
            timeout,
        )
    raw_records = (
        source.get("records")
        if isinstance(source.get("records"), list)
        else source.get("enrichment", {}).get("records", [])
        if isinstance(source.get("enrichment"), dict)
        else []
    )
    records = [
        projected for projected in
        (_project_investigation_enrichment_record(item) for item in raw_records[:16])
        if projected
    ]
    canonical_query = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    canonical_result = json.dumps(records, sort_keys=True, separators=(",", ":"), default=str)
    query_digest = hashlib.sha256(canonical_query.encode("utf-8")).hexdigest()
    result_digest = hashlib.sha256(canonical_result.encode("utf-8")).hexdigest()
    return {
        "schema": "onion-sentinel-investigation-enrichment-evidence-v1",
        "status": "ok",
        "indicator_type": payload["indicator_type"],
        "indicator": payload["indicator"],
        "cache_checked_first": True,
        "cache_complete": bool(cache.get("cache_complete")),
        "n8n_invoked": n8n_invoked,
        "rate_limits_enforced_by": "alert-store-persisted-provider-scheduler",
        "records": records,
        "skipped": (source.get("enrichment") or source).get("skipped", []),
        "errors": (source.get("enrichment") or source).get("errors", []),
        "query_digest": query_digest,
        "result_digest": result_digest,
        "evidence_ref": f"enrichment:{query_digest[:20]}:{result_digest[:20]}",
    }


def security_onion_authorization_context(value: Any) -> dict[str, Any]:
    """Project local-only policy data out of the restricted broker contract."""
    if not isinstance(value, dict):
        return {}
    unsupported = set(value).difference(
        INVESTIGATION_SECURITY_ONION_AUTHORIZATION_CONTEXT_FIELDS,
        INVESTIGATION_LOCAL_ONLY_AUTHORIZATION_CONTEXT_FIELDS,
    )
    if unsupported:
        raise InvestigationQueryContractError(
            "local authorization context contains unsupported fields: "
            + ", ".join(sorted(str(item) for item in unsupported))
        )
    return {
        key: copy.deepcopy(value[key])
        for key in INVESTIGATION_SECURITY_ONION_AUTHORIZATION_CONTEXT_FIELDS
        if key in value
    }


def _execute_security_query_backend(
    requests: list[dict[str, Any]], context: dict[str, Any],
    round_number: int, executor: Callable[..., dict[str, Any]],
):
    module = _query_execution_security_onion()
    return module.execute(
        requests, context, round_number=round_number,
        policy=module.Policy(
            query_contract=INVESTIGATION_QUERY_CONTRACT,
            require_anchor_time=INVESTIGATION_QUERY_V2),
        dependencies=module.Dependencies(
            project_context=security_onion_authorization_context,
            authorize=authorize_investigation_query_request,
            executor=executor,
            text=_query_text,
            random_hex=lambda size: os.urandom(size).hex(),
            bounded_audit=_bounded_trusted_query_audit,
            safe_audit_summary=_safe_audit_summary,
            contract_error=InvestigationQueryContractError,
            query_error=InvestigationQueryError,
        ),
    )
def _execute_endpoint_query_backend(
    requests: list[dict[str, Any]], prompt_package: dict[str, Any],
    config: dict[str, Any] | None, executor: Callable[..., dict[str, Any]],
):
    module = _query_execution_endpoint()
    return module.execute(
        requests, prompt_package, config,
        dependencies=module.Dependencies(
            executor=executor,
            validate_artifact=validate_live_osquery_result_artifact,
            case_id=live_osquery_case_id,
            target_bound=_live_osquery_target_bound_to_case,
            support_bindings=_live_osquery_support_bindings,
            accumulate_evidence=accumulate_live_osquery_evidence,
            accumulate_failure=accumulate_live_osquery_failure,
            normalize_query=normalize_live_osquery_query,
            text=_query_text,
            bounded_audit=_bounded_trusted_query_audit,
            safe_audit_summary=_safe_audit_summary,
            client_error=LiveOsqueryClientError,
            handled_errors=(LiveOsqueryClientError, LiveOsqueryContractError, OSError),
        ),
    )
def _execute_derived_query_backend(
    requests: list[dict[str, Any]], prompt_package: dict[str, Any],
    executor: Callable[..., dict[str, Any]],
):
    module = _query_execution_derived()
    context = prompt_package.get("pcap_evidence")
    return module.execute(
        requests, context if isinstance(context, dict) else {},
        dependencies=module.Dependencies(
            executor=executor,
            validate_evidence=validate_derived_query_evidence,
            source_digest=_derived_evidence_source_digest,
            bounded_audit=_bounded_trusted_query_audit,
            safe_audit_summary=_safe_audit_summary,
            handled_errors=(InvestigationQueryError, PcapEvidenceQueryError, OSError),
        ),
    )
def _execute_enrichment_query_backend(
    requests: list[dict[str, Any]], config: dict[str, Any] | None,
    executor: Callable[..., dict[str, Any]],
):
    module = _query_execution_enrichment()
    return module.execute(
        requests, config,
        dependencies=module.Dependencies(
            executor=executor,
            error_type=InvestigationQueryError,
            handled_errors=(InvestigationQueryError, OSError, urllib.error.URLError),
        ),
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
    if security_onion_executor is None:
        security_onion_executor = lambda proposal, authorization: (
            collect_security_onion_pivots(
                proposal, authorization,
                config_path=security_onion_config_path,
                out_dir=investigation_pivot_dir)
        )
    osquery_executor = osquery_executor or collect_live_osquery
    derived_executor = derived_executor or query_derived_pcap_evidence
    enrichment_executor = enrichment_executor or collect_investigation_enrichment
    local_context = prompt_package.get("_local_investigation_query_context")
    authorization_context = local_context if isinstance(local_context, dict) else {}
    module = _query_execution_batch()
    return module.execute(
        requests, round_number=round_number,
        policy=module.Policy(result_schema=INVESTIGATION_QUERY_RESULT_SCHEMA),
        dependencies=module.Dependencies(
            security_onion=lambda selected: _execute_security_query_backend(
                selected, authorization_context, round_number, security_onion_executor,
            ),
            endpoint=lambda selected: _execute_endpoint_query_backend(
                selected, prompt_package, live_osquery_config, osquery_executor,
            ),
            derived=lambda selected: _execute_derived_query_backend(
                selected, prompt_package, derived_executor,
            ),
            enrichment=lambda selected: _execute_enrichment_query_backend(
                selected, enrichment_config, enrichment_executor,
            ),
            now=project_now,
        ),
    )


def _evidence_ref_component(value: Any, maximum: int = 40) -> str:
    """Return a compact collision-resistant component for an authorization ref."""
    text = _query_text(value, 512)
    if (
        text
        and len(text) <= maximum
        and re.fullmatch(r"[A-Za-z0-9_.:@+=-]+", text)
    ):
        return text
    return "sha256-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]


def _validated_discovered_observables(
    results: Any,
    *,
    limit: int = MAX_DISCOVERED_OBSERVABLES,
) -> list[dict[str, str]]:
    """Extract pivots only from provenance-bound broker hits or derived records."""
    return _query_observables().validate(
        results,
        limit=limit,
        policy=_query_observable_validation_policy(),
        dependencies=_query_observable_validation_dependencies(),
    )


def investigation_query_prompt_error_category(reason: Any) -> str:
    return _query_prompt_errors().category(reason)


def investigation_query_prompt_error_digest(reason: Any) -> str:
    return _query_prompt_errors().digest(reason, canonical_payload_digest)


def _prompt_project_investigation_rows(
    value: Any,
    state: dict[str, int | bool],
) -> Any:
    module = _query_prompt_compaction()
    return module.project_rows(
        value,
        state,
        policy=module.Policy(
            maximum_rows=MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS
        ),
        dependencies=_query_prompt_compaction_dependencies(),
    )


def _investigation_prompt_json_bytes(value: Any) -> bytes:
    return _query_prompt_facts().canonical_bytes(value)


def _compact_prompt_trusted_query_audit(
    value: Any,
) -> dict[str, Any]:
    return _query_prompt_compaction().compact_audit(
        value, dependencies=_query_prompt_compaction_dependencies()
    )


def _bounded_investigation_prompt_fact(
    value: Any,
    *,
    maximum_bytes: int = 256,
) -> str:
    return _query_prompt_facts().bounded(
        value, maximum_bytes=maximum_bytes
    )


def _canonical_investigation_count(value: Any) -> int | None:
    return _query_prompt_facts().canonical_count(
        value, policy=_query_prompt_facts_policy()
    )


def _investigation_provenance_count(
    containers: tuple[dict[str, Any], ...],
    keys: tuple[str, ...],
) -> int | None:
    return _query_prompt_facts().provenance_count(
        containers, keys, policy=_query_prompt_facts_policy()
    )


def _investigation_query_semantics(
    containers: tuple[dict[str, Any], ...],
) -> str:
    return _query_prompt_facts().query_semantics(containers)


def _investigation_result_summary(
    containers: tuple[dict[str, Any], ...],
    *,
    status: str,
    returned: int | None,
) -> str:
    return _query_prompt_facts().result_summary(
        containers,
        status=status,
        returned=returned,
        policy=_query_prompt_facts_policy(),
    )


def _investigation_prompt_provenance_rows(
    rounds: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    return _query_prompt_provenance().rows(
        rounds, policy=_query_prompt_provenance_policy()
    )


def _columnar_investigation_prompt_payload(
    rounds: list[dict[str, Any]],
    *,
    maximum_bytes: int,
) -> dict[str, Any] | None:
    return _query_prompt_provenance().columnar_payload(
        rounds,
        maximum_bytes=maximum_bytes,
        policy=_query_prompt_provenance_policy(),
        dependencies=_query_prompt_provenance_dependencies(),
    )


def _investigation_prompt_payload(
    rounds: list[dict[str, Any]],
    *,
    maximum_bytes: int = MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES,
) -> dict[str, Any]:
    module = _query_prompt_budget()
    return module.payload(
        rounds,
        maximum_bytes=maximum_bytes,
        policy=module.Policy(
            maximum_rows=MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS,
            result_schema=INVESTIGATION_QUERY_RESULT_SCHEMA,
        ),
        dependencies=_query_prompt_budget_dependencies(),
        error_type=InvestigationQueryError,
    )

def _admit_investigation_query_prompt(
    prompt_package: dict[str, Any],
    rounds: list[dict[str, Any]],
    *,
    maximum_prompt_bytes: int,
    hosted: bool,
) -> int:
    module = _query_prompt_admission()
    return module.admit(
        prompt_package,
        rounds,
        maximum_prompt_bytes=maximum_prompt_bytes,
        hosted=hosted,
        policy=module.Policy(
            maximum_evidence_bytes=MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES
        ),
        dependencies=_query_prompt_admission_dependencies(),
        error_type=InvestigationQueryError,
    )

def _investigation_round_audit(round_result: dict[str, Any]) -> dict[str, Any]:
    return _query_audit().round_audit(
        round_result,
        policy=_query_audit_policy(),
        dependencies=_query_audit_dependencies(),
    )

INVESTIGATION_QUERY_NONEXECUTION_STATUSES = frozenset(
    {"rejected", "denied", "blocked", "unauthorized", "forbidden"}
)


def _investigation_tool_call_bindings(
    round_result: dict[str, Any],
) -> list[dict[str, Any]]:
    return _query_audit().tool_call_bindings(
        round_result,
        policy=_query_audit_policy(),
        dependencies=_query_audit_dependencies(),
    )


def investigation_query_binding_summary(
    bindings: list[dict[str, Any]],
    *,
    queries_admitted: int,
) -> dict[str, Any]:
    return _query_audit().binding_summary(
        bindings,
        queries_admitted=queries_admitted,
        policy=_query_audit_policy(),
    )


def investigation_query_outcome_summary(
    rounds: list[dict[str, Any]],
    *,
    queries_admitted: int,
) -> dict[str, Any]:
    return _query_outcomes().summary(
        rounds,
        queries_admitted=queries_admitted,
        policy=_query_outcomes_policy(),
    )


def _append_investigation_evidence_gaps(
    response: dict[str, Any],
    gaps: list[str],
) -> None:
    _query_outcomes().append_evidence_gaps(response, gaps)


def investigation_backend_available(
    prompt_package: dict[str, Any],
    backend: str,
    *,
    live_osquery_config: dict[str, Any] | None,
) -> bool:
    """Require both an advertised capability and its trusted local prerequisite."""
    capability = prompt_package.get("investigation_query_capability")
    backends = capability.get("backends") if isinstance(capability, dict) else None
    descriptor = backends.get(backend) if isinstance(backends, dict) else None
    if (
        not isinstance(capability, dict)
        or capability.get("enabled") is not True
        or not isinstance(descriptor, dict)
        or descriptor.get("enabled") is not True
    ):
        return False
    if backend in {"elastic", "oql"}:
        local_context = prompt_package.get("_local_investigation_query_context")
        return bool(
            isinstance(local_context, dict)
            and isinstance(local_context.get("anchor"), dict)
        )
    if backend == "pcap_zeek":
        pcap = prompt_package.get("pcap_evidence")
        return bool(
            isinstance(pcap, dict)
            and isinstance(pcap.get("parsed_evidence"), list)
            and pcap.get("parsed_evidence")
        )
    if backend == "osquery":
        return bool(live_osquery_config and live_osquery_config.get("enabled"))
    if backend == "enrichment":
        return bool(descriptor.get("enabled"))
    return False


def investigation_request_semantic_digest(request: dict[str, Any]) -> str:
    """Identify an equivalent execution independently of model labels/purpose."""
    parameters = json.loads(
        json.dumps(request.get("parameters") or {}, sort_keys=True, default=str)
    )
    backend = request.get("backend")
    if backend in {"elastic", "oql"} and isinstance(parameters, dict):
        observables = parameters.get("observables")
        if isinstance(observables, dict):
            for kind in ("ips", "domains", "hosts", "users"):
                values = observables.get(kind)
                if not isinstance(values, list):
                    continue
                normalized_values: list[str] = []
                for raw in values:
                    text = str(raw or "").strip().rstrip(".")
                    if kind == "ips":
                        import ipaddress

                        try:
                            text = str(ipaddress.ip_address(text))
                        except ValueError:
                            pass
                    elif kind == "domains":
                        text = text.lower()
                    if text:
                        normalized_values.append(text)
                observables[kind] = sorted(set(normalized_values))
        window = parameters.get("window")
        if isinstance(window, dict):
            for boundary in ("start", "end"):
                text = str(window.get(boundary) or "").strip()
                if text.endswith("Z"):
                    text = text[:-1] + "+00:00"
                try:
                    parsed = dt.datetime.fromisoformat(text)
                    if parsed.tzinfo is not None:
                        window[boundary] = parsed.astimezone(
                            dt.timezone.utc
                        ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                except ValueError:
                    pass
    elif backend == "osquery" and isinstance(parameters, dict):
        normalized_query = normalize_live_osquery_query(parameters.get("query"))
        parts = re.split(r"('(?:''|[^'])*')", normalized_query)
        parameters["query"] = "".join(
            part if index % 2 else " ".join(part.lower().split())
            for index, part in enumerate(parts)
        )
    elif backend == "pcap_zeek" and isinstance(parameters, dict):
        if isinstance(parameters.get("indicator"), str):
            parameters["indicator"] = parameters["indicator"].casefold()
        filters = parameters.get("filters")
        if isinstance(filters, dict):
            parameters["filters"] = {
                key: value.casefold() if isinstance(value, str) else value
                for key, value in filters.items()
            }
    elif backend == "enrichment" and isinstance(parameters, dict):
        parameters["indicator_type"] = str(parameters.get("indicator_type") or "").lower()
        parameters["indicator"] = str(parameters.get("indicator") or "").strip().rstrip(".").lower()
    canonical = {
        "backend": backend,
        "parameters": parameters,
    }
    return hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def recover_repair_observables_from_trusted_catalog(
    value: Any,
    authorization_context: Any,
) -> dict[str, list[str]] | None:
    return _query_repair().recover_observables(
        value, authorization_context
    )


def investigation_query_repair_scope(
    raw: Any,
    *,
    round_number: int,
    position: int,
    time_envelope: Any = None,
    authorization_context: Any = None,
) -> dict[str, Any] | None:
    return _query_repair().scope(
        raw,
        round_number=round_number,
        position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context,
        dependencies=_query_repair_dependencies(),
        error_type=InvestigationQueryError,
    )


def validate_investigation_query_repair_scope(
    request: dict[str, Any],
    scope: dict[str, Any],
) -> None:
    _query_repair().validate(
        request, scope, error_type=InvestigationQueryError
    )


def investigation_query_request_from_repair_scope(
    scope: dict[str, Any],
) -> dict[str, Any]:
    return _query_repair().request_from_scope(scope)


def investigation_query_repair_failures(
    round_result: Any,
) -> dict[str, str]:
    return _query_repair().failures(round_result)


def investigation_query_repair_prompt_entry(
    scope: dict[str, Any],
    *,
    reason: str,
    trigger: str,
) -> dict[str, Any]:
    return _query_repair().prompt_entry(
        scope,
        reason=reason,
        trigger=trigger,
        dependencies=_query_repair_dependencies(),
    )


def deterministic_incident_pivot_requests(
    prompt_package: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compile a repeatable protocol-first plan from trusted local context."""
    module = _query_deterministic_planning()
    return module.plan(
        prompt_package,
        policy=_query_deterministic_planning_policy(),
        dependencies=_query_deterministic_planning_dependencies(),
    )


class _QueryCoordinatorRuntime:
    def __init__(
        self,
        *,
        coordinator: Any,
        prompt_package: dict[str, Any],
        args: argparse.Namespace,
        settings: dict[str, Any],
        route: str,
        harness_runtime: OnionSentinelHarnessRun | None,
        model_executor: Callable[..., Any],
        query_executor: Callable[..., Any],
        configured_query_executor: bool,
        live_osquery_config: dict[str, Any] | None,
        enrichment_config: dict[str, Any] | None,
        security_onion_config_path: Path,
        investigation_pivot_dir: Path,
        model_input_builder: Callable[[dict[str, Any], int], Any] | None,
        model_call_independent_review: bool,
        evaluation_required: bool,
        maximum_prompt_bytes: int,
        hosted_route: bool,
    ) -> None:
        self.coordinator = coordinator
        self.prompt_package = prompt_package
        self.args = args
        self.settings = settings
        self.route = route
        self.harness_runtime = harness_runtime
        self.model_executor = model_executor
        self.query_executor = query_executor
        self.configured_query_executor = configured_query_executor
        self.live_osquery_config = live_osquery_config
        self.enrichment_config = enrichment_config
        self.security_onion_config_path = security_onion_config_path
        self.investigation_pivot_dir = investigation_pivot_dir
        self.model_input_builder = model_input_builder
        self.model_call_independent_review = model_call_independent_review
        self.evaluation_required = evaluation_required
        self.maximum_prompt_bytes = maximum_prompt_bytes
        self.hosted_route = hosted_route

    def observe(self, call: Callable[[], Any]) -> Any:
        if self.harness_runtime is None:
            return None
        try:
            return call()
        except Exception as exc:
            if (
                self.harness_runtime.policy.mode == "enforce"
                or self.evaluation_required
            ):
                raise
            print(
                "warning: Onion Sentinel harness shadow query observation "
                f"failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return None

    def planning_phase(self, note: str) -> None:
        self.observe(
            lambda: self.harness_runtime.phase(
                "investigation_query_planning", self.route, note
            ) if self.harness_runtime is not None else None
        )

    def planning_preflight(self, package: dict[str, Any]) -> None:
        self.observe(
            lambda: self.harness_runtime.preflight_model_call(
                call_id="primary-query-planning-retry-1",
                input_value=package,
                requested_route=self.route,
                purpose="evaluation query-planning retry 1 of 1",
            ) if self.harness_runtime is not None else None
        )

    def planning_record(
        self, response: dict[str, Any], duration: float, status: str,
    ) -> None:
        kwargs = {"status": status} if status else {}
        self.observe(
            lambda: self.harness_runtime.model_call(
                call_id="primary-query-planning-retry-1",
                purpose="evaluation query-planning retry 1 of 1",
                requested_route=self.route,
                response=response,
                input_value=self.prompt_package,
                duration_seconds=duration,
                **kwargs,
            ) if self.harness_runtime is not None else None
        )

    def authorize(
        self, round_number: int, request: dict[str, Any],
    ) -> Any:
        decision = self.observe(
            lambda: self.harness_runtime.authorize_tool(
                round_number=round_number,
                query_id=request["query_id"],
                backend=request["backend"],
                approved=(
                    request["backend"] == "osquery"
                    and live_osquery_harness_operator_approved(
                        self.live_osquery_config,
                        request["parameters"].get("target_alias"),
                    )
                ),
            ) if self.harness_runtime is not None else None
        )
        return self.coordinator.round_admission.resolve_authorization(
            runtime_present=self.harness_runtime is not None,
            approval_gated=query_backend_is_approval_gated(request["backend"]),
            policy_mode=(
                self.harness_runtime.policy.mode
                if self.harness_runtime is not None else "off"
            ),
            decision=decision,
            decision_effective=policy_decision_is_effective,
            fallback_capability=query_backend_capability(request["backend"]),
        )

    def backend_available(self, backend: str) -> bool:
        return investigation_backend_available(
            self.prompt_package,
            backend,
            live_osquery_config=self.live_osquery_config,
        )

    def query_execute(
        self, round_number: int, requests: list[dict[str, Any]],
    ) -> Any:
        self.observe(
            lambda: self.harness_runtime.preflight_query_batch(
                round_number=round_number, request_count=len(requests)
            ) if self.harness_runtime is not None else None
        )
        self.observe(
            lambda: self.harness_runtime.phase(
                "investigation_query_execution", self.route,
                f"round {round_number}; {len(requests)} admitted request(s)",
            ) if self.harness_runtime is not None else None
        )
        kwargs = {
            "round_number": round_number,
            "live_osquery_config": self.live_osquery_config,
        }
        if self.configured_query_executor:
            kwargs.update({
                "security_onion_config_path": self.security_onion_config_path,
                "investigation_pivot_dir": self.investigation_pivot_dir,
            })
        if self.enrichment_config is not None:
            kwargs["enrichment_config"] = self.enrichment_config
        return self.query_executor(self.prompt_package, requests, **kwargs)

    def observe_round(self, result: dict[str, Any]) -> None:
        self.observe(
            lambda: self.harness_runtime.query_round(result)
            if self.harness_runtime is not None else None
        )

    def admit_prompt(
        self, package: dict[str, Any], rounds: list[dict[str, Any]],
    ) -> None:
        _admit_investigation_query_prompt(
            package,
            rounds,
            maximum_prompt_bytes=self.maximum_prompt_bytes,
            hosted=self.hosted_route,
        )

    def build_model_input(self, package: dict[str, Any], number: int) -> Any:
        return (
            self.model_input_builder(package, number)
            if self.model_input_builder is not None else package
        )

    def synthesis_preflight(
        self, call_id: str, model_input: Any, purpose: str,
    ) -> None:
        self.observe(
            lambda: self.harness_runtime.preflight_model_call(
                call_id=call_id,
                input_value=model_input,
                requested_route=self.route,
                purpose=purpose,
                independent_review=self.model_call_independent_review,
            ) if self.harness_runtime is not None else None
        )

    def synthesis_record(
        self, call_id: str, purpose: str, response: Any, model_input: Any,
        duration: float, status: str,
    ) -> None:
        kwargs = {"status": status} if status else {}
        self.observe(
            lambda: self.harness_runtime.model_call(
                call_id=call_id,
                purpose=purpose,
                requested_route=self.route,
                response=response,
                input_value=model_input,
                duration_seconds=duration,
                independent_review=self.model_call_independent_review,
                **kwargs,
            ) if self.harness_runtime is not None else None
        )

    def model_safe_copy(self, value: Any, hosted: bool) -> Any:
        return model_safe_copy(value, hosted=hosted)

    def planning_execute(self, package: dict[str, Any]) -> Any:
        return self.model_executor(self.route, package, self.args, self.settings)

    def valid_query_id(self, value: str) -> bool:
        return bool(INVESTIGATION_QUERY_ID_RE.fullmatch(value))

    def synthesis_catalogue(self, value: Any) -> None:
        self.observe(
            lambda: self.harness_runtime.catalogue_prompt_evidence(value)
            if self.harness_runtime is not None else None
        )

    def synthesis_execute(self, model_input: Any) -> Any:
        return self.model_executor(
            self.route, model_input, self.args, self.settings
        )

    def synthesis_phase(self, note: str) -> None:
        self.observe(
            lambda: self.harness_runtime.phase(
                "evidence_synthesis", self.route, note
            ) if self.harness_runtime is not None else None
        )

    def ports(self) -> Any:
        return self.coordinator.Ports(
            pop_requests=pop_investigation_query_requests,
            deterministic_requests=deterministic_incident_pivot_requests,
            model_safe_copy=self.model_safe_copy,
            planning_execute=self.planning_execute,
            planning_phase=self.planning_phase,
            planning_preflight=self.planning_preflight,
            planning_record=self.planning_record,
            normalize_request=normalize_investigation_query_request,
            validate_repair=validate_investigation_query_repair_scope,
            backend_available=self.backend_available,
            semantic_digest=investigation_request_semantic_digest,
            authorize=self.authorize,
            repair_scope=investigation_query_repair_scope,
            query_text=_query_text,
            valid_query_id=self.valid_query_id,
            query_execute=self.query_execute,
            repair_failures=investigation_query_repair_failures,
            now=project_now,
            observe_round=self.observe_round,
            validate_observables=_validated_discovered_observables,
            canonical_digest=investigation_query_canonical_digest,
            error_digest=canonical_payload_digest,
            repair_prompt_entry=investigation_query_repair_prompt_entry,
            request_from_scope=investigation_query_request_from_repair_scope,
            admit_prompt=self.admit_prompt,
            build_model_input=self.build_model_input,
            synthesis_catalogue=self.synthesis_catalogue,
            synthesis_preflight=self.synthesis_preflight,
            synthesis_execute=self.synthesis_execute,
            synthesis_record=self.synthesis_record,
            synthesis_phase=self.synthesis_phase,
            outcome_summary=investigation_query_outcome_summary,
            round_audit=_investigation_round_audit,
            binding_summary=investigation_query_binding_summary,
            append_gaps=_append_investigation_evidence_gaps,
            monotonic=time.monotonic,
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
    from onion_sentinel.analysis.query import coordinator

    model_executor = model_executor or analyze_model_route
    configured_query_executor = query_executor is None
    query_executor = query_executor or execute_investigation_query_batch
    route = canonical_model_route(
        route_override or (settings.get("agent_models") or {}).get(agent_role)
    )
    evaluation_required = bool(
        harness_runtime is not None
        and boolean_setting(os.environ.get(EVALUATION_FREEZE_MEMORY_ENV))
        and not model_call_independent_review
    )
    maximum_prompt_bytes = int(
        getattr(args, "max_prompt_bytes", DEFAULT_MAX_PROMPT_BYTES)
        or DEFAULT_MAX_PROMPT_BYTES
    )
    hosted_route = model_route_is_hosted(route, settings)
    if canonical_model_route(
        route, enabled_agent_model_routes(settings)
    ).startswith("codex-cli:"):
        maximum_prompt_bytes = min(
            maximum_prompt_bytes, CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES
        )
    runtime = _QueryCoordinatorRuntime(
        coordinator=coordinator,
        prompt_package=prompt_package,
        args=args,
        settings=settings,
        route=route,
        harness_runtime=harness_runtime,
        model_executor=model_executor,
        query_executor=query_executor,
        configured_query_executor=configured_query_executor,
        live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        model_input_builder=model_input_builder,
        model_call_independent_review=model_call_independent_review,
        evaluation_required=evaluation_required,
        maximum_prompt_bytes=maximum_prompt_bytes,
        hosted_route=hosted_route,
    )
    return coordinator.run(
        prompt_package,
        primary_response,
        policy=coordinator.Policy(
            route=route,
            state_policy=_query_state().Policy(
                maximum_rounds=MAX_INVESTIGATION_QUERY_ROUNDS,
                maximum_queries=MAX_INVESTIGATION_QUERIES_TOTAL,
                maximum_queries_per_round=MAX_INVESTIGATION_QUERIES_PER_ROUND,
            ),
            rounds_override=max_rounds_override,
            queries_override=max_queries_total_override,
            evaluation_required=evaluation_required,
            include_deterministic_requests=include_deterministic_requests,
            maximum_prompt_bytes=maximum_prompt_bytes,
            hosted_route=hosted_route,
            query_round_offset=query_round_offset,
            model_call_id_prefix=model_call_id_prefix,
            model_call_purpose_prefix=model_call_purpose_prefix,
            model_call_independent_review=model_call_independent_review,
            query_result_schema=INVESTIGATION_QUERY_RESULT_SCHEMA,
            query_contract=INVESTIGATION_QUERY_CONTRACT,
            max_discovered_observables=MAX_DISCOVERED_OBSERVABLES,
            max_prompt_evidence_bytes=MAX_INVESTIGATION_PROMPT_EVIDENCE_BYTES,
            max_prompt_evidence_rows=MAX_INVESTIGATION_PROMPT_EVIDENCE_ROWS,
        ),
        ports=runtime.ports(),
        error_type=InvestigationQueryError,
    )


def _ollama_request(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    task: str,
    *,
    system_prompt_file: Path | None = None,
) -> dict[str, Any]:
    return _ollama_provider().request(
        prompt_package,
        args,
        settings,
        task,
        system_prompt_file=system_prompt_file,
        load_system_prompt=load_system_prompt,
        read_bounded_json=read_bounded_json,
        extract_json_object=extract_json_object,
        urlopen=urllib.request.urlopen,
        request_factory=urllib.request.Request,
        transport_errors=(urllib.error.URLError, BoundedHttpError),
        fallback_model=FALLBACK_OLLAMA_MODEL,
        default_url=DEFAULT_OLLAMA_URL,
    )


def _unload_ollama_model(
    settings: dict[str, Any],
    model: str,
    *,
    timeout: float,
) -> None:
    _ollama_provider().unload_model(
        settings,
        model,
        timeout=timeout,
        urlopen=urllib.request.urlopen,
        request_factory=urllib.request.Request,
        default_url=DEFAULT_OLLAMA_URL,
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
    return _ollama_provider().unlocked_chat(
        prompt_package,
        args,
        settings,
        model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        safe_copy=model_safe_copy,
        request_call=_ollama_request,
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
    return _ollama_provider().locked_chat(
        prompt_package,
        args,
        settings,
        model,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        lock_path=DEFAULT_OLLAMA_INFERENCE_LOCK,
        flock=fcntl.flock,
        lock_exclusive=fcntl.LOCK_EX,
        lock_unlock=fcntl.LOCK_UN,
        unlocked_call=_ollama_chat_for_model_unlocked,
        unload_call=_unload_ollama_model,
    )


def ollama_chat(prompt_package: dict[str, Any], args: argparse.Namespace, settings: dict[str, Any]) -> dict[str, Any]:
    return _ollama_provider().chat_with_failover(
        prompt_package,
        args,
        settings,
        normalize_roster=normalized_model_roster,
        chat_for_model=_ollama_chat_for_model,
        fallback_model=FALLBACK_OLLAMA_MODEL,
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
    return _codex_provider().response_schema(
        template,
        structured_enums=STRUCTURED_ENUMS,
        boolean_keys=STRUCTURED_BOOLEAN_KEYS,
    )


def canonical_cli_system_prompt_file(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> Path:
    return _codex_provider().canonical_system_prompt_file(
        prompt_package,
        args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        roles=CYBER_SECURITY_AGENT_ROLES,
        default_settings_file=DEFAULT_AI_SETTINGS_FILE,
        default_system_prompt_file=DEFAULT_SYSTEM_PROMPT_FILE,
        role_prompt_resolver=role_prompt_file,
        reviewer_prompt_resolver=role_second_opinion_prompt_file,
    )


def load_canonical_cli_system_prompt(path: Path, agent_role: str) -> str:
    return _codex_provider().load_canonical_system_prompt(
        path,
        agent_role,
        DEFAULT_MAX_SYSTEM_PROMPT_BYTES,
    )


def cli_analysis_payload(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    hosted: bool,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> dict[str, Any]:
    return _codex_provider().analysis_payload(
        prompt_package,
        args,
        hosted=hosted,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        roles=CYBER_SECURITY_AGENT_ROLES,
        canonical_prompt_file=canonical_cli_system_prompt_file,
        load_canonical_prompt=load_canonical_cli_system_prompt,
        load_legacy_prompt=load_system_prompt,
        safe_copy=model_safe_copy,
    )


def prepare_codex_cli_transport(
    prompt_package: dict[str, Any],
    args: argparse.Namespace,
    *,
    system_prompt_file: Path | None = None,
    independent_review: bool = False,
) -> tuple[dict[str, Any], str]:
    return _codex_provider().prepare_transport(
        prompt_package,
        args,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        build_payload=cli_analysis_payload,
        prompt_json_bytes=_investigation_prompt_json_bytes,
        max_package_bytes=CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        max_stdin_bytes=CODEX_CLI_MAX_STDIN_BYTES,
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
    return _codex_provider().chat(
        prompt_package,
        args,
        settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        resolve_executable=resolve_codex_cli,
        model_pattern=CODEX_CLI_MODEL_PATTERN,
        reasoning_efforts=CODEX_CLI_REASONING_EFFORTS,
        prepare=prepare_codex_cli_transport,
        schema_builder=response_output_json_schema,
        run_command=run_bounded_command,
        sanitized_env=sanitized_cli_harness_env,
        process_error=BoundedProcessError,
        summarize=summarize_codex_cli_failure,
        read_bytes=read_bytes_bounded,
        extract_json=extract_json_object,
        max_stderr_bytes=DEFAULT_CLOUD_MAX_STDERR_BYTES,
        controlled_tmpdir=_CONTROLLED_EVALUATION_TMPDIR,
    )


def sanitized_cli_harness_env(
    executable: str,
    *,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    return _cli_common_provider().sanitized_environment(executable, extra=extra)


def summarize_cli_harness_failure(
    label: str,
    stderr: str,
    returncode: int,
) -> str:
    return _cli_common_provider().summarize_harness_failure(
        label,
        stderr,
        returncode,
    )


def _filtered_hermes_auth_store(
    raw: dict[str, Any],
    *,
    require_credentials: bool = True,
) -> dict[str, Any]:
    return _hermes_provider().filtered_auth_store(
        raw,
        error_type=RuntimeArtifactError,
        require_credentials=require_credentials,
    )


def _load_bounded_regular_json(
    path: Path,
    *,
    max_bytes: int,
    label: str,
    required_mode: int | None = None,
) -> dict[str, Any]:
    """Read one non-symlink JSON file through its verified descriptor."""
    try:
        admitted = path.lstat()
    except OSError as exc:
        raise RuntimeArtifactError(f"{label} is missing") from exc
    if stat.S_ISLNK(admitted.st_mode) or not stat.S_ISREG(admitted.st_mode):
        raise RuntimeArtifactError(f"{label} must be a regular file")
    if required_mode is not None and stat.S_IMODE(admitted.st_mode) != required_mode:
        raise RuntimeArtifactError(
            f"{label} must have mode {required_mode:04o}"
        )
    if admitted.st_size > max_bytes:
        raise RuntimeArtifactError(f"{label} exceeds its size limit")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (admitted.st_dev, admitted.st_ino)
        ):
            raise RuntimeArtifactError(f"{label} changed during admission")
        if (
            required_mode is not None
            and stat.S_IMODE(opened.st_mode) != required_mode
        ):
            raise RuntimeArtifactError(
                f"{label} must have mode {required_mode:04o}"
            )
        if opened.st_size > max_bytes:
            raise RuntimeArtifactError(f"{label} exceeds its size limit")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise RuntimeArtifactError(f"{label} exceeds its size limit")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeArtifactError(f"{label} is not valid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeArtifactError(f"{label} JSON root must be an object")
        return value
    except OSError as exc:
        raise RuntimeArtifactError(f"{label} is not safely readable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_dedicated_hermes_auth(path: Path) -> dict[str, Any]:
    return _hermes_provider().load_auth(
        path,
        read_json=_load_bounded_regular_json,
        error_type=RuntimeArtifactError,
        max_bytes=HERMES_MAX_AUTH_BYTES,
    )


def _write_dedicated_hermes_auth(
    path: Path,
    auth_store: dict[str, Any],
) -> None:
    return _hermes_provider().write_auth(
        path,
        auth_store,
        error_type=RuntimeArtifactError,
    )


def _verified_hermes_usage(
    path: Path,
    *,
    expected_model: str,
) -> dict[str, Any]:
    return _hermes_provider().verified_usage(
        path,
        expected_model=expected_model,
        read_json=_load_bounded_regular_json,
        error_type=RuntimeArtifactError,
        max_bytes=HERMES_MAX_USAGE_BYTES,
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
    return _hermes_provider().chat(
        prompt_package,
        args,
        settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        boolean_setting=boolean_setting,
        model_catalog=CODEX_CLI_MODEL_CATALOG,
        required_effort=HERMES_AGENT_REASONING_EFFORT,
        resolve_executable=lambda configured: resolve_cli_harness(
            configured,
            setting_key="hermes_agent_path",
            basename="hermes",
            label="Hermes Agent",
        ),
        build_payload=cli_analysis_payload,
        auth_file=DEFAULT_HERMES_AUTH_FILE,
        load_dedicated_auth=_load_dedicated_hermes_auth,
        write_dedicated_auth=_write_dedicated_hermes_auth,
        atomic_write_json=atomic_write_json,
        run_command=run_bounded_command,
        sanitized_env=sanitized_cli_harness_env,
        process_error=BoundedProcessError,
        artifact_error=RuntimeArtifactError,
        summarize_failure=summarize_cli_harness_failure,
        verify_usage=_verified_hermes_usage,
        extract_json=extract_json_object,
        max_prompt_bytes=HERMES_MAX_PROMPT_ARGUMENT_BYTES,
        max_stderr_bytes=DEFAULT_CLOUD_MAX_STDERR_BYTES,
        flock=fcntl.flock,
        lock_exclusive=fcntl.LOCK_EX,
        lock_unlock=fcntl.LOCK_UN,
    )


def _openclaw_output_text(envelope: dict[str, Any]) -> str:
    return _openclaw_provider().output_text(envelope)


def _verified_openclaw_observation(
    envelope: dict[str, Any],
    expected_model: str,
) -> tuple[str, str]:
    return _openclaw_provider().verified_observation(envelope, expected_model)


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
    return _openclaw_provider().infer_unlocked(
        prompt_package,
        args,
        settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        validate=validate_isolated_openclaw_route,
        resolve_executable=lambda configured: resolve_cli_harness(
            configured,
            setting_key="openclaw_path",
            basename="openclaw",
            label="OpenClaw",
        ),
        build_payload=cli_analysis_payload,
        atomic_write_json=atomic_write_json,
        run_command=run_bounded_command,
        sanitized_env=sanitized_cli_harness_env,
        process_error=BoundedProcessError,
        summarize_failure=summarize_cli_harness_failure,
        extract_json=extract_json_object,
        max_prompt_bytes=OPENCLAW_MAX_PROMPT_ARGUMENT_BYTES,
        max_stderr_bytes=DEFAULT_CLOUD_MAX_STDERR_BYTES,
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
    return _openclaw_provider().locked_chat(
        prompt_package,
        args,
        settings,
        model=model,
        reasoning_effort=reasoning_effort,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        boolean_setting=boolean_setting,
        model_pattern=CLI_HARNESS_MODEL_PATTERN,
        reasoning_efforts=CODEX_CLI_REASONING_EFFORTS,
        validate=validate_isolated_openclaw_route,
        lock_path=DEFAULT_OLLAMA_INFERENCE_LOCK,
        flock=fcntl.flock,
        lock_exclusive=fcntl.LOCK_EX,
        lock_unlock=fcntl.LOCK_UN,
        infer=_openclaw_infer_unlocked,
        unload=_unload_ollama_model,
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
    return _provider_registry().dispatch(
        route,
        prompt_package,
        args,
        settings,
        system_prompt_file=system_prompt_file,
        independent_review=independent_review,
        enabled_routes=enabled_agent_model_routes,
        canonicalize=canonical_model_route,
        is_hosted=model_route_is_hosted,
        synchronize_hosted=synchronize_hosted_investigation_contract,
        parse_codex=parse_codex_cli_route,
        parse_harness=parse_cli_harness_route,
        codex_adapter=cloud_cli_chat,
        hermes_adapter=hermes_agent_chat,
        openclaw_adapter=openclaw_infer_chat,
        ollama_adapter=_ollama_chat_for_model,
        attest=attest_model_route_response,
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
    return _review_contracts().validation_failure(
        attempt=attempt, call_id=call_id, error=error, input_value=input_value,
        response=response, schema=REVIEW_VALIDATION_FAILURE_SCHEMA,
        message_max=REVIEW_VALIDATION_MESSAGE_MAX, digest_json=harness_digest_json,
    )


def reviewer_repair_guidance(validation_message: str) -> list[str]:
    """Translate validator output into bounded field-specific repair steps."""
    return _review_contracts().repair_guidance(
        validation_message, message_max=REVIEW_VALIDATION_MESSAGE_MAX,
    )


def reviewer_repair_error_category(validation_message: str) -> str:
    """Classify a validator failure without echoing rejected observables."""
    return _review_contracts().repair_error_category(
        validation_message, message_max=REVIEW_VALIDATION_MESSAGE_MAX,
    )



class ControlledEvaluationReviewerGateError(RuntimeError):
    """A controlled evaluation cannot commit without its reviewer decision."""


def reviewer_case_id(prompt_package: dict[str, Any]) -> str:
    return _review_contracts().case_id(
        prompt_package, bounded_reference=_bounded_reference,
        model_safe_copy=model_safe_copy,
    )


def reviewer_evidence_hash(review_package: dict[str, Any]) -> str:
    """Bind the reviewer response to its blind model-visible package."""
    return _review_contracts().evidence_hash(
        review_package, model_safe_copy=model_safe_copy,
    )


def independent_reviewer_package(
    prompt_package: dict[str, Any],
    *, hosted: bool = False,
) -> dict[str, Any]:
    """Build the exact route-safe blind evidence view sent to the reviewer."""
    return _review_package().build(
        prompt_package, hosted=hosted,
        max_queries=MAX_INVESTIGATION_QUERIES_PER_ROUND,
        model_safe_copy=model_safe_copy,
        attach_evidence_contract=attach_evidence_reference_contract,
        case_id=reviewer_case_id, observable_catalog=reviewer_observable_catalog,
        taxonomy_catalog=reviewer_non_domain_taxonomy_catalog,
        artifact_catalog=reviewer_non_domain_artifact_catalog,
        rule_shorthand_catalog=reviewer_non_domain_rule_shorthand_catalog,
        evidence_hash=reviewer_evidence_hash,
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
    module = _review_validation()
    dependencies = module.Dependencies(
        error_type=ReviewerValidationError,
        evidence_hash=reviewer_evidence_hash,
        taxonomy_catalog=reviewer_non_domain_taxonomy_catalog,
        artifact_catalog=reviewer_non_domain_artifact_catalog,
        rule_shorthand_catalog=reviewer_non_domain_rule_shorthand_catalog,
        bounded_reference=_bounded_reference,
        response_strings=_response_strings,
        repetition_reasons=_review_repetition_reasons,
        ipv4_re=REVIEW_IPV4_RE,
        domain_re=REVIEW_DOMAIN_RE,
        community_id_re=REVIEW_COMMUNITY_ID_RE,
        known_field_paths=REVIEW_KNOWN_FIELD_PATHS,
        non_domain_suffixes=REVIEW_NON_DOMAIN_SUFFIXES,
        required_keys=frozenset(REQUIRED_KEYS).union(STRICT_FACTORED_REQUIRED_KEYS),
        observable_max=REVIEW_OBSERVABLE_MAX,
        evidence_used_max=REVIEW_EVIDENCE_USED_MAX,
        hypotheses_max=REVIEW_HYPOTHESES_MAX,
    )
    return module.validate(response, review_package, dependencies)


def reviewer_supplemental_pivot_reason(
    reviewer_response: dict[str, Any],
) -> str:
    return _review_supplemental().pivot_reason(reviewer_response)


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
    return _review_supplemental().execute(
        prompt_package, reviewer_response, args, settings, agent_role, route,
        reviewer_prompt, live_osquery_config=live_osquery_config,
        enrichment_config=enrichment_config,
        security_onion_config_path=security_onion_config_path,
        investigation_pivot_dir=investigation_pivot_dir,
        harness_runtime=harness_runtime,
        deps=_review_supplemental_dependencies(),
    )


def second_opinion_trigger(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None = None,
) -> str:
    """Return the deterministic reason an independent review is warranted."""
    return _review_comparison().trigger(
        response, prompt_package,
        control_tuning_values=CONTROL_TUNING_VALUES,
        consequential_outcomes=CONSEQUENTIAL_CLOSURE_OUTCOMES,
    )


def compare_analysis_results(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
) -> dict[str, Any]:
    """Compare independent conclusions without model self-arbitration."""
    return _review_comparison().compare(
        primary_response, reviewer_response,
        control_tuning_values=CONTROL_TUNING_VALUES,
        non_escalatory_values=NON_ESCALATORY_HANDLING_VALUES,
        boolean_setting=boolean_setting,
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
    module = _review_adjudication()
    dependencies = module.PackageDependencies(
        independent_package=independent_reviewer_package,
        case_id=reviewer_case_id,
        model_safe_copy=model_safe_copy,
    )
    return module.build_package(
        prompt_package, primary_response, reviewer_response, comparison,
        hosted=hosted, deps=dependencies,
    )


def validate_disagreement_adjudication(
    response: Any,
    package: dict[str, Any],
) -> dict[str, Any]:
    """Validate identity, closed choices, disputed fields, and evidence citations."""
    module = _review_adjudication()
    dependencies = module.ValidationDependencies(
        error_type=DisagreementAdjudicationValidationError,
        bounded_reference=_bounded_reference,
    )
    return module.validate(response, package, dependencies)


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
    configured_route = str(
        (settings.get("agent_adjudicator_models") or {}).get(agent_role) or ""
    ).strip()
    frozen_reviewer_route = str(
        harness_runtime.envelope.assigned_reviewer_route
        if harness_runtime is not None
        else ""
    ).strip()
    # A harness run has an immutable two-route execution contract. Reuse its
    # already-authorized reviewer for bounded reconsideration instead of
    # silently invoking a third model that the run envelope cannot attest.
    route = frozen_reviewer_route or configured_route
    route_source = (
        "frozen_reviewer_route"
        if frozen_reviewer_route
        else "configured_adjudicator_route"
    )
    if not route:
        return {
            "status": "not_configured",
            "mode": "shadow",
            "automation_authorized": False,
            "error": "No independent disagreement adjudicator is configured.",
        }
    primary_identity = model_route_identity(
        (settings.get("agent_models") or {}).get(agent_role), settings
    )
    reviewer_identity = model_route_identity(
        (settings.get("agent_second_opinion_models") or {}).get(agent_role),
        settings,
    )
    route_identity = model_route_identity(route, settings)
    if route_identity == primary_identity or (
        route_identity == reviewer_identity and not frozen_reviewer_route
    ):
        return {
            "status": "not_independent",
            "mode": "shadow",
            "model_route": route,
            "automation_authorized": False,
            "error": (
                "The configured adjudicator resolves to a primary or reviewer "
                "provider/model identity."
            ),
        }
    notify_analysis_phase(
        phase_callback,
        "disagreement_adjudication",
        route,
        "Material primary/reviewer disagreement requires bounded adjudication.",
    )
    package = disagreement_adjudication_package(
        prompt_package,
        primary_response,
        reviewer_response,
        comparison,
        hosted=model_route_is_hosted(route, settings),
    )
    prompt_file = Path(
        getattr(
            args,
            "disagreement_adjudicator_prompt_file",
            DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT_FILE,
        )
    )
    started = time.monotonic()
    failures: list[dict[str, Any]] = []
    attempts = 0
    try:
        result: dict[str, Any] | None = None
        for attempt in range(1, 3):
            attempts = attempt
            call_id = f"disagreement-adjudication-{attempt}"
            if harness_runtime is not None:
                harness_runtime.preflight_model_call(
                    call_id=call_id,
                    input_value=package,
                    requested_route=route,
                    purpose="bounded disagreement adjudication",
                    independent_review=True,
                )
            call_started = time.monotonic()
            candidate = analyze_model_route(
                route,
                package,
                args,
                settings,
                system_prompt_file=prompt_file,
                independent_review=True,
            )
            try:
                result = validate_disagreement_adjudication(candidate, package)
                result = reconcile_supplied_endpoint_evidence_gaps(
                    result,
                    package,
                )
                if harness_runtime is not None:
                    harness_runtime.model_call(
                        call_id=call_id,
                        purpose="bounded disagreement adjudication",
                        requested_route=route,
                        response=candidate,
                        input_value=package,
                        duration_seconds=time.monotonic() - call_started,
                        independent_review=True,
                    )
                break
            except DisagreementAdjudicationValidationError as exc:
                if harness_runtime is not None:
                    harness_runtime.model_call(
                        call_id=call_id,
                        purpose="bounded disagreement adjudication",
                        requested_route=route,
                        response=candidate,
                        input_value=package,
                        duration_seconds=time.monotonic() - call_started,
                        independent_review=True,
                        status="validation-failed",
                    )
                failures.append({
                    "attempt": attempt,
                    "error": str(exc)[:2000],
                })
                if attempt >= 2:
                    raise
                package["adjudication_contract_repair"] = {
                    "attempt": 1,
                    "instruction": (
                        "Return one fresh complete object matching response_schema. "
                        "Use only exact contract field names and evidence refs."
                    ),
                    "validation_error": str(exc)[:1000],
                }
        if result is None:
            raise DisagreementAdjudicationValidationError(
                "adjudicator produced no validated response"
            )
        return {
            "status": "completed",
            "mode": "shadow",
            "model_route": route,
            "route_source": route_source,
            "system_prompt_file": str(prompt_file),
            "runtime_seconds": round(time.monotonic() - started, 3),
            "attempts": attempts,
            "validation_failures": failures,
            "response": result,
            "decision": result["decision"],
            "automation_authorized": False,
            "human_adjudication_required": True,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "mode": "shadow",
            "model_route": route,
            "route_source": route_source,
            "system_prompt_file": str(prompt_file),
            "runtime_seconds": round(time.monotonic() - started, 3),
            "attempts": attempts,
            "validation_failures": failures,
            "automation_authorized": False,
            "human_adjudication_required": True,
            "error": f"{type(exc).__name__}: {exc}"[:2000],
        }


def second_opinion_memory_eligibility(second_opinion: Any) -> tuple[bool, str]:
    return _review_authorization().memory_eligibility(second_opinion)


def reviewer_automation_authorization(
    primary_response: dict[str, Any],
    reviewer_response: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    return _review_authorization().automation_authorization(
        primary_response, reviewer_response, comparison,
        _review_authorization_dependencies(),
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
    return _memory_journal_persistence().plan(
        candidates, allowed=allowed, eligibility_reason=eligibility_reason,
        normalize_candidates=normalize_memory_candidates,
    )


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

    return _memory_journal_persistence().persist_postcommit(
        analysis_id=analysis_id, agent_role=agent_role,
        role_memory_file=role_memory_file, shared_memory_file=shared_memory_file,
        source_artifact=source_artifact, primary_candidates=primary_candidates,
        primary_allowed=primary_allowed, primary_reason=primary_reason,
        reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed, reviewer_reason=reviewer_reason,
        receipt_dir=receipt_dir, normalize_candidates=normalize_memory_candidates,
        canonical_digest=canonical_payload_digest,
        persist_candidates=persist_memory_candidates, safe_filename=safe_filename,
        atomic_write_private_json=atomic_write_private_json, now=project_now,
    )


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
    for key in list(primary_response):
        if str(key).startswith("_analysis_"):
            primary_response.pop(key, None)
    primary_response.pop("_second_opinion", None)
    primary_response.pop("_disagreement_adjudication", None)
    primary_response["_analysis_input_mode"] = SAVED_RESPONSE_INPUT_MODE
    trigger = second_opinion_trigger(primary_response, prompt_package)
    if not trigger:
        primary_response["final_disposition_status"] = "primary_not_reviewed"
        return primary_response

    reason = (
        "Saved-response mode did not execute the required independent reviewer: "
        f"{trigger}"
    )
    apply_review_required_gate(
        primary_response,
        status="review_required_failed",
        reason=reason,
    )
    primary_response["_second_opinion"] = {
        "status": "review_required_failed",
        "trigger": trigger,
        "model_route": "",
        "error": reason,
    }
    reconcile_incident_response_report(primary_response, prompt_package)
    return primary_response


def sanitize_saved_response_input(response: dict[str, Any]) -> dict[str, Any]:
    """Remove caller-supplied runtime attestations from an offline fixture."""
    return {
        key: value
        for key, value in response.items()
        if isinstance(key, str) and not key.startswith("_")
    }


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
    module = _review_workflow()
    return module.execute(
        module.Context(
            prompt_package=prompt_package,
            primary_response=primary_response,
            args=args,
            settings=settings,
            agent_role=agent_role,
            phase_callback=phase_callback,
            harness_runtime=harness_runtime,
            force_review_reason=force_review_reason,
            live_osquery_config=live_osquery_config,
            enrichment_config=enrichment_config,
            security_onion_config_path=security_onion_config_path,
            investigation_pivot_dir=investigation_pivot_dir,
            strict_harness_observation=bool(
                harness_runtime is not None
                and boolean_setting(
                    os.environ.get(EVALUATION_FREEZE_MEMORY_ENV)
                )
            ),
        ),
        module.Policy(
            default_prompt_file=DEFAULT_SECOND_OPINION_PROMPT_FILE,
        ),
        _review_workflow_dependencies(),
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
    second_opinion = (
        response.get("_second_opinion")
        if isinstance(response.get("_second_opinion"), dict)
        else None
    )
    reviewer_response = (
        second_opinion.get("response")
        if isinstance(second_opinion, dict)
        and isinstance(second_opinion.get("response"), dict)
        else None
    )
    if not freeze_enabled:
        return reviewer_response
    trigger = str(trigger_reason or "").strip()
    if not trigger:
        return reviewer_response

    reviewer_route = str(
        (settings.get("agent_second_opinion_models") or {}).get(agent_role)
        or ""
    ).strip()
    if not reviewer_route:
        return reviewer_response
    primary_route = str(
        (settings.get("agent_models") or {}).get(agent_role) or ""
    ).strip()
    if model_route_identity(primary_route, settings) == model_route_identity(
        reviewer_route,
        settings,
    ):
        return reviewer_response

    def reject(reason: str) -> NoReturn:
        raise ControlledEvaluationReviewerGateError(
            "controlled evaluation reviewer precommit gate failed: "
            f"{reason[:1000]}"
        )

    if second_opinion is None or reviewer_response is None:
        status = (
            str(second_opinion.get("status") or "missing")
            if isinstance(second_opinion, dict)
            else "missing"
        )
        error = (
            str(second_opinion.get("error") or "").strip()
            if isinstance(second_opinion, dict)
            else ""
        )
        reject(
            "the triggered independent reviewer produced no validated "
            f"response (status={status}{'; error=' + error if error else ''})"
        )

    status = str(second_opinion.get("status") or "").strip().lower()
    if status not in {"completed", "invalid"}:
        reject(f"reviewer response has non-recordable status {status or 'missing'}")
    attempts = second_opinion.get("attempts")
    failures = second_opinion.get("validation_failures")
    if (
        isinstance(attempts, bool)
        or attempts not in {1, 2}
        or not isinstance(failures, list)
        or len(failures) != attempts - 1
    ):
        reject("reviewer attempt history exceeds or violates the one-repair contract")

    review_package = independent_reviewer_package(
        prompt_package,
        hosted=model_route_is_hosted(reviewer_route, settings),
    )
    try:
        validated = validate_reviewer_response(
            reviewer_response,
            review_package,
        )
        validate_response(validated, review_package)
    except (ReviewerValidationError, SystemExit, TypeError, ValueError) as exc:
        reject(f"retained reviewer response is not recordable: {exc}")

    attestation = reviewer_response.get("_review_contract_validation")
    expected_contract = review_package["review_contract"]
    if (
        not isinstance(attestation, dict)
        or attestation.get("schema")
        != "onion-sentinel-independent-review-validation-v1"
        or attestation.get("valid") is not True
        or str(attestation.get("case_id") or "")
        != str(expected_contract.get("case_id") or "")
        or str(attestation.get("evidence_hash") or "")
        != str(expected_contract.get("evidence_hash") or "")
    ):
        reject("reviewer validation attestation is missing or does not bind this case")
    return reviewer_response


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
    if (
        isinstance(prompt_package.get("response_schema"), dict)
        or isinstance(prompt_package.get("alert"), dict)
        or isinstance(prompt_package.get("incident_response_evidence"), dict)
    ):
        attach_evidence_reference_contract(prompt_package)
    if agent_role not in CYBER_SECURITY_AGENT_ROLES:
        raise SystemExit(f"Unknown cyber-security agent role: {agent_role}")
    route = canonical_model_route((settings.get("agent_models") or {}).get(agent_role))
    if not route:
        raise SystemExit(f"Agent {agent_role} has no enabled analysis model assignment")
    notify_analysis_phase(phase_callback, "primary_analysis", route)
    evaluation_harness_run = bool(
        harness_runtime is not None
        and boolean_setting(os.environ.get(EVALUATION_FREEZE_MEMORY_ENV))
    )

    def observe_harness(call: Callable[[], Any]) -> Any:
        if harness_runtime is None:
            return None
        try:
            return call()
        except Exception as exc:
            if harness_runtime.policy.mode == "enforce" or evaluation_harness_run:
                raise
            print(
                "warning: Onion Sentinel harness shadow model observation "
                f"failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return None

    observe_harness(
        lambda: harness_runtime.preflight_model_call(
            call_id="primary-initial",
            input_value=prompt_package,
            requested_route=route,
            purpose="initial primary analysis",
        )
        if harness_runtime is not None
        else None
    )
    model_started = time.monotonic()
    try:
        primary = analyze_model_route(route, prompt_package, args, settings)
    except (Exception, SystemExit) as exc:
        observe_harness(
            lambda: harness_runtime.model_call(
                call_id="primary-initial",
                purpose="initial primary analysis",
                requested_route=route,
                response={},
                input_value=prompt_package,
                duration_seconds=time.monotonic() - model_started,
                status=f"failed:{type(exc).__name__}",
            )
            if harness_runtime is not None
            else None
        )
        raise
    observe_harness(
        lambda: harness_runtime.model_call(
            call_id="primary-initial",
            purpose="initial primary analysis",
            requested_route=route,
            response=primary,
            input_value=prompt_package,
            duration_seconds=time.monotonic() - model_started,
        )
        if harness_runtime is not None
        else None
    )
    if evaluation_harness_run and str(
        primary.get("_analysis_model_route") or ""
    ).strip() != route:
        raise InvestigationQueryError(
            "controlled harness evaluation initial response did not preserve "
            "the assigned model route"
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
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def normalize_correlation_assessment(value: Any) -> dict[str, Any]:
    assessment = value if isinstance(value, dict) else {}
    related_groups = []
    for item in (
        assessment.get("related_groups", [])[:20]
        if isinstance(assessment.get("related_groups"), list)
        else []
    ):
        if isinstance(item, str):
            group_id, reason = item, ""
        elif isinstance(item, dict):
            group_id, reason = item.get("group_id"), item.get("reason")
        else:
            continue
        group_id = str(group_id or "").strip().lower()[:64]
        if group_id:
            related_groups.append({"group_id": group_id, "reason": str(reason or "")[:1000]})
    confidence = str(assessment.get("confidence") or "low").lower()
    if confidence not in CONFIDENCE_VALUES:
        confidence = "low"
    unique_group_ids = sorted(
        {item["group_id"] for item in related_groups if item.get("group_id")}
    )
    episode_id = (
        "episode-"
        + hashlib.sha256(
            json.dumps(
                unique_group_ids,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:20]
        if unique_group_ids
        else ""
    )
    return {
        "correlation_found": bool(assessment.get("correlation_found")) and bool(related_groups),
        "confidence": confidence,
        "episode_id": episode_id,
        "episode_basis": [
            f"related_group:{group_id}" for group_id in unique_group_ids
        ],
        "related_groups": related_groups[:20],
        "shared_evidence": coerce_list(assessment.get("shared_evidence"))[:20],
        "contradicting_evidence": coerce_list(assessment.get("contradicting_evidence"))[:20],
        "attack_chain_hypothesis": str(assessment.get("attack_chain_hypothesis") or "")[:4000],
        "recommended_pivots": coerce_list(assessment.get("recommended_pivots"))[:20],
    }


def bounded_text(value: Any, limit: int = 8000) -> str:
    return str(value or "")[:limit]


def bounded_text_list(value: Any, limit: int = 50, item_limit: int = 4000) -> list[str]:
    return [bounded_text(item, item_limit) for item in coerce_list(value)[:limit]]


def normalize_hypotheses(value: Any) -> list[dict[str, Any]]:
    """Keep a bounded, structured hypothesis ledger instead of stringifying it."""
    if not isinstance(value, list):
        return []
    output: list[dict[str, Any]] = []
    for item in value[:20]:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unresolved").strip().lower()
        if status not in {"supported", "contradicted", "unresolved"}:
            status = "unresolved"
        identifier = re.sub(
            r"[^A-Za-z0-9._-]+",
            "-",
            str(item.get("id") or f"hypothesis-{len(output) + 1}"),
        ).strip("-")[:64]
        statement = bounded_text(item.get("statement"), 2000)
        if not identifier or not statement:
            continue
        output.append(
            {
                "id": identifier,
                "statement": statement,
                "status": status,
                "supporting_evidence": bounded_text_list(
                    item.get("supporting_evidence"),
                    limit=20,
                    item_limit=500,
                ),
                "contradicting_evidence": bounded_text_list(
                    item.get("contradicting_evidence"),
                    limit=20,
                    item_limit=500,
                ),
                "next_discriminator": bounded_text(
                    item.get("next_discriminator"),
                    1000,
                ),
            }
        )
    return output


def safe_nonnegative_int(value: Any) -> int:
    """Coerce untrusted collector/model metadata without breaking artifact writes."""
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def normalized_detection_outcome(value: Any) -> str:
    """Return the canonical legacy outcome code or ``inconclusive``."""
    return _conclusion_verdict().normalize_outcome(
        value, allowed=DETECTION_OUTCOME_VALUES,
    )


def legacy_verdict_factors(
    outcome: str,
    *,
    escalation_needed: bool = False,
) -> dict[str, Any]:
    """Map a legacy disposition into the orthogonal verdict dimensions."""
    return _conclusion_verdict().legacy_factors(
        outcome, escalation_needed=escalation_needed,
    )


def derive_legacy_detection_outcome(factors: dict[str, Any]) -> str:
    """Derive the compatibility outcome from normalized verdict dimensions."""
    return _conclusion_verdict().derive_outcome(factors)


def normalize_factored_verdict(response: dict[str, Any]) -> dict[str, Any]:
    """Normalize factored verdict fields and reconcile the legacy outcome."""
    return _conclusion_verdict().normalize(
        response,
        outcome_values=DETECTION_OUTCOME_VALUES,
        event_status_values=EVENT_STATUS_VALUES,
        validity_values=DETECTION_VALIDITY_VALUES,
        disposition_values=ACTIVITY_DISPOSITION_VALUES,
        handling_values=HANDLING_VALUES,
        factored_keys=FACTORED_VERDICT_KEYS,
        boolean_setting=boolean_setting,
    )


def normalize_scope_dispositions(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Keep the selected event distinct from broader grouped history."""
    raw = (
        response.get("scope_dispositions")
        if isinstance(response.get("scope_dispositions"), dict)
        else {}
    )
    raw_group = (
        raw.get("group_history")
        if isinstance(raw.get("group_history"), dict)
        else {}
    )
    grouped = (
        prompt_package.get("grouped_alert_context")
        if isinstance(prompt_package, dict)
        and isinstance(prompt_package.get("grouped_alert_context"), dict)
        else {}
    )
    try:
        observation_count = max(
            1,
            int(grouped.get("total_observations") or 1),
        )
    except (TypeError, ValueError, OverflowError):
        observation_count = 1

    group_disposition = re.sub(
        r"[^a-z0-9]+",
        "_",
        str(raw_group.get("activity_disposition") or "").lower(),
    ).strip("_")
    group_handling = re.sub(
        r"[^a-z0-9]+",
        "_",
        str(raw_group.get("handling") or "").lower(),
    ).strip("_")
    invalid_fields: list[str] = []
    if group_disposition not in ACTIVITY_DISPOSITION_VALUES:
        if group_disposition:
            invalid_fields.append(
                "scope_dispositions.group_history.activity_disposition"
            )
        group_disposition = (
            str(response.get("activity_disposition") or "unknown")
            if observation_count == 1
            else "unknown"
        )
    if group_handling not in HANDLING_VALUES:
        if group_handling:
            invalid_fields.append(
                "scope_dispositions.group_history.handling"
            )
        group_handling = (
            str(response.get("handling") or "investigate")
            if observation_count == 1
            else "monitor"
        )

    supplied_group = bool(raw_group)
    response["scope_dispositions"] = {
        "selected_event": {
            "activity_disposition": str(
                response.get("activity_disposition") or "unknown"
            ),
            "handling": str(response.get("handling") or "investigate"),
            "evidence_basis": bounded_text_list(
                (
                    raw.get("selected_event") or {}
                ).get("evidence_basis")
                if isinstance(raw.get("selected_event"), dict)
                else [],
                limit=20,
                item_limit=1000,
            ),
        },
        "group_history": {
            "activity_disposition": group_disposition,
            "handling": group_handling,
            "evidence_basis": bounded_text_list(
                raw_group.get("evidence_basis"),
                limit=20,
                item_limit=1000,
            ),
        },
    }
    response["_scope_disposition_validation"] = {
        "schema": "onion-sentinel-scope-disposition-v1",
        "selected_event_is_top_level_verdict": True,
        "group_observation_count": observation_count,
        "group_history_model_supplied": supplied_group,
        "group_history_defaulted_to_unresolved": bool(
            observation_count > 1 and not supplied_group
        ),
        "invalid_fields": invalid_fields,
    }
    return response


def _has_trusted_endpoint_evidence(prompt_package: dict[str, Any] | None) -> bool:
    """Return whether a collector supplied relevant, positive endpoint facts."""
    if not isinstance(prompt_package, dict):
        return False
    def completed_result(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        status = str(value.get("status") or "").strip().lower()
        rows = value.get("rows")
        return (
            status in {"complete", "completed", "ok", "success", "succeeded"}
            and isinstance(rows, list)
            and bool(rows)
        )

    def relevant_live_result(value: Any) -> bool:
        if not completed_result(value):
            return False
        digest = str(value.get("query_digest") or "").strip().lower()
        query = str(value.get("query") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not query:
            return False
        try:
            normalized_query = normalize_live_osquery_query(query)
        except LiveOsqueryContractError:
            return False
        if (
            hashlib.sha256(normalized_query.encode("utf-8")).hexdigest()
            != digest
        ):
            return False
        tables = {
            match.group(1).lower()
            for match in re.finditer(
                r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)",
                query,
                re.IGNORECASE,
            )
        }
        supports = value.get("support_bindings")
        if not isinstance(supports, list) or not supports:
            return False
        rows = value.get("rows")
        if not isinstance(rows, list):
            return False
        for support in supports:
            if (
                not isinstance(support, dict)
                or support.get("schema")
                != "onion-sentinel-live-osquery-support-v1"
                or support.get("query_digest") != digest
                or support.get("target_alias")
                != value.get("target_alias")
                or support.get("source")
                != "trusted-investigation-context"
                or support.get("temporal_scope")
                != "collection_snapshot"
                or support.get("table") not in tables
            ):
                continue
            row_index = support.get("row_index")
            column = str(support.get("column") or "")
            kind = str(support.get("observable_kind") or "")
            if (
                isinstance(row_index, bool)
                or not isinstance(row_index, int)
                or row_index < 0
                or row_index >= len(rows)
                or not isinstance(rows[row_index], dict)
                or column not in rows[row_index]
                or kind not in {"ip", "port", "host", "domain", "user"}
            ):
                continue
            row_value = str(rows[row_index][column] or "").strip().rstrip(".")
            if kind in {"host", "domain", "user"}:
                row_value = row_value.lower()
            plural = f"{kind}s"
            expected_support_digest = hashlib.sha256(
                f"{plural}\0{row_value}".encode("utf-8")
            ).hexdigest()
            if (
                support.get("observable_digest")
                == expected_support_digest
            ):
                return True
        return False

    def endpoint_collection_has_evidence(value: Any) -> bool:
        if isinstance(value, list):
            return any(endpoint_collection_has_evidence(item) for item in value)
        if not isinstance(value, dict):
            return False
        results = value.get("results")
        if isinstance(results, list) and any(
            completed_result(item) for item in results
        ):
            return True
        status = str(value.get("status") or "").strip().lower()
        if status not in {
            "complete",
            "completed",
            "ok",
            "success",
            "succeeded",
        }:
            return False
        for key in (
            "rows",
            "findings",
            "observations",
            "artifacts",
            "processes",
        ):
            items = value.get(key)
            if isinstance(items, list) and bool(items):
                return True
        return False

    live_osquery = prompt_package.get("_live_osquery_evidence_accumulator")
    if isinstance(live_osquery, dict):
        results = live_osquery.get("results")
        batches = live_osquery.get("batches")
        provenance_ok = (
            live_osquery.get("schema") == LIVE_OSQUERY_SCHEMA
            and live_osquery.get("read_only") is True
            and (
                isinstance(batches, list)
                and bool(batches)
                and all(
                    isinstance(item, dict)
                    and item.get("validated") is True
                    for item in batches
                )
            )
        )
        if (
            provenance_ok
            and live_osquery.get("complete") is True
            and isinstance(results, list)
            and any(relevant_live_result(item) for item in results)
        ):
            return True

    incident_evidence = prompt_package.get("incident_response_evidence")
    if isinstance(incident_evidence, dict):
        # Fixed ``osquery_results`` are local snapshots of the Security Onion
        # appliance. They cannot corroborate process, persistence, identity, or
        # compromise claims about the alert endpoint. Only explicitly separate
        # endpoint/host evidence collections may satisfy this guard.
        for key in ("endpoint_evidence", "host_evidence", "osquery_evidence"):
            evidence = incident_evidence.get(key)
            if endpoint_collection_has_evidence(evidence):
                return True

    for key in ("endpoint_evidence", "host_evidence", "osquery_evidence"):
        evidence = prompt_package.get(key)
        if endpoint_collection_has_evidence(evidence):
            return True
    return False


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
    if not isinstance(prompt_package, dict):
        return set()
    iterative = prompt_package.get("investigation_query_results")
    if not isinstance(iterative, dict):
        return set()
    rounds = iterative.get("rounds")
    if not isinstance(rounds, list):
        return set()

    supplied: set[str] = set()

    def record_source(source: Any) -> None:
        if not isinstance(source, dict):
            return
        process = source.get("process")
        if (
            isinstance(process, dict)
            and isinstance(process.get("executable"), str)
            and process["executable"].strip()
        ):
            supplied.add("process.executable")
        direct = source.get("process.executable")
        if isinstance(direct, str) and direct.strip():
            supplied.add("process.executable")

    for round_item in rounds:
        if not isinstance(round_item, dict):
            continue
        results = round_item.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            if result.get("read_only") is not True:
                continue
            if str(result.get("status") or "").strip().lower() not in (
                INVESTIGATION_QUERY_SUCCESS_STATUSES
            ):
                continue
            evidence = result.get("evidence")
            if (
                not isinstance(evidence, dict)
                or evidence.get("controls_valid") is False
                or evidence.get("partial") is True
                or evidence.get("complete") is False
            ):
                continue
            evidence_results = evidence.get("results")
            if not isinstance(evidence_results, list):
                continue
            for evidence_result in evidence_results:
                if not isinstance(evidence_result, dict):
                    continue
                if str(
                    evidence_result.get("status") or ""
                ).strip().lower() not in INVESTIGATION_QUERY_SUCCESS_STATUSES:
                    continue
                if (
                    evidence_result.get("semantic_valid") is False
                    or evidence_result.get("truncated") is True
                    or evidence_result.get("model_projection_truncated") is True
                    or evidence_result.get("hits_prompt_truncated") is True
                    or evidence_result.get("rows_prompt_truncated") is True
                ):
                    continue
                hits = evidence_result.get("hits")
                if isinstance(hits, list):
                    for hit in hits:
                        if not isinstance(hit, dict):
                            continue
                        source = hit.get("_source")
                        if not isinstance(source, dict):
                            source = hit.get("source")
                        if not isinstance(source, dict):
                            source = hit
                        record_source(source)
                rows = evidence_result.get("rows")
                if isinstance(rows, list):
                    for row in rows:
                        record_source(row)
    return supplied


def _remove_supplied_executable_path_gap(text: Any) -> tuple[str, bool]:
    """Remove only a false executable-path absence from one gap string."""
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    if not value:
        return "", False
    if not re.search(
        r"\b(?:process\.)?executable path(?:s)?\b",
        value,
        re.IGNORECASE,
    ):
        return value, False

    rewritten = re.sub(
        r"\b(?:process\.)?executable path(?:s)?\s*,\s*",
        "",
        value,
        count=1,
        flags=re.IGNORECASE,
    )
    if rewritten != value:
        rewritten = re.sub(r"\s+", " ", rewritten).strip()
        return rewritten, True

    # A standalone assertion that the path is absent is wholly contradicted
    # by the trusted row and has no remaining gap to preserve.
    absence_markers = (
        "missing",
        "absent",
        "unavailable",
        "not supplied",
        "not provided",
        "not present",
        "not available",
        "required",
        "needed",
        "obtain",
        "collect",
    )
    if any(marker in value.lower() for marker in absence_markers):
        return "", True
    return value, False


def reconcile_supplied_endpoint_evidence_gaps(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Prevent model-authored gap lists from denying supplied endpoint facts."""
    supplied = _trusted_endpoint_evidence_fields(prompt_package)
    if "process.executable" not in supplied:
        return response

    rewritten_count = 0
    removed_count = 0

    def reconcile_list(container: dict[str, Any], key: str) -> None:
        nonlocal rewritten_count, removed_count
        values = container.get(key)
        if not isinstance(values, list):
            return
        normalized: list[Any] = []
        for item in values:
            if not isinstance(item, str):
                normalized.append(item)
                continue
            rewritten, changed = _remove_supplied_executable_path_gap(item)
            if not changed:
                normalized.append(item)
            elif rewritten:
                normalized.append(rewritten)
                rewritten_count += 1
            else:
                removed_count += 1
        container[key] = normalized

    reconcile_list(response, "evidence_gaps")
    reconcile_list(response, "additional_evidence_needed")
    report = response.get("incident_response_report")
    if isinstance(report, dict):
        reconcile_list(report, "evidence_gaps")
        reconcile_list(report, "constraints")

    if rewritten_count or removed_count:
        response["_endpoint_evidence_gap_reconciliation"] = {
            "schema": "onion-sentinel-endpoint-evidence-gap-reconciliation-v1",
            "executable_path_supplied": True,
            "rewritten_gap_count": rewritten_count,
            "removed_gap_count": removed_count,
        }
    return response


def _consequential_model_conclusion(response: dict[str, Any]) -> bool:
    return _conclusion_evidence_guard().consequential(
        response, _evidence_guard_dependencies(),
    )


def apply_deterministic_evidence_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Reconcile model conclusions with collector-owned rule-intent evidence."""
    return _conclusion_evidence_guard().apply(
        response, prompt_package, _evidence_guard_dependencies(),
    )


def confidence_label_for_score(score: float) -> str:
    return _conclusion_confidence().label(
        score, low_threshold=CONFIDENCE_LOW_THRESHOLD,
        high_threshold=CONFIDENCE_HIGH_THRESHOLD,
    )


def calibrate_response_confidence(response: dict[str, Any]) -> dict[str, Any]:
    """Apply deterministic evidence caps to the model confidence claim."""
    return _conclusion_confidence().calibrate(
        response, confidence_values=CONFIDENCE_VALUES,
        score_by_label=CONFIDENCE_SCORE_BY_LABEL,
        calibration_version=CONFIDENCE_CALIBRATION_VERSION,
        critical_keys=DECISION_CRITICAL_KEYS,
        consequential_outcomes=CONSEQUENTIAL_CLOSURE_OUTCOMES,
        outcome_normalizer=normalized_detection_outcome,
        label_for_score=confidence_label_for_score,
    )


def _is_incident_responder_package(prompt_package: dict[str, Any] | None) -> bool:
    if not isinstance(prompt_package, dict):
        return False
    role = str(prompt_package.get("agent_role") or "").strip().lower().replace("_", "-")
    return role == "incident-responder"


def _canonical_authorization_timestamp(value: Any) -> dt.datetime | None:
    return _conclusion_authorization_evidence().canonical_timestamp(value)


def _prompt_authorization_event_tuple(
    prompt_package: dict[str, Any],
) -> dict[str, Any] | None:
    return _conclusion_authorization_evidence().prompt_event(prompt_package)


def _canonical_authorization_coverage(value: Any) -> dict[str, Any] | None:
    return _conclusion_authorization_evidence().canonical_coverage(value)


def _canonical_authorization_entry_covers_event(
    entry: Any, event: dict[str, Any],
) -> bool:
    return _conclusion_authorization_evidence().entry_covers_event(entry, event)


def _has_structured_authorization_evidence(
    prompt_package: dict[str, Any] | None,
) -> bool:
    return _conclusion_authorization_evidence().has_structured_evidence(
        prompt_package
    )


def _tuning_material_evidence_gap_signals(
    response: dict[str, Any],
) -> list[str]:
    return _conclusion_tuning().material_evidence_gap_signals(
        response, _tuning_guard_dependencies(),
    )


def _unresolved_reviewer_material_disagreement(
    response: dict[str, Any],
) -> bool:
    return _conclusion_tuning().unresolved_reviewer_material_disagreement(response)


def apply_tuning_coherence_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Keep suppress/drop evidence-complete, advisory, and human-controlled."""
    return _conclusion_tuning().apply(
        response, prompt_package, _tuning_guard_dependencies(),
    )


def apply_authorized_benign_evidence_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Remove unsupported authorization and no-action claims from IR cases."""
    return _conclusion_authorization().apply_authorized_benign(
        response, prompt_package, _authorization_guard_dependencies(),
    )


def apply_policy_sensitive_activity_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Keep unattributed policy-sensitive application detections unresolved."""
    return _conclusion_authorization().apply_policy_sensitive(
        response, prompt_package, _authorization_guard_dependencies(),
    )


def _incident_timeline_timestamp(value: Any) -> dt.datetime | None:
    return _conclusion_incident_report().timeline_timestamp(value)


def validate_incident_response_report_shape(value: Any) -> dict[str, Any]:
    return _conclusion_incident_report().validate_shape(
        value, _incident_report_dependencies(),
    )


def normalize_incident_response_report(value: Any) -> dict[str, Any]:
    return _conclusion_incident_report().normalize(
        value, _incident_report_dependencies(),
    )


def apply_incident_evidence_completeness_guard(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    """Cap confidence when required Incident Responder evidence is incomplete."""
    return _conclusion_incident_completeness().apply(
        response, prompt_package, _incident_completeness_dependencies(),
    )


def _canonical_incident_disposition_sentence(response: dict[str, Any]) -> str:
    return _conclusion_incident_report().canonical_disposition(
        response, _incident_report_dependencies(),
    )


def _human_review_incident_actions(response: dict[str, Any]) -> dict[str, list[str]]:
    return _conclusion_incident_report().human_review_actions(response)


def _incident_report_requests_containment(report: dict[str, Any]) -> bool:
    return _conclusion_incident_report().requests_containment(
        report, _incident_report_dependencies(),
    )


def reconcile_incident_response_report(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    return _conclusion_incident_report().reconcile(
        response, prompt_package, _incident_report_dependencies(),
    )


def incident_query_audit(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Extract immutable Security Onion query provenance without event bodies.

    This runs after model inference. Consequently neither the primary nor the
    second-opinion model can claim that an invented query executed. The exact
    Query DSL and the wrapper-produced KQL equivalent are copied from the
    restricted collection artifact; hit documents remain in that artifact.
    """
    evidence = prompt_package.get("incident_response_evidence")
    response = evidence.get("security_onion_response") if isinstance(evidence, dict) else None
    if not isinstance(response, dict):
        return {
            "trusted_source": "restricted-security-onion-wrapper",
            "complete": False,
            "partial": True,
            "read_only": True,
            "queries": [],
            "error": "Restricted Security Onion query evidence was unavailable.",
        }

    queries: list[dict[str, Any]] = []
    results = response.get("results") if isinstance(response.get("results"), list) else []
    for result in results[:100]:
        if not isinstance(result, dict):
            continue
        query_dsl = result.get("query_dsl") if isinstance(result.get("query_dsl"), dict) else {}
        window = result.get("window") if isinstance(result.get("window"), dict) else {}
        projection = (
            result.get("prompt_projection")
            if isinstance(result.get("prompt_projection"), dict)
            else {}
        )
        queries.append({
            "pack": bounded_text(result.get("pack"), 100),
            "status": bounded_text(result.get("status"), 40),
            "query_digest": bounded_text(result.get("query_digest"), 128),
            "kql_equivalent": bounded_text(result.get("kql_equivalent"), 12000),
            "query_dsl": query_dsl,
            "window_index": result.get("window_index"),
            "window": {
                "start": bounded_text(window.get("start"), 100),
                "end": bounded_text(window.get("end"), 100),
            },
            "total_hits": safe_nonnegative_int(result.get("total_hits")),
            "returned_hits": safe_nonnegative_int(result.get("returned_hits")),
            "source_returned_hits": safe_nonnegative_int(
                projection.get("source_returned_hits", result.get("returned_hits"))
            ),
            "prompt_projection_applied": bool(projection),
            "truncated": bool(result.get("truncated")),
            "duration_ms": safe_nonnegative_int(result.get("duration_ms")),
            "error": bounded_text(result.get("error"), 1000),
        })
    return {
        "trusted_source": "restricted-security-onion-wrapper",
        "generated_at": bounded_text(evidence.get("generated_at") if isinstance(evidence, dict) else "", 100),
        "complete": bool(response.get("complete")),
        "partial": bool(response.get("partial")),
        "read_only": bool(response.get("read_only", True)),
        "query_contract": bounded_text(response.get("query_contract"), 200),
        "queries": queries,
    }


def incident_osquery_audit(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Copy trusted Security Onion appliance OSQuery snapshot provenance.

    The LLM can reason over validated rows but cannot author this audit trail.
    Every SQL statement is an exact reviewed pack from the Security Onion
    wrapper, and bounded row previews make host evidence inspectable without
    turning the Incident Response report into an unbounded telemetry export.
    """
    evidence = prompt_package.get("incident_response_evidence")
    response = evidence.get("security_onion_response") if isinstance(evidence, dict) else None
    if not isinstance(response, dict):
        return {
            "trusted_source": "restricted-security-onion-osquery-wrapper",
            "read_only": True,
            "queries": [],
            "error": "Restricted live OSquery evidence was unavailable.",
        }

    queries: list[dict[str, Any]] = []
    results = response.get("osquery_results")
    if not isinstance(results, list):
        results = []
    for result in results[:32]:
        if not isinstance(result, dict):
            continue
        rows: list[dict[str, str]] = []
        raw_rows = result.get("rows") if isinstance(result.get("rows"), list) else []
        for raw_row in raw_rows[:25]:
            if not isinstance(raw_row, dict):
                continue
            rows.append({
                bounded_text(key, 128): bounded_text(value, 2000)
                for key, value in list(raw_row.items())[:64]
            })
        queries.append({
            "pack": bounded_text(result.get("pack"), 100),
            "target": bounded_text(result.get("target"), 100),
            "status": bounded_text(result.get("status"), 40),
            "query_digest": bounded_text(result.get("query_digest"), 128),
            "query": bounded_text(result.get("query"), 16000),
            "total_rows": safe_nonnegative_int(result.get("total_rows")),
            "returned_rows": safe_nonnegative_int(result.get("returned_rows")),
            "truncated": bool(result.get("truncated")),
            "duration_ms": safe_nonnegative_int(result.get("duration_ms")),
            "rows_preview": rows,
            "error": bounded_text(result.get("error"), 1000),
        })
    return {
        "trusted_source": "restricted-security-onion-appliance-osquery-wrapper",
        "generated_at": bounded_text(
            evidence.get("generated_at") if isinstance(evidence, dict) else "", 100
        ),
        "read_only": bool(response.get("read_only", True)),
        "query_contract": bounded_text(response.get("query_contract"), 200),
        "queries": queries,
    }


def incident_live_osquery_audit(prompt_package: dict[str, Any]) -> dict[str, Any]:
    """Copy endpoint live-query provenance from the validated collector artifact."""
    evidence = prompt_package.get("_live_osquery_evidence_accumulator")
    if not isinstance(evidence, dict):
        evidence = prompt_package.get("live_osquery_evidence")
    if not isinstance(evidence, dict):
        return {
            "trusted_source": "restricted-elastic-osquery-manager-wrapper",
            "complete": False,
            "read_only": True,
            "queries": [],
            "error": "No endpoint live-host OSQuery batch was requested.",
        }
    queries: list[dict[str, Any]] = []
    preview_rows_remaining = 100
    preview_bytes_remaining = 256 * 1024
    preview_truncated = False
    for result in evidence.get("results", []) if isinstance(evidence.get("results"), list) else []:
        if not isinstance(result, dict):
            continue
        rows: list[dict[str, str]] = []
        source_rows = (
            result.get("rows")
            if isinstance(result.get("rows"), list)
            else []
        )
        query_preview_truncated = False
        for raw_row in source_rows:
            if not isinstance(raw_row, dict):
                continue
            bounded_row = {
                bounded_text(key, 128): bounded_text(value, 2000)
                for key, value in list(raw_row.items())[:64]
            }
            row_bytes = len(
                json.dumps(
                    bounded_row,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            if (
                len(rows) >= 25
                or preview_rows_remaining <= 0
                or row_bytes > preview_bytes_remaining
            ):
                query_preview_truncated = True
                preview_truncated = True
                break
            rows.append(bounded_row)
            preview_rows_remaining -= 1
            preview_bytes_remaining -= row_bytes
        if len(rows) < len(source_rows):
            query_preview_truncated = True
            preview_truncated = True
        support_bindings = (
            result.get("support_bindings")
            if isinstance(result.get("support_bindings"), list)
            else []
        )
        queries.append({
            "target_alias": bounded_text(result.get("target_alias"), 64),
            "status": bounded_text(result.get("status"), 40),
            "purpose": bounded_text(result.get("purpose"), 500),
            "query_digest": bounded_text(result.get("query_digest"), 128),
            "query": bounded_text(result.get("query"), 4096),
            "total_rows": safe_nonnegative_int(result.get("total_rows")),
            "returned_rows": len(
                result.get("rows")
                if isinstance(result.get("rows"), list)
                else []
            ),
            "truncated": bool(result.get("truncated")),
            "duration_ms": safe_nonnegative_int(result.get("duration_ms")),
            "rows_preview": rows,
            "rows_preview_truncated": query_preview_truncated,
            "support_binding_count": len(
                [
                    item
                    for item in support_bindings
                    if isinstance(item, dict)
                    and item.get("schema")
                    == "onion-sentinel-live-osquery-support-v1"
                ]
            ),
            "error": bounded_text(result.get("error"), 1000),
        })
    batches = (
        evidence.get("batches")
        if isinstance(evidence.get("batches"), list)
        else []
    )
    return {
        "trusted_source": "restricted-elastic-osquery-manager-wrapper",
        "generated_at": bounded_text(evidence.get("generated_at"), 100),
        "complete": bool(evidence.get("complete")),
        "read_only": bool(evidence.get("read_only", True)),
        "query_contract": bounded_text(evidence.get("schema"), 200),
        "endpoint_read_only": bool(evidence.get("read_only", True)),
        "control_plane_writes": bool(
            evidence.get("control_plane_writes", True)
        ),
        "control_plane_write_status": bounded_text(
            evidence.get("control_plane_write_status")
            or (
                "confirmed"
                if evidence.get("control_plane_writes", True)
                else "none"
            ),
            20,
        ),
        "batches": len(batches),
        "validated_batches": sum(
            1
            for item in batches
            if isinstance(item, dict) and item.get("validated") is True
        ),
        "failed_batches": sum(
            1
            for item in batches
            if isinstance(item, dict) and item.get("validated") is not True
        ),
        "preview_truncated": preview_truncated,
        "queries": queries,
        "error": bounded_text(evidence.get("collection_error"), 1000),
    }


def prepare_live_osquery_context(
    prompt_package: dict[str, Any],
    agent_role: str,
    config_path: Path = DEFAULT_LIVE_OSQUERY_CONFIG_FILE,
) -> dict[str, Any] | None:
    """Expose a model-safe capability descriptor without exposing transport secrets."""
    if agent_role not in {"soc-analyst", "incident-responder"}:
        return None
    config_path = config_path.expanduser()
    if config_path.is_file():
        config = load_live_osquery_config(config_path)
    else:
        config = {
            "enabled": False,
            "allowed_target_aliases": [],
            "allowed_agent_roles": ["incident-responder"],
        }
    allowed_roles = config.get("allowed_agent_roles")
    if not isinstance(allowed_roles, list):
        allowed_roles = ["incident-responder"]
    if agent_role not in allowed_roles:
        config = {
            **config,
            "enabled": False,
            "allowed_target_aliases": [],
        }
    descriptor = live_osquery_capability_descriptor(config)
    prompt_package["live_osquery_capability"] = descriptor
    capability = prompt_package.get("investigation_query_capability")
    if isinstance(capability, dict):
        if descriptor.get("enabled") is True:
            capability["enabled"] = True
        backends = capability.get("backends")
        if isinstance(backends, dict):
            backends["osquery"] = {
                "enabled": bool(descriptor.get("enabled")),
                "target_aliases": list(descriptor.get("target_aliases") or []),
                "allowed_tables": list(descriptor.get("allowed_tables") or []),
                "target_platform": descriptor.get("target_platform") or "",
                "osquery_version": descriptor.get("osquery_version") or "",
                "table_schemas": dict(descriptor.get("table_schemas") or {}),
                "max_queries": descriptor.get("max_queries"),
                "max_rows_per_query": descriptor.get("max_rows_per_query"),
                "restrictions": list(descriptor.get("restrictions") or []),
            }
    return config


def live_osquery_case_id(prompt_package: dict[str, Any]) -> str:
    """Derive a non-sensitive stable case token for cross-node audit correlation."""
    analyst_state = prompt_package.get("analyst_state")
    alert = prompt_package.get("alert")
    raw = ""
    if isinstance(analyst_state, dict):
        raw = str(analyst_state.get("group_id") or "")
    if not raw and isinstance(alert, dict):
        raw = str(alert.get("alert_id") or alert.get("rule_name") or "")
    return "ir-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def apply_live_osquery_follow_up(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    args: argparse.Namespace,
    settings: dict[str, Any],
    config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Execute at most one validated live-host batch, then rerun the same model.

    The model proposes SELECT queries against opaque endpoint aliases. The
    collector owns validation, transport, target resolution, and provenance.
    A collection failure is supplied to the final reasoning pass as an explicit
    evidence gap instead of silently discarding the Incident Response run.
    """
    requests = primary_response.pop("live_osquery_requests", [])
    if not requests:
        return primary_response
    case_id = live_osquery_case_id(prompt_package)
    collection_error = ""
    try:
        if not config or not config.get("enabled"):
            raise LiveOsqueryClientError("live-host OSQuery is not enabled for this deployment")
        evidence = collect_live_osquery(
            case_id=case_id,
            requests=requests,
            config=config,
            persist=True,
        )
    except (LiveOsqueryClientError, LiveOsqueryContractError, OSError) as exc:
        collection_error = str(exc)[:1000]
        evidence = {
            "schema": LIVE_OSQUERY_SCHEMA,
            "case_id": case_id,
            "generated_at": project_now(),
            "complete": False,
            "read_only": True,
            "results": [],
            "collection_error": collection_error,
        }
    prompt_package["live_osquery_evidence"] = evidence
    prompt_package["live_osquery_follow_up"] = {
        "final_pass": True,
        "instruction": (
            "Use the collected endpoint evidence and return the final report. "
            "Do not request another live OSQuery batch."
        ),
    }
    route = canonical_model_route(
        (settings.get("agent_models") or {}).get("incident-responder")
    )
    final_response = analyze_model_route(route, prompt_package, args, settings)
    repeated = final_response.pop("live_osquery_requests", [])
    final_response["_live_osquery_follow_up"] = {
        "requested": len(requests) if isinstance(requests, list) else 0,
        "collected": len(evidence.get("results") or []),
        "complete": bool(evidence.get("complete")),
        "collection_error": collection_error,
        "repeated_requests_ignored": len(repeated) if isinstance(repeated, list) else 0,
    }
    return final_response


def validate_response(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize a model response without letting minor schema drift jam the queue.

    Local models occasionally omit a low-risk field such as tuning_reason. The
    dashboard still needs an artifact for every unique alert, so use explicit
    defaults for missing fields and preserve the model output that was present.
    """
    normalized = dict(response)
    # Query requests are an intermediate local-tool protocol, never part of a
    # completed analysis artifact or a hosted second-opinion payload.
    normalized.pop("investigation_query_requests", None)
    normalized.pop("pcap_query_requests", None)
    normalized.pop("live_osquery_requests", None)
    strict_factored_contract = bool(
        isinstance(prompt_package, dict)
        and (
            isinstance(prompt_package.get("review_contract"), dict)
            or _is_incident_responder_package(prompt_package)
            or (
                isinstance(prompt_package.get("response_schema"), dict)
                and STRICT_FACTORED_REQUIRED_KEYS.issubset(
                    prompt_package["response_schema"]
                )
            )
        )
    )
    required_keys = set(REQUIRED_KEYS)
    if strict_factored_contract:
        required_keys.update(STRICT_FACTORED_REQUIRED_KEYS)
    missing = sorted(required_keys.difference(normalized))
    for key in missing:
        normalized[key] = DEFAULT_RESPONSE_VALUES.get(
            key,
            STRICT_RESPONSE_VALUES.get(key, "n/a"),
        )
    if missing:
        normalized["_schema_repair"] = {
            "missing_keys": missing,
            "repair_note": "Filled safe defaults so the alert still receives local AI analysis.",
        }
    for key in LIST_KEYS:
        normalized[key] = coerce_list(normalized.get(key))
    normalized["detection_outcome"] = str(normalized["detection_outcome"])
    normalized["bluf"] = str(normalized["bluf"])
    normalized["summary"] = str(normalized["summary"])
    normalized["likely_meaning"] = str(normalized["likely_meaning"])
    normalized["severity_reasoning"] = str(normalized["severity_reasoning"])
    normalized["alert_frequency_assessment"] = str(normalized["alert_frequency_assessment"])
    normalized["tuning_reason"] = str(normalized["tuning_reason"])
    normalized["confidence"] = str(normalized["confidence"]).lower()
    normalized["tuning_recommendation"] = str(normalized["tuning_recommendation"]).lower()
    normalized["escalation_needed"] = boolean_setting(normalized["escalation_needed"])
    normalized["hosted_second_opinion_recommended"] = boolean_setting(
        normalized["hosted_second_opinion_recommended"]
    )
    normalized["second_opinion_recommended"] = boolean_setting(
        normalized.get("second_opinion_recommended", False)
    )
    normalized["second_opinion_reason"] = str(normalized.get("second_opinion_reason") or "")[:1000]
    normalized["correlation_assessment"] = normalize_correlation_assessment(normalized.get("correlation_assessment"))
    normalized["memory_candidates"] = normalize_memory_candidates(normalized.get("memory_candidates"))
    if strict_factored_contract or "hypotheses" in normalized:
        normalized["hypotheses"] = normalize_hypotheses(
            normalized.get("hypotheses")
        )
    incident_responder = _is_incident_responder_package(prompt_package)
    if incident_responder:
        raw_report = normalized.get("incident_response_report")
        report_validation = validate_incident_response_report_shape(raw_report)
        normalized["incident_response_report"] = normalize_incident_response_report(
            raw_report
        )
        normalized["_incident_response_report_validation"] = report_validation
        if not report_validation["valid"]:
            repair = (
                dict(normalized.get("_schema_repair"))
                if isinstance(normalized.get("_schema_repair"), dict)
                else {}
            )
            repaired_keys = {
                str(item)
                for item in repair.get("missing_keys", [])
                if isinstance(repair.get("missing_keys"), list)
            }
            repaired_keys.update(
                f"incident_response_report.{key}"
                for key in report_validation["missing_fields"]
            )
            if not report_validation["model_report_present"]:
                repaired_keys.add("incident_response_report")
            repair["missing_keys"] = sorted(repaired_keys)
            repair["repair_note"] = (
                "Filled safe defaults and marked the Incident Responder output "
                "for human review because its required report was incomplete."
            )
            normalized["_schema_repair"] = repair
    elif "incident_response_report" in normalized:
        normalized["incident_response_report"] = normalize_incident_response_report(
            normalized.get("incident_response_report")
        )
        # Preserve the legacy SOC analyst projection. Nested numeric
        # confidence is an Incident Responder contract and must not silently
        # expand unsolicited SOC output.
        normalized["incident_response_report"].pop("confidence_score", None)

    if normalized["confidence"] not in CONFIDENCE_VALUES:
        normalized["_invalid_confidence"] = normalized["confidence"]
        normalized["confidence"] = "low"
    if normalized["tuning_recommendation"] not in TUNING_VALUES:
        normalized["_invalid_tuning_recommendation"] = normalized["tuning_recommendation"]
        normalized["tuning_recommendation"] = "needs_more_data"
    raw_outcome_key = re.sub(
        r"[^a-z0-9]+",
        "_",
        normalized["detection_outcome"].strip().lower(),
    ).strip("_")
    if (
        raw_outcome_key not in DETECTION_OUTCOME_VALUES
        and raw_outcome_key
        not in {
            "true_positive_benign",
            "authorized_benign",
            "false_positive_rule_logic",
            "false_positive_parser",
            "false_positive_intel",
        }
    ):
        normalized["_invalid_detection_outcome"] = normalized["detection_outcome"]
    normalized = normalize_factored_verdict(normalized)
    normalized = apply_deterministic_evidence_guard(
        normalized,
        prompt_package,
    )
    normalized = apply_authorized_benign_evidence_guard(
        normalized,
        prompt_package,
    )
    normalized = apply_policy_sensitive_activity_guard(
        normalized,
        prompt_package,
    )
    normalized = apply_incident_evidence_completeness_guard(
        normalized,
        prompt_package,
    )
    normalized = reconcile_supplied_endpoint_evidence_gaps(
        normalized,
        prompt_package,
    )
    normalized = validate_evidence_references(normalized, prompt_package)
    normalized = apply_tuning_coherence_guard(
        normalized,
        prompt_package,
    )
    normalized = normalize_scope_dispositions(
        normalized,
        prompt_package,
    )
    normalized = calibrate_response_confidence(normalized)
    normalized = reconcile_incident_response_report(
        normalized,
        prompt_package,
    )
    normalized.setdefault("final_disposition_status", "primary_unreviewed")
    return normalized


def markdown_list(items: list[str]) -> str:
    return _reporting_incident().markdown_list(items)


def render_incident_response_markdown(response: dict[str, Any]) -> list[str]:
    return _reporting_incident().render_incident_response(
        response,
        bounded_text_list=bounded_text_list,
    )


def render_incident_query_audit_markdown(response: dict[str, Any]) -> list[str]:
    return _reporting_incident().render_security_onion_query_audit(response)


def render_incident_osquery_audit_markdown(response: dict[str, Any]) -> list[str]:
    return _reporting_incident().render_appliance_osquery_audit(response)


def render_incident_live_osquery_audit_markdown(response: dict[str, Any]) -> list[str]:
    return _reporting_incident().render_live_osquery_audit(response)


def render_markdown(
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    generated_at: str,
    json_path: Path,
) -> str:
    return _reporting_markdown().render(
        prompt_package,
        response,
        generated_at,
        json_path,
        normalize_correlation=normalize_correlation_assessment,
        safe_filename=safe_filename,
        bounded_text_list=bounded_text_list,
    )


def write_outputs(
    prompt_path: Path,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    args: argparse.Namespace,
    analysis_id: str,
) -> tuple[Path, Path, str]:
    generated_at = project_now()
    plan = _reporting_publication().build_plan(
        prompt_path,
        prompt_package,
        response,
        args,
        analysis_id,
        generated_at=generated_at,
        safe_filename=safe_filename,
        filename_timestamp=filename_timestamp,
        render_markdown=render_markdown,
        saved_response_input_mode=SAVED_RESPONSE_INPUT_MODE,
        default_second_opinion_prompt_file=DEFAULT_SECOND_OPINION_PROMPT_FILE,
    )
    return _reporting_publication().publish(plan)


def _bootstrap_pipeline(module: Any, pipeline_module: Any, args: argparse.Namespace) -> Any:
    return module.bootstrap(
        args, environment=os.environ,
        policy=module.BootstrapPolicy(
            freeze_memory_env=EVALUATION_FREEZE_MEMORY_ENV,
            path_defaults=pipeline_module.RuntimePathDefaults(
                log_dir=DEFAULT_LLM_LOG_DIR,
                index_queue_dir=DEFAULT_ANALYSIS_INDEX_QUEUE_DIR,
                index_quarantine_dir=DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR,
                memory_receipt_dir=DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
                memory_pending_dir=DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
                memory_committed_dir=DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR)),
        ports=module.BootstrapPorts(
            controlled_runtime=controlled_evaluation_runtime,
            controlled_output_dir=controlled_evaluation_output_dir,
            consume_token=consume_controlled_evaluation_token,
            result_identity=lambda controlled, attempt: controlled_evaluation_result_identity(
                controlled, reanalysis_attempt_id=attempt),
            boolean_setting=boolean_setting,
            flush_queue=lambda url, enabled: flush_analysis_index_queue(
                url, memory_writeback_enabled=enabled),
            emit=lambda payload: print(json.dumps(payload))),
    )


def _memory_guard_ports(
    module: Any,
    harness: OnionSentinelHarnessRun | None,
    observe: Callable[[Callable[[], Any]], Any],
) -> Any:
    return module.MemoryGuardPorts(
        promotion_decision=lambda candidate, shared: (
            harness.memory_promotion_decision(
                candidate, has_shared_candidates=shared, human_approved=False)
            if harness is not None else None),
        decision_is_effective=lambda decision: policy_decision_is_effective(
            harness.policy.mode, decision),
        record_audit=lambda audit: observe(
            lambda: harness.store.append_event(
                harness.run_id, "policy.memory-promotion", "post-processing",
                audit, idempotency_key="policy.memory-promotion")),
        apply_freeze=lambda allowed, reason, frozen: apply_evaluation_memory_freeze(
            allowed, reason, freeze_enabled=frozen),
        plan=lambda candidates, allowed, reason: memory_writeback_plan(
            candidates, allowed=allowed, eligibility_reason=reason),
        reviewer_eligibility=second_opinion_memory_eligibility,
        controlled_claim_digest=controlled_evaluation_claim_digest,
    )


def _publication_ports(
    module: Any,
    *,
    args: argparse.Namespace,
    run_id: str,
    prompt_path: Path,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    started_at: dt.datetime,
    runtime_paths: Any,
    harness: OnionSentinelHarnessRun | None,
    observe: Callable[[Callable[[], Any]], Any],
) -> Any:
    return module.PublicationPorts(
        write_outputs=lambda: write_outputs(
            prompt_path, prompt_package, response, args, run_id),
        build_payload=lambda generated, artifact: analysis_index_payload(
            run_id, prompt_package, response, args.reanalysis_attempt_id,
            started_at, generated, artifact),
        preflight=lambda: observe(
            lambda: harness.preflight_completion(operation_id="pre-index-commit")
            if harness is not None else None),
        queue=lambda payload, controlled: queue_analysis_index(
            payload, queue_dir=runtime_paths.index_queue_dir)
            if controlled else queue_analysis_index(payload),
        submit=lambda payload, controlled: post_controlled_analysis_index(
            payload, args.alert_store_url)
            if controlled else post_analysis_index(payload, args.alert_store_url),
        quarantine=lambda path, payload, exc: quarantine_analysis_index(
            path, payload, exc,
            quarantine_dir=runtime_paths.index_quarantine_dir),
        discard_memory=lambda: discard_pending_memory_writeback(
            run_id, pending_dir=runtime_paths.memory_pending_dir),
    )


def _memory_promotion_ports(
    module: Any,
    *,
    run_id: str,
    response_digest: str,
    runtime_paths: Any,
    agent_role: str,
    role_memory_file: Path,
    shared_memory_file: Path,
    prompt_path: Path,
    guards: Any,
) -> Any:
    return module.MemoryPromotionPorts(
        promote_staged=lambda: mark_memory_writeback_committed(
            run_id, expected_response_digest=response_digest,
            pending_dir=runtime_paths.memory_pending_dir,
            committed_dir=runtime_paths.memory_committed_dir),
        process_staged=lambda task: process_committed_memory_writeback(
            task, receipt_dir=runtime_paths.memory_receipt_dir),
        persist_direct=lambda: persist_postcommit_memory_writeback(
            analysis_id=run_id, agent_role=agent_role,
            role_memory_file=role_memory_file,
            shared_memory_file=shared_memory_file,
            source_artifact=str(prompt_path),
            primary_candidates=guards.primary_candidates,
            primary_allowed=guards.primary_allowed,
            primary_reason=guards.primary_reason,
            reviewer_candidates=guards.reviewer_candidates,
            reviewer_allowed=guards.reviewer_allowed,
            reviewer_reason=guards.reviewer_reason,
            receipt_dir=runtime_paths.memory_receipt_dir),
        error_digest=canonical_payload_digest,
        warn=best_effort_warning,
    )


def _finalize_pipeline_telemetry(
    module: Any,
    *,
    status: str,
    error: str,
    monitor_started: bool,
    harness: OnionSentinelHarnessRun | None,
    resource_monitor: SystemResourceMonitor,
    started_at: dt.datetime,
    started_monotonic: float,
    run_id: str,
    prompt_path: Path | None,
    prompt_package: dict[str, Any],
    settings: dict[str, Any],
    args: argparse.Namespace,
    response: dict[str, Any] | None,
    json_path: Path | None,
    md_path: Path | None,
    runtime_paths: Any,
    running_record: dict[str, Any],
    active_record_path: Path,
) -> None:
    module.finalize(
        module.FinalizationInputs(
            status, error, bool(prompt_path or prompt_package),
            monitor_started, harness),
        module.FinalizationPorts(
            fail_harness=lambda reason: harness.fail(reason),
            stop_monitor=resource_monitor.stop,
            build_record=lambda: build_llm_log_record(
                run_id=run_id, status=status, started_at=started_at,
                finished_at=project_now(),
                runtime_seconds=time.monotonic() - started_monotonic,
                prompt_path=prompt_path, prompt_package=prompt_package,
                settings=settings or effective_ai_settings(args),
                response=response, json_path=json_path, md_path=md_path,
                resource_monitor=resource_monitor, error=error,
                runtime_observation=running_record),
            append_record=lambda record: append_jsonl(
                runtime_paths.log_file, record),
            write_current=lambda record: atomic_write_json(
                runtime_paths.current_file, record),
            cleanup_active=lambda: active_record_path.unlink(missing_ok=True),
            warn=best_effort_warning,
        ),
    )


def _finalize_harness_completion(
    module: Any,
    harness: OnionSentinelHarnessRun | None,
    *,
    run_id: str,
    response_digest: str,
    commit_receipt: dict[str, Any],
    json_path: Path,
    md_path: Path,
    response: dict[str, Any],
    memory_frozen: bool,
    memory_receipt: dict[str, Any] | None,
    memory_receipt_path: Path | None,
) -> None:
    if harness is None:
        return
    inputs = module.HarnessCompletionInputs(
        analysis_id=run_id, submitted_response_sha256=response_digest,
        commit_receipt=commit_receipt, json_path=json_path,
        markdown_path=md_path, response=response,
        evaluation_memory_frozen=memory_frozen,
        memory_receipt=memory_receipt,
        memory_receipt_path=memory_receipt_path)
    ports = module.HarnessCompletionPorts(
        digest=canonical_payload_digest,
        record_memory_writeback=harness.record_memory_writeback,
        observe_runtime=harness.observe_postcommit_runtime,
        complete=lambda payload: harness.complete(payload, check_budget=False),
        warn=best_effort_warning)
    module.finalize_harness(inputs, ports)


def _print_committed_outputs(
    markdown_path: Path,
    json_path: Path,
    response: dict[str, Any],
    include_response: bool,
) -> None:
    try:
        print(markdown_path)
        print(json_path)
        if include_response:
            print(json.dumps(response, indent=2, sort_keys=True))
    except Exception as exc:
        best_effort_warning(
            "committed analysis output could not be printed: "
            f"{type(exc).__name__}")


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
    bootstrap = _bootstrap_pipeline(startup_module, pipeline_module, args)
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
        run_id,
        active_dir=runtime_paths.active_dir,
    )
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
        attested = startup_module.load_and_attest(
            pipeline_context, args,
            policy=startup_module.PromptAttestationPolicy(
                package_type="soc-ai-investigation-prompt",
                allowed_roles=frozenset(CYBER_SECURITY_AGENT_ROLES),
                default_settings_file=DEFAULT_AI_SETTINGS_FILE,
                default_live_osquery_file=DEFAULT_LIVE_OSQUERY_CONFIG_FILE,
                controlled_identity=controlled_result_identity,
            ),
            ports=startup_module.PromptAttestationPorts(
                generate_prompt=generate_prompt,
                latest_prompt=latest_prompt,
                load_json=load_json,
                role_prompt_file=role_prompt_file,
                role_review_file=role_second_opinion_prompt_file,
                validate_incident_evidence=validate_incident_evidence_artifact,
                effective_settings=effective_ai_settings,
                require_controlled_routes=require_controlled_evaluation_routes,
                prepare_live_osquery=prepare_live_osquery_context,
                prepare_enrichment=prepare_investigation_enrichment_context,
                attach_evidence_contract=attach_evidence_reference_contract,
            ),
        )
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
            ports=_memory_guard_ports(
                memory_policy_module, harness_runtime, observe_harness),
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
            ports=_publication_ports(
                transaction_module, args=args, run_id=run_id,
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
            ports=_memory_promotion_ports(
                transaction_module, run_id=run_id,
                response_digest=submitted_response_sha256,
                runtime_paths=runtime_paths, agent_role=agent_role,
                role_memory_file=role_memory_file,
                shared_memory_file=shared_memory_file,
                prompt_path=prompt_path, guards=memory_guards),
        )
        memory_receipt = memory_promotion.receipt
        memory_receipt_path = memory_promotion.receipt_path
        _finalize_harness_completion(
            postcommit_module, harness_runtime, run_id=run_id,
            response_digest=submitted_response_sha256,
            commit_receipt=commit_receipt, json_path=json_path, md_path=md_path,
            response=response, memory_frozen=evaluation_memory_frozen,
            memory_receipt=memory_receipt,
            memory_receipt_path=memory_receipt_path)
        pipeline_context.advance(pipeline_module.Stage.POST_COMMIT, "post-commit work finalized")
        _print_committed_outputs(md_path, json_path, response, args.stdout)
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
        _finalize_pipeline_telemetry(
            telemetry_module, status=status, error=error,
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
