"""Package-free import-time contracts for the local AI compatibility runner."""
from __future__ import annotations

import os
from pathlib import Path
import re

from investigation_query_contract import INVESTIGATION_QUERY_CONTRACT

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



__all__ = tuple(
    name for name in globals()
    if name.isupper()
    or name in {"RuntimeArtifactError", "AnalysisIndexSubmissionError"}
)
