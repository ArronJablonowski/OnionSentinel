"""Install the legacy scheduler API from cohesive implementation modules."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import functools
import hashlib
import importlib
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, MutableMapping
from urllib.parse import urlparse

import scheduler_composition as composition
import scheduler_configuration as configuration
import scheduler_controlled_compat as controlled
import scheduler_job_compat as jobs
import scheduler_runtime_compat as runtime_adapters
import scheduler_selection_compat as selection


Namespace = MutableMapping[str, Any]


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_HARNESS_DB = (
    HOME / "n8n-local" / "alert_store_data" / "investigation-harness.sqlite3"
)
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_ROLLUP_DIR = HOME / "n8n-local" / "soc-alerts" / "daily-rollups"
DEFAULT_AGENT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"
DEFAULT_SHARED_MEMORY_FILE = DEFAULT_AGENT_MEMORY_DIR / "shared-agent-memory.md"
DEFAULT_ASSET_INVENTORY_FILE = (
    HOME / "n8n-local" / "config" / "asset_inventory.database-export.json"
)
DEFAULT_LIVE_OSQUERY_CONFIG = HOME / "n8n-local" / "config" / "live-osquery.json"
DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT = (
    HOME / "n8n-local" / "config" / "disagreement_adjudicator_system_prompt.md"
)
DEFAULT_INVESTIGATION_PIVOT_DIR = (
    HOME / "n8n-local" / "soc-alerts" / "investigation-pivots"
)
DEFAULT_INCIDENT_EVIDENCE_DIR = (
    HOME / "n8n-local" / "soc-alerts" / "incident-evidence"
)
DEFAULT_INCIDENT_EVIDENCE_CONFIG = (
    HOME / "n8n-local" / "config" / "incident-evidence.json"
)
DEFAULT_AI_SETTINGS = HOME / "n8n-local" / "config" / "ai_model_settings.json"
DEFAULT_INVESTIGATION_HARNESS_POLICY = (
    HOME / "n8n-local" / "config" / "investigation_harness_policy.json"
)
DEFAULT_DETECTION_PLAYBOOKS = (
    HOME / "n8n-local" / "config" / "detection_playbooks.json"
)
DEFAULT_INVESTIGATION_SKILLS = (
    HOME / "n8n-local" / "config" / "investigation_skills.json"
)
DEFAULT_LOCK = HOME / "n8n-local" / "run" / "ai-analysis.lock"
DEFAULT_DRAIN = HOME / "n8n-local" / "run" / "ai-analysis-maintenance-drain"
DEFAULT_WAKE = Path(
    os.environ.get(
        "AI_ANALYSIS_WAKE_PATH",
        HOME / "n8n-local" / "run" / "ai-analysis.wake",
    )
)
DEFAULT_DASHBOARD_WAKE = Path(
    os.environ.get(
        "SOC_DASHBOARD_WAKE_PATH",
        HOME / "n8n-local" / "run" / "dashboard-refresh.wake",
    )
)
DEFAULT_MODEL = os.environ.get("SOC_AI_MODEL", "")
DEFAULT_LEVELS = "critical,high,medium,low,informational"
SEVERITY_PRIORITY = ("critical", "high", "medium", "low", "informational")
ELIGIBLE_FILTER_STATUSES = ("accepted", "escalated", "unknown", "suppressed")
TEST_PREFIXES = (
    "phase%",
    "config-%",
    "internal-test-%",
    "sqlite-%",
    "policy-%",
    "codex-%",
)
DEFAULT_MAX_PROMPT_BYTES = max(
    256 * 1024,
    int(os.environ.get("SOC_AI_MAX_PROMPT_PACKAGE_BYTES", 4 * 1024 * 1024)),
)
CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES = 320 * 1024
CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES = 384 * 1024
DEFAULT_MAX_CHILD_STDOUT_BYTES = max(
    1024 * 1024,
    int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDOUT_BYTES", 16 * 1024 * 1024)),
)
DEFAULT_MAX_CHILD_STDERR_BYTES = max(
    256 * 1024,
    int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDERR_BYTES", 2 * 1024 * 1024)),
)
DEFAULT_MAX_CONTROL_RESPONSE_BYTES = 1024 * 1024
MAX_CONTROLLED_RESULT_SPOOL_BYTES = 16 * 1024 * 1024
CONTROLLED_RESULT_SUBMISSION_ATTEMPTS = 3
CONTROLLED_EXACT_CLAIM_ATTEMPTS = 3
CONTROLLED_RESULT_SUBMISSION_INDETERMINATE = (
    "controlled analysis result submission remains indeterminate"
)
CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE = 1
MAX_AI_SETTINGS_BYTES = 256 * 1024
CODEX_CLI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
CODEX_CLI_MODEL_CATALOG = frozenset(
    {"gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"}
)
AGENT_ROLES = (
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
)
CONTROLLED_ALERT_ID_RE = re.compile(r"[A-Za-z0-9._:@=-]{1,256}")
CONTROLLED_DISPATCH_ID_RE = re.compile(r"[a-f0-9]{64}")
CONTROLLED_RELEASE_ID_RE = re.compile(r"[a-f0-9]{40}")
CONTROLLED_MODEL_ROUTE_RE = re.compile(
    r"codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):"
    r"(?:low|medium|high|xhigh)"
)
CONTROLLED_COHORT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
CONTROLLED_LEASE_TOKEN_RE = re.compile(
    r"[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-"
    r"[89ab][a-f0-9]{3}-[a-f0-9]{12}"
)
CONTROLLED_ANALYSIS_ID_RE = re.compile(r"[a-z0-9_-]{8,120}")
CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH = 2048
CONTROLLED_EVALUATION_TOKEN_ENV = "ONION_SENTINEL_EVALUATION_TOKEN"
CONTROLLED_EVALUATION_TOKEN_HEADER = "X-Onion-Sentinel-Evaluation-Token"
CONTROLLED_EVALUATION_TOKEN_RE = re.compile(r"[a-f0-9]{64}")
RUNTIME_RELEASE_ENV_KEY = "ONION_SENTINEL_RELEASE_ID"
DEFAULT_RUNTIME_ENV_PATH = HOME / "n8n-local" / ".env"
MAX_RUNTIME_ENV_BYTES = 1024 * 1024
AI_JOB_FAIRNESS_AGE_SECONDS = 15 * 60
NON_RETRYABLE_AI_FAILURE_MARKERS = (
    "model context window exhausted",
    "prompt package remains above",
    "prompt package exceeded",
    "codex cli complete transport exceeds",
    "investigation follow-up prompt exceeds",
    "investigation query prompt projection exceeds",
    "no safe prompt budget remains",
    "codex cli executable was not found",
    "codex cli model name is invalid",
    "codex cli reasoning effort is invalid",
    "provider authentication failed",
    "configured model is unavailable or unauthorized",
    "command stderr exceeded the",
    "command stdout exceeded the",
    "incident reanalysis claim did not return its server-authoritative job identity",
    "incident reanalysis lease identity did not match its server-bound attempt",
    "durable ai claim job identity is invalid",
    "durable ai claim group identity is invalid",
    "durable ai claim alert identity is invalid",
    "controlled ai run requires a durable ai job claim",
    "controlled ai run identity arguments are incomplete",
    "controlled ai claim group identity did not match",
    "controlled ai claim alert identity did not match",
    "controlled ai claim dispatch identity did not match",
    "controlled ai claim release_id did not match",
)


DEPENDENCIES: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("disk_capacity", (("require_runtime_capacity", "require_runtime_capacity"),)),
    ("agent_memory", (("role_memory_file", "role_memory_file"), ("role_prompt_file", "role_prompt_file"), ("role_second_opinion_prompt_file", "role_second_opinion_prompt_file"))),
    ("bounded_http", (("BoundedHttpError", "BoundedHttpError"), ("read_bounded_json", "read_bounded_json"))),
    ("bounded_process", (("BoundedProcessError", "BoundedProcessError"), ("run_bounded_command", "run_bounded_command"))),
    ("controlled_evaluation_isolation", (("ControlledEvaluationIsolationError", "ControlledEvaluationIsolationError"), ("pin_controlled_tmpdir", "pin_controlled_tmpdir"), ("validate_controlled_incident_evidence_route", "validate_controlled_incident_evidence_route"))),
    ("scheduler_cli", (("SchedulerCliDefaults", "SchedulerCliDefaults"), ("SchedulerCliPolicy", "SchedulerCliPolicy"), ("parse_scheduler_args", "parse_scheduler_args"))),
    ("scheduler_ai_settings", (("SchedulerSettingsPolicy", "SchedulerSettingsPolicy"), ("StrictSettingsSources", "StrictSettingsSources"), ("discover_cli_agent_roles", "cli_agent_roles"), ("apply_analysis_level_floor", "configured_analysis_levels"), ("role_uses_codex_cli", "role_uses_codex_cli"), ("strict_controlled_ai_settings", "strict_controlled_ai_settings"))),
    ("scheduler_artifact_repository", tuple((name, name) for name in ("alert_group_id", "alert_group_key", "alert_group_key_from_mapping", "analyzed_alert_groups", "analyzed_alert_ids", "completed_analysis_group_ids", "latest_analysis_mtimes", "latest_pcap_analysis_mtimes", "latest_pcap_evidence_mtime_for_alert", "latest_pcap_group_mtimes", "latest_prompt_for_alert", "latest_prompt_group_mtimes", "latest_prompt_mtimes", "reusable_prompt_for_alert"))),
    ("scheduler_legacy_reconciliation", tuple((name, name) for name in ("orphaned_pending_ai_job_ids", "pending_ai_job_ids", "reconcilable_ai_job_ids", "reconcilable_completed_ai_job_ids"))),
    ("scheduler_controlled_runtime", (("ControlledRuntimePolicy", "ControlledRuntimePolicy"), ("ControlledRuntimeSources", "ControlledRuntimeSources"), ("validate_controlled_evaluation_runtime", "validate_controlled_evaluation_runtime"))),
    ("scheduler_controlled_recovery", (("ControlledRecoveryPolicy", "ControlledRecoveryPolicy"), ("ControlledRecoverySources", "ControlledRecoverySources"), ("controlled_spool_pending", "controlled_recovery_spool_pending"), ("replay_controlled_result_spool", "recover_controlled_evaluation_spool"))),
    ("scheduler_controlled_result_client", (("ControlledResultClientPolicy", "ControlledResultClientPolicy"), ("ControlledResultClientSources", "ControlledResultClientSources"), ("post_controlled_result", "post_controlled_recovery_result"))),
    ("scheduler_controlled_release", (("ControlledReleasePolicy", "ControlledReleasePolicy"), ("load_runtime_release_id", "current_runtime_release_id"), ("attest_controlled_release", "require_controlled_release_attestation"))),
    ("scheduler_controlled_claim_contract", (("ControlledClaimSources", "ControlledClaimSources"), ("ControlledLeaseIdentitySources", "ControlledLeaseIdentitySources"), ("ControlledRoutePolicy", "ControlledRoutePolicy"), ("ControlledRouteSources", "ControlledRouteSources"), ("validate_claim_expectations", "controlled_claim_expectations"), ("validate_job_route_contract", "controlled_job_route_contract"), ("incident_reanalysis_attempt_id", "incident_reanalysis_attempt_id"), ("require_controlled_lease_identity", "require_controlled_lease_identity"))),
    ("scheduler_claim_snapshot", (("ClaimSnapshotPolicy", "ClaimSnapshotPolicy"), ("load_claimed_durable_job", "claimed_durable_ai_job"))),
    ("scheduler_prompt_builder", (("PromptBuilderDefaults", "PromptBuilderDefaults"), ("PromptBuilderSources", "PromptBuilderSources"), ("build_prompt_package", "build_prompt_package"))),
    ("scheduler_runner_invocation", (("RunnerInvocationDefaults", "RunnerInvocationDefaults"), ("RunnerInvocationSources", "RunnerInvocationSources"), ("build_analysis_command", "analysis_command"), ("invoke_analysis_runner", "invoke_analysis_runner"))),
    ("scheduler_application", (("SchedulerApplicationSources", "SchedulerApplicationSources"), ("run_scheduler_application", "run_scheduler_application"))),
    ("scheduler_controlled_payload", (("ControlledPayloadPolicy", "ControlledPayloadPolicy"), ("ControlledPayloadSources", "ControlledPayloadSources"), ("validate_controlled_payload", "validate_controlled_recovery_payload"))),
    ("scheduler_controlled_acceptance", (("controlled_accepted_fields_match", "controlled_accepted_fields_match"), ("controlled_expected_accepted_fields", "controlled_expected_accepted_fields"))),
    ("scheduler_controlled_artifacts", (("FrozenMemoryPolicy", "FrozenMemoryPolicy"), ("load_private_recovery_json", "load_owner_private_json"), ("private_recovery_directory", "owner_private_directory"), ("settle_frozen_memory", "settle_controlled_frozen_memory_artifacts"))),
    ("scheduler_controlled_canonical", (("controlled_normalize_timestamp", "controlled_normalize_timestamp"), ("controlled_storage_canonical_digest", "controlled_storage_canonical_digest"))),
    ("scheduler_controlled_terminal_proof", (("ControlledTerminalProofSources", "ControlledTerminalProofSources"), ("prove_controlled_terminal_success", "prove_controlled_terminal_success"))),
    ("scheduler_claim", (("SchedulerClaimSources", "SchedulerClaimSources"), ("acquire_scheduler_claim", "acquire_scheduler_claim"))),
    ("scheduler_execution", (("SchedulerExecutionSources", "SchedulerExecutionSources"), ("execute_scheduler_analysis", "execute_scheduler_analysis"))),
    ("scheduler_drain", (("SchedulerDrainSources", "SchedulerDrainSources"), ("select_scheduler_work", "select_scheduler_work"))),
    ("scheduler_job_reporting", (("ClaimedAiLease", "ClaimedAiLease"), ("ControlledClaimRejected", "ControlledClaimRejected"), ("SchedulerReportingSources", "SchedulerReportingSources"), ("transition_ai_job_status", "transition_ai_job_status"))),
    ("scheduler_outcome", (("SchedulerOutcomeSources", "SchedulerOutcomeSources"), ("handle_controlled_claim_rejection", "handle_controlled_claim_rejection"), ("handle_process_outcome", "handle_process_outcome"), ("handle_scheduler_exception", "handle_scheduler_exception"))),
    ("scheduler_indexed_state", (("indexed_reconcilable_ai_job_ids", "indexed_reconcilable_ai_job_ids"), ("indexed_scheduler_available", "indexed_scheduler_available"))),
    ("scheduler_indexed_selection", (("IndexedSelectionRequest", "IndexedSelectionRequest"), ("IndexedSelectionSources", "IndexedSelectionSources"), ("provider_lane_predicate", "provider_lane_predicate"), ("select_next_indexed_alert", "select_next_indexed_alert"))),
    ("scheduler_legacy_selection", (("LegacySelectionRequest", "LegacySelectionRequest"), ("LegacySelectionSources", "LegacySelectionSources"), ("select_next_legacy_alert", "select_next_legacy_alert"))),
    ("scheduler_startup", (("SchedulerStartupSources", "SchedulerStartupSources"), ("initialize_scheduler_run", "initialize_scheduler_run"), ("prepare_scheduler_run", "prepare_scheduler_run"))),
    ("scheduler_settlement", (("SchedulerSettlementSources", "SchedulerSettlementSources"), ("settle_scheduler_run", "settle_scheduler_run"))),
    ("scheduler_terminal_recovery", (("TerminalRecoverySources", "TerminalRecoverySources"), ("reconcile_terminal_success", "reconcile_terminal_success"), ("load_terminal_success_recovery_candidates", "terminal_success_recovery_candidates"))),
    ("scheduler_worker", (("SchedulerWorkerSources", "SchedulerWorkerSources"), ("process_scheduler_selection", "process_scheduler_selection"))),
)


def _bind(namespace: Namespace, name: str, function: Any, **defaults: Any) -> None:
    bound = functools.partial(function, namespace, **defaults)
    bound.__name__ = name
    bound.__qualname__ = name
    bound.__doc__ = getattr(function, "__doc__", None)
    namespace[name] = bound


def _install_dependencies(namespace: Namespace, source_file: str) -> None:
    namespace.update({
        "argparse": argparse,
        "dt": dt,
        "fcntl": fcntl,
        "hashlib": hashlib,
        "importlib": importlib,
        "json": json,
        "os": os,
        "re": re,
        "sqlite3": sqlite3,
        "stat": stat,
        "sys": sys,
        "tempfile": tempfile,
        "time": time,
        "urllib": urllib,
        "Path": Path,
        "urlparse": urlparse,
        "BIN_DIR": Path(source_file).resolve().parent,
    })
    namespace.update({
        name: value
        for name, value in globals().items()
        if name.isupper() and name not in {"DEPENDENCIES"}
    })
    namespace["_STRICT_AI_SETTINGS_MODULE"] = None
    namespace["_CONTROLLED_EVALUATION_TOKEN"] = ""
    for module_name, exports in DEPENDENCIES:
        module = importlib.import_module(module_name)
        namespace.update(
            {public: getattr(module, source) for public, source in exports}
        )


def _install_controlled_exports(namespace: Namespace) -> None:
    namespace["controlled_canonical_digest"] = controlled.controlled_canonical_digest
    _bind(namespace, "controlled_evaluation_runtime", controlled.controlled_evaluation_runtime)
    namespace["valid_controlled_stable_group_key"] = lambda value: controlled.valid_controlled_stable_group_key(value, namespace["CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH"])
    _bind(namespace, "consume_controlled_evaluation_token", controlled.consume_controlled_evaluation_token)
    _bind(namespace, "alert_store_mutation_headers", controlled.alert_store_mutation_headers)
    _bind(namespace, "owner_private_directory", controlled.owner_private_directory)
    _bind(namespace, "load_owner_private_json", controlled.load_owner_private_json)
    _bind(namespace, "post_controlled_recovery_result", controlled.post_controlled_recovery_result, attempts=namespace["CONTROLLED_RESULT_SUBMISSION_ATTEMPTS"])
    _bind(namespace, "validate_controlled_recovery_payload", controlled.validate_controlled_recovery_payload)
    _bind(namespace, "settle_controlled_frozen_memory_artifacts", controlled.settle_controlled_frozen_memory_artifacts)
    _bind(namespace, "controlled_recovery_policy", controlled.build_controlled_recovery_policy)
    _bind(namespace, "recover_controlled_evaluation_spool", controlled.recover_controlled_evaluation_spool)
    _bind(namespace, "controlled_recovery_spool_pending", controlled.controlled_recovery_spool_pending)
    _bind(namespace, "controlled_recovery_terminal_success", controlled.controlled_recovery_terminal_success)
    _bind(namespace, "current_runtime_release_id", controlled.current_runtime_release_id)
    _bind(namespace, "require_controlled_release_attestation", controlled.require_controlled_release_attestation)


def _install_configuration_exports(namespace: Namespace) -> None:
    namespace["alert_time_sql"] = configuration.alert_time_sql
    namespace["alert_group_key_sql"] = configuration.alert_group_key_sql
    namespace["severity_priority_sql"] = lambda column="triage_level": configuration.severity_priority_sql(namespace["SEVERITY_PRIORITY"], column)
    _bind(namespace, "scheduler_cli_defaults", configuration.build_cli_defaults)
    _bind(namespace, "parse_args", configuration.parse_args)
    _bind(namespace, "scheduler_settings_policy", configuration.build_settings_policy)
    _bind(namespace, "cli_agent_roles", configuration.cli_agent_roles)
    _bind(namespace, "_role_uses_codex_cli", configuration.role_uses_codex_cli)
    _bind(namespace, "effective_prompt_package_limit", configuration.effective_prompt_package_limit)
    _bind(namespace, "effective_initial_prompt_package_limit", configuration.effective_prompt_package_limit, initial=True)
    _bind(namespace, "configured_analysis_levels", configuration.configured_analysis_levels)
    _bind(namespace, "provider_lane_sql", configuration.provider_lane_sql)


def _install_composition_exports(namespace: Namespace) -> None:
    namespace["build_application_sources"] = composition.build_application_sources
    _bind(namespace, "scheduler_reporting_sources", composition.build_reporting_sources)
    _bind(namespace, "controlled_recovery_sources", composition.build_controlled_recovery_sources)
    _bind(namespace, "controlled_terminal_proof_sources", composition.build_controlled_terminal_proof_sources)
    _bind(namespace, "runner_invocation_sources", composition.build_runner_invocation_sources)
    _bind(namespace, "terminal_recovery_sources", composition.build_terminal_recovery_sources)
    _bind(namespace, "scheduler_startup_sources", composition.build_startup_sources)
    _bind(namespace, "scheduler_settlement_sources", composition.build_settlement_sources)
    _bind(namespace, "scheduler_claim_sources", composition.build_claim_sources)
    _bind(namespace, "scheduler_execution_sources", composition.build_execution_sources)
    _bind(namespace, "scheduler_outcome_sources", composition.build_outcome_sources)
    _bind(namespace, "scheduler_drain_sources", composition.build_drain_sources)
    _bind(namespace, "scheduler_worker_sources", composition.build_worker_sources)


def _install_job_exports(namespace: Namespace) -> None:
    _bind(namespace, "report_ai_job_status", jobs.report_ai_job_status)
    _bind(namespace, "job_reanalysis_attempt_id", jobs.job_reanalysis_attempt_id)
    namespace["ai_failure_is_retryable"] = lambda error: jobs.ai_failure_is_retryable(namespace["NON_RETRYABLE_AI_FAILURE_MARKERS"], error)
    _bind(namespace, "reconcile_completed_ai_jobs", jobs.reconcile_completed_ai_jobs)
    _bind(namespace, "claimed_durable_ai_job", jobs.claimed_durable_ai_job)
    _bind(namespace, "require_controlled_claim_identity", jobs.require_controlled_claim_identity)
    _bind(namespace, "_strict_ai_settings_module", jobs.strict_ai_settings_module)
    _bind(namespace, "_strict_controlled_ai_settings", jobs.strict_controlled_ai_settings)
    _bind(namespace, "controlled_job_route_contract", jobs.controlled_job_route_contract)
    _bind(namespace, "controlled_claim_expectations", jobs.controlled_claim_expectations)
    _bind(namespace, "run_command", jobs.run_command, max_stdout_bytes=namespace["DEFAULT_MAX_CHILD_STDOUT_BYTES"], max_stderr_bytes=namespace["DEFAULT_MAX_CHILD_STDERR_BYTES"], env=None, progress_callback=None, progress_interval_seconds=30)
    _bind(namespace, "collect_incident_evidence", jobs.collect_incident_evidence)
    _bind(namespace, "build_prompt", jobs.build_prompt)
    _bind(namespace, "analysis_command", jobs.analysis_command)
    _bind(namespace, "runner_invocation_defaults", jobs.runner_invocation_defaults)
    _bind(namespace, "run_analysis", jobs.run_analysis)


def _install_selection_runtime_exports(namespace: Namespace) -> None:
    namespace["test_filter_sql"] = lambda column="alert_id": selection.test_filter_sql(namespace["TEST_PREFIXES"], column)
    _bind(namespace, "select_next_alert_indexed", selection.select_next_alert_indexed)
    _bind(namespace, "select_next_alert", selection.select_next_alert_legacy)
    _bind(namespace, "durable_payload", selection.durable_payload)

    for name in ("project_now", "project_now_precise", "rows", "flush_deferred_analysis_results", "signal_dashboard_refresh", "consume_wake_marker", "maintenance_drain_active", "stop_for_maintenance_drain", "reconcile_worker_state", "terminal_success_recovery_candidates", "scheduler_read_only_connection", "reconcile_terminal_success_durable_jobs", "detect_indexed_scheduler_mode", "main"):
        _bind(namespace, name, getattr(runtime_adapters, name))


def install_scheduler_facade(namespace: Namespace, source_file: str) -> None:
    _install_dependencies(namespace, source_file)
    _install_controlled_exports(namespace)
    _install_configuration_exports(namespace)
    _install_composition_exports(namespace)
    _install_job_exports(namespace)
    _install_selection_runtime_exports(namespace)
