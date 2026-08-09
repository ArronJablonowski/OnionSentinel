#!/usr/bin/env python3
"""Automatically analyze the next eligible SOC alert with its assigned model.

This wrapper is intended for launchd. Separate provider lanes allow hosted CLI
work to proceed while local Ollama inference is active. Each lane still holds
its own worker lock, while run-local-ai-analysis.py enforces a second host-wide
lock around every Ollama call so local models can never overlap.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
import urllib.error
import urllib.request
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from disk_capacity import require_runtime_capacity
from agent_memory import (
    role_memory_file,
    role_prompt_file,
    role_second_opinion_prompt_file,
)
from bounded_http import BoundedHttpError, read_bounded_json
from bounded_process import BoundedProcessError, run_bounded_command
from controlled_evaluation_isolation import (
    ControlledEvaluationIsolationError,
    pin_controlled_tmpdir,
    validate_controlled_incident_evidence_route,
)
from scheduler_cli import (
    SchedulerCliDefaults,
    SchedulerCliPolicy,
    parse_scheduler_args,
)
from scheduler_ai_settings import (
    SchedulerSettingsPolicy,
    StrictSettingsSources,
    cli_agent_roles as discover_cli_agent_roles,
    configured_analysis_levels as apply_analysis_level_floor,
    role_uses_codex_cli,
    strict_controlled_ai_settings,
)
from scheduler_artifact_repository import (
    alert_group_id as artifact_alert_group_id,
    alert_group_key as artifact_alert_group_key,
    alert_group_key_from_mapping as artifact_group_key_from_mapping,
    analyzed_alert_groups as artifact_analyzed_alert_groups,
    analyzed_alert_ids as artifact_analyzed_alert_ids,
    completed_analysis_group_ids as artifact_completed_group_ids,
    latest_analysis_mtimes as artifact_analysis_mtimes,
    latest_pcap_analysis_mtimes as artifact_pcap_analysis_mtimes,
    latest_pcap_evidence_mtime_for_alert as artifact_pcap_evidence_mtime,
    latest_pcap_group_mtimes as artifact_pcap_group_mtimes,
    latest_prompt_for_alert as artifact_latest_prompt,
    latest_prompt_group_mtimes as artifact_prompt_group_mtimes,
    latest_prompt_mtimes as artifact_prompt_mtimes,
    reusable_prompt_for_alert as artifact_reusable_prompt,
)
from scheduler_controlled_runtime import (
    ControlledRuntimePolicy,
    ControlledRuntimeSources,
    validate_controlled_evaluation_runtime,
)
from scheduler_controlled_recovery import (
    ControlledRecoveryPolicy,
    ControlledRecoverySources,
    controlled_recovery_spool_pending as controlled_spool_pending,
    recover_controlled_evaluation_spool as replay_controlled_result_spool,
)
from scheduler_controlled_result_client import (
    ControlledResultClientPolicy,
    ControlledResultClientSources,
    post_controlled_recovery_result as post_controlled_result,
)
from scheduler_controlled_release import (
    ControlledReleasePolicy,
    current_runtime_release_id as load_runtime_release_id,
    require_controlled_release_attestation as attest_controlled_release,
)
from scheduler_controlled_claim_contract import (
    ControlledClaimSources,
    ControlledRoutePolicy,
    ControlledRouteSources,
    controlled_claim_expectations as validate_claim_expectations,
    controlled_job_route_contract as validate_job_route_contract,
    incident_reanalysis_attempt_id as derive_incident_attempt_id,
)
from scheduler_controlled_payload import (
    ControlledPayloadPolicy,
    ControlledPayloadSources,
    validate_controlled_recovery_payload as validate_controlled_payload,
)
from scheduler_controlled_acceptance import (
    controlled_accepted_fields_match,
    controlled_expected_accepted_fields,
)
from scheduler_controlled_artifacts import (
    FrozenMemoryPolicy,
    load_owner_private_json as load_private_recovery_json,
    owner_private_directory as private_recovery_directory,
    settle_controlled_frozen_memory_artifacts as settle_frozen_memory,
)
from scheduler_controlled_canonical import (
    controlled_normalize_timestamp,
    controlled_storage_canonical_digest,
)
from scheduler_controlled_terminal_proof import (
    ControlledTerminalProofSources,
    prove_controlled_terminal_success,
)
from scheduler_claim import (
    SchedulerClaimSources,
    acquire_scheduler_claim,
)
from scheduler_execution import (
    SchedulerExecutionSources,
    execute_scheduler_analysis,
)
from scheduler_drain import (
    SchedulerDrainSources,
    SchedulerDrainState,
    select_scheduler_work,
)
from scheduler_job_reporting import (
    ClaimedAiLease,
    ControlledClaimRejected,
    SchedulerReportingSources,
    transition_ai_job_status,
)
from scheduler_outcome import (
    SchedulerOutcomeSources,
    handle_controlled_claim_rejection,
    handle_process_outcome,
    handle_scheduler_exception,
)
from scheduler_indexed_state import (
    indexed_reconcilable_ai_job_ids as load_indexed_reconcilable_ai_job_ids,
    indexed_scheduler_available as indexed_scheduler_state_available,
)
from scheduler_indexed_selection import (
    IndexedSelectionRequest,
    IndexedSelectionSources,
    provider_lane_predicate,
    select_next_indexed_alert,
)
from scheduler_legacy_selection import (
    LegacySelectionRequest,
    LegacySelectionSources,
    select_next_legacy_alert,
)
from scheduler_startup import (
    SchedulerStartupSources,
    initialize_scheduler_run,
    prepare_scheduler_run,
)
from scheduler_settlement import (
    SchedulerSettlement,
    SchedulerSettlementSources,
    settle_scheduler_run,
)
from scheduler_terminal_recovery import (
    TerminalRecoverySources,
    reconcile_terminal_success,
    terminal_success_recovery_candidates as load_terminal_success_recovery_candidates,
)
from scheduler_worker import (
    SchedulerWorkerSources,
    process_scheduler_selection,
)


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
DEFAULT_SHARED_MEMORY_FILE = (
    DEFAULT_AGENT_MEMORY_DIR / "shared-agent-memory.md"
)
DEFAULT_ASSET_INVENTORY_FILE = (
    HOME / "n8n-local" / "config" / "asset_inventory.database-export.json"
)
DEFAULT_LIVE_OSQUERY_CONFIG = (
    HOME / "n8n-local" / "config" / "live-osquery.json"
)
DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT = (
    HOME / "n8n-local" / "config" / "disagreement_adjudicator_system_prompt.md"
)
DEFAULT_INVESTIGATION_PIVOT_DIR = (
    HOME / "n8n-local" / "soc-alerts" / "investigation-pivots"
)
DEFAULT_INCIDENT_EVIDENCE_DIR = HOME / "n8n-local" / "soc-alerts" / "incident-evidence"
DEFAULT_INCIDENT_EVIDENCE_CONFIG = HOME / "n8n-local" / "config" / "incident-evidence.json"
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
DEFAULT_WAKE = Path(os.environ.get(
    "AI_ANALYSIS_WAKE_PATH",
    HOME / "n8n-local" / "run" / "ai-analysis.wake",
))
DEFAULT_DASHBOARD_WAKE = Path(os.environ.get(
    "SOC_DASHBOARD_WAKE_PATH",
    HOME / "n8n-local" / "run" / "dashboard-refresh.wake",
))
DEFAULT_MODEL = os.environ.get("SOC_AI_MODEL", "")
DEFAULT_LEVELS = "critical,high,medium,low,informational"
SEVERITY_PRIORITY = ("critical", "high", "medium", "low", "informational")
ELIGIBLE_FILTER_STATUSES = ("accepted", "escalated", "unknown", "suppressed")
TEST_PREFIXES = ("phase%", "config-%", "internal-test-%", "sqlite-%", "policy-%", "codex-%")
DEFAULT_MAX_PROMPT_BYTES = max(256 * 1024, int(os.environ.get("SOC_AI_MAX_PROMPT_PACKAGE_BYTES", 4 * 1024 * 1024)))
CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES = 320 * 1024
CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES = 384 * 1024
DEFAULT_MAX_CHILD_STDOUT_BYTES = max(1024 * 1024, int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDOUT_BYTES", 16 * 1024 * 1024)))
DEFAULT_MAX_CHILD_STDERR_BYTES = max(256 * 1024, int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDERR_BYTES", 2 * 1024 * 1024)))
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
CODEX_CLI_MODEL_CATALOG = frozenset({
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
})
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
CONTROLLED_EVALUATION_TOKEN_HEADER = (
    "X-Onion-Sentinel-Evaluation-Token"
)
CONTROLLED_EVALUATION_TOKEN_RE = re.compile(r"[a-f0-9]{64}")
_STRICT_AI_SETTINGS_MODULE: Any | None = None
RUNTIME_RELEASE_ENV_KEY = "ONION_SENTINEL_RELEASE_ID"
DEFAULT_RUNTIME_ENV_PATH = HOME / "n8n-local" / ".env"
MAX_RUNTIME_ENV_BYTES = 1024 * 1024
# Keep one busy provider lane from starving another analysis role. This is
# deliberately shorter than the 30-minute operational SLO so an eligible job
# receives a scheduling opportunity before the stalled-worker alarm fires.
AI_JOB_FAIRNESS_AGE_SECONDS = 15 * 60
_CONTROLLED_EVALUATION_TOKEN = ""


def controlled_evaluation_runtime(
    args: argparse.Namespace,
) -> Path | None:
    """Compatibility delegate for frozen controlled-runtime admission."""
    return validate_controlled_evaluation_runtime(
        args,
        ControlledRuntimePolicy(
            home=HOME,
            release_environment_key=RUNTIME_RELEASE_ENV_KEY,
            token_environment_key=CONTROLLED_EVALUATION_TOKEN_ENV,
            release_pattern=CONTROLLED_RELEASE_ID_RE,
            token_pattern=CONTROLLED_EVALUATION_TOKEN_RE,
        ),
        ControlledRuntimeSources(
            environment=os.environ,
            effective_uid=os.getuid,
            pin_tmpdir=pin_controlled_tmpdir,
            validate_incident_evidence_route=(
                validate_controlled_incident_evidence_route
            ),
            role_prompt_file=role_prompt_file,
            role_second_opinion_prompt_file=(
                role_second_opinion_prompt_file
            ),
            role_memory_file=role_memory_file,
            isolation_error=ControlledEvaluationIsolationError,
        ),
    )
def valid_controlled_stable_group_key(value: object) -> bool:
    """Return whether a frozen group key has one safe bounded UTF-8 encoding."""
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH


def controlled_canonical_digest(value: object, *, ensure_ascii: bool = True) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=ensure_ascii,
        ).encode("utf-8")
    ).hexdigest()


def consume_controlled_evaluation_token(enabled: bool) -> str:
    """Keep the mutation credential out of unrelated child environments."""
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


def alert_store_mutation_headers(*, user_agent: str = "") -> dict[str, str]:
    """Attach the ephemeral token only inside controlled evaluation mode."""
    headers = {"Content-Type": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent
    supplied_token = str(
        os.environ.get(CONTROLLED_EVALUATION_TOKEN_ENV) or ""
    ).strip()
    evaluation_token = (
        supplied_token
        if CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(supplied_token)
        else _CONTROLLED_EVALUATION_TOKEN
    )
    if (
        str(
            os.environ.get("ONION_SENTINEL_EVALUATION_MODE") or ""
        ).strip()
        == "1"
        and CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(evaluation_token)
    ):
        headers[CONTROLLED_EVALUATION_TOKEN_HEADER] = evaluation_token
    return headers


def owner_private_directory(path: Path, runtime_root: Path) -> bool:
    """Compatibility delegate for owner-private recovery directories."""
    return private_recovery_directory(
        path,
        runtime_root,
        effective_uid=os.getuid(),
    )


def load_owner_private_json(
    path: Path,
    runtime_root: Path,
    *,
    max_bytes: int,
) -> dict[str, Any]:
    """Compatibility delegate for bounded owner-private JSON loading."""
    return load_private_recovery_json(
        path,
        runtime_root,
        max_bytes=max_bytes,
        effective_uid=os.getuid(),
    )


def post_controlled_recovery_result(
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    attempts: int = CONTROLLED_RESULT_SUBMISSION_ATTEMPTS,
) -> dict[str, Any]:
    """Compatibility delegate for bounded exact result replay."""
    return post_controlled_result(
        ControlledResultClientSources(
            mutation_headers=lambda user_agent: alert_store_mutation_headers(
                user_agent=user_agent
            ),
            open_url=urllib.request.urlopen,
            read_bounded_json=read_bounded_json,
            sleep=time.sleep,
            transport_errors=(
                urllib.error.URLError,
                TimeoutError,
                OSError,
                BoundedHttpError,
            ),
        ),
        ControlledResultClientPolicy(
            indeterminate_marker=(
                CONTROLLED_RESULT_SUBMISSION_INDETERMINATE
            ),
            max_response_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES,
        ),
        payload,
        alert_store_url,
        attempts=attempts,
    )


def validate_controlled_recovery_payload(
    payload: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Compatibility delegate for exact controlled payload validation."""
    return validate_controlled_payload(
        ControlledPayloadPolicy(
            lease_token_pattern=CONTROLLED_LEASE_TOKEN_RE,
            cohort_id_pattern=CONTROLLED_COHORT_ID_RE,
            model_route_pattern=CONTROLLED_MODEL_ROUTE_RE,
            analysis_id_pattern=CONTROLLED_ANALYSIS_ID_RE,
        ),
        ControlledPayloadSources(
            current_release_id=current_runtime_release_id,
            incident_attempt_id=incident_reanalysis_attempt_id,
            canonical_digest=controlled_canonical_digest,
            storage_canonical_digest=controlled_storage_canonical_digest,
            expected_accepted_fields=controlled_expected_accepted_fields,
        ),
        payload,
        args,
    )


def settle_controlled_frozen_memory_artifacts(
    runtime_root: Path,
    recovery: dict[str, Any],
) -> None:
    """Compatibility delegate for exact frozen-memory settlement."""
    settle_frozen_memory(
        runtime_root,
        recovery,
        policy=FrozenMemoryPolicy(),
        effective_uid=os.getuid(),
    )


def controlled_recovery_sources() -> ControlledRecoverySources:
    """Bind exact result validation, replay, proof, and memory settlement."""
    return ControlledRecoverySources(
        effective_uid=os.getuid,
        owner_private_directory=owner_private_directory,
        load_owner_private_json=load_owner_private_json,
        validate_payload=validate_controlled_recovery_payload,
        post_result=post_controlled_recovery_result,
        terminal_success=controlled_recovery_terminal_success,
        settle_frozen_memory=settle_controlled_frozen_memory_artifacts,
    )


def controlled_recovery_policy() -> ControlledRecoveryPolicy:
    return ControlledRecoveryPolicy(
        max_spool_bytes=MAX_CONTROLLED_RESULT_SPOOL_BYTES,
        indeterminate_submission_marker=(
            CONTROLLED_RESULT_SUBMISSION_INDETERMINATE
        ),
    )


def recover_controlled_evaluation_spool(
    args: argparse.Namespace,
    runtime_root: Path,
) -> bool:
    """Compatibility delegate for exact controlled result recovery."""
    return replay_controlled_result_spool(
        controlled_recovery_sources(),
        controlled_recovery_policy(),
        args,
        runtime_root,
    )


def controlled_recovery_spool_pending(runtime_root: Path) -> bool:
    """Compatibility delegate for fail-closed spool presence checks."""
    return controlled_spool_pending(
        runtime_root,
        effective_uid=os.getuid,
    )


def controlled_terminal_proof_sources() -> ControlledTerminalProofSources:
    """Bind the immutable database proof and canonical digest policies."""
    def open_readonly_database(database_path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        return connection

    return ControlledTerminalProofSources(
        open_readonly_database=open_readonly_database,
        accepted_fields_match=controlled_accepted_fields_match,
        storage_canonical_digest=controlled_storage_canonical_digest,
        valid_digest=lambda value: bool(re.fullmatch(r"[a-f0-9]{64}", value)),
    )


def controlled_recovery_terminal_success(
    args: argparse.Namespace,
    recovery: dict[str, Any],
) -> bool:
    """Compatibility delegate for immutable terminal database proof."""
    return prove_controlled_terminal_success(
        controlled_terminal_proof_sources(),
        args.db,
        recovery,
    )


def current_runtime_release_id(
    *,
    environ: object | None = None,
    env_path: Path | None = None,
) -> str:
    """Compatibility delegate for literal deployed release loading."""
    return load_runtime_release_id(
        ControlledReleasePolicy(
            environment_key=RUNTIME_RELEASE_ENV_KEY,
            default_env_path=DEFAULT_RUNTIME_ENV_PATH,
            max_env_bytes=MAX_RUNTIME_ENV_BYTES,
            release_pattern=CONTROLLED_RELEASE_ID_RE,
        ),
        environ=os.environ if environ is None else environ,
        env_path=env_path,
    )


def require_controlled_release_attestation(
    claimed_payload: dict[str, object],
) -> str:
    """Compatibility delegate for durable release attestation."""
    return attest_controlled_release(
        ControlledReleasePolicy(
            environment_key=RUNTIME_RELEASE_ENV_KEY,
            default_env_path=DEFAULT_RUNTIME_ENV_PATH,
            max_env_bytes=MAX_RUNTIME_ENV_BYTES,
            release_pattern=CONTROLLED_RELEASE_ID_RE,
        ),
        claimed_payload,
        current_runtime_release_id(),
        ControlledClaimRejected,
    )


def alert_time_sql(alias: str = "") -> str:
    """Return the newest usable alert timestamp expression for queue priority."""
    prefix = f"{alias}." if alias else ""
    return (
        f"COALESCE(NULLIF({prefix}last_seen, ''), "
        f"NULLIF({prefix}timestamp, ''), NULLIF({prefix}first_seen, ''))"
    )


def alert_group_key_sql() -> str:
    """Return SQL for the same duplicate-group key used by the dashboard."""
    return (
        "COALESCE(NULLIF(suppression_key, ''), "
        "COALESCE(triage_level, '') || '|' || "
        "COALESCE(rule_name, '') || '|' || "
        "COALESCE(source_ip, '') || '|' || "
        "COALESCE(destination_ip, '') || '|' || "
        "COALESCE(NULLIF(filter_status, ''), 'accepted'))"
    )


def severity_priority_sql(column: str = "triage_level") -> str:
    """Return SQL that drains each severity bucket before moving lower.

    Policy: no High alert is selected while any eligible Critical group remains;
    no Medium alert is selected while any eligible Critical or High group
    remains; and so on. Inside each severity bucket, newest alerts go first.
    """
    cases = "\n            ".join(
        f"WHEN '{level}' THEN {index}"
        for index, level in enumerate(SEVERITY_PRIORITY, start=1)
    )
    return f"CASE {column}\n            {cases}\n            ELSE {len(SEVERITY_PRIORITY) + 1}\n          END"


def scheduler_cli_defaults() -> SchedulerCliDefaults:
    """Resolve scheduler defaults at parse time for test and environment parity."""
    return SchedulerCliDefaults(
        db=DEFAULT_DB,
        harness_db=DEFAULT_HARNESS_DB,
        prompt_dir=DEFAULT_PROMPT_DIR,
        analysis_dir=DEFAULT_ANALYSIS_DIR,
        pcap_analysis_dir=DEFAULT_PCAP_ANALYSIS_DIR,
        rollup_dir=DEFAULT_ROLLUP_DIR,
        agent_memory_dir=DEFAULT_AGENT_MEMORY_DIR,
        shared_memory_file=DEFAULT_SHARED_MEMORY_FILE,
        asset_inventory_file=DEFAULT_ASSET_INVENTORY_FILE,
        incident_evidence_dir=DEFAULT_INCIDENT_EVIDENCE_DIR,
        incident_evidence_config=DEFAULT_INCIDENT_EVIDENCE_CONFIG,
        investigation_pivot_dir=DEFAULT_INVESTIGATION_PIVOT_DIR,
        live_osquery_config=DEFAULT_LIVE_OSQUERY_CONFIG,
        disagreement_adjudicator_prompt=DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT,
        ai_settings=DEFAULT_AI_SETTINGS,
        investigation_harness_policy=DEFAULT_INVESTIGATION_HARNESS_POLICY,
        detection_playbooks=DEFAULT_DETECTION_PLAYBOOKS,
        investigation_skills=DEFAULT_INVESTIGATION_SKILLS,
        lock=DEFAULT_LOCK,
        drain=DEFAULT_DRAIN,
        wake=DEFAULT_WAKE,
        levels=DEFAULT_LEVELS,
        model=DEFAULT_MODEL,
        max_prompt_bytes=DEFAULT_MAX_PROMPT_BYTES,
        portal_wake=DEFAULT_DASHBOARD_WAKE,
        alert_store_url=os.environ.get(
            "ALERT_STORE_URL", "http://127.0.0.1:8787"
        ),
    )


def parse_args() -> argparse.Namespace:
    return parse_scheduler_args(
        scheduler_cli_defaults(),
        SchedulerCliPolicy(
            controlled_alert_id=CONTROLLED_ALERT_ID_RE,
            controlled_dispatch_id=CONTROLLED_DISPATCH_ID_RE,
            stable_group_key_valid=valid_controlled_stable_group_key,
            stable_group_key_max_bytes=CONTROLLED_STABLE_GROUP_KEY_MAX_LENGTH,
        ),
    )


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def project_now_precise() -> str:
    """Return a queue clock precise enough for sub-second retry timestamps."""
    return dt.datetime.now().astimezone().isoformat(
        timespec="milliseconds"
    ).replace("T", "  ")


def scheduler_settings_policy() -> SchedulerSettingsPolicy:
    return SchedulerSettingsPolicy(
        max_bytes=MAX_AI_SETTINGS_BYTES,
        agent_roles=AGENT_ROLES,
        codex_models=CODEX_CLI_MODEL_CATALOG,
        codex_efforts=CODEX_CLI_REASONING_EFFORTS,
    )


def cli_agent_roles(settings_path: Path) -> set[str]:
    """Compatibility delegate for fail-closed hosted-lane discovery."""
    return discover_cli_agent_roles(settings_path, scheduler_settings_policy())


def _role_uses_codex_cli(
    args: argparse.Namespace,
    *,
    agent_role: str = "",
) -> bool:
    """Return whether any configured route for this role uses Codex CLI."""
    role = str(agent_role or "").strip()
    settings_path = Path(
        getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS)
    )
    return role_uses_codex_cli(
        settings_path,
        scheduler_settings_policy(),
        role,
    )


def effective_prompt_package_limit(
    args: argparse.Namespace,
    *,
    agent_role: str = "",
) -> int:
    """Clamp the mutable Codex runner prompt to its transport-safe ceiling."""
    configured = int(
        getattr(args, "max_prompt_bytes", DEFAULT_MAX_PROMPT_BYTES)
        or DEFAULT_MAX_PROMPT_BYTES
    )
    if _role_uses_codex_cli(args, agent_role=agent_role):
        return min(configured, CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES)
    return configured


def effective_initial_prompt_package_limit(
    args: argparse.Namespace,
    *,
    agent_role: str = "",
) -> int:
    """Leave deterministic headroom for audited follow-up query evidence."""
    configured = int(
        getattr(args, "max_prompt_bytes", DEFAULT_MAX_PROMPT_BYTES)
        or DEFAULT_MAX_PROMPT_BYTES
    )
    if _role_uses_codex_cli(args, agent_role=agent_role):
        return min(configured, CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES)
    return configured


def configured_analysis_levels(settings_path: Path, configured_levels: str) -> list[str]:
    """Return the launch allowlist constrained by the saved automatic AI floor.

    The scheduler argument remains a deployment-level ceiling. Settings can
    raise the floor at runtime without editing or reloading the launchd plist.
    Older settings files retain the historical all-severity analysis behavior
    until the operator explicitly saves the new control.
    """
    return apply_analysis_level_floor(
        settings_path,
        scheduler_settings_policy(),
        configured_levels,
        SEVERITY_PRIORITY,
    )


def provider_lane_sql(args: argparse.Namespace) -> tuple[str, list[object]]:
    """Build an allowlisted SQL predicate for the selected provider lane."""
    provider_lane = str(getattr(args, "provider_lane", "any") or "any")
    cli_roles = sorted(cli_agent_roles(Path(getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS))))
    return provider_lane_predicate(provider_lane, cli_roles)


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def scheduler_reporting_sources() -> SchedulerReportingSources:
    """Bind the scheduler's bounded HTTP and controlled-claim policy ports."""
    return SchedulerReportingSources(
        request_factory=urllib.request.Request,
        open_url=urllib.request.urlopen,
        read_json=read_bounded_json,
        mutation_headers=alert_store_mutation_headers,
        sleep=time.sleep,
        valid_stable_group_key=valid_controlled_stable_group_key,
        model_route_pattern=CONTROLLED_MODEL_ROUTE_RE,
        max_response_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES,
        exact_claim_attempts=CONTROLLED_EXACT_CLAIM_ATTEMPTS,
    )


def report_ai_job_status(
    base_url: str,
    group_id: str,
    status: str,
    error: str = "",
    lease_token: str = "",
    job_type: str = "ai_analysis",
    retryable: bool = True,
    expected_job_id: int = 0,
    expected_representative_alert_id: str = "",
    expected_dispatch_id: str = "",
    expected_stable_group_key: str = "",
    expected_assigned_route: str = "",
    expected_reviewer_route: str = "",
    reviewer_required: bool = False,
) -> bool | str:
    """Transition durable AI intent through a bounded local HTTP contract.

    Returning ``False`` only represents a rolling-deployment 404. Network,
    malformed-response, and oversized-response failures remain visible so the
    worker never performs expensive inference without a durable processing
    lease in the current indexed architecture.
    """
    return transition_ai_job_status(
        scheduler_reporting_sources(),
        base_url,
        group_id,
        status,
        error,
        lease_token,
        job_type,
        retryable,
        expected_job_id,
        expected_representative_alert_id,
        expected_dispatch_id,
        expected_stable_group_key,
        expected_assigned_route,
        expected_reviewer_route,
        reviewer_required,
    )


def incident_reanalysis_attempt_id(lease_token: str) -> str:
    """Compatibility delegate for one non-secret IR lease fingerprint."""
    return derive_incident_attempt_id(lease_token)


def job_reanalysis_attempt_id(job_payload: dict, lease_token: str) -> str:
    """Fingerprint only a validated manual reanalysis job, never escalation."""
    if job_payload.get("manual_reanalysis") is not True:
        return ""
    run_id = str(job_payload.get("reanalysis_run_id") or "").strip().lower()
    case_id = str(job_payload.get("case_id") or "").strip().lower()
    if not re.fullmatch(r"irr-[a-f0-9-]{36}", run_id):
        return ""
    if not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return ""
    return incident_reanalysis_attempt_id(lease_token)


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


def ai_failure_is_retryable(error: object) -> bool:
    """Return false for deterministic failures that rebuilding cannot repair."""
    detail = str(error or "").strip().lower()
    return not any(marker in detail for marker in NON_RETRYABLE_AI_FAILURE_MARKERS)


def reconcile_completed_ai_jobs(base_url: str, group_ids: set[str]) -> int:
    """Mark pending queue intent complete when current artifacts already satisfy it."""
    if not group_ids:
        return 0
    payload = json.dumps({
        "job_type": "ai_analysis",
        "dedupe_keys": sorted(group_ids),
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/jobs/reconcile-completed",
        data=payload,
        headers=alert_store_mutation_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status not in range(200, 300):
                raise RuntimeError(f"AI job reconciliation returned HTTP {response.status}")
            result = read_bounded_json(response, max_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES)
            return int(result.get("reconciled") or 0)
    except urllib.error.HTTPError as exc:
        # Older alert-store versions may not have the batch endpoint during a
        # rolling deployment. Analysis must continue and the next run retries.
        if exc.code == 404:
            return 0
        raise RuntimeError(f"AI job reconciliation returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, BoundedHttpError) as exc:
        raise RuntimeError(f"AI job reconciliation failed: {exc}") from exc


def test_filter_sql(column: str = "alert_id") -> tuple[str, list[object]]:
    clauses = []
    params: list[object] = []
    for pattern in TEST_PREFIXES:
        clauses.append(f"{column} NOT LIKE ?")
        params.append(pattern)
    return " AND ".join(clauses), params


def latest_analysis_mtimes(analysis_dir: Path) -> dict[str, float]:
    return artifact_analysis_mtimes(analysis_dir)


def latest_pcap_analysis_mtimes(pcap_analysis_dir: Path) -> dict[str, float]:
    return artifact_pcap_analysis_mtimes(pcap_analysis_dir)


def latest_pcap_group_mtimes(pcap_analysis_dir: Path) -> dict[str, float]:
    """Return newest parsed PCAP evidence time keyed by grouped detection id."""
    return artifact_pcap_group_mtimes(pcap_analysis_dir)


def latest_prompt_mtimes(prompt_dir: Path) -> dict[str, float]:
    return artifact_prompt_mtimes(prompt_dir)


def alert_group_key_from_mapping(alert: dict) -> str:
    """Return the scheduler duplicate-group key for prompt-package alert data."""
    return artifact_group_key_from_mapping(alert)


def latest_prompt_group_mtimes(conn: sqlite3.Connection, prompt_dir: Path) -> dict[str, float]:
    return artifact_prompt_group_mtimes(conn, prompt_dir)


def analyzed_alert_ids(analysis_dir: Path, pcap_analysis_dir: Path | None = None, prompt_dir: Path | None = None) -> set[str]:
    """Return analyzed alert ids, excluding AI artifacts stale versus PCAP or manual requeue prompts."""
    return artifact_analyzed_alert_ids(
        analysis_dir, pcap_analysis_dir, prompt_dir
    )


def alert_group_key(row: sqlite3.Row) -> str:
    """Return the same duplicate-group key used by the SOC dashboard."""
    return artifact_alert_group_key(row)


def alert_group_id(group_key: str) -> str:
    return artifact_alert_group_id(group_key)


def analyzed_alert_groups(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path | None = None,
    pcap_analysis_dir: Path | None = None,
    prompt_dir: Path | None = None,
) -> set[str]:
    return artifact_analyzed_alert_groups(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )


def completed_analysis_group_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Return stable queue keys for groups whose analysis artifacts are current."""
    return artifact_completed_group_ids(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )


def orphaned_pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return pending AI queue keys that no longer map to an alert group.

    Stable group identities can be replaced when legacy rows are normalized or
    grouping policy changes. Those old durable intents are not actionable, but
    leaving them pending makes queue health report a worker stall forever.
    """
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    pending_ids = {
        str(row[0] or "").strip()
        for row in conn.execute(
            "SELECT dedupe_key FROM durable_jobs WHERE job_type = 'ai_analysis' AND status = 'pending'"
        ).fetchall()
        if str(row[0] or "").strip()
    }
    if not pending_ids:
        return set()
    # alert_group_summary is the authoritative set of currently actionable
    # groups. Raw alert rows can retain superseded identities after a recovery
    # or grouping-policy migration, which otherwise leaves queue intents that
    # no scheduler selection can ever satisfy.
    active_ids = {
        str(row[0] or "").strip()
        for row in conn.execute("SELECT group_id FROM alert_group_summary").fetchall()
        if str(row[0] or "").strip()
    }
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "alert_group_alias" in tables:
        for legacy_id, stable_id in conn.execute(
            "SELECT legacy_group_id, stable_group_id FROM alert_group_alias"
        ).fetchall():
            # Summaries retain the legacy dashboard identifier while durable
            # AI jobs use the V2 stable identity. Follow the alias in that
            # direction so both forms remain actionable.
            if str(legacy_id or "").strip() in active_ids:
                active_ids.add(str(stable_id or "").strip())
    return pending_ids - active_ids


def pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return coalesced durable AI intents that still require a model run."""
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            "SELECT dedupe_key FROM durable_jobs WHERE job_type = 'ai_analysis' AND status = 'pending'"
        ).fetchall()
        if str(row[0] or "").strip()
    }


def reconcilable_completed_ai_job_ids(conn: sqlite3.Connection, group_ids: set[str]) -> set[str]:
    """Keep artifact reconciliation from erasing newly queued evidence.

    A pending job is artifact-reconcilable only when a worker previously began
    processing it. Fresh alert, enrichment, and PCAP intents deliberately have
    no processing start and must reach the scheduler even when an older report
    artifact exists for the same duplicate group.
    """
    if not group_ids:
        return set()
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(durable_jobs)").fetchall()}
    if "processing_started_at" not in columns or "rerun_requested" not in columns:
        return group_ids
    placeholders = ", ".join("?" for _ in group_ids)
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            f"""
            SELECT dedupe_key FROM durable_jobs
            WHERE job_type = 'ai_analysis' AND status = 'pending'
              AND COALESCE(rerun_requested, 0) = 0
              AND processing_started_at IS NOT NULL
              AND dedupe_key IN ({placeholders})
            """,
            sorted(group_ids),
        ).fetchall()
        if str(row[0] or "").strip()
    }


def reconcilable_ai_job_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Combine artifact-complete and obsolete durable AI queue intents."""
    completed = completed_analysis_group_ids(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )
    return reconcilable_completed_ai_job_ids(conn, completed) | orphaned_pending_ai_job_ids(conn)


def indexed_scheduler_available(conn: sqlite3.Connection) -> bool:
    """Compatibility delegate for indexed scheduler capability detection."""
    return indexed_scheduler_state_available(conn)


def indexed_reconcilable_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Compatibility delegate for indexed committed-result reconciliation."""
    return load_indexed_reconcilable_ai_job_ids(conn)


def select_next_alert_indexed(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    already_selected_groups: set[str] | None = None,
) -> sqlite3.Row | None:
    lane_sql, lane_params = provider_lane_sql(args)
    # Indexed groups are guarded by durable job state. Do not apply the legacy
    # per-process exclusion set: a request coalesced while inference is active
    # becomes a fresh pending job and should be eligible immediately.
    del already_selected_groups
    request = IndexedSelectionRequest(
        levels=args.levels,
        hours=args.hours,
        include_tests=args.include_tests,
        only_group_id=str(getattr(args, "only_group_id", "") or ""),
        lane_sql=lane_sql,
        lane_params=tuple(lane_params),
    )
    sources = IndexedSelectionSources(
        now=lambda: dt.datetime.now().astimezone(),
        precise_now=project_now_precise,
        alert_time_sql=alert_time_sql,
        severity_priority_sql=severity_priority_sql,
        test_filter_sql=test_filter_sql,
        eligible_filter_statuses=ELIGIBLE_FILTER_STATUSES,
        fairness_age_seconds=AI_JOB_FAIRNESS_AGE_SECONDS,
    )
    return select_next_indexed_alert(conn, request, sources)


def select_next_alert(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    already_analyzed: set[str],
    already_selected_groups: set[str] | None = None,
) -> sqlite3.Row | None:
    request = LegacySelectionRequest(
        levels=args.levels,
        hours=args.hours,
        include_tests=args.include_tests,
        only_group_id=str(getattr(args, "only_group_id", "") or ""),
        analysis_dir=getattr(args, "analysis_dir", None),
        pcap_analysis_dir=getattr(args, "pcap_analysis_dir", None),
        prompt_dir=getattr(args, "prompt_dir", None),
        already_analyzed=frozenset(already_analyzed),
        already_selected_groups=frozenset(already_selected_groups or set()),
    )
    sources = LegacySelectionSources(
        now=lambda: dt.datetime.now().astimezone(),
        alert_time_sql=lambda: alert_time_sql(),
        alert_group_key_sql=alert_group_key_sql,
        severity_priority_sql=lambda: severity_priority_sql(),
        test_filter_sql=lambda: test_filter_sql(),
        latest_prompt_mtimes=latest_prompt_mtimes,
        latest_analysis_mtimes=latest_analysis_mtimes,
        analyzed_alert_groups=analyzed_alert_groups,
        pending_ai_job_ids=pending_ai_job_ids,
        alert_group_key=alert_group_key,
        alert_group_id=alert_group_id,
        eligible_filter_statuses=ELIGIBLE_FILTER_STATUSES,
    )
    return select_next_legacy_alert(conn, request, sources)


def latest_prompt_for_alert(prompt_dir: Path, alert_id: str) -> Path | None:
    return artifact_latest_prompt(prompt_dir, alert_id)


def latest_pcap_evidence_mtime_for_alert(selected: sqlite3.Row, pcap_analysis_dir: Path) -> float:
    """Return newest parsed PCAP evidence mtime for the selected alert group."""
    return artifact_pcap_evidence_mtime(selected, pcap_analysis_dir)


def reusable_prompt_for_alert(prompt_dir: Path, selected: sqlite3.Row, pcap_analysis_dir: Path) -> Path | None:
    """Return a prompt package only if it is current with parsed PCAP evidence."""
    return artifact_reusable_prompt(prompt_dir, selected, pcap_analysis_dir)


def durable_payload(selected: sqlite3.Row) -> dict[str, object]:
    """Decode trusted queue metadata without letting corruption alter limits."""
    if "durable_payload_json" not in selected.keys():
        return {}
    try:
        payload = json.loads(str(selected["durable_payload_json"] or "{}"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def claimed_durable_ai_job(
    processing_transition: object,
    database_path: Path,
    *,
    expected_job_type: str,
    expected_group_id: str,
    expected_job_id: int = 0,
) -> tuple[dict[str, object], str, str, str]:
    """Validate and return the exact durable AI snapshot bound to a lease."""
    claimed_payload = getattr(processing_transition, "job_payload", None)
    if not isinstance(claimed_payload, dict) or not claimed_payload:
        raise RuntimeError(
            "durable AI claim did not return its server-authoritative job identity"
        )

    claimed_job_type = str(
        getattr(processing_transition, "job_type", "") or ""
    ).strip()
    if claimed_job_type != expected_job_type:
        raise RuntimeError("durable AI claim job identity is invalid")
    claimed_job_id = int(
        getattr(processing_transition, "job_id", 0) or 0
    )
    if expected_job_id and claimed_job_id != expected_job_id:
        raise RuntimeError("durable AI claim job identity is invalid")

    resolved_group_id = str(
        getattr(processing_transition, "resolved_key", "") or ""
    ).strip().lower()
    payload_group_id = str(
        claimed_payload.get("group_id") or ""
    ).strip().lower()
    if (
        not resolved_group_id
        or resolved_group_id != expected_group_id.strip().lower()
        or not payload_group_id
        or payload_group_id != resolved_group_id
    ):
        raise RuntimeError("durable AI claim group identity is invalid")

    payload_alert_ids = {
        str(claimed_payload.get(field) or "").strip()
        for field in ("alert_id", "representative_alert_id")
        if str(claimed_payload.get(field) or "").strip()
    }
    if len(payload_alert_ids) != 1:
        raise RuntimeError("durable AI claim alert identity is invalid")
    claimed_alert_id = next(iter(payload_alert_ids))

    try:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            alert = connection.execute(
                """
                SELECT stable_group_id, stable_group_key, triage_level
                FROM alerts
                WHERE alert_id = ?
                LIMIT 1
                """,
                (claimed_alert_id,),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RuntimeError(
            "durable AI claim identity verification failed"
        ) from exc

    if (
        not alert
        or str(alert["stable_group_id"] or "").strip().lower()
        != resolved_group_id
    ):
        raise RuntimeError("durable AI claim alert identity is invalid")
    claimed_stable_group_key = claimed_payload.get("stable_group_key")
    if (
        claimed_stable_group_key is not None
        and (
            not valid_controlled_stable_group_key(claimed_stable_group_key)
            or not valid_controlled_stable_group_key(
                alert["stable_group_key"]
            )
            or str(alert["stable_group_key"] or "")
            != claimed_stable_group_key
        )
    ):
        raise RuntimeError("durable AI claim stable group key is invalid")
    triage_level = str(alert["triage_level"] or "").strip().lower()
    if triage_level not in SEVERITY_PRIORITY:
        raise RuntimeError("durable AI claim alert identity is invalid")
    return (
        dict(claimed_payload),
        claimed_alert_id,
        resolved_group_id,
        triage_level,
    )


def require_controlled_claim_identity(
    args: argparse.Namespace,
    claimed_payload: dict[str, object],
    *,
    claimed_alert_id: str,
    claimed_group_id: str,
    claimed_job_id: int,
    expected_job_id: int,
) -> None:
    """Fail closed when a controlled run leases a different frozen member."""
    expected_group_id = str(
        getattr(args, "only_group_id", "") or ""
    ).strip().lower()
    expected_alert_id = str(
        getattr(args, "only_alert_id", "") or ""
    ).strip()
    expected_stable_group_key = str(
        getattr(args, "only_stable_group_key", "") or ""
    )
    expected_dispatch_id = str(
        getattr(args, "only_dispatch_id", "") or ""
    ).strip()
    configured_identity = (
        bool(expected_group_id),
        bool(expected_alert_id),
        bool(expected_stable_group_key),
        bool(expected_dispatch_id),
    )
    if not any(configured_identity):
        return
    if not all(configured_identity):
        raise ControlledClaimRejected(
            "controlled AI run identity arguments are incomplete"
        )
    if not valid_controlled_stable_group_key(expected_stable_group_key):
        raise ControlledClaimRejected(
            "controlled AI run stable group key is invalid"
        )
    require_controlled_release_attestation(claimed_payload)
    controlled_job_route_contract(args, claimed_payload)

    if (
        int(claimed_job_id or 0) != int(expected_job_id or 0)
        or int(expected_job_id or 0) < 1
    ):
        raise ControlledClaimRejected(
            "controlled AI claim job identity did not match the selected job"
        )

    payload_group_id = str(
        claimed_payload.get("group_id") or ""
    ).strip().lower()
    payload_stable_group_id = str(
        claimed_payload.get("stable_group_id") or ""
    ).strip().lower()
    if (
        str(claimed_group_id or "").strip().lower() != expected_group_id
        or payload_group_id != expected_group_id
        or payload_stable_group_id != expected_group_id
    ):
        raise ControlledClaimRejected(
            "controlled AI claim group identity did not match --only-group-id"
        )

    payload_alert_id = str(claimed_payload.get("alert_id") or "").strip()
    payload_representative_alert_id = str(
        claimed_payload.get("representative_alert_id") or ""
    ).strip()
    if (
        str(claimed_alert_id or "").strip() != expected_alert_id
        or payload_alert_id != expected_alert_id
        or payload_representative_alert_id != expected_alert_id
    ):
        raise ControlledClaimRejected(
            "controlled AI claim alert identity did not match --only-alert-id"
        )

    if (
        not valid_controlled_stable_group_key(
            claimed_payload.get("stable_group_key")
        )
        or claimed_payload.get("stable_group_key")
        != expected_stable_group_key
    ):
        raise ControlledClaimRejected(
            "controlled AI claim stable group key did not match "
            "--only-stable-group-key"
        )

    payload_dispatch_id = str(
        claimed_payload.get("dispatch_id") or ""
    ).strip()
    if payload_dispatch_id != expected_dispatch_id:
        raise ControlledClaimRejected(
            "controlled AI claim dispatch identity did not match "
            "--only-dispatch-id"
        )


def _strict_ai_settings_module() -> Any:
    """Load the analysis runner so both processes use one settings parser."""

    global _STRICT_AI_SETTINGS_MODULE
    if _STRICT_AI_SETTINGS_MODULE is not None:
        return _STRICT_AI_SETTINGS_MODULE
    runner_path = (BIN_DIR / "run-local-ai-analysis.py").resolve(strict=True)
    module_name = (
        "_onion_sentinel_strict_ai_settings_"
        + hashlib.sha256(str(runner_path).encode("utf-8")).hexdigest()[:16]
    )
    module = sys.modules.get(module_name)
    if module is None:
        spec = importlib.util.spec_from_file_location(module_name, runner_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("analysis runner settings loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(module_name, None)
            raise
    if not callable(getattr(module, "load_ai_settings", None)) or not callable(
        getattr(module, "enabled_agent_model_routes", None)
    ):
        raise RuntimeError("analysis runner settings loader is incomplete")
    _STRICT_AI_SETTINGS_MODULE = module
    return module


def _strict_controlled_ai_settings(
    settings_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    """Return runner-normalized settings plus exact persisted assignments."""

    runner = _strict_ai_settings_module()
    return strict_controlled_ai_settings(
        settings_path,
        MAX_AI_SETTINGS_BYTES,
        StrictSettingsSources(
            load_ai_settings=runner.load_ai_settings,
            read_bytes_bounded=runner.read_bytes_bounded,
            enabled_agent_model_routes=runner.enabled_agent_model_routes,
            max_settings_bytes=runner.DEFAULT_MAX_SETTINGS_BYTES,
        ),
    )


def controlled_job_route_contract(
    args: argparse.Namespace,
    job_payload: dict[str, object],
) -> dict[str, object]:
    """Compatibility delegate for canonical enabled route binding."""
    settings_path = Path(
        getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS)
    )
    return validate_job_route_contract(
        ControlledRoutePolicy(model_route_pattern=CONTROLLED_MODEL_ROUTE_RE),
        ControlledRouteSources(
            load_settings=lambda: _strict_controlled_ai_settings(
                settings_path
            ),
            reject=ControlledClaimRejected,
            settings_errors=(
                OSError,
                UnicodeError,
                ValueError,
                TypeError,
                RuntimeError,
            ),
        ),
        job_payload,
    )


def controlled_claim_expectations(
    args: argparse.Namespace,
    selected: sqlite3.Row,
    job_payload: dict[str, object],
) -> dict[str, object]:
    """Compatibility delegate for exact frozen candidate validation."""
    return validate_claim_expectations(
        ControlledClaimSources(
            stable_group_key_valid=valid_controlled_stable_group_key,
            require_release=require_controlled_release_attestation,
            route_contract=lambda payload: controlled_job_route_contract(
                args, payload
            ),
            reject=ControlledClaimRejected,
        ),
        args,
        selected,
        job_payload,
    )


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def run_command(
    cmd: list[str],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int = DEFAULT_MAX_CHILD_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_CHILD_STDERR_BYTES,
    env: dict[str, str] | None = None,
    progress_callback=None,
    progress_interval_seconds: float = 30,
):
    """Run one trusted helper with bounded time, memory, and descendants."""
    print("running:", " ".join(cmd), flush=True)
    return run_bounded_command(
        cmd,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        env=env,
        progress_callback=progress_callback,
        progress_interval_seconds=progress_interval_seconds,
    )


def collect_incident_evidence(alert_id: str, args: argparse.Namespace, *, progress_callback=None) -> Path:
    collector = Path(__file__).with_name("collect-incident-evidence.py")
    proc = run_command(
        [
            sys.executable,
            str(collector),
            "--alert-id",
            alert_id,
            "--db",
            str(args.db),
            "--config",
            str(args.incident_evidence_config),
            "--out-dir",
            str(args.incident_evidence_dir),
        ],
        timeout_seconds=360,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
        progress_callback=progress_callback,
        progress_interval_seconds=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"incident evidence collector failed rc={proc.returncode}")
    output_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError("incident evidence collector returned no artifact path")
    artifact = Path(output_lines[-1])
    try:
        artifact.resolve().relative_to(args.incident_evidence_dir.resolve())
    except ValueError as exc:
        raise RuntimeError("incident evidence collector returned a path outside its configured directory") from exc
    if not artifact.is_file():
        raise RuntimeError("incident evidence collector did not publish its artifact")
    return artifact


def build_prompt(
    alert_id: str,
    args: argparse.Namespace,
    job_payload: dict[str, object] | None = None,
    incident_evidence_path: Path | None = None,
) -> Path:
    builder = Path(__file__).with_name("build-ai-investigation-prompt.py")
    job_payload = job_payload or {}
    related_limit = bounded_int(job_payload.get("related_limit"), args.related_limit, 1, 500)
    pcap_analysis_limit = bounded_int(job_payload.get("pcap_analysis_limit"), 8, 1, 25)
    agent_role = str(job_payload.get("agent_role") or "soc-analyst")
    prompt_limit = effective_initial_prompt_package_limit(
        args,
        agent_role=agent_role,
    )
    config_dir = Path(args.ai_settings_file).parent
    cmd = [
        sys.executable,
        str(builder),
        "--db",
        str(getattr(args, "db", DEFAULT_DB)),
        "--alert-id",
        alert_id,
        "--out-dir",
        str(args.prompt_dir),
        "--rollup-dir",
        str(getattr(args, "rollup_dir", DEFAULT_ROLLUP_DIR)),
        "--related-limit",
        str(related_limit),
        "--correlation-limit",
        str(args.correlation_limit),
        "--correlation-min-score",
        str(args.correlation_min_score),
        "--pcap-analysis-limit",
        str(pcap_analysis_limit),
        "--max-package-bytes",
        str(prompt_limit),
        "--agent-role",
        agent_role,
        "--system-prompt-file",
        str(role_prompt_file(config_dir, agent_role)),
        "--second-opinion-prompt-file",
        str(role_second_opinion_prompt_file(config_dir, agent_role)),
        "--agent-memory-file",
        str(
            role_memory_file(
                getattr(args, "agent_memory_dir", DEFAULT_AGENT_MEMORY_DIR),
                agent_role,
            )
        ),
        "--shared-memory-file",
        str(getattr(args, "shared_memory_file", DEFAULT_SHARED_MEMORY_FILE)),
        "--pcap-analysis-dir",
        str(getattr(args, "pcap_analysis_dir", DEFAULT_PCAP_ANALYSIS_DIR)),
        "--analysis-dir",
        str(getattr(args, "prior_analysis_dir", DEFAULT_ANALYSIS_DIR)),
        "--asset-inventory-file",
        str(getattr(args, "asset_inventory_file", DEFAULT_ASSET_INVENTORY_FILE)),
        "--detection-playbooks",
        str(
            getattr(
                args,
                "detection_playbooks",
                DEFAULT_DETECTION_PLAYBOOKS,
            )
        ),
        "--investigation-skills",
        str(
            getattr(
                args,
                "investigation_skills",
                DEFAULT_INVESTIGATION_SKILLS,
            )
        ),
    ]
    if incident_evidence_path is not None:
        cmd.extend(["--incident-evidence-file", str(incident_evidence_path)])
    if job_payload.get("manual_reanalysis") is True:
        cmd.append("--blind-reanalysis")
    if args.include_tests:
        cmd.append("--include-tests")
    proc = run_command(
        cmd,
        timeout_seconds=180,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
    )
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        # Preserve the bounded terminal diagnostic so deterministic admission
        # failures (especially an irreducibly oversized package) are retired
        # instead of being retried forever under the generic wrapper error.
        stderr_lines = [
            line.strip()
            for line in str(proc.stderr or "").splitlines()
            if line.strip()
        ]
        detail = stderr_lines[-1][:700] if stderr_lines else ""
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"prompt builder failed rc={proc.returncode}{suffix}"
        )
    output_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError("prompt builder returned no output path")
    prompt_path = Path(output_lines[-1])
    if not prompt_path.exists():
        raise RuntimeError(f"prompt builder did not create a prompt package: {prompt_path}")
    try:
        prompt_path.resolve().relative_to(args.prompt_dir.resolve())
    except ValueError as exc:
        raise RuntimeError("prompt builder returned a path outside the configured prompt directory") from exc
    if prompt_path.stat().st_size > prompt_limit:
        raise RuntimeError(
            f"prompt package exceeded the {prompt_limit}-byte worker limit"
        )
    return prompt_path


def analysis_command(
    prompt_path: Path,
    args: argparse.Namespace,
    *,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
) -> list[str]:
    agent_role = str(agent_role or "soc-analyst")
    runner = Path(__file__).with_name("run-local-ai-analysis.py")
    cmd = [
        sys.executable,
        str(runner),
        "--prompt-package",
        str(prompt_path),
        "--prompt-dir",
        str(getattr(args, "prompt_dir", DEFAULT_PROMPT_DIR)),
        "--out-dir",
        str(args.analysis_dir),
        "--timeout",
        str(args.timeout),
        "--max-prompt-bytes",
        str(
            effective_prompt_package_limit(
                args,
                agent_role=agent_role,
            )
        ),
        "--alert-store-url",
        args.alert_store_url,
        "--ai-settings-file",
        str(args.ai_settings_file),
        "--investigation-harness-policy",
        str(
            getattr(
                args,
                "investigation_harness_policy",
                DEFAULT_INVESTIGATION_HARNESS_POLICY,
            )
        ),
        "--system-prompt-file",
        str(
            role_prompt_file(
                Path(args.ai_settings_file).parent,
                agent_role,
            )
        ),
        "--second-opinion-prompt-file",
        str(
            role_second_opinion_prompt_file(
                Path(args.ai_settings_file).parent,
                agent_role,
            )
        ),
        "--disagreement-adjudicator-prompt-file",
        str(
            getattr(
                args,
                "disagreement_adjudicator_prompt_file",
                DEFAULT_DISAGREEMENT_ADJUDICATOR_PROMPT,
            )
        ),
        "--live-osquery-config",
        str(getattr(args, "live_osquery_config", DEFAULT_LIVE_OSQUERY_CONFIG)),
        "--incident-evidence-config",
        str(
            getattr(
                args,
                "incident_evidence_config",
                DEFAULT_INCIDENT_EVIDENCE_CONFIG,
            )
        ),
        "--investigation-pivot-dir",
        str(
            getattr(
                args,
                "investigation_pivot_dir",
                DEFAULT_INVESTIGATION_PIVOT_DIR,
            )
        ),
    ]
    if args.model:
        cmd.extend(["--model", args.model])
    if reanalysis_attempt_id:
        cmd.extend(["--reanalysis-attempt-id", reanalysis_attempt_id])
    return cmd


def run_analysis(
    prompt_path: Path,
    args: argparse.Namespace,
    *,
    progress_callback=None,
    reanalysis_attempt_id: str = "",
    agent_role: str = "",
    controlled_result_identity: dict[str, object] | None = None,
):
    cmd = analysis_command(
        prompt_path,
        args,
        reanalysis_attempt_id=reanalysis_attempt_id,
        agent_role=agent_role,
    )
    # One durable analysis may now include the initial inference, as many as
    # three bounded evidence-pivot follow-ups, and an independent review.  The
    # child enforces the per-call timeout and query budgets; this outer watchdog
    # must not terminate a healthy multi-turn investigation after only one
    # model-call allowance.
    worker_timeout = (args.timeout * 5) + 300
    child_environment = None
    if controlled_result_identity:
        field_environment = {
            "job_id": "ONION_SENTINEL_EVALUATION_JOB_ID",
            "job_type": "ONION_SENTINEL_EVALUATION_JOB_TYPE",
            "lease_token": "ONION_SENTINEL_EVALUATION_LEASE_TOKEN",
            "cohort_id": "ONION_SENTINEL_EVALUATION_COHORT_ID",
            "dispatch_id": "ONION_SENTINEL_EVALUATION_DISPATCH_ID",
            "representative_alert_id": (
                "ONION_SENTINEL_EVALUATION_REPRESENTATIVE_ALERT_ID"
            ),
            "stable_group_id": (
                "ONION_SENTINEL_EVALUATION_STABLE_GROUP_ID"
            ),
            "stable_group_key": (
                "ONION_SENTINEL_EVALUATION_STABLE_GROUP_KEY"
            ),
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
            "reviewer_required": (
                "ONION_SENTINEL_EVALUATION_REVIEWER_REQUIRED"
            ),
        }
        child_environment = dict(os.environ)
        evaluation_token = (
            str(
                os.environ.get(CONTROLLED_EVALUATION_TOKEN_ENV)
                or ""
            ).strip()
            or _CONTROLLED_EVALUATION_TOKEN
        )
        if CONTROLLED_EVALUATION_TOKEN_RE.fullmatch(evaluation_token):
            child_environment[
                CONTROLLED_EVALUATION_TOKEN_ENV
            ] = evaluation_token
        child_environment["TMPDIR"] = str(os.environ["TMPDIR"])
        for field, environment_key in field_environment.items():
            value = controlled_result_identity.get(field)
            child_environment[environment_key] = (
                "1" if field == "reviewer_required" and value is True
                else str(value or "")
            )
    return run_command(
        cmd,
        timeout_seconds=worker_timeout,
        max_stdout_bytes=DEFAULT_MAX_CHILD_STDOUT_BYTES,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
        env=child_environment,
        progress_callback=progress_callback,
        progress_interval_seconds=60,
    )


def flush_deferred_analysis_results(args: argparse.Namespace) -> None:
    """Publish locally spooled result indexes before scheduling new GPU work."""
    runner = Path(__file__).with_name("run-local-ai-analysis.py")
    proc = run_command(
        [
            sys.executable,
            str(runner),
            "--flush-index-only",
            "--alert-store-url",
            args.alert_store_url,
        ],
        timeout_seconds=60,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=1024 * 1024,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"rc={proc.returncode}"
        raise RuntimeError(f"deferred analysis index flush failed: {detail}")


def signal_dashboard_refresh(
    args: argparse.Namespace,
    *,
    controlled_evaluation: bool = False,
) -> None:
    """Wake the independent portal worker without delaying local inference.

    The Web UI polls fast-changing AI state from the API. Static dashboard
    generation is therefore eventual presentation work and must never sit on
    the alert-analysis critical path.
    """
    if (
        args.no_portal_refresh
        or controlled_evaluation
    ):
        return
    try:
        args.portal_wake_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.portal_wake_file.write_text(f"{project_now()} ai-analysis-complete\n", encoding="utf-8")
        args.portal_wake_file.chmod(0o600)
    except OSError as error:
        # Durable AI completion remains authoritative even if presentation
        # refresh signaling is temporarily unavailable.
        print(f"dashboard refresh signal failed: {error}", file=sys.stderr)


def consume_wake_marker(path: Path) -> None:
    """Clear the event that launched this run so later work is not lost.

    If durable work arrives while the worker is active, alert-store recreates
    the marker. launchd then observes a pending path event and starts another
    pass after this process exits.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        print(f"AI wake marker could not be consumed: {error}", file=sys.stderr)


def maintenance_drain_active(path: Path) -> tuple[bool, str]:
    """Fail closed when a maintenance marker exists but is not trustworthy.

    The marker is an operator control, not job input.  Requiring an owner-only
    regular file prevents another local account, directory swap, or symlink
    from silently controlling scheduler availability.  An unsafe marker still
    drains the worker so an operator can repair it without new claims racing
    the maintenance window.
    """
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False, ""
    except OSError as error:
        return True, f"maintenance drain marker cannot be inspected: {error}"
    if not stat.S_ISREG(metadata.st_mode):
        return True, "maintenance drain marker is not a regular file"
    if metadata.st_uid != os.getuid():
        return True, "maintenance drain marker is not owned by the worker account"
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        return True, "maintenance drain marker is not owner-only"
    if metadata.st_size > 4096:
        return True, "maintenance drain marker exceeds its byte limit"
    return True, "maintenance drain requested"


def stop_for_maintenance_drain(path: Path) -> bool:
    active, detail = maintenance_drain_active(path)
    if active:
        print(f"{project_now()} {detail}; no additional AI work will be claimed", flush=True)
    return active


def reconcile_worker_state(
    args: argparse.Namespace,
    indexed_mode: bool,
    *,
    controlled_evaluation: bool = False,
) -> int:
    """Reconcile durable queue state without scanning artifacts in modern mode."""
    if controlled_evaluation:
        # A controlled cohort invocation owns exactly one freshly dispatched
        # durable job. Global reconciliation could otherwise complete unrelated
        # production jobs whose older artifacts happen to be current.
        return 0
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        if indexed_mode:
            completed_group_ids = indexed_reconcilable_ai_job_ids(conn)
        else:
            analyzed_ids = analyzed_alert_ids(args.analysis_dir, args.pcap_analysis_dir, args.prompt_dir)
            completed_group_ids = reconcilable_ai_job_ids(
                conn,
                analyzed_ids,
                args.analysis_dir,
                args.pcap_analysis_dir,
                args.prompt_dir,
            )
    finally:
        conn.close()
    return reconcile_completed_ai_jobs(args.alert_store_url, completed_group_ids)


def terminal_success_recovery_candidates(
    alert_conn: sqlite3.Connection,
    harness_conn: sqlite3.Connection,
    provider_lane: str,
    *,
    limit: int = 32,
) -> list[dict[str, object]]:
    """Compatibility delegate for exact terminal-success proof."""
    return load_terminal_success_recovery_candidates(
        alert_conn,
        harness_conn,
        provider_lane,
        limit=limit,
    )


def scheduler_read_only_connection(path: Path) -> sqlite3.Connection:
    """Open a SQLite database without granting mutation capability."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def terminal_recovery_sources() -> TerminalRecoverySources:
    """Bind recovery services at call time for compatibility and testing."""
    return TerminalRecoverySources(
        connect_read_only=scheduler_read_only_connection,
        path_exists=lambda path: path.exists(),
        load_candidates=load_terminal_success_recovery_candidates,
        report_status=report_ai_job_status,
    )


def reconcile_terminal_success_durable_jobs(args: argparse.Namespace) -> int:
    """Compatibility delegate for exact stranded-lease recovery."""
    provider_lane = str(getattr(args, "provider_lane", "any") or "any")
    harness_db = Path(
        getattr(args, "harness_db", args.db.parent / "investigation-harness.sqlite3")
    )
    return reconcile_terminal_success(
        terminal_recovery_sources(),
        alert_db=args.db,
        harness_db=harness_db,
        provider_lane=provider_lane,
        alert_store_url=args.alert_store_url,
    )


def detect_indexed_scheduler_mode(path: Path) -> bool:
    """Inspect scheduler schema without granting database mutation access."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return indexed_scheduler_available(conn)
    finally:
        conn.close()


def scheduler_startup_sources() -> SchedulerStartupSources:
    """Bind startup services at call time for compatibility and testing."""
    return SchedulerStartupSources(
        stop_for_drain=stop_for_maintenance_drain,
        controlled_runtime=controlled_evaluation_runtime,
        consume_controlled_token=consume_controlled_evaluation_token,
        require_capacity=require_runtime_capacity,
        path_exists=lambda path: path.exists(),
        consume_wake_marker=consume_wake_marker,
        detect_indexed_mode=detect_indexed_scheduler_mode,
        recover_controlled_spool=recover_controlled_evaluation_spool,
        flush_deferred_results=flush_deferred_analysis_results,
        recover_terminal_success=reconcile_terminal_success_durable_jobs,
        reconcile_worker_state=reconcile_worker_state,
        emit=lambda message: print(message, flush=True),
        emit_error=lambda message: print(message, file=sys.stderr),
        now=project_now,
    )


def scheduler_settlement_sources() -> SchedulerSettlementSources:
    """Bind post-drain settlement effects at call time."""
    return SchedulerSettlementSources(
        signal_dashboard_refresh=signal_dashboard_refresh,
        reconcile_worker_state=reconcile_worker_state,
        emit=lambda message: print(message, flush=True),
        emit_error=lambda message: print(message, file=sys.stderr),
        now=project_now,
        controlled_failure_exit_code=CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
    )


def scheduler_claim_sources() -> SchedulerClaimSources:
    """Bind exact claim and server-authoritative identity services."""
    return SchedulerClaimSources(
        exact_expectations=controlled_claim_expectations,
        report_status=report_ai_job_status,
        load_claimed_job=claimed_durable_ai_job,
        require_controlled_identity=require_controlled_claim_identity,
        job_reanalysis_attempt_id=job_reanalysis_attempt_id,
        emit=lambda message: print(message, flush=True),
        now=project_now,
    )


def scheduler_execution_sources() -> SchedulerExecutionSources:
    """Bind evidence, prompt, lease-renewal, and runner services."""
    return SchedulerExecutionSources(
        report_status=report_ai_job_status,
        validate_controlled_route=controlled_job_route_contract,
        collect_incident_evidence=collect_incident_evidence,
        build_prompt=build_prompt,
        reusable_prompt=reusable_prompt_for_alert,
        run_analysis=run_analysis,
    )


def scheduler_outcome_sources() -> SchedulerOutcomeSources:
    """Bind status reporting, spool recovery, and output effects."""
    return SchedulerOutcomeSources(
        report_status=report_ai_job_status,
        failure_is_retryable=ai_failure_is_retryable,
        recover_controlled_spool=recover_controlled_evaluation_spool,
        controlled_spool_pending=controlled_recovery_spool_pending,
        now=project_now,
        emit=lambda message: print(message, flush=True),
        emit_error=lambda message: print(message, file=sys.stderr),
        write_stdout=lambda message: print(message, end=""),
        write_stderr=lambda message: print(message, file=sys.stderr, end=""),
        result_submission_indeterminate_marker=(
            CONTROLLED_RESULT_SUBMISSION_INDETERMINATE
        ),
    )


def scheduler_drain_sources() -> SchedulerDrainSources:
    """Bind queue selection and drain-loop projection services."""
    def open_readonly_database(database_path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        return connection

    return SchedulerDrainSources(
        stop_for_drain=stop_for_maintenance_drain,
        configured_levels=configured_analysis_levels,
        open_readonly_database=open_readonly_database,
        select_indexed=select_next_alert_indexed,
        select_legacy=select_next_alert,
        analyzed_alert_ids=analyzed_alert_ids,
        alert_group_key=alert_group_key,
        alert_group_id=alert_group_id,
        durable_payload=durable_payload,
        now=project_now,
        emit=lambda message: print(message, flush=True),
    )


def scheduler_worker_sources() -> SchedulerWorkerSources:
    """Bind the per-selection scheduler application workflow."""
    return SchedulerWorkerSources(
        acquire_claim=acquire_scheduler_claim,
        claim_sources=scheduler_claim_sources,
        execute_analysis=execute_scheduler_analysis,
        execution_sources=scheduler_execution_sources,
        handle_process_outcome=handle_process_outcome,
        handle_claim_rejection=handle_controlled_claim_rejection,
        handle_exception=handle_scheduler_exception,
        outcome_sources=scheduler_outcome_sources,
        controlled_claim_error=ControlledClaimRejected,
        execution_errors=(BoundedProcessError, RuntimeError, OSError),
    )


def main() -> int:
    args = parse_args()
    startup_sources = scheduler_startup_sources()
    preflight = prepare_scheduler_run(
        startup_sources,
        args,
        drain_file=getattr(args, "drain_file", DEFAULT_DRAIN),
    )
    if not preflight.proceed:
        return preflight.exit_code
    controlled_evaluation_dir = preflight.controlled_evaluation_dir
    launch_levels = preflight.launch_levels

    args.lock_file.parent.mkdir(parents=True, exist_ok=True)
    with args.lock_file.open("w") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"{project_now()} another AI analysis run is already active")
            return 0

        initialization = initialize_scheduler_run(
            startup_sources,
            args,
            controlled_evaluation_dir=controlled_evaluation_dir,
        )
        if not initialization.proceed:
            return 0
        indexed_mode = initialization.indexed_mode
        drain_state = SchedulerDrainState()
        while True:
            selection = select_scheduler_work(
                scheduler_drain_sources(),
                args,
                drain_state,
                indexed_mode=indexed_mode,
                launch_levels=launch_levels,
                drain_file=getattr(args, "drain_file", DEFAULT_DRAIN),
            )
            if selection.disposition != "selected":
                break
            if process_scheduler_selection(
                scheduler_worker_sources(),
                args,
                drain_state,
                selection,
                indexed_mode=indexed_mode,
                controlled_evaluation_dir=controlled_evaluation_dir,
            ):
                break

        return settle_scheduler_run(
            scheduler_settlement_sources(),
            args,
            SchedulerSettlement(
                analyzed_count=drain_state.analyzed_count,
                indexed_mode=indexed_mode,
                controlled_evaluation=controlled_evaluation_dir is not None,
                controlled_owned_job_failed=(
                    drain_state.controlled_owned_job_failed
                ),
                controlled_failure_detail=drain_state.controlled_failure_detail,
                controlled_failure_group_id=(
                    drain_state.controlled_failure_group_id
                ),
            ),
        )


if __name__ == "__main__":
    raise SystemExit(main())
