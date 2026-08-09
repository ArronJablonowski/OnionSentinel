#!/usr/bin/env python3
"""Freeze and orchestrate a bounded Onion Sentinel agent evaluation cohort.

This utility deliberately does not grade investigation semantics.  It provides
the reproducible control plane around an evaluation:

* choose the newest distinct stable detection groups from SQLite in read-only
  mode;
* freeze dashboard/stable identities and pre-run state in an owner-only,
  digest-bound manifest;
* enqueue each member once through the loopback dashboard API, using a
  single-group SOC analysis, incident escalation, or single-case reanalysis
  endpoint;
* monitor the exact case/run identities returned by the API; and
* export bounded result metadata and cryptographic digests without exporting
  prompts, raw responses, queries, evidence rows, credentials, or job payloads.

It never connects to Security Onion and it never writes the alert database.
All database connections use SQLite ``mode=ro`` plus ``PRAGMA query_only``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))
from cohort_freezing import (
    CohortFreezePolicy,
    CohortFreezeSources,
    freeze_cohort as run_freeze_cohort,
    freeze_cohort_from_rows as run_freeze_cohort_from_rows,
)
from cohort_dispatch_contract import (
    CohortDispatchContract,
    request_for_member as build_dispatch_request,
    validate_dispatch_job_payload as validate_job_payload,
    validate_success_response as validate_dispatch_response,
)
from cohort_dispatch_readback import (
    CohortDispatchReadbackSources,
    verify_dispatch_readback as prove_dispatch_readback,
)
from cohort_dispatch_workflow import (
    CohortDispatchSources,
    Poster,
    queue_cohort as run_queue_cohort,
)
from cohort_http import (
    CohortHttpPolicy,
    HttpResult,
    dashboard_post_json as post_dashboard_json,
    load_evaluation_token as read_evaluation_token,
    validate_loopback_base_url as validate_dashboard_base_url,
)
from cohort_monitor_binding import (
    CohortMonitorBindingSources,
    monitor_dispatch_job_binding as prove_monitor_dispatch_binding,
)
from cohort_monitor_contract import (
    CohortMonitorContract,
    durable_job_monitor_state as resolve_durable_job_monitor_state,
    validate_completed_analysis_job_window as validate_analysis_job_window,
)
from cohort_monitor_workflow import (
    CohortMonitorSources,
    monitor_cohort as run_monitor_cohort,
    monitor_cohort_once as run_monitor_cohort_once,
    monitor_member as observe_monitor_member,
)
from cohort_execution_models import (
    ModelExecutionPolicy,
    evaluate_model_execution,
)
from cohort_execution_skills import (
    SkillAttestationPolicy,
    validate_skill_attestation,
)
from cohort_execution_tools import evaluate_tool_execution
from cohort_execution_trace import (
    TraceExecutionExpectation,
    TraceExecutionPolicy,
    evaluate_trace_execution,
)
from cohort_execution_render import ExecutionProofView, render_execution_proof
from cohort_execution_result import (
    ResultExecutionPolicy,
    evaluate_result_execution,
    expected_task_kind as resolve_expected_task_kind,
    prior_analysis_ids as collect_prior_analysis_ids,
)
from cohort_export import (
    CohortExportSources,
    export_cohort as run_export_cohort,
)
from cohort_query_audit_projection import project_query_audit
from cohort_evaluation_query_audit import (
    QueryAuditPolicy,
    query_audit_execution_binding as normalize_query_audit_binding,
)
from cohort_execution_proof_service import (
    ExecutionProofPolicy,
    build_execution_proof,
)
from cohort_analysis_metadata import (
    AnalysisMetadataPolicy,
    load_analysis_metadata,
)
from cohort_preflight import (
    MemberPreflightSources,
    RepresentativeBindingPolicy,
    validate_member_preflight as run_member_preflight,
    validate_representative_binding as prove_representative_binding,
)
from cohort_dispatch_identity import (
    DispatchIdentityPolicy,
    deterministic_dispatch_id as derive_dispatch_id,
)
from cohort_manifest_contract import (
    ManifestContractPolicy,
    execution_contract as build_execution_contract,
    frozen_plan_digest as calculate_frozen_plan_digest,
    member_stable_group_key as resolve_member_stable_group_key,
    ordered_identity_projection as project_ordered_identity,
    validate_agent_role as validate_manifest_agent_role,
    validate_cohort_identity as validate_manifest_identity,
    validate_manifest_document,
    validate_model_route as validate_manifest_model_route,
    validate_release_id as validate_manifest_release_id,
    validate_stable_group_key as validate_manifest_stable_group_key,
)
from cohort_private_input import (
    CohortPrivateInputPolicy,
    load_private_manifest as read_private_manifest,
    load_private_source_rows as read_private_source_rows,
)
from cohort_runner_cli import (
    CohortCliOperations,
    build_parser as build_cli_parser,
    main as run_cli,
)
from cohort_artifact_io import (
    AlertStoreReceiptPolicy,
    DigestArtifactPolicy,
    alert_store_response_sha256 as verify_alert_store_response_sha256,
    digest_bound as bind_artifact_digest,
    validate_digest as validate_artifact_digest,
    write_private_json as persist_private_json,
)
from cohort_storage_core import (
    CohortStoragePolicy,
    connect_read_only as open_cohort_database_read_only,
    load_aliases as read_group_aliases,
    require_columns as require_storage_columns,
    resolve_alias as resolve_group_alias,
    schema_fingerprint as calculate_schema_fingerprint,
    table_columns as storage_table_columns,
    table_exists as storage_table_exists,
)
from cohort_storage_state import (
    CohortStatePolicy,
    active_jobs as query_active_jobs,
    active_reanalysis as query_active_reanalysis,
    analysis_ids_for_group as query_analysis_ids_for_group,
    durable_dispatch_job as read_durable_dispatch_job,
    durable_job_snapshot as read_durable_job_snapshot,
    frozen_analysis_ids as read_frozen_analysis_ids,
    incident_cases as query_incident_cases,
    incident_pre_state as build_incident_pre_state,
    latest_analysis_metadata as read_latest_analysis_metadata,
    soc_pre_state as build_soc_pre_state,
    summary_rows as query_summary_rows,
    verify_zero_fresh_analyses as prove_zero_fresh_analyses,
)
from cohort_source_rows import (
    CohortSourceRowPolicy,
    source_detection_projection as project_source_detection,
    source_identity as read_source_identity,
    validate_source_detection as prove_source_detection,
    validate_source_pre_state as prove_source_pre_state,
)
from cohort_representative_state import (
    CohortRepresentativeStatePolicy,
    alert_representative_identity as read_alert_representative_identity,
    bind_representative_stable_group_key as bind_stable_group_key,
    case_for_stable as read_case_for_stable,
    current_summary_identity as read_current_summary_identity,
)
from cohort_second_opinion_state import (
    second_opinion_metadata as read_second_opinion_metadata,
)
from cohort_runner_contracts import (
    ACTIVE_AGENT_STATES,
    ACTIVE_JOB_STATES,
    ACTIVE_REANALYSIS_STATES,
    AGENT_ROLES,
    ALERT_STORE_CANONICAL_SHA256_JS,
    CASE_ID_RE,
    COHORT_ID_RE,
    CONTROLLED_EVALUATION_PROFILE,
    CONTROLLED_ROUTE_RE,
    DASHBOARD_GROUP_ID_RE,
    DISPATCH_ID_SCHEMA,
    EXPORT_SCHEMA,
    FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    MAX_COHORT_SIZE,
    MAX_EVALUATION_TOKEN_BYTES,
    MAX_HTTP_BODY_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_RUNTIME_MODEL_CALLS,
    MAX_SOURCE_ROWS_BYTES,
    MAX_STABLE_GROUP_KEY_BYTES,
    MAX_STORED_RESPONSE_BYTES,
    MODEL_CALL_CONTRACT_SCHEMA,
    PROFILE_ASSIGNED_ROUTE,
    PROFILE_REVIEWER_ROUTE,
    RELEASE_ID_RE,
    REPRESENTATIVE_ALERT_ID_RE,
    REPRESENTATIVE_BINDING_SCHEMA,
    RUN_ID_RE,
    SAFE_ROUTE_RE,
    SCHEMA,
    SHA256_RE,
    SKILL_ID_RE,
    STABLE_GROUP_ID_RE,
    TERMINAL_MONITOR_STATES,
    AmbiguousDispatchError,
    CohortError,
    canonical_bytes,
    constant_time_equal,
    sha256_value,
    utc_now,
)


TRACE_EVALUATOR_PATH = Path(__file__).with_name("evaluate-harness-traces.py")


def alert_store_response_sha256(raw_response: str) -> str:
    """Reproduce alert-store's JavaScript canonical response digest exactly.

    Python's JSON serializer cannot be used for this receipt comparison:
    ECMAScript differs in number formatting and orders object keys by UTF-16
    code units. Execute a fixed, input-only Node program so the observer proves
    the same byte representation that alert-store hashed at commit time.
    """

    return verify_alert_store_response_sha256(
        raw_response,
        AlertStoreReceiptPolicy(
            error=CohortError,
            maximum_response_bytes=MAX_STORED_RESPONSE_BYTES,
            sha256_pattern=SHA256_RE,
            canonical_sha256_javascript=ALERT_STORE_CANONICAL_SHA256_JS,
            node_candidates=(
            Path("/opt/homebrew/bin/node"),
            Path("/usr/local/bin/node"),
            Path("/usr/bin/node"),
            ),
        ),
    )


def _digest_artifact_policy() -> DigestArtifactPolicy:
    return DigestArtifactPolicy(
        error=CohortError,
        sha256_pattern=SHA256_RE,
        sha256_value=sha256_value,
        constant_time_equal=_constant_time_equal,
    )


def _digest_bound(document: Mapping[str, Any], field: str) -> dict[str, Any]:
    return bind_artifact_digest(document, field, _digest_artifact_policy())


def _validate_digest(document: Mapping[str, Any], field: str) -> None:
    validate_artifact_digest(document, field, _digest_artifact_policy())


def _constant_time_equal(left: str, right: str) -> bool:
    return constant_time_equal(left, right)


def write_private_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    digest_field: str,
    replace: bool = True,
) -> dict[str, Any]:
    """Atomically write a digest-bound JSON document with mode 0600."""

    return persist_private_json(
        path,
        document,
        digest_field=digest_field,
        policy=_digest_artifact_policy(),
        replace=replace,
    )


def _manifest_contract_policy() -> ManifestContractPolicy:
    return ManifestContractPolicy(
        error=CohortError,
        schema=SCHEMA,
        cohort_id_pattern=COHORT_ID_RE,
        safe_route_pattern=SAFE_ROUTE_RE,
        controlled_route_pattern=CONTROLLED_ROUTE_RE,
        release_id_pattern=RELEASE_ID_RE,
        sha256_pattern=SHA256_RE,
        agent_roles=frozenset(AGENT_ROLES),
        maximum_stable_group_key_bytes=MAX_STABLE_GROUP_KEY_BYTES,
        controlled_evaluation_profile=CONTROLLED_EVALUATION_PROFILE,
        profile_assigned_route=PROFILE_ASSIGNED_ROUTE,
        profile_reviewer_route=PROFILE_REVIEWER_ROUTE,
        sha256_value=sha256_value,
        constant_time_equal=_constant_time_equal,
    )


def _private_input_policy() -> CohortPrivateInputPolicy:
    policy = _manifest_contract_policy()
    return CohortPrivateInputPolicy(
        error=CohortError,
        maximum_manifest_bytes=MAX_MANIFEST_BYTES,
        maximum_source_rows_bytes=MAX_SOURCE_ROWS_BYTES,
        maximum_cohort_size=MAX_COHORT_SIZE,
        validate_manifest_document=lambda document: validate_manifest_document(
            document, policy
        ),
    )


def load_private_manifest(path: Path) -> dict[str, Any]:
    return read_private_manifest(path, _private_input_policy())


def load_private_source_rows(path: Path) -> tuple[list[dict[str, Any]], str]:
    return read_private_source_rows(path, _private_input_policy())


def validate_cohort_identity(cohort_id: str, reason: str) -> tuple[str, str]:
    return validate_manifest_identity(
        cohort_id, reason, _manifest_contract_policy()
    )


def validate_agent_role(value: str) -> str:
    return validate_manifest_agent_role(value, _manifest_contract_policy())


def validate_model_route(value: str, label: str, *, allow_empty: bool = False) -> str:
    return validate_manifest_model_route(
        value,
        label,
        _manifest_contract_policy(),
        allow_empty=allow_empty,
    )


def validate_release_id(value: Any, label: str = "expected release ID") -> str:
    return validate_manifest_release_id(
        value, _manifest_contract_policy(), label
    )


def validate_stable_group_key(value: Any, label: str) -> str:
    return validate_manifest_stable_group_key(
        value, label, _manifest_contract_policy()
    )


def _member_stable_group_key(member: Mapping[str, Any]) -> str:
    return resolve_member_stable_group_key(
        member, _manifest_contract_policy()
    )


def execution_contract(
    *,
    expected_release_id: str,
    expected_assigned_route: str,
    expected_reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
    evaluation_profile: str = "",
) -> dict[str, Any]:
    return build_execution_contract(
        expected_release_id=expected_release_id,
        expected_assigned_route=expected_assigned_route,
        expected_reviewer_route=expected_reviewer_route,
        evaluation_profile=evaluation_profile,
        policy=_manifest_contract_policy(),
    )


def ordered_identity_projection(
    members: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return project_ordered_identity(members, _manifest_contract_policy())


def _frozen_plan_digest(manifest: Mapping[str, Any]) -> str:
    return calculate_frozen_plan_digest(
        manifest, _manifest_contract_policy()
    )


def deterministic_dispatch_id(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> str:
    return derive_dispatch_id(
        manifest,
        member,
        DispatchIdentityPolicy(
            error=CohortError,
            cohort_id_pattern=COHORT_ID_RE,
            sha256_pattern=SHA256_RE,
            dashboard_group_id_pattern=DASHBOARD_GROUP_ID_RE,
            stable_group_id_pattern=STABLE_GROUP_ID_RE,
            representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
            dispatch_id_schema=DISPATCH_ID_SCHEMA,
            member_stable_group_key=_member_stable_group_key,
            sha256_value=sha256_value,
            constant_time_equal=_constant_time_equal,
        ),
    )


def _parse_timestamp(value: Any, label: str) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        raise CohortError(f"{label} is missing")
    text = re.sub(
        r"^(\d{4}-\d{2}-\d{2})\s+",
        r"\1T",
        text,
        count=1,
    )
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CohortError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise CohortError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def connect_read_only(database_path: Path) -> sqlite3.Connection:
    return open_cohort_database_read_only(database_path, _storage_policy())


def _storage_policy() -> CohortStoragePolicy:
    return CohortStoragePolicy(error=CohortError, sha256_value=sha256_value)


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return storage_table_exists(connection, table)


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return storage_table_columns(connection, table)


def _require_columns(
    connection: sqlite3.Connection,
    table: str,
    required: Iterable[str],
) -> set[str]:
    return require_storage_columns(
        connection, table, required, _storage_policy()
    )


def schema_fingerprint(connection: sqlite3.Connection) -> str:
    return calculate_schema_fingerprint(connection, _storage_policy())


def load_aliases(connection: sqlite3.Connection) -> dict[str, str]:
    return read_group_aliases(connection, _storage_policy())


def resolve_alias(identity: str, aliases: Mapping[str, str]) -> str:
    return resolve_group_alias(identity, aliases, _storage_policy())


SUMMARY_EXPORT_COLUMNS = (
    "group_id",
    "representative_alert_id",
    "first_seen",
    "last_seen",
    "timestamp",
    "rule_name",
    "event_dataset",
    "severity",
    "severity_label",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "network_protocol",
    "transport_protocol",
    "traffic_direction",
    "triage_score",
    "triage_level",
    "raw_alert_count",
    "total_seen_count",
)


def _summary_rows(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    return query_summary_rows(connection, _state_policy())


def _state_policy() -> CohortStatePolicy:
    return CohortStatePolicy(
        error=CohortError,
        ambiguous_error=AmbiguousDispatchError,
        storage=_storage_policy(),
        active_agent_states=frozenset(ACTIVE_AGENT_STATES),
    )


def _incident_cases(
    connection: sqlite3.Connection,
    aliases: Mapping[str, str],
) -> dict[str, list[dict[str, Any]]]:
    return query_incident_cases(connection, aliases, _state_policy())


def _active_jobs(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    *,
    job_type: str = "incident_response_analysis",
) -> list[dict[str, Any]]:
    return query_active_jobs(
        connection,
        stable_group_id,
        aliases,
        _state_policy(),
        job_type=job_type,
    )


def _durable_dispatch_job(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
) -> dict[str, Any]:
    return read_durable_dispatch_job(
        connection,
        job_type=job_type,
        stable_group_id=stable_group_id,
        policy=_state_policy(),
    )


def _durable_job_snapshot(
    connection: sqlite3.Connection,
    *,
    job_type: str,
    stable_group_id: str,
) -> dict[str, Any] | None:
    return read_durable_job_snapshot(
        connection,
        job_type=job_type,
        stable_group_id=stable_group_id,
        policy=_state_policy(),
    )


def _active_reanalysis(
    connection: sqlite3.Connection,
    stable_group_id: str,
    case_id: str,
    aliases: Mapping[str, str],
) -> list[dict[str, Any]]:
    return query_active_reanalysis(
        connection,
        stable_group_id,
        case_id,
        aliases,
        _state_policy(),
    )


def _analysis_ids_for_group(
    connection: sqlite3.Connection,
    stable_group_id: str,
    *,
    agent_role: str,
) -> list[str]:
    return query_analysis_ids_for_group(
        connection,
        stable_group_id,
        agent_role=agent_role,
        policy=_state_policy(),
    )


def _frozen_analysis_ids(
    member: Mapping[str, Any],
    *,
    agent_role: str,
    pre_state_field: str,
) -> set[str]:
    return read_frozen_analysis_ids(
        member,
        agent_role=agent_role,
        pre_state_field=pre_state_field,
        policy=_state_policy(),
    )


def _verify_zero_fresh_analyses(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
    stable_group_id: str,
    *,
    agent_role: str,
    pre_state_field: str,
) -> list[str]:
    return prove_zero_fresh_analyses(
        connection,
        member,
        stable_group_id,
        agent_role=agent_role,
        pre_state_field=pre_state_field,
        policy=_state_policy(),
    )


def _soc_pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
) -> dict[str, Any]:
    return build_soc_pre_state(
        connection, stable_group_id, aliases, _state_policy()
    )


def _latest_analysis_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
) -> dict[str, Any] | None:
    return read_latest_analysis_metadata(connection, analysis_id)


def _pre_state(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
    cases_by_stable: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    return build_incident_pre_state(
        connection,
        stable_group_id,
        aliases,
        cases_by_stable,
        _state_policy(),
    )


def freeze_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    cohort_id: str,
    reason: str,
    count: int,
    expected_release_id: str,
    expected_assigned_route: str = "codex-cli:gpt-5.5:high",
    expected_reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
    evaluation_profile: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Compatibility adapter for the extracted cohort-freezing workflow."""
    return run_freeze_cohort(
        _cohort_freeze_policy(),
        _cohort_freeze_sources(),
        database_path,
        manifest_path,
        cohort_id=cohort_id,
        reason=reason,
        count=count,
        expected_release_id=expected_release_id,
        expected_assigned_route=expected_assigned_route,
        expected_reviewer_route=expected_reviewer_route,
        evaluation_profile=evaluation_profile,
        dry_run=dry_run,
    )


def _source_identity(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return read_source_identity(row, _source_row_policy())


def _source_detection_projection(
    source: Mapping[str, Any],
) -> dict[str, Any]:
    return project_source_detection(source, _source_row_policy())


def _validate_source_detection(
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
) -> dict[str, Any]:
    return prove_source_detection(
        source,
        current,
        dashboard_id,
        _source_row_policy(),
    )


def _validate_source_pre_state(
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
) -> None:
    prove_source_pre_state(
        source,
        current,
        dashboard_id,
        _source_row_policy(),
    )


def _source_row_policy() -> CohortSourceRowPolicy:
    return CohortSourceRowPolicy(
        error=CohortError,
        dashboard_group_id_pattern=DASHBOARD_GROUP_ID_RE,
        stable_group_id_pattern=STABLE_GROUP_ID_RE,
        representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
        summary_export_columns=SUMMARY_EXPORT_COLUMNS,
    )


def _cohort_freeze_policy() -> CohortFreezePolicy:
    return CohortFreezePolicy(
        schema=SCHEMA,
        maximum_cohort_size=MAX_COHORT_SIZE,
        dashboard_group_id_pattern=DASHBOARD_GROUP_ID_RE,
        stable_group_id_pattern=STABLE_GROUP_ID_RE,
        representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
    )


def _cohort_freeze_sources() -> CohortFreezeSources:
    """Bind legacy patch points to the extracted freezing workflow."""
    return CohortFreezeSources(
        error_type=CohortError,
        validate_cohort_identity=validate_cohort_identity,
        validate_release_id=validate_release_id,
        validate_agent_role=validate_agent_role,
        connect_read_only=connect_read_only,
        load_aliases=load_aliases,
        incident_cases=_incident_cases,
        summary_rows=_summary_rows,
        resolve_alias=resolve_alias,
        bind_representative_stable_group_key=(
            _bind_representative_stable_group_key
        ),
        validate_stable_group_key=validate_stable_group_key,
        validate_representative_binding=_validate_representative_binding,
        incident_pre_state=_pre_state,
        soc_pre_state=_soc_pre_state,
        source_identity=_source_identity,
        source_detection_projection=_source_detection_projection,
        validate_source_detection=_validate_source_detection,
        validate_source_pre_state=_validate_source_pre_state,
        ordered_identity_projection=ordered_identity_projection,
        utc_now=utc_now,
        sha256_value=sha256_value,
        execution_contract=execution_contract,
        schema_fingerprint=schema_fingerprint,
        frozen_plan_digest=_frozen_plan_digest,
        digest_bound=_digest_bound,
        write_private_json=write_private_json,
        load_private_source_rows=load_private_source_rows,
    )


def freeze_cohort_from_rows(
    database_path: Path,
    source_rows_path: Path,
    manifest_path: Path,
    *,
    cohort_id: str,
    reason: str,
    expected_count: int,
    expected_release_id: str,
    agent_role: str = "incident-responder",
    expected_assigned_route: str = "codex-cli:gpt-5.5:high",
    expected_reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
    evaluation_profile: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Compatibility adapter for exact imported-row cohort freezing."""
    return run_freeze_cohort_from_rows(
        _cohort_freeze_policy(),
        _cohort_freeze_sources(),
        database_path,
        source_rows_path,
        manifest_path,
        cohort_id=cohort_id,
        reason=reason,
        expected_count=expected_count,
        expected_release_id=expected_release_id,
        agent_role=agent_role,
        expected_assigned_route=expected_assigned_route,
        expected_reviewer_route=expected_reviewer_route,
        evaluation_profile=evaluation_profile,
        dry_run=dry_run,
    )


def _current_summary_identity(
    connection: sqlite3.Connection,
    dashboard_group_id: str,
    aliases: Mapping[str, str],
) -> tuple[str, str] | None:
    return read_current_summary_identity(
        connection,
        dashboard_group_id,
        aliases,
        _representative_state_policy(),
    )


def _alert_representative_identity(
    connection: sqlite3.Connection,
    alert_id: str,
) -> dict[str, Any] | None:
    return read_alert_representative_identity(
        connection,
        alert_id,
        _representative_state_policy(),
    )


def _bind_representative_stable_group_key(
    connection: sqlite3.Connection,
    representative_alert_id: str,
    detection: Mapping[str, Any],
) -> dict[str, Any]:
    return bind_stable_group_key(
        connection,
        representative_alert_id,
        detection,
        _representative_state_policy(),
        alert_identity=_alert_representative_identity,
    )


def _representative_state_policy() -> CohortRepresentativeStatePolicy:
    return CohortRepresentativeStatePolicy(
        error=CohortError,
        storage=_storage_policy(),
        resolve_alias=resolve_alias,
        incident_cases=_incident_cases,
        immutable_fields=FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS,
    )


def _validate_representative_binding(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
    current_representative_alert_id: str,
) -> dict[str, Any]:
    return prove_representative_binding(
        connection,
        member,
        current_representative_alert_id,
        alert_identity=_alert_representative_identity,
        member_stable_group_key=_member_stable_group_key,
        policy=RepresentativeBindingPolicy(
            error=CohortError,
            representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
            immutable_fields=FROZEN_REPRESENTATIVE_IMMUTABLE_FIELDS,
            binding_schema=REPRESENTATIVE_BINDING_SCHEMA,
            validate_stable_group_key=validate_stable_group_key,
            sha256_value=sha256_value,
        ),
    )


def _case_for_stable(
    connection: sqlite3.Connection,
    stable_group_id: str,
    aliases: Mapping[str, str],
) -> dict[str, Any] | None:
    return read_case_for_stable(
        connection,
        stable_group_id,
        aliases,
        _representative_state_policy(),
    )


def validate_member_preflight(
    connection: sqlite3.Connection,
    member: Mapping[str, Any],
) -> dict[str, Any]:
    return run_member_preflight(
        connection,
        member,
        MemberPreflightSources(
            error=CohortError,
            active_agent_states=frozenset(ACTIVE_AGENT_STATES),
            load_aliases=load_aliases,
            current_summary_identity=_current_summary_identity,
            validate_representative_binding=_validate_representative_binding,
            soc_pre_state=_soc_pre_state,
            frozen_analysis_ids=_frozen_analysis_ids,
            analysis_ids_for_group=_analysis_ids_for_group,
            case_for_stable=_case_for_stable,
            active_jobs=_active_jobs,
            active_reanalysis=_active_reanalysis,
        ),
    )


def validate_frozen_cohort(
    database_path: Path,
    manifest: Mapping[str, Any],
) -> None:
    connection = connect_read_only(database_path)
    try:
        connection.execute("BEGIN")
        if (
            schema_fingerprint(connection)
            != (manifest.get("database") or {}).get("schema_sha256")
        ):
            raise CohortError("alert database schema changed after cohort freeze")
        for member in manifest["members"]:
            validate_member_preflight(connection, member)
    finally:
        connection.close()


def _cohort_http_policy() -> CohortHttpPolicy:
    return CohortHttpPolicy(
        maximum_http_body_bytes=MAX_HTTP_BODY_BYTES,
        evaluation_token_bytes=MAX_EVALUATION_TOKEN_BYTES,
        token_pattern=SHA256_RE,
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        canonical_bytes=canonical_bytes,
    )


def validate_loopback_base_url(value: str) -> str:
    """Compatibility adapter for loopback-origin validation."""
    return validate_dashboard_base_url(_cohort_http_policy(), value)


def load_evaluation_token(path: Path) -> str:
    """Compatibility adapter for private evaluation-token loading."""
    return read_evaluation_token(_cohort_http_policy(), path)


def dashboard_post_json(
    url: str,
    payload: Mapping[str, Any],
    *,
    timeout: float,
    evaluation_token: str | None = None,
) -> HttpResult:
    """Compatibility adapter for bounded dashboard POST requests."""
    return post_dashboard_json(
        _cohort_http_policy(),
        url,
        payload,
        timeout=timeout,
        evaluation_token=evaluation_token,
    )


def _cohort_dispatch_contract() -> CohortDispatchContract:
    return CohortDispatchContract(
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        case_id_pattern=CASE_ID_RE,
        run_id_pattern=RUN_ID_RE,
        validate_release_id=validate_release_id,
        member_stable_group_key=_member_stable_group_key,
        deterministic_dispatch_id=deterministic_dispatch_id,
        sha256_value=sha256_value,
    )


def _request_for_member(
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Compatibility adapter for frozen dispatch request construction."""
    return build_dispatch_request(
        _cohort_dispatch_contract(), base_url, manifest, member
    )


def _validate_success_response(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    result: HttpResult,
) -> dict[str, Any]:
    """Compatibility adapter for dashboard acceptance validation."""
    return validate_dispatch_response(
        _cohort_dispatch_contract(), manifest, member, result
    )


def _validate_dispatch_job_payload(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    manual_reanalysis: bool,
    expected_case_id: str = "",
    expected_reanalysis_run_id: str = "",
) -> dict[str, Any]:
    """Compatibility adapter for durable dispatch payload validation."""
    return validate_job_payload(
        _cohort_dispatch_contract(),
        manifest,
        member,
        job,
        manual_reanalysis=manual_reanalysis,
        expected_case_id=expected_case_id,
        expected_reanalysis_run_id=expected_reanalysis_run_id,
    )


def _cohort_dispatch_readback_sources() -> CohortDispatchReadbackSources:
    return CohortDispatchReadbackSources(
        ambiguous_dispatch_error=AmbiguousDispatchError,
        active_job_states=frozenset(ACTIVE_JOB_STATES),
        active_agent_states=frozenset(ACTIVE_AGENT_STATES),
        active_reanalysis_states=frozenset(ACTIVE_REANALYSIS_STATES),
        connect_read_only=connect_read_only,
        load_aliases=load_aliases,
        member_stable_group_key=_member_stable_group_key,
        durable_dispatch_job=_durable_dispatch_job,
        validate_dispatch_job_payload=_validate_dispatch_job_payload,
        verify_zero_fresh_analyses=_verify_zero_fresh_analyses,
        deterministic_dispatch_id=deterministic_dispatch_id,
        case_for_stable=_case_for_stable,
        resolve_alias=resolve_alias,
    )


def _verify_dispatch_readback(
    database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility adapter for durable dispatch readback proof."""
    return prove_dispatch_readback(
        _cohort_dispatch_readback_sources(),
        database_path,
        manifest,
        member,
        accepted,
    )


def _cohort_monitor_binding_sources() -> CohortMonitorBindingSources:
    return CohortMonitorBindingSources(
        cohort_error=CohortError,
        sha256_pattern=SHA256_RE,
        constant_time_equal=_constant_time_equal,
        member_stable_group_key=_member_stable_group_key,
        load_aliases=load_aliases,
        current_summary_identity=_current_summary_identity,
        validate_representative_binding=_validate_representative_binding,
        durable_dispatch_job=_durable_dispatch_job,
        validate_dispatch_job_payload=_validate_dispatch_job_payload,
        deterministic_dispatch_id=deterministic_dispatch_id,
        parse_timestamp=_parse_timestamp,
        sha256_value=sha256_value,
    )


def _monitor_dispatch_job_binding(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility adapter for monitor-time durable-job rebinding."""
    return prove_monitor_dispatch_binding(
        _cohort_monitor_binding_sources(), connection, manifest, member
    )


def _cohort_dispatch_sources() -> CohortDispatchSources:
    """Bind legacy queue patch points to the extracted dispatch workflow."""
    return CohortDispatchSources(
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        load_private_manifest=load_private_manifest,
        validate_loopback_base_url=validate_loopback_base_url,
        load_evaluation_token=load_evaluation_token,
        validate_frozen_cohort=validate_frozen_cohort,
        deterministic_dispatch_id=deterministic_dispatch_id,
        utc_now=utc_now,
        write_private_json=write_private_json,
        connect_read_only=connect_read_only,
        validate_member_preflight=validate_member_preflight,
        request_for_member=_request_for_member,
        validate_success_response=_validate_success_response,
        verify_dispatch_readback=_verify_dispatch_readback,
        dashboard_post_json=dashboard_post_json,
        sha256_value=sha256_value,
    )


def queue_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    base_url: str,
    timeout: float = 15.0,
    dry_run: bool = False,
    poster: Poster | None = None,
    evaluation_token_file: Path | None = None,
) -> dict[str, Any]:
    """Compatibility adapter for the extracted cohort queue state machine."""
    return run_queue_cohort(
        _cohort_dispatch_sources(),
        database_path,
        manifest_path,
        base_url=base_url,
        timeout=timeout,
        dry_run=dry_run,
        poster=poster,
        evaluation_token_file=evaluation_token_file,
    )


def _analysis_metadata_policy() -> AnalysisMetadataPolicy:
    return AnalysisMetadataPolicy(
        error=CohortError,
        require_columns=_require_columns,
        response_sha256=alert_store_response_sha256,
        query_audit_projection=_bounded_query_audit_metadata,
    )


def _analysis_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
    stable_group_id: str,
    *,
    expected_alert_id: str,
    expected_agent_role: str = "incident-responder",
) -> dict[str, Any]:
    return load_analysis_metadata(
        connection,
        analysis_id,
        stable_group_id,
        expected_alert_id=expected_alert_id,
        expected_agent_role=expected_agent_role,
        policy=_analysis_metadata_policy(),
    )


def _bounded_query_audit_metadata(response: Mapping[str, Any]) -> dict[str, Any]:
    return project_query_audit(response)


def _query_audit_policy() -> QueryAuditPolicy:
    return QueryAuditPolicy(
        successful_statuses=frozenset(
            {"ok", "complete", "completed", "success", "succeeded"}
        ),
        sha256_pattern=SHA256_RE,
        sha256_value=sha256_value,
    )


def _query_audit_execution_binding(
    analysis: Mapping[str, Any],
) -> dict[str, Any]:
    return normalize_query_audit_binding(analysis, _query_audit_policy())


def _second_opinion_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
) -> dict[str, Any] | None:
    return read_second_opinion_metadata(
        connection,
        analysis_id,
    )


def _cohort_monitor_contract() -> CohortMonitorContract:
    return CohortMonitorContract(
        cohort_error=CohortError,
        parse_timestamp=_parse_timestamp,
    )


def _durable_job_monitor_state(job: Mapping[str, Any]) -> str:
    """Compatibility adapter for durable-job monitor state validation."""
    return resolve_durable_job_monitor_state(_cohort_monitor_contract(), job)


def _validate_completed_analysis_job_window(
    *,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    analysis: Mapping[str, Any],
) -> None:
    """Compatibility adapter for credited analysis time-window validation."""
    validate_analysis_job_window(
        _cohort_monitor_contract(),
        dispatch=dispatch,
        job=job,
        analysis=analysis,
    )


def _reanalysis_monitor_case(
    connection: sqlite3.Connection,
    run_id: str,
    case_id: str,
) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT run_id, case_id, group_id, dashboard_group_id,
               representative_alert_id, status, skip_reason, latest_error,
               queued_at, started_at, completed_at, latest_attempt_id,
               analysis_id, executed_model, executed_provider,
               executed_model_path, result_generated_at, updated_at
        FROM incident_reanalysis_run_cases
        WHERE run_id = ? AND case_id = ?
        """,
        (run_id, case_id),
    ).fetchone()
    return dict(row) if row else None


def _cohort_monitor_sources() -> CohortMonitorSources:
    return CohortMonitorSources(
        cohort_error=CohortError,
        terminal_monitor_states=frozenset(TERMINAL_MONITOR_STATES),
        monitor_dispatch_job_binding=_monitor_dispatch_job_binding,
        durable_job_monitor_state=_durable_job_monitor_state,
        analysis_ids_for_group=_analysis_ids_for_group,
        analysis_metadata=_analysis_metadata,
        validate_completed_analysis_job_window=(
            _validate_completed_analysis_job_window
        ),
        second_opinion_metadata=_second_opinion_metadata,
        utc_now=utc_now,
        load_aliases=load_aliases,
        case_for_stable=_case_for_stable,
        reanalysis_run_case=_reanalysis_monitor_case,
        resolve_alias=resolve_alias,
        frozen_analysis_ids=_frozen_analysis_ids,
        load_private_manifest=load_private_manifest,
        connect_read_only=connect_read_only,
        write_private_json=write_private_json,
        monotonic=time.monotonic,
        sleep=time.sleep,
    )


def monitor_member(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    """Compatibility adapter for exact terminal member observation."""
    return observe_monitor_member(
        _cohort_monitor_sources(), connection, manifest, member
    )


def monitor_cohort_once(
    database_path: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], bool]:
    """Compatibility adapter for one sealed cohort monitor snapshot."""
    return run_monitor_cohort_once(
        _cohort_monitor_sources(), database_path, manifest_path
    )


def monitor_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    timeout: float,
    poll_interval: float,
) -> tuple[dict[str, Any], bool]:
    """Compatibility adapter for bounded cohort polling."""
    return run_monitor_cohort(
        _cohort_monitor_sources(),
        database_path,
        manifest_path,
        timeout=timeout,
        poll_interval=poll_interval,
    )


def _load_trace_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "onion_sentinel_cohort_trace_evaluator",
        TRACE_EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise CohortError("could not load the harness trace evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prior_analysis_ids(member: Mapping[str, Any]) -> set[str]:
    """Compatibility adapter for frozen prior-analysis identities."""
    return collect_prior_analysis_ids(member)


def _expected_task_kind(role: str, dispatch_kind: str) -> str:
    """Compatibility adapter for role/dispatch task-kind binding."""
    return resolve_expected_task_kind(role, dispatch_kind, CohortError)


def _execution_proof_policy() -> ExecutionProofPolicy:
    return ExecutionProofPolicy(
        error=CohortError,
        parse_timestamp=_parse_timestamp,
        sha256_pattern=SHA256_RE,
        skill_id_pattern=SKILL_ID_RE,
        maximum_selected_skills=MAX_ATTESTED_INVESTIGATION_SKILLS,
        model_call_contract_schema=MODEL_CALL_CONTRACT_SCHEMA,
        maximum_model_calls=MAX_RUNTIME_MODEL_CALLS,
        sha256_value=sha256_value,
    )


def _harness_execution_proof(
    *,
    harness_database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    monitor: Mapping[str, Any],
) -> dict[str, Any]:
    return build_execution_proof(
        harness_database_path=harness_database_path,
        manifest=manifest,
        member=member,
        monitor=monitor,
        load_trace_evaluator=_load_trace_evaluator,
        expected_task_kind=_expected_task_kind,
        query_audit_binding=_query_audit_execution_binding,
        policy=_execution_proof_policy(),
    )


def _cohort_export_sources() -> CohortExportSources:
    return CohortExportSources(
        cohort_error=CohortError,
        export_schema=EXPORT_SCHEMA,
        monitor_cohort_once=monitor_cohort_once,
        harness_execution_proof=_harness_execution_proof,
        member_stable_group_key=_member_stable_group_key,
        utc_now=utc_now,
        sha256_value=sha256_value,
        ordered_identity_projection=ordered_identity_projection,
        write_private_json=write_private_json,
    )


def export_cohort(
    database_path: Path,
    manifest_path: Path,
    output_path: Path,
    *,
    harness_database_path: Path | None = None,
) -> dict[str, Any]:
    """Compatibility adapter for a digest-sealed terminal cohort export."""
    return run_export_cohort(
        _cohort_export_sources(),
        database_path,
        manifest_path,
        output_path,
        harness_database_path=harness_database_path,
    )


def build_parser() -> argparse.ArgumentParser:
    return build_cli_parser(__doc__ or "", sorted(AGENT_ROLES))


def _cli_operations() -> CohortCliOperations:
    return CohortCliOperations(
        freeze_cohort=freeze_cohort,
        freeze_cohort_from_rows=freeze_cohort_from_rows,
        queue_cohort=queue_cohort,
        monitor_cohort=monitor_cohort,
        export_cohort=export_cohort,
        handled_errors=(CohortError, sqlite3.Error),
    )


def main(argv: list[str] | None = None) -> int:
    return run_cli(argv, parser=build_parser(), operations=_cli_operations())


if __name__ == "__main__":
    raise SystemExit(main())
