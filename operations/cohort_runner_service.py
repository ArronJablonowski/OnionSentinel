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
from dataclasses import replace
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
from cohort_dispatch_readback import (
    CohortDispatchReadbackSources,
    verify_dispatch_readback as prove_dispatch_readback,
)
from cohort_dispatch_workflow import (
    CohortDispatchSources,
    Poster,
    queue_cohort as run_queue_cohort,
)
from cohort_http import HttpResult
from cohort_monitor_binding import (
    CohortMonitorBindingSources,
    monitor_dispatch_job_binding as prove_monitor_dispatch_binding,
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
from cohort_dispatch_identity import deterministic_dispatch_id as derive_dispatch_id
from cohort_manifest_contract import (
    frozen_plan_digest as calculate_frozen_plan_digest,
    validate_manifest_document,
)
from cohort_private_input import (
    load_private_manifest as read_private_manifest,
    load_private_source_rows as read_private_source_rows,
)
from cohort_runner_cli import (
    CohortCliOperations,
    build_parser as build_cli_parser,
    main as run_cli,
)
from cohort_artifact_io import (
    alert_store_response_sha256 as verify_alert_store_response_sha256,
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
    constant_time_equal as _constant_time_equal,
    sha256_value,
    utc_now,
)
from cohort_dispatch_adapters import (
    DispatchContractPorts,
    dashboard_post_json,
    dispatch_contract as build_dispatch_contract,
    http_policy as _cohort_http_policy,
    load_evaluation_token,
    request_for_member as build_adapter_dispatch_request,
    validate_dispatch_job_payload as validate_adapter_job_payload,
    validate_loopback_base_url,
    validate_success_response as validate_adapter_dispatch_response,
)
from cohort_monitor_adapters import (
    MonitorContractPorts,
    durable_job_monitor_state as resolve_adapter_job_monitor_state,
    monitor_contract as build_monitor_contract,
    reanalysis_monitor_case as _reanalysis_monitor_case,
    validate_completed_analysis_job_window as validate_adapter_analysis_window,
)
from cohort_artifact_adapters import (
    alert_store_response_sha256,
    digest_artifact_policy as _digest_artifact_policy,
    digest_bound as _digest_bound,
    validate_digest as _validate_digest,
    write_private_json,
)
from cohort_manifest_adapters import (
    deterministic_dispatch_id,
    execution_contract,
    frozen_plan_digest as _frozen_plan_digest,
    load_private_manifest,
    load_private_source_rows,
    manifest_contract_policy as _manifest_contract_policy,
    member_stable_group_key as _member_stable_group_key,
    ordered_identity_projection,
    private_input_policy as _private_input_policy,
    validate_agent_role,
    validate_cohort_identity,
    validate_model_route,
    validate_release_id,
    validate_stable_group_key,
)
from cohort_freeze_state_composition import (
    SUMMARY_EXPORT_COLUMNS,
    active_jobs as _active_jobs,
    active_reanalysis as _active_reanalysis,
    alert_representative_identity as _alert_representative_identity,
    analysis_ids_for_group as _analysis_ids_for_group,
    bind_representative_stable_group_key as _bind_representative_stable_group_key,
    case_for_stable as _case_for_stable,
    connect_read_only,
    current_summary_identity as _current_summary_identity,
    durable_dispatch_job as _durable_dispatch_job,
    durable_job_snapshot as _durable_job_snapshot,
    frozen_analysis_ids as _frozen_analysis_ids,
    incident_cases as _incident_cases,
    incident_pre_state as _pre_state,
    latest_analysis_metadata as _latest_analysis_metadata,
    load_aliases,
    representative_state_policy as _representative_state_policy,
    require_columns as _require_columns,
    resolve_alias,
    schema_fingerprint,
    soc_pre_state as _soc_pre_state,
    state_policy as _state_policy,
    storage_policy as _storage_policy,
    summary_rows as _summary_rows,
    table_columns as _table_columns,
    table_exists as _table_exists,
    validate_frozen_cohort,
    validate_member_preflight,
    validate_representative_binding as _validate_representative_binding,
    verify_zero_fresh_analyses as _verify_zero_fresh_analyses,
)
from cohort_runtime_composition import (
    TRACE_EVALUATOR_PATH,
    analysis_metadata as _analysis_metadata,
    analysis_metadata_policy as _analysis_metadata_policy,
    bounded_query_audit_metadata as _bounded_query_audit_metadata,
    cohort_dispatch_contract as _cohort_dispatch_contract,
    cohort_monitor_contract as _cohort_monitor_contract,
    dispatch_contract_ports as _dispatch_contract_ports,
    dispatch_readback_sources as _cohort_dispatch_readback_sources,
    dispatch_sources as runtime_dispatch_sources,
    durable_job_monitor_state as _durable_job_monitor_state,
    execution_proof_policy as _execution_proof_policy,
    expected_task_kind as _expected_task_kind,
    export_cohort as runtime_export_cohort,
    export_sources as runtime_export_sources,
    harness_execution_proof as runtime_harness_execution_proof,
    load_trace_evaluator as runtime_load_trace_evaluator,
    monitor_binding_sources as _cohort_monitor_binding_sources,
    monitor_cohort,
    monitor_cohort_once,
    monitor_dispatch_job_binding as _monitor_dispatch_job_binding,
    monitor_member,
    monitor_sources as _cohort_monitor_sources,
    monitor_contract_ports as _monitor_contract_ports,
    parse_timestamp as _parse_timestamp,
    prior_analysis_ids as _prior_analysis_ids,
    query_audit_execution_binding as _query_audit_execution_binding,
    query_audit_policy as _query_audit_policy,
    queue_cohort as runtime_queue_cohort,
    request_for_member as _request_for_member,
    validate_completed_analysis_job_window as _validate_completed_analysis_job_window,
    validate_dispatch_job_payload as _validate_dispatch_job_payload,
    validate_success_response as _validate_success_response,
    verify_dispatch_readback as _verify_dispatch_readback,
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


def _cohort_dispatch_sources() -> CohortDispatchSources:
    """Rebind legacy façade patch points to the extracted runtime."""
    return replace(
        runtime_dispatch_sources(),
        load_private_manifest=load_private_manifest,
        validate_loopback_base_url=validate_loopback_base_url,
        load_evaluation_token=load_evaluation_token,
        validate_frozen_cohort=validate_frozen_cohort,
        deterministic_dispatch_id=deterministic_dispatch_id,
        write_private_json=write_private_json,
        connect_read_only=connect_read_only,
        validate_member_preflight=validate_member_preflight,
        request_for_member=_request_for_member,
        validate_success_response=_validate_success_response,
        verify_dispatch_readback=_verify_dispatch_readback,
        dashboard_post_json=dashboard_post_json,
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


def _load_trace_evaluator() -> Any:
    return runtime_load_trace_evaluator()


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
    return replace(
        runtime_export_sources(),
        monitor_cohort_once=monitor_cohort_once,
        harness_execution_proof=_harness_execution_proof,
    )


def export_cohort(
    database_path: Path,
    manifest_path: Path,
    output_path: Path,
    *,
    harness_database_path: Path | None = None,
) -> dict[str, Any]:
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
