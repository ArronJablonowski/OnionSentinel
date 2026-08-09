"""Compose cohort dispatch, monitoring, execution proof, and export runtime."""

from __future__ import annotations

import datetime as dt
import importlib.util
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

from cohort_analysis_metadata import AnalysisMetadataPolicy, load_analysis_metadata
from cohort_artifact_adapters import alert_store_response_sha256, write_private_json
from cohort_dispatch_adapters import (
    DispatchContractPorts,
    dashboard_post_json,
    dispatch_contract as build_dispatch_contract,
    load_evaluation_token,
    request_for_member as build_adapter_dispatch_request,
    validate_dispatch_job_payload as validate_adapter_job_payload,
    validate_loopback_base_url,
    validate_success_response as validate_adapter_dispatch_response,
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
from cohort_evaluation_query_audit import (
    QueryAuditPolicy,
    query_audit_execution_binding as normalize_query_audit_binding,
)
from cohort_execution_proof_service import (
    ExecutionProofPolicy,
    build_execution_proof,
)
from cohort_execution_result import (
    expected_task_kind as resolve_expected_task_kind,
    prior_analysis_ids as collect_prior_analysis_ids,
)
from cohort_export import CohortExportSources, export_cohort as run_export_cohort
from cohort_freeze_state_composition import (
    active_jobs,
    active_reanalysis,
    analysis_ids_for_group,
    case_for_stable,
    connect_read_only,
    current_summary_identity,
    durable_dispatch_job,
    frozen_analysis_ids,
    load_aliases,
    require_columns,
    resolve_alias,
    validate_frozen_cohort,
    validate_member_preflight,
    validate_representative_binding,
    verify_zero_fresh_analyses,
)
from cohort_http import HttpResult
from cohort_manifest_adapters import (
    deterministic_dispatch_id,
    load_private_manifest,
    member_stable_group_key,
    ordered_identity_projection,
    validate_release_id,
)
from cohort_monitor_adapters import (
    MonitorContractPorts,
    durable_job_monitor_state as resolve_adapter_job_monitor_state,
    monitor_contract as build_monitor_contract,
    reanalysis_monitor_case,
    validate_completed_analysis_job_window as validate_adapter_analysis_window,
)
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
from cohort_query_audit_projection import project_query_audit
from cohort_runner_contracts import (
    ACTIVE_AGENT_STATES,
    ACTIVE_JOB_STATES,
    ACTIVE_REANALYSIS_STATES,
    EXPORT_SCHEMA,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    MAX_RUNTIME_MODEL_CALLS,
    MODEL_CALL_CONTRACT_SCHEMA,
    SHA256_RE,
    SKILL_ID_RE,
    TERMINAL_MONITOR_STATES,
    AmbiguousDispatchError,
    CohortError,
    constant_time_equal,
    sha256_value,
    utc_now,
)
from cohort_second_opinion_state import second_opinion_metadata


TRACE_EVALUATOR_PATH = Path(__file__).with_name("evaluate-harness-traces.py")


def parse_timestamp(value: Any, label: str) -> dt.datetime:
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


def dispatch_contract_ports() -> DispatchContractPorts:
    return DispatchContractPorts(
        validate_release_id=validate_release_id,
        member_stable_group_key=member_stable_group_key,
        deterministic_dispatch_id=deterministic_dispatch_id,
    )


def cohort_dispatch_contract() -> Any:
    return build_dispatch_contract(dispatch_contract_ports())


def request_for_member(
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    return build_adapter_dispatch_request(
        dispatch_contract_ports(),
        base_url,
        manifest,
        member,
    )


def validate_success_response(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    result: HttpResult,
) -> dict[str, Any]:
    return validate_adapter_dispatch_response(
        dispatch_contract_ports(),
        manifest,
        member,
        result,
    )


def validate_dispatch_job_payload(
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    manual_reanalysis: bool,
    expected_case_id: str = "",
    expected_reanalysis_run_id: str = "",
) -> dict[str, Any]:
    return validate_adapter_job_payload(
        dispatch_contract_ports(),
        manifest,
        member,
        job,
        manual_reanalysis=manual_reanalysis,
        expected_case_id=expected_case_id,
        expected_reanalysis_run_id=expected_reanalysis_run_id,
    )


def dispatch_readback_sources() -> CohortDispatchReadbackSources:
    return CohortDispatchReadbackSources(
        ambiguous_dispatch_error=AmbiguousDispatchError,
        active_job_states=frozenset(ACTIVE_JOB_STATES),
        active_agent_states=frozenset(ACTIVE_AGENT_STATES),
        active_reanalysis_states=frozenset(ACTIVE_REANALYSIS_STATES),
        connect_read_only=connect_read_only,
        load_aliases=load_aliases,
        member_stable_group_key=member_stable_group_key,
        durable_dispatch_job=durable_dispatch_job,
        validate_dispatch_job_payload=validate_dispatch_job_payload,
        verify_zero_fresh_analyses=verify_zero_fresh_analyses,
        deterministic_dispatch_id=deterministic_dispatch_id,
        case_for_stable=case_for_stable,
        resolve_alias=resolve_alias,
    )


def verify_dispatch_readback(
    database_path: Path,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    accepted: Mapping[str, Any],
) -> dict[str, Any]:
    return prove_dispatch_readback(
        dispatch_readback_sources(),
        database_path,
        manifest,
        member,
        accepted,
    )


def monitor_binding_sources() -> CohortMonitorBindingSources:
    return CohortMonitorBindingSources(
        cohort_error=CohortError,
        sha256_pattern=SHA256_RE,
        constant_time_equal=constant_time_equal,
        member_stable_group_key=member_stable_group_key,
        load_aliases=load_aliases,
        current_summary_identity=current_summary_identity,
        validate_representative_binding=validate_representative_binding,
        durable_dispatch_job=durable_dispatch_job,
        validate_dispatch_job_payload=validate_dispatch_job_payload,
        deterministic_dispatch_id=deterministic_dispatch_id,
        parse_timestamp=parse_timestamp,
        sha256_value=sha256_value,
    )


def monitor_dispatch_job_binding(
    connection: sqlite3.Connection,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> dict[str, Any]:
    return prove_monitor_dispatch_binding(
        monitor_binding_sources(),
        connection,
        manifest,
        member,
    )


def dispatch_sources() -> CohortDispatchSources:
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
        request_for_member=request_for_member,
        validate_success_response=validate_success_response,
        verify_dispatch_readback=verify_dispatch_readback,
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
    return run_queue_cohort(
        dispatch_sources(),
        database_path,
        manifest_path,
        base_url=base_url,
        timeout=timeout,
        dry_run=dry_run,
        poster=poster,
        evaluation_token_file=evaluation_token_file,
    )


def bounded_query_audit_metadata(response: Mapping[str, Any]) -> dict[str, Any]:
    return project_query_audit(response)


def analysis_metadata_policy() -> AnalysisMetadataPolicy:
    return AnalysisMetadataPolicy(
        error=CohortError,
        require_columns=require_columns,
        response_sha256=alert_store_response_sha256,
        query_audit_projection=bounded_query_audit_metadata,
    )


def analysis_metadata(
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
        policy=analysis_metadata_policy(),
    )


def query_audit_policy() -> QueryAuditPolicy:
    return QueryAuditPolicy(
        successful_statuses=frozenset(
            {"ok", "complete", "completed", "success", "succeeded"}
        ),
        sha256_pattern=SHA256_RE,
        sha256_value=sha256_value,
    )


def query_audit_execution_binding(
    analysis: Mapping[str, Any],
) -> dict[str, Any]:
    return normalize_query_audit_binding(analysis, query_audit_policy())


def monitor_contract_ports() -> MonitorContractPorts:
    return MonitorContractPorts(parse_timestamp=parse_timestamp)


def cohort_monitor_contract() -> Any:
    return build_monitor_contract(monitor_contract_ports())


def durable_job_monitor_state(job: Mapping[str, Any]) -> str:
    return resolve_adapter_job_monitor_state(monitor_contract_ports(), job)


def validate_completed_analysis_job_window(
    *,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    analysis: Mapping[str, Any],
) -> None:
    validate_adapter_analysis_window(
        monitor_contract_ports(),
        dispatch=dispatch,
        job=job,
        analysis=analysis,
    )


def monitor_sources() -> CohortMonitorSources:
    return CohortMonitorSources(
        cohort_error=CohortError,
        terminal_monitor_states=frozenset(TERMINAL_MONITOR_STATES),
        monitor_dispatch_job_binding=monitor_dispatch_job_binding,
        durable_job_monitor_state=durable_job_monitor_state,
        analysis_ids_for_group=analysis_ids_for_group,
        analysis_metadata=analysis_metadata,
        validate_completed_analysis_job_window=(
            validate_completed_analysis_job_window
        ),
        second_opinion_metadata=second_opinion_metadata,
        utc_now=utc_now,
        load_aliases=load_aliases,
        case_for_stable=case_for_stable,
        reanalysis_run_case=reanalysis_monitor_case,
        resolve_alias=resolve_alias,
        frozen_analysis_ids=frozen_analysis_ids,
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
    return observe_monitor_member(monitor_sources(), connection, manifest, member)


def monitor_cohort_once(
    database_path: Path,
    manifest_path: Path,
) -> tuple[dict[str, Any], bool]:
    return run_monitor_cohort_once(monitor_sources(), database_path, manifest_path)


def monitor_cohort(
    database_path: Path,
    manifest_path: Path,
    *,
    timeout: float,
    poll_interval: float,
) -> tuple[dict[str, Any], bool]:
    return run_monitor_cohort(
        monitor_sources(),
        database_path,
        manifest_path,
        timeout=timeout,
        poll_interval=poll_interval,
    )


def load_trace_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "onion_sentinel_cohort_trace_evaluator",
        TRACE_EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise CohortError("could not load the harness trace evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prior_analysis_ids(member: Mapping[str, Any]) -> set[str]:
    return collect_prior_analysis_ids(member)


def expected_task_kind(role: str, dispatch_kind: str) -> str:
    return resolve_expected_task_kind(role, dispatch_kind, CohortError)


def execution_proof_policy() -> ExecutionProofPolicy:
    return ExecutionProofPolicy(
        error=CohortError,
        parse_timestamp=parse_timestamp,
        sha256_pattern=SHA256_RE,
        skill_id_pattern=SKILL_ID_RE,
        maximum_selected_skills=MAX_ATTESTED_INVESTIGATION_SKILLS,
        model_call_contract_schema=MODEL_CALL_CONTRACT_SCHEMA,
        maximum_model_calls=MAX_RUNTIME_MODEL_CALLS,
        sha256_value=sha256_value,
    )


def harness_execution_proof(
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
        load_trace_evaluator=load_trace_evaluator,
        expected_task_kind=expected_task_kind,
        query_audit_binding=query_audit_execution_binding,
        policy=execution_proof_policy(),
    )


def export_sources() -> CohortExportSources:
    return CohortExportSources(
        cohort_error=CohortError,
        export_schema=EXPORT_SCHEMA,
        monitor_cohort_once=monitor_cohort_once,
        harness_execution_proof=harness_execution_proof,
        member_stable_group_key=member_stable_group_key,
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
    return run_export_cohort(
        export_sources(),
        database_path,
        manifest_path,
        output_path,
        harness_database_path=harness_database_path,
    )
