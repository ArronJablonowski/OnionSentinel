"""Late-bound scheduler service composition.

The legacy scheduler entrypoint passes its module namespace into these pure
builders.  That preserves the historical compatibility seam where tests and
operators may replace a facade dependency before asking it to construct a
workflow, without giving this module any database, network, or process
authority of its own.
"""
from __future__ import annotations

from typing import Any, Mapping


RuntimeNamespace = Mapping[str, Any]


def _emit(runtime: RuntimeNamespace, message: str, *, error: bool = False) -> None:
    destination = runtime["sys"].stderr if error else None
    runtime.get("print", print)(message, file=destination, flush=not error)


def build_terminal_recovery_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["TerminalRecoverySources"](
        connect_read_only=runtime["scheduler_read_only_connection"],
        path_exists=lambda path: path.exists(),
        load_candidates=runtime["load_terminal_success_recovery_candidates"],
        report_status=runtime["report_ai_job_status"],
    )


def build_startup_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerStartupSources"](
        stop_for_drain=runtime["stop_for_maintenance_drain"],
        controlled_runtime=runtime["controlled_evaluation_runtime"],
        consume_controlled_token=runtime["consume_controlled_evaluation_token"],
        require_capacity=runtime["require_runtime_capacity"],
        path_exists=lambda path: path.exists(),
        consume_wake_marker=runtime["consume_wake_marker"],
        detect_indexed_mode=runtime["detect_indexed_scheduler_mode"],
        recover_controlled_spool=runtime["recover_controlled_evaluation_spool"],
        flush_deferred_results=runtime["flush_deferred_analysis_results"],
        recover_terminal_success=runtime["reconcile_terminal_success_durable_jobs"],
        reconcile_worker_state=runtime["reconcile_worker_state"],
        emit=lambda message: _emit(runtime, message),
        emit_error=lambda message: _emit(runtime, message, error=True),
        now=runtime["project_now"],
    )


def build_settlement_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerSettlementSources"](
        signal_dashboard_refresh=runtime["signal_dashboard_refresh"],
        reconcile_worker_state=runtime["reconcile_worker_state"],
        emit=lambda message: _emit(runtime, message),
        emit_error=lambda message: _emit(runtime, message, error=True),
        now=runtime["project_now"],
        controlled_failure_exit_code=runtime[
            "CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE"
        ],
    )


def build_claim_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerClaimSources"](
        exact_expectations=runtime["controlled_claim_expectations"],
        report_status=runtime["report_ai_job_status"],
        load_claimed_job=runtime["claimed_durable_ai_job"],
        require_controlled_identity=runtime["require_controlled_claim_identity"],
        job_reanalysis_attempt_id=runtime["job_reanalysis_attempt_id"],
        emit=lambda message: _emit(runtime, message),
        now=runtime["project_now"],
    )


def build_execution_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerExecutionSources"](
        report_status=runtime["report_ai_job_status"],
        validate_controlled_route=runtime["controlled_job_route_contract"],
        collect_incident_evidence=runtime["collect_incident_evidence"],
        build_prompt=runtime["build_prompt"],
        reusable_prompt=runtime["reusable_prompt_for_alert"],
        run_analysis=runtime["run_analysis"],
    )


def build_outcome_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerOutcomeSources"](
        report_status=runtime["report_ai_job_status"],
        failure_is_retryable=runtime["ai_failure_is_retryable"],
        recover_controlled_spool=runtime["recover_controlled_evaluation_spool"],
        controlled_spool_pending=runtime["controlled_recovery_spool_pending"],
        now=runtime["project_now"],
        emit=lambda message: _emit(runtime, message),
        emit_error=lambda message: _emit(runtime, message, error=True),
        write_stdout=lambda message: runtime.get("print", print)(message, end=""),
        write_stderr=lambda message: runtime.get("print", print)(
            message,
            file=runtime["sys"].stderr,
            end="",
        ),
        result_submission_indeterminate_marker=runtime[
            "CONTROLLED_RESULT_SUBMISSION_INDETERMINATE"
        ],
    )


def build_drain_sources(runtime: RuntimeNamespace) -> Any:
    def open_readonly_database(database_path: Any) -> Any:
        connection = runtime["sqlite3"].connect(
            f"file:{database_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = runtime["sqlite3"].Row
        return connection

    return runtime["SchedulerDrainSources"](
        stop_for_drain=runtime["stop_for_maintenance_drain"],
        configured_levels=runtime["configured_analysis_levels"],
        open_readonly_database=open_readonly_database,
        select_indexed=runtime["select_next_alert_indexed"],
        select_legacy=runtime["select_next_alert"],
        analyzed_alert_ids=runtime["analyzed_alert_ids"],
        alert_group_key=runtime["alert_group_key"],
        alert_group_id=runtime["alert_group_id"],
        durable_payload=runtime["durable_payload"],
        now=runtime["project_now"],
        emit=lambda message: _emit(runtime, message),
    )


def build_worker_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerWorkerSources"](
        acquire_claim=runtime["acquire_scheduler_claim"],
        claim_sources=runtime["scheduler_claim_sources"],
        execute_analysis=runtime["execute_scheduler_analysis"],
        execution_sources=runtime["scheduler_execution_sources"],
        handle_process_outcome=runtime["handle_process_outcome"],
        handle_claim_rejection=runtime["handle_controlled_claim_rejection"],
        handle_exception=runtime["handle_scheduler_exception"],
        outcome_sources=runtime["scheduler_outcome_sources"],
        controlled_claim_error=runtime["ControlledClaimRejected"],
        execution_errors=(
            runtime["BoundedProcessError"],
            RuntimeError,
            OSError,
        ),
    )


def build_application_sources(runtime: RuntimeNamespace) -> Any:
    return runtime["SchedulerApplicationSources"](
        parse_args=runtime["parse_args"],
        startup_sources=runtime["scheduler_startup_sources"],
        prepare_run=runtime["prepare_scheduler_run"],
        initialize_run=runtime["initialize_scheduler_run"],
        drain_sources=runtime["scheduler_drain_sources"],
        select_work=runtime["select_scheduler_work"],
        worker_sources=runtime["scheduler_worker_sources"],
        process_selection=runtime["process_scheduler_selection"],
        settlement_sources=runtime["scheduler_settlement_sources"],
        settle_run=runtime["settle_scheduler_run"],
        acquire_nonblocking_lock=lambda handle: runtime["fcntl"].flock(
            handle,
            runtime["fcntl"].LOCK_EX | runtime["fcntl"].LOCK_NB,
        ),
        emit=lambda message: _emit(runtime, message),
        now=runtime["project_now"],
        default_drain_file=runtime["DEFAULT_DRAIN"],
    )
