"""Scheduler process outcomes, failure reporting, and spool recovery."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SchedulerOutcomeRequest:
    args: Any
    group_id: str
    job_type: str
    processing_recorded: bool
    lease_token: str
    controlled: bool
    controlled_evaluation_dir: Path | None
    controlled_exact_lease_owned: bool


@dataclass(frozen=True)
class SchedulerOutcomeSources:
    report_status: Callable[..., object]
    failure_is_retryable: Callable[[object], bool]
    recover_controlled_spool: Callable[[Any, Path | None], bool]
    controlled_spool_pending: Callable[[Path], bool]
    now: Callable[[], str]
    emit: Callable[[str], None]
    emit_error: Callable[[str], None]
    write_stdout: Callable[[str], None]
    write_stderr: Callable[[str], None]
    result_submission_indeterminate_marker: str


@dataclass(frozen=True)
class SchedulerOutcome:
    analyzed_increment: int = 0
    stop: bool = False
    controlled_owned_job_failed: bool = False
    failure_detail: str = ""
    failure_group_id: str = ""


def _controlled_failure(
    request: SchedulerOutcomeRequest,
    detail: str,
) -> SchedulerOutcome:
    return SchedulerOutcome(
        stop=True,
        controlled_owned_job_failed=True,
        failure_detail=detail,
        failure_group_id=request.group_id,
    )


def _recover_indeterminate_result(
    sources: SchedulerOutcomeSources,
    request: SchedulerOutcomeRequest,
) -> bool:
    sources.emit_error(
        f"{sources.now()} exact controlled result is retained for recovery; "
        "its owned job remains processing"
    )
    try:
        if sources.recover_controlled_spool(
            request.args,
            request.controlled_evaluation_dir,
        ):
            sources.emit(
                f"{sources.now()} recovered the indeterminate controlled "
                "result without another inference"
            )
            return True
    except RuntimeError as error:
        sources.emit_error(
            f"{sources.now()} controlled result remains safely spooled: "
            f"{error}"
        )
    return False


def _handle_failed_process(
    sources: SchedulerOutcomeSources,
    request: SchedulerOutcomeRequest,
    process: Any,
) -> SchedulerOutcome:
    detail = (
        process.stderr.strip()
        or f"local AI analysis failed rc={process.returncode}"
    )
    indeterminate = bool(
        request.controlled
        and sources.result_submission_indeterminate_marker in detail
    )
    recovered = False
    if request.processing_recorded and indeterminate:
        recovered = _recover_indeterminate_result(sources, request)
    elif request.processing_recorded:
        sources.report_status(
            request.args.alert_store_url,
            request.group_id,
            "failed",
            detail,
            request.lease_token,
            job_type=request.job_type,
            retryable=sources.failure_is_retryable(detail),
        )
    sources.emit_error(detail)
    if recovered:
        return SchedulerOutcome(analyzed_increment=1, stop=True)
    if request.controlled_exact_lease_owned:
        return _controlled_failure(request, detail)
    return SchedulerOutcome()


def handle_process_outcome(
    sources: SchedulerOutcomeSources,
    request: SchedulerOutcomeRequest,
    process: Any,
) -> SchedulerOutcome:
    """Project one child-process result into durable scheduler behavior."""
    if process.stdout:
        sources.write_stdout(process.stdout)
    if process.returncode != 0:
        return _handle_failed_process(sources, request, process)

    if process.stderr:
        sources.write_stderr(process.stderr)
    if (
        request.processing_recorded
        and request.controlled_evaluation_dir is None
    ):
        sources.report_status(
            request.args.alert_store_url,
            request.group_id,
            "completed",
            lease_token=request.lease_token,
            job_type=request.job_type,
        )
    return SchedulerOutcome(analyzed_increment=1)


def handle_controlled_claim_rejection(
    sources: SchedulerOutcomeSources,
    request: SchedulerOutcomeRequest,
    error: Exception,
) -> SchedulerOutcome:
    """Release only an exact owned lease after controlled validation fails."""
    detail = str(error)
    outcome = SchedulerOutcome(stop=True)
    if request.controlled_exact_lease_owned:
        try:
            sources.report_status(
                request.args.alert_store_url,
                request.group_id,
                "failed",
                detail,
                request.lease_token,
                job_type=request.job_type,
                retryable=True,
            )
        except RuntimeError as status_error:
            sources.emit_error(
                "controlled AI lease release also failed: "
                f"{status_error}"
            )
        outcome = _controlled_failure(request, detail)
    sources.emit_error(
        f"{sources.now()} controlled AI claim rejected: {error}"
    )
    return outcome


def handle_scheduler_exception(
    sources: SchedulerOutcomeSources,
    request: SchedulerOutcomeRequest,
    error: Exception,
) -> SchedulerOutcome:
    """Recover an exact spool or report an owned execution failure."""
    may_be_spooled = bool(
        request.controlled_exact_lease_owned
        and request.controlled_evaluation_dir is not None
        and sources.controlled_spool_pending(
            request.controlled_evaluation_dir
        )
    )
    if may_be_spooled:
        try:
            if sources.recover_controlled_spool(
                request.args,
                request.controlled_evaluation_dir,
            ):
                sources.emit(
                    f"{sources.now()} recovered a controlled result after "
                    "its child process ended indeterminately"
                )
                return SchedulerOutcome(analyzed_increment=1)
        except RuntimeError as recovery_error:
            sources.emit_error(
                f"{sources.now()} controlled result remains safely spooled: "
                f"{recovery_error}"
            )
    if request.processing_recorded and not may_be_spooled:
        try:
            sources.report_status(
                request.args.alert_store_url,
                request.group_id,
                "failed",
                str(error),
                request.lease_token,
                job_type=request.job_type,
                retryable=sources.failure_is_retryable(error),
            )
        except RuntimeError as status_error:
            sources.emit_error(
                f"AI failure callback also failed: {status_error}"
            )
    sources.emit_error(
        f"{sources.now()} AI group {request.group_id} failed: {error}"
    )
    if request.controlled_exact_lease_owned:
        return _controlled_failure(request, str(error))
    return SchedulerOutcome()
