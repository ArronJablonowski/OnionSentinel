"""Post-drain scheduler reconciliation and exit projection."""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SchedulerSettlement:
    analyzed_count: int
    indexed_mode: bool
    controlled_evaluation: bool
    controlled_owned_job_failed: bool = False
    controlled_failure_detail: str = ""
    controlled_failure_group_id: str = ""


@dataclass(frozen=True)
class SchedulerSettlementSources:
    signal_dashboard_refresh: Callable[..., None]
    reconcile_worker_state: Callable[..., int]
    emit: Callable[[str], None]
    emit_error: Callable[[str], None]
    now: Callable[[], str]
    controlled_failure_exit_code: int


def _publish_refresh(
    sources: SchedulerSettlementSources,
    args: Any,
    settlement: SchedulerSettlement,
) -> None:
    if not settlement.analyzed_count:
        return
    sources.emit(
        f"{sources.now()} analyzed {settlement.analyzed_count} unique "
        "alert group(s)"
    )
    sources.signal_dashboard_refresh(
        args,
        controlled_evaluation=settlement.controlled_evaluation,
    )


def _reconcile_before_exit(
    sources: SchedulerSettlementSources,
    args: Any,
    settlement: SchedulerSettlement,
) -> None:
    reconciled = sources.reconcile_worker_state(
        args,
        settlement.indexed_mode,
        controlled_evaluation=settlement.controlled_evaluation,
    )
    if reconciled:
        sources.emit(
            f"{sources.now()} reconciled {reconciled} completed durable "
            "AI job(s) before exit"
        )


def _controlled_failure_payload(settlement: SchedulerSettlement) -> str:
    return json.dumps(
        {
            "controlled_evaluation": "selected_job_failed",
            "error": (
                settlement.controlled_failure_detail[:1000]
                or "selected controlled job failed"
            ),
            "stable_group_id": settlement.controlled_failure_group_id,
        },
        sort_keys=True,
    )


def settle_scheduler_run(
    sources: SchedulerSettlementSources,
    args: Any,
    settlement: SchedulerSettlement,
) -> int:
    """Publish run effects, reconcile late intent, and project the exit code."""
    _publish_refresh(sources, args, settlement)
    _reconcile_before_exit(sources, args, settlement)
    if settlement.controlled_owned_job_failed:
        sources.emit_error(_controlled_failure_payload(settlement))
        return sources.controlled_failure_exit_code
    return 0
