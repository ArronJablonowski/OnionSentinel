#!/usr/bin/env python3
"""Lock-owning scheduler application coordinator."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from scheduler_drain import SchedulerDrainState
from scheduler_settlement import SchedulerSettlement


@dataclass(frozen=True)
class SchedulerApplicationSources:
    """Entry-point effects resolved by the launchd compatibility facade."""

    parse_args: Callable[[], Any]
    startup_sources: Callable[[], Any]
    prepare_run: Callable[..., Any]
    initialize_run: Callable[..., Any]
    drain_sources: Callable[[], Any]
    select_work: Callable[..., Any]
    worker_sources: Callable[[], Any]
    process_selection: Callable[..., bool]
    settlement_sources: Callable[[], Any]
    settle_run: Callable[..., int]
    acquire_nonblocking_lock: Callable[[Any], None]
    emit: Callable[[str], None]
    now: Callable[[], str]
    default_drain_file: Path


def _settlement(state: SchedulerDrainState, indexed: bool, controlled: bool):
    return SchedulerSettlement(
        analyzed_count=state.analyzed_count,
        indexed_mode=indexed,
        controlled_evaluation=controlled,
        controlled_owned_job_failed=state.controlled_owned_job_failed,
        controlled_failure_detail=state.controlled_failure_detail,
        controlled_failure_group_id=state.controlled_failure_group_id,
    )


def _run_locked_scheduler(
    sources: SchedulerApplicationSources,
    args: Any,
    controlled_directory: Path | None,
    launch_levels: str,
) -> int:
    initialization = sources.initialize_run(
        sources.startup_sources(),
        args,
        controlled_evaluation_dir=controlled_directory,
    )
    if not initialization.proceed:
        return 0
    state = SchedulerDrainState()
    drain_file = getattr(args, "drain_file", sources.default_drain_file)
    while True:
        selection = sources.select_work(
            sources.drain_sources(),
            args,
            state,
            indexed_mode=initialization.indexed_mode,
            launch_levels=launch_levels,
            drain_file=drain_file,
        )
        if selection.disposition != "selected":
            break
        if sources.process_selection(
            sources.worker_sources(),
            args,
            state,
            selection,
            indexed_mode=initialization.indexed_mode,
            controlled_evaluation_dir=controlled_directory,
        ):
            break
    return sources.settle_run(
        sources.settlement_sources(),
        args,
        _settlement(
            state,
            initialization.indexed_mode,
            controlled_directory is not None,
        ),
    )


def run_scheduler_application(sources: SchedulerApplicationSources) -> int:
    """Run one preflighted, non-overlapping scheduler drain."""
    args = sources.parse_args()
    startup = sources.startup_sources()
    preflight = sources.prepare_run(
        startup,
        args,
        drain_file=getattr(args, "drain_file", sources.default_drain_file),
    )
    if not preflight.proceed:
        return preflight.exit_code
    args.lock_file.parent.mkdir(parents=True, exist_ok=True)
    with args.lock_file.open("w") as lock_handle:
        try:
            sources.acquire_nonblocking_lock(lock_handle)
        except BlockingIOError:
            sources.emit(
                f"{sources.now()} another AI analysis run is already active"
            )
            return 0
        return _run_locked_scheduler(
            sources,
            args,
            preflight.controlled_evaluation_dir,
            preflight.launch_levels,
        )
