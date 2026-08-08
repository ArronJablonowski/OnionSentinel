"""Scheduler preflight and locked-runtime initialization services."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SchedulerStartupSources:
    stop_for_drain: Callable[[Path], bool]
    controlled_runtime: Callable[[Any], Path | None]
    consume_controlled_token: Callable[[bool], str]
    require_capacity: Callable[..., None]
    path_exists: Callable[[Path], bool]
    consume_wake_marker: Callable[[Path], None]
    detect_indexed_mode: Callable[[Path], bool]
    recover_controlled_spool: Callable[[Any, Path], bool]
    flush_deferred_results: Callable[[Any], None]
    recover_terminal_success: Callable[[Any], int]
    reconcile_worker_state: Callable[..., int]
    emit: Callable[[str], None]
    emit_error: Callable[[str], None]
    now: Callable[[], str]


@dataclass(frozen=True)
class SchedulerPreflight:
    proceed: bool
    exit_code: int
    controlled_evaluation_dir: Path | None
    launch_levels: str


@dataclass(frozen=True)
class SchedulerInitialization:
    proceed: bool
    indexed_mode: bool


def prepare_scheduler_run(
    sources: SchedulerStartupSources,
    args: Any,
    *,
    drain_file: Path,
) -> SchedulerPreflight:
    """Validate a run before lock acquisition or runtime mutation."""
    if sources.stop_for_drain(drain_file):
        return SchedulerPreflight(False, 0, None, "")
    controlled_dir = sources.controlled_runtime(args)
    sources.consume_controlled_token(controlled_dir is not None)
    launch_levels = str(args.levels)
    sources.require_capacity(args.analysis_dir, 0, label="AI analysis")
    if not sources.path_exists(args.db):
        sources.emit_error(f"{sources.now()} SQLite DB not found: {args.db}")
        return SchedulerPreflight(False, 2, controlled_dir, launch_levels)
    return SchedulerPreflight(True, 0, controlled_dir, launch_levels)


def _prepare_runtime_paths(
    sources: SchedulerStartupSources,
    args: Any,
    controlled_dir: Path | None,
) -> None:
    if controlled_dir is None:
        sources.consume_wake_marker(args.wake_file)
    args.prompt_dir.mkdir(parents=True, exist_ok=True)
    args.analysis_dir.mkdir(parents=True, exist_ok=True)


def _recover_controlled_result(
    sources: SchedulerStartupSources,
    args: Any,
    controlled_dir: Path | None,
) -> bool:
    if controlled_dir is None:
        return False
    if not sources.recover_controlled_spool(args, controlled_dir):
        return False
    sources.emit(
        f"{sources.now()} recovered one exact controlled result and completed "
        "its prior lease without inference"
    )
    return True


def _recover_terminal_results(
    sources: SchedulerStartupSources,
    args: Any,
    indexed_mode: bool,
    controlled_dir: Path | None,
) -> None:
    if not indexed_mode or controlled_dir is not None:
        return
    sources.flush_deferred_results(args)
    try:
        recovered = sources.recover_terminal_success(args)
    except (OSError, sqlite3.Error, RuntimeError) as error:
        sources.emit_error(
            f"{sources.now()} terminal harness recovery deferred: {error}"
        )
        return
    if recovered:
        sources.emit(
            f"{sources.now()} recovered {recovered} terminal-success durable "
            "AI job(s) without duplicate inference"
        )


def initialize_scheduler_run(
    sources: SchedulerStartupSources,
    args: Any,
    *,
    controlled_evaluation_dir: Path | None,
) -> SchedulerInitialization:
    """Initialize one lock-owning run before its claim-and-dispatch loop."""
    _prepare_runtime_paths(sources, args, controlled_evaluation_dir)
    indexed_mode = sources.detect_indexed_mode(args.db)
    if _recover_controlled_result(
        sources,
        args,
        controlled_evaluation_dir,
    ):
        return SchedulerInitialization(False, indexed_mode)
    if not indexed_mode and args.provider_lane == "cli":
        sources.emit(
            f"{sources.now()} CLI provider lane requires the indexed "
            "scheduler; no work claimed"
        )
        return SchedulerInitialization(False, indexed_mode)
    _recover_terminal_results(
        sources,
        args,
        indexed_mode,
        controlled_evaluation_dir,
    )
    reconciled = sources.reconcile_worker_state(
        args,
        indexed_mode,
        controlled_evaluation=controlled_evaluation_dir is not None,
    )
    if reconciled:
        sources.emit(
            f"{sources.now()} reconciled {reconciled} completed durable "
            "AI job(s)"
        )
    return SchedulerInitialization(True, indexed_mode)
