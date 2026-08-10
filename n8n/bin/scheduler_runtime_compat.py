"""Scheduler clock, filesystem signaling, and reconciliation adapters."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping


RuntimeNamespace = Mapping[str, Any]


def project_now(runtime: RuntimeNamespace) -> str:
    return (
        runtime["dt"].datetime.now()
        .astimezone()
        .replace(microsecond=0)
        .isoformat()
        .replace("T", "  ")
    )


def project_now_precise(runtime: RuntimeNamespace) -> str:
    return runtime["dt"].datetime.now().astimezone().isoformat(
        timespec="milliseconds"
    ).replace("T", "  ")


def rows(runtime: RuntimeNamespace, conn: Any, sql: str, params: Any = ()) -> list[Any]:
    return conn.execute(sql, tuple(params)).fetchall()


def flush_deferred_analysis_results(runtime: RuntimeNamespace, args: Any) -> None:
    runner = Path(runtime["__file__"]).with_name("run-local-ai-analysis.py")
    proc = runtime["run_command"](
        [
            runtime["sys"].executable,
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
        detail = (
            proc.stderr.strip()
            or proc.stdout.strip()
            or f"rc={proc.returncode}"
        )
        raise RuntimeError(f"deferred analysis index flush failed: {detail}")


def signal_dashboard_refresh(
    runtime: RuntimeNamespace,
    args: Any,
    *,
    controlled_evaluation: bool = False,
) -> None:
    if args.no_portal_refresh or controlled_evaluation:
        return
    try:
        args.portal_wake_file.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        args.portal_wake_file.write_text(
            f"{runtime['project_now']()} ai-analysis-complete\n",
            encoding="utf-8",
        )
        args.portal_wake_file.chmod(0o600)
    except OSError as error:
        runtime.get("print", print)(
            f"dashboard refresh signal failed: {error}",
            file=runtime["sys"].stderr,
        )


def consume_wake_marker(runtime: RuntimeNamespace, path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        runtime.get("print", print)(
            f"AI wake marker could not be consumed: {error}",
            file=runtime["sys"].stderr,
        )


def maintenance_drain_active(
    runtime: RuntimeNamespace,
    path: Path,
) -> tuple[bool, str]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False, ""
    except OSError as error:
        return True, f"maintenance drain marker cannot be inspected: {error}"
    if not runtime["stat"].S_ISREG(metadata.st_mode):
        return True, "maintenance drain marker is not a regular file"
    if metadata.st_uid != runtime["os"].getuid():
        return True, "maintenance drain marker is not owned by the worker account"
    if runtime["stat"].S_IMODE(metadata.st_mode) & 0o077:
        return True, "maintenance drain marker is not owner-only"
    if metadata.st_size > 4096:
        return True, "maintenance drain marker exceeds its byte limit"
    return True, "maintenance drain requested"


def stop_for_maintenance_drain(runtime: RuntimeNamespace, path: Path) -> bool:
    active, detail = runtime["maintenance_drain_active"](path)
    if active:
        runtime.get("print", print)(
            f"{runtime['project_now']()} {detail}; "
            "no additional AI work will be claimed",
            flush=True,
        )
    return active


def reconcile_worker_state(
    runtime: RuntimeNamespace,
    args: Any,
    indexed_mode: bool,
    *,
    controlled_evaluation: bool = False,
) -> int:
    if controlled_evaluation:
        return 0
    conn = runtime["sqlite3"].connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = runtime["sqlite3"].Row
    try:
        if indexed_mode:
            completed_group_ids = runtime[
                "indexed_reconcilable_ai_job_ids"
            ](conn)
        else:
            analyzed_ids = runtime["analyzed_alert_ids"](
                args.analysis_dir,
                args.pcap_analysis_dir,
                args.prompt_dir,
            )
            completed_group_ids = runtime["reconcilable_ai_job_ids"](
                conn,
                analyzed_ids,
                args.analysis_dir,
                args.pcap_analysis_dir,
                args.prompt_dir,
            )
    finally:
        conn.close()
    return runtime["reconcile_completed_ai_jobs"](
        args.alert_store_url,
        completed_group_ids,
    )


def terminal_success_recovery_candidates(
    runtime: RuntimeNamespace,
    alert_conn: Any,
    harness_conn: Any,
    provider_lane: str,
    *,
    limit: int = 32,
) -> list[dict[str, object]]:
    return runtime["load_terminal_success_recovery_candidates"](
        alert_conn,
        harness_conn,
        provider_lane,
        limit=limit,
    )


def scheduler_read_only_connection(runtime: RuntimeNamespace, path: Path) -> Any:
    conn = runtime["sqlite3"].connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = runtime["sqlite3"].Row
    return conn


def reconcile_terminal_success_durable_jobs(
    runtime: RuntimeNamespace,
    args: Any,
) -> int:
    provider_lane = str(getattr(args, "provider_lane", "any") or "any")
    harness_db = Path(
        getattr(
            args,
            "harness_db",
            args.db.parent / "investigation-harness.sqlite3",
        )
    )
    return runtime["reconcile_terminal_success"](
        runtime["terminal_recovery_sources"](),
        alert_db=args.db,
        harness_db=harness_db,
        provider_lane=provider_lane,
        alert_store_url=args.alert_store_url,
    )


def detect_indexed_scheduler_mode(runtime: RuntimeNamespace, path: Path) -> bool:
    conn = runtime["sqlite3"].connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = runtime["sqlite3"].Row
    try:
        return runtime["indexed_scheduler_available"](conn)
    finally:
        conn.close()


def main(runtime: RuntimeNamespace) -> int:
    return runtime["run_scheduler_application"](
        runtime["build_application_sources"](runtime)
    )
