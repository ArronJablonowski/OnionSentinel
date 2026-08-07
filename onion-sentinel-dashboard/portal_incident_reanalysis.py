"""Query policy and read repository for Incident Response reanalysis progress."""
from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3


RUN_ID_PATTERN = re.compile(r"irr-[a-z0-9-]{1,64}")
RUN_CASE_STATUSES = ("queued", "running", "completed", "failed", "skipped")


class IncidentReanalysisQueryError(ValueError):
    """Raised when a progress request contains an invalid run identifier."""


@dataclass(frozen=True)
class IncidentReanalysisProgress:
    schema_ready: bool
    runs: list[dict]
    cases: list[dict]


def parse_reanalysis_run_id(query: dict[str, list[str]]) -> str:
    run_id = str((query.get("run_id") or [""])[0] or "").strip().lower()
    if run_id and not RUN_ID_PATTERN.fullmatch(run_id):
        raise IncidentReanalysisQueryError("Invalid incident reanalysis run id")
    return run_id


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return bool(row)


def _load_runs(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    where_sql = "WHERE run_id = ?" if run_id else ""
    arguments = [run_id] if run_id else []
    rows = conn.execute(
        f"""
        SELECT run_id, release_id, scope, status, requested_by, reason,
               total_count, created_at, updated_at, completed_at
        FROM incident_reanalysis_runs
        {where_sql}
        ORDER BY created_at DESC, run_id DESC LIMIT 20
        """,
        arguments,
    ).fetchall()
    return [dict(row) for row in rows]


def _empty_counts(run_ids: list[str]) -> dict[str, dict[str, int]]:
    return {
        run_id: {status: 0 for status in RUN_CASE_STATUSES}
        for run_id in run_ids
    }


def _load_counts(
    conn: sqlite3.Connection,
    run_ids: list[str],
) -> dict[str, dict[str, int]]:
    counts = _empty_counts(run_ids)
    if not run_ids or not _table_exists(conn, "incident_reanalysis_run_cases"):
        return counts
    placeholders = ",".join("?" for _ in run_ids)
    rows = conn.execute(
        f"""
        SELECT run_id, status, COUNT(*) AS count
        FROM incident_reanalysis_run_cases
        WHERE run_id IN ({placeholders})
        GROUP BY run_id, status
        """,
        run_ids,
    ).fetchall()
    for row in rows:
        run_counts = counts.get(str(row["run_id"] or ""))
        status = str(row["status"] or "")
        if run_counts is not None and status in run_counts:
            run_counts[status] = int(row["count"] or 0)
    return counts


def _attach_counts(
    runs: list[dict],
    counts: dict[str, dict[str, int]],
) -> list[dict]:
    enriched = []
    for run in runs:
        item = dict(run)
        item["total_count"] = int(item.get("total_count") or 0)
        item["counts"] = counts.get(str(item.get("run_id") or ""), {})
        enriched.append(item)
    return enriched


def _load_cases(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    if not run_id or not _table_exists(conn, "incident_reanalysis_run_cases"):
        return []
    rows = conn.execute(
        """
        SELECT run_id, case_id, group_id, dashboard_group_id,
               representative_alert_id, status, skip_reason,
               latest_error, queued_at, started_at, completed_at,
               updated_at
        FROM incident_reanalysis_run_cases
        WHERE run_id = ?
        ORDER BY case_id ASC LIMIT 2000
        """,
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def load_reanalysis_progress(
    conn: sqlite3.Connection,
    run_id: str,
) -> IncidentReanalysisProgress:
    if not _table_exists(conn, "incident_reanalysis_runs"):
        return IncidentReanalysisProgress(False, [], [])
    runs = _load_runs(conn, run_id)
    run_ids = [str(item.get("run_id") or "") for item in runs]
    runs = _attach_counts(runs, _load_counts(conn, run_ids))
    selected = run_id or (run_ids[0] if run_ids else "")
    return IncidentReanalysisProgress(
        True,
        runs,
        _load_cases(conn, selected),
    )


def compose_reanalysis_progress_payload(
    progress: IncidentReanalysisProgress,
) -> dict:
    return {
        "ok": True,
        "latest_run": progress.runs[0] if progress.runs else None,
        "runs": progress.runs,
        "cases": progress.cases,
        "schema_ready": progress.schema_ready,
    }
