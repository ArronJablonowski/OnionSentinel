"""Read-only proof and exact-lease recovery for terminal scheduler results."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DURABLE_JOB_COLUMNS = {
    "id", "job_type", "dedupe_key", "status", "payload_json",
    "lease_token", "processing_started_at",
}
ANALYSIS_COLUMNS = {
    "analysis_id", "group_id", "alert_id", "agent_role", "generated_at",
}
HARNESS_COLUMNS = {
    "run_id", "correlation_id", "case_id", "alert_id", "role", "status",
    "stage", "assigned_route", "completed_at",
}
INCIDENT_COLUMNS = {
    "case_id", "group_id", "agent_status", "latest_analysis_id",
    "latest_error",
}


@dataclass(frozen=True)
class TerminalRecoverySources:
    """Runtime boundaries used by terminal-success reconciliation."""

    connect_read_only: Callable[[Path], sqlite3.Connection]
    path_exists: Callable[[Path], bool]
    load_candidates: Callable[..., list[dict[str, object]]]
    report_status: Callable[..., bool]


@dataclass(frozen=True)
class RecoveryJob:
    job_id: int
    job_type: str
    group_id: str
    lease_token: str
    processing_started_at: str
    expected_role: str
    payload: dict[str, Any]

    @property
    def case_id(self) -> str:
        return str(self.payload.get("case_id") or "").strip()


@dataclass(frozen=True)
class RecoveryRun:
    run_id: str
    case_id: str
    alert_id: str
    assigned_route: str


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1])
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _route_matches_provider_lane(route: str, provider_lane: str) -> bool:
    normalized = str(route or "").strip().lower()
    prefixes = {"cli": "codex-cli:", "ollama": "ollama:"}
    prefix = prefixes.get(provider_lane)
    return bool(prefix and normalized.startswith(prefix))


def _required_schemas_ready(
    alert_conn: sqlite3.Connection,
    harness_conn: sqlite3.Connection,
) -> bool:
    return (
        DURABLE_JOB_COLUMNS.issubset(_table_columns(alert_conn, "durable_jobs"))
        and ANALYSIS_COLUMNS.issubset(
            _table_columns(alert_conn, "ai_analysis_runs")
        )
        and HARNESS_COLUMNS.issubset(
            _table_columns(harness_conn, "harness_runs")
        )
    )


def _load_payload(raw_payload: object) -> dict[str, Any] | None:
    try:
        payload = json.loads(str(raw_payload or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _expected_role(job_type: str) -> str:
    if job_type == "incident_response_analysis":
        return "incident-responder"
    return "soc-analyst"


def _payload_identity_matches(
    payload: dict[str, Any],
    *,
    group_id: str,
    expected_role: str,
    requires_case: bool,
) -> bool:
    payload_role = str(payload.get("agent_role") or expected_role).strip()
    if payload_role != expected_role:
        return False
    for key in ("group_id", "stable_group_id"):
        value = str(payload.get(key) or "").strip()
        if value and value != group_id:
            return False
    return not requires_case or bool(str(payload.get("case_id") or "").strip())


def _recovery_job(row: sqlite3.Row) -> RecoveryJob | None:
    job_type = str(row["job_type"] or "").strip()
    group_id = str(row["dedupe_key"] or "").strip()
    lease_token = str(row["lease_token"] or "").strip()
    payload = _load_payload(row["payload_json"])
    expected_role = _expected_role(job_type)
    requires_case = job_type == "incident_response_analysis"
    if payload is None or not _payload_identity_matches(
        payload,
        group_id=group_id,
        expected_role=expected_role,
        requires_case=requires_case,
    ):
        return None
    return RecoveryJob(
        job_id=int(row["id"]),
        job_type=job_type,
        group_id=group_id,
        lease_token=lease_token,
        processing_started_at=str(row["processing_started_at"] or ""),
        expected_role=expected_role,
        payload=payload,
    )


def _load_jobs(
    alert_conn: sqlite3.Connection,
    limit: int,
) -> list[RecoveryJob]:
    rows = alert_conn.execute(
        """
        SELECT id, job_type, dedupe_key, payload_json, lease_token,
               processing_started_at
        FROM durable_jobs
        WHERE status = 'processing'
          AND job_type IN ('ai_analysis', 'incident_response_analysis')
          AND lease_token IS NOT NULL AND TRIM(lease_token) != ''
          AND processing_started_at IS NOT NULL
        ORDER BY processing_started_at ASC, id ASC
        LIMIT ?
        """,
        (max(1, min(int(limit), 128)),),
    ).fetchall()
    return [job for row in rows if (job := _recovery_job(row)) is not None]


def _load_runs(
    harness_conn: sqlite3.Connection,
    job: RecoveryJob,
) -> list[RecoveryRun]:
    rows = harness_conn.execute(
        """
        SELECT run_id, case_id, alert_id, assigned_route
        FROM harness_runs
        WHERE correlation_id = ? AND role = ?
          AND status = 'succeeded' AND stage = 'complete'
          AND completed_at IS NOT NULL
        ORDER BY completed_at DESC, run_id DESC
        LIMIT 8
        """,
        (job.group_id, job.expected_role),
    ).fetchall()
    return [
        RecoveryRun(
            run_id=str(row["run_id"] or "").strip(),
            case_id=str(row["case_id"] or "").strip(),
            alert_id=str(row["alert_id"] or "").strip(),
            assigned_route=str(row["assigned_route"] or "").strip(),
        )
        for row in rows
    ]


def _run_route_matches(
    job: RecoveryJob,
    run: RecoveryRun,
    provider_lane: str,
) -> bool:
    if not run.run_id or not run.alert_id:
        return False
    if not _route_matches_provider_lane(run.assigned_route, provider_lane):
        return False
    expected_route = str(
        job.payload.get("expected_assigned_route")
        or job.payload.get("assigned_route")
        or ""
    ).strip()
    if expected_route and expected_route != run.assigned_route:
        return False
    return True


def _payload_alerts_match(job: RecoveryJob, run: RecoveryRun) -> bool:
    payload_alerts = {
        str(job.payload.get(key) or "").strip()
        for key in ("alert_id", "representative_alert_id")
        if str(job.payload.get(key) or "").strip()
    }
    return not payload_alerts or payload_alerts == {run.alert_id}


def _run_identity_matches(
    job: RecoveryJob,
    run: RecoveryRun,
    provider_lane: str,
) -> bool:
    return _run_route_matches(
        job,
        run,
        provider_lane,
    ) and _payload_alerts_match(job, run)


def _incident_commit_matches(
    alert_conn: sqlite3.Connection,
    incident_columns: set[str],
    job: RecoveryJob,
    run: RecoveryRun,
) -> bool:
    if job.job_type != "incident_response_analysis":
        return True
    if run.case_id != job.case_id or not INCIDENT_COLUMNS.issubset(incident_columns):
        return False
    row = alert_conn.execute(
        """
        SELECT 1 FROM incident_response_cases
        WHERE case_id = ? AND group_id = ?
          AND agent_status = 'analyzed'
          AND latest_analysis_id = ?
          AND latest_error IS NULL
        """,
        (job.case_id, job.group_id, run.run_id),
    ).fetchone()
    return row is not None


def _analysis_commit_matches(
    alert_conn: sqlite3.Connection,
    job: RecoveryJob,
    run: RecoveryRun,
) -> bool:
    row = alert_conn.execute(
        """
        SELECT 1 FROM ai_analysis_runs
        WHERE analysis_id = ? AND group_id = ? AND alert_id = ?
          AND agent_role = ?
          AND julianday(replace(generated_at, '  ', 'T')) >=
              julianday(replace(?, '  ', 'T'))
        """,
        (
            run.run_id,
            job.group_id,
            run.alert_id,
            job.expected_role,
            job.processing_started_at,
        ),
    ).fetchone()
    return row is not None


def _proven_run(
    alert_conn: sqlite3.Connection,
    harness_conn: sqlite3.Connection,
    incident_columns: set[str],
    job: RecoveryJob,
    provider_lane: str,
) -> RecoveryRun | None:
    for run in _load_runs(harness_conn, job):
        if not _run_identity_matches(job, run, provider_lane):
            continue
        if not _incident_commit_matches(alert_conn, incident_columns, job, run):
            continue
        if _analysis_commit_matches(alert_conn, job, run):
            return run
    return None


def _candidate(job: RecoveryJob, run: RecoveryRun) -> dict[str, object]:
    return {
        "job_id": job.job_id,
        "job_type": job.job_type,
        "group_id": job.group_id,
        "lease_token": job.lease_token,
        "analysis_id": run.run_id,
    }


def terminal_success_recovery_candidates(
    alert_conn: sqlite3.Connection,
    harness_conn: sqlite3.Connection,
    provider_lane: str,
    *,
    limit: int = 32,
) -> list[dict[str, object]]:
    """Prove exact terminal commits eligible for no-inference recovery."""
    if provider_lane not in {"cli", "ollama"}:
        return []
    if not _required_schemas_ready(alert_conn, harness_conn):
        return []
    incident_columns = _table_columns(alert_conn, "incident_response_cases")
    candidates: list[dict[str, object]] = []
    for job in _load_jobs(alert_conn, limit):
        run = _proven_run(
            alert_conn,
            harness_conn,
            incident_columns,
            job,
            provider_lane,
        )
        if run is not None:
            candidates.append(_candidate(job, run))
    return candidates


def _load_from_paths(
    sources: TerminalRecoverySources,
    alert_db: Path,
    harness_db: Path,
    provider_lane: str,
) -> list[dict[str, object]]:
    alert_conn = sources.connect_read_only(alert_db)
    try:
        harness_conn = sources.connect_read_only(harness_db)
        try:
            return sources.load_candidates(
                alert_conn,
                harness_conn,
                provider_lane,
            )
        finally:
            harness_conn.close()
    finally:
        alert_conn.close()


def reconcile_terminal_success(
    sources: TerminalRecoverySources,
    *,
    alert_db: Path,
    harness_db: Path,
    provider_lane: str,
    alert_store_url: str,
) -> int:
    """Report completion for exact, still-owned stranded scheduler leases."""
    if provider_lane not in {"cli", "ollama"}:
        return 0
    if not sources.path_exists(harness_db):
        return 0
    candidates = _load_from_paths(
        sources,
        alert_db,
        harness_db,
        provider_lane,
    )
    return sum(
        bool(sources.report_status(
            alert_store_url,
            str(candidate["group_id"]),
            "completed",
            lease_token=str(candidate["lease_token"]),
            job_type=str(candidate["job_type"]),
        ))
        for candidate in candidates
    )
