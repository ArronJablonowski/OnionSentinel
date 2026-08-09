"""Durable monitor contracts and bounded reanalysis state projection."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from cohort_monitor_contract import (
    CohortMonitorContract,
    durable_job_monitor_state as resolve_durable_job_monitor_state,
    validate_completed_analysis_job_window as validate_analysis_job_window,
)
from cohort_runner_contracts import CohortError


@dataclass(frozen=True)
class MonitorContractPorts:
    """Time parser required by durable-job monitor contracts."""

    parse_timestamp: Callable[[Any, str], Any]


def monitor_contract(ports: MonitorContractPorts) -> CohortMonitorContract:
    return CohortMonitorContract(
        cohort_error=CohortError,
        parse_timestamp=ports.parse_timestamp,
    )


def durable_job_monitor_state(
    ports: MonitorContractPorts,
    job: Mapping[str, Any],
) -> str:
    return resolve_durable_job_monitor_state(monitor_contract(ports), job)


def validate_completed_analysis_job_window(
    ports: MonitorContractPorts,
    *,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    analysis: Mapping[str, Any],
) -> None:
    validate_analysis_job_window(
        monitor_contract(ports),
        dispatch=dispatch,
        job=job,
        analysis=analysis,
    )


def reanalysis_monitor_case(
    connection: sqlite3.Connection,
    run_id: str,
    case_id: str,
) -> dict[str, Any] | None:
    """Project the bounded state needed to monitor one exact reanalysis case."""
    row = connection.execute(
        """
        SELECT run_id, case_id, group_id, dashboard_group_id,
               representative_alert_id, status, skip_reason, latest_error,
               queued_at, started_at, completed_at, latest_attempt_id,
               analysis_id, executed_model, executed_provider,
               executed_model_path, result_generated_at, updated_at
        FROM incident_reanalysis_run_cases
        WHERE run_id = ? AND case_id = ?
        """,
        (run_id, case_id),
    ).fetchone()
    return dict(row) if row else None
