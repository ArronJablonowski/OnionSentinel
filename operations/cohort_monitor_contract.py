#!/usr/bin/env python3
"""Durable-job state and credited-analysis time-window contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class CohortMonitorContract:
    cohort_error: type[RuntimeError]
    parse_timestamp: Callable[[Any, str], Any]


def durable_job_monitor_state(
    policy: CohortMonitorContract,
    job: Mapping[str, Any],
) -> str:
    status = str(job.get("status") or "")
    state = {
        "pending": "queued",
        "processing": "running",
        "completed": "completed",
        "failed": "failed",
    }.get(status)
    if state is None:
        raise policy.cohort_error(
            f"accepted durable job has unsupported status: {status!r}"
        )
    requested_at = policy.parse_timestamp(
        job.get("requested_at"), "accepted durable job requested_at"
    )
    updated_at = policy.parse_timestamp(
        job.get("updated_at"), "accepted durable job updated_at"
    )
    if updated_at < requested_at:
        raise policy.cohort_error(
            "accepted durable job timestamp order is inconsistent"
        )
    if status != "completed":
        return state
    completed_at = policy.parse_timestamp(
        job.get("completed_at"), "accepted durable job completed_at"
    )
    last_completed_at = policy.parse_timestamp(
        job.get("last_completed_at"), "accepted durable job last_completed_at"
    )
    if (
        completed_at < requested_at
        or last_completed_at < completed_at
        or updated_at < last_completed_at
    ):
        raise policy.cohort_error(
            "accepted durable job completion timestamps are inconsistent"
        )
    return state


def validate_completed_analysis_job_window(
    policy: CohortMonitorContract,
    *,
    dispatch: Mapping[str, Any],
    job: Mapping[str, Any],
    analysis: Mapping[str, Any],
) -> None:
    if str(job.get("status") or "") != "completed":
        raise policy.cohort_error(
            "credited analysis does not belong to a completed durable job"
        )
    timestamps = {
        "dispatch_started": policy.parse_timestamp(
            dispatch.get("started_at"), "credited dispatch started_at"
        ),
        "requested": policy.parse_timestamp(
            job.get("requested_at"), "credited durable job requested_at"
        ),
        "generated": policy.parse_timestamp(
            analysis.get("generated_at"), "credited analysis generated_at"
        ),
        "completed": policy.parse_timestamp(
            job.get("completed_at"), "credited durable job completed_at"
        ),
        "last_completed": policy.parse_timestamp(
            job.get("last_completed_at"),
            "credited durable job last_completed_at",
        ),
        "updated": policy.parse_timestamp(
            job.get("updated_at"), "credited durable job updated_at"
        ),
    }
    invalid = bool(
        timestamps["requested"] < timestamps["dispatch_started"]
        or timestamps["generated"] < timestamps["dispatch_started"]
        or timestamps["generated"] < timestamps["requested"]
        or timestamps["generated"] > timestamps["completed"]
        or timestamps["generated"] > timestamps["last_completed"]
        or timestamps["completed"] > timestamps["last_completed"]
        or timestamps["last_completed"] > timestamps["updated"]
    )
    if invalid:
        raise policy.cohort_error(
            "credited analysis falls outside its exact durable job window"
        )
