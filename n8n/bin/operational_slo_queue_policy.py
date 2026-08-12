"""Pure durable-job and pipeline-throughput SLO evaluation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class JobSignals:
    aggregate_age: int
    enrichment_age: int
    ai_age: int
    incident_age: int
    completion_ages: dict[str, int]
    processing_ages: dict[str, int]
    ai_pending: int
    ai_processing: int
    incident_pending: int
    incident_processing: int

    @property
    def combined(self) -> int:
        return self.ai_pending + self.incident_pending


def _typed_values(
    rows: object,
    *,
    value_name: str,
    required_status: str | None = None,
) -> dict[str, int]:
    values: dict[str, int] = {}
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        if required_status is not None and str(item.get("status") or "") != required_status:
            continue
        values[str(item.get("job_type") or "")] = int(item.get(value_name) or 0)
    return values


def _job_state(metrics: dict[str, object]) -> JobSignals:
    pending_ages = _typed_values(
        metrics.get("oldest_pending_jobs"), value_name="seconds"
    )
    completion_ages = _typed_values(
        metrics.get("latest_completed_jobs"), value_name="seconds"
    )
    processing_ages = _typed_values(
        metrics.get("oldest_processing_jobs"), value_name="seconds"
    )
    pending_counts = _typed_values(
        metrics.get("durable_jobs"), value_name="count", required_status="pending"
    )
    processing_counts = _typed_values(
        metrics.get("durable_jobs"), value_name="count", required_status="processing"
    )
    aggregate_age = int(metrics.get("oldest_pending_job_seconds") or 0)
    fallback_age = aggregate_age if not pending_ages else 0
    return JobSignals(
        aggregate_age=aggregate_age,
        enrichment_age=pending_ages.get("public_enrichment", fallback_age),
        ai_age=pending_ages.get("ai_analysis", fallback_age),
        incident_age=pending_ages.get("incident_response_analysis", 0),
        completion_ages=completion_ages,
        processing_ages=processing_ages,
        ai_pending=pending_counts.get("ai_analysis", 0),
        ai_processing=processing_counts.get("ai_analysis", 0),
        incident_pending=pending_counts.get("incident_response_analysis", 0),
        incident_processing=processing_counts.get("incident_response_analysis", 0),
    )


def _evaluate_worker_queue(
    *,
    label: str,
    pending_count: int,
    processing_count: int,
    pending_age: int,
    processing_age: int | None,
    completion_age: int | None,
    failures: list[str],
) -> None:
    if processing_count and (processing_age is None or processing_age > 15 * 60):
        failures.append(
            f"{label} has been processing without state progress for 15 minutes"
        )
    elif (
        pending_count
        and not processing_count
        and pending_age > 30 * 60
        and (completion_age is None or completion_age > 30 * 60)
    ):
        failures.append(f"{label} has pending work but no completion within 30 minutes")


def _evaluate_workers(state: JobSignals, failures: list[str]) -> None:
    if state.enrichment_age > 15 * 60:
        failures.append("enrichment job backlog exceeds 15 minutes")
    _evaluate_worker_queue(
        label="AI analysis",
        pending_count=state.ai_pending,
        processing_count=state.ai_processing,
        pending_age=state.ai_age,
        processing_age=state.processing_ages.get("ai_analysis"),
        completion_age=state.completion_ages.get("ai_analysis"),
        failures=failures,
    )
    _evaluate_worker_queue(
        label="incident-response analysis",
        pending_count=state.incident_pending,
        processing_count=state.incident_processing,
        pending_age=state.incident_age,
        processing_age=state.processing_ages.get("incident_response_analysis"),
        completion_age=state.completion_ages.get("incident_response_analysis"),
        failures=failures,
    )


def _evaluate_growth(
    state: JobSignals,
    previous_counts: dict[str, int],
    advisories: list[str],
) -> None:
    previous_combined = int(previous_counts.get("ai_analysis") or 0) + int(
        previous_counts.get("incident_response_analysis") or 0
    )
    material_growth = max(5, int(previous_combined * 0.05))
    if (
        previous_combined > 0
        and state.combined >= 25
        and state.combined - previous_combined >= material_growth
    ):
        advisories.append(
            "combined AI and incident-response queues are growing faster than the bounded soak gate"
        )


def _evaluate_pipeline_stage(
    stage: dict[str, object],
    label: str,
    advisories: list[str],
) -> None:
    pending = int(stage.get("pending") or 0)
    throughput = dict(stage.get("throughput") or {}).get("15m", {})
    arrivals = int(throughput.get("enqueued") or 0)
    completions = int(throughput.get("completed") or 0)
    drain_eta = stage.get("drain_eta_seconds")
    if pending >= 25 and arrivals > completions:
        advisories.append(f"{label} 15-minute arrivals exceed completions")
    if pending >= 25 and drain_eta is not None and int(drain_eta) > 4 * 60 * 60:
        advisories.append(f"{label} projected drain time exceeds 4 hours")


def _evaluate_pipeline(
    stages: dict[str, dict[str, object]],
    advisories: list[str],
) -> None:
    for stage_name, label in (
        ("ai_analysis", "AI analysis"),
        ("incident_response_analysis", "incident-response analysis"),
        ("pcap_transfer", "PCAP transfer"),
    ):
        _evaluate_pipeline_stage(stages.get(stage_name, {}), label, advisories)


def _project_job_signals(state: JobSignals) -> dict[str, object]:
    return {
        "oldest_pending_job_seconds": state.aggregate_age,
        "oldest_pending_enrichment_job_seconds": state.enrichment_age,
        "oldest_pending_ai_job_seconds": state.ai_age,
        "latest_ai_completion_age_seconds": state.completion_ages.get("ai_analysis"),
        "oldest_ai_processing_seconds": state.processing_ages.get("ai_analysis"),
        "pending_ai_job_count": state.ai_pending,
        "processing_ai_job_count": state.ai_processing,
        "oldest_pending_incident_response_job_seconds": state.incident_age,
        "latest_incident_response_completion_age_seconds": state.completion_ages.get(
            "incident_response_analysis"
        ),
        "oldest_incident_response_processing_seconds": state.processing_ages.get(
            "incident_response_analysis"
        ),
        "pending_incident_response_job_count": state.incident_pending,
        "processing_incident_response_job_count": state.incident_processing,
        "combined_analysis_pending_job_count": state.combined,
    }


def evaluate_jobs(
    metrics: dict[str, object],
    pipeline_stages: dict[str, dict[str, object]],
    previous_counts: dict[str, int],
    failures: list[str],
    advisories: list[str],
) -> dict[str, object]:
    state = _job_state(metrics)
    _evaluate_workers(state, failures)
    _evaluate_growth(state, previous_counts, advisories)
    _evaluate_pipeline(pipeline_stages, advisories)
    return _project_job_signals(state)
