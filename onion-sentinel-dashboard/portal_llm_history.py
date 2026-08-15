"""Pure durable LLM run projection and reconciliation policy."""
from __future__ import annotations

import datetime as dt


PARENT_RUN_FIELDS = (
    "alert",
    "gpu_temperature_celsius_max",
    "gpu_utilization_percent_max",
    "gpu_percent_max",
    "cpu_temperature_celsius_max",
    "soc_temperature_celsius_max",
    "memory_used_percent_max",
    "power_watts_max",
    "cpu_used_percent_max",
    "pcap_total_size_bytes",
    "alert_context_size_bytes",
)


def llm_analysis_run_timestamp(value: object) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        parsed = dt.datetime.fromisoformat(text.replace("  ", "T", 1))
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def llm_primary_run_identity(record: object) -> tuple[str, str, float]:
    current = record if isinstance(record, dict) else {}
    alert = current.get("alert") if isinstance(current.get("alert"), dict) else {}
    alert_id = str(
        alert.get("primary_alert_id") or current.get("alert_id") or ""
    ).strip()
    role = str(current.get("agent_role") or "soc-analyst").strip().lower()
    timestamp = llm_analysis_run_timestamp(
        current.get("finished_at")
        or current.get("generated_at")
        or current.get("started_at")
    )
    return alert_id, role.replace("_", "-"), timestamp


def _positive_alert_count(value: object) -> int:
    try:
        return max(1, int(value or 1))
    except (TypeError, ValueError):
        return 1


def project_database_primary_rows(rows: list[object]) -> list[dict]:
    logs = []
    for raw in rows:
        row = dict(raw)
        analysis_id = str(row.get("analysis_id") or "").strip()
        alert_id = str(row.get("alert_id") or "").strip()
        generated_at = str(row.get("generated_at") or "").strip()
        logs.append(
            {
                "log_id": analysis_id,
                "analysis_id": analysis_id,
                "run_kind": "primary_analysis",
                "agent_role": row.get("agent_role") or "soc-analyst",
                "status": "success",
                "model": row.get("model"),
                "model_path": row.get("model_path"),
                "model_route": "",
                "started_at": generated_at,
                "finished_at": generated_at,
                "runtime_seconds": None,
                "telemetry_source": "analysis_run_database",
                "error": "Committed analysis record; host telemetry unavailable",
                "alert": {
                    "primary_alert_id": alert_id,
                    "rule_name": row.get("rule_name") or "Security Onion alert",
                    "alert_count": _positive_alert_count(row.get("seen_count")),
                    "source_ip": row.get("source_ip"),
                    "destination_ip": row.get("destination_ip"),
                    "destination_port": row.get("destination_port"),
                },
            }
        )
    return logs


def _index_primary_logs(
    merged: list[dict],
) -> tuple[dict[str, int], dict[tuple[str, str], list[tuple[float, int]]]]:
    exact_ids = {}
    fallback: dict[tuple[str, str], list[tuple[float, int]]] = {}
    for index, item in enumerate(merged):
        run_id = str(item.get("analysis_id") or item.get("log_id") or "").strip()
        if run_id:
            exact_ids[run_id] = index
        alert_id, role, timestamp = llm_primary_run_identity(item)
        if alert_id and timestamp:
            fallback.setdefault((alert_id, role), []).append((timestamp, index))
    return exact_ids, fallback


def _confirm_database_identity(current: dict, database: dict) -> None:
    if not str(current.get("agent_role") or "").strip():
        current["agent_role"] = database.get("agent_role") or "soc-analyst"
    if not str(current.get("analysis_id") or "").strip():
        current["analysis_id"] = database.get("analysis_id")
    current["database_confirmed"] = True


def _fallback_match(
    fallback: dict[tuple[str, str], list[tuple[float, int]]],
    alert_id: str,
    role: str,
    timestamp: float,
) -> int | None:
    if not alert_id or not timestamp:
        return None
    return next(
        (
            index
            for observed, index in fallback.get((alert_id, role), ())
            if abs(timestamp - observed) <= 5.0
        ),
        None,
    )


def _merge_database_record(
    item: object,
    merged: list[dict],
    exact_ids: dict[str, int],
    fallback: dict[tuple[str, str], list[tuple[float, int]]],
) -> bool:
    if not isinstance(item, dict):
        return False
    run_id = str(item.get("analysis_id") or item.get("log_id") or "").strip()
    alert_id, role, timestamp = llm_primary_run_identity(item)
    matched = exact_ids.get(run_id) if run_id else None
    if matched is None:
        matched = _fallback_match(fallback, alert_id, role, timestamp)
    if matched is not None:
        _confirm_database_identity(merged[matched], item)
        return False
    merged.append(dict(item))
    index = len(merged) - 1
    if run_id:
        exact_ids[run_id] = index
    if alert_id and timestamp:
        fallback.setdefault((alert_id, role), []).append((timestamp, index))
    return True


def reconcile_llm_primary_logs(
    telemetry_logs: list[dict], database_logs: list[dict]
) -> tuple[list[dict], int]:
    merged = [dict(item) for item in telemetry_logs if isinstance(item, dict)]
    exact_ids, fallback = _index_primary_logs(merged)
    recovered = 0
    for item in database_logs:
        recovered += int(_merge_database_record(item, merged, exact_ids, fallback))
    return merged, recovered


def llm_reviewer_started_at(generated_at: object, runtime: object) -> str:
    text = str(generated_at or "").strip()
    try:
        seconds = max(0.0, float(runtime or 0))
        parsed = dt.datetime.fromisoformat(text.replace("  ", "T", 1))
    except (TypeError, ValueError, OverflowError):
        return text
    return (parsed - dt.timedelta(seconds=seconds)).isoformat(
        timespec="seconds"
    ).replace("T", "  ", 1)


def hydrate_llm_reviewer_from_parent(reviewer: dict, parent: dict | None) -> None:
    if not isinstance(parent, dict):
        return
    for key in PARENT_RUN_FIELDS:
        if key in parent:
            reviewer[key] = parent.get(key)


def _primary_by_id(primary_logs: list[dict]) -> dict[str, dict]:
    return {
        str(item.get("analysis_id") or item.get("log_id") or ""): item
        for item in primary_logs
        if isinstance(item, dict)
    }


def _reviewer_detail(row: dict) -> tuple[str, str, str]:
    error = str(row.get("reviewer_error") or "").strip()
    agreement = str(row.get("agreement") or "").strip()
    outcome = str(row.get("reviewer_outcome") or "").strip()
    parts = [
        error,
        f"Agreement: {agreement.replace('_', ' ')}" if agreement else "",
        f"Outcome: {outcome.replace('_', ' ')}" if outcome else "",
    ]
    return " · ".join(part for part in parts if part), agreement, outcome


def _project_second_opinion_row(row: dict, parent: dict) -> dict:
    analysis_id = str(row.get("analysis_id") or "")
    status = str(row.get("status") or "unknown").strip().lower()
    detail, agreement, outcome = _reviewer_detail(row)
    reviewer = {
        "log_id": f"{analysis_id}:second-opinion",
        "analysis_id": analysis_id,
        "parent_log_id": analysis_id,
        "run_kind": "second_opinion",
        "active_phase": "second_opinion",
        "phase_label": "Second-opinion review",
        "agent_role": row.get("agent_role"),
        "job_label": "Second-opinion review",
        "status": "success" if status == "completed" else status,
        "review_status": status,
        "error": detail,
        "trigger": row.get("trigger"),
        "model": row.get("reviewer_model"),
        "model_path": row.get("reviewer_model_path"),
        "model_route": row.get("reviewer_model_route") or "",
        "mode": "codex-cli" if row.get("reviewer_model_path") == "frontier-codex-cli" else row.get("reviewer_model_path"),
        "runtime_seconds": row.get("reviewer_runtime_seconds"),
        "started_at": llm_reviewer_started_at(row.get("generated_at"), row.get("reviewer_runtime_seconds")),
        "finished_at": row.get("generated_at"),
        "alert": parent.get("alert") or {"primary_alert_id": row.get("alert_id"), "rule_name": "Security Onion alert", "alert_count": 1},
        "reviewer_outcome": outcome,
        "reviewer_confidence": row.get("reviewer_confidence"),
        "agreement": agreement,
        "material_disagreement": bool(row.get("material_disagreement")),
    }
    hydrate_llm_reviewer_from_parent(reviewer, parent)
    return reviewer


def project_second_opinion_rows(rows: list[object], primary_logs: list[dict]) -> list[dict]:
    parents = _primary_by_id(primary_logs)
    return [
        _project_second_opinion_row(dict(raw), dict(parents.get(str(dict(raw).get("analysis_id") or "")) or {}))
        for raw in rows
    ]


def _adjudicator_mode(row: dict, route: str) -> str:
    if route.startswith("codex-cli:"):
        return "codex-cli"
    if route.startswith("ollama:"):
        return "ollama"
    return str(row.get("mode") or "shadow")


def _normalized_run_status(row: dict) -> str:
    status = str(row.get("status") or "unknown").strip().lower()
    return "success" if status == "completed" else status


def _fallback_alert(row: dict, parent: dict) -> dict:
    return parent.get("alert") or {
        "primary_alert_id": row.get("alert_id"),
        "rule_name": "Security Onion alert",
        "alert_count": 1,
    }


def _adjudicator_detail(error: str, decision: str, human_required: bool) -> str:
    parts = [error]
    if decision:
        parts.append(f"Decision: {decision.replace('_', ' ')}")
    if human_required:
        parts.append("Human adjudication required")
    return " · ".join(parts)


def _project_adjudication_row(row: dict, parent: dict) -> dict:
    analysis_id = str(row.get("analysis_id") or "")
    decision = str(row.get("decision") or "").strip()
    error = str(row.get("adjudicator_error") or "").strip()
    route = str(row.get("model_route") or "").strip()
    human_required = bool(row.get("human_adjudication_required"))
    mode = _adjudicator_mode(row, route)
    adjudicator = {
        "log_id": f"{analysis_id}:disagreement-adjudication",
        "analysis_id": analysis_id,
        "parent_log_id": analysis_id,
        "run_kind": "disagreement_adjudication",
        "active_phase": "disagreement_adjudication",
        "phase_label": "Disagreement adjudication",
        "agent_role": row.get("agent_role"),
        "job_label": "Disagreement adjudication",
        "status": _normalized_run_status(row),
        "review_status": str(row.get("status") or "unknown").strip().lower(),
        "error": _adjudicator_detail(error, decision, human_required),
        "model": route,
        "model_path": mode,
        "model_route": route,
        "mode": mode,
        "runtime_seconds": row.get("adjudicator_runtime_seconds"),
        "started_at": llm_reviewer_started_at(row.get("generated_at"), row.get("adjudicator_runtime_seconds")),
        "finished_at": row.get("generated_at"),
        "alert": _fallback_alert(row, parent),
        "adjudication_decision": decision,
        "adjudication_confidence": row.get("confidence"),
        "adjudication_confidence_score": row.get("confidence_score"),
        "human_adjudication_required": human_required,
    }
    hydrate_llm_reviewer_from_parent(adjudicator, parent)
    return adjudicator


def project_adjudication_rows(rows: list[object], primary_logs: list[dict]) -> list[dict]:
    parents = _primary_by_id(primary_logs)
    return [
        _project_adjudication_row(dict(raw), dict(parents.get(str(dict(raw).get("analysis_id") or "")) or {}))
        for raw in rows
    ]


def llm_log_sort_timestamp(record: dict) -> float:
    for key in ("started_at", "finished_at"):
        timestamp = llm_analysis_run_timestamp(record.get(key))
        if timestamp:
            return timestamp
    return 0.0


def compose_llm_activity_snapshot(
    telemetry_total: int,
    telemetry_loaded: int,
    primary_logs: list[dict],
    database_loaded: int,
    database_recovered: int,
    reviewer_logs: list[dict],
    adjudication_logs: list[dict],
    history_limit: int,
) -> dict:
    combined = [*primary_logs, *reviewer_logs, *adjudication_logs]
    combined.sort(key=lambda row: (llm_log_sort_timestamp(row), str(row.get("log_id") or "")), reverse=True)
    agent_totals = {}
    for record in combined:
        role = str(record.get("agent_role") or "unknown").strip().lower().replace("_", "-") or "unknown"
        agent_totals[role] = agent_totals.get(role, 0) + 1
    return {
        "primary_logs": primary_logs,
        "reviewer_logs": reviewer_logs,
        "adjudication_logs": adjudication_logs,
        "combined": combined,
        "telemetry_total": telemetry_total,
        "database_recovered_total": database_recovered,
        "agent_totals": agent_totals,
        "history_truncated": telemetry_total > telemetry_loaded or any(
            count >= history_limit
            for count in (
                database_loaded,
                len(reviewer_logs),
                len(adjudication_logs),
            )
        ),
    }
