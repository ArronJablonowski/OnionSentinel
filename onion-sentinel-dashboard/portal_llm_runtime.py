"""Runtime wiring for bounded LLM activity and durable history projections."""
from __future__ import annotations

from typing import Any


def llm_analysis_log_limit(r: Any, raw: object) -> int:
    return r.bounded_llm_analysis_log_limit(raw)


def llm_analysis_log_page(r: Any, raw: object) -> int:
    return r.bounded_llm_analysis_log_page(raw)


def read_llm_analysis_logs(r: Any, max_rows: int = 1000) -> list[dict]:
    return r.SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.tail(max_rows)


def current_llm_queue_size(r: Any) -> int:
    return r.llm_queue_size(r.read_soc_alert_json_file(r.SOC_ALERT_STATIC_STATUS_FILE))


def read_bounded_llm_analysis_record(r: Any, path: Any) -> dict:
    return r.read_bounded_llm_record(path, r.SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES)


def active_llm_analysis_record_paths(r: Any) -> list[Any]:
    return r.active_llm_record_paths(
        r.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR, r.SOC_ALERT_LLM_ANALYSIS_ACTIVE_LIMIT
    )


def active_llm_sources(r: Any) -> Any:
    return r.ActiveLlmSources(
        active_directory=r.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR,
        record_max_bytes=r.SOC_ALERT_LLM_ANALYSIS_RECORD_MAX_BYTES,
        active_limit=r.SOC_ALERT_LLM_ANALYSIS_ACTIVE_LIMIT,
        process_commands=r.llm_analysis_process_commands,
    )


def read_active_llm_analyses(r: Any) -> list[dict]:
    return r.load_active_llm_analyses(r.active_llm_sources())


def llm_agent_execution_state(r: Any, record: object) -> dict:
    return r.project_llm_agent_execution_state(record)


def decorate_llm_analysis_record(r: Any, record: object, *, live: bool) -> dict:
    return r.project_llm_analysis_record(record, live=live)


def read_llm_current_analysis(r: Any) -> dict:
    queue_size = r.current_llm_queue_size()
    active_runs = r.read_active_llm_analyses()
    data = {} if active_runs else r.read_bounded_llm_analysis_record(
        r.SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE
    )
    return r.compose_current_llm_analysis(
        queue_size, active_runs, data, r.llm_analysis_process_active
    )


def merge_live_llm_activity(r: Any, static_ai: object, current: object) -> dict:
    return r.project_live_llm_activity(static_ai, current)


def llm_analysis_process_commands(r: Any) -> list[str]:
    try:
        proc = r.subprocess.run(
            ["ps", "axo", "pid=,command="], check=False, text=True,
            stdout=r.subprocess.PIPE, stderr=r.subprocess.PIPE, timeout=3,
        )
    except Exception:
        return []
    return proc.stdout.splitlines()


def llm_analysis_process_active(
    r: Any, prompt_package: str, commands: list[str] | None = None,
    runner_pid: object = None,
) -> bool:
    commands = commands if commands is not None else r.llm_analysis_process_commands()
    return r.active_llm_process_present(prompt_package, commands, runner_pid)


def llm_history_store_sources(r: Any) -> Any:
    return r.LlmHistoryStoreSources(
        connect=r.soc_alert_db_connect,
        history_limit=r.LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
    )


def llm_analysis_run_timestamp(r: Any, value: object) -> float:
    return r.projected_llm_run_timestamp(value)


def llm_primary_run_identity(r: Any, record: object) -> tuple[str, str, float]:
    return r.projected_llm_primary_identity(record)


def read_llm_database_primary_logs(r: Any, *, limit: int | None = None) -> list[dict]:
    limit = r.LLM_ANALYSIS_COMBINED_HISTORY_LIMIT if limit is None else limit
    rows = r.read_primary_history_rows(r.llm_history_store_sources(), limit=limit)
    return r.project_database_primary_rows(rows)


def reconcile_llm_primary_logs(r: Any, telemetry_logs: list[dict], database_logs: list[dict]) -> tuple[list[dict], int]:
    return r.reconcile_projected_llm_primary_logs(telemetry_logs, database_logs)


def llm_reviewer_started_at(r: Any, generated_at: object, runtime: object) -> str:
    return r.projected_llm_reviewer_started_at(generated_at, runtime)


def hydrate_llm_reviewer_from_parent(r: Any, reviewer: dict, parent: dict | None) -> None:
    r.hydrate_projected_llm_reviewer(reviewer, parent)


def read_llm_second_opinion_logs(r: Any, primary_logs: list[dict], *, limit: int | None = None) -> list[dict]:
    limit = r.LLM_ANALYSIS_COMBINED_HISTORY_LIMIT if limit is None else limit
    rows = r.read_second_opinion_history_rows(r.llm_history_store_sources(), limit=limit)
    return r.project_second_opinion_rows(rows, primary_logs)


def read_llm_disagreement_adjudication_logs(r: Any, primary_logs: list[dict], *, limit: int | None = None) -> list[dict]:
    limit = r.LLM_ANALYSIS_COMBINED_HISTORY_LIMIT if limit is None else limit
    rows = r.read_adjudication_history_rows(r.llm_history_store_sources(), limit=limit)
    return r.project_adjudication_rows(rows, primary_logs)


def llm_log_sort_timestamp(r: Any, record: dict) -> float:
    return r.projected_llm_log_sort_timestamp(record)


def llm_history_api_sources(r: Any) -> Any:
    return r.LlmHistoryApiSources(
        telemetry_page=lambda page, limit: r.SOC_ALERT_LLM_ANALYSIS_LOG_INDEX.page(page=page, limit=limit),
        read_database_primary=r.read_llm_database_primary_logs,
        reconcile_primary=r.reconcile_llm_primary_logs,
        read_reviewer=r.read_llm_second_opinion_logs,
        read_adjudication=r.read_llm_disagreement_adjudication_logs,
        compose_snapshot=r.compose_llm_activity_snapshot,
        read_active=r.read_active_llm_analyses,
        decorate=lambda record, live: r.decorate_llm_analysis_record(record, live=live),
        cache=r.LLM_AGENT_ACTIVITY_CACHE,
        history_limit=r.LLM_ANALYSIS_COMBINED_HISTORY_LIMIT,
    )


def read_llm_agent_activity_snapshot(r: Any) -> dict:
    return r.load_llm_agent_activity_snapshot(r.llm_history_api_sources())


def llm_analysis_logs_response(r: Any, query: dict[str, list[str]]) -> dict:
    return r.compose_llm_analysis_logs_response(r.llm_history_api_sources(), query)
