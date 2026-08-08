"""Bounded Hermes cron-failure collection and escaped rendering."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import datetime as dt
import html
import json
from pathlib import Path
import re


@dataclass(frozen=True)
class CronFailureSources:
    jobs_file: Path
    output_dir: Path
    parse_timestamp: Callable[[object], dt.datetime]
    format_timestamp: Callable[[dt.datetime], str]
    redact: Callable[[str], str]


def _failure_status(status: str) -> bool:
    normalized = status.lower().strip()
    return bool(normalized) and any(
        marker in normalized for marker in ("fail", "error", "timeout", "exception")
    )


def _parse_time(value: object, sources: CronFailureSources) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = sources.parse_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone()
    except Exception:
        return None


def _job_index(sources: CronFailureSources) -> dict[str, dict]:
    try:
        data = json.loads(sources.jobs_file.read_text(encoding="utf-8"))
    except Exception:
        return {}
    jobs = {}
    raw_jobs = data.get("jobs") if isinstance(data, dict) else []
    if not isinstance(raw_jobs, list):
        return jobs
    for job in raw_jobs:
        if not isinstance(job, dict):
            continue
        job_id = str(job.get("id") or job.get("job_id") or "").strip()
        if job_id:
            jobs[job_id] = job
    return jobs


def _output_files(sources: CronFailureSources) -> list[Path]:
    try:
        candidates = [
            path for path in sources.output_dir.rglob("*.md") if path.is_file()
        ]
        return sorted(
            candidates, key=lambda path: path.stat().st_mtime, reverse=True
        )[:300]
    except Exception:
        return []


def _match(pattern: str, text: str) -> str:
    matched = re.search(pattern, text, re.MULTILINE)
    return matched.group(1).strip() if matched else ""


def _read_output(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _output_identity(
    path: Path, text: str, jobs: dict[str, dict]
) -> tuple[str, str]:
    job_id = _match(r"^\*\*Job ID:\*\*\s*(.+)$", text) or path.parent.name
    name = _match(r"^#\s+Cron Job:\s*(.+)$", text)
    fallback_name = str(jobs.get(job_id, {}).get("name") or "Unnamed cron")
    return job_id or "unknown", name or fallback_name


def _file_time(path: Path) -> dt.datetime | None:
    try:
        return dt.datetime.fromtimestamp(path.stat().st_mtime).astimezone()
    except OSError:
        return None


def _output_record(
    path: Path, jobs: dict[str, dict], sources: CronFailureSources
) -> dict | None:
    text = _read_output(path)
    if text is None:
        return None
    status = _match(r"^\*\*Status:\*\*\s*(.+)$", text)
    if not _failure_status(status):
        return None
    job_id, name = _output_identity(path, text, jobs)
    run_time = _match(r"^\*\*Run Time:\*\*\s*(.+)$", text)
    return {
        "job_id": job_id,
        "name": name,
        "status": status or "error",
        "when": _parse_time(run_time, sources) if run_time else _file_time(path),
        "detail": sources.redact(text.strip()) if text else "No failure detail recorded.",
        "source": path,
    }


def _job_time_value(job: dict) -> object:
    return job.get("last_run_at") or job.get("updated_at") or job.get("created_at")


def _job_failure_detail(status: str, error: str) -> str:
    return error or f"Last status: {status}"


def _job_record(
    job_id: str, job: dict, sources: CronFailureSources
) -> dict | None:
    status = str(job.get("last_status") or "")
    error = str(job.get("last_error") or "")
    if not error and not _failure_status(status):
        return None
    when = _parse_time(_job_time_value(job), sources)
    detail = _job_failure_detail(status, error)
    return {
        "job_id": job_id or "unknown",
        "name": str(job.get("name") or "Unnamed cron"),
        "status": status or "error",
        "when": when,
        "detail": sources.redact(detail.strip()) if detail else "No failure detail recorded.",
        "source": None,
    }


def _same_run(record: dict, candidate: dict) -> bool:
    record_time = record.get("when")
    candidate_time = candidate.get("when")
    return (
        record.get("job_id") == candidate.get("job_id")
        and isinstance(record_time, dt.datetime)
        and isinstance(candidate_time, dt.datetime)
        and abs((record_time - candidate_time).total_seconds()) <= 5
    )


def _record_key(record: dict, jobs_file: Path) -> tuple[str, str]:
    source = record.get("source")
    source_key = str(source) if source else str(record.get("when") or jobs_file)
    return str(record.get("job_id") or "unknown"), source_key


def compose_cron_failure_records(
    sources: CronFailureSources, limit: int = 12
) -> list[dict]:
    """Collect recent failed runs from output artifacts and jobs.json fallback state."""
    jobs = _job_index(sources)
    records = [
        record
        for path in _output_files(sources)
        if (record := _output_record(path, jobs, sources)) is not None
    ]
    for job_id, job in jobs.items():
        candidate = _job_record(job_id, job, sources)
        if candidate is not None and not any(
            _same_run(record, candidate) for record in records
        ):
            records.append(candidate)
    unique = {}
    for record in records:
        unique.setdefault(_record_key(record, sources.jobs_file), record)
    epoch = dt.datetime.fromtimestamp(0).astimezone()
    ordered = sorted(
        unique.values(), key=lambda record: record.get("when") or epoch, reverse=True
    )
    return ordered[: max(0, limit)]


def _when_label(record: dict, sources: CronFailureSources) -> str:
    when = record.get("when")
    if not isinstance(when, dt.datetime):
        return "unknown time"
    return sources.format_timestamp(when.astimezone())


def _record_fragments(
    index: int, record: dict, sources: CronFailureSources
) -> tuple[str, str]:
    when_label = _when_label(record, sources)
    source = record.get("source")
    source_label = str(source) if source else str(sources.jobs_file)
    detail = str(record.get("detail") or "No failure detail recorded.")[-9000:]
    name = str(record.get("name") or "Unnamed cron")
    status = str(record.get("status") or "error")
    job_id = str(record.get("job_id") or "unknown")
    row = (
        f"<tr><td>{index}</td><td>{html.escape(name)}<br><code>{html.escape(job_id)}</code></td>"
        f'<td><span class="badge warn">{html.escape(status)}</span></td>'
        f"<td>{html.escape(when_label)}</td><td><code>{html.escape(source_label)}</code></td></tr>"
    )
    detail_block = (
        f'<details class="cron-failure-detail" {"open" if index == 1 else ""}>'
        f"<summary>{html.escape(name)} · {html.escape(status)} · {html.escape(when_label)}</summary>"
        f"<pre>{html.escape(detail)}</pre></details>"
    )
    return row, detail_block


def render_cron_failure_log(
    records: list[dict], sources: CronFailureSources
) -> str:
    """Render one escaped Administration section from collected failure records."""
    jobs_path = html.escape(str(sources.jobs_file))
    output_path = html.escape(str(sources.output_dir))
    if not records:
        body = (
            f"<p>No failed Hermes cron runs found in <code>{jobs_path}</code> "
            f"or <code>{output_path}</code>.</p>"
        )
    else:
        fragments = [
            _record_fragments(index, record, sources)
            for index, record in enumerate(records, 1)
        ]
        rows = "".join(row for row, _detail in fragments)
        details = "".join(detail for _row, detail in fragments)
        body = (
            f"<p>Recent failed Hermes cron runs from <code>{jobs_path}</code> "
            f"and <code>{output_path}</code>.</p>"
            "<table><thead><tr><th>#</th><th>Job</th><th>Status</th><th>Run time</th>"
            f"<th>Source</th></tr></thead><tbody>{rows}</tbody></table>{details}"
        )
    return (
        '<section class="section cron-failure-log"><h2>Cron failure log</h2>'
        f"{body}</section>"
    )
