"""Legacy runtime, persistence, and settings compatibility delegates."""
from __future__ import annotations

from local_ai_runtime_contract import *  # noqa: F403

def _analysis_entrypoint():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis import entrypoint
    return entrypoint


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def filename_timestamp(value: str) -> str:
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$", value)
    if match:
        year, month, day, hour, minute, second, zone = match.groups()
        return f"{year}{month}{day}-{hour}{minute}{second}{zone.replace(':', '')}"
    return safe_filename(value)


def safe_filename(value: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "alert")).strip("-")
    return (cleaned or "alert")[:120]


def _system_resources():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis import system_resources
    return system_resources


def _runtime_io():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis import runtime_io
    return runtime_io


def _persistence_runtime_adapter():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel.analysis.persistence import runtime_adapter
    return runtime_adapter


def _startup_runtime_adapter():
    package_root = str(BIN_DIR.parent)
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from onion_sentinel import startup_runtime_adapter
    return startup_runtime_adapter


def _system_resource_dependencies():
    module = _system_resources()
    return module.Dependencies(
        environment=os.environ,
        path_exists=lambda path: path.exists(),
        run_command=run_bounded_command,
        process_error=BoundedProcessError,
    )


def read_mactop_system_sample(
    *,
    cancel_event: threading.Event | None = None,
) -> tuple[
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    float | None,
    str,
]:
    return _system_resources().read_mactop_system_sample(
        dependencies=_system_resource_dependencies(),
        cancel_event=cancel_event,
    )


def read_gpu_temperature_celsius(
    *,
    cancel_event: threading.Event | None = None,
) -> tuple[float | None, str]:
    return _system_resources().read_gpu_temperature_celsius(
        dependencies=_system_resource_dependencies(),
        cancel_event=cancel_event,
    )
def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    _runtime_io().atomic_write_json(path, data)


def atomic_write_private_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically write owner-only runtime state."""
    _runtime_io().atomic_write_private_json(path, data)


def canonical_payload_digest(value: Any) -> str:
    return _runtime_io().canonical_payload_digest(value)


def active_analysis_record_path(run_id: object, active_dir: Path | None = None) -> Path:
    return _runtime_io().active_analysis_record_path(run_id, active_dir if active_dir is not None else DEFAULT_LLM_ACTIVE_DIR)


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    _runtime_io().append_jsonl(path, data)


def best_effort_warning(message: str) -> None:
    """Report supplemental failures without risking the committed job result."""
    _runtime_io().best_effort_warning(message)


def analysis_index_payload(
    analysis_id: str,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    reanalysis_attempt_id: str,
    analysis_started_at: str,
    generated_at: str,
    artifact_path: Path,
) -> dict[str, Any]:
    return _persistence_runtime_adapter().build_analysis_index_payload(
        globals(), analysis_id, prompt_package, response,
        reanalysis_attempt_id, analysis_started_at, generated_at, artifact_path)


def post_analysis_index(
    payload: dict[str, Any],
    alert_store_url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    return _persistence_runtime_adapter().post_analysis_index(
        globals(), payload, alert_store_url, timeout)


def post_controlled_analysis_index(
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    attempts: int = CONTROLLED_RESULT_SUBMISSION_ATTEMPTS,
) -> dict[str, Any]:
    """Retry one immutable controlled result while its exact lease is live."""
    return _persistence_runtime_adapter().post_controlled_analysis_index(
        globals(), payload, alert_store_url, attempts)


def queue_analysis_index(payload: dict[str, Any], queue_dir: Path = DEFAULT_ANALYSIS_INDEX_QUEUE_DIR) -> Path:
    return _persistence_runtime_adapter().queue_analysis_index(
        globals(), payload, queue_dir)


def stage_memory_writeback_task(
    *,
    analysis_id: str,
    response_digest: str,
    agent_role: str,
    role_memory_file: Path,
    shared_memory_file: Path,
    source_artifact: str,
    primary_candidates: Any,
    primary_allowed: bool,
    primary_reason: str,
    reviewer_candidates: Any,
    reviewer_allowed: bool,
    reviewer_reason: str,
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
) -> Path | None:
    """Durably stage eligible memory intent before the authoritative commit."""
    return _persistence_runtime_adapter().stage_memory_writeback_task(
        globals(), analysis_id=analysis_id, response_digest=response_digest,
        agent_role=agent_role, role_memory_file=role_memory_file,
        shared_memory_file=shared_memory_file, source_artifact=source_artifact,
        primary_candidates=primary_candidates, primary_allowed=primary_allowed,
        primary_reason=primary_reason, reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed, reviewer_reason=reviewer_reason,
        pending_dir=pending_dir)


def mark_memory_writeback_committed(
    analysis_id: str,
    *,
    expected_response_digest: str = "",
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
    committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
) -> Path | None:
    """Move a staged task across the commit boundary atomically."""
    return _persistence_runtime_adapter().mark_memory_writeback_committed(
        globals(), analysis_id,
        expected_response_digest=expected_response_digest,
        pending_dir=pending_dir, committed_dir=committed_dir)


def process_committed_memory_writeback(
    task_path: Path,
    *,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
) -> tuple[dict[str, Any], Path | None]:
    """Replay one post-commit task; successful lanes are analysis-idempotent."""
    return _persistence_runtime_adapter().process_committed_memory_writeback(
        globals(), task_path, receipt_dir=receipt_dir)


def resume_committed_memory_writebacks(
    *,
    committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
    receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
    limit: int = 100,
) -> tuple[int, int]:
    return _persistence_runtime_adapter().resume_committed_memory_writebacks(
        globals(), committed_dir=committed_dir,
        receipt_dir=receipt_dir, limit=limit)


def discard_pending_memory_writeback(
    analysis_id: str,
    *,
    pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
) -> None:
    _persistence_runtime_adapter().discard_pending_memory_writeback(
        globals(), analysis_id, pending_dir=pending_dir)


def quarantine_analysis_index(
    path: Path,
    payload: dict[str, Any],
    error: AnalysisIndexSubmissionError,
    *,
    quarantine_dir: Path = DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR,
) -> Path:
    """Atomically remove one deterministic rejection from the ordered spool."""
    return _persistence_runtime_adapter().quarantine_analysis_index(
        globals(), path, payload, error, quarantine_dir=quarantine_dir)


def flush_analysis_index_queue(
    alert_store_url: str,
    queue_dir: Path = DEFAULT_ANALYSIS_INDEX_QUEUE_DIR,
    quarantine_dir: Path = DEFAULT_ANALYSIS_INDEX_QUARANTINE_DIR,
    memory_pending_dir: Path = DEFAULT_MEMORY_WRITEBACK_PENDING_DIR,
    memory_committed_dir: Path = DEFAULT_MEMORY_WRITEBACK_COMMITTED_DIR,
    memory_receipt_dir: Path = DEFAULT_MEMORY_WRITEBACK_RECEIPT_DIR,
    limit: int = 100,
    memory_writeback_enabled: bool = True,
) -> tuple[int, int, int]:
    return _persistence_runtime_adapter().flush_analysis_index_queue(
        globals(), alert_store_url, queue_dir=queue_dir,
        quarantine_dir=quarantine_dir, memory_pending_dir=memory_pending_dir,
        memory_committed_dir=memory_committed_dir,
        memory_receipt_dir=memory_receipt_dir, limit=limit,
        memory_writeback_enabled=memory_writeback_enabled)


def build_llm_log_record(
    *,
    run_id: str,
    status: str,
    started_at: str,
    finished_at: str | None,
    runtime_seconds: float | None,
    prompt_path: Path | None,
    prompt_package: dict[str, Any],
    settings: dict[str, Any],
    response: dict[str, Any] | None,
    json_path: Path | None,
    md_path: Path | None,
    resource_monitor: SystemResourceMonitor,
    error: str = "",
    runtime_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility delegate for the pure operational run-log projection."""
    return _reporting_runtime_adapter().build_log_record(
        globals(), run_id=run_id, status=status, started_at=started_at,
        finished_at=finished_at, runtime_seconds=runtime_seconds,
        prompt_path=prompt_path, prompt_package=prompt_package,
        settings=settings, response=response, json_path=json_path,
        markdown_path=md_path, resource_monitor=resource_monitor,
        error=error, runtime_observation=runtime_observation,
    )


def latest_prompt(prompt_dir: Path) -> Path:
    return _startup_runtime_adapter().latest_prompt(prompt_dir)


def generate_prompt(args: argparse.Namespace) -> Path:
    """Call the existing prompt builder and return the newly written file path."""
    return _startup_runtime_adapter().generate_prompt(globals(), args)


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a runtime file only while it remains inside its admission limit."""
    return _runtime_io().read_bytes_bounded(
        path, max_bytes, error_type=RuntimeArtifactError)


def load_json(path: Path, max_bytes: int = DEFAULT_MAX_JSON_ARTIFACT_BYTES) -> dict[str, Any]:
    return _runtime_io().load_json(
        path, max_bytes, error_type=RuntimeArtifactError)


def load_system_prompt(path: Path) -> str:
    """Read the editable SOC Analyst prompt, falling back to a safe default."""
    return _runtime_io().load_system_prompt(
        path, max_bytes=DEFAULT_MAX_SYSTEM_PROMPT_BYTES,
        default_prompt=DEFAULT_SYSTEM_PROMPT,
        error_type=RuntimeArtifactError)


def default_ai_settings() -> dict[str, Any]:
    """Return safe local-first AI routing defaults."""
    return _provider_settings_runtime_adapter().default_ai_settings(globals())

__all__ = tuple(
    name for name, value in globals().items()
    if getattr(value, "__module__", None) == __name__
)

