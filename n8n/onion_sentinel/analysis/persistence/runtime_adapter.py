"""Legacy runtime bindings for analysis-index and memory-journal persistence."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from . import analysis_index, memory_journal


def build_analysis_index_payload(
    bindings: Mapping[str, Any],
    analysis_id: str,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    reanalysis_attempt_id: str,
    analysis_started_at: str,
    generated_at: str,
    artifact_path: Path,
) -> dict[str, Any]:
    return analysis_index.build_payload(
        analysis_id,
        prompt_package,
        response,
        reanalysis_attempt_id,
        analysis_started_at,
        generated_at,
        artifact_path,
    )


def post_analysis_index(
    bindings: Mapping[str, Any],
    payload: dict[str, Any],
    alert_store_url: str,
    timeout: int,
) -> dict[str, Any]:
    b = bindings
    return analysis_index.post(
        payload,
        alert_store_url,
        timeout=timeout,
        max_response_bytes=b["ANALYSIS_INDEX_MAX_RESPONSE_BYTES"],
        read_bounded_json=b["read_bounded_json"],
        submission_error=b["AnalysisIndexSubmissionError"],
        environment=os.environ,
        evaluation_mode_env=b["CONTROLLED_EVALUATION_MODE_ENV"],
        evaluation_token_env=b["CONTROLLED_EVALUATION_TOKEN_ENV"],
        evaluation_token_header=b["CONTROLLED_EVALUATION_TOKEN_HEADER"],
        evaluation_token_pattern=b["CONTROLLED_EVALUATION_TOKEN_RE"],
        fallback_evaluation_token=b["_CONTROLLED_EVALUATION_TOKEN"],
    )


def post_controlled_analysis_index(
    bindings: Mapping[str, Any],
    payload: dict[str, Any],
    alert_store_url: str,
    attempts: int,
) -> dict[str, Any]:
    b = bindings
    return analysis_index.post_with_retry(
        payload,
        alert_store_url,
        post_result=b["post_analysis_index"],
        submission_error=b["AnalysisIndexSubmissionError"],
        attempts=attempts,
    )


def queue_analysis_index(
    bindings: Mapping[str, Any],
    payload: dict[str, Any],
    queue_dir: Path,
) -> Path:
    b = bindings
    return analysis_index.queue(
        payload,
        queue_dir,
        safe_filename=b["safe_filename"],
        load_json=b["load_json"],
        canonical_digest=b["canonical_payload_digest"],
        atomic_write_private_json=b["atomic_write_private_json"],
    )


def stage_memory_writeback_task(
    bindings: Mapping[str, Any],
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
    pending_dir: Path,
) -> Path | None:
    b = bindings
    return memory_journal.stage(
        analysis_id=analysis_id,
        response_digest=response_digest,
        agent_role=agent_role,
        role_memory_file=role_memory_file,
        shared_memory_file=shared_memory_file,
        source_artifact=source_artifact,
        primary_candidates=primary_candidates,
        primary_allowed=primary_allowed,
        primary_reason=primary_reason,
        reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed,
        reviewer_reason=reviewer_reason,
        pending_dir=pending_dir,
        schema=b["MEMORY_WRITEBACK_TASK_SCHEMA"],
        max_bytes=b["MAX_MEMORY_WRITEBACK_TASK_BYTES"],
        normalize_candidates=b["normalize_memory_candidates"],
        canonical_digest=b["canonical_payload_digest"],
        safe_filename=b["safe_filename"],
        load_json=b["load_json"],
        atomic_write_private_json=b["atomic_write_private_json"],
    )


def mark_memory_writeback_committed(
    bindings: Mapping[str, Any],
    analysis_id: str,
    *,
    expected_response_digest: str,
    pending_dir: Path,
    committed_dir: Path,
) -> Path | None:
    b = bindings
    return memory_journal.mark_committed(
        analysis_id,
        expected_response_digest=expected_response_digest,
        pending_dir=pending_dir,
        committed_dir=committed_dir,
        max_bytes=b["MAX_MEMORY_WRITEBACK_TASK_BYTES"],
        safe_filename=b["safe_filename"],
        load_json=b["load_json"],
        canonical_digest=b["canonical_payload_digest"],
    )


def process_committed_memory_writeback(
    bindings: Mapping[str, Any],
    task_path: Path,
    *,
    receipt_dir: Path,
) -> tuple[dict[str, Any], Path | None]:
    b = bindings
    return memory_journal.process_committed(
        task_path,
        receipt_dir=receipt_dir,
        schema=b["MEMORY_WRITEBACK_TASK_SCHEMA"],
        max_bytes=b["MAX_MEMORY_WRITEBACK_TASK_BYTES"],
        safe_filename=b["safe_filename"],
        load_json=b["load_json"],
        canonical_digest=b["canonical_payload_digest"],
        persist=b["persist_postcommit_memory_writeback"],
    )


def resume_committed_memory_writebacks(
    bindings: Mapping[str, Any],
    *,
    committed_dir: Path,
    receipt_dir: Path,
    limit: int,
) -> tuple[int, int]:
    return memory_journal.resume(
        committed_dir=committed_dir,
        receipt_dir=receipt_dir,
        limit=limit,
        process=bindings["process_committed_memory_writeback"],
    )


def discard_pending_memory_writeback(
    bindings: Mapping[str, Any],
    analysis_id: str,
    *,
    pending_dir: Path,
) -> None:
    memory_journal.discard(
        analysis_id,
        pending_dir=pending_dir,
        safe_filename=bindings["safe_filename"],
    )


def quarantine_analysis_index(
    bindings: Mapping[str, Any],
    path: Path,
    payload: dict[str, Any],
    error: Exception,
    *,
    quarantine_dir: Path,
) -> Path:
    b = bindings
    return analysis_index.quarantine(
        path,
        payload,
        error,
        quarantine_dir=quarantine_dir,
        atomic_write_json=b["atomic_write_json"],
        now=b["project_now"],
    )


def flush_analysis_index_queue(
    bindings: Mapping[str, Any],
    alert_store_url: str,
    *,
    queue_dir: Path,
    quarantine_dir: Path,
    memory_pending_dir: Path,
    memory_committed_dir: Path,
    memory_receipt_dir: Path,
    limit: int,
    memory_writeback_enabled: bool,
) -> tuple[int, int, int]:
    b = bindings
    return analysis_index.flush(
        alert_store_url,
        queue_dir=queue_dir,
        quarantine_dir=quarantine_dir,
        memory_pending_dir=memory_pending_dir,
        memory_committed_dir=memory_committed_dir,
        memory_receipt_dir=memory_receipt_dir,
        limit=limit,
        memory_writeback_enabled=memory_writeback_enabled,
        submission_error=b["AnalysisIndexSubmissionError"],
        load_json=b["load_json"],
        post_result=b["post_analysis_index"],
        canonical_digest=b["canonical_payload_digest"],
        mark_memory_committed=b["mark_memory_writeback_committed"],
        process_committed_memory=b["process_committed_memory_writeback"],
        resume_committed_memory=b["resume_committed_memory_writebacks"],
        quarantine_result=b["quarantine_analysis_index"],
        discard_pending_memory=b["discard_pending_memory_writeback"],
    )


def memory_writeback_plan(
    bindings: Mapping[str, Any],
    candidates: Any,
    *,
    allowed: bool,
    eligibility_reason: str,
) -> dict[str, Any]:
    return memory_journal.plan(
        candidates,
        allowed=allowed,
        eligibility_reason=eligibility_reason,
        normalize_candidates=bindings["normalize_memory_candidates"],
    )


def persist_postcommit_memory_writeback(
    bindings: Mapping[str, Any],
    *,
    analysis_id: str,
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
    receipt_dir: Path,
) -> tuple[dict[str, Any], Path | None]:
    b = bindings
    return memory_journal.persist_postcommit(
        analysis_id=analysis_id,
        agent_role=agent_role,
        role_memory_file=role_memory_file,
        shared_memory_file=shared_memory_file,
        source_artifact=source_artifact,
        primary_candidates=primary_candidates,
        primary_allowed=primary_allowed,
        primary_reason=primary_reason,
        reviewer_candidates=reviewer_candidates,
        reviewer_allowed=reviewer_allowed,
        reviewer_reason=reviewer_reason,
        receipt_dir=receipt_dir,
        normalize_candidates=b["normalize_memory_candidates"],
        canonical_digest=b["canonical_payload_digest"],
        persist_candidates=b["persist_memory_candidates"],
        safe_filename=b["safe_filename"],
        atomic_write_private_json=b["atomic_write_private_json"],
        now=b["project_now"],
    )
