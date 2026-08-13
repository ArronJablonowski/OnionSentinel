"""Commit-gated, crash-recoverable agent-memory writeback journal."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable


def plan(
    candidates: Any,
    *,
    allowed: bool,
    eligibility_reason: str,
    normalize_candidates: Callable[[Any], list[dict[str, Any]]],
) -> dict[str, Any]:
    """Describe a commit-gated memory operation without changing memory."""
    submitted = len(candidates) if isinstance(candidates, list) else 0
    normalized = normalize_candidates(candidates)
    result = {
        "submitted": submitted,
        "accepted": len(normalized),
        "rejected": max(0, submitted - len(normalized)),
        "commit_gated": True,
        "eligibility_reason": str(eligibility_reason or "")[:500],
    }
    if not allowed:
        return {**result, "skipped": True, "persistence_status": "blocked_before_commit"}
    if not normalized:
        return {**result, "skipped": True, "persistence_status": "no_candidates"}
    return {**result, "skipped": False, "persistence_status": "pending_authoritative_commit"}


def _lane(
    *,
    lane: str,
    candidates: Any,
    allowed: bool,
    reason: str,
    analysis_id: str,
    agent_role: str,
    role_memory_file: Path,
    shared_memory_file: Path,
    source_artifact: str,
    normalize_candidates: Callable[[Any], list[dict[str, Any]]],
    canonical_digest: Callable[[Any], str],
    persist_candidates: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    normalized = normalize_candidates(candidates)
    receipt: dict[str, Any] = {
        "lane": lane,
        "candidate_count": len(normalized),
        "candidate_manifest_digest": canonical_digest(normalized),
        "eligibility_reason": str(reason or "")[:500],
    }
    if not allowed:
        return {**receipt, "status": "blocked"}
    if not normalized:
        return {**receipt, "status": "no_candidates"}
    if not str(role_memory_file) or not str(shared_memory_file):
        return {
            **receipt,
            "status": "failed",
            "error_type": "MissingMemoryTarget",
            "error_digest": canonical_digest("memory target path is missing"),
        }
    try:
        persisted = persist_candidates(
            agent_role=agent_role,
            role_memory_file=role_memory_file,
            shared_memory_file=shared_memory_file,
            candidates=normalized,
            analysis_id=analysis_id,
            source_artifact=source_artifact,
        )
    except Exception as exc:
        return {
            **receipt,
            "status": "failed",
            "error_type": type(exc).__name__,
            "error_digest": canonical_digest(str(exc)),
        }
    return {**receipt, "status": "persisted", "result": persisted}


def persist_postcommit(
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
    normalize_candidates: Callable[[Any], list[dict[str, Any]]],
    canonical_digest: Callable[[Any], str],
    persist_candidates: Callable[..., dict[str, Any]],
    safe_filename: Callable[[Any], str],
    atomic_write_private_json: Callable[[Path, dict[str, Any]], None],
    now: Callable[[], str],
) -> tuple[dict[str, Any], Path | None]:
    """Persist eligible memory after commit and store a secret-free receipt."""
    common = {
        "agent_role": agent_role,
        "role_memory_file": role_memory_file,
        "shared_memory_file": shared_memory_file,
        "source_artifact": source_artifact,
        "normalize_candidates": normalize_candidates,
        "canonical_digest": canonical_digest,
        "persist_candidates": persist_candidates,
    }
    receipt: dict[str, Any] = {
        "schema": "onion-sentinel-memory-writeback-receipt-v1",
        "analysis_id": str(analysis_id)[:128],
        "authoritative_analysis_committed": True,
        "committed_memory_at": now(),
        "primary": _lane(
            lane="primary", candidates=primary_candidates,
            allowed=primary_allowed, reason=primary_reason,
            analysis_id=analysis_id, **common,
        ),
        "reviewer": _lane(
            lane="reviewer", candidates=reviewer_candidates,
            allowed=reviewer_allowed, reason=reviewer_reason,
            analysis_id=f"{analysis_id}-reviewer", **common,
        ),
    }
    receipt["ok"] = all(receipt[name]["status"] != "failed" for name in ("primary", "reviewer"))
    receipt_path = receipt_dir / f"{safe_filename(analysis_id)}.json"
    receipt["receipt_storage"] = {
        "status": "stored",
        "receipt_payload_digest": canonical_digest(receipt),
    }
    try:
        atomic_write_private_json(receipt_path, receipt)
    except Exception as exc:
        receipt["ok"] = False
        receipt["receipt_storage"] = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error_digest": canonical_digest(str(exc)),
        }
        return receipt, None
    return receipt, receipt_path


def _persist_staged_task(
    task: dict[str, Any],
    *,
    analysis_id: Any,
    pending_dir: Path,
    max_bytes: int,
    canonical_digest: Callable[[Any], str],
    safe_filename: Callable[[Any], str],
    load_json: Callable[..., dict[str, Any]],
    atomic_write_private_json: Callable[[Path, dict[str, Any]], None],
) -> Path:
    encoded = json.dumps(task, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > max_bytes:
        raise RuntimeError("memory writeback task exceeds its byte limit")
    path = pending_dir / f"{safe_filename(analysis_id)}.json"
    if path.exists():
        if canonical_digest(load_json(path, max_bytes)) != canonical_digest(task):
            raise RuntimeError(
                "memory writeback task identity collides with different content"
            )
        return path
    atomic_write_private_json(path, task)
    return path


def stage(
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
    schema: str,
    max_bytes: int,
    normalize_candidates: Callable[[Any], list[dict[str, Any]]],
    canonical_digest: Callable[[Any], str],
    safe_filename: Callable[[Any], str],
    load_json: Callable[..., dict[str, Any]],
    atomic_write_private_json: Callable[[Path, dict[str, Any]], None],
) -> Path | None:
    """Durably stage eligible memory intent before authoritative commit."""
    identity = str(analysis_id)
    normalized_digest = str(response_digest).lower()
    if not identity or len(identity) > 128:
        raise RuntimeError("memory writeback analysis identity is invalid")
    if not re.fullmatch(r"[a-f0-9]{64}", normalized_digest):
        raise RuntimeError("memory writeback response digest is invalid")
    primary = normalize_candidates(primary_candidates) if primary_allowed else []
    reviewer = normalize_candidates(reviewer_candidates) if reviewer_allowed else []
    if not primary and not reviewer:
        return None
    task = _task(
        schema=schema, analysis_id=identity, response_digest=normalized_digest,
        agent_role=agent_role, role_memory_file=role_memory_file,
        shared_memory_file=shared_memory_file, source_artifact=source_artifact,
        primary=(primary, primary_allowed, primary_reason),
        reviewer=(reviewer, reviewer_allowed, reviewer_reason),
        canonical_digest=canonical_digest,
    )
    return _persist_staged_task(
        task, analysis_id=analysis_id, pending_dir=pending_dir,
        max_bytes=max_bytes, canonical_digest=canonical_digest,
        safe_filename=safe_filename, load_json=load_json,
        atomic_write_private_json=atomic_write_private_json,
    )


def _task(
    *, schema: str, analysis_id: str, response_digest: str, agent_role: str,
    role_memory_file: Path, shared_memory_file: Path, source_artifact: str,
    primary: tuple[list[dict[str, Any]], bool, str],
    reviewer: tuple[list[dict[str, Any]], bool, str],
    canonical_digest: Callable[[Any], str],
) -> dict[str, Any]:
    def lane(value: tuple[list[dict[str, Any]], bool, str]) -> dict[str, Any]:
        candidates, allowed, reason = value
        return {
            "allowed": bool(allowed), "reason": str(reason or "")[:500],
            "candidates": candidates,
            "candidate_manifest_digest": canonical_digest(candidates),
        }
    return {
        "schema": schema, "analysis_id": analysis_id,
        "submitted_response_sha256": response_digest,
        "agent_role": str(agent_role), "role_memory_file": str(role_memory_file),
        "shared_memory_file": str(shared_memory_file),
        "source_artifact": str(source_artifact),
        "primary": lane(primary), "reviewer": lane(reviewer),
    }


def mark_committed(
    analysis_id: str,
    *,
    expected_response_digest: str,
    pending_dir: Path,
    committed_dir: Path,
    max_bytes: int,
    safe_filename: Callable[[Any], str],
    load_json: Callable[..., dict[str, Any]],
    canonical_digest: Callable[[Any], str],
) -> Path | None:
    """Move a staged task across the authoritative commit boundary."""
    expected = str(expected_response_digest or "").lower()
    if expected and not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise RuntimeError("expected memory response digest is invalid")

    def validate(task: dict[str, Any]) -> None:
        if str(task.get("analysis_id") or "") != str(analysis_id):
            raise RuntimeError("memory task analysis identity is invalid")
        if expected and str(task.get("submitted_response_sha256") or "").lower() != expected:
            raise RuntimeError("memory task is not bound to the committed response")

    name = f"{safe_filename(analysis_id)}.json"
    pending_path, committed_path = pending_dir / name, committed_dir / name
    if committed_path.exists():
        committed = load_json(committed_path, max_bytes)
        validate(committed)
        if pending_path.exists():
            pending = load_json(pending_path, max_bytes)
            validate(pending)
            if canonical_digest(pending) != canonical_digest(committed):
                raise RuntimeError("pending and committed memory tasks disagree")
            pending_path.unlink()
        return committed_path
    if not pending_path.exists():
        return None
    validate(load_json(pending_path, max_bytes))
    committed_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(committed_dir, stat.S_IRWXU)
    os.replace(pending_path, committed_path)
    os.chmod(committed_path, stat.S_IRUSR | stat.S_IWUSR)
    _fsync_directory(committed_dir)
    _fsync_directory(pending_dir)
    return committed_path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def process_committed(
    task_path: Path,
    *,
    receipt_dir: Path,
    schema: str,
    max_bytes: int,
    safe_filename: Callable[[Any], str],
    load_json: Callable[..., dict[str, Any]],
    canonical_digest: Callable[[Any], str],
    persist: Callable[..., tuple[dict[str, Any], Path | None]],
) -> tuple[dict[str, Any], Path | None]:
    """Replay one post-commit task after validating its immutable manifest."""
    task, primary, reviewer = _validated_task(
        task_path, schema=schema, max_bytes=max_bytes,
        safe_filename=safe_filename, load_json=load_json,
        canonical_digest=canonical_digest,
    )
    analysis_id = str(task["analysis_id"])
    receipt, receipt_path = persist(
        analysis_id=analysis_id, agent_role=str(task.get("agent_role") or ""),
        role_memory_file=Path(str(task.get("role_memory_file") or "")).expanduser(),
        shared_memory_file=Path(str(task.get("shared_memory_file") or "")).expanduser(),
        source_artifact=str(task.get("source_artifact") or ""),
        primary_candidates=primary["candidates"], primary_allowed=bool(primary.get("allowed")),
        primary_reason=str(primary.get("reason") or ""),
        reviewer_candidates=reviewer["candidates"], reviewer_allowed=bool(reviewer.get("allowed")),
        reviewer_reason=str(reviewer.get("reason") or ""), receipt_dir=receipt_dir,
    )
    if receipt.get("ok") is True and receipt_path is not None:
        task_path.unlink()
    return receipt, receipt_path


def _candidate_manifest_valid(
    lane: dict[str, Any],
    canonical_digest: Callable[[Any], str],
) -> bool:
    candidates = lane.get("candidates")
    return (
        isinstance(candidates, list)
        and canonical_digest(candidates)
        == str(lane.get("candidate_manifest_digest") or "")
    )


def _load_regular_task(
    task_path: Path,
    max_bytes: int,
    load_json: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    if task_path.is_symlink() or not task_path.is_file():
        raise RuntimeError("committed memory task must be a regular file")
    return load_json(task_path, max_bytes)


def _validated_task(
    task_path: Path,
    *,
    schema: str,
    max_bytes: int,
    safe_filename: Callable[[Any], str],
    load_json: Callable[..., dict[str, Any]],
    canonical_digest: Callable[[Any], str],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    task = _load_regular_task(task_path, max_bytes, load_json)
    if task.get("schema") != schema:
        raise RuntimeError("committed memory task schema is invalid")
    analysis_id = str(task.get("analysis_id") or "")
    if task_path.name != f"{safe_filename(analysis_id)}.json":
        raise RuntimeError("committed memory task identity is invalid")
    if not re.fullmatch(r"[a-f0-9]{64}", str(task.get("submitted_response_sha256") or "").lower()):
        raise RuntimeError("committed memory task response digest is invalid")
    primary, reviewer = task.get("primary"), task.get("reviewer")
    if not isinstance(primary, dict) or not isinstance(reviewer, dict):
        raise RuntimeError("committed memory task lanes are invalid")
    for lane in (primary, reviewer):
        if not _candidate_manifest_valid(lane, canonical_digest):
            raise RuntimeError("committed memory candidate manifest is invalid")
    return task, primary, reviewer


def resume(
    *, committed_dir: Path, receipt_dir: Path, limit: int,
    process: Callable[..., tuple[dict[str, Any], Path | None]],
) -> tuple[int, int]:
    if not committed_dir.exists():
        return 0, 0
    completed = failed = 0
    for task_path in sorted(committed_dir.glob("*.json"))[:limit]:
        try:
            receipt, receipt_path = process(task_path, receipt_dir=receipt_dir)
            if receipt.get("ok") is True and receipt_path is not None:
                completed += 1
            else:
                failed += 1
        except Exception:
            failed += 1
    return completed, failed


def discard(analysis_id: str, *, pending_dir: Path, safe_filename: Callable[[Any], str]) -> None:
    (pending_dir / f"{safe_filename(analysis_id)}.json").unlink(missing_ok=True)
