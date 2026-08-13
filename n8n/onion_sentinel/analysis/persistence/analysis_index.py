"""Receipt-bound submission and durable replay of analysis-index results."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping, NamedTuple
import urllib.error
import urllib.request


def _response_digest(result: dict[str, Any]) -> str:
    body = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _submission_headers(
    environment: Mapping[str, str],
    *,
    evaluation_mode_env: str,
    evaluation_token_env: str,
    evaluation_token_header: str,
    evaluation_token_pattern: re.Pattern[str],
    fallback_evaluation_token: str | None,
) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "User-Agent": "Onion-Sentinel-AI/1.0"}
    supplied = str(environment.get(evaluation_token_env) or "").strip()
    token = supplied if evaluation_token_pattern.fullmatch(supplied) else fallback_evaluation_token
    controlled = str(environment.get(evaluation_mode_env) or "").strip() == "1"
    if controlled and token is not None and evaluation_token_pattern.fullmatch(token):
        headers[evaluation_token_header] = token
    return headers


def _validate_receipt(
    result: dict[str, Any],
    payload: dict[str, Any],
    submission_sha256: str,
    submission_error: type[Exception],
) -> dict[str, Any]:
    if not result.get("ok"):
        raise submission_error(
            "alert-store rejected analysis index response",
            retryable=False,
            status_code=200,
            response_sha256=_response_digest(result),
        )
    analysis_id = str(payload.get("analysis_id") or "").lower()
    stored_digest = str(result.get("stored_response_sha256") or "").lower()
    bound = (
        str(result.get("analysis_id") or "").lower() == analysis_id
        and str(result.get("submission_sha256") or "").lower() == submission_sha256
        and re.fullmatch(r"[a-f0-9]{64}", stored_digest) is not None
    )
    if not bound:
        raise submission_error(
            "alert-store commit receipt did not bind the submitted analysis",
            retryable=True,
            status_code=200,
            response_sha256=_response_digest(result),
        )
    return {
        "analysis_id": analysis_id,
        "submission_sha256": submission_sha256,
        "stored_response_sha256": stored_digest,
        "idempotent": bool(result.get("idempotent")),
    }


def build_payload(
    analysis_id: str,
    prompt_package: dict[str, Any],
    response: dict[str, Any],
    reanalysis_attempt_id: str,
    analysis_started_at: str,
    generated_at: str,
    artifact_path: Path,
) -> dict[str, Any]:
    """Build the canonical alert-store result envelope without side effects."""
    alert = prompt_package.get("alert")
    alert = alert if isinstance(alert, dict) else {}
    correlation = prompt_package.get("correlated_alert_context")
    candidates = correlation.get("candidates", []) if isinstance(correlation, dict) else []
    evidence_hash = hashlib.sha256(
        json.dumps(prompt_package, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "analysis_id": analysis_id,
        "alert_id": alert.get("alert_id"),
        "agent_role": prompt_package.get("agent_role") or "soc-analyst",
        "reanalysis_attempt_id": reanalysis_attempt_id or None,
        "analysis_started_at": analysis_started_at,
        "generated_at": generated_at,
        "model": response.get("_analysis_model"),
        "model_path": response.get("_analysis_model_path"),
        "provider": response.get("_analysis_provider"),
        "harness": response.get("_analysis_harness"),
        "input_mode": response.get("_analysis_input_mode"),
        "artifact_path": str(artifact_path),
        "evidence_hash": evidence_hash,
        "response": response,
        "correlation_candidates": candidates,
    }


def _http_submission_error(
    exc: urllib.error.HTTPError,
    *,
    max_response_bytes: int,
    submission_error: type[Exception],
) -> Exception:
    try:
        response_body = exc.read(max_response_bytes + 1)
        status_code = int(exc.code)
    finally:
        exc.close()
    retryable = status_code >= 500 or status_code in {408, 425, 429}
    return submission_error(
        f"analysis index HTTP {status_code}",
        retryable=retryable,
        status_code=status_code,
        response_sha256=hashlib.sha256(response_body).hexdigest(),
    )


def _read_submission_response(
    request: urllib.request.Request,
    *,
    timeout: int,
    max_response_bytes: int,
    read_bounded_json: Callable[..., dict[str, Any]],
    submission_error: type[Exception],
) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return read_bounded_json(response, max_bytes=max_response_bytes)
    except urllib.error.HTTPError as exc:
        raise _http_submission_error(
            exc,
            max_response_bytes=max_response_bytes,
            submission_error=submission_error,
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise submission_error(
            "analysis index transport failed",
            retryable=True,
        ) from exc


def post(
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    timeout: int,
    max_response_bytes: int,
    read_bounded_json: Callable[..., dict[str, Any]],
    submission_error: type[Exception],
    environment: Mapping[str, str],
    evaluation_mode_env: str,
    evaluation_token_env: str,
    evaluation_token_header: str,
    evaluation_token_pattern: re.Pattern[str],
    fallback_evaluation_token: str | None,
) -> dict[str, Any]:
    """Submit one immutable result and require a cryptographically bound receipt."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    submission_sha256 = hashlib.sha256(body).hexdigest()
    headers = _submission_headers(
        environment,
        evaluation_mode_env=evaluation_mode_env,
        evaluation_token_env=evaluation_token_env,
        evaluation_token_header=evaluation_token_header,
        evaluation_token_pattern=evaluation_token_pattern,
        fallback_evaluation_token=fallback_evaluation_token,
    )
    request = urllib.request.Request(
        alert_store_url.rstrip("/") + "/analysis/result",
        data=body,
        headers=headers,
        method="POST",
    )
    result = _read_submission_response(
        request,
        timeout=timeout,
        max_response_bytes=max_response_bytes,
        read_bounded_json=read_bounded_json,
        submission_error=submission_error,
    )
    return _validate_receipt(result, payload, submission_sha256, submission_error)


def post_with_retry(
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    post_result: Callable[[dict[str, Any], str], dict[str, Any]],
    submission_error: type[Exception],
    attempts: int,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Retry one immutable controlled result within a small fixed bound."""
    bounded_attempts = max(1, min(int(attempts), 5))
    last_error: Exception | None = None
    for attempt_index in range(bounded_attempts):
        if attempt_index:
            sleep(0.05 * attempt_index)
        try:
            return post_result(payload, alert_store_url)
        except submission_error as exc:
            if not bool(getattr(exc, "retryable", False)):
                raise
            last_error = exc
    if last_error is None:
        raise RuntimeError("controlled result retry invariant failed")
    raise last_error


def queue(
    payload: dict[str, Any],
    queue_dir: Path,
    *,
    safe_filename: Callable[[Any], str],
    load_json: Callable[[Path], dict[str, Any]],
    canonical_digest: Callable[[Any], str],
    atomic_write_private_json: Callable[[Path, dict[str, Any]], None],
) -> Path:
    """Durably spool one identity-stable result without overwriting collisions."""
    analysis_id = str(payload.get("analysis_id") or "")
    if not analysis_id or len(analysis_id) > 128:
        raise RuntimeError("analysis index spool identity is invalid")
    path = queue_dir / f"{safe_filename(analysis_id)}.json"
    if path.exists():
        if canonical_digest(load_json(path)) != canonical_digest(payload):
            raise RuntimeError("analysis index spool identity collides with different content")
        return path
    atomic_write_private_json(path, payload)
    return path


def quarantine(
    path: Path,
    payload: dict[str, Any],
    error: Exception,
    *,
    quarantine_dir: Path,
    atomic_write_json: Callable[[Path, dict[str, Any]], None],
    now: Callable[[], str],
    time_ns: Callable[[], int] = time.time_ns,
) -> Path:
    """Atomically remove one deterministic rejection from the ordered spool."""
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_sha256 = hashlib.sha256(canonical_payload).hexdigest()
    source_name_sha256 = hashlib.sha256(path.name.encode("utf-8")).hexdigest()
    quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(quarantine_dir, 0o700)
    stem = f"{int(time_ns())}-{payload_sha256[:24]}"
    rejected_path = quarantine_dir / f"{stem}.rejected.json"
    metadata_path = quarantine_dir / f"{stem}.metadata.json"
    os.replace(path, rejected_path)
    try:
        os.chmod(rejected_path, 0o600)
        atomic_write_json(metadata_path, {
            "schema": "onion-sentinel-analysis-index-quarantine-v1",
            "quarantined_at": now(),
            "classification": "deterministic_submission_rejection",
            "http_status": getattr(error, "status_code", None),
            "payload_sha256": payload_sha256,
            "source_name_sha256": source_name_sha256,
            "response_sha256": getattr(error, "response_sha256", ""),
        })
    except Exception:
        metadata_path.unlink(missing_ok=True)
        os.replace(rejected_path, path)
        raise
    return rejected_path


def _commit_replayed_result(
    path: Path,
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    memory_pending_dir: Path,
    memory_committed_dir: Path,
    memory_receipt_dir: Path,
    memory_writeback_enabled: bool,
    post_result: Callable[[dict[str, Any], str], dict[str, Any]],
    canonical_digest: Callable[[Any], str],
    mark_memory_committed: Callable[..., Path | None],
    process_committed_memory: Callable[..., tuple[dict[str, Any], Path | None]],
) -> None:
    post_result(payload, alert_store_url)
    committed_task = mark_memory_committed(
        str(payload.get("analysis_id") or ""),
        expected_response_digest=canonical_digest(payload.get("response")),
        pending_dir=memory_pending_dir,
        committed_dir=memory_committed_dir,
    )
    path.unlink(missing_ok=True)
    if committed_task is not None and memory_writeback_enabled:
        try:
            process_committed_memory(committed_task, receipt_dir=memory_receipt_dir)
        except Exception:
            pass


def _quarantine_replayed_result(
    path: Path,
    payload: dict[str, Any],
    error: Exception,
    *,
    quarantine_dir: Path,
    memory_pending_dir: Path,
    quarantine_result: Callable[..., Path],
    discard_pending_memory: Callable[..., None],
) -> None:
    quarantine_result(path, payload, error, quarantine_dir=quarantine_dir)
    discard_pending_memory(
        str(payload.get("analysis_id") or ""),
        pending_dir=memory_pending_dir,
    )


def _replay_paths(
    queue_dir: Path,
    *,
    memory_committed_dir: Path,
    memory_receipt_dir: Path,
    limit: int,
    memory_writeback_enabled: bool,
    resume_committed_memory: Callable[..., tuple[int, int]],
) -> list[Path]:
    if memory_writeback_enabled:
        resume_committed_memory(
            committed_dir=memory_committed_dir,
            receipt_dir=memory_receipt_dir,
            limit=limit,
        )
    if not queue_dir.exists():
        return []
    return sorted(queue_dir.glob("*.json"))[:limit]


class _ReplayContext(NamedTuple):
    quarantine_dir: Path
    memory_pending_dir: Path
    memory_committed_dir: Path
    memory_receipt_dir: Path
    memory_writeback_enabled: bool
    submission_error: type[Exception]
    load_json: Callable[[Path], dict[str, Any]]
    post_result: Callable[[dict[str, Any], str], dict[str, Any]]
    canonical_digest: Callable[[Any], str]
    mark_memory_committed: Callable[..., Path | None]
    process_committed_memory: Callable[..., tuple[dict[str, Any], Path | None]]
    quarantine_result: Callable[..., Path]
    discard_pending_memory: Callable[..., None]


def _replay_result_paths(
    alert_store_url: str,
    paths: list[Path],
    context: _ReplayContext,
) -> tuple[int, int, int]:
    completed = failed = quarantined = 0
    for path in paths:
        payload: dict[str, Any] = {}
        try:
            payload = context.load_json(path)
            _commit_replayed_result(
                path, payload, alert_store_url,
                memory_pending_dir=context.memory_pending_dir,
                memory_committed_dir=context.memory_committed_dir,
                memory_receipt_dir=context.memory_receipt_dir,
                memory_writeback_enabled=context.memory_writeback_enabled,
                post_result=context.post_result,
                canonical_digest=context.canonical_digest,
                mark_memory_committed=context.mark_memory_committed,
                process_committed_memory=context.process_committed_memory,
            )
        except context.submission_error as exc:
            if bool(getattr(exc, "retryable", False)):
                failed += 1
                break
            _quarantine_replayed_result(
                path, payload, exc, quarantine_dir=context.quarantine_dir,
                memory_pending_dir=context.memory_pending_dir,
                quarantine_result=context.quarantine_result,
                discard_pending_memory=context.discard_pending_memory,
            )
            quarantined += 1
        except Exception:
            failed += 1
            break
        else:
            completed += 1
    return completed, failed, quarantined


def flush(
    alert_store_url: str, *, queue_dir: Path, quarantine_dir: Path,
    memory_pending_dir: Path, memory_committed_dir: Path,
    memory_receipt_dir: Path, limit: int, memory_writeback_enabled: bool,
    submission_error: type[Exception],
    load_json: Callable[[Path], dict[str, Any]],
    post_result: Callable[[dict[str, Any], str], dict[str, Any]],
    canonical_digest: Callable[[Any], str],
    mark_memory_committed: Callable[..., Path | None],
    process_committed_memory: Callable[..., tuple[dict[str, Any], Path | None]],
    resume_committed_memory: Callable[..., tuple[int, int]],
    quarantine_result: Callable[..., Path], discard_pending_memory: Callable[..., None],
) -> tuple[int, int, int]:
    """Replay the ordered spool, preserving index/memory commit ordering."""
    paths = _replay_paths(
        queue_dir, memory_committed_dir=memory_committed_dir,
        memory_receipt_dir=memory_receipt_dir, limit=limit,
        memory_writeback_enabled=memory_writeback_enabled,
        resume_committed_memory=resume_committed_memory,
    )
    context = _ReplayContext(
        quarantine_dir, memory_pending_dir, memory_committed_dir,
        memory_receipt_dir, memory_writeback_enabled, submission_error,
        load_json, post_result, canonical_digest, mark_memory_committed,
        process_committed_memory, quarantine_result, discard_pending_memory,
    )
    return _replay_result_paths(alert_store_url, paths, context)
