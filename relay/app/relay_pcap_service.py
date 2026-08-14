#!/usr/bin/env python3
"""PCAP request orchestration and outcome accounting."""
from __future__ import annotations

import fcntl
import json
import os
import socket
import sys
from dataclasses import dataclass as _dataclass, field as _dataclass_field
from pathlib import Path

from relay_pcap_delivery import *  # noqa: F401,F403

def process_pcap_requests(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    if not broker.get("enabled"):
        return {
            "ok": True,
            "enabled": False,
            "processed": 0,
            "operational_failures": 0,
        }
    lock_path = Path(str(broker.get("lock_path") or "/tmp/onion-sentinel-pcap-broker.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {
                "ok": True,
                "enabled": True,
                "locked": True,
                "processed": 0,
                "operational_failures": 0,
            }
        lock_handle.write(f"{os.getpid()}\n")
        lock_handle.flush()
        try:
            return _process_pcap_requests_unlocked(config)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


@_dataclass
class _PcapRunState:
    processed: int = 0
    fulfilled: int = 0
    failed: int = 0
    completion_failed: int = 0
    artifact_upload_failed: int = 0
    artifact_cleanup_failed: int = 0
    artifact_cleanup_succeeded: int = 0
    relay_spool_cleanup_failed: int = 0
    relay_spool_cleanup_succeeded: int = 0
    retry_scheduled: int = 0
    retry_exhausted: int = 0
    retry_callback_failed: int = 0
    outcomes: dict[str, int] = _dataclass_field(default_factory=dict)
    operational_failures: int = 0

    def record_outcome(self, outcome: str) -> None:
        self.outcomes[outcome] = self.outcomes.get(outcome, 0) + 1


def _pending_pcap_response(config: dict, broker: dict, limit: int) -> dict:
    pending_path = (
        f"{broker_path(config, 'requests', '/pcap/requests')}"
        f"?status=pending&limit={limit}"
    )
    requests_method = str(
        broker.get("requests_method") or "GET"
    ).strip().upper()
    if requests_method not in {"GET", "POST"}:
        requests_method = "GET"
    pending_payload = (
        {"status": "pending", "limit": limit}
        if requests_method == "POST"
        else None
    )
    return broker_request(
        config, requests_method, pending_path, pending_payload
    )


def _pcap_spool_context(config: dict, broker: dict) -> tuple[dict, dict | None]:
    streamed_chunk_mode(config)
    stale_spool_partials_removed = cleanup_stale_spool_partials(config)
    stale_spool_artifacts_removed = cleanup_stale_spool_artifacts(config)
    spool_snapshot = spool_usage(config)
    if bool(broker.get("artifact_spool_require_mount", False)) and not spool_snapshot.get("available"):
        return {}, {
            "ok": False, "enabled": True, "processed": 0,
            "operational_failures": 1, "outcomes": {}, "spool": spool_snapshot,
        }
    return {
        "spool_snapshot": spool_snapshot,
        "stale_spool_artifacts_removed": stale_spool_artifacts_removed,
        "stale_spool_partials_removed": stale_spool_partials_removed,
    }, None


def _no_pending_pcap_result(
    config: dict,
    dynamic_threshold: object,
    context: dict,
) -> dict:
    threshold = capture_protection_decision(
        config,
        {"zeek_capture_loss_available": True},
        capture_loss_threshold_percent=dynamic_threshold,
    ).get("threshold_percent")
    return {
        "ok": True,
        "enabled": True,
        "processed": 0,
        "capture_protection": {
            "deferred": False,
            "reason": "no_pending_requests",
            "threshold_percent": threshold,
        },
        "operational_failures": 0,
        "outcomes": {},
        "stale_spool_partials_removed": context["stale_spool_partials_removed"],
        "stale_spool_artifacts_removed": context["stale_spool_artifacts_removed"],
        "spool": context["spool_snapshot"],
    }


def _capture_protection_context(
    config: dict,
    dynamic_threshold: object,
    context: dict,
) -> tuple[dict, dict | None]:
    try:
        security_onion_storage = security_onion_storage_status(config)
    except Exception as exc:
        security_onion_storage = {"available": False, "error": str(exc)[:300]}
    capture_protection = capture_protection_decision(
        config,
        security_onion_storage,
        capture_loss_threshold_percent=dynamic_threshold,
    )
    context["security_onion_storage"] = security_onion_storage
    if not capture_protection.get("deferred"):
        return context, None
    return context, {
        "ok": True,
        "enabled": True,
        "processed": 0,
        "deferred": True,
        "defer_reason": capture_protection.get("reason"),
        "capture_protection": capture_protection,
        "operational_failures": 0,
        "outcomes": {},
        "stale_spool_partials_removed": context["stale_spool_partials_removed"],
        "stale_spool_artifacts_removed": context["stale_spool_artifacts_removed"],
        "spool": context["spool_snapshot"],
        "security_onion_storage": security_onion_storage,
    }


def _eligible_pending_requests(pending: dict, limit: int) -> list[dict]:
    pending_requests = (
        pending.get("requests")
        if isinstance(pending.get("requests"), list)
        else []
    )
    return [
        item
        for item in pending_requests
        if isinstance(item, dict)
        and str(item.get("status") or "pending").lower() == "pending"
    ][:limit]


def _pcap_poll_context(config: dict, broker: dict) -> tuple[dict, dict | None]:
    context, early_result = _pcap_spool_context(config, broker)
    if early_result is not None:
        return context, early_result
    # One request per invocation is a capture-protection invariant. The timer's
    # post-run cooldown prevents a backlog from creating continuous SO reads.
    limit = 1
    pending = _pending_pcap_response(config, broker, limit)
    pending_requests = pending.get("requests") or []
    policy = pending.get("policy") if isinstance(pending.get("policy"), dict) else {}
    dynamic_threshold = policy.get("capture_loss_threshold_percent")
    if not pending_requests:
        return context, _no_pending_pcap_result(
            config, dynamic_threshold, context
        )
    context, early_result = _capture_protection_context(
        config, dynamic_threshold, context
    )
    if early_result is not None:
        return context, early_result
    return {
        "eligible_requests": _eligible_pending_requests(pending, limit),
        **context,
    }, None


_NO_RETRY_DIAGNOSTICS = object()
_RETRYABLE_PCAP_OUTCOMES = {"timeout", "transport_failed", "checksum_failed", "failed"}


def _record_relay_spool_cleanup(
    config: dict,
    request_id: object,
    state: _PcapRunState,
) -> None:
    if cleanup_relay_spool_artifact(config, str(request_id)):
        state.relay_spool_cleanup_succeeded += 1
    else:
        state.relay_spool_cleanup_failed += 1


def _apply_pcap_retry_result(
    config: dict,
    request_id: object,
    outcome: str,
    retry_result: dict,
    state: _PcapRunState,
) -> None:
    if retry_result.get("retry_scheduled"):
        state.retry_scheduled += 1
    elif retry_result.get("exhausted"):
        state.retry_exhausted += 1
        state.failed += 1
        state.record_outcome(outcome)
        state.operational_failures += 1
        _record_relay_spool_cleanup(config, request_id, state)
    else:
        state.retry_callback_failed += 1
        state.operational_failures += 1


def _schedule_pcap_retry(
    config: dict,
    request_id: object,
    stage: str,
    error: object,
    attempt_count: int,
    outcome: str,
    state: _PcapRunState,
    diagnostics: object = _NO_RETRY_DIAGNOSTICS,
) -> None:
    try:
        if diagnostics is _NO_RETRY_DIAGNOSTICS:
            retry_result = retry_pcap_request(
                config, str(request_id), stage, error, attempt_count
            )
        else:
            retry_result = retry_pcap_request(
                config, str(request_id), stage, error, attempt_count, diagnostics
            )
        _apply_pcap_retry_result(config, request_id, outcome, retry_result, state)
    except Exception as retry_error:
        state.retry_callback_failed += 1
        state.operational_failures += 1
        print(
            json.dumps(
                {
                    "event": "pcap_retry_schedule_failed",
                    "request_id": request_id,
                    "error": str(retry_error)[:500],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )


def _stream_and_upload_claimed_artifact(
    config: dict,
    claim: dict,
    claimed_request: dict,
    request_id: object,
    progress: PcapProgressReporter,
    state: _PcapRunState,
) -> tuple[dict, dict | None, str]:
    progress.update("exporting")
    result = streamed_spool_artifact(config, dict(claimed_request), progress)
    upload = None
    upload_error = ""
    try:
        upload = upload_pcap_artifact(config, claim["request"], result, progress)
    except Exception as exc:
        state.artifact_upload_failed += 1
        upload_error = str(exc)[:500]
        print(
            json.dumps(
                {
                    "event": "pcap_artifact_upload_failed",
                    "request_id": request_id,
                    "error": upload_error,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    return result, upload, upload_error


def _handle_upload_failure(
    config: dict,
    request_id: object,
    stage: str,
    attempt_count: int,
    upload_error: str,
    completion_payload: dict,
    state: _PcapRunState,
) -> None:
    upload_outcome = pcap_outcome_from_error(upload_error)
    if upload_outcome in _RETRYABLE_PCAP_OUTCOMES:
        _schedule_pcap_retry(
            config,
            request_id,
            stage,
            f"artifact upload failed: {upload_error}",
            attempt_count,
            upload_outcome,
            state,
        )
        return
    completion_payload["error"] = f"artifact upload failed: {upload_error}"
    completion_payload["outcome"] = upload_outcome
    if complete_pcap_request(
        config, str(request_id), "failed", completion_payload
    ):
        state.failed += 1
        state.record_outcome(upload_outcome)
    else:
        state.completion_failed += 1


def _complete_uploaded_request(
    config: dict,
    request_id: object,
    completion_status: str,
    completion_payload: dict,
    state: _PcapRunState,
) -> None:
    if not complete_pcap_request(
        config, request_id, completion_status, completion_payload
    ):
        state.completion_failed += 1
        return
    if completion_status == "fulfilled":
        state.fulfilled += 1
        _record_relay_spool_cleanup(config, request_id, state)
        # Read-only stream mode creates no Security Onion artifact, so there is
        # intentionally no source-side cleanup action.
    else:
        state.failed += 1
        state.record_outcome("transport_failed")
        state.operational_failures += 1


def _handle_pcap_processing_exception(
    config: dict,
    request_id: object,
    progress: PcapProgressReporter | None,
    attempt_count: int,
    exc: Exception,
    state: _PcapRunState,
) -> None:
    outcome = pcap_outcome_from_error(exc)
    completion_payload = {"error": str(exc)[:500], "outcome": outcome}
    diagnostics = getattr(exc, "diagnostics", None)
    if diagnostics:
        completion_payload["diagnostics"] = diagnostics
    if outcome in _RETRYABLE_PCAP_OUTCOMES:
        _schedule_pcap_retry(
            config,
            request_id,
            progress.stage if progress else "claimed",
            exc,
            attempt_count,
            outcome,
            state,
            diagnostics,
        )
        return
    if not complete_pcap_request(
        config, request_id, "failed", completion_payload
    ):
        state.completion_failed += 1
    state.failed += 1
    state.record_outcome(outcome)


def _pcap_completion_payload(
    result: dict,
    upload: dict | None,
    upload_ok: bool,
    upload_error: str,
) -> dict:
    return {
        "artifact_path": completed_artifact_path(result, upload),
        "artifact_sha256": result.get("artifact_sha256"),
        "artifact_size_bytes": result.get("artifact_size_bytes"),
        "artifact_ingested": upload_ok,
        "artifact_ingest_error": upload_error,
    }


def _process_claimed_pcap_request(
    config: dict,
    pcap_request: dict,
    claim: dict,
    state: _PcapRunState,
) -> None:
    request_id = pcap_request.get("request_id")
    claimed_request = (
        claim.get("request")
        if isinstance(claim.get("request"), dict)
        else pcap_request
    )
    attempt_count = max(1, int(claimed_request.get("transfer_attempt_count") or 1))
    progress: PcapProgressReporter | None = None
    try:
        with PcapProgressReporter(config, str(request_id)) as progress:
            result, upload, upload_error = _stream_and_upload_claimed_artifact(
                config, claim, claimed_request, request_id, progress, state
            )
        upload_ok = bool(upload and upload.get("ok"))
        if not upload_error and not upload_ok:
            upload_error = "Mac artifact ingest did not confirm success"
        completion_status = "failed" if upload_error else "fulfilled"
        completion_payload = _pcap_completion_payload(
            result, upload, upload_ok, upload_error
        )
        if upload_error:
            _handle_upload_failure(
                config,
                request_id,
                progress.stage,
                attempt_count,
                upload_error,
                completion_payload,
                state,
            )
            return
        completion_payload["outcome"] = "captured"
        _complete_uploaded_request(
            config,
            request_id,
            completion_status,
            completion_payload,
            state,
        )
    except Exception as exc:
        _handle_pcap_processing_exception(
            config, request_id, progress, attempt_count, exc, state
        )


def _claim_pending_pcap_request(
    config: dict,
    pcap_request: dict,
    state: _PcapRunState,
) -> None:
    request_id = pcap_request.get("request_id")
    claim = broker_request(
        config,
        "POST",
        broker_path(config, "claim", "/pcap/claim"),
        {"request_id": request_id, "relay_host": socket.gethostname()},
    )
    if not claim.get("claimed"):
        return
    _process_claimed_pcap_request(config, pcap_request, claim, state)
    state.processed += 1


def _pcap_run_summary(
    config: dict,
    context: dict,
    state: _PcapRunState,
) -> dict:
    return {
        "ok": True,
        "enabled": True,
        # This is an end-to-end recovery proof for the health wrapper. Local
        # capture holds, disabled mode, and lock skips return before this point.
        "broker_contacted": True,
        "processed": state.processed,
        "fulfilled": state.fulfilled,
        "failed": state.failed,
        "completion_failed": state.completion_failed,
        "artifact_upload_failed": state.artifact_upload_failed,
        "artifact_cleanup_failed": state.artifact_cleanup_failed,
        "artifact_cleanup_succeeded": state.artifact_cleanup_succeeded,
        "relay_spool_cleanup_failed": state.relay_spool_cleanup_failed,
        "relay_spool_cleanup_succeeded": state.relay_spool_cleanup_succeeded,
        "retry_scheduled": state.retry_scheduled,
        "retry_exhausted": state.retry_exhausted,
        "retry_callback_failed": state.retry_callback_failed,
        "outcomes": state.outcomes,
        "operational_failures": (
            state.operational_failures
            + state.completion_failed
            + state.artifact_cleanup_failed
            + state.relay_spool_cleanup_failed
        ),
        "stale_spool_partials_removed": context["stale_spool_partials_removed"],
        "stale_spool_artifacts_removed": context["stale_spool_artifacts_removed"],
        "spool": spool_usage(config),
        "security_onion_storage": context["security_onion_storage"],
    }


def _process_pcap_requests_unlocked(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    context, early_result = _pcap_poll_context(config, broker)
    if early_result is not None:
        return early_result
    state = _PcapRunState()
    for pcap_request in context["eligible_requests"]:
        _claim_pending_pcap_request(config, pcap_request, state)
    return _pcap_run_summary(config, context, state)
