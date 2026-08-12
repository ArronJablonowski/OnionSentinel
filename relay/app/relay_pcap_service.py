#!/usr/bin/env python3
"""PCAP request orchestration and outcome accounting."""
from __future__ import annotations

import fcntl
import json
import os
import socket
import sys
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


def _process_pcap_requests_unlocked(config: dict) -> dict:
    broker = config.get("pcap_broker", {})
    streamed_chunk_mode(config)
    stale_spool_partials_removed = cleanup_stale_spool_partials(config)
    stale_spool_artifacts_removed = cleanup_stale_spool_artifacts(config)
    spool_snapshot = spool_usage(config)
    if bool(broker.get("artifact_spool_require_mount", False)) and not spool_snapshot.get("available"):
        return {
            "ok": False, "enabled": True, "processed": 0,
            "operational_failures": 1, "outcomes": {}, "spool": spool_snapshot,
        }
    # One request per invocation is a capture-protection invariant. The timer's
    # post-run cooldown prevents a backlog from creating continuous SO reads.
    limit = 1
    pending_path = f"{broker_path(config, 'requests', '/pcap/requests')}?status=pending&limit={limit}"
    requests_method = str(broker.get("requests_method") or "GET").strip().upper()
    if requests_method not in {"GET", "POST"}:
        requests_method = "GET"
    pending_payload = {"status": "pending", "limit": limit} if requests_method == "POST" else None
    pending = broker_request(config, requests_method, pending_path, pending_payload)
    pending_requests = pending.get("requests") or []
    policy = pending.get("policy") if isinstance(pending.get("policy"), dict) else {}
    dynamic_threshold = policy.get("capture_loss_threshold_percent")
    if not pending_requests:
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
            "stale_spool_partials_removed": stale_spool_partials_removed,
            "stale_spool_artifacts_removed": stale_spool_artifacts_removed,
            "spool": spool_snapshot,
        }
    try:
        security_onion_storage = security_onion_storage_status(config)
    except Exception as exc:
        security_onion_storage = {"available": False, "error": str(exc)[:300]}
    capture_protection = capture_protection_decision(
        config,
        security_onion_storage,
        capture_loss_threshold_percent=dynamic_threshold,
    )
    if capture_protection.get("deferred"):
        return {
            "ok": True,
            "enabled": True,
            "processed": 0,
            "deferred": True,
            "defer_reason": capture_protection.get("reason"),
            "capture_protection": capture_protection,
            "operational_failures": 0,
            "outcomes": {},
            "stale_spool_partials_removed": stale_spool_partials_removed,
            "stale_spool_artifacts_removed": stale_spool_artifacts_removed,
            "spool": spool_snapshot,
            "security_onion_storage": security_onion_storage,
        }
    processed = 0
    fulfilled = 0
    failed = 0
    completion_failed = 0
    artifact_upload_failed = 0
    artifact_cleanup_failed = 0
    artifact_cleanup_succeeded = 0
    relay_spool_cleanup_failed = 0
    relay_spool_cleanup_succeeded = 0
    retry_scheduled = 0
    retry_exhausted = 0
    retry_callback_failed = 0
    outcomes: dict[str, int] = {}
    operational_failures = 0
    pending_requests = pending.get("requests") if isinstance(pending.get("requests"), list) else []
    eligible_requests = [
        item for item in pending_requests
        if isinstance(item, dict) and str(item.get("status") or "pending").lower() == "pending"
    ][:limit]
    for pcap_request in eligible_requests:
        request_id = pcap_request.get("request_id")
        claim = broker_request(
            config,
            "POST",
            broker_path(config, "claim", "/pcap/claim"),
            {"request_id": request_id, "relay_host": socket.gethostname()},
        )
        if not claim.get("claimed"):
            continue
        claimed_request = claim.get("request") if isinstance(claim.get("request"), dict) else pcap_request
        attempt_count = max(1, int(claimed_request.get("transfer_attempt_count") or 1))
        progress: PcapProgressReporter | None = None
        try:
            with PcapProgressReporter(config, str(request_id)) as progress:
                progress.update("exporting")
                export_request = dict(claimed_request)
                result = streamed_spool_artifact(config, export_request, progress)
                upload = None
                upload_error = ""
                try:
                    upload = upload_pcap_artifact(config, claim["request"], result, progress)
                except Exception as exc:
                    artifact_upload_failed += 1
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
            upload_ok = bool(upload and upload.get("ok"))
            if not upload_error and not upload_ok:
                upload_error = "Mac artifact ingest did not confirm success"
            completion_status = "failed" if upload_error else "fulfilled"
            completion_payload = {
                "artifact_path": completed_artifact_path(result, upload),
                "artifact_sha256": result.get("artifact_sha256"),
                "artifact_size_bytes": result.get("artifact_size_bytes"),
                "artifact_ingested": upload_ok,
                "artifact_ingest_error": upload_error,
            }
            if upload_error:
                upload_outcome = pcap_outcome_from_error(upload_error)
                if upload_outcome in {"timeout", "transport_failed", "checksum_failed", "failed"}:
                    try:
                        retry_result = retry_pcap_request(
                            config,
                            str(request_id),
                            progress.stage,
                            f"artifact upload failed: {upload_error}",
                            attempt_count,
                        )
                        if retry_result.get("retry_scheduled"):
                            retry_scheduled += 1
                        elif retry_result.get("exhausted"):
                            retry_exhausted += 1
                            failed += 1
                            outcomes[upload_outcome] = outcomes.get(upload_outcome, 0) + 1
                            operational_failures += 1
                            if cleanup_relay_spool_artifact(config, str(request_id)):
                                relay_spool_cleanup_succeeded += 1
                            else:
                                relay_spool_cleanup_failed += 1
                        else:
                            retry_callback_failed += 1
                            operational_failures += 1
                    except Exception as retry_error:
                        retry_callback_failed += 1
                        operational_failures += 1
                        print(
                            json.dumps(
                                {"event": "pcap_retry_schedule_failed", "request_id": request_id, "error": str(retry_error)[:500]},
                                sort_keys=True,
                            ),
                            file=sys.stderr,
                        )
                else:
                    completion_payload["error"] = f"artifact upload failed: {upload_error}"
                    completion_payload["outcome"] = upload_outcome
                    if complete_pcap_request(config, str(request_id), "failed", completion_payload):
                        failed += 1
                        outcomes[upload_outcome] = outcomes.get(upload_outcome, 0) + 1
                    else:
                        completion_failed += 1
                processed += 1
                continue
            else:
                completion_payload["outcome"] = "captured"
            if complete_pcap_request(
                config,
                request_id,
                completion_status,
                completion_payload,
            ):
                if completion_status == "fulfilled":
                    fulfilled += 1
                    if cleanup_relay_spool_artifact(config, str(request_id)):
                        relay_spool_cleanup_succeeded += 1
                    else:
                        relay_spool_cleanup_failed += 1
                    # Read-only stream mode creates no Security Onion artifact,
                    # so there is intentionally no source-side cleanup action.
                else:
                    failed += 1
                    outcomes["transport_failed"] = outcomes.get("transport_failed", 0) + 1
                    operational_failures += 1
            else:
                completion_failed += 1
        except Exception as exc:
            outcome = pcap_outcome_from_error(exc)
            completion_payload = {"error": str(exc)[:500], "outcome": outcome}
            diagnostics = getattr(exc, "diagnostics", None)
            if diagnostics:
                completion_payload["diagnostics"] = diagnostics
            if outcome in {"timeout", "transport_failed", "checksum_failed", "failed"}:
                try:
                    retry_result = retry_pcap_request(
                        config,
                        str(request_id),
                        progress.stage if progress else "claimed",
                        exc,
                        attempt_count,
                        diagnostics,
                    )
                    if retry_result.get("retry_scheduled"):
                        retry_scheduled += 1
                    elif retry_result.get("exhausted"):
                        retry_exhausted += 1
                        failed += 1
                        outcomes[outcome] = outcomes.get(outcome, 0) + 1
                        operational_failures += 1
                        if cleanup_relay_spool_artifact(config, str(request_id)):
                            relay_spool_cleanup_succeeded += 1
                        else:
                            relay_spool_cleanup_failed += 1
                    else:
                        retry_callback_failed += 1
                        operational_failures += 1
                except Exception as retry_error:
                    retry_callback_failed += 1
                    operational_failures += 1
                    print(
                        json.dumps(
                            {"event": "pcap_retry_schedule_failed", "request_id": request_id, "error": str(retry_error)[:500]},
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                    )
            else:
                completion_recorded = complete_pcap_request(config, request_id, "failed", completion_payload)
                if not completion_recorded:
                    completion_failed += 1
                failed += 1
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
        processed += 1
    return {
        "ok": True,
        "enabled": True,
        # This is an end-to-end recovery proof for the health wrapper. Local
        # capture holds, disabled mode, and lock skips return before this point.
        "broker_contacted": True,
        "processed": processed,
        "fulfilled": fulfilled,
        "failed": failed,
        "completion_failed": completion_failed,
        "artifact_upload_failed": artifact_upload_failed,
        "artifact_cleanup_failed": artifact_cleanup_failed,
        "artifact_cleanup_succeeded": artifact_cleanup_succeeded,
        "relay_spool_cleanup_failed": relay_spool_cleanup_failed,
        "relay_spool_cleanup_succeeded": relay_spool_cleanup_succeeded,
        "retry_scheduled": retry_scheduled,
        "retry_exhausted": retry_exhausted,
        "retry_callback_failed": retry_callback_failed,
        "outcomes": outcomes,
        "operational_failures": operational_failures + completion_failed + artifact_cleanup_failed + relay_spool_cleanup_failed,
        "stale_spool_partials_removed": stale_spool_partials_removed,
        "stale_spool_artifacts_removed": stale_spool_artifacts_removed,
        "spool": spool_usage(config),
        "security_onion_storage": security_onion_storage,
    }
