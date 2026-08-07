"""Best-effort harness finalization after authoritative analysis commit."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class HarnessCompletionInputs:
    analysis_id: str
    submitted_response_sha256: str
    commit_receipt: dict[str, Any]
    json_path: Path
    markdown_path: Path
    response: dict[str, Any]
    evaluation_memory_frozen: bool
    memory_receipt: dict[str, Any]
    memory_receipt_path: Path | None


@dataclass(frozen=True)
class HarnessCompletionPorts:
    digest: Callable[[Any], str]
    record_memory_writeback: Callable[[dict[str, Any]], None]
    observe_runtime: Callable[[], dict[str, Any]]
    complete: Callable[[dict[str, Any]], None]
    warn: Callable[[str], None]


def finalize_harness(
    inputs: HarnessCompletionInputs,
    ports: HarnessCompletionPorts,
) -> dict[str, Any]:
    """Finalize harness evidence without changing committed job success."""
    postcommit_runtime: dict[str, Any] = {}
    try:
        ports.record_memory_writeback(_memory_audit(inputs, ports.digest))
        postcommit_runtime = ports.observe_runtime()
    except Exception as exc:
        ports.warn(
            "Onion Sentinel harness could not record post-commit audit state: "
            f"{type(exc).__name__}: {exc}"
        )
    try:
        ports.complete(_completion_payload(inputs, postcommit_runtime, ports.digest))
    except Exception as exc:
        ports.warn(
            "Onion Sentinel harness could not finalize committed analysis: "
            f"{type(exc).__name__}: {exc}"
        )
    return postcommit_runtime


def _memory_audit(
    inputs: HarnessCompletionInputs,
    digest: Callable[[Any], str],
) -> dict[str, Any]:
    receipt = inputs.memory_receipt
    primary = receipt.get("primary")
    reviewer = receipt.get("reviewer")
    return {
        "receipt_digest": digest(receipt),
        "receipt_stored": inputs.memory_receipt_path is not None,
        "ok": bool(receipt.get("ok")),
        "primary_status": (
            primary.get("status") if isinstance(primary, dict) else "unknown"
        ),
        "reviewer_status": (
            reviewer.get("status") if isinstance(reviewer, dict) else "unknown"
        ),
    }


def _completion_payload(
    inputs: HarnessCompletionInputs,
    postcommit_runtime: dict[str, Any],
    digest: Callable[[Any], str],
) -> dict[str, Any]:
    return {
        "analysis_id": inputs.analysis_id,
        "submitted_response_sha256": inputs.submitted_response_sha256,
        "commit_submission_sha256": inputs.commit_receipt.get("submission_sha256"),
        "stored_response_sha256": inputs.commit_receipt.get("stored_response_sha256"),
        "artifact_json_sha256": hashlib.sha256(inputs.json_path.read_bytes()).hexdigest(),
        "artifact_markdown_sha256": hashlib.sha256(
            inputs.markdown_path.read_bytes()
        ).hexdigest(),
        "detection_outcome": inputs.response.get("detection_outcome"),
        "final_disposition_status": inputs.response.get("final_disposition_status"),
        "evaluation_memory_frozen": inputs.evaluation_memory_frozen,
        "memory_writeback_receipt_sha256": digest(inputs.memory_receipt),
        "postcommit_runtime": postcommit_runtime,
    }
