"""Atomic publication coordinator for one completed AI analysis."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class PublicationPolicy:
    controlled: bool
    controlled_identity: dict[str, Any] | None
    submission_error: type[Exception]
    indeterminate_message: str


@dataclass(frozen=True)
class PublicationPorts:
    write_outputs: Callable[[], tuple[Path, Path, str]]
    build_payload: Callable[[str, Path], dict[str, Any]]
    preflight: Callable[[], None]
    queue: Callable[[dict[str, Any], bool], Path]
    submit: Callable[[dict[str, Any], bool], dict[str, Any]]
    quarantine: Callable[[Path, dict[str, Any], Exception], Path]
    discard_memory: Callable[[], None]


@dataclass(frozen=True)
class PublicationResult:
    json_path: Path
    markdown_path: Path
    generated_at: str
    index_payload: dict[str, Any]
    pending_index_path: Path
    commit_receipt: dict[str, Any]


def publish(
    *,
    policy: PublicationPolicy,
    ports: PublicationPorts,
) -> PublicationResult:
    """Publish artifacts and obtain an authoritative, receipt-bound commit."""
    json_path: Path | None = None
    markdown_path: Path | None = None
    payload: dict[str, Any] = {}
    try:
        json_path, markdown_path, generated_at = ports.write_outputs()
        payload = ports.build_payload(generated_at, json_path)
        if policy.controlled_identity is not None:
            payload["controlled_job"] = dict(policy.controlled_identity)
        ports.preflight()
        pending_path = ports.queue(payload, policy.controlled)
    except Exception:
        ports.discard_memory()
        for artifact in (json_path, markdown_path):
            if artifact is not None:
                artifact.unlink(missing_ok=True)
        raise

    try:
        receipt = ports.submit(payload, policy.controlled)
    except policy.submission_error as exc:
        if not bool(getattr(exc, "retryable", False)):
            rejected = ports.quarantine(pending_path, payload, exc)
            ports.discard_memory()
            raise RuntimeError(
                "analysis index was deterministically rejected and "
                f"quarantined as {rejected.name}"
            ) from exc
        raise RuntimeError(_deferred_message(policy, pending_path, exc)) from exc
    except Exception as exc:
        raise RuntimeError(_deferred_message(policy, pending_path, exc)) from exc

    return PublicationResult(
        json_path=json_path,
        markdown_path=markdown_path,
        generated_at=generated_at,
        index_payload=payload,
        pending_index_path=pending_path,
        commit_receipt=receipt,
    )


def _deferred_message(
    policy: PublicationPolicy,
    pending_path: Path,
    error: Exception,
) -> str:
    if policy.controlled:
        return f"{policy.indeterminate_message}; exact result retained at {pending_path}"
    return f"analysis index deferred to {pending_path}: {error}"
