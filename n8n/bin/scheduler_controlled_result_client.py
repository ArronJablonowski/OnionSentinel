"""Bounded alert-store client for exact controlled result recovery."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ControlledResultClientPolicy:
    indeterminate_marker: str
    max_response_bytes: int
    max_attempts: int = 5
    timeout_seconds: int = 10
    retryable_client_statuses: frozenset[int] = frozenset({408, 425, 429})
    user_agent: str = "Onion-Sentinel-AI-Recovery/1.0"


@dataclass(frozen=True)
class ControlledResultClientSources:
    mutation_headers: Callable[[str], dict[str, str]]
    open_url: Callable[..., Any]
    read_bounded_json: Callable[..., dict[str, Any]]
    sleep: Callable[[float], None]
    transport_errors: tuple[type[BaseException], ...]


def _request(
    sources: ControlledResultClientSources,
    policy: ControlledResultClientPolicy,
    alert_store_url: str,
    body: bytes,
) -> urllib.request.Request:
    return urllib.request.Request(
        f"{alert_store_url.rstrip('/')}/analysis/result",
        data=body,
        headers=sources.mutation_headers(policy.user_agent),
        method="POST",
    )


def _http_detail(status_code: int) -> str:
    return f"analysis result recovery returned HTTP {status_code}"


def _raise_for_terminal_http_status(
    status_code: int,
    policy: ControlledResultClientPolicy,
    *,
    cause: BaseException | None = None,
) -> None:
    detail = _http_detail(status_code)
    if status_code == 409:
        error = RuntimeError(f"{policy.indeterminate_marker}: {detail}")
        if cause is None:
            raise error
        raise error from cause
    if (
        status_code < 500
        and status_code not in policy.retryable_client_statuses
    ):
        error = RuntimeError(detail)
        if cause is None:
            raise error
        raise error from cause


def _exact_receipt(
    result: dict[str, Any],
    payload: dict[str, Any],
    submission_sha256: str,
) -> bool:
    stored_digest = str(result.get("stored_response_sha256") or "").lower()
    return bool(
        result.get("ok") is True
        and str(result.get("analysis_id") or "").lower()
        == str(payload.get("analysis_id") or "").lower()
        and str(result.get("submission_sha256") or "").lower()
        == submission_sha256
        and re.fullmatch(r"[a-f0-9]{64}", stored_digest)
    )


def _read_attempt(
    sources: ControlledResultClientSources,
    policy: ControlledResultClientPolicy,
    request: urllib.request.Request,
) -> tuple[dict[str, Any] | None, str]:
    with sources.open_url(
        request, timeout=policy.timeout_seconds
    ) as response:
        status_code = int(response.status)
        if status_code not in range(200, 300):
            _raise_for_terminal_http_status(status_code, policy)
            return None, _http_detail(status_code)
        return (
            sources.read_bounded_json(
                response, max_bytes=policy.max_response_bytes
            ),
            "",
        )


def _close_http_error(error: urllib.error.HTTPError) -> int:
    status_code = int(error.code)
    with suppress(Exception):
        error.close()
    return status_code


def post_controlled_recovery_result(
    sources: ControlledResultClientSources,
    policy: ControlledResultClientPolicy,
    payload: dict[str, Any],
    alert_store_url: str,
    *,
    attempts: int,
) -> dict[str, Any]:
    """Replay one immutable result with bounded exact-receipt retries."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    submission_sha256 = hashlib.sha256(body).hexdigest()
    last_error = ""
    attempt_count = max(1, min(int(attempts), policy.max_attempts))
    for attempt_index in range(attempt_count):
        if attempt_index:
            sources.sleep(0.05 * attempt_index)
        request = _request(sources, policy, alert_store_url, body)
        try:
            result, last_error = _read_attempt(sources, policy, request)
            if result is not None and _exact_receipt(
                result, payload, submission_sha256
            ):
                return result
            if result is not None:
                last_error = "analysis result recovery receipt was not exact"
        except urllib.error.HTTPError as exc:
            status_code = _close_http_error(exc)
            last_error = _http_detail(status_code)
            _raise_for_terminal_http_status(
                status_code, policy, cause=exc
            )
        except sources.transport_errors as exc:
            last_error = (
                "analysis result recovery transport failed: "
                f"{type(exc).__name__}"
            )
    raise RuntimeError(f"{policy.indeterminate_marker}: {last_error}")
