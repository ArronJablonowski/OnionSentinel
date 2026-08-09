#!/usr/bin/env python3
"""Loopback-only HTTP transport and private evaluation-token loading."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping, Pattern
import urllib.error
import urllib.parse
import urllib.request


@dataclass(frozen=True)
class CohortHttpPolicy:
    maximum_http_body_bytes: int
    evaluation_token_bytes: int
    token_pattern: Pattern[str]
    cohort_error: type[RuntimeError]
    ambiguous_dispatch_error: type[RuntimeError]
    canonical_bytes: Callable[[Any], bytes]


class HttpResult:
    def __init__(self, status: int, payload: Any, body_sha256: str):
        self.status = status
        self.payload = payload
        self.body_sha256 = body_sha256


def _is_plain_loopback_origin(parsed: urllib.parse.SplitResult) -> bool:
    return bool(
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.path in {"", "/"}
    )


def validate_loopback_base_url(policy: CohortHttpPolicy, value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    if not _is_plain_loopback_origin(parsed):
        raise policy.cohort_error(
            "dashboard base URL must be a plain loopback HTTP origin"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise policy.cohort_error("dashboard base URL has an invalid port") from exc
    if port is None:
        raise policy.cohort_error(
            "dashboard base URL must include an explicit port"
        )
    rendered_host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{rendered_host}:{port}"


def _open_valid_token_file(policy: CohortHttpPolicy, path: Path) -> tuple[int, os.stat_result]:
    target = path.expanduser()
    try:
        link_metadata = os.lstat(target)
    except OSError as exc:
        raise policy.cohort_error(
            "evaluation token file is missing or inaccessible"
        ) from exc
    if not stat.S_ISREG(link_metadata.st_mode):
        raise policy.cohort_error(
            "evaluation token file must be a regular non-symlink file"
        )
    if stat.S_IMODE(link_metadata.st_mode) & 0o077:
        raise policy.cohort_error(
            "evaluation token file must be owner-only (0600 or stricter)"
        )
    if link_metadata.st_uid != os.geteuid():
        raise policy.cohort_error(
            "evaluation token file is not owned by the current user"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(target, flags), link_metadata
    except OSError as exc:
        raise policy.cohort_error(
            "evaluation token file could not be opened safely"
        ) from exc


def _read_valid_token_bytes(
    policy: CohortHttpPolicy,
    file_descriptor: int,
    link_metadata: os.stat_result,
) -> bytes:
    metadata = os.fstat(file_descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_dev != link_metadata.st_dev
        or metadata.st_ino != link_metadata.st_ino
    ):
        raise policy.cohort_error("evaluation token file changed during validation")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise policy.cohort_error(
            "evaluation token file must be owner-only (0600 or stricter)"
        )
    if metadata.st_uid != os.geteuid():
        raise policy.cohort_error(
            "evaluation token file is not owned by the current user"
        )
    if metadata.st_size != policy.evaluation_token_bytes:
        raise policy.cohort_error(
            "evaluation token must be exactly 64 lowercase hexadecimal characters"
        )
    raw = os.read(file_descriptor, policy.evaluation_token_bytes + 1)
    if len(raw) != policy.evaluation_token_bytes or os.read(file_descriptor, 1):
        raise policy.cohort_error(
            "evaluation token must be exactly 64 lowercase hexadecimal characters"
        )
    return raw


def load_evaluation_token(policy: CohortHttpPolicy, path: Path) -> str:
    """Read a fixed-size token from an owner-only, race-checked regular file."""
    file_descriptor, link_metadata = _open_valid_token_file(policy, path)
    try:
        raw = _read_valid_token_bytes(policy, file_descriptor, link_metadata)
    finally:
        os.close(file_descriptor)
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise policy.cohort_error(
            "evaluation token must be exactly 64 lowercase hexadecimal characters"
        ) from exc
    if not policy.token_pattern.fullmatch(token):
        raise policy.cohort_error(
            "evaluation token must be exactly 64 lowercase hexadecimal characters"
        )
    return token


def _request_headers(policy: CohortHttpPolicy, url: str, token: str | None) -> dict[str, str]:
    origin = urllib.parse.urlunsplit((*urllib.parse.urlsplit(url)[:2], "", "", ""))
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": origin,
        "Sec-Fetch-Site": "same-origin",
        "X-Onion-Sentinel-Request": "dashboard",
    }
    if token is not None:
        if not policy.token_pattern.fullmatch(token):
            raise policy.cohort_error("evaluation token is malformed")
        headers["X-Onion-Sentinel-Evaluation-Token"] = token
    return headers


def _read_response(policy: CohortHttpPolicy, request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read(policy.maximum_http_body_bytes + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        try:
            return status, exc.read(policy.maximum_http_body_bytes + 1)
        except OSError as read_error:
            raise policy.ambiguous_dispatch_error(
                "dashboard error response could not be read"
            ) from read_error
        finally:
            exc.close()
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise policy.ambiguous_dispatch_error(
            f"dashboard request outcome is ambiguous: {type(exc).__name__}"
        ) from exc


def dashboard_post_json(
    policy: CohortHttpPolicy,
    url: str,
    payload: Mapping[str, Any],
    *,
    timeout: float,
    evaluation_token: str | None = None,
) -> HttpResult:
    body = policy.canonical_bytes(payload)
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=_request_headers(policy, url, evaluation_token),
    )
    status, raw = _read_response(policy, request, timeout)
    if len(raw) > policy.maximum_http_body_bytes:
        raise policy.ambiguous_dispatch_error(
            "dashboard response exceeded the bounded response size"
        )
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = None
    return HttpResult(status, parsed, hashlib.sha256(raw).hexdigest())
