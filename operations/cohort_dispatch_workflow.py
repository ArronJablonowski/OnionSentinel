#!/usr/bin/env python3
"""Idempotent cohort queue state machine over injected dispatch ports."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
import urllib.parse

from cohort_http import HttpResult


Poster = Callable[[str, Mapping[str, Any]], HttpResult]


@dataclass(frozen=True)
class CohortDispatchSources:
    cohort_error: type[RuntimeError]
    ambiguous_dispatch_error: type[RuntimeError]
    load_private_manifest: Callable[[Path], dict[str, Any]]
    validate_loopback_base_url: Callable[[str], str]
    load_evaluation_token: Callable[[Path], str]
    validate_frozen_cohort: Callable[[Path, Mapping[str, Any]], None]
    deterministic_dispatch_id: Callable[[Mapping[str, Any], Mapping[str, Any]], str]
    utc_now: Callable[[], str]
    write_private_json: Callable[..., dict[str, Any]]
    connect_read_only: Callable[[Path], Any]
    validate_member_preflight: Callable[[Any, Mapping[str, Any]], dict[str, Any]]
    request_for_member: Callable[[str, Mapping[str, Any], Mapping[str, Any]], tuple[str, dict[str, Any]]]
    validate_success_response: Callable[[Mapping[str, Any], Mapping[str, Any], HttpResult], dict[str, Any]]
    verify_dispatch_readback: Callable[[Path, Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], dict[str, Any]]
    dashboard_post_json: Callable[..., HttpResult]
    sha256_value: Callable[[Any], str]


def _dispatch_ids(
    sources: CohortDispatchSources,
    manifest: Mapping[str, Any],
) -> list[str]:
    dispatch_ids = [
        sources.deterministic_dispatch_id(manifest, member)
        for member in manifest["members"]
    ]
    if len(dispatch_ids) != len(set(dispatch_ids)):
        raise sources.cohort_error("cohort members derived duplicate dispatch IDs")
    return dispatch_ids


def _validate_dispatch_state(
    sources: CohortDispatchSources,
    manifest: Mapping[str, Any],
) -> bool:
    states = {
        str((member.get("dispatch") or {}).get("state") or "")
        for member in manifest["members"]
    }
    if states == {"accepted"}:
        return False
    if states != {"unattempted"}:
        raise sources.cohort_error(
            "cohort contains a prior, partial, rejected, dispatching, or "
            "ambiguous dispatch; refusing to send another request"
        )
    return True


def _post_result(
    sources: CohortDispatchSources,
    poster: Poster | None,
    url: str,
    payload: Mapping[str, Any],
    timeout: float,
    token: str | None,
) -> HttpResult:
    if poster is not None:
        return poster(url, payload)
    return sources.dashboard_post_json(
        url,
        payload,
        timeout=timeout,
        evaluation_token=token,
    )


def _persist_dispatch_error(
    sources: CohortDispatchSources,
    manifest_path: Path,
    manifest: dict[str, Any],
    member: dict[str, Any],
    index: int,
    exc: RuntimeError,
    *,
    state: str,
    manifest_state: str,
) -> None:
    member["dispatch"].update(
        {
            "state": state,
            "finished_at": sources.utc_now(),
            "error_type": type(exc).__name__,
            "error_digest": sources.sha256_value(str(exc)),
        }
    )
    manifest["state"] = manifest_state
    manifest["members"][index] = member
    sources.write_private_json(
        manifest_path, manifest, digest_field="manifest_sha256"
    )


def _member_preflight(
    sources: CohortDispatchSources,
    database_path: Path,
    member: Mapping[str, Any],
) -> dict[str, Any]:
    connection = sources.connect_read_only(database_path)
    try:
        return sources.validate_member_preflight(connection, member)
    finally:
        connection.close()


def _prepare_member_dispatch(
    sources: CohortDispatchSources,
    database_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    index: int,
    base_url: str,
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    member = manifest["members"][index]
    binding = _member_preflight(sources, database_path, member)
    url, payload = sources.request_for_member(base_url, manifest, member)
    member["dispatch"].update(
        {
            "state": "dispatching",
            "attempt_count": 1,
            "started_at": sources.utc_now(),
            "request_path": urllib.parse.urlsplit(url).path,
            "request_sha256": sources.sha256_value(payload),
            "representative_binding": binding,
        }
    )
    manifest["members"][index] = member
    manifest = sources.write_private_json(
        manifest_path, manifest, digest_field="manifest_sha256"
    )
    return manifest, member, url, payload


def _dispatch_member(
    sources: CohortDispatchSources,
    database_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    index: int,
    base_url: str,
    timeout: float,
    token: str | None,
    poster: Poster | None,
) -> dict[str, Any]:
    manifest, member, url, payload = _prepare_member_dispatch(
        sources, database_path, manifest_path, manifest, index, base_url
    )
    dispatch = member["dispatch"]
    try:
        result = _post_result(sources, poster, url, payload, timeout, token)
        accepted = sources.validate_success_response(manifest, member, result)
        readback = sources.verify_dispatch_readback(
            database_path, manifest, member, accepted
        )
    except sources.ambiguous_dispatch_error as exc:
        _persist_dispatch_error(
            sources, manifest_path, manifest, member, index, exc,
            state="ambiguous", manifest_state="dispatch_ambiguous",
        )
        raise
    except sources.cohort_error as exc:
        _persist_dispatch_error(
            sources, manifest_path, manifest, member, index, exc,
            state="rejected", manifest_state="dispatch_rejected",
        )
        raise
    dispatch.update(
        {
            "state": "accepted",
            "finished_at": sources.utc_now(),
            "accepted": accepted,
            "readback": readback,
        }
    )
    manifest["members"][index] = member
    return sources.write_private_json(
        manifest_path, manifest, digest_field="manifest_sha256"
    )


def queue_cohort(
    sources: CohortDispatchSources,
    database_path: Path,
    manifest_path: Path,
    *,
    base_url: str,
    timeout: float = 15.0,
    dry_run: bool = False,
    poster: Poster | None = None,
    evaluation_token_file: Path | None = None,
) -> dict[str, Any]:
    manifest = sources.load_private_manifest(manifest_path)
    base_url = sources.validate_loopback_base_url(base_url)
    token = (
        sources.load_evaluation_token(evaluation_token_file)
        if evaluation_token_file is not None
        else None
    )
    if not _validate_dispatch_state(sources, manifest):
        return manifest
    sources.validate_frozen_cohort(database_path, manifest)
    dispatch_ids = _dispatch_ids(sources, manifest)
    if dry_run:
        return manifest
    for member, dispatch_id in zip(manifest["members"], dispatch_ids):
        member["dispatch"]["dispatch_id"] = dispatch_id
    manifest["state"] = "queueing"
    manifest["queue_started_at"] = sources.utc_now()
    manifest = sources.write_private_json(
        manifest_path, manifest, digest_field="manifest_sha256"
    )
    for index in range(len(manifest["members"])):
        manifest = _dispatch_member(
            sources, database_path, manifest_path, manifest, index,
            base_url, timeout, token, poster,
        )
    manifest["state"] = "queued"
    manifest["queue_completed_at"] = sources.utc_now()
    return sources.write_private_json(
        manifest_path, manifest, digest_field="manifest_sha256"
    )
