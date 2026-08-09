#!/usr/bin/env python3
"""Validate and project skill-selection facts from one harness trace."""
from __future__ import annotations

import collections
import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Pattern, Sequence


@dataclass(frozen=True)
class TraceSkillPolicy:
    attestation_keys: frozenset[str]
    skill_id_pattern: Pattern[str]
    sha256_pattern: Pattern[str]
    maximum_selected: int
    job_digest_fields: Sequence[str]
    maximum_reported_errors: int
    digest_value: Callable[[Any], str]


def legacy_skill_result() -> dict[str, Any]:
    return {
        "present": False,
        "legacy": True,
        "valid": True,
        "available": False,
        "job_digest_bound": False,
        "mandatory_ready": False,
        "registry_version": None,
        "registry_sha256": "",
        "selected": [],
        "selected_count": 0,
        "truncated": False,
        "advisory_mode": "",
        "error_count": 0,
        "errors": [],
    }


def _started_payload(
    events: Iterable[Mapping[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, Any] | None:
    started = next(
        (
            event
            for event in events
            if str(event.get("event_type") or "") == "run.started"
        ),
        None,
    )
    if started is None:
        return None
    raw = started.get("payload_json")
    if not isinstance(raw, str):
        malformed["event.run_started.payload_json"] += 1
        return {}
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        malformed["event.run_started.payload_json"] += 1
        return {}
    if not isinstance(payload, dict):
        malformed["event.run_started.payload_json"] += 1
        return {}
    return payload


def _raw_attestation(
    payload: Mapping[str, Any], policy: TraceSkillPolicy
) -> tuple[dict[str, Any], list[str]]:
    raw = payload.get("skill_selection_attestation")
    errors: list[str] = []
    if not isinstance(raw, dict):
        raw = {}
        errors.append("skill selection attestation is not an object")
    if set(raw) - policy.attestation_keys:
        errors.append("skill selection attestation has unexpected fields")
    if policy.attestation_keys - set(raw):
        errors.append("skill selection attestation is missing fields")
    return raw, errors


def _selected_identity(
    item: Any,
    identities: set[tuple[str, int]],
    errors: list[str],
    policy: TraceSkillPolicy,
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        errors.append("selected skill identity is not an object")
        return None
    if set(item) != {"id", "version", "skill_sha256"}:
        errors.append("selected skill identity has invalid fields")
    skill_id = str(item.get("id") or "")
    version = item.get("version")
    digest = str(item.get("skill_sha256") or "")
    fields_valid = _selected_fields_valid(
        skill_id, version, digest, errors, policy
    )
    if not fields_valid:
        return None
    identity = (skill_id, version)
    if identity in identities:
        errors.append("selected skill identity is duplicated")
        return None
    identities.add(identity)
    return {"id": skill_id, "version": version, "skill_sha256": digest}


def _selected_fields_valid(
    skill_id: str,
    version: Any,
    digest: str,
    errors: list[str],
    policy: TraceSkillPolicy,
) -> bool:
    id_valid = policy.skill_id_pattern.fullmatch(skill_id) is not None
    if not id_valid:
        errors.append("selected skill id is invalid")
    version_valid = bool(
        isinstance(version, int) and not isinstance(version, bool) and version >= 1
    )
    if not version_valid:
        errors.append("selected skill version is invalid")
    digest_valid = policy.sha256_pattern.fullmatch(digest) is not None
    if not digest_valid:
        errors.append("selected skill digest is invalid")
    return bool(id_valid and version_valid and digest_valid)


def _selected_skills(
    raw: Mapping[str, Any], errors: list[str], policy: TraceSkillPolicy
) -> tuple[list[dict[str, Any]], list[Any]]:
    selected_raw = raw.get("selected")
    if not isinstance(selected_raw, list) or len(selected_raw) > policy.maximum_selected:
        errors.append("skill selection identities are not a bounded list")
        selected_raw = []
    identities: set[tuple[str, int]] = set()
    selected = [
        projected
        for item in selected_raw
        if (
            projected := _selected_identity(item, identities, errors, policy)
        )
        is not None
    ]
    canonical = sorted(
        selected,
        key=lambda item: (
            str(item["id"]), int(item["version"]), str(item["skill_sha256"])
        ),
    )
    if selected != canonical:
        errors.append("selected skill identities are not in canonical order")
    return selected, selected_raw


def _registry_version(raw: Mapping[str, Any], errors: list[str]) -> int | None:
    value = raw.get("registry_version")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        errors.append("skill selection registry version is invalid")
        return None
    return value


def _selected_count(
    raw: Mapping[str, Any],
    selected_raw: Sequence[Any],
    selected: Sequence[Mapping[str, Any]],
    errors: list[str],
) -> int:
    value = raw.get("selected_count")
    valid = (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value == len(selected_raw)
        and value == len(selected)
    )
    if not valid:
        errors.append("skill selection count does not match identities")
        return len(selected)
    return value


def _availability(
    registry_version: int | None,
    registry_sha256: str,
    advisory_mode: str,
    selected: Sequence[Mapping[str, Any]],
    selected_count: int,
    truncated: bool,
    errors: list[str],
    policy: TraceSkillPolicy,
) -> bool:
    digest_valid = policy.sha256_pattern.fullmatch(registry_sha256) is not None
    _append_advisory_errors(
        advisory_mode, registry_version, digest_valid, errors
    )
    if _unavailable_selection_invalid(
        advisory_mode,
        registry_version,
        registry_sha256,
        digest_valid,
        selected,
        selected_count,
        truncated,
    ):
        errors.append("unavailable skill selection is not empty")
    return bool(
        registry_version is not None
        and registry_version > 0
        and digest_valid
        and advisory_mode == "advisory_only"
    )


def _append_advisory_errors(
    advisory_mode: str,
    registry_version: int | None,
    digest_valid: bool,
    errors: list[str],
) -> None:
    if advisory_mode not in {"advisory_only", "unavailable"}:
        errors.append("skill selection advisory mode is invalid")
    if advisory_mode == "advisory_only" and not digest_valid:
        errors.append("skill selection registry digest is invalid")
    if advisory_mode == "advisory_only" and (
        registry_version is None or registry_version < 1
    ):
        errors.append("version-zero skill registry is unavailable")


def _unavailable_selection_invalid(
    advisory_mode: str,
    registry_version: int | None,
    registry_sha256: str,
    digest_valid: bool,
    selected: Sequence[Mapping[str, Any]],
    selected_count: int,
    truncated: bool,
) -> bool:
    return bool(advisory_mode == "unavailable" and (
        registry_version != 0
        or bool(selected)
        or bool(selected_count)
        or truncated
        or bool(registry_sha256 and not digest_valid)
    ))


def _job_digest_bound(
    run: Mapping[str, Any],
    payload: Mapping[str, Any],
    raw: Mapping[str, Any],
    errors: list[str],
    policy: TraceSkillPolicy,
) -> bool:
    if not all(field in run for field in policy.job_digest_fields):
        errors.append("skill selection job identity is incomplete")
        return False
    expected_job = {field: run.get(field) for field in policy.job_digest_fields}
    expected_job["skill_selection_attestation"] = {
        key: raw.get(key) for key in policy.attestation_keys
    }
    stored = str(run.get("job_digest") or "")
    bound = bool(
        policy.sha256_pattern.fullmatch(stored) is not None
        and stored == policy.digest_value(expected_job)
        and str(payload.get("job_digest") or "") == stored
    )
    if not bound:
        errors.append("skill selection attestation is not job-digest bound")
    return bound


def skill_selection_attestation_result(
    run: Mapping[str, Any],
    events: Iterable[Mapping[str, Any]],
    malformed: collections.Counter[str],
    policy: TraceSkillPolicy,
) -> dict[str, Any]:
    """Validate and project the content-free skill selection attestation."""
    payload = _started_payload(events, malformed)
    if payload is None or "skill_selection_attestation" not in payload:
        return legacy_skill_result()
    raw, errors = _raw_attestation(payload, policy)
    registry_version = _registry_version(raw, errors)
    registry_sha256 = str(raw.get("registry_sha256") or "")
    advisory_mode = str(raw.get("advisory_mode") or "")
    selected, selected_raw = _selected_skills(raw, errors, policy)
    selected_count = _selected_count(raw, selected_raw, selected, errors)
    truncated = raw.get("truncated")
    if not isinstance(truncated, bool):
        errors.append("skill selection truncation flag is invalid")
        truncated = False
    available = _availability(
        registry_version, registry_sha256, advisory_mode, selected,
        selected_count, truncated, errors, policy,
    )
    digest_bound = _job_digest_bound(run, payload, raw, errors, policy)
    errors = list(dict.fromkeys(errors))
    valid = not errors
    return {
        "present": True,
        "legacy": False,
        "valid": valid,
        "available": available,
        "job_digest_bound": digest_bound,
        "mandatory_ready": valid and available and digest_bound,
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "selected": selected,
        "selected_count": selected_count,
        "truncated": truncated,
        "advisory_mode": advisory_mode,
        "error_count": len(errors),
        "errors": errors[: policy.maximum_reported_errors],
    }
