#!/usr/bin/env python3
"""Validate and project skill-selection facts from one harness trace."""
from __future__ import annotations

import collections
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Pattern, Sequence


V2_ATTESTATION_KEYS = frozenset({
        "framework_version", "registry_version", "registry_sha256",
        "provider", "provider_compatible", "selected", "selected_count",
        "truncated", "rejected", "aggregate_budget", "advisory_mode",
})
V2_SELECTED_KEYS = frozenset({"id", "version", "skill_sha256", "selection_reason"})
V2_SEMANTIC_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?"
)
V2_PROVIDERS = frozenset({"codex-cli", "ollama"})
V2_SELECTION_REASON = "exact_match_capability_and_promotion_gates_satisfied"
V2_REJECTION_REASONS = frozenset(
    {
        "aggregate_budget_exceeded", "artifact_revoked",
        "capability_not_permitted", "compatibility_mismatch",
        "dependency_unavailable", "exact_match_failed",
        "lifecycle_state_unavailable", "manifest_validation_failed",
        "promotion_gates_incomplete", "role_mismatch", "skill_conflict",
        "unsupported_provider",
    }
)
V2_BUDGET_FIELDS = ("max_queries", "max_rows", "max_bytes", "timeout_seconds")
V2_MAXIMUM_REJECTIONS = 64


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
) -> tuple[dict[str, Any], bool, list[str]]:
    raw = payload.get("skill_selection_attestation")
    errors: list[str] = []
    if not isinstance(raw, dict):
        raw = {}
        errors.append("skill selection attestation is not an object")
    is_v2 = "framework_version" in raw
    expected_keys = V2_ATTESTATION_KEYS if is_v2 else policy.attestation_keys
    if set(raw) - expected_keys:
        errors.append("skill selection attestation has unexpected fields")
    if expected_keys - set(raw):
        errors.append("skill selection attestation is missing fields")
    if is_v2 and raw.get("framework_version") != 2:
        errors.append("skill selection framework version is invalid")
    return raw, is_v2, errors


def _selected_identity(
    item: Any,
    identities: set[tuple[str, Any]],
    errors: list[str],
    policy: TraceSkillPolicy,
    *,
    is_v2: bool,
) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        errors.append("selected skill identity is not an object")
        return None
    if not _selected_schema_valid(item, is_v2=is_v2):
        errors.append("selected skill identity has invalid fields")
    skill_id = str(item.get("id") or "")
    version = item.get("version")
    digest = str(item.get("skill_sha256") or "")
    fields_valid = _selected_fields_valid(
        skill_id, version, digest, errors, policy, is_v2=is_v2
    )
    reason = item.get("selection_reason")
    if not _selection_reason_valid(reason, is_v2=is_v2):
        errors.append("selected skill selection reason is invalid")
        fields_valid = False
    if not fields_valid:
        return None
    identity = (skill_id, version)
    if identity in identities:
        errors.append("selected skill identity is duplicated")
        return None
    identities.add(identity)
    projected = {
        "id": skill_id,
        "version": version,
        "skill_sha256": digest,
    }
    if is_v2:
        projected["selection_reason"] = reason
    return projected


def _selected_schema_valid(item: Mapping[str, Any], *, is_v2: bool) -> bool:
    expected = (
        V2_SELECTED_KEYS
        if is_v2
        else frozenset({"id", "version", "skill_sha256"})
    )
    return set(item) == expected


def _selection_reason_valid(value: Any, *, is_v2: bool) -> bool:
    return not is_v2 or value == V2_SELECTION_REASON


def _selected_fields_valid(
    skill_id: str,
    version: Any,
    digest: str,
    errors: list[str],
    policy: TraceSkillPolicy,
    *,
    is_v2: bool,
) -> bool:
    id_valid = policy.skill_id_pattern.fullmatch(skill_id) is not None
    if not id_valid:
        errors.append("selected skill id is invalid")
    version_valid = (
        isinstance(version, str)
        and V2_SEMANTIC_VERSION_RE.fullmatch(version) is not None
        if is_v2
        else bool(
            isinstance(version, int)
            and not isinstance(version, bool)
            and version >= 1
        )
    )
    if not version_valid:
        errors.append("selected skill version is invalid")
    digest_valid = policy.sha256_pattern.fullmatch(digest) is not None
    if not digest_valid:
        errors.append("selected skill digest is invalid")
    return bool(id_valid and version_valid and digest_valid)


def _selected_skills(
    raw: Mapping[str, Any], errors: list[str], policy: TraceSkillPolicy,
    *,
    is_v2: bool,
) -> tuple[list[dict[str, Any]], list[Any]]:
    selected_raw = raw.get("selected")
    if not isinstance(selected_raw, list) or len(selected_raw) > policy.maximum_selected:
        errors.append("skill selection identities are not a bounded list")
        selected_raw = []
    identities: set[tuple[str, Any]] = set()
    selected = [
        projected
        for item in selected_raw
        if (
            projected := _selected_identity(
                item, identities, errors, policy, is_v2=is_v2
            )
        )
        is not None
    ]
    canonical = sorted(
        selected,
        key=lambda item: (
            str(item["id"]), str(item["version"]), str(item["skill_sha256"])
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
    *,
    is_v2: bool,
    provider_compatible: bool,
) -> bool:
    digest_valid = policy.sha256_pattern.fullmatch(registry_sha256) is not None
    _availability_errors(
        advisory_mode,
        registry_version,
        registry_sha256,
        digest_valid,
        selected,
        selected_count,
        truncated,
        errors,
        is_v2=is_v2,
    )
    expected_mode = (
        "identity_only_no_execution" if is_v2 else "advisory_only"
    )
    compatible = provider_compatible if is_v2 else True
    return bool(
        registry_version is not None
        and registry_version > 0
        and digest_valid
        and advisory_mode == expected_mode
        and compatible
    )


def _availability_errors(
    advisory_mode: str,
    registry_version: int | None,
    registry_sha256: str,
    digest_valid: bool,
    selected: Sequence[Mapping[str, Any]],
    selected_count: int,
    truncated: bool,
    errors: list[str],
    *,
    is_v2: bool,
) -> None:
    if is_v2:
        _append_v2_advisory_errors(
            advisory_mode, registry_version, digest_valid, errors
        )
    else:
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


def _append_v2_advisory_errors(
    advisory_mode: str,
    registry_version: int | None,
    digest_valid: bool,
    errors: list[str],
) -> None:
    if advisory_mode != "identity_only_no_execution":
        errors.append("skill selection advisory mode is invalid")
    if not digest_valid:
        errors.append("skill selection registry digest is invalid")
    if registry_version is None or registry_version < 1:
        errors.append("version-zero skill registry is unavailable")


def _v2_provider(
    raw: Mapping[str, Any], errors: list[str], policy: TraceSkillPolicy
) -> tuple[str, bool]:
    provider = raw.get("provider")
    compatible = raw.get("provider_compatible")
    if (
        not isinstance(provider, str)
        or policy.skill_id_pattern.fullmatch(provider) is None
    ):
        errors.append("skill selection provider is invalid")
        provider = ""
    if not isinstance(compatible, bool):
        errors.append("skill selection provider compatibility is invalid")
        compatible = False
    elif compatible != (provider in V2_PROVIDERS):
        errors.append("skill selection provider compatibility is inconsistent")
    return provider, compatible


def _v2_rejections(
    raw: Mapping[str, Any], errors: list[str], policy: TraceSkillPolicy
) -> list[dict[str, str]]:
    value = raw.get("rejected")
    if not isinstance(value, list) or len(value) > V2_MAXIMUM_REJECTIONS:
        errors.append("skill selection rejections are not a bounded list")
        return []
    projected: list[dict[str, str]] = []
    for item in value:
        projected_item = _v2_rejection(item, policy)
        if projected_item is None:
            errors.append("skill selection rejection is invalid")
            continue
        projected.append(projected_item)
    canonical = sorted(projected, key=lambda item: (item["id"], item["reason"]))
    if len({(item["id"], item["reason"]) for item in projected}) != len(
        projected
    ):
        errors.append("skill selection rejections are duplicated")
    if projected != canonical:
        errors.append("skill selection rejections are not in canonical order")
    return projected


def _v2_rejection(
    value: Any, policy: TraceSkillPolicy
) -> dict[str, str] | None:
    if not isinstance(value, dict) or set(value) != {"id", "reason"}:
        return None
    skill_id = value.get("id")
    reason = value.get("reason")
    if not isinstance(skill_id, str):
        return None
    if policy.skill_id_pattern.fullmatch(skill_id) is None:
        return None
    if reason not in V2_REJECTION_REASONS:
        return None
    return {"id": skill_id, "reason": reason}


def _v2_budget(
    raw: Mapping[str, Any], errors: list[str]
) -> dict[str, int]:
    value = raw.get("aggregate_budget")
    if not isinstance(value, dict) or set(value) != set(V2_BUDGET_FIELDS):
        errors.append("skill selection aggregate budget is invalid")
        return {}
    projected: dict[str, int] = {}
    for field in V2_BUDGET_FIELDS:
        item = value.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            errors.append("skill selection aggregate budget is invalid")
            continue
        projected[field] = item
    return projected


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
    attestation_keys: frozenset[str],
) -> bool:
    if not all(field in run for field in policy.job_digest_fields):
        errors.append("skill selection job identity is incomplete")
        return False
    expected_job = {field: run.get(field) for field in policy.job_digest_fields}
    expected_job["skill_selection_attestation"] = {
        key: raw.get(key) for key in attestation_keys
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


def _attestation_facts(
    raw: Mapping[str, Any],
    is_v2: bool,
    errors: list[str],
    policy: TraceSkillPolicy,
) -> dict[str, Any]:
    selected, selected_raw = _selected_skills(
        raw, errors, policy, is_v2=is_v2
    )
    truncated = raw.get("truncated")
    if not isinstance(truncated, bool):
        errors.append("skill selection truncation flag is invalid")
        truncated = False
    facts = {
        "registry_version": _registry_version(raw, errors),
        "registry_sha256": str(raw.get("registry_sha256") or ""),
        "advisory_mode": str(raw.get("advisory_mode") or ""),
        "selected": selected,
        "selected_count": _selected_count(
            raw, selected_raw, selected, errors
        ),
        "truncated": truncated,
        "provider": "",
        "provider_compatible": False,
        "rejected": [],
        "aggregate_budget": {},
    }
    if is_v2:
        facts.update(_v2_facts(raw, errors, policy))
    return facts


def _v2_facts(
    raw: Mapping[str, Any], errors: list[str], policy: TraceSkillPolicy
) -> dict[str, Any]:
    provider, compatible = _v2_provider(raw, errors, policy)
    return {
        "provider": provider,
        "provider_compatible": compatible,
        "rejected": _v2_rejections(raw, errors, policy),
        "aggregate_budget": _v2_budget(raw, errors),
    }


def _result_projection(
    facts: Mapping[str, Any],
    errors: list[str],
    available: bool,
    digest_bound: bool,
    policy: TraceSkillPolicy,
    *,
    is_v2: bool,
) -> dict[str, Any]:
    valid = not errors
    result = {
        "present": True,
        "legacy": False,
        "valid": valid,
        "available": available,
        "job_digest_bound": digest_bound,
        "mandatory_ready": valid and available and digest_bound,
        "registry_version": facts["registry_version"],
        "registry_sha256": facts["registry_sha256"],
        "selected": facts["selected"],
        "selected_count": facts["selected_count"],
        "truncated": facts["truncated"],
        "advisory_mode": facts["advisory_mode"],
        "error_count": len(errors),
        "errors": errors[: policy.maximum_reported_errors],
    }
    return _v2_result(result, facts) if is_v2 else result


def _v2_result(base: Mapping[str, Any], facts: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "present": base["present"],
        "legacy": base["legacy"],
        "valid": base["valid"],
        "available": base["available"],
        "job_digest_bound": base["job_digest_bound"],
        "mandatory_ready": base["mandatory_ready"],
        "framework_version": 2,
        "registry_version": base["registry_version"],
        "registry_sha256": base["registry_sha256"],
        "provider": facts["provider"],
        "provider_compatible": facts["provider_compatible"],
        "selected": base["selected"],
        "selected_count": base["selected_count"],
        "truncated": base["truncated"],
        "rejected": facts["rejected"],
        "aggregate_budget": facts["aggregate_budget"],
        "advisory_mode": base["advisory_mode"],
        "error_count": base["error_count"],
        "errors": base["errors"],
    }


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
    raw, is_v2, errors = _raw_attestation(payload, policy)
    facts = _attestation_facts(raw, is_v2, errors, policy)
    available = _availability(
        facts["registry_version"], facts["registry_sha256"],
        facts["advisory_mode"], facts["selected"],
        facts["selected_count"], facts["truncated"], errors, policy,
        is_v2=is_v2, provider_compatible=facts["provider_compatible"],
    )
    digest_bound = _job_digest_bound(
        run, payload, raw, errors, policy,
        V2_ATTESTATION_KEYS if is_v2 else policy.attestation_keys,
    )
    errors = list(dict.fromkeys(errors))
    return _result_projection(
        facts, errors, available, digest_bound, policy, is_v2=is_v2
    )
