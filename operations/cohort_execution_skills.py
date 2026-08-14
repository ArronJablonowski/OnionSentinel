#!/usr/bin/env python3
"""Validation and projection of harness skill-selection attestations."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Pattern


SKILL_SELECTION_SUMMARY_KEYS = frozenset(
    {
        "registry_version",
        "registry_sha256",
        "selected",
        "selected_count",
        "truncated",
        "advisory_mode",
    }
)
V2_SKILL_SELECTION_SUMMARY_KEYS = frozenset(
    {
        "framework_version",
        "registry_version",
        "registry_sha256",
        "provider",
        "provider_compatible",
        "selected",
        "selected_count",
        "truncated",
        "rejected",
        "aggregate_budget",
        "advisory_mode",
    }
)
V2_SEMANTIC_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?"
)
V2_PROVIDERS = frozenset({"codex-cli", "ollama"})
V2_SELECTION_REASON = (
    "exact_match_capability_and_promotion_gates_satisfied"
)
V2_REJECTION_REASONS = frozenset(
    {
        "aggregate_budget_exceeded",
        "artifact_revoked",
        "capability_not_permitted",
        "compatibility_mismatch",
        "dependency_unavailable",
        "exact_match_failed",
        "lifecycle_state_unavailable",
        "manifest_validation_failed",
        "promotion_gates_incomplete",
        "role_mismatch",
        "skill_conflict",
        "unsupported_provider",
    }
)
V2_BUDGET_FIELDS = frozenset(
    {"max_queries", "max_rows", "max_bytes", "timeout_seconds"}
)
V2_MAXIMUM_REJECTIONS = 64


@dataclass(frozen=True)
class SkillAttestationPolicy:
    skill_id_pattern: Pattern[str]
    sha256_pattern: Pattern[str]
    maximum_selected: int


def _selected_version_valid(value: Mapping[str, Any], *, is_v2: bool) -> bool:
    version = value.get("version")
    if is_v2:
        return bool(
            isinstance(version, str)
            and V2_SEMANTIC_VERSION_RE.fullmatch(version) is not None
            and value.get("selection_reason") == V2_SELECTION_REASON
        )
    return bool(
        isinstance(version, int)
        and not isinstance(version, bool)
        and version >= 1
    )


def _selected_skill(
    value: Any,
    policy: SkillAttestationPolicy,
    *,
    is_v2: bool,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    skill_id = str(value.get("id") or "")
    version = value.get("version")
    digest = str(value.get("skill_sha256") or "")
    expected_keys = {"id", "version", "skill_sha256"}
    if is_v2:
        expected_keys.add("selection_reason")
    if set(value) != expected_keys:
        return None
    if not policy.skill_id_pattern.fullmatch(skill_id):
        return None
    if not _selected_version_valid(value, is_v2=is_v2):
        return None
    if not policy.sha256_pattern.fullmatch(digest):
        return None
    projected = {"id": skill_id, "version": version, "skill_sha256": digest}
    if is_v2:
        projected["selection_reason"] = value.get("selection_reason")
    return projected


def _selected_skills(
    attestation: Mapping[str, Any],
    policy: SkillAttestationPolicy,
    *,
    is_v2: bool,
) -> tuple[list[dict[str, Any]], bool]:
    selected = attestation.get("selected")
    if not isinstance(selected, list):
        selected = []
    projected = [
        item
        for item in (
            _selected_skill(value, policy, is_v2=is_v2)
            for value in selected
        )
        if item is not None
    ]
    valid = (
        len(selected) <= policy.maximum_selected
        and len(projected) == len(selected)
    )
    return projected, valid


def _attestation_flags_valid(attestation: Mapping[str, Any]) -> bool:
    return bool(
        attestation.get("present") is True
        and attestation.get("legacy") is False
        and attestation.get("valid") is True
        and attestation.get("available") is True
        and attestation.get("job_digest_bound") is True
        and attestation.get("mandatory_ready") is True
        and attestation.get("error_count") == 0
        and attestation.get("errors") == []
    )


def _metadata_valid(
    policy: SkillAttestationPolicy,
    registry_version: Any,
    registry_sha256: str,
    selected_count: Any,
    selected: list[dict[str, Any]],
    truncated: Any,
    advisory_mode: str,
    *,
    is_v2: bool,
) -> bool:
    checks = (
        isinstance(registry_version, int),
        not isinstance(registry_version, bool),
        isinstance(registry_version, int) and registry_version > 0,
        policy.sha256_pattern.fullmatch(registry_sha256) is not None,
        isinstance(selected_count, int),
        not isinstance(selected_count, bool),
        selected_count == len(selected),
        isinstance(truncated, bool),
        advisory_mode
        == ("identity_only_no_execution" if is_v2 else "advisory_only"),
    )
    return all(checks)


def _v2_provider(attestation: Mapping[str, Any]) -> tuple[str, bool, bool]:
    provider = attestation.get("provider")
    compatible = attestation.get("provider_compatible")
    valid = bool(
        isinstance(provider, str)
        and provider in V2_PROVIDERS
        and compatible is True
    )
    return str(provider or ""), compatible is True, valid


def _v2_rejections(
    attestation: Mapping[str, Any], policy: SkillAttestationPolicy
) -> tuple[list[dict[str, str]], bool]:
    value = attestation.get("rejected")
    if not isinstance(value, list) or len(value) > V2_MAXIMUM_REJECTIONS:
        return [], False
    projected: list[dict[str, str]] = []
    for item in value:
        projected_item = _v2_rejection(item, policy)
        if projected_item is None:
            return [], False
        projected.append(projected_item)
    canonical = sorted(projected, key=lambda item: (item["id"], item["reason"]))
    unique = len({(item["id"], item["reason"]) for item in projected})
    return projected, bool(projected == canonical and unique == len(projected))


def _v2_rejection(
    value: Any, policy: SkillAttestationPolicy
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


def _v2_budget(attestation: Mapping[str, Any]) -> tuple[dict[str, int], bool]:
    value = attestation.get("aggregate_budget")
    if not isinstance(value, dict) or set(value) != V2_BUDGET_FIELDS:
        return {}, False
    valid = all(
        isinstance(value.get(field), int)
        and not isinstance(value.get(field), bool)
        and value[field] >= 0
        for field in V2_BUDGET_FIELDS
    )
    return (
        {field: value[field] for field in sorted(V2_BUDGET_FIELDS)}
        if valid
        else {},
        valid,
    )


def validate_skill_attestation(
    attestation: Mapping[str, Any],
    policy: SkillAttestationPolicy,
) -> tuple[dict[str, Any], bool]:
    """Return the public attestation projection and strict validity result."""
    is_v2 = attestation.get("framework_version") == 2
    selected, identities_valid = _selected_skills(
        attestation, policy, is_v2=is_v2
    )
    registry_version = attestation.get("registry_version")
    registry_sha256 = str(attestation.get("registry_sha256") or "")
    selected_count = attestation.get("selected_count")
    truncated = attestation.get("truncated")
    advisory_mode = str(attestation.get("advisory_mode") or "")
    metadata_valid = _metadata_valid(
        policy,
        registry_version,
        registry_sha256,
        selected_count,
        selected,
        truncated,
        advisory_mode,
        is_v2=is_v2,
    )
    summary: dict[str, Any] = {
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "selected": selected,
        "selected_count": selected_count,
        "truncated": truncated,
        "advisory_mode": advisory_mode,
    }
    if is_v2:
        summary, v2_valid = _v2_trace_projection(
            attestation, selected, policy
        )
    else:
        v2_valid = True
    valid = _attestation_flags_valid(attestation)
    return summary, bool(
        valid and identities_valid and metadata_valid and v2_valid
    )


def _v2_trace_projection(
    attestation: Mapping[str, Any],
    selected: list[dict[str, Any]],
    policy: SkillAttestationPolicy,
) -> tuple[dict[str, Any], bool]:
    provider, provider_compatible, provider_valid = _v2_provider(attestation)
    rejected, rejections_valid = _v2_rejections(attestation, policy)
    aggregate_budget, budget_valid = _v2_budget(attestation)
    return {
        "framework_version": 2,
        "registry_version": attestation.get("registry_version"),
        "registry_sha256": str(attestation.get("registry_sha256") or ""),
        "provider": provider,
        "provider_compatible": provider_compatible,
        "selected": selected,
        "selected_count": attestation.get("selected_count"),
        "truncated": attestation.get("truncated"),
        "rejected": rejected,
        "aggregate_budget": aggregate_budget,
        "advisory_mode": str(attestation.get("advisory_mode") or ""),
    }, bool(provider_valid and rejections_valid and budget_valid)


def _exported_skill(
    value: Any,
    identities: set[tuple[str, Any]],
    policy: SkillAttestationPolicy,
    label: str,
    error: type[RuntimeError],
    *,
    is_v2: bool,
) -> dict[str, Any]:
    expected_keys = {"id", "version", "skill_sha256"}
    if is_v2:
        expected_keys.add("selection_reason")
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise error(f"{label} selected skill identity schema is invalid")
    skill_id = str(value.get("id") or "")
    version = value.get("version")
    digest = str(value.get("skill_sha256") or "")
    identity = (skill_id, version)
    valid = _exported_identity_valid(
        skill_id,
        version,
        digest,
        identities,
        policy,
        is_v2=is_v2,
    )
    if is_v2 and value.get("selection_reason") != V2_SELECTION_REASON:
        valid = False
    if not valid:
        raise error(f"{label} selected skill identity is invalid")
    identities.add(identity)
    projected = {"id": skill_id, "version": version, "skill_sha256": digest}
    if is_v2:
        projected["selection_reason"] = value.get("selection_reason")
    return projected


def _exported_identity_valid(
    skill_id: str,
    version: Any,
    digest: str,
    identities: set[tuple[str, Any]],
    policy: SkillAttestationPolicy,
    *,
    is_v2: bool,
) -> bool:
    return bool(
        policy.skill_id_pattern.fullmatch(skill_id) is not None
        and (
            isinstance(version, str)
            and V2_SEMANTIC_VERSION_RE.fullmatch(version) is not None
            if is_v2
            else isinstance(version, int)
            and not isinstance(version, bool)
            and version >= 1
        )
        and policy.sha256_pattern.fullmatch(digest) is not None
        and (skill_id, version) not in identities
    )


def _exported_metadata_valid(
    summary: Mapping[str, Any],
    selected: Any,
    policy: SkillAttestationPolicy,
    *,
    is_v2: bool,
) -> bool:
    version = summary.get("registry_version")
    count = summary.get("selected_count")
    checks = (
        isinstance(version, int),
        not isinstance(version, bool),
        isinstance(version, int) and version >= 1,
        policy.sha256_pattern.fullmatch(
            str(summary.get("registry_sha256") or "")
        ) is not None,
        isinstance(selected, list),
        isinstance(selected, list) and len(selected) <= policy.maximum_selected,
        isinstance(count, int),
        not isinstance(count, bool),
        isinstance(selected, list) and count == len(selected),
        isinstance(summary.get("truncated"), bool),
        str(summary.get("advisory_mode") or "")
        == ("identity_only_no_execution" if is_v2 else "advisory_only"),
    )
    return all(checks)


def _v2_exported_projection(
    summary: Mapping[str, Any],
    projected: list[dict[str, Any]],
    policy: SkillAttestationPolicy,
    label: str,
    error: type[RuntimeError],
) -> dict[str, Any]:
    provider, provider_compatible, provider_valid = _v2_provider(summary)
    rejected, rejections_valid = _v2_rejections(summary, policy)
    aggregate_budget, budget_valid = _v2_budget(summary)
    if not (provider_valid and rejections_valid and budget_valid):
        raise error(f"{label} skill selection attestation values are invalid")
    return {
        "framework_version": 2,
        "registry_version": summary.get("registry_version"),
        "registry_sha256": str(summary.get("registry_sha256") or ""),
        "provider": provider,
        "provider_compatible": provider_compatible,
        "selected": projected,
        "selected_count": summary.get("selected_count"),
        "truncated": summary.get("truncated"),
        "rejected": rejected,
        "aggregate_budget": aggregate_budget,
        "advisory_mode": str(summary.get("advisory_mode") or ""),
    }


def validate_exported_skill_summary(
    harness: Mapping[str, Any],
    label: str,
    policy: SkillAttestationPolicy,
    error: type[RuntimeError],
) -> dict[str, Any]:
    """Validate the bounded, content-free skill proof in a cohort export."""
    if harness.get("skill_selection_attestation_validated") is not True:
        raise error(f"{label} skill selection attestation was not validated")
    summary, is_v2 = _exported_summary(
        harness.get("skill_selection_attestation"), label, error
    )

    selected = summary.get("selected")
    if not _exported_metadata_valid(
        summary, selected, policy, is_v2=is_v2
    ):
        raise error(f"{label} skill selection attestation values are invalid")
    projected = _exported_skills(
        selected, policy, label, error, is_v2=is_v2
    )
    if is_v2:
        return _v2_exported_projection(
            summary, projected, policy, label, error
        )
    return {
        "registry_version": summary.get("registry_version"),
        "registry_sha256": str(summary.get("registry_sha256") or ""),
        "selected": projected,
        "selected_count": summary.get("selected_count"),
        "truncated": summary.get("truncated"),
        "advisory_mode": str(summary.get("advisory_mode") or ""),
    }


def _exported_summary(
    value: Any, label: str, error: type[RuntimeError]
) -> tuple[Mapping[str, Any], bool]:
    is_v2 = isinstance(value, dict) and value.get("framework_version") == 2
    expected_keys = (
        V2_SKILL_SELECTION_SUMMARY_KEYS if is_v2
        else SKILL_SELECTION_SUMMARY_KEYS
    )
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise error(f"{label} skill selection attestation schema is invalid")
    return value, is_v2


def _exported_skills(
    selected: Any,
    policy: SkillAttestationPolicy,
    label: str,
    error: type[RuntimeError],
    *,
    is_v2: bool,
) -> list[dict[str, Any]]:
    identities: set[tuple[str, Any]] = set()
    projected = [
        _exported_skill(
            item, identities, policy, label, error, is_v2=is_v2
        )
        for item in selected
    ]
    canonical = sorted(
        projected,
        key=lambda item: (
            str(item["id"]), str(item["version"]), str(item["skill_sha256"])
        ),
    )
    if projected != canonical:
        raise error(f"{label} selected skill identities are not canonical")
    return projected
