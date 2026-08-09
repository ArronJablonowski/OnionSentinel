#!/usr/bin/env python3
"""Validation and projection of harness skill-selection attestations."""
from __future__ import annotations

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


@dataclass(frozen=True)
class SkillAttestationPolicy:
    skill_id_pattern: Pattern[str]
    sha256_pattern: Pattern[str]
    maximum_selected: int


def _selected_skill(
    value: Any,
    policy: SkillAttestationPolicy,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    skill_id = str(value.get("id") or "")
    version = value.get("version")
    digest = str(value.get("skill_sha256") or "")
    if set(value) != {"id", "version", "skill_sha256"}:
        return None
    if not policy.skill_id_pattern.fullmatch(skill_id):
        return None
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        return None
    if not policy.sha256_pattern.fullmatch(digest):
        return None
    return {"id": skill_id, "version": version, "skill_sha256": digest}


def _selected_skills(
    attestation: Mapping[str, Any],
    policy: SkillAttestationPolicy,
) -> tuple[list[dict[str, Any]], bool]:
    selected = attestation.get("selected")
    if not isinstance(selected, list):
        selected = []
    projected = [
        item
        for item in (_selected_skill(value, policy) for value in selected)
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
        advisory_mode == "advisory_only",
    )
    return all(checks)


def validate_skill_attestation(
    attestation: Mapping[str, Any],
    policy: SkillAttestationPolicy,
) -> tuple[dict[str, Any], bool]:
    """Return the public attestation projection and strict validity result."""
    selected, identities_valid = _selected_skills(attestation, policy)
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
    )
    summary = {
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "selected": selected,
        "selected_count": selected_count,
        "truncated": truncated,
        "advisory_mode": advisory_mode,
    }
    valid = _attestation_flags_valid(attestation)
    return summary, bool(valid and identities_valid and metadata_valid)


def _exported_skill(
    value: Any,
    identities: set[tuple[str, int]],
    policy: SkillAttestationPolicy,
    label: str,
    error: type[RuntimeError],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "id", "version", "skill_sha256"
    }:
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
    )
    if not valid:
        raise error(f"{label} selected skill identity is invalid")
    identities.add(identity)
    return {"id": skill_id, "version": version, "skill_sha256": digest}


def _exported_identity_valid(
    skill_id: str,
    version: Any,
    digest: str,
    identities: set[tuple[str, int]],
    policy: SkillAttestationPolicy,
) -> bool:
    return bool(
        policy.skill_id_pattern.fullmatch(skill_id) is not None
        and isinstance(version, int)
        and not isinstance(version, bool)
        and version >= 1
        and policy.sha256_pattern.fullmatch(digest) is not None
        and (skill_id, version) not in identities
    )


def _exported_metadata_valid(
    summary: Mapping[str, Any],
    selected: Any,
    policy: SkillAttestationPolicy,
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
        str(summary.get("advisory_mode") or "") == "advisory_only",
    )
    return all(checks)


def validate_exported_skill_summary(
    harness: Mapping[str, Any],
    label: str,
    policy: SkillAttestationPolicy,
    error: type[RuntimeError],
) -> dict[str, Any]:
    """Validate the bounded, content-free skill proof in a cohort export."""
    if harness.get("skill_selection_attestation_validated") is not True:
        raise error(f"{label} skill selection attestation was not validated")
    summary = harness.get("skill_selection_attestation")
    if not isinstance(summary, dict) or set(summary) != SKILL_SELECTION_SUMMARY_KEYS:
        raise error(f"{label} skill selection attestation schema is invalid")
    selected = summary.get("selected")
    if not _exported_metadata_valid(summary, selected, policy):
        raise error(f"{label} skill selection attestation values are invalid")
    identities: set[tuple[str, int]] = set()
    projected = [
        _exported_skill(item, identities, policy, label, error)
        for item in selected
    ]
    canonical = sorted(
        projected,
        key=lambda item: (
            str(item["id"]), int(item["version"]), str(item["skill_sha256"])
        ),
    )
    if projected != canonical:
        raise error(f"{label} selected skill identities are not canonical")
    return {
        "registry_version": summary.get("registry_version"),
        "registry_sha256": str(summary.get("registry_sha256") or ""),
        "selected": projected,
        "selected_count": summary.get("selected_count"),
        "truncated": summary.get("truncated"),
        "advisory_mode": str(summary.get("advisory_mode") or ""),
    }
