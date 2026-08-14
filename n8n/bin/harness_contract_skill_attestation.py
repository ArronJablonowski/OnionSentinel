"""Content-free investigation-skill identity attestation."""
from __future__ import annotations

import re
from typing import Any, Mapping

from harness_policy import (
    DIGEST_RE,
    HarnessIntegrityError,
    IDENTIFIER_RE,
    INVESTIGATION_SKILL_ADVISORY_MODE,
    INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
)


V2_SELECTION_SCHEMA = "onion-sentinel-investigation-skill-selection-v2"
V2_ENFORCEMENT = "identity_only_no_execution"
_V2_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?"
)
_V2_PROVIDERS = frozenset({"codex-cli", "ollama"})
_V2_SELECTION_REASONS = frozenset(
    {"exact_match_capability_and_promotion_gates_satisfied"}
)
_V2_REJECTION_REASONS = frozenset(
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
_V2_BUDGET_FIELDS = (
    "max_queries",
    "max_rows",
    "max_bytes",
    "timeout_seconds",
)
_V2_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "registry_version",
        "registry_digest",
        "provider",
        "provider_compatible",
        "selected",
        "selected_count",
        "truncated",
        "rejected",
        "aggregate_budget",
        "enforcement",
    }
)


def investigation_skill_selection_attestation(
    prompt_package: Mapping[str, Any],
) -> dict[str, Any]:
    """Project prompt skill selection into a bounded, content-free identity."""
    raw = prompt_package.get("investigation_skills")
    if raw is None:
        return _unavailable_attestation()
    if not isinstance(raw, Mapping):
        raise HarnessIntegrityError(
            "investigation skill selection must be an object"
        )
    if raw.get("schema") == V2_SELECTION_SCHEMA:
        return _v2_attestation(raw)
    registry_version = _registry_version(raw)
    registry_sha256 = _registry_digest(raw)
    _require_advisory_shadow_mode(raw)
    projected = _selected_identities(raw)
    selected_count, truncated = _selection_summary(raw, projected)
    advisory_mode = _advisory_mode(
        registry_version,
        projected,
        selected_count,
        truncated,
    )
    projected.sort(
        key=lambda item: (
            str(item["id"]),
            int(item["version"]),
            str(item["skill_sha256"]),
        )
    )
    return {
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "selected": projected,
        "selected_count": selected_count,
        "truncated": truncated,
        "advisory_mode": advisory_mode,
    }


def _v2_attestation(raw: Mapping[str, Any]) -> dict[str, Any]:
    if frozenset(raw) != _V2_FIELDS:
        raise HarnessIntegrityError(
            "v2 investigation skill selection field set is invalid"
        )
    registry_version = _registry_version(raw)
    registry_sha256 = _v2_registry_digest(raw)
    provider, compatible = _v2_provider(raw)
    projected = _v2_selected_identities(raw)
    selected_count, truncated = _selection_summary(raw, projected)
    rejected = _v2_rejections(raw)
    budget = _v2_budget(raw)
    if raw.get("enforcement") != V2_ENFORCEMENT:
        raise HarnessIntegrityError(
            "v2 investigation skills must remain identity-only"
        )
    if not compatible and projected:
        raise HarnessIntegrityError(
            "incompatible v2 provider selection must be empty"
        )
    projected.sort(
        key=lambda item: (
            str(item["id"]),
            str(item["version"]),
            str(item["skill_sha256"]),
        )
    )
    return {
        "framework_version": 2,
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "provider": provider,
        "provider_compatible": compatible,
        "selected": projected,
        "selected_count": selected_count,
        "truncated": truncated,
        "rejected": rejected,
        "aggregate_budget": budget,
        "advisory_mode": V2_ENFORCEMENT,
    }


def _v2_registry_digest(raw: Mapping[str, Any]) -> str:
    value = raw.get("registry_digest")
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise HarnessIntegrityError(
            "v2 investigation skill registry digest is invalid"
        )
    return value


def _v2_provider(raw: Mapping[str, Any]) -> tuple[str, bool]:
    provider = raw.get("provider")
    compatible = raw.get("provider_compatible")
    if not isinstance(provider, str) or not IDENTIFIER_RE.fullmatch(provider):
        raise HarnessIntegrityError("v2 investigation skill provider is invalid")
    if not isinstance(compatible, bool):
        raise HarnessIntegrityError(
            "v2 investigation skill provider compatibility is invalid"
        )
    if compatible != (provider in _V2_PROVIDERS):
        raise HarnessIntegrityError(
            "v2 investigation skill provider compatibility is inconsistent"
        )
    return provider, compatible


def _v2_selected_identities(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    selected = raw.get("selected")
    if (
        not isinstance(selected, list)
        or len(selected) > MAX_ATTESTED_INVESTIGATION_SKILLS
    ):
        raise HarnessIntegrityError(
            "v2 investigation skill selection exceeds its bounded list"
        )
    projected = [_v2_selected_identity(item) for item in selected]
    identities = {(item["id"], item["version"]) for item in projected}
    if len(identities) != len(projected):
        raise HarnessIntegrityError(
            "selected v2 investigation skill identities must be unique"
        )
    return projected


def _v2_selected_identity(item: object) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise HarnessIntegrityError(
            "selected v2 investigation skill identity must be an object"
        )
    skill_id = item.get("id")
    version = item.get("version")
    digest = item.get("artifact_digest")
    reason = item.get("selection_reason")
    if not isinstance(skill_id, str) or not IDENTIFIER_RE.fullmatch(skill_id):
        raise HarnessIntegrityError("selected v2 investigation skill id is invalid")
    if not isinstance(version, str) or not _V2_VERSION_RE.fullmatch(version):
        raise HarnessIntegrityError(
            "selected v2 investigation skill version is invalid"
        )
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise HarnessIntegrityError(
            "selected v2 investigation skill digest is invalid"
        )
    if reason not in _V2_SELECTION_REASONS:
        raise HarnessIntegrityError(
            "selected v2 investigation skill selection reason is invalid"
        )
    return {
        "id": skill_id,
        "version": version,
        "skill_sha256": digest,
        "selection_reason": reason,
    }


def _v2_rejections(raw: Mapping[str, Any]) -> list[dict[str, str]]:
    rejected = raw.get("rejected")
    if not isinstance(rejected, list) or len(rejected) > 64:
        raise HarnessIntegrityError(
            "v2 investigation skill rejections are invalid"
        )
    projected = [_v2_rejection(item) for item in rejected]
    if len({(item["id"], item["reason"]) for item in projected}) != len(projected):
        raise HarnessIntegrityError(
            "v2 investigation skill rejections must be unique"
        )
    return sorted(projected, key=lambda item: (item["id"], item["reason"]))


def _v2_rejection(item: object) -> dict[str, str]:
    if not isinstance(item, Mapping) or frozenset(item) != {"id", "reason"}:
        raise HarnessIntegrityError(
            "v2 investigation skill rejection is invalid"
        )
    skill_id = item.get("id")
    reason = item.get("reason")
    if (
        not isinstance(skill_id, str)
        or not IDENTIFIER_RE.fullmatch(skill_id)
        or reason not in _V2_REJECTION_REASONS
    ):
        raise HarnessIntegrityError(
            "v2 investigation skill rejection is invalid"
        )
    return {"id": skill_id, "reason": reason}


def _v2_budget(raw: Mapping[str, Any]) -> dict[str, int]:
    value = raw.get("aggregate_budget")
    if not isinstance(value, Mapping) or frozenset(value) != frozenset(
        _V2_BUDGET_FIELDS
    ):
        raise HarnessIntegrityError(
            "v2 investigation skill aggregate budget is invalid"
        )
    projected: dict[str, int] = {}
    for field in _V2_BUDGET_FIELDS:
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise HarnessIntegrityError(
                "v2 investigation skill aggregate budget is invalid"
            )
        projected[field] = item
    return projected


def _unavailable_attestation() -> dict[str, Any]:
    return {
        "registry_version": 0,
        "registry_sha256": "",
        "selected": [],
        "selected_count": 0,
        "truncated": False,
        "advisory_mode": INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    }


def _registry_version(raw: Mapping[str, Any]) -> int:
    version = raw.get("registry_version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version < 0
    ):
        raise HarnessIntegrityError(
            "investigation skill registry version is invalid"
        )
    return version


def _registry_digest(raw: Mapping[str, Any]) -> str:
    value = str(raw.get("registry_sha256") or "")
    if not DIGEST_RE.fullmatch(value):
        raise HarnessIntegrityError(
            "investigation skill registry digest is invalid"
        )
    return value


def _require_advisory_shadow_mode(raw: Mapping[str, Any]) -> None:
    if (
        raw.get("mode") != "shadow"
        or raw.get("enforcement") != INVESTIGATION_SKILL_ADVISORY_MODE
    ):
        raise HarnessIntegrityError(
            "investigation skills must remain advisory-only in shadow mode"
        )


def _selected_identities(
    raw: Mapping[str, Any],
) -> list[dict[str, Any]]:
    selected = raw.get("selected")
    if (
        not isinstance(selected, list)
        or len(selected) > MAX_ATTESTED_INVESTIGATION_SKILLS
    ):
        raise HarnessIntegrityError(
            "investigation skill selection exceeds its bounded list"
        )
    projected: list[dict[str, Any]] = []
    identities: set[tuple[str, int]] = set()
    for item in selected:
        identity = _selected_identity(item)
        identity_key = (identity["id"], identity["version"])
        if identity_key in identities:
            raise HarnessIntegrityError(
                "selected investigation skill identities must be unique"
            )
        identities.add(identity_key)
        projected.append(identity)
    return projected


def _selected_identity(item: object) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise HarnessIntegrityError(
            "selected investigation skill identity must be an object"
        )
    skill_id = str(item.get("id") or "")
    version = item.get("version")
    skill_sha256 = str(item.get("skill_sha256") or "")
    if not IDENTIFIER_RE.fullmatch(skill_id):
        raise HarnessIntegrityError(
            "selected investigation skill id is invalid"
        )
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version < 1
    ):
        raise HarnessIntegrityError(
            "selected investigation skill version is invalid"
        )
    if not DIGEST_RE.fullmatch(skill_sha256):
        raise HarnessIntegrityError(
            "selected investigation skill digest is invalid"
        )
    return {
        "id": skill_id,
        "version": version,
        "skill_sha256": skill_sha256,
    }


def _selection_summary(
    raw: Mapping[str, Any],
    projected: list[dict[str, Any]],
) -> tuple[int, bool]:
    selected_count = raw.get("selected_count")
    if (
        not isinstance(selected_count, int)
        or isinstance(selected_count, bool)
        or selected_count != len(projected)
    ):
        raise HarnessIntegrityError(
            "investigation skill selected count does not match selection"
        )
    truncated = raw.get("truncated")
    if not isinstance(truncated, bool):
        raise HarnessIntegrityError(
            "investigation skill truncation flag is invalid"
        )
    return selected_count, truncated


def _advisory_mode(
    registry_version: int,
    projected: list[dict[str, Any]],
    selected_count: int,
    truncated: bool,
) -> str:
    if registry_version != 0:
        return INVESTIGATION_SKILL_ADVISORY_MODE
    if projected or selected_count or truncated:
        raise HarnessIntegrityError(
            "unavailable investigation skill registry must be empty"
        )
    return INVESTIGATION_SKILL_UNAVAILABLE_MODE
