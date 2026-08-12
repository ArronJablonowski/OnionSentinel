"""Content-free investigation-skill identity attestation."""
from __future__ import annotations

from typing import Any, Mapping

from harness_policy import (
    DIGEST_RE,
    HarnessIntegrityError,
    IDENTIFIER_RE,
    INVESTIGATION_SKILL_ADVISORY_MODE,
    INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
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
