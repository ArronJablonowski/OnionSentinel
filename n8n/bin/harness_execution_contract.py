"""Versioned, content-free execution identity for durable harness jobs."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from harness_policy_primitives import HARNESS_SCHEMA


EXECUTION_CONTRACT_SCHEMA = "onion-sentinel-harness-execution-contract-v1"
EXECUTION_CONTRACT_SCHEMA_V2 = "onion-sentinel-harness-execution-contract-v2"
_RELEASE_RE = re.compile(r"^[a-f0-9]{40}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$")
_POLICY_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$")
_SKILL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SKILL_VERSION_V2_RE = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?$"
)
_REASONING_LEVELS = frozenset({"low", "medium", "high", "xhigh"})
_EXTERNAL_PROVIDERS = frozenset({"hermes-agent", "openclaw"})
_CONTRACT_FIELDS = frozenset(
    {
        "schema",
        "source_revision",
        "harness_version",
        "policy_version",
        "primary",
        "reviewer",
        "skill_registry",
        "skill_versions",
    }
)
_ROUTE_FIELDS = frozenset({"route", "provider", "model", "reasoning_level"})
_SKILL_FIELDS = frozenset({"id", "version", "sha256"})
_CONTRACT_FIELDS_V2 = _CONTRACT_FIELDS | {"skill_selection"}
_SKILL_FIELDS_V2 = _SKILL_FIELDS | {"selection_reason"}
_SELECTION_FIELDS_V2 = frozenset(
    {
        "provider",
        "provider_compatible",
        "selected_count",
        "truncated",
        "rejected",
        "aggregate_budget",
        "enforcement",
    }
)
_BUDGET_FIELDS = (
    "max_queries", "max_rows", "max_bytes", "timeout_seconds",
)
_SELECTION_REASON = "exact_match_capability_and_promotion_gates_satisfied"
_REJECTION_REASONS = frozenset(
    {
        "aggregate_budget_exceeded", "artifact_revoked",
        "capability_not_permitted", "compatibility_mismatch",
        "dependency_unavailable", "exact_match_failed",
        "lifecycle_state_unavailable", "manifest_validation_failed",
        "promotion_gates_incomplete", "role_mismatch", "skill_conflict",
        "unsupported_provider",
    }
)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _native_route_identity(route: object, label: str) -> dict[str, str] | None:
    normalized = str(route or "").strip()
    if not normalized:
        return None
    provider = normalized.split(":", 1)[0].lower()
    if provider in _EXTERNAL_PROVIDERS:
        raise ValueError(f"{label} uses an external harness provider")
    if provider == "ollama":
        model = normalized.removeprefix("ollama:").strip()
        if _MODEL_RE.fullmatch(model):
            return {
                "route": normalized,
                "provider": "ollama",
                "model": model,
                "reasoning_level": "not-applicable",
            }
    if provider == "codex-cli":
        try:
            model, reasoning = normalized.removeprefix("codex-cli:").rsplit(":", 1)
        except ValueError:
            model, reasoning = "", ""
        if _MODEL_RE.fullmatch(model) and reasoning in _REASONING_LEVELS:
            return {
                "route": normalized,
                "provider": "codex-cli",
                "model": model,
                "reasoning_level": reasoning,
            }
    raise ValueError(
        f"{label} must pin an exact provider, model, and reasoning level"
    )


def _skill_registry(attestation: Mapping[str, Any]) -> dict[str, Any]:
    version = attestation.get("registry_version")
    digest = attestation.get("registry_sha256")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ValueError("skill registry version is invalid")
    if not isinstance(digest, str) or (
        digest != "" and not _DIGEST_RE.fullmatch(digest)
    ):
        raise ValueError("skill registry digest is invalid")
    return {"version": version, "sha256": digest}


def _skill_id(value: Any) -> str:
    if not isinstance(value, str) or not _SKILL_ID_RE.fullmatch(value):
        raise ValueError("skill version entry is invalid")
    return value


def _skill_version(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("skill version entry is invalid")
    return value


def _skill_digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError("skill version entry is invalid")
    return value


def _skill_version_entry(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise ValueError("skill version entry is invalid")
    return {
        "id": _skill_id(item.get("id")),
        "version": _skill_version(item.get("version")),
        "sha256": _skill_digest(item.get("skill_sha256")),
    }


def _skill_versions(attestation: Mapping[str, Any]) -> list[dict[str, Any]]:
    selected = attestation.get("selected")
    if not isinstance(selected, list):
        raise ValueError("skill version selection is invalid")
    projected = [_skill_version_entry(item) for item in selected]
    projected.sort(key=lambda value: value["id"])
    if len({item["id"] for item in projected}) != len(projected):
        raise ValueError("skill version selection contains duplicates")
    if attestation.get("selected_count") != len(projected):
        raise ValueError("skill version selection count does not match")
    return projected


def _skill_version_entry_v2(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise ValueError("v2 skill version entry is invalid")
    version = item.get("version")
    reason = item.get("selection_reason")
    if not isinstance(version, str) or not _SKILL_VERSION_V2_RE.fullmatch(version):
        raise ValueError("v2 skill version entry is invalid")
    if reason != _SELECTION_REASON:
        raise ValueError("v2 skill selection reason is invalid")
    return {
        "id": _skill_id(item.get("id")),
        "version": version,
        "sha256": _skill_digest(item.get("skill_sha256")),
        "selection_reason": reason,
    }


def _skill_versions_v2(attestation: Mapping[str, Any]) -> list[dict[str, Any]]:
    selected = attestation.get("selected")
    if not isinstance(selected, list):
        raise ValueError("v2 skill version selection is invalid")
    projected = [_skill_version_entry_v2(item) for item in selected]
    projected.sort(key=lambda value: (value["id"], value["version"]))
    if len({(item["id"], item["version"]) for item in projected}) != len(projected):
        raise ValueError("v2 skill version selection contains duplicates")
    if attestation.get("selected_count") != len(projected):
        raise ValueError("v2 skill version selection count does not match")
    return projected


def _selection_budget(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or frozenset(value) != frozenset(_BUDGET_FIELDS):
        raise ValueError("v2 skill aggregate budget is invalid")
    projected: dict[str, int] = {}
    for field in _BUDGET_FIELDS:
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ValueError("v2 skill aggregate budget is invalid")
        projected[field] = item
    return projected


def _selection_rejections(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("v2 skill selection rejections are invalid")
    projected: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping) or frozenset(item) != {"id", "reason"}:
            raise ValueError("v2 skill selection rejection is invalid")
        skill_id = _skill_id(item.get("id"))
        reason = item.get("reason")
        if reason not in _REJECTION_REASONS:
            raise ValueError("v2 skill selection rejection is invalid")
        projected.append({"id": skill_id, "reason": reason})
    if projected != sorted(projected, key=lambda item: (item["id"], item["reason"])):
        raise ValueError("v2 skill selection rejections are not sorted")
    if len({(item["id"], item["reason"]) for item in projected}) != len(projected):
        raise ValueError("v2 skill selection rejections contain duplicates")
    return projected


def _skill_selection_v2(
    attestation: Mapping[str, Any], primary: Mapping[str, str] | None,
) -> dict[str, Any]:
    if attestation.get("framework_version") != 2:
        raise ValueError("v2 skill framework version is invalid")
    provider = _selection_provider(attestation, primary)
    count, truncated = _selection_summary_v2(attestation)
    return {
        "provider": provider,
        "provider_compatible": True,
        "selected_count": count,
        "truncated": truncated,
        "rejected": _selection_rejections(attestation.get("rejected")),
        "aggregate_budget": _selection_budget(attestation.get("aggregate_budget")),
        "enforcement": "identity_only_no_execution",
    }


def _selection_provider(
    attestation: Mapping[str, Any], primary: Mapping[str, str] | None,
) -> str:
    provider = attestation.get("provider")
    compatible = attestation.get("provider_compatible")
    if (
        not isinstance(provider, str)
        or provider not in {"codex-cli", "ollama"}
        or compatible is not True
        or primary is None
        or primary.get("provider") != provider
    ):
        raise ValueError("v2 skills require a compatible native provider")
    return provider


def _selection_summary_v2(attestation: Mapping[str, Any]) -> tuple[int, bool]:
    count = attestation.get("selected_count")
    truncated = attestation.get("truncated")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("v2 skill selected count is invalid")
    if not isinstance(truncated, bool):
        raise ValueError("v2 skill truncation flag is invalid")
    if attestation.get("advisory_mode") != "identity_only_no_execution":
        raise ValueError("v2 skill enforcement is invalid")
    return count, truncated


def build_execution_contract(
    *,
    source_revision: str,
    assigned_route: str,
    reviewer_route: str,
    policy_version: str,
    skill_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one immutable identity projection before durable job admission."""
    revision = str(source_revision or "").strip()
    if not _RELEASE_RE.fullmatch(revision):
        raise ValueError("source revision must be an exact lowercase commit SHA")
    version = str(policy_version or "").strip()
    if not _POLICY_VERSION_RE.fullmatch(version):
        raise ValueError("policy version is invalid")
    if not isinstance(skill_attestation, Mapping):
        raise ValueError("skill version attestation is invalid")
    primary = _native_route_identity(assigned_route, "assigned route")
    reviewer = _native_route_identity(reviewer_route, "reviewer route")
    if skill_attestation.get("framework_version") == 2:
        skill_versions = _skill_versions_v2(skill_attestation)
        selection = _skill_selection_v2(skill_attestation, primary)
        return {
            "schema": EXECUTION_CONTRACT_SCHEMA_V2,
            "source_revision": revision,
            "harness_version": HARNESS_SCHEMA,
            "policy_version": version,
            "primary": primary,
            "reviewer": reviewer,
            "skill_registry": _skill_registry(skill_attestation),
            "skill_versions": skill_versions,
            "skill_selection": selection,
        }
    return {
        "schema": EXECUTION_CONTRACT_SCHEMA,
        "source_revision": revision,
        "harness_version": HARNESS_SCHEMA,
        "policy_version": version,
        "primary": primary,
        "reviewer": reviewer,
        "skill_registry": _skill_registry(skill_attestation),
        "skill_versions": _skill_versions(skill_attestation),
    }


def _validated_route(value: Any, label: str, *, optional: bool) -> Any:
    if value is None and optional:
        return None
    if not isinstance(value, Mapping) or frozenset(value) != _ROUTE_FIELDS:
        raise ValueError(f"execution contract {label} field set is invalid")
    expected = _native_route_identity(value.get("route"), label)
    if dict(value) != expected:
        raise ValueError(f"execution contract {label} identity is invalid")
    return dict(value)


def _validated_skills(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("execution contract skill versions are invalid")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping) or frozenset(item) != _SKILL_FIELDS:
            raise ValueError("execution contract skill version field set is invalid")
        converted = {
            "id": item.get("id"),
            "version": item.get("version"),
            "skill_sha256": item.get("sha256"),
        }
        normalized.extend(_skill_versions({"selected": [converted], "selected_count": 1}))
    if normalized != sorted(normalized, key=lambda item: item["id"]):
        raise ValueError("execution contract skill versions are not sorted")
    if len({item["id"] for item in normalized}) != len(normalized):
        raise ValueError("execution contract skill versions contain duplicates")
    return normalized


def _validated_skills_v2(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("v2 execution contract skill versions are invalid")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping) or frozenset(item) != _SKILL_FIELDS_V2:
            raise ValueError("v2 execution contract skill version field set is invalid")
        converted = {
            "id": item.get("id"),
            "version": item.get("version"),
            "skill_sha256": item.get("sha256"),
            "selection_reason": item.get("selection_reason"),
        }
        normalized.append(_skill_version_entry_v2(converted))
    if normalized != sorted(normalized, key=lambda item: (item["id"], item["version"])):
        raise ValueError("v2 execution contract skill versions are not sorted")
    if len({(item["id"], item["version"]) for item in normalized}) != len(normalized):
        raise ValueError("v2 execution contract skill versions contain duplicates")
    return normalized


def _validate_contract_header(value: Mapping[str, Any], schema: str) -> None:
    if value.get("schema") != schema:
        raise ValueError("execution contract schema is invalid")
    if value.get("harness_version") != HARNESS_SCHEMA:
        raise ValueError("execution contract harness version is invalid")
    revision = value.get("source_revision")
    if not isinstance(revision, str) or not _RELEASE_RE.fullmatch(revision):
        raise ValueError("execution contract source revision is invalid")
    version = value.get("policy_version")
    if not isinstance(version, str) or not _POLICY_VERSION_RE.fullmatch(version):
        raise ValueError("execution contract policy version is invalid")


def _validate_contract_registry(value: Any) -> None:
    if not isinstance(value, Mapping) or frozenset(value) != {"version", "sha256"}:
        raise ValueError("execution contract skill registry field set is invalid")
    _skill_registry(
        {
            "registry_version": value.get("version"),
            "registry_sha256": value.get("sha256"),
        }
    )


def validate_execution_contract(value: Any) -> dict[str, Any]:
    """Validate an already-materialized execution contract without fallback."""
    if not isinstance(value, Mapping):
        raise ValueError("execution contract field set is invalid")
    schema = value.get("schema")
    fields = _CONTRACT_FIELDS_V2 if schema == EXECUTION_CONTRACT_SCHEMA_V2 else _CONTRACT_FIELDS
    if frozenset(value) != fields:
        raise ValueError("execution contract field set is invalid")
    if schema not in {EXECUTION_CONTRACT_SCHEMA, EXECUTION_CONTRACT_SCHEMA_V2}:
        raise ValueError("execution contract schema is invalid")
    _validate_contract_header(value, schema)
    _validate_contract_registry(value.get("skill_registry"))
    primary = _validated_route(value.get("primary"), "primary", optional=False)
    _validated_route(value.get("reviewer"), "reviewer", optional=True)
    if schema == EXECUTION_CONTRACT_SCHEMA_V2:
        skills = _validated_skills_v2(value.get("skill_versions"))
        selection = value.get("skill_selection")
        if not isinstance(selection, Mapping) or frozenset(selection) != _SELECTION_FIELDS_V2:
            raise ValueError("v2 execution contract skill selection field set is invalid")
        normalized = _skill_selection_v2(
            {
                "framework_version": 2,
                "provider": selection.get("provider"),
                "provider_compatible": selection.get("provider_compatible"),
                "selected_count": selection.get("selected_count"),
                "truncated": selection.get("truncated"),
                "rejected": selection.get("rejected"),
                "aggregate_budget": selection.get("aggregate_budget"),
                "advisory_mode": selection.get("enforcement"),
            },
            primary,
        )
        if normalized != dict(selection) or normalized["selected_count"] != len(skills):
            raise ValueError("v2 execution contract skill selection is invalid")
    else:
        _validated_skills(value.get("skill_versions"))
    return dict(value)


def execution_contract_digest(value: Any) -> str:
    validated = validate_execution_contract(value)
    return hashlib.sha256(_canonical_json(validated).encode("utf-8")).hexdigest()


def execution_contract_json(value: Any) -> str:
    return _canonical_json(validate_execution_contract(value))


def parse_execution_contract(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("execution contract JSON is invalid") from exc
    return validate_execution_contract(value)
