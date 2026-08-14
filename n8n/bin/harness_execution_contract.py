"""Versioned, content-free execution identity for durable harness jobs."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from harness_policy_primitives import HARNESS_SCHEMA


EXECUTION_CONTRACT_SCHEMA = "onion-sentinel-harness-execution-contract-v1"
_RELEASE_RE = re.compile(r"^[a-f0-9]{40}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$")
_POLICY_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$")
_SKILL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
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
    return {
        "schema": EXECUTION_CONTRACT_SCHEMA,
        "source_revision": revision,
        "harness_version": HARNESS_SCHEMA,
        "policy_version": version,
        "primary": _native_route_identity(assigned_route, "assigned route"),
        "reviewer": _native_route_identity(reviewer_route, "reviewer route"),
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


def _validate_contract_header(value: Mapping[str, Any]) -> None:
    if value.get("schema") != EXECUTION_CONTRACT_SCHEMA:
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
    if not isinstance(value, Mapping) or frozenset(value) != _CONTRACT_FIELDS:
        raise ValueError("execution contract field set is invalid")
    _validate_contract_header(value)
    _validate_contract_registry(value.get("skill_registry"))
    _validated_route(value.get("primary"), "primary", optional=False)
    _validated_route(value.get("reviewer"), "reviewer", optional=True)
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
