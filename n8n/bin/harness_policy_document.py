"""Strict harness policy document validation, authorization, and loading."""
from __future__ import annotations

import dataclasses
import json
import stat
from pathlib import Path
from typing import Any, Mapping

from harness_policy_capabilities import (
    ALL_CAPABILITIES,
    APPROVAL_GATED_CAPABILITIES,
    DEFAULT_ROLE_CAPABILITIES,
    PolicyDecision,
)
from harness_policy_primitives import (
    AgentRole,
    DEFAULT_POLICY_PATH,
    HarnessPolicyError,
    MAX_POLICY_BYTES,
    POLICY_SCHEMA,
    _valid_identifier,
    digest_json,
)


DEFAULT_BUDGETS: dict[str, int] = {
    "max_model_calls": 6,
    "max_query_rounds": 3,
    "max_queries_total": 12,
    "max_queries_per_round": 4,
    "max_prompt_evidence_bytes": 1024 * 1024,
    "max_prompt_evidence_rows": 1_200,
    "max_run_seconds": 3_900,
}
MIN_BUDGETS: dict[str, int] = {
    **{key: 1 for key in DEFAULT_BUDGETS},
    "max_prompt_evidence_bytes": 4_096,
}
MAX_BUDGETS: dict[str, int] = {
    key: max(default * 16, default + 100)
    for key, default in DEFAULT_BUDGETS.items()
}
REQUIRED_POLICY_FIELDS = frozenset(
    {
        "schema", "version", "enabled", "mode", "budgets",
        "role_capabilities", "approval_required", "memory",
    }
)
REQUIRED_MEMORY_FIELDS = frozenset(
    {"require_independent_agreement", "shared_requires_human_approval"}
)


def _require_policy_shape(value: Any) -> dict:
    if not isinstance(value, dict) or value.get("schema") != POLICY_SCHEMA:
        raise HarnessPolicyError(f"harness policy schema must be {POLICY_SCHEMA}")
    unknown = set(value).difference(REQUIRED_POLICY_FIELDS)
    if unknown:
        raise HarnessPolicyError(
            "unsupported harness policy fields: " + ", ".join(sorted(unknown))
        )
    missing = REQUIRED_POLICY_FIELDS.difference(value)
    if missing:
        raise HarnessPolicyError(
            "missing required harness policy fields: " + ", ".join(sorted(missing))
        )
    return value


def _parse_identity(value: dict) -> tuple[str, str, bool]:
    if not isinstance(value["version"], str):
        raise HarnessPolicyError("harness policy version must be a string")
    version = _valid_identifier(value["version"], "policy version", 64)
    if not isinstance(value["mode"], str):
        raise HarnessPolicyError("harness policy mode must be a string")
    mode = value["mode"]
    if mode not in {"shadow", "enforce"}:
        raise HarnessPolicyError("harness policy mode must be shadow or enforce")
    if not isinstance(value["enabled"], bool):
        raise HarnessPolicyError("harness policy enabled must be boolean")
    return version, mode, value["enabled"]


def _parse_budgets(raw_budgets: object) -> dict[str, int]:
    if not isinstance(raw_budgets, dict):
        raise HarnessPolicyError("harness policy budgets must be an object")
    unknown = set(raw_budgets).difference(DEFAULT_BUDGETS)
    if unknown:
        raise HarnessPolicyError("unsupported harness budgets: " + ", ".join(sorted(unknown)))
    missing = set(DEFAULT_BUDGETS).difference(raw_budgets)
    if missing:
        raise HarnessPolicyError(
            "missing required harness budgets: " + ", ".join(sorted(missing))
        )
    budgets: dict[str, int] = {}
    for key in DEFAULT_BUDGETS:
        raw = raw_budgets[key]
        if type(raw) is not int:
            raise HarnessPolicyError(f"{key} must be an integer")
        if raw < MIN_BUDGETS[key] or raw > MAX_BUDGETS[key]:
            raise HarnessPolicyError(f"{key} is outside its safe range")
        budgets[key] = raw
    return budgets


def _parse_roles(raw_roles: object) -> dict[str, frozenset[str]]:
    if not isinstance(raw_roles, dict) or set(raw_roles) != {
        item.value for item in AgentRole
    }:
        raise HarnessPolicyError(
            "role_capabilities must define every cyber-security agent role"
        )
    roles: dict[str, frozenset[str]] = {}
    for role, capabilities in raw_roles.items():
        if not isinstance(capabilities, list):
            raise HarnessPolicyError(f"role_capabilities.{role} must be a unique array")
        if any(not isinstance(item, str) for item in capabilities):
            raise HarnessPolicyError(f"role_capabilities.{role} entries must be strings")
        if len(capabilities) != len(set(capabilities)):
            raise HarnessPolicyError(f"role_capabilities.{role} must be a unique array")
        normalized = frozenset(capabilities)
        unknown = normalized.difference(ALL_CAPABILITIES)
        if unknown:
            raise HarnessPolicyError(
                f"unknown capabilities for {role}: " + ", ".join(sorted(unknown))
            )
        roles[role] = normalized
    return roles


def _parse_approvals(raw_approvals: object) -> frozenset[str]:
    if (
        not isinstance(raw_approvals, list)
        or any(not isinstance(item, str) for item in raw_approvals)
    ):
        raise HarnessPolicyError("approval_required must be an array of strings")
    if len(raw_approvals) != len(set(raw_approvals)):
        raise HarnessPolicyError("approval_required must be a unique array")
    approvals = frozenset(raw_approvals)
    unknown = approvals.difference(ALL_CAPABILITIES)
    if unknown:
        raise HarnessPolicyError(
            "unknown approval capabilities: " + ", ".join(sorted(unknown))
        )
    return approvals | APPROVAL_GATED_CAPABILITIES


def _parse_memory(raw_memory: object) -> tuple[bool, bool]:
    if not isinstance(raw_memory, dict):
        raise HarnessPolicyError("memory policy must be an object")
    unknown = set(raw_memory).difference(REQUIRED_MEMORY_FIELDS)
    if unknown:
        raise HarnessPolicyError(
            "unsupported memory policy fields: " + ", ".join(sorted(unknown))
        )
    missing = REQUIRED_MEMORY_FIELDS.difference(raw_memory)
    if missing:
        raise HarnessPolicyError(
            "missing required memory policy fields: " + ", ".join(sorted(missing))
        )
    independent = raw_memory["require_independent_agreement"]
    shared_approval = raw_memory["shared_requires_human_approval"]
    if not isinstance(independent, bool) or not isinstance(shared_approval, bool):
        raise HarnessPolicyError("memory policy flags must be boolean")
    return independent, shared_approval


@dataclasses.dataclass(frozen=True)
class HarnessPolicy:
    version: str
    enabled: bool
    mode: str
    budgets: Mapping[str, int]
    role_capabilities: Mapping[str, frozenset[str]]
    approval_required: frozenset[str]
    memory_require_independent_agreement: bool
    shared_memory_requires_human_approval: bool

    @property
    def digest(self) -> str:
        return digest_json(
            {
                "schema": POLICY_SCHEMA, "version": self.version,
                "enabled": self.enabled, "mode": self.mode,
                "budgets": dict(self.budgets),
                "role_capabilities": {
                    role: sorted(capabilities)
                    for role, capabilities in sorted(self.role_capabilities.items())
                },
                "approval_required": sorted(self.approval_required),
                "memory": {
                    "require_independent_agreement": self.memory_require_independent_agreement,
                    "shared_requires_human_approval": self.shared_memory_requires_human_approval,
                },
            }
        )

    @classmethod
    def disabled_default(cls) -> "HarnessPolicy":
        return cls(
            version="1.0.0", enabled=False, mode="shadow",
            budgets=dict(DEFAULT_BUDGETS),
            role_capabilities=dict(DEFAULT_ROLE_CAPABILITIES),
            approval_required=APPROVAL_GATED_CAPABILITIES,
            memory_require_independent_agreement=True,
            shared_memory_requires_human_approval=True,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "HarnessPolicy":
        document = _require_policy_shape(value)
        version, mode, enabled = _parse_identity(document)
        independent, shared_approval = _parse_memory(document["memory"])
        return cls(
            version=version, enabled=enabled, mode=mode,
            budgets=_parse_budgets(document["budgets"]),
            role_capabilities=_parse_roles(document["role_capabilities"]),
            approval_required=_parse_approvals(document["approval_required"]),
            memory_require_independent_agreement=independent,
            shared_memory_requires_human_approval=shared_approval,
        )

    def authorize(
        self, role: str, capability: str, *, approved: bool = False,
    ) -> PolicyDecision:
        requires_approval = capability in self.approval_required
        if role not in self.role_capabilities:
            return PolicyDecision(False, capability, "unknown agent role",
                                  requires_approval=requires_approval)
        if capability not in ALL_CAPABILITIES:
            return PolicyDecision(False, capability, "capability is not registered")
        if capability not in self.role_capabilities[role]:
            return PolicyDecision(False, capability, "capability is not assigned to role",
                                  requires_approval=requires_approval)
        if requires_approval and not approved:
            return PolicyDecision(False, capability,
                                  "explicit human approval is required",
                                  requires_approval=True)
        return PolicyDecision(True, capability, "authorized by exact role capability",
                              requires_approval=requires_approval)


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> HarnessPolicy:
    if not path.exists():
        return HarnessPolicy.disabled_default()
    if path.is_symlink() or not path.is_file():
        raise HarnessPolicyError("harness policy must be a regular file")
    if stat.S_IMODE(path.stat().st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise HarnessPolicyError("harness policy must not be group- or world-writable")
    raw = path.read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise HarnessPolicyError("harness policy exceeds its byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessPolicyError("harness policy is not valid UTF-8 JSON") from exc
    return HarnessPolicy.from_dict(value)
