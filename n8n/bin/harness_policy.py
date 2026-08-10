"""Policy, activation, identity, and capability contracts for the harness."""
from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any, Mapping


HARNESS_SCHEMA = "onion-sentinel-investigation-harness-v1"
POLICY_SCHEMA = "onion-sentinel-investigation-harness-policy-v1"
TRACE_SCHEMA = "onion-sentinel-investigation-trace-v1"
LEDGER_MANIFEST_SCHEMA_V1 = "onion-sentinel-harness-ledger-manifest-v1"
LEDGER_MANIFEST_SCHEMA = "onion-sentinel-harness-ledger-manifest-v2"
SQL_SCHEMA_VERSION = 4
DEFAULT_POLICY_PATH = (
    Path.home() / "n8n-local" / "config" / "investigation_harness_policy.json"
)
DEFAULT_DB_PATH = (
    Path.home() / "n8n-local" / "alert_store_data" / "investigation-harness.sqlite3"
)
DEFAULT_HARNESS_LOG_PATH = (
    Path.home() / "n8n-local" / "logs" / "investigation-harness.jsonl"
)
MAX_POLICY_BYTES = 256 * 1024
MAX_EVENT_PAYLOAD_BYTES = 64 * 1024
MAX_EVENT_STRING = 4_000
MAX_EVENT_ITEMS = 256
MAX_EVIDENCE_REFS = 2_048
MAX_HYPOTHESES = 64
MAX_DECISION_EVIDENCE_REFS = 256
# External Security Onion/Elastic identifiers commonly begin with ".ds-".
# Control characters and whitespace remain prohibited.
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9.][A-Za-z0-9._:@+=/-]{0,255}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
INVESTIGATION_SKILL_ADVISORY_MODE = "advisory_only"
INVESTIGATION_SKILL_UNAVAILABLE_MODE = "unavailable"
MAX_ATTESTED_INVESTIGATION_SKILLS = 4
INVESTIGATION_SKILL_ATTESTATION_KEYS = frozenset(
    {
        "registry_version",
        "registry_sha256",
        "selected",
        "selected_count",
        "truncated",
        "advisory_mode",
    }
)
EXTERNAL_AGENT_HARNESS_PROVIDERS = frozenset(
    {"hermes-agent", "openclaw"}
)


def external_agent_harness_provider(route: Any) -> str:
    """Return the third-party agent harness selected by an exact route."""
    normalized = str(route or "").strip().lower()
    return next(
        (
            provider
            for provider in EXTERNAL_AGENT_HARNESS_PROVIDERS
            if normalized == provider
            or normalized.startswith(f"{provider}:")
        ),
        "",
    )


def should_start_onion_sentinel_harness(
    *,
    policy_enabled: bool,
    assigned_route: Any,
    reviewer_route: Any,
) -> tuple[bool, str]:
    """Keep the custom harness mutually exclusive with external harnesses."""
    if not policy_enabled:
        return False, "investigation harness policy is disabled"
    for route_kind, route in (
        ("assigned", assigned_route),
        ("second-opinion", reviewer_route),
    ):
        provider = external_agent_harness_provider(route)
        if provider:
            return (
                False,
                f"{route_kind} route uses the external {provider} harness",
            )
    return True, "policy enabled and selected routes are eligible"


class HarnessError(RuntimeError):
    """Base error for a rejected harness operation."""


class HarnessPolicyError(HarnessError):
    """A policy document or authorization request is invalid."""


class HarnessIntegrityError(HarnessError):
    """Durable trace state failed an integrity or collision check."""


class AgentRole(str, enum.Enum):
    SOC_ANALYST = "soc-analyst"
    INCIDENT_RESPONDER = "incident-responder"
    SIEM_ENGINEER = "siem-engineer"
    CYBER_THREAT_INTEL = "cyber-threat-intel"
    THREAT_HUNTER = "threat-hunter"


class TaskKind(str, enum.Enum):
    ALERT_TRIAGE = "alert-triage"
    INCIDENT_RESPONSE = "incident-response"
    DETECTION_ENGINEERING = "detection-engineering"
    THREAT_INTELLIGENCE = "threat-intelligence"
    THREAT_HUNT = "threat-hunt"
    REANALYSIS = "reanalysis"


class RunStatus(str, enum.Enum):
    RUNNING = "running"
    WAITING_FOR_REVIEW = "waiting-for-review"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Stage(str, enum.Enum):
    INTAKE = "intake"
    CONTEXT_ASSEMBLY = "context-assembly"
    PRIMARY_ANALYSIS = "primary-analysis"
    QUERY_PLANNING = "query-planning"
    QUERY_EXECUTION = "query-execution"
    EVIDENCE_SYNTHESIS = "evidence-synthesis"
    INDEPENDENT_REVIEW = "independent-review"
    HUMAN_REVIEW = "human-review"
    POST_PROCESSING = "post-processing"
    PERSISTENCE = "persistence"
    COMPLETE = "complete"
    FAILED = "failed"


class TrustTier(str, enum.Enum):
    TRUSTED_COLLECTOR = "trusted-collector"
    READ_ONLY_BACKEND = "read-only-backend"
    HUMAN_CONFIRMED = "human-confirmed"
    EXTERNAL_INTELLIGENCE = "external-intelligence"
    MODEL_DERIVED = "model-derived"
    MEMORY_LEAD = "memory-lead"
    UNKNOWN = "unknown"


READ_ONLY_CAPABILITIES = frozenset(
    {
        "alerts.read",
        "cases.read",
        "reports.read",
        "security-onion.events.query",
        "security-onion.oql.query",
        "endpoint.osquery.query",
        "pcap.derived.query",
        "zeek.derived.query",
        "suricata.events.read",
        "threat-intel.lookup",
        "detections.read",
        "memory.read",
    }
)
MUTATING_CAPABILITIES = frozenset(
    {
        "alerts.acknowledge",
        "alerts.suppress",
        "cases.write",
        "detections.write",
        "notifications.send",
        "response.contain",
        "memory.promote",
    }
)
SENSITIVE_ACTIVE_CAPABILITIES = frozenset(
    {
        # A live distributed query is read-only SQL, but dispatching work to an
        # endpoint is still an operational action. Historical osquery result
        # reads belong in a separate future capability.
        "endpoint.osquery.query",
    }
)
APPROVAL_GATED_CAPABILITIES = (
    MUTATING_CAPABILITIES | SENSITIVE_ACTIVE_CAPABILITIES
)
ALL_CAPABILITIES = READ_ONLY_CAPABILITIES | MUTATING_CAPABILITIES
QUERY_BACKEND_CAPABILITIES = {
    "elastic": "security-onion.events.query",
    "oql": "security-onion.oql.query",
    "osquery": "endpoint.osquery.query",
    "pcap_zeek": "pcap.derived.query",
}


def query_backend_capability(backend: object) -> str:
    return QUERY_BACKEND_CAPABILITIES.get(str(backend), "unknown")


def query_backend_is_approval_gated(backend: object) -> bool:
    return query_backend_capability(backend) in APPROVAL_GATED_CAPABILITIES

DEFAULT_ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    AgentRole.SOC_ANALYST.value: frozenset(
        {
            "alerts.read",
            "reports.read",
            "security-onion.events.query",
            "security-onion.oql.query",
            "endpoint.osquery.query",
            "pcap.derived.query",
            "zeek.derived.query",
            "suricata.events.read",
            "threat-intel.lookup",
            "detections.read",
            "memory.read",
            "alerts.acknowledge",
            "alerts.suppress",
            "cases.write",
            "notifications.send",
            "memory.promote",
        }
    ),
    AgentRole.INCIDENT_RESPONDER.value: frozenset(
        {
            "alerts.read",
            "cases.read",
            "reports.read",
            "security-onion.events.query",
            "security-onion.oql.query",
            "endpoint.osquery.query",
            "pcap.derived.query",
            "zeek.derived.query",
            "suricata.events.read",
            "threat-intel.lookup",
            "detections.read",
            "memory.read",
            "cases.write",
            "notifications.send",
            "response.contain",
            "memory.promote",
        }
    ),
    AgentRole.SIEM_ENGINEER.value: frozenset(
        {
            "alerts.read",
            "cases.read",
            "reports.read",
            "security-onion.events.query",
            "security-onion.oql.query",
            "pcap.derived.query",
            "zeek.derived.query",
            "suricata.events.read",
            "detections.read",
            "memory.read",
            "detections.write",
            "memory.promote",
        }
    ),
    AgentRole.CYBER_THREAT_INTEL.value: frozenset(
        {
            "alerts.read",
            "cases.read",
            "reports.read",
            "security-onion.events.query",
            "security-onion.oql.query",
            "pcap.derived.query",
            "zeek.derived.query",
            "suricata.events.read",
            "threat-intel.lookup",
            "detections.read",
            "memory.read",
            "memory.promote",
        }
    ),
    AgentRole.THREAT_HUNTER.value: frozenset(
        {
            "alerts.read",
            "cases.read",
            "reports.read",
            "security-onion.events.query",
            "security-onion.oql.query",
            "endpoint.osquery.query",
            "pcap.derived.query",
            "zeek.derived.query",
            "suricata.events.read",
            "threat-intel.lookup",
            "detections.read",
            "memory.read",
            "cases.write",
            "detections.write",
            "memory.promote",
        }
    ),
}

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
        "schema",
        "version",
        "enabled",
        "mode",
        "budgets",
        "role_capabilities",
        "approval_required",
        "memory",
    }
)
REQUIRED_MEMORY_FIELDS = frozenset(
    {
        "require_independent_agreement",
        "shared_requires_human_approval",
    }
)

SECRET_KEY_RE = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|authorization|cookie|credential|password|"
    r"private[_-]?key|secret|session|token)(?:$|[_-])",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|authorization|credential|password|passwd|secret|"
        r"session|token)\s*[:=]\s*[^\s,;]{4,}",
        re.IGNORECASE,
    ),
)


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _valid_identifier(value: object, label: str, maximum: int = 256) -> str:
    raw = str(value or "").strip()
    if len(raw) > maximum:
        raise HarnessPolicyError(f"{label} exceeds its length limit")
    text = raw
    if not text or not IDENTIFIER_RE.fullmatch(text):
        raise HarnessPolicyError(f"{label} is invalid")
    return text


def _model_route(
    value: object,
    label: str,
    *,
    allow_empty: bool = False,
) -> str:
    text = str(value or "").strip()
    if not text and allow_empty:
        return ""
    return _valid_identifier(text, label, 256)


def _digest_or_hash(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if DIGEST_RE.fullmatch(text) else digest_json(value)


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


@dataclasses.dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    capability: str
    reason: str
    requires_approval: bool = False


def policy_decision_is_effective(
    mode: str,
    decision: PolicyDecision,
) -> bool:
    """Return whether a policy decision permits the requested operation.

    Shadow mode may observe ordinary policy denials without changing the
    existing workflow, but it must never manufacture consent for an operation
    that explicitly requires human approval.
    """
    return bool(
        decision.allowed
        or (
            str(mode).strip().lower() == "shadow"
            and not decision.requires_approval
        )
    )


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
                "schema": POLICY_SCHEMA,
                "version": self.version,
                "enabled": self.enabled,
                "mode": self.mode,
                "budgets": dict(self.budgets),
                "role_capabilities": {
                    role: sorted(capabilities)
                    for role, capabilities in sorted(
                        self.role_capabilities.items()
                    )
                },
                "approval_required": sorted(self.approval_required),
                "memory": {
                    "require_independent_agreement": (
                        self.memory_require_independent_agreement
                    ),
                    "shared_requires_human_approval": (
                        self.shared_memory_requires_human_approval
                    ),
                },
            }
        )

    @classmethod
    def disabled_default(cls) -> "HarnessPolicy":
        return cls(
            version="1.0.0",
            enabled=False,
            mode="shadow",
            budgets=dict(DEFAULT_BUDGETS),
            role_capabilities=dict(DEFAULT_ROLE_CAPABILITIES),
            approval_required=APPROVAL_GATED_CAPABILITIES,
            memory_require_independent_agreement=True,
            shared_memory_requires_human_approval=True,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "HarnessPolicy":
        if not isinstance(value, dict) or value.get("schema") != POLICY_SCHEMA:
            raise HarnessPolicyError(
                f"harness policy schema must be {POLICY_SCHEMA}"
            )
        unknown = set(value).difference(REQUIRED_POLICY_FIELDS)
        if unknown:
            raise HarnessPolicyError(
                "unsupported harness policy fields: " + ", ".join(sorted(unknown))
            )
        missing = REQUIRED_POLICY_FIELDS.difference(value)
        if missing:
            raise HarnessPolicyError(
                "missing required harness policy fields: "
                + ", ".join(sorted(missing))
            )
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
        raw_budgets = value["budgets"]
        if not isinstance(raw_budgets, dict):
            raise HarnessPolicyError("harness policy budgets must be an object")
        unknown_budgets = set(raw_budgets).difference(DEFAULT_BUDGETS)
        if unknown_budgets:
            raise HarnessPolicyError(
                "unsupported harness budgets: " + ", ".join(sorted(unknown_budgets))
            )
        missing_budgets = set(DEFAULT_BUDGETS).difference(raw_budgets)
        if missing_budgets:
            raise HarnessPolicyError(
                "missing required harness budgets: "
                + ", ".join(sorted(missing_budgets))
            )
        budgets: dict[str, int] = {}
        for key in DEFAULT_BUDGETS:
            raw = raw_budgets[key]
            if type(raw) is not int:
                raise HarnessPolicyError(f"{key} must be an integer")
            number = raw
            if number < MIN_BUDGETS[key] or number > MAX_BUDGETS[key]:
                raise HarnessPolicyError(f"{key} is outside its safe range")
            budgets[key] = number

        raw_roles = value["role_capabilities"]
        if not isinstance(raw_roles, dict) or set(raw_roles) != {
            item.value for item in AgentRole
        }:
            raise HarnessPolicyError(
                "role_capabilities must define every cyber-security agent role"
            )
        roles: dict[str, frozenset[str]] = {}
        for role, capabilities in raw_roles.items():
            if not isinstance(capabilities, list):
                raise HarnessPolicyError(
                    f"role_capabilities.{role} must be a unique array"
                )
            if any(not isinstance(item, str) for item in capabilities):
                raise HarnessPolicyError(
                    f"role_capabilities.{role} entries must be strings"
                )
            if len(capabilities) != len(set(capabilities)):
                raise HarnessPolicyError(
                    f"role_capabilities.{role} must be a unique array"
                )
            normalized = frozenset(capabilities)
            unknown_caps = normalized.difference(ALL_CAPABILITIES)
            if unknown_caps:
                raise HarnessPolicyError(
                    f"unknown capabilities for {role}: "
                    + ", ".join(sorted(unknown_caps))
                )
            roles[role] = normalized

        raw_approvals = value["approval_required"]
        if (
            not isinstance(raw_approvals, list)
            or any(not isinstance(item, str) for item in raw_approvals)
        ):
            raise HarnessPolicyError(
                "approval_required must be an array of strings"
            )
        if len(raw_approvals) != len(set(raw_approvals)):
            raise HarnessPolicyError("approval_required must be a unique array")
        approvals = frozenset(raw_approvals)
        unknown_approvals = approvals.difference(ALL_CAPABILITIES)
        if unknown_approvals:
            raise HarnessPolicyError(
                "unknown approval capabilities: "
                + ", ".join(sorted(unknown_approvals))
            )
        # Every mutating or operationally active capability is approval-gated
        # even if a policy author accidentally omits it.
        approvals = approvals | APPROVAL_GATED_CAPABILITIES

        raw_memory = value["memory"]
        if not isinstance(raw_memory, dict):
            raise HarnessPolicyError("memory policy must be an object")
        unknown_memory = set(raw_memory).difference(REQUIRED_MEMORY_FIELDS)
        if unknown_memory:
            raise HarnessPolicyError(
                "unsupported memory policy fields: "
                + ", ".join(sorted(unknown_memory))
            )
        missing_memory = REQUIRED_MEMORY_FIELDS.difference(raw_memory)
        if missing_memory:
            raise HarnessPolicyError(
                "missing required memory policy fields: "
                + ", ".join(sorted(missing_memory))
            )
        independent = raw_memory["require_independent_agreement"]
        shared_approval = raw_memory["shared_requires_human_approval"]
        if not isinstance(independent, bool) or not isinstance(shared_approval, bool):
            raise HarnessPolicyError("memory policy flags must be boolean")
        return cls(
            version=version,
            enabled=value["enabled"],
            mode=mode,
            budgets=budgets,
            role_capabilities=roles,
            approval_required=approvals,
            memory_require_independent_agreement=independent,
            shared_memory_requires_human_approval=shared_approval,
        )

    def authorize(
        self,
        role: str,
        capability: str,
        *,
        approved: bool = False,
    ) -> PolicyDecision:
        requires_approval = capability in self.approval_required
        if role not in self.role_capabilities:
            return PolicyDecision(
                False,
                capability,
                "unknown agent role",
                requires_approval=requires_approval,
            )
        if capability not in ALL_CAPABILITIES:
            return PolicyDecision(False, capability, "capability is not registered")
        if capability not in self.role_capabilities[role]:
            return PolicyDecision(
                False,
                capability,
                "capability is not assigned to role",
                requires_approval=requires_approval,
            )
        if requires_approval and not approved:
            return PolicyDecision(
                False,
                capability,
                "explicit human approval is required",
                requires_approval=True,
            )
        return PolicyDecision(
            True,
            capability,
            "authorized by exact role capability",
            requires_approval=requires_approval,
        )


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> HarnessPolicy:
    if not path.exists():
        return HarnessPolicy.disabled_default()
    if path.is_symlink() or not path.is_file():
        raise HarnessPolicyError("harness policy must be a regular file")
    if stat.S_IMODE(path.stat().st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise HarnessPolicyError(
            "harness policy must not be group- or world-writable"
        )
    raw = path.read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise HarnessPolicyError("harness policy exceeds its byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessPolicyError("harness policy is not valid UTF-8 JSON") from exc
    return HarnessPolicy.from_dict(value)


def task_kind_for_role(
    role: str,
    *,
    reanalysis_attempt_id: str = "",
    manual_reanalysis: bool = False,
) -> str:
    if reanalysis_attempt_id or manual_reanalysis:
        return TaskKind.REANALYSIS.value
    return {
        AgentRole.SOC_ANALYST.value: TaskKind.ALERT_TRIAGE.value,
        AgentRole.INCIDENT_RESPONDER.value: TaskKind.INCIDENT_RESPONSE.value,
        AgentRole.SIEM_ENGINEER.value: TaskKind.DETECTION_ENGINEERING.value,
        AgentRole.CYBER_THREAT_INTEL.value: TaskKind.THREAT_INTELLIGENCE.value,
        AgentRole.THREAT_HUNTER.value: TaskKind.THREAT_HUNT.value,
    }[role]
