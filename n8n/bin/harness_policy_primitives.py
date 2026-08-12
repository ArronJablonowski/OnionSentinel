"""Harness schemas, identities, enums, digests, and secret classifiers."""
from __future__ import annotations

import datetime as dt
import enum
import hashlib
import json
import re
from pathlib import Path
from typing import Any


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
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9.][A-Za-z0-9._:@+=/-]{0,255}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
INVESTIGATION_SKILL_ADVISORY_MODE = "advisory_only"
INVESTIGATION_SKILL_UNAVAILABLE_MODE = "unavailable"
MAX_ATTESTED_INVESTIGATION_SKILLS = 4
INVESTIGATION_SKILL_ATTESTATION_KEYS = frozenset(
    {
        "registry_version", "registry_sha256", "selected", "selected_count",
        "truncated", "advisory_mode",
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


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        .isoformat().replace("+00:00", "Z")
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        default=str,
    )


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _valid_identifier(value: object, label: str, maximum: int = 256) -> str:
    raw = str(value or "").strip()
    if len(raw) > maximum:
        raise HarnessPolicyError(f"{label} exceeds its length limit")
    if not raw or not IDENTIFIER_RE.fullmatch(raw):
        raise HarnessPolicyError(f"{label} is invalid")
    return raw


def _model_route(
    value: object, label: str, *, allow_empty: bool = False,
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
