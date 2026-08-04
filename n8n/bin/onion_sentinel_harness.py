#!/usr/bin/env python3
"""Durable, model-neutral investigation harness for Onion Sentinel.

The harness is deliberately a trusted control-plane component. Models may
propose queries, hypotheses, memory candidates, and actions, but this module
owns policy decisions, durable run state, provenance, and audit integrity.

Version 1 is a shadow-capable runtime around the existing production runner.
It does not give a model direct shell, database, Security Onion, or credential
access. Existing typed brokers remain the only query execution boundary.
"""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import enum
import hashlib
import hmac
import importlib.util
import json
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

try:
    from security_jsonl_log import SecurityJsonlLogger
except ModuleNotFoundError:
    _logging_spec = importlib.util.spec_from_file_location(
        "security_jsonl_log",
        Path(__file__).with_name("security_jsonl_log.py"),
    )
    if _logging_spec is None or _logging_spec.loader is None:
        raise
    _logging_module = importlib.util.module_from_spec(_logging_spec)
    sys.modules.setdefault("security_jsonl_log", _logging_module)
    _logging_spec.loader.exec_module(_logging_module)
    SecurityJsonlLogger = _logging_module.SecurityJsonlLogger


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


RETURNED_COUNT_KEYS = frozenset(
    {
        "returned",
        "returned_hits",
        "returned_rows",
        "records_returned",
        "total_hits",
        "total_rows",
    }
)


def observed_returned_count(value: Any, *, depth: int = 0) -> int | None:
    """Find an explicit bounded result count without inventing a zero or one."""
    if depth > 8:
        return None
    counts: list[int] = []
    if isinstance(value, Mapping):
        for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
            key = str(raw_key).strip().lower()
            if key in RETURNED_COUNT_KEYS and not isinstance(child, bool):
                try:
                    number = int(child)
                except (TypeError, ValueError, OverflowError):
                    number = -1
                if number >= 0:
                    counts.append(number)
            nested = observed_returned_count(child, depth=depth + 1)
            if nested is not None:
                counts.append(nested)
    elif isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        for child in list(value)[:MAX_EVENT_ITEMS]:
            nested = observed_returned_count(child, depth=depth + 1)
            if nested is not None:
                counts.append(nested)
    return max(counts) if counts else None


def observed_truncation(value: Any, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(value, Mapping):
        for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
            key = str(raw_key).strip().lower()
            if (key == "truncated" or key.endswith("_truncated")) and child is True:
                return True
            if observed_truncation(child, depth=depth + 1):
                return True
    elif isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        return any(
            observed_truncation(child, depth=depth + 1)
            for child in list(value)[:MAX_EVENT_ITEMS]
        )
    return False


QUERY_SUCCESS_STATUSES = frozenset(
    {"ok", "complete", "completed", "success", "succeeded"}
)
SECURITY_ONION_QUERY_STATUSES = frozenset(
    {"ok", "timeout", "output_limit", "error", "invalid_response"}
)


def resolve_query_binding(
    result: Mapping[str, Any],
    query_id: str,
) -> tuple[str, Any]:
    """Resolve one durable tool status from a provenance-bound batch result.

    The Security Onion broker returns one envelope for a batch. A mixed batch
    is correctly marked ``partial`` even when some nested queries succeeded.
    Copying that coarse status to every tool row loses the successful pivots
    and can incorrectly fail a controlled evaluation. Only unwrap an
    individual status when the trusted response digest, semantic controls,
    per-query audit, and both query/result digests agree exactly.

    The caller must continue hashing the full outer result for durable result
    provenance. The returned observation is only for per-query status,
    coverage, and truncation semantics.
    """
    outer_status = str(result.get("status") or "missing").strip().lower()[:40]
    if (
        outer_status != "partial"
        or str(result.get("backend") or "") != "security_onion"
        or result.get("read_only") is not True
    ):
        return outer_status, result

    response_digest = str(
        result.get("security_onion_response_digest") or ""
    ).strip()
    evidence = (
        result.get("evidence")
        if isinstance(result.get("evidence"), Mapping)
        else None
    )
    query_ids = (
        [str(value) for value in result.get("query_ids", [])]
        if isinstance(result.get("query_ids"), list)
        else []
    )
    if (
        not DIGEST_RE.fullmatch(response_digest)
        or not isinstance(evidence, Mapping)
        or evidence.get("read_only") is not True
        or evidence.get("partial") is not True
        or evidence.get("complete") is not False
        or evidence.get("controls_valid") is not True
        or not query_ids
        or len(query_ids) != len(set(query_ids))
        or query_ids.count(query_id) != 1
    ):
        return outer_status, result

    nested_results = (
        evidence.get("results")
        if isinstance(evidence.get("results"), list)
        else []
    )
    audits = (
        result.get("trusted_query_audit")
        if isinstance(result.get("trusted_query_audit"), list)
        else []
    )
    nested_ids = [
        str(item.get("query_id") or "")
        for item in nested_results
        if isinstance(item, Mapping)
    ]
    audit_ids = [
        str(item.get("query_id") or "")
        for item in audits
        if isinstance(item, Mapping)
    ]
    if (
        len(nested_ids) != len(nested_results)
        or len(audit_ids) != len(audits)
        or nested_ids != query_ids
        or audit_ids != query_ids
        or len(nested_ids) != len(set(nested_ids))
        or len(audit_ids) != len(set(audit_ids))
    ):
        return outer_status, result
    matching_results = [
        item
        for item in nested_results
        if isinstance(item, Mapping)
        and str(item.get("query_id") or "") == query_id
    ]
    matching_audits = [
        item
        for item in audits
        if isinstance(item, Mapping)
        and str(item.get("query_id") or "") == query_id
    ]
    if len(matching_results) != 1 or len(matching_audits) != 1:
        return outer_status, result
    nested = matching_results[0]
    audit = matching_audits[0]

    nested_status = str(nested.get("status") or "").strip().lower()[:40]
    audit_status = str(audit.get("status") or "").strip().lower()[:40]
    nested_query_digest = str(
        nested.get("query_digest") or ""
    ).strip()
    audit_query_digest = str(
        audit.get("query_digest") or ""
    ).strip()
    nested_result_digest = str(
        nested.get("result_digest") or ""
    ).strip()
    audit_result_digest = str(
        audit.get("result_digest") or ""
    ).strip()
    if (
        not nested_status
        or nested_status not in SECURITY_ONION_QUERY_STATUSES
        or nested_status != audit_status
        or not DIGEST_RE.fullmatch(nested_query_digest)
        or not DIGEST_RE.fullmatch(audit_query_digest)
        or not hmac.compare_digest(nested_query_digest, audit_query_digest)
        or not DIGEST_RE.fullmatch(nested_result_digest)
        or not DIGEST_RE.fullmatch(audit_result_digest)
        or not hmac.compare_digest(nested_result_digest, audit_result_digest)
    ):
        return outer_status, result

    observation = {"result": nested, "audit": audit}
    expected_semantic_valid = nested_status == "ok"
    if (
        nested.get("semantic_valid") is not expected_semantic_valid
        or audit.get("semantic_valid") is not expected_semantic_valid
        or not isinstance(audit.get("timed_out"), bool)
        or (
            "timed_out" in nested
            and nested.get("timed_out") is not audit.get("timed_out")
        )
        or audit.get("timed_out") is not (nested_status == "timeout")
    ):
        return outer_status, observation
    if nested_status in QUERY_SUCCESS_STATUSES:
        shards = (
            audit.get("shards")
            if isinstance(audit.get("shards"), Mapping)
            else None
        )
        shard_total = (
            shards.get("total")
            if isinstance(shards, Mapping)
            else None
        )
        shard_successful = (
            shards.get("successful")
            if isinstance(shards, Mapping)
            else None
        )
        shard_skipped = (
            shards.get("skipped")
            if isinstance(shards, Mapping)
            else None
        )
        shard_failed = (
            shards.get("failed")
            if isinstance(shards, Mapping)
            else None
        )
        if (
            not isinstance(shard_total, int)
            or isinstance(shard_total, bool)
            or shard_total <= 0
            or not isinstance(shard_successful, int)
            or isinstance(shard_successful, bool)
            or shard_successful != shard_total
            or not isinstance(shard_skipped, int)
            or isinstance(shard_skipped, bool)
            or shard_skipped < 0
            or shard_skipped > shard_successful
            or not isinstance(shard_failed, int)
            or isinstance(shard_failed, bool)
            or shard_failed != 0
            or shards.get("failures") != []
        ):
            return outer_status, observation
    return nested_status, observation


def _redacted_string(value: object, maximum: int = MAX_EVENT_STRING) -> str:
    text = str(value or "")
    if any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS):
        return "[redacted-sensitive-value]"
    return text[:maximum]


def sanitize_metadata(
    value: Any,
    *,
    depth: int = 0,
    item_budget: list[int] | None = None,
) -> Any:
    """Return bounded audit metadata without prompt bodies or common secrets."""
    if item_budget is None:
        item_budget = [MAX_EVENT_ITEMS]
    if depth > 8 or item_budget[0] <= 0:
        return "[truncated]"
    item_budget[0] -= 1
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redacted_string(value)
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
            if item_budget[0] <= 0:
                output["_truncated"] = True
                break
            key = _redacted_string(raw_key, 128)
            output[key] = (
                "[redacted-sensitive-field]"
                if SECRET_KEY_RE.search(key)
                else sanitize_metadata(
                    child,
                    depth=depth + 1,
                    item_budget=item_budget,
                )
            )
        return output
    if isinstance(value, Sequence) and not isinstance(
        value,
        (bytes, bytearray, memoryview),
    ):
        return [
            sanitize_metadata(item, depth=depth + 1, item_budget=item_budget)
            for item in list(value)[:MAX_EVENT_ITEMS]
            if item_budget[0] > 0
        ]
    return _redacted_string(value)


def bounded_metadata(value: Any) -> dict[str, Any]:
    sanitized = sanitize_metadata(value)
    if not isinstance(sanitized, dict):
        sanitized = {"value": sanitized}
    encoded = canonical_json(sanitized).encode("utf-8")
    if len(encoded) <= MAX_EVENT_PAYLOAD_BYTES:
        return sanitized
    return {
        "payload_omitted": True,
        "original_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def investigation_skill_selection_attestation(
    prompt_package: Mapping[str, Any],
) -> dict[str, Any]:
    """Project prompt skill selection into a bounded, content-free identity.

    Skill bodies and alert context remain in the prompt package digest.  This
    separate projection makes the exact registry and selected skill versions
    easy to attest without copying guidance, evidence, telemetry, or secrets
    into the audit event stream.
    """
    raw = prompt_package.get("investigation_skills")
    if raw is None:
        return {
            "registry_version": 0,
            "registry_sha256": "",
            "selected": [],
            "selected_count": 0,
            "truncated": False,
            "advisory_mode": INVESTIGATION_SKILL_UNAVAILABLE_MODE,
        }
    if not isinstance(raw, Mapping):
        raise HarnessIntegrityError(
            "investigation skill selection must be an object"
        )
    registry_version = raw.get("registry_version")
    if (
        not isinstance(registry_version, int)
        or isinstance(registry_version, bool)
        or registry_version < 0
    ):
        raise HarnessIntegrityError(
            "investigation skill registry version is invalid"
        )
    registry_sha256 = str(raw.get("registry_sha256") or "")
    if not DIGEST_RE.fullmatch(registry_sha256):
        raise HarnessIntegrityError(
            "investigation skill registry digest is invalid"
        )
    if (
        raw.get("mode") != "shadow"
        or raw.get("enforcement") != INVESTIGATION_SKILL_ADVISORY_MODE
    ):
        raise HarnessIntegrityError(
            "investigation skills must remain advisory-only in shadow mode"
        )
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
        identity = (skill_id, version)
        if identity in identities:
            raise HarnessIntegrityError(
                "selected investigation skill identities must be unique"
            )
        identities.add(identity)
        projected.append(
            {
                "id": skill_id,
                "version": version,
                "skill_sha256": skill_sha256,
            }
        )
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
    advisory_mode = INVESTIGATION_SKILL_ADVISORY_MODE
    if registry_version == 0:
        if projected or selected_count or truncated:
            raise HarnessIntegrityError(
                "unavailable investigation skill registry must be empty"
            )
        advisory_mode = INVESTIGATION_SKILL_UNAVAILABLE_MODE
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


def hypothesis_manifest_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    manifest = [
        {
            "hypothesis_id": str(row["hypothesis_id"]),
            "statement_digest": str(row["statement_digest"]),
            "status": str(row["status"]),
            "supporting_refs_json": str(row["supporting_refs_json"]),
            "contradicting_refs_json": str(row["contradicting_refs_json"]),
            "next_discriminator_digest": digest_json(
                str(row["next_discriminator"])
            ),
            "revision": int(row["revision"]),
        }
        for row in rows
    ]
    return digest_json(manifest)


LEDGER_TABLE_ORDERS: tuple[tuple[str, str], ...] = (
    ("harness_evidence", "evidence_ref"),
    ("harness_hypotheses", "hypothesis_id"),
    ("harness_decisions", "created_at, decision_id"),
    ("harness_model_calls", "created_at, call_id"),
    ("harness_tool_calls", "round_number, call_id"),
    (
        "harness_budget_reservations",
        "reservation_type, reservation_id",
    ),
)
RUN_IDENTITY_COLUMNS = (
    "run_id",
    "trace_id",
    "correlation_id",
    "case_id",
    "alert_id",
    "role",
    "task_kind",
    "assigned_route",
    "assigned_reviewer_route",
    "prompt_digest",
    "evidence_manifest_digest",
    "configuration_digest",
    "policy_version",
    "policy_digest",
    "policy_mode",
    "parent_run_id",
    "job_digest",
    "started_at",
)
LEGACY_RUN_IDENTITY_COLUMNS_V1 = tuple(
    column
    for column in RUN_IDENTITY_COLUMNS
    if column != "assigned_reviewer_route"
)
SUPPORTED_LEDGER_MANIFEST_SCHEMAS = frozenset(
    {LEDGER_MANIFEST_SCHEMA_V1, LEDGER_MANIFEST_SCHEMA}
)


def ledger_manifest(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    schema: str = LEDGER_MANIFEST_SCHEMA,
) -> dict[str, Any]:
    """Digest every non-event ledger at a terminal state.

    Table and ordering identifiers are closed constants above. Only the run ID
    is caller-controlled and it remains a bound SQL parameter.
    """
    if schema == LEDGER_MANIFEST_SCHEMA:
        run_identity_columns = RUN_IDENTITY_COLUMNS
    elif schema == LEDGER_MANIFEST_SCHEMA_V1:
        # Manifest v1 predates the separately bound reviewer assignment. Keep
        # this projection so a schema-v4 store can still verify terminal traces
        # produced before that column was added.
        run_identity_columns = LEGACY_RUN_IDENTITY_COLUMNS_V1
    else:
        raise HarnessIntegrityError(
            f"unsupported ledger manifest schema: {schema}"
        )
    tables: dict[str, dict[str, Any]] = {}
    run_identity = connection.execute(
        f"""
        SELECT {", ".join(run_identity_columns)}
        FROM harness_runs
        WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    run_identity_rows = [dict(run_identity)] if run_identity is not None else []
    tables["harness_run_identity"] = {
        "count": len(run_identity_rows),
        "sha256": digest_json(run_identity_rows),
    }
    for table, order_by in LEDGER_TABLE_ORDERS:
        rows = [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM {table} WHERE run_id = ? ORDER BY {order_by}",
                (run_id,),
            ).fetchall()
        ]
        tables[table] = {
            "count": len(rows),
            "sha256": digest_json(rows),
        }
    return {
        "schema": schema,
        "tables": tables,
    }


def approximate_evidence_rows(value: Any, *, depth: int = 0) -> int:
    """Conservatively count model-visible evidence records for budget checks."""
    if depth > 12:
        return 0
    if isinstance(value, Mapping):
        total = 0
        for raw_key, child in value.items():
            key = str(raw_key).strip().lower()
            if isinstance(child, list) and key in {
                "events",
                "hits",
                "parsed_evidence",
                "records",
                "results",
                "rows",
                "rows_preview",
                "samples",
            }:
                total += len(child)
                # Result containers can carry nested bounded result rows.
                if key == "results":
                    total += sum(
                        approximate_evidence_rows(item, depth=depth + 1)
                        for item in child
                    )
            else:
                total += approximate_evidence_rows(child, depth=depth + 1)
        return total
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        return sum(
            approximate_evidence_rows(item, depth=depth + 1)
            for item in value
        )
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


@dataclasses.dataclass(frozen=True)
class JobEnvelope:
    run_id: str
    trace_id: str
    correlation_id: str
    case_id: str
    alert_id: str
    role: str
    task_kind: str
    assigned_route: str
    assigned_reviewer_route: str
    prompt_digest: str
    evidence_manifest_digest: str
    configuration_digest: str
    skill_selection_attestation: dict[str, Any]
    parent_run_id: str
    created_at: str

    @classmethod
    def from_prompt(
        cls,
        *,
        run_id: str,
        prompt_package: Mapping[str, Any],
        role: str,
        assigned_route: str,
        configuration: Mapping[str, Any],
        reanalysis_attempt_id: str = "",
    ) -> "JobEnvelope":
        try:
            AgentRole(role)
        except ValueError as exc:
            raise HarnessPolicyError(f"unsupported agent role: {role}") from exc
        alert = (
            prompt_package.get("alert")
            if isinstance(prompt_package.get("alert"), dict)
            else {}
        )
        incident = (
            prompt_package.get("incident_response_evidence")
            if isinstance(prompt_package.get("incident_response_evidence"), dict)
            else {}
        )
        alert_id = str(alert.get("alert_id") or prompt_package.get("alert_id") or "")
        case_id = str(
            incident.get("case_id")
            or prompt_package.get("case_id")
            or alert_id
            or run_id
        )
        correlation_id = str(
            prompt_package.get("group_id")
            or (
                prompt_package.get("grouped_alert_context", {}).get("group_id")
                if isinstance(prompt_package.get("grouped_alert_context"), dict)
                else ""
            )
            or case_id
        )
        contract = prompt_package.get("evidence_reference_contract")
        if not isinstance(contract, dict):
            contract = {}
        task_kind = task_kind_for_role(
            role,
            reanalysis_attempt_id=reanalysis_attempt_id,
            manual_reanalysis=bool(prompt_package.get("manual_reanalysis")),
        )
        run_id = _valid_identifier(run_id, "run_id", 128)
        return cls(
            run_id=run_id,
            trace_id=hashlib.sha256(
                f"{HARNESS_SCHEMA}:{run_id}".encode("utf-8")
            ).hexdigest()[:32],
            correlation_id=_valid_identifier(
                correlation_id or run_id,
                "correlation_id",
            ),
            case_id=_valid_identifier(case_id or run_id, "case_id"),
            alert_id=(
                _valid_identifier(alert_id, "alert_id") if alert_id else ""
            ),
            role=role,
            task_kind=task_kind,
            assigned_route=_model_route(
                assigned_route,
                "assigned primary route",
            ),
            assigned_reviewer_route=_model_route(
                configuration.get("reviewer_route"),
                "assigned reviewer route",
                allow_empty=True,
            ),
            prompt_digest=digest_json(prompt_package),
            evidence_manifest_digest=digest_json(contract),
            configuration_digest=digest_json(configuration),
            skill_selection_attestation=(
                investigation_skill_selection_attestation(prompt_package)
            ),
            parent_run_id=str(
                prompt_package.get("parent_analysis_id")
                or prompt_package.get("prior_analysis_id")
                or ""
            )[:128],
            created_at=utc_now(),
        )

    @property
    def job_digest(self) -> str:
        value = dataclasses.asdict(self)
        value.pop("created_at", None)
        return digest_json(value)


def _secure_sqlite_files(path: Path) -> None:
    for candidate in (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
    ):
        if candidate.exists() and not candidate.is_symlink():
            os.chmod(candidate, stat.S_IRUSR | stat.S_IWUSR)


def _probe_existing_schema_version(path: Path) -> int | None:
    """Inspect an existing database without changing its journal or sidecars."""
    if path.is_symlink():
        raise HarnessIntegrityError("harness database must not be a symlink")
    if not path.exists():
        return None
    if not path.is_file():
        raise HarnessIntegrityError("harness database must be a regular file")
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise HarnessIntegrityError(
            "harness database could not be inspected safely"
        ) from exc
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        has_metadata = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'harness_metadata'
            """
        ).fetchone()
        if has_metadata is None:
            return None
        row = connection.execute(
            """
            SELECT value
            FROM harness_metadata
            WHERE key = 'schema_version'
            """
        ).fetchone()
        if row is None:
            return None
        try:
            return int(row["value"])
        except (TypeError, ValueError) as exc:
            raise HarnessIntegrityError(
                "harness database schema version is invalid"
            ) from exc
    except sqlite3.Error as exc:
        raise HarnessIntegrityError(
            "harness database schema could not be read"
        ) from exc
    finally:
        connection.close()


@contextlib.contextmanager
def _connect(path: Path) -> Iterable[sqlite3.Connection]:
    if path.is_symlink():
        raise HarnessIntegrityError("harness database must not be a symlink")
    if path.exists() and not path.is_file():
        raise HarnessIntegrityError("harness database must be a regular file")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    new_database = not path.exists()
    connection = sqlite3.connect(path, timeout=30.0)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        if new_database:
            # This must be selected before any tables or WAL state exist.
            connection.execute("PRAGMA auto_vacuum = INCREMENTAL")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        _secure_sqlite_files(path)
        with connection:
            yield connection
    finally:
        connection.close()
        _secure_sqlite_files(path)


class HarnessStore:
    """Owner-only SQLite event store with per-run hash chains."""

    def __init__(
        self,
        path: Path = DEFAULT_DB_PATH,
        *,
        log_path: Path | None = None,
    ):
        self.path = path.expanduser()
        resolved_default = DEFAULT_DB_PATH.expanduser()
        selected_log_path = (
            log_path.expanduser()
            if log_path is not None
            else (
                DEFAULT_HARNESS_LOG_PATH
                if self.path == resolved_default
                else self.path.with_suffix(".events.jsonl")
            )
        )
        self.logger = SecurityJsonlLogger(
            selected_log_path,
            service="onion-sentinel-investigation-harness",
        )
        existing_version = _probe_existing_schema_version(self.path)
        if (
            existing_version is not None
            and existing_version > SQL_SCHEMA_VERSION
        ):
            raise HarnessIntegrityError(
                "harness database was created by a newer runtime"
            )
        self.initialize()
        self.logger.log(
            "info",
            "harness.store.ready",
            database_path=str(self.path),
            schema=HARNESS_SCHEMA,
            schema_version=SQL_SCHEMA_VERSION,
        )

    def _audit_event(self, event: Mapping[str, Any]) -> None:
        """Mirror committed event metadata without duplicating evidence."""
        try:
            with _connect(self.path) as connection:
                run = connection.execute(
                    """
                    SELECT correlation_id, case_id, alert_id, role, task_kind,
                           assigned_route, assigned_reviewer_route, status
                    FROM harness_runs WHERE run_id = ?
                    """,
                    (str(event.get("run_id") or ""),),
                ).fetchone()
            identity = dict(run) if run is not None else {}
            self.logger.log(
                "error"
                if str(event.get("event_type") or "") == "run.failed"
                else "info",
                "harness.event",
                run_id=str(event.get("run_id") or ""),
                trace_sequence=int(event.get("sequence") or 0),
                harness_event_type=str(event.get("event_type") or ""),
                stage=str(event.get("stage") or ""),
                event_id=str(event.get("event_id") or ""),
                event_created_at=str(event.get("created_at") or ""),
                event_sha256=str(event.get("event_sha256") or ""),
                payload_sha256=str(event.get("payload_sha256") or ""),
                **identity,
            )
        except Exception:
            # SQLite remains the authoritative hash-chained audit ledger.
            # Troubleshooting log failure must not invalidate committed work.
            return

    def initialize(self) -> None:
        with _connect(self.path) as connection:
            has_metadata = connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'harness_metadata'
                """
            ).fetchone()
            if has_metadata is not None:
                version_row = connection.execute(
                    """
                    SELECT value
                    FROM harness_metadata
                    WHERE key = 'schema_version'
                    """
                ).fetchone()
                if version_row is not None:
                    try:
                        existing_version = int(version_row["value"])
                    except (TypeError, ValueError) as exc:
                        raise HarnessIntegrityError(
                            "harness database schema version is invalid"
                        ) from exc
                    if existing_version > SQL_SCHEMA_VERSION:
                        raise HarnessIntegrityError(
                            "harness database was created by a newer runtime"
                        )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS harness_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS harness_runs (
                    run_id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL UNIQUE,
                    correlation_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    task_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    assigned_route TEXT NOT NULL,
                    assigned_reviewer_route TEXT NOT NULL DEFAULT '',
                    active_route TEXT NOT NULL DEFAULT '',
                    prompt_digest TEXT NOT NULL,
                    evidence_manifest_digest TEXT NOT NULL,
                    configuration_digest TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    policy_mode TEXT NOT NULL,
                    parent_run_id TEXT NOT NULL,
                    job_digest TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    terminal_reason TEXT NOT NULL DEFAULT '',
                    summary_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_harness_runs_case
                    ON harness_runs(case_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_harness_runs_status
                    ON harness_runs(status, updated_at);

                CREATE TABLE IF NOT EXISTS harness_events (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_event_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    PRIMARY KEY (run_id, sequence),
                    UNIQUE (run_id, event_id),
                    UNIQUE (run_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS harness_evidence (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    evidence_ref TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_class TEXT NOT NULL,
                    trust_tier TEXT NOT NULL,
                    corroborating INTEGER NOT NULL CHECK(corroborating IN (0, 1)),
                    status TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, evidence_ref)
                );

                CREATE TABLE IF NOT EXISTS harness_hypotheses (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    hypothesis_id TEXT NOT NULL,
                    statement TEXT NOT NULL,
                    statement_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    supporting_refs_json TEXT NOT NULL,
                    contradicting_refs_json TEXT NOT NULL,
                    next_discriminator TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, hypothesis_id)
                );

                CREATE TABLE IF NOT EXISTS harness_decisions (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    decision_id TEXT NOT NULL,
                    decision_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    confidence_score REAL,
                    evidence_refs_json TEXT NOT NULL,
                    rationale_digest TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, decision_id)
                );

                CREATE TABLE IF NOT EXISTS harness_model_calls (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    call_id TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    requested_route TEXT NOT NULL,
                    observed_model TEXT NOT NULL,
                    observed_model_path TEXT NOT NULL,
                    observed_provider TEXT NOT NULL,
                    observed_harness TEXT NOT NULL,
                    independent_review INTEGER NOT NULL
                        CHECK(independent_review IN (0, 1)),
                    status TEXT NOT NULL,
                    input_digest TEXT NOT NULL,
                    output_digest TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, call_id)
                );

                CREATE TABLE IF NOT EXISTS harness_tool_calls (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    call_id TEXT NOT NULL,
                    round_number INTEGER NOT NULL,
                    backend TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    read_only INTEGER NOT NULL CHECK(read_only IN (0, 1)),
                    coverage TEXT NOT NULL,
                    truncated INTEGER NOT NULL CHECK(truncated IN (0, 1)),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, call_id)
                );

                CREATE TABLE IF NOT EXISTS harness_budget_reservations (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    reservation_type TEXT NOT NULL,
                    reservation_id TEXT NOT NULL,
                    amount INTEGER NOT NULL CHECK(amount >= 0),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, reservation_type, reservation_id)
                );
                """
            )
            run_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(harness_runs)"
                ).fetchall()
            }
            if "policy_digest" not in run_columns:
                connection.execute(
                    """
                    ALTER TABLE harness_runs
                    ADD COLUMN policy_digest TEXT NOT NULL DEFAULT ''
                    """
                )
            if "assigned_reviewer_route" not in run_columns:
                connection.execute(
                    """
                    ALTER TABLE harness_runs
                    ADD COLUMN assigned_reviewer_route TEXT NOT NULL DEFAULT ''
                    """
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO harness_budget_reservations(
                    run_id, reservation_type, reservation_id, amount, created_at
                )
                SELECT run_id, 'model-call', call_id, 1, created_at
                FROM harness_model_calls
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO harness_budget_reservations(
                    run_id, reservation_type, reservation_id, amount, created_at
                )
                SELECT run_id, 'query-round', CAST(round_number AS TEXT),
                       SUM(
                         CASE
                           WHEN lower(status) IN (
                             'rejected', 'denied', 'blocked',
                             'unauthorized', 'forbidden'
                           ) THEN 0
                           ELSE 1
                         END
                       ),
                       MIN(created_at)
                FROM harness_tool_calls
                GROUP BY run_id, round_number
                """
            )
            connection.execute(
                """
                INSERT INTO harness_metadata(key, value)
                VALUES('schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(SQL_SCHEMA_VERSION),),
            )
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def _append_event_tx(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        stage: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        payload_value = bounded_metadata(payload)
        payload_json = canonical_json(payload_value)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        existing = connection.execute(
            """
            SELECT * FROM harness_events
            WHERE run_id = ? AND idempotency_key = ?
            """,
            (run_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            if (
                existing["event_type"] != event_type
                or existing["stage"] != stage
                or existing["payload_sha256"] != payload_sha256
            ):
                raise HarnessIntegrityError(
                    "idempotency key was reused with different event content"
                )
            return dict(existing)
        previous = connection.execute(
            """
            SELECT sequence, event_sha256
            FROM harness_events
            WHERE run_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = str(previous["event_sha256"]) if previous else "0" * 64
        created_at = created_at or utc_now()
        body = {
            "run_id": run_id,
            "sequence": sequence,
            "idempotency_key": idempotency_key,
            "event_type": event_type,
            "stage": stage,
            "created_at": created_at,
            "payload_sha256": payload_sha256,
            "previous_event_sha256": previous_hash,
        }
        event_sha256 = digest_json(body)
        event_id = f"evt-{event_sha256[:32]}"
        connection.execute(
            """
            INSERT INTO harness_events(
                run_id, sequence, event_id, idempotency_key, event_type,
                stage, created_at, payload_json, payload_sha256,
                previous_event_sha256, event_sha256
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                sequence,
                event_id,
                idempotency_key,
                event_type,
                stage,
                created_at,
                payload_json,
                payload_sha256,
                previous_hash,
                event_sha256,
            ),
        )
        return {
            **body,
            "event_id": event_id,
            "payload_json": payload_json,
            "event_sha256": event_sha256,
        }

    @staticmethod
    def _require_mutable_run_tx(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> sqlite3.Row:
        run = connection.execute(
            "SELECT status FROM harness_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run is None:
            raise HarnessIntegrityError("unknown harness run")
        if run["status"] not in {
            RunStatus.RUNNING.value,
            RunStatus.WAITING_FOR_REVIEW.value,
        }:
            raise HarnessIntegrityError("terminal harness run is immutable")
        return run

    @staticmethod
    def _update_run_stage_tx(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        stage: str,
        updated_at: str,
        active_route: str | None = None,
    ) -> None:
        if active_route is None:
            cursor = connection.execute(
                """
                UPDATE harness_runs
                SET stage = ?, updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND status IN (?, ?)
                """,
                (
                    stage,
                    updated_at,
                    run_id,
                    RunStatus.RUNNING.value,
                    RunStatus.WAITING_FOR_REVIEW.value,
                ),
            )
        else:
            cursor = connection.execute(
                """
                UPDATE harness_runs
                SET stage = ?, active_route = ?, updated_at = ?,
                    revision = revision + 1
                WHERE run_id = ? AND status IN (?, ?)
                """,
                (
                    stage,
                    active_route[:256],
                    updated_at,
                    run_id,
                    RunStatus.RUNNING.value,
                    RunStatus.WAITING_FOR_REVIEW.value,
                ),
            )
        if cursor.rowcount != 1:
            raise HarnessIntegrityError(
                "unknown or terminal harness run cannot advance"
            )

    def start_run(
        self,
        envelope: JobEnvelope,
        policy: HarnessPolicy,
    ) -> dict[str, Any]:
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM harness_runs WHERE run_id = ?",
                (envelope.run_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["job_digest"] != envelope.job_digest
                    or existing["policy_digest"] != policy.digest
                ):
                    raise HarnessIntegrityError(
                        "run_id collides with a different job or policy"
                    )
                connection.commit()
                return dict(existing)
            connection.execute(
                """
                INSERT INTO harness_runs(
                    run_id, trace_id, correlation_id, case_id, alert_id, role,
                    task_kind, status, stage, assigned_route,
                    assigned_reviewer_route, prompt_digest,
                    evidence_manifest_digest, configuration_digest,
                    policy_version, policy_digest, policy_mode, parent_run_id,
                    job_digest, started_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.run_id,
                    envelope.trace_id,
                    envelope.correlation_id,
                    envelope.case_id,
                    envelope.alert_id,
                    envelope.role,
                    envelope.task_kind,
                    RunStatus.RUNNING.value,
                    Stage.INTAKE.value,
                    envelope.assigned_route,
                    envelope.assigned_reviewer_route,
                    envelope.prompt_digest,
                    envelope.evidence_manifest_digest,
                    envelope.configuration_digest,
                    policy.version,
                    policy.digest,
                    policy.mode,
                    envelope.parent_run_id,
                    envelope.job_digest,
                    envelope.created_at,
                    envelope.created_at,
                ),
            )
            event = self._append_event_tx(
                connection,
                run_id=envelope.run_id,
                event_type="run.started",
                stage=Stage.INTAKE.value,
                payload={
                    "schema": HARNESS_SCHEMA,
                    "trace_id": envelope.trace_id,
                    "correlation_id": envelope.correlation_id,
                    "case_id": envelope.case_id,
                    "alert_id": envelope.alert_id,
                    "role": envelope.role,
                    "task_kind": envelope.task_kind,
                    "assigned_route": envelope.assigned_route,
                    "assigned_reviewer_route": (
                        envelope.assigned_reviewer_route
                    ),
                    "prompt_digest": envelope.prompt_digest,
                    "evidence_manifest_digest": envelope.evidence_manifest_digest,
                    "configuration_digest": envelope.configuration_digest,
                    "skill_selection_attestation": (
                        envelope.skill_selection_attestation
                    ),
                    "job_digest": envelope.job_digest,
                    "policy_version": policy.version,
                    "policy_digest": policy.digest,
                    "policy_mode": policy.mode,
                },
                idempotency_key="run.started",
                created_at=envelope.created_at,
            )
            connection.commit()
        self._audit_event(event)
        return self.snapshot(envelope.run_id)

    def append_event(
        self,
        run_id: str,
        event_type: str,
        stage: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        try:
            Stage(stage)
        except ValueError as exc:
            raise HarnessPolicyError(f"unknown harness stage: {stage}") from exc
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type=event_type,
                stage=stage,
                payload=payload,
                idempotency_key=idempotency_key,
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=stage,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)
        return event

    def reserve_budget_operation(
        self,
        run_id: str,
        *,
        reservation_type: str,
        reservation_id: str,
        amount: int,
        max_total: int,
        max_operations: int,
        enforce: bool,
        preexisting_violations: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Atomically reserve bounded work before a model or broker executes."""
        if reservation_type not in {"model-call", "query-round"}:
            raise HarnessPolicyError("unknown budget reservation type")
        reservation_id = _valid_identifier(
            reservation_id,
            "budget reservation_id",
            128,
        )
        amount = max(0, int(amount))
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            existing = connection.execute(
                """
                SELECT amount
                FROM harness_budget_reservations
                WHERE run_id = ? AND reservation_type = ?
                  AND reservation_id = ?
                """,
                (run_id, reservation_type, reservation_id),
            ).fetchone()
            totals = connection.execute(
                """
                SELECT COUNT(*) operation_count, COALESCE(SUM(amount), 0) total
                FROM harness_budget_reservations
                WHERE run_id = ? AND reservation_type = ?
                """,
                (run_id, reservation_type),
            ).fetchone()
            if existing is not None:
                if int(existing["amount"]) != amount:
                    raise HarnessIntegrityError(
                        "budget reservation collides with different amount"
                    )
                connection.commit()
                return {
                    "reserved": True,
                    "existing": True,
                    "operation_count": int(totals["operation_count"]),
                    "total": int(totals["total"]),
                    "violations": sorted(set(preexisting_violations)),
                }
            proposed_operations = int(totals["operation_count"]) + 1
            proposed_total = int(totals["total"]) + amount
            violations = list(preexisting_violations)
            if proposed_operations > int(max_operations):
                violations.append(
                    "max_model_calls"
                    if reservation_type == "model-call"
                    else "max_query_rounds"
                )
            if proposed_total > int(max_total):
                violations.append(
                    "max_model_calls"
                    if reservation_type == "model-call"
                    else "max_queries_total"
                )
            reserved = not violations or not enforce
            if reserved:
                connection.execute(
                    """
                    INSERT INTO harness_budget_reservations(
                        run_id, reservation_type, reservation_id,
                        amount, created_at
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        reservation_type,
                        reservation_id,
                        amount,
                        utc_now(),
                    ),
                )
            connection.commit()
        return {
            "reserved": reserved,
            "existing": False,
            "operation_count": proposed_operations,
            "total": proposed_total,
            "violations": sorted(set(violations)),
        }

    def transition(
        self,
        run_id: str,
        stage: str,
        *,
        route: str = "",
        reason: str = "",
        ordinal: int = 0,
    ) -> dict[str, Any]:
        try:
            Stage(stage)
        except ValueError as exc:
            raise HarnessPolicyError(f"unknown harness stage: {stage}") from exc
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = connection.execute(
                "SELECT status, active_route FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            if run["status"] not in {
                RunStatus.RUNNING.value,
                RunStatus.WAITING_FOR_REVIEW.value,
            }:
                raise HarnessIntegrityError(
                    "cannot transition a terminal harness run"
                )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="run.stage",
                stage=stage,
                payload={
                    "active_route": route[:256],
                    "reason": reason[:500],
                },
                idempotency_key=f"stage:{stage}:{ordinal}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=stage,
                updated_at=event["created_at"],
                active_route=(
                    route[:256] if route else str(run["active_route"])
                ),
            )
            connection.commit()
        self._audit_event(event)
        return event

    def register_evidence(
        self,
        run_id: str,
        *,
        evidence_ref: str,
        source: str,
        source_class: str,
        trust_tier: str,
        corroborating: bool,
        status: str = "",
        evidence_digest: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        evidence_ref = str(evidence_ref or "").strip()[:512]
        if not evidence_ref:
            raise HarnessIntegrityError("evidence reference is required")
        try:
            TrustTier(trust_tier)
        except ValueError as exc:
            raise HarnessIntegrityError("unknown evidence trust tier") from exc
        digest = _digest_or_hash(evidence_digest or {
            "ref": evidence_ref,
            "source": source,
            "source_class": source_class,
            "status": status,
            "metadata": metadata or {},
        })
        metadata_json = canonical_json(bounded_metadata(metadata or {}))
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            existing = connection.execute(
                """
                SELECT evidence_digest FROM harness_evidence
                WHERE run_id = ? AND evidence_ref = ?
                """,
                (run_id, evidence_ref),
            ).fetchone()
            if existing is not None:
                if existing["evidence_digest"] != digest:
                    raise HarnessIntegrityError(
                        "immutable evidence reference collides with different content"
                    )
                connection.commit()
                return
            connection.execute(
                """
                INSERT INTO harness_evidence(
                    run_id, evidence_ref, source, source_class, trust_tier,
                    corroborating, status, evidence_digest, observed_at,
                    metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    evidence_ref,
                    str(source or "")[:160],
                    str(source_class or "unknown")[:160],
                    trust_tier,
                    1 if corroborating else 0,
                    str(status or "")[:64],
                    digest,
                    utc_now(),
                    metadata_json,
                ),
            )
            connection.commit()

    def register_evidence_contract(
        self,
        run_id: str,
        contract: Mapping[str, Any] | None,
    ) -> int:
        references = (
            contract.get("references")
            if isinstance(contract, Mapping)
            else None
        )
        if not isinstance(references, list):
            return 0
        count = 0
        for item in references[:MAX_EVIDENCE_REFS]:
            if not isinstance(item, dict) or not item.get("ref"):
                continue
            source = str(item.get("source") or "unknown")
            source_class = str(item.get("source_class") or source)
            trust = (
                TrustTier.MEMORY_LEAD.value
                if source_class in {"agent_memory", "shared_memory", "memory"}
                else TrustTier.EXTERNAL_INTELLIGENCE.value
                if source_class == "public_enrichment"
                else TrustTier.TRUSTED_COLLECTOR.value
            )
            self.register_evidence(
                run_id,
                evidence_ref=str(item["ref"]),
                source=source,
                source_class=source_class,
                trust_tier=trust,
                corroborating=item.get("corroborating") is True,
                status=str(item.get("status") or ""),
                evidence_digest=str(item.get("evidence_digest") or ""),
                metadata={"returned": item.get("returned")},
            )
            count += 1
        manifest_digest = digest_json(contract or {})
        self.append_event(
            run_id,
            "evidence.catalogued",
            Stage.CONTEXT_ASSEMBLY.value,
            {
                "contract_schema": str(
                    (contract or {}).get("schema") if isinstance(contract, Mapping) else ""
                ),
                "references_registered": count,
                "manifest_digest": manifest_digest,
            },
            idempotency_key=f"evidence.catalogued:{manifest_digest[:24]}",
        )
        return count

    def record_hypotheses(
        self,
        run_id: str,
        hypotheses: Any,
        *,
        revision: int,
    ) -> dict[str, int]:
        if not isinstance(hypotheses, list):
            return {"accepted": 0, "rejected": 0}
        accepted = 0
        rejected = 0
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            known_refs = {
                str(row["evidence_ref"])
                for row in connection.execute(
                    "SELECT evidence_ref FROM harness_evidence WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
            }
            for index, item in enumerate(hypotheses[:MAX_HYPOTHESES], 1):
                if not isinstance(item, dict):
                    rejected += 1
                    continue
                hypothesis_id = re.sub(
                    r"[^A-Za-z0-9._-]+",
                    "-",
                    str(item.get("id") or f"hypothesis-{index}"),
                ).strip("-")[:64]
                statement = _redacted_string(
                    str(item.get("statement") or "").strip(),
                    4_000,
                )
                status = str(item.get("status") or "unresolved").strip().lower()
                if (
                    not hypothesis_id
                    or not statement
                    or status not in {"supported", "contradicted", "unresolved"}
                ):
                    rejected += 1
                    continue
                supporting = [
                    str(ref)[:512]
                    for ref in (
                        item.get("supporting_evidence")
                        if isinstance(item.get("supporting_evidence"), list)
                        else []
                    )[:MAX_DECISION_EVIDENCE_REFS]
                    if str(ref) in known_refs
                ]
                contradicting = [
                    str(ref)[:512]
                    for ref in (
                        item.get("contradicting_evidence")
                        if isinstance(item.get("contradicting_evidence"), list)
                        else []
                    )[:MAX_DECISION_EVIDENCE_REFS]
                    if str(ref) in known_refs
                ]
                # A model may leave a hypothesis unresolved without citations,
                # but supported/contradicted states require matching provenance.
                if (
                    status == "supported"
                    and not supporting
                    or status == "contradicted"
                    and not contradicting
                ):
                    status = "unresolved"
                supporting_json = canonical_json(supporting)
                contradicting_json = canonical_json(contradicting)
                next_discriminator = _redacted_string(
                    item.get("next_discriminator"),
                    2_000,
                )
                statement_digest = digest_json(statement)
                normalized_revision = max(0, int(revision))
                existing = connection.execute(
                    """
                    SELECT statement_digest, status, supporting_refs_json,
                           contradicting_refs_json, next_discriminator, revision
                    FROM harness_hypotheses
                    WHERE run_id = ? AND hypothesis_id = ?
                    """,
                    (run_id, hypothesis_id),
                ).fetchone()
                content = (
                    statement_digest,
                    status,
                    supporting_json,
                    contradicting_json,
                    next_discriminator,
                )
                if existing is not None:
                    existing_content = tuple(existing)[:5]
                    existing_revision = int(existing["revision"])
                    if normalized_revision < existing_revision:
                        raise HarnessIntegrityError(
                            "hypothesis revision cannot move backwards"
                        )
                    if (
                        normalized_revision == existing_revision
                        and content != existing_content
                    ):
                        raise HarnessIntegrityError(
                            "hypothesis revision collides with different content"
                        )
                connection.execute(
                    """
                    INSERT INTO harness_hypotheses(
                        run_id, hypothesis_id, statement, statement_digest,
                        status, supporting_refs_json, contradicting_refs_json,
                        next_discriminator, revision, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id, hypothesis_id) DO UPDATE SET
                        statement = excluded.statement,
                        statement_digest = excluded.statement_digest,
                        status = excluded.status,
                        supporting_refs_json = excluded.supporting_refs_json,
                        contradicting_refs_json = excluded.contradicting_refs_json,
                        next_discriminator = excluded.next_discriminator,
                        revision = excluded.revision,
                        updated_at = excluded.updated_at
                    WHERE excluded.revision > harness_hypotheses.revision
                    """,
                    (
                        run_id,
                        hypothesis_id,
                        statement,
                        statement_digest,
                        status,
                        supporting_json,
                        contradicting_json,
                        next_discriminator,
                        normalized_revision,
                        utc_now(),
                    ),
                )
                accepted += 1
            manifest_digest = hypothesis_manifest_digest(
                connection.execute(
                    """
                    SELECT hypothesis_id, statement_digest, status,
                           supporting_refs_json, contradicting_refs_json,
                           next_discriminator, revision
                    FROM harness_hypotheses
                    WHERE run_id = ?
                    ORDER BY hypothesis_id
                    """,
                    (run_id,),
                ).fetchall()
            )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="hypotheses.updated",
                stage=Stage.EVIDENCE_SYNTHESIS.value,
                payload={
                    "accepted": accepted,
                    "rejected": rejected,
                    "revision": revision,
                    "manifest_digest": manifest_digest,
                },
                idempotency_key=f"hypotheses:{revision}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=Stage.EVIDENCE_SYNTHESIS.value,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)
        return {"accepted": accepted, "rejected": rejected}

    def record_decision(
        self,
        run_id: str,
        *,
        decision_id: str,
        decision_type: str,
        response: Mapping[str, Any],
        stage: str = Stage.EVIDENCE_SYNTHESIS.value,
    ) -> None:
        try:
            Stage(stage)
        except ValueError as exc:
            raise HarnessPolicyError("invalid decision stage") from exc
        evidence_refs = [
            str(item)[:512]
            for item in (
                response.get("evidence_used")
                if isinstance(response.get("evidence_used"), list)
                else []
            )[:MAX_DECISION_EVIDENCE_REFS]
        ]
        rationale = " ".join(
            str(response.get(key) or "")
            for key in (
                "executive_summary",
                "detection_outcome_reasoning",
                "tuning_reason",
            )
        )[:12_000]
        try:
            confidence_score = float(response.get("confidence_score"))
            if not 0.0 <= confidence_score <= 1.0:
                confidence_score = None
        except (TypeError, ValueError, OverflowError):
            confidence_score = None
        payload = bounded_metadata(
            {
                **{
                    key: response.get(key)
                    for key in (
                        "event_status",
                        "detection_validity",
                        "activity_disposition",
                        "handling",
                        "duplicate_of",
                        "detection_outcome",
                        "confidence",
                        "confidence_score",
                        "escalation_needed",
                        "final_disposition_status",
                        "tuning_recommendation",
                    )
                },
                # Keep the selected fields queryable while binding this ledger
                # row to the exact canonical response supplied at this stage.
                "response_digest": digest_json(response),
            }
        )
        decision_id = _valid_identifier(decision_id, "decision_id", 128)
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT payload_json, evidence_refs_json, rationale_digest
                FROM harness_decisions
                WHERE run_id = ? AND decision_id = ?
                """,
                (run_id, decision_id),
            ).fetchone()
            values = (
                canonical_json(payload),
                canonical_json(evidence_refs),
                digest_json(rationale),
            )
            if existing is not None:
                if tuple(existing) != values:
                    raise HarnessIntegrityError(
                        "decision_id collides with different decision content"
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO harness_decisions(
                        run_id, decision_id, decision_type, status, outcome,
                        confidence_score, evidence_refs_json, rationale_digest,
                        payload_json, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        decision_id,
                        str(decision_type or "")[:80],
                        str(response.get("final_disposition_status") or "")[:80],
                        str(response.get("detection_outcome") or "")[:80],
                        confidence_score,
                        values[1],
                        values[2],
                        values[0],
                        utc_now(),
                    ),
                )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="decision.recorded",
                stage=stage,
                payload={
                    "decision_id": decision_id,
                    "decision_type": decision_type,
                    "outcome": response.get("detection_outcome"),
                    "confidence_score": confidence_score,
                    "evidence_ref_count": len(evidence_refs),
                    "rationale_digest": values[2],
                    "response_digest": payload["response_digest"],
                },
                idempotency_key=f"decision:{decision_id}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=stage,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)

    def record_model_call(
        self,
        run_id: str,
        *,
        call_id: str,
        purpose: str,
        requested_route: str,
        response: Mapping[str, Any],
        independent_review: bool,
        input_digest: str,
        duration_ms: int,
        status: str = "completed",
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        output_digest = digest_json(response)
        values = (
            _redacted_string(purpose, 160),
            str(requested_route or "")[:256],
            str(response.get("_analysis_model") or "")[:256],
            str(response.get("_analysis_model_path") or "")[:80],
            str(response.get("_analysis_provider") or "")[:80],
            str(response.get("_analysis_harness") or "")[:80],
            1 if independent_review else 0,
            str(status or "")[:80],
            _digest_or_hash(input_digest),
            output_digest,
            max(0, int(duration_ms)),
            utc_now(),
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT purpose, requested_route, observed_model,
                       observed_model_path, observed_provider,
                       observed_harness, independent_review, status,
                       input_digest, output_digest, duration_ms, created_at
                FROM harness_model_calls
                WHERE run_id = ? AND call_id = ?
                """,
                (run_id, call_id),
            ).fetchone()
            if existing is not None:
                # Wall-clock duration and creation time are observational. The
                # immutable input/output identities are the collision boundary.
                if tuple(existing)[:10] != values[:10]:
                    raise HarnessIntegrityError(
                        "model call_id collides with different call content"
                    )
                event_duration_ms = int(existing["duration_ms"])
            else:
                connection.execute(
                    """
                    INSERT INTO harness_model_calls(
                        run_id, call_id, purpose, requested_route,
                        observed_model, observed_model_path, observed_provider,
                        observed_harness, independent_review, status,
                        input_digest, output_digest, duration_ms, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (run_id, call_id, *values),
                )
                event_duration_ms = values[10]
            model_stage = (
                Stage.INDEPENDENT_REVIEW.value
                if independent_review
                else Stage.PRIMARY_ANALYSIS.value
            )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="model.completed",
                stage=model_stage,
                payload={
                    "call_id": call_id,
                    "purpose": purpose,
                    "requested_route": requested_route,
                    "observed_model": response.get("_analysis_model"),
                    "observed_model_path": response.get(
                        "_analysis_model_path"
                    ),
                    "observed_provider": response.get("_analysis_provider"),
                    "observed_harness": response.get("_analysis_harness"),
                    "independent_review": independent_review,
                    "input_digest": values[8],
                    "output_digest": output_digest,
                    "duration_ms": event_duration_ms,
                    "status": status,
                },
                idempotency_key=f"model.completed:{call_id}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=model_stage,
                updated_at=event["created_at"],
                active_route=str(requested_route or ""),
            )
            connection.commit()
        self._audit_event(event)

    def record_tool_call(
        self,
        run_id: str,
        *,
        call_id: str,
        round_number: int,
        backend: str,
        capability: str,
        purpose: str,
        request_digest: str,
        result_digest: str,
        status: str,
        read_only: bool,
        coverage: str,
        truncated: bool,
    ) -> None:
        call_id = _valid_identifier(call_id, "tool call_id", 128)
        values = (
            max(0, int(round_number)),
            str(backend or "")[:80],
            str(capability or "")[:120],
            _redacted_string(purpose, 500),
            _digest_or_hash(request_digest),
            _digest_or_hash(result_digest),
            str(status or "")[:80],
            1 if read_only else 0,
            str(coverage or "unknown")[:80],
            1 if truncated else 0,
            utc_now(),
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT round_number, backend, capability, purpose,
                       request_digest, result_digest, status, read_only,
                       coverage, truncated, created_at
                FROM harness_tool_calls
                WHERE run_id = ? AND call_id = ?
                """,
                (run_id, call_id),
            ).fetchone()
            if existing is not None:
                if tuple(existing)[:10] != values[:10]:
                    raise HarnessIntegrityError(
                        "tool call_id collides with different call content"
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO harness_tool_calls(
                        run_id, call_id, round_number, backend, capability,
                        purpose, request_digest, result_digest, status,
                        read_only, coverage, truncated, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (run_id, call_id, *values),
                )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="tool.completed",
                stage=Stage.QUERY_EXECUTION.value,
                payload={
                    "call_id": call_id,
                    "round": values[0],
                    "backend": values[1],
                    "capability": values[2],
                    "request_digest": values[4],
                    "result_digest": values[5],
                    "status": values[6],
                    "read_only": bool(values[7]),
                    "coverage": values[8],
                    "truncated": bool(values[9]),
                },
                idempotency_key=f"tool.completed:{call_id}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=Stage.QUERY_EXECUTION.value,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)

    def finish(
        self,
        run_id: str,
        *,
        status: str,
        reason: str = "",
        summary: Mapping[str, Any] | None = None,
    ) -> None:
        if status not in {
            RunStatus.SUCCEEDED.value,
            RunStatus.FAILED.value,
            RunStatus.CANCELLED.value,
            RunStatus.WAITING_FOR_REVIEW.value,
        }:
            raise HarnessPolicyError("invalid terminal run status")
        stage = (
            Stage.COMPLETE.value
            if status == RunStatus.SUCCEEDED.value
            else Stage.HUMAN_REVIEW.value
            if status == RunStatus.WAITING_FOR_REVIEW.value
            else Stage.FAILED.value
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT status FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if current is None:
                raise HarnessIntegrityError("unknown harness run")
            if current["status"] not in {
                RunStatus.RUNNING.value,
                RunStatus.WAITING_FOR_REVIEW.value,
                status,
            }:
                raise HarnessIntegrityError("run already has a different terminal status")
            reason_digest = digest_json(str(reason or ""))
            terminal_reason = (
                f"sha256:{reason_digest}" if str(reason or "") else ""
            )
            terminal_ledger_manifest = (
                ledger_manifest(connection, run_id)
                if status
                in {
                    RunStatus.SUCCEEDED.value,
                    RunStatus.FAILED.value,
                    RunStatus.CANCELLED.value,
                }
                else None
            )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type=f"run.{status}",
                stage=stage,
                payload={
                    "reason_present": bool(str(reason or "")),
                    "reason_digest": reason_digest,
                    "summary": summary or {},
                    **(
                        {"ledger_manifest": terminal_ledger_manifest}
                        if terminal_ledger_manifest is not None
                        else {}
                    ),
                },
                idempotency_key=f"run.terminal:{status}",
            )
            connection.execute(
                """
                UPDATE harness_runs
                SET status = ?, stage = ?, completed_at = ?, updated_at = ?,
                    terminal_reason = ?, summary_json = ?,
                    revision = revision + 1
                WHERE run_id = ?
                """,
                (
                    status,
                    stage,
                    event["created_at"],
                    event["created_at"],
                    terminal_reason,
                    canonical_json(bounded_metadata(summary or {})),
                    run_id,
                ),
            )
            connection.commit()
        self._audit_event(event)

    def snapshot(self, run_id: str) -> dict[str, Any]:
        with _connect(self.path) as connection:
            run = connection.execute(
                "SELECT * FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            counts = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM harness_events WHERE run_id = ?) events,
                  (SELECT COUNT(*) FROM harness_evidence WHERE run_id = ?) evidence,
                  (SELECT COUNT(*) FROM harness_hypotheses WHERE run_id = ?) hypotheses,
                  (SELECT COUNT(*) FROM harness_decisions WHERE run_id = ?) decisions,
                  (SELECT COUNT(*) FROM harness_model_calls WHERE run_id = ?) model_calls,
                  (SELECT COUNT(*) FROM harness_tool_calls WHERE run_id = ?) tool_calls
                """,
                (run_id, run_id, run_id, run_id, run_id, run_id),
            ).fetchone()
            return {
                **dict(run),
                "counts": dict(counts),
            }

    def verify_chain(self, run_id: str) -> dict[str, Any]:
        with _connect(self.path) as connection:
            run = connection.execute(
                "SELECT status FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            rows = connection.execute(
                """
                SELECT * FROM harness_events
                WHERE run_id = ?
                ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
            actual_ledger_manifests = {
                schema: ledger_manifest(
                    connection,
                    run_id,
                    schema=schema,
                )
                for schema in SUPPORTED_LEDGER_MANIFEST_SCHEMAS
            }
            hypothesis_rows = connection.execute(
                """
                SELECT hypothesis_id, statement_digest, status,
                       supporting_refs_json, contradicting_refs_json,
                       next_discriminator, revision
                FROM harness_hypotheses
                WHERE run_id = ?
                ORDER BY hypothesis_id
                """,
                (run_id,),
            ).fetchall()
        previous = "0" * 64
        errors: list[str] = []
        expected_sequence = 1
        for row in rows:
            payload_hash = hashlib.sha256(
                str(row["payload_json"]).encode("utf-8")
            ).hexdigest()
            body = {
                "run_id": run_id,
                "sequence": int(row["sequence"]),
                "idempotency_key": row["idempotency_key"],
                "event_type": row["event_type"],
                "stage": row["stage"],
                "created_at": row["created_at"],
                "payload_sha256": row["payload_sha256"],
                "previous_event_sha256": row["previous_event_sha256"],
            }
            expected_hash = digest_json(body)
            if int(row["sequence"]) != expected_sequence:
                errors.append(f"sequence gap at {row['sequence']}")
            if row["payload_sha256"] != payload_hash:
                errors.append(f"payload digest mismatch at {row['sequence']}")
            if row["previous_event_sha256"] != previous:
                errors.append(f"previous hash mismatch at {row['sequence']}")
            if row["event_sha256"] != expected_hash:
                errors.append(f"event hash mismatch at {row['sequence']}")
            if row["event_id"] != f"evt-{expected_hash[:32]}":
                errors.append(f"event id mismatch at {row['sequence']}")
            previous = str(row["event_sha256"])
            expected_sequence += 1
        latest_hypothesis_event = next(
            (
                row
                for row in reversed(rows)
                if row["event_type"] == "hypotheses.updated"
            ),
            None,
        )
        if latest_hypothesis_event is not None:
            try:
                payload = json.loads(latest_hypothesis_event["payload_json"])
            except (TypeError, json.JSONDecodeError):
                payload = {}
            expected_manifest = str(payload.get("manifest_digest") or "")
            actual_manifest = hypothesis_manifest_digest(hypothesis_rows)
            if not expected_manifest:
                errors.append("latest hypothesis event has no manifest digest")
            elif expected_manifest != actual_manifest:
                errors.append("hypothesis ledger manifest mismatch")
        ledger_manifest_bound = False
        ledger_manifest_schema = ""
        started_event = next(
            (
                row
                for row in rows
                if row["event_type"] == "run.started"
            ),
            None,
        )
        try:
            started_payload = (
                json.loads(started_event["payload_json"])
                if started_event is not None
                else {}
            )
        except (TypeError, json.JSONDecodeError):
            started_payload = {}
        legacy_manifest_eligible = (
            started_event is not None
            and isinstance(started_payload, dict)
            and "assigned_reviewer_route" not in started_payload
        )
        if run["status"] in {
            RunStatus.SUCCEEDED.value,
            RunStatus.FAILED.value,
            RunStatus.CANCELLED.value,
        }:
            terminal_event = next(
                (
                    row
                    for row in reversed(rows)
                    if row["event_type"] == f"run.{run['status']}"
                ),
                None,
            )
            if terminal_event is None:
                errors.append("terminal run has no matching terminal event")
            else:
                try:
                    terminal_payload = json.loads(
                        terminal_event["payload_json"]
                    )
                except (TypeError, json.JSONDecodeError):
                    terminal_payload = {}
                expected_ledger_manifest = terminal_payload.get(
                    "ledger_manifest"
                )
                if not isinstance(expected_ledger_manifest, dict):
                    errors.append(
                        "terminal ledger manifest is missing or malformed"
                    )
                else:
                    ledger_manifest_schema = str(
                        expected_ledger_manifest.get("schema") or ""
                    )
                    actual_ledger_manifest = actual_ledger_manifests.get(
                        ledger_manifest_schema
                    )
                    if (
                        ledger_manifest_schema
                        == LEDGER_MANIFEST_SCHEMA_V1
                        and not legacy_manifest_eligible
                    ):
                        errors.append(
                            "terminal ledger manifest schema downgrade"
                        )
                    elif actual_ledger_manifest is None:
                        errors.append(
                            "unsupported terminal ledger manifest schema"
                        )
                    else:
                        ledger_manifest_bound = True
                if ledger_manifest_bound:
                    if digest_json(expected_ledger_manifest) != digest_json(
                        actual_ledger_manifest
                    ):
                        errors.append("terminal ledger manifest mismatch")
        return {
            "run_id": run_id,
            "valid": not errors and bool(rows),
            "event_count": len(rows),
            "head_sha256": previous if rows else "",
            "ledger_manifest_bound": ledger_manifest_bound,
            "ledger_manifest_schema": ledger_manifest_schema,
            "errors": errors,
        }

    def export_trace(self, run_id: str) -> dict[str, Any]:
        with _connect(self.path) as connection:
            run = connection.execute(
                "SELECT * FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            events = [
                {
                    **dict(row),
                    "payload": json.loads(row["payload_json"]),
                }
                for row in connection.execute(
                    """
                    SELECT * FROM harness_events
                    WHERE run_id = ? ORDER BY sequence
                    """,
                    (run_id,),
                ).fetchall()
            ]
            evidence = [
                {
                    **dict(row),
                    "metadata": json.loads(row["metadata_json"]),
                }
                for row in connection.execute(
                    """
                    SELECT * FROM harness_evidence
                    WHERE run_id = ? ORDER BY evidence_ref
                    """,
                    (run_id,),
                ).fetchall()
            ]
            hypotheses = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_hypotheses
                    WHERE run_id = ? ORDER BY hypothesis_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            decisions = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_decisions
                    WHERE run_id = ? ORDER BY created_at, decision_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            model_calls = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_model_calls
                    WHERE run_id = ? ORDER BY created_at, call_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            tool_calls = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_tool_calls
                    WHERE run_id = ? ORDER BY round_number, call_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            budget_reservations = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_budget_reservations
                    WHERE run_id = ?
                    ORDER BY reservation_type, reservation_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
        return {
            "schema": TRACE_SCHEMA,
            "exported_at": utc_now(),
            "run": dict(run),
            "events": events,
            "evidence": evidence,
            "hypotheses": hypotheses,
            "decisions": decisions,
            "model_calls": model_calls,
            "tool_calls": tool_calls,
            "budget_reservations": budget_reservations,
            "integrity": self.verify_chain(run_id),
        }


PHASE_STAGE_MAP = {
    "preparing": Stage.CONTEXT_ASSEMBLY.value,
    "primary_analysis": Stage.PRIMARY_ANALYSIS.value,
    "investigation_query_planning": Stage.QUERY_PLANNING.value,
    "investigation_query_execution": Stage.QUERY_EXECUTION.value,
    "evidence_synthesis": Stage.EVIDENCE_SYNTHESIS.value,
    "second_opinion": Stage.INDEPENDENT_REVIEW.value,
    "post_processing": Stage.POST_PROCESSING.value,
    "persistence": Stage.PERSISTENCE.value,
}


class HarnessRun:
    """Small integration surface used by the existing model runner."""

    def __init__(
        self,
        store: HarnessStore,
        envelope: JobEnvelope,
        policy: HarnessPolicy,
    ):
        self.store = store
        self.envelope = envelope
        self.policy = policy
        self.store.start_run(envelope, policy)
        with _connect(self.store.path) as connection:
            usage = connection.execute(
                """
                SELECT
                  (
                    SELECT COUNT(*)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'query-round'
                  ) query_rounds,
                  (
                    SELECT COALESCE(SUM(amount), 0)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'query-round'
                  ) queries_total,
                  (
                    SELECT COUNT(*)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'model-call'
                  ) model_calls
                """,
                (self.run_id, self.run_id, self.run_id),
            ).fetchone()
            phase_rows = connection.execute(
                """
                SELECT stage, COUNT(*) phase_count
                FROM harness_events
                WHERE run_id = ? AND event_type = 'run.stage'
                GROUP BY stage
                """,
                (self.run_id,),
            ).fetchall()
        self._phase_counts = {
            str(row["stage"]): int(row["phase_count"])
            for row in phase_rows
        }
        self._query_rounds = int(usage["query_rounds"])
        self._queries_total = int(usage["queries_total"])
        self._model_calls = int(usage["model_calls"])

    @property
    def run_id(self) -> str:
        return self.envelope.run_id

    def remaining_model_calls(self) -> int:
        """Return the hard remaining call budget for bounded orchestration."""
        return max(
            0,
            int(self.policy.budgets["max_model_calls"])
            - int(self._model_calls),
        )

    def query_rounds_used(self) -> int:
        """Return the highest globally reserved query-round ordinal."""
        return max(0, int(self._query_rounds))

    def remaining_query_rounds(self) -> int:
        """Return the hard remaining global query-round budget."""
        return max(
            0,
            int(self.policy.budgets["max_query_rounds"])
            - self.query_rounds_used(),
        )

    def remaining_queries(self) -> int:
        """Return the hard remaining admitted-query budget."""
        return max(
            0,
            int(self.policy.budgets["max_queries_total"])
            - int(self._queries_total),
        )

    def trace_context(self) -> dict[str, Any]:
        return {
            "schema": HARNESS_SCHEMA,
            "run_id": self.envelope.run_id,
            "trace_id": self.envelope.trace_id,
            "correlation_id": self.envelope.correlation_id,
            "policy_version": self.policy.version,
            "policy_mode": self.policy.mode,
        }

    def catalogue_prompt_evidence(self, prompt_package: Mapping[str, Any]) -> int:
        contract = prompt_package.get("evidence_reference_contract")
        return self.store.register_evidence_contract(
            self.run_id,
            contract if isinstance(contract, Mapping) else {},
        )

    def _elapsed_seconds(self) -> float:
        snapshot = self.store.snapshot(self.run_id)
        raw = str(snapshot.get("started_at") or "")
        try:
            started = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return 0.0
        if started.tzinfo is None:
            started = started.replace(tzinfo=dt.timezone.utc)
        return max(
            0.0,
            (dt.datetime.now(dt.timezone.utc) - started).total_seconds(),
        )

    def _enforce_budget(
        self,
        *,
        operation_id: str,
        operation: str,
        stage: str,
        observed: Mapping[str, Any],
        violations: Sequence[str],
    ) -> None:
        payload = {
            "operation_id": operation_id,
            "operation": operation,
            "observed": dict(observed),
            "limits": dict(self.policy.budgets),
            "violations": sorted(set(violations)),
            "policy_mode": self.policy.mode,
        }
        decision_digest = digest_json(payload)[:24]
        self.store.append_event(
            self.run_id,
            "policy.budget",
            stage,
            payload,
            idempotency_key=(
                f"policy.budget:{operation_id}:{decision_digest}"
            ),
        )
        if violations and self.policy.mode == "enforce":
            raise HarnessPolicyError(
                f"{operation} exceeds harness budget: "
                + ", ".join(sorted(set(violations)))
            )

    def preflight_model_call(
        self,
        *,
        call_id: str,
        input_value: Any,
        requested_route: str,
        purpose: str,
        independent_review: bool = False,
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        requested_route = _model_route(
            requested_route,
            "requested model route",
        )
        expected_route = (
            self.envelope.assigned_reviewer_route
            if independent_review
            else self.envelope.assigned_route
        )
        route_allowed = (
            bool(expected_route) and requested_route == expected_route
        )
        route_reason = (
            "requested route matches the immutable reviewer assignment"
            if route_allowed and independent_review
            else "requested route matches the immutable primary assignment"
            if route_allowed
            else "no reviewer route was assigned to this run"
            if independent_review and not expected_route
            else "no primary route was assigned to this run"
            if not expected_route
            else "requested route does not match the immutable run assignment"
        )
        model_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        )
        self.store.append_event(
            self.run_id,
            "policy.model-route",
            model_stage,
            {
                "call_id": call_id,
                "purpose": _redacted_string(purpose, 160),
                "requested_route": requested_route,
                "expected_route": expected_route,
                "independent_review": independent_review,
                "allowed": route_allowed,
                "reason": route_reason,
                "policy_mode": self.policy.mode,
            },
            idempotency_key=f"policy.model-route:{call_id}",
        )
        if not route_allowed and self.policy.mode == "enforce":
            raise HarnessPolicyError(route_reason)
        prompt_bytes = len(canonical_json(input_value).encode("utf-8"))
        evidence_rows = approximate_evidence_rows(input_value)
        elapsed_seconds = self._elapsed_seconds()
        violations: list[str] = []
        if prompt_bytes > self.policy.budgets["max_prompt_evidence_bytes"]:
            violations.append("max_prompt_evidence_bytes")
        if evidence_rows > self.policy.budgets["max_prompt_evidence_rows"]:
            violations.append("max_prompt_evidence_rows")
        if elapsed_seconds > self.policy.budgets["max_run_seconds"]:
            violations.append("max_run_seconds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="model-call",
            reservation_id=call_id,
            amount=1,
            max_total=self.policy.budgets["max_model_calls"],
            max_operations=self.policy.budgets["max_model_calls"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=violations,
        )
        violations = list(reservation["violations"])
        if reservation["reserved"]:
            self._model_calls = max(
                self._model_calls,
                int(reservation["total"]),
            )
        next_model_call = int(reservation["operation_count"])
        self._enforce_budget(
            operation_id=f"model:{call_id}",
            operation="model call",
            stage=model_stage,
            observed={
                "call_id": call_id,
                "purpose": _redacted_string(purpose, 160),
                "requested_route": requested_route,
                "expected_route": expected_route,
                "route_allowed": route_allowed,
                "independent_review": independent_review,
                "next_model_call": next_model_call,
                "prompt_bytes": prompt_bytes,
                "approximate_evidence_rows": evidence_rows,
                "reserved": bool(
                    reservation["reserved"]
                ),
            },
            violations=violations,
        )

    def authorize_tool(
        self,
        *,
        round_number: int,
        query_id: str,
        backend: str,
        approved: bool = False,
    ) -> PolicyDecision:
        capability = query_backend_capability(backend)
        decision = self.policy.authorize(
            self.envelope.role,
            capability,
            approved=approved,
        )
        event_key = digest_json(
            {
                "round": round_number,
                "query_id": str(query_id),
                "backend": str(backend),
                "capability": capability,
                "approved": approved,
            }
        )[:24]
        self.store.append_event(
            self.run_id,
            "policy.tool-authorization",
            Stage.QUERY_PLANNING.value,
            {
                "round": max(0, int(round_number)),
                "query_id": str(query_id)[:128],
                "backend": str(backend)[:80],
                "capability": capability,
                "allowed": decision.allowed,
                "approved": approved,
                "effective_in_shadow": policy_decision_is_effective(
                    "shadow",
                    decision,
                ),
                "requires_approval": decision.requires_approval,
                "reason": decision.reason,
            },
            idempotency_key=f"policy.tool:{event_key}",
        )
        return decision

    def preflight_query_batch(
        self,
        *,
        round_number: int,
        request_count: int,
    ) -> None:
        round_number = int(round_number)
        if round_number < 1:
            raise HarnessPolicyError("query round_number must be positive")
        request_count = max(0, int(request_count))
        elapsed_seconds = self._elapsed_seconds()
        violations: list[str] = []
        if round_number > self.policy.budgets["max_query_rounds"]:
            violations.append("max_query_rounds")
        if request_count > self.policy.budgets["max_queries_per_round"]:
            violations.append("max_queries_per_round")
        if elapsed_seconds > self.policy.budgets["max_run_seconds"]:
            violations.append("max_run_seconds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="query-round",
            reservation_id=str(round_number),
            amount=request_count,
            max_total=self.policy.budgets["max_queries_total"],
            max_operations=self.policy.budgets["max_query_rounds"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=violations,
        )
        violations = list(reservation["violations"])
        if reservation["reserved"]:
            self._query_rounds = max(self._query_rounds, round_number)
            self._queries_total = max(
                self._queries_total,
                int(reservation["total"]),
            )
        queries_after_batch = int(reservation["total"])
        self._enforce_budget(
            operation_id=f"query-round:{round_number}",
            operation="query batch",
            stage=Stage.QUERY_PLANNING.value,
            observed={
                "round": round_number,
                "request_count": request_count,
                "queries_after_batch": queries_after_batch,
                "reserved": bool(
                    reservation["reserved"]
                ),
            },
            violations=violations,
        )

    def phase(
        self,
        phase: str,
        route: str = "",
        reason: str = "",
    ) -> None:
        stage = PHASE_STAGE_MAP.get(phase, Stage.POST_PROCESSING.value)
        ordinal = self._phase_counts.get(stage, 0) + 1
        self._phase_counts[stage] = ordinal
        self.store.transition(
            self.run_id,
            stage,
            route=route,
            reason=reason,
            ordinal=ordinal,
        )

    def model_call(
        self,
        *,
        call_id: str,
        purpose: str,
        requested_route: str,
        response: Mapping[str, Any],
        input_value: Any,
        duration_seconds: float,
        independent_review: bool = False,
        status: str = "completed",
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        requested_route = _model_route(
            requested_route,
            "completed model route",
        )
        with _connect(self.store.path) as connection:
            authorization_row = connection.execute(
                """
                SELECT payload_json
                FROM harness_events
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (
                    self.run_id,
                    f"policy.model-route:{call_id}",
                ),
            ).fetchone()
        authorization = (
            json.loads(str(authorization_row["payload_json"]))
            if authorization_row is not None
            else {}
        )
        observed_route = str(
            response.get("_analysis_model_route") or ""
        ).strip()
        route_authorized = bool(
            authorization.get("allowed") is True
            and authorization.get("requested_route") == requested_route
            and bool(authorization.get("independent_review"))
            is bool(independent_review)
        )
        observed_matches = (
            not response
            or (
                bool(observed_route)
                and observed_route == requested_route
            )
        )
        observation_allowed = route_authorized and observed_matches
        observation_reason = (
            "authorized route and collector-observed route agree"
            if observation_allowed and response
            else "authorized failed invocation has no model response"
            if observation_allowed
            else "model call has no matching allowed preflight"
            if not route_authorized
            else "collector-observed route differs from the authorized route"
        )
        observation_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        )
        self.store.append_event(
            self.run_id,
            "policy.model-observation",
            observation_stage,
            {
                "call_id": call_id,
                "requested_route": requested_route,
                "observed_route": observed_route,
                "independent_review": independent_review,
                "response_present": bool(response),
                "allowed": observation_allowed,
                "reason": observation_reason,
                "policy_mode": self.policy.mode,
            },
            idempotency_key=f"policy.model-observation:{call_id}",
        )
        if not observation_allowed and self.policy.mode == "enforce":
            raise HarnessPolicyError(observation_reason)
        # The runner performs the full prompt/runtime preflight before invoking
        # a model. This idempotent reservation is a final hard-count backstop
        # for callers using the record API directly.
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="model-call",
            reservation_id=call_id,
            amount=1,
            max_total=self.policy.budgets["max_model_calls"],
            max_operations=self.policy.budgets["max_model_calls"],
            enforce=self.policy.mode == "enforce",
        )
        if reservation["violations"] and self.policy.mode == "enforce":
            self._enforce_budget(
                operation_id=f"model:{call_id}",
                operation="model call",
                stage=(
                    Stage.INDEPENDENT_REVIEW.value
                    if independent_review
                    else Stage.PRIMARY_ANALYSIS.value
                ),
                observed={
                    "call_id": call_id,
                    "next_model_call": reservation["operation_count"],
                    "reserved": False,
                },
                violations=reservation["violations"],
            )
        self.store.record_model_call(
            self.run_id,
            call_id=call_id,
            purpose=purpose,
            requested_route=requested_route,
            response=response,
            independent_review=independent_review,
            input_digest=digest_json(input_value),
            duration_ms=max(0, round(float(duration_seconds) * 1_000)),
            status=status,
        )
        self._model_calls = max(self._model_calls, int(reservation["total"]))

    def query_round(
        self,
        round_result: Mapping[str, Any],
    ) -> None:
        round_number = int(round_result.get("round") or self._query_rounds + 1)
        if round_number < 1:
            raise HarnessPolicyError("query round_number must be positive")
        requests = (
            round_result.get("requests")
            if isinstance(round_result.get("requests"), list)
            else []
        )
        results = (
            round_result.get("results")
            if isinstance(round_result.get("results"), list)
            else []
        )
        # The typed query broker is expected to call the full preflight before
        # execution. Reserve again idempotently so direct record-API users
        # cannot exceed hard count/round limits without a durable denial.
        direct_violations: list[str] = []
        if len(requests) > self.policy.budgets["max_queries_per_round"]:
            direct_violations.append("max_queries_per_round")
        if round_number > self.policy.budgets["max_query_rounds"]:
            direct_violations.append("max_query_rounds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="query-round",
            reservation_id=str(round_number),
            amount=len(requests),
            max_total=self.policy.budgets["max_queries_total"],
            max_operations=self.policy.budgets["max_query_rounds"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=direct_violations,
        )
        direct_violations = list(reservation["violations"])
        if direct_violations and self.policy.mode == "enforce":
            self._enforce_budget(
                operation_id=f"query-round:{round_number}",
                operation="query batch",
                stage=Stage.QUERY_PLANNING.value,
                observed={
                    "round": round_number,
                    "request_count": len(requests),
                    "queries_after_batch": (
                        reservation["total"]
                    ),
                    "reserved": bool(
                        reservation["reserved"]
                    ),
                },
                violations=direct_violations,
            )
        if reservation["reserved"]:
            self._queries_total = max(
                self._queries_total,
                int(reservation["total"]),
            )
        self._query_rounds = max(self._query_rounds, round_number)
        status_counts: dict[str, int] = {}
        backend_counts: dict[str, int] = {}
        trusted_query_digests: list[str] = []
        request_by_id = {
            str(item.get("query_id")): item
            for item in requests
            if isinstance(item, dict) and item.get("query_id")
        }
        result_by_id: dict[str, dict[str, Any]] = {}
        for item in results:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "unknown")[:40]
            backend = str(item.get("backend") or "unknown")[:40]
            status_counts[status] = status_counts.get(status, 0) + 1
            backend_counts[backend] = backend_counts.get(backend, 0) + 1
            item_ids = (
                [str(value) for value in item.get("query_ids", [])]
                if isinstance(item.get("query_ids"), list)
                else [str(item.get("query_id"))]
                if item.get("query_id")
                else []
            )
            for item_id in item_ids:
                result_by_id[item_id] = item
            audits = (
                item.get("trusted_query_audit")
                if isinstance(item.get("trusted_query_audit"), list)
                else []
            )
            for audit in audits:
                if not isinstance(audit, dict):
                    continue
                digest = str(audit.get("query_digest") or "")
                if DIGEST_RE.fullmatch(digest):
                    trusted_query_digests.append(digest)
                    returned_count = observed_returned_count(audit)
                    result_digest = str(
                        audit.get("result_digest") or ""
                    ).lower()
                    if not DIGEST_RE.fullmatch(result_digest):
                        result_digest = ""
                    supplied_ref = str(
                        audit.get("evidence_ref")
                        or f"query:{digest}"
                    ).strip()
                    if not supplied_ref or supplied_ref.startswith("query:"):
                        ref = f"query:{digest}"
                        if DIGEST_RE.fullmatch(result_digest):
                            ref += f":{result_digest}"
                    else:
                        ref = supplied_ref[:512]
                    self.store.register_evidence(
                        self.run_id,
                        evidence_ref=ref,
                        source=backend,
                        source_class=(
                            "live_endpoint_osquery"
                            if backend == "osquery"
                            else "packet_evidence"
                            if backend == "pcap_zeek"
                            else "security_onion_investigation_query"
                        ),
                        trust_tier=TrustTier.READ_ONLY_BACKEND.value,
                        corroborating=(
                            str(audit.get("status") or status)
                            in {"ok", "completed", "success"}
                            and returned_count is not None
                            and returned_count > 0
                        ),
                        status=str(audit.get("status") or status),
                        evidence_digest=str(
                            result_digest or digest
                        ),
                        metadata={
                            "query_id": audit.get("query_id"),
                            "query_digest": digest,
                            "returned": returned_count,
                            "truncated": audit.get("truncated"),
                        },
                    )
        # Policy/schema/backend rejections may never have entered the admitted
        # request list. They still need a durable tool ledger row so denial and
        # evidence-gap metrics reflect the actual investigation trajectory.
        for query_id, result in result_by_id.items():
            if query_id not in request_by_id:
                request_by_id[query_id] = {
                    "query_id": query_id,
                    "backend": result.get("backend"),
                    "purpose": result.get("purpose")
                    or "proposal rejected before execution",
                    "rejected_before_execution": True,
                }
        for query_id, request in request_by_id.items():
            result = result_by_id.get(query_id, {})
            backend = str(request.get("backend") or result.get("backend") or "")
            evidence = (
                result.get("evidence")
                if isinstance(result.get("evidence"), dict)
                else {}
            )
            result_status, result_observation = resolve_query_binding(
                result,
                query_id,
            )
            returned_count = observed_returned_count(result_observation)
            coverage = str(
                evidence.get("coverage")
                or evidence.get("coverage_semantics")
                or (
                    "exact-zero"
                    if result_status == "ok"
                    and returned_count == 0
                    else "bounded-result"
                    if result_status == "ok"
                    and returned_count is not None
                    and returned_count > 0
                    else "unknown"
                    if result_status == "ok"
                    else "evidence-gap"
                )
            )
            self.store.record_tool_call(
                self.run_id,
                call_id=f"round-{round_number}-{query_id}"[:128],
                round_number=round_number,
                backend=backend,
                capability=query_backend_capability(backend),
                purpose=str(request.get("purpose") or ""),
                request_digest=digest_json(request),
                result_digest=digest_json(result),
                status=result_status,
                read_only=result.get("read_only") is True,
                coverage=coverage,
                truncated=observed_truncation(result_observation),
            )
        with _connect(self.store.path) as connection:
            usage = connection.execute(
                """
                SELECT COUNT(*) executed_queries
                FROM harness_tool_calls
                WHERE run_id = ?
                  AND lower(status) NOT IN (
                    'rejected', 'denied', 'blocked',
                    'unauthorized', 'forbidden'
                  )
                """,
                (self.run_id,),
            ).fetchone()
        self._queries_total = max(
            self._queries_total,
            int(usage["executed_queries"]),
        )
        budget_violations = list(direct_violations)
        if self._query_rounds > self.policy.budgets["max_query_rounds"]:
            budget_violations.append("max_query_rounds")
        # Rejected proposals are audit rows but did not consume an execution
        # budget. The preflight reservation is authoritative when present;
        # this post-execution fallback counts admitted requests for callers that
        # use the harness API directly.
        admitted_total = max(self._queries_total, len(requests))
        if admitted_total > self.policy.budgets["max_queries_total"]:
            budget_violations.append("max_queries_total")
        if len(requests) > self.policy.budgets["max_queries_per_round"]:
            budget_violations.append("max_queries_per_round")
        self.store.append_event(
            self.run_id,
            "queries.completed",
            Stage.QUERY_EXECUTION.value,
            {
                "round": round_number,
                "request_count": len(requests),
                "result_count": len(results),
                "rejected_proposal_count": sum(
                    1
                    for request in request_by_id.values()
                    if request.get("rejected_before_execution") is True
                ),
                "status_counts": status_counts,
                "backend_counts": backend_counts,
                "trusted_query_digests": sorted(set(trusted_query_digests)),
                "budget_violations": budget_violations,
            },
            idempotency_key=f"queries.completed:{round_number}",
        )
        if budget_violations and self.policy.mode == "enforce":
            raise HarnessPolicyError(
                "investigation exceeded harness budget: "
                + ", ".join(budget_violations)
            )

    def record_response(
        self,
        response: Mapping[str, Any],
        *,
        decision_id: str,
        decision_type: str,
        hypothesis_revision: int,
    ) -> None:
        decision_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if decision_type == "independent-review"
            else Stage.POST_PROCESSING.value
            if decision_type == "post-review-analysis"
            else Stage.EVIDENCE_SYNTHESIS.value
        )
        self.store.record_hypotheses(
            self.run_id,
            response.get("hypotheses"),
            revision=hypothesis_revision,
        )
        self.store.record_decision(
            self.run_id,
            decision_id=decision_id,
            decision_type=decision_type,
            response=response,
            stage=decision_stage,
        )

    def memory_promotion_decision(
        self,
        response: Mapping[str, Any],
        *,
        has_shared_candidates: bool,
        human_approved: bool = False,
    ) -> PolicyDecision:
        return memory_promotion_decision(
            self.policy,
            response,
            role=self.envelope.role,
            has_shared_candidates=has_shared_candidates,
            human_approved=human_approved,
        )

    def preflight_completion(
        self,
        *,
        operation_id: str = "run-complete",
    ) -> None:
        operation_id = _valid_identifier(
            operation_id,
            "completion operation_id",
            128,
        )
        elapsed_seconds = self._elapsed_seconds()
        self._enforce_budget(
            operation_id=operation_id,
            operation="run completion",
            stage=Stage.PERSISTENCE.value,
            observed={"elapsed_seconds": round(elapsed_seconds, 3)},
            violations=(
                ["max_run_seconds"]
                if elapsed_seconds > self.policy.budgets["max_run_seconds"]
                else []
            ),
        )

    def record_memory_writeback(
        self,
        receipt: Mapping[str, Any],
    ) -> None:
        """Record bounded post-commit results without storing memory content."""
        self.store.append_event(
            self.run_id,
            "memory.writeback",
            Stage.PERSISTENCE.value,
            receipt,
            idempotency_key="memory.writeback:post-commit",
        )

    def observe_postcommit_runtime(self) -> dict[str, Any]:
        """Audit an SLO breach after commit without invalidating durable work."""
        elapsed_seconds = self._elapsed_seconds()
        exceeded = elapsed_seconds > self.policy.budgets["max_run_seconds"]
        payload = {
            "elapsed_seconds": round(elapsed_seconds, 3),
            "max_run_seconds": self.policy.budgets["max_run_seconds"],
            "exceeded": exceeded,
            "enforcement_boundary": "post-commit-observation",
        }
        self.store.append_event(
            self.run_id,
            "slo.runtime",
            Stage.PERSISTENCE.value,
            payload,
            idempotency_key="slo.runtime:post-commit",
        )
        return payload

    def complete(
        self,
        summary: Mapping[str, Any] | None = None,
        *,
        check_budget: bool = True,
    ) -> None:
        if check_budget:
            self.preflight_completion()
        self.store.finish(
            self.run_id,
            status=RunStatus.SUCCEEDED.value,
            summary=summary,
        )

    def fail(self, reason: str) -> None:
        self.store.finish(
            self.run_id,
            status=RunStatus.FAILED.value,
            reason=reason,
        )


def memory_promotion_decision(
    policy: HarnessPolicy,
    response: Mapping[str, Any],
    *,
    role: str,
    has_shared_candidates: bool,
    human_approved: bool = False,
) -> PolicyDecision:
    """Gate durable model memory against review, evidence, and poisoning risks."""
    controls = (
        response.get("_automation_controls")
        if isinstance(response.get("_automation_controls"), dict)
        else {}
    )
    if controls.get("memory_writeback_blocked"):
        return PolicyDecision(
            False,
            "memory.promote",
            str(controls.get("reason") or "automation guardrail blocked memory"),
        )
    validation = (
        response.get("_evidence_reference_validation")
        if isinstance(response.get("_evidence_reference_validation"), dict)
        else {}
    )
    source_classes = {
        str(item)
        for item in validation.get("corroborating_source_classes", [])
        if str(item)
    } if isinstance(validation.get("corroborating_source_classes"), list) else set()
    invalid_refs = (
        validation.get("invalid_refs")
        if isinstance(validation.get("invalid_refs"), list)
        else []
    )
    if invalid_refs:
        return PolicyDecision(
            False,
            "memory.promote",
            "memory candidate depends on unresolved evidence references",
        )
    if len(source_classes) < 2:
        return PolicyDecision(
            False,
            "memory.promote",
            "fewer than two corroborating evidence source classes",
        )
    try:
        confidence_score = float(response.get("confidence_score"))
    except (TypeError, ValueError, OverflowError):
        confidence_score = 0.0
    if (
        str(response.get("confidence") or "").lower() != "high"
        or confidence_score < 0.8
    ):
        return PolicyDecision(
            False,
            "memory.promote",
            "analysis confidence is below the memory promotion threshold",
        )
    if policy.memory_require_independent_agreement:
        review = (
            response.get("_second_opinion")
            if isinstance(response.get("_second_opinion"), dict)
            else {}
        )
        comparison = (
            review.get("comparison")
            if isinstance(review.get("comparison"), dict)
            else {}
        )
        if (
            review.get("status") != "completed"
            or comparison.get("agreement") != "agreement"
            or comparison.get("material_disagreement") is True
        ):
            return PolicyDecision(
                False,
                "memory.promote",
                "independent reviewer did not fully corroborate the analysis",
            )
    if (
        has_shared_candidates
        and policy.shared_memory_requires_human_approval
        and not human_approved
    ):
        return PolicyDecision(
            False,
            "memory.promote",
            "shared memory requires explicit human approval",
            requires_approval=True,
        )
    return policy.authorize(
        role,
        "memory.promote",
        approved=human_approved,
    )


def start_harness_run(
    *,
    run_id: str,
    prompt_package: Mapping[str, Any],
    role: str,
    assigned_route: str,
    configuration: Mapping[str, Any],
    reanalysis_attempt_id: str = "",
    policy_path: Path = DEFAULT_POLICY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    policy: HarnessPolicy | None = None,
) -> HarnessRun | None:
    effective_policy = policy or load_policy(policy_path)
    start_allowed, _ = should_start_onion_sentinel_harness(
        policy_enabled=effective_policy.enabled,
        assigned_route=assigned_route,
        reviewer_route=configuration.get("reviewer_route"),
    )
    if not start_allowed:
        return None
    envelope = JobEnvelope.from_prompt(
        run_id=run_id,
        prompt_package=prompt_package,
        role=role,
        assigned_route=assigned_route,
        configuration=configuration,
        reanalysis_attempt_id=reanalysis_attempt_id,
    )
    run = HarnessRun(HarnessStore(db_path), envelope, effective_policy)
    run.catalogue_prompt_evidence(prompt_package)
    return run


def main() -> int:
    print(
        "onion_sentinel_harness.py is a runtime module; use the read-only "
        "evaluate-harness-traces.py utility for inspection",
        file=os.sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
