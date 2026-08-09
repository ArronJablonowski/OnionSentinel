#!/usr/bin/env python3
"""Stable schemas, limits, identity fields, and pure trace-evaluation helpers."""
from __future__ import annotations

import collections
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any


REPORT_SCHEMA = "onion-sentinel-harness-trace-evaluation-v1"
LEDGER_MANIFEST_SCHEMA_V1 = "onion-sentinel-harness-ledger-manifest-v1"
LEDGER_MANIFEST_SCHEMA = "onion-sentinel-harness-ledger-manifest-v2"
CURRENT_SQL_SCHEMA_VERSION = 4
DEFAULT_DB = (
    Path.home()
    / "n8n-local"
    / "alert_store_data"
    / "investigation-harness.sqlite3"
)
REQUIRED_TABLES = frozenset({"harness_runs", "harness_events"})
OPTIONAL_TABLES = frozenset(
    {
        "harness_evidence",
        "harness_hypotheses",
        "harness_decisions",
        "harness_model_calls",
        "harness_tool_calls",
        "harness_budget_reservations",
    }
)
TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})
SUCCESS_STATUSES = frozenset(
    {"ok", "complete", "completed", "success", "succeeded"}
)
REVIEWER_REPAIR_PURPOSE = "independent second-opinion review"
REVIEWER_REPAIR_CALL_IDS = ("independent-review-1", "independent-review-2")
ADJUDICATION_PURPOSE = "bounded disagreement adjudication"
ADJUDICATION_CALL_IDS = (
    "disagreement-adjudication-1",
    "disagreement-adjudication-2",
)
VALIDATION_FAILED_STATUS = "validation-failed"
MODEL_CALL_CONTRACT_SCHEMA = "onion-sentinel-model-call-contract-v1"
MAX_RUNTIME_MODEL_CALLS = 6
PRIMARY_INITIAL_CALL_ID = "primary-initial"
PRIMARY_INITIAL_PURPOSE = "initial primary analysis"
QUERY_PLANNING_CALL_ID = "primary-query-planning-retry-1"
QUERY_PLANNING_PURPOSE = "evaluation query-planning retry 1 of 1"
QUERY_PLANNING_REPAIR_CALL_ID = "primary-query-planning-repair-1"
QUERY_PLANNING_REPAIR_PURPOSE = "primary query-planning repair 1 of 1"
FOLLOWUP_CALL_RE = re.compile(r"primary-followup-([1-3])")
SUPPLEMENTAL_REVIEW_CALL_ID = "independent-review-supplemental-1"
SUPPLEMENTAL_REVIEW_PURPOSE = (
    "independent reviewer supplemental reconciliation round 1"
)
REJECTION_STATUSES = frozenset(
    {"rejected", "denied", "blocked", "unauthorized", "forbidden"}
)
FAILURE_STATUSES = frozenset(
    {"error", "failed", "failure", "timeout", "timed-out", "missing"}
)
GAP_COVERAGE = frozenset(
    {"", "unknown", "evidence-gap", "missing", "unavailable", "not-collected"}
)
MATERIAL_REVIEW_FIELDS = (
    "detection_outcome",
    "event_status",
    "detection_validity",
    "activity_disposition",
    "handling",
    "duplicate_of",
)
MAX_REPORTED_IDS = 100
SKILL_SELECTION_ATTESTATION_KEYS = frozenset(
    {
        "registry_version",
        "registry_sha256",
        "selected",
        "selected_count",
        "truncated",
        "advisory_mode",
    }
)
SKILL_SELECTION_ID_RE = re.compile(
    r"^[A-Za-z0-9.][A-Za-z0-9._:@+=/-]{0,255}$"
)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_ATTESTED_INVESTIGATION_SKILLS = 4
JOB_ENVELOPE_DIGEST_FIELDS = (
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
    "parent_run_id",
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


class EvaluationError(RuntimeError):
    """The requested trace evaluation cannot be completed safely."""


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


def ratio(numerator: int | float, denominator: int | float) -> float | None:
    if not denominator:
        return None
    return round(float(numerator) / float(denominator), 4)


def normalize_status(value: object) -> str:
    return str(value or "").strip().lower().replace("_", "-")


def nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def safe_json(
    value: object,
    default: Any,
    malformed: collections.Counter[str],
    label: str,
) -> Any:
    if not isinstance(value, str):
        malformed[label] += 1
        return default
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        malformed[label] += 1
        return default
    if not isinstance(decoded, type(default)):
        malformed[label] += 1
        return default
    return decoded
