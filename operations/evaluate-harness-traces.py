#!/usr/bin/env python3
"""Evaluate Onion Sentinel investigation-harness traces without changing them.

The evaluator opens the harness SQLite database in read-only/query-only mode.
It verifies every selected event hash chain and reports operational coverage,
model/tool use, reviewer disagreement, budget violations, and memory-promotion
decisions. It never initializes, migrates, checkpoints, or vacuums the database.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))

from trace_evaluation_skills import (
    TraceSkillPolicy,
    skill_selection_attestation_result as evaluate_skill_attestation,
)
from trace_evaluation_storage import (
    TraceStoragePolicy,
    connect_read_only as open_trace_database,
    database_schema_version as read_database_schema_version,
    rows_for_run as read_rows_for_run,
    selected_runs as read_selected_runs,
    table_names as read_table_names,
)
from trace_evaluation_integrity import (
    TraceIntegrityPolicy,
    hypothesis_manifest_digest as build_hypothesis_manifest_digest,
    ledger_manifest as build_ledger_manifest,
    verify_chain as verify_trace_chain,
)
from trace_evaluation_reviewer import (
    ReviewerEvaluationPolicy,
    decision_payloads as parse_decision_payloads,
    reviewer_completion_contract as evaluate_reviewer_completion,
    reviewer_result as evaluate_reviewer_result,
)
from trace_evaluation_model_contract import (
    ModelCallContractPolicy,
    canonical_model_call_contract as build_model_call_contract,
)
from trace_evaluation_model_completion import (
    ModelPurposePolicy,
    model_purpose_completion as evaluate_model_purpose_completion,
)
from trace_evaluation_model_routes import (
    ModelRoutePolicy,
    expected_route_identity,
    model_route_consistency as evaluate_model_route_consistency,
)


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
TERMINAL_STATUSES = frozenset(
    {"succeeded", "failed", "cancelled"}
)
SUCCESS_STATUSES = frozenset(
    {"ok", "complete", "completed", "success", "succeeded"}
)
REVIEWER_REPAIR_PURPOSE = "independent second-opinion review"
REVIEWER_REPAIR_CALL_IDS = (
    "independent-review-1",
    "independent-review-2",
)
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


def tool_query_id(row: Mapping[str, Any]) -> str:
    """Return the logical query id encoded in a collector-owned call id."""
    call_id = str(row.get("call_id") or "")
    round_number = nonnegative_int(row.get("round_number"))
    prefix = f"round-{round_number}-"
    return call_id[len(prefix) :] if call_id.startswith(prefix) else ""


def unresolved_tool_coverage_gaps(
    tool_calls: Iterable[Mapping[str, Any]],
) -> list[str]:
    """Keep failed attempts auditable while grading their terminal outcome.

    The runtime permits a single deterministic repair only under the original
    query id and validates that it cannot widen scope.  Therefore an earlier
    gap for that id is resolved only when a later ledger row is successful;
    an unrepaired or terminally failed id remains a coverage gap.
    """
    ordered = sorted(
        tool_calls,
        key=lambda row: (
            nonnegative_int(row.get("round_number")),
            str(row.get("call_id") or ""),
        ),
    )
    terminal_by_query_id: dict[str, Mapping[str, Any]] = {}
    standalone_gaps: list[str] = []
    for row in ordered:
        query_id = tool_query_id(row)
        if query_id:
            terminal_by_query_id[query_id] = row
        elif (
            normalize_status(row.get("coverage")) in GAP_COVERAGE
            or normalize_status(row.get("status"))
            not in (SUCCESS_STATUSES | REJECTION_STATUSES)
        ):
            standalone_gaps.append(str(row.get("call_id") or ""))
    unresolved = list(standalone_gaps)
    for row in terminal_by_query_id.values():
        if (
            normalize_status(row.get("coverage")) in GAP_COVERAGE
            or normalize_status(row.get("status"))
            not in SUCCESS_STATUSES
        ):
            unresolved.append(str(row.get("call_id") or ""))
    return unresolved
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


def _trace_skill_policy() -> TraceSkillPolicy:
    return TraceSkillPolicy(
        attestation_keys=SKILL_SELECTION_ATTESTATION_KEYS,
        skill_id_pattern=SKILL_SELECTION_ID_RE,
        sha256_pattern=SHA256_RE,
        maximum_selected=MAX_ATTESTED_INVESTIGATION_SKILLS,
        job_digest_fields=JOB_ENVELOPE_DIGEST_FIELDS,
        maximum_reported_errors=MAX_REPORTED_IDS,
        digest_value=digest_json,
    )


def skill_selection_attestation_result(
    run: Mapping[str, Any],
    events: Iterable[Mapping[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, Any]:
    return evaluate_skill_attestation(
        run, events, malformed, _trace_skill_policy()
    )


def _trace_storage_policy() -> TraceStoragePolicy:
    return TraceStoragePolicy(
        current_schema_version=CURRENT_SQL_SCHEMA_VERSION,
        error=EvaluationError,
    )


def connect_read_only(path: Path) -> sqlite3.Connection:
    return open_trace_database(path, _trace_storage_policy())


def table_names(connection: sqlite3.Connection) -> set[str]:
    return read_table_names(connection)


def database_schema_version(
    connection: sqlite3.Connection,
    available_tables: set[str],
) -> int | None:
    return read_database_schema_version(
        connection, available_tables, _trace_storage_policy()
    )


def selected_runs(
    connection: sqlite3.Connection,
    run_id: str | None,
) -> list[dict[str, Any]]:
    return read_selected_runs(connection, run_id, _trace_storage_policy())


def rows_for_run(
    connection: sqlite3.Connection,
    available_tables: set[str],
    table: str,
    run_id: str,
    order_by: str,
) -> list[dict[str, Any]]:
    return read_rows_for_run(
        connection, available_tables, table, run_id, order_by
    )


def _trace_integrity_policy() -> TraceIntegrityPolicy:
    return TraceIntegrityPolicy(
        current_manifest_schema=LEDGER_MANIFEST_SCHEMA,
        legacy_manifest_schema=LEDGER_MANIFEST_SCHEMA_V1,
        supported_manifest_schemas=SUPPORTED_LEDGER_MANIFEST_SCHEMAS,
        current_run_identity_columns=RUN_IDENTITY_COLUMNS,
        legacy_run_identity_columns=LEGACY_RUN_IDENTITY_COLUMNS_V1,
        terminal_statuses=TERMINAL_STATUSES,
        maximum_reported_errors=MAX_REPORTED_IDS,
        digest_value=digest_json,
        normalize_status=normalize_status,
        error=EvaluationError,
    )


def hypothesis_manifest_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    return build_hypothesis_manifest_digest(rows, digest_json)


def ledger_manifest(
    ledgers: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    schema: str = LEDGER_MANIFEST_SCHEMA,
) -> dict[str, Any]:
    return build_ledger_manifest(
        ledgers, schema=schema, policy=_trace_integrity_policy()
    )


def verify_chain(
    run_id: str,
    events: Iterable[Mapping[str, Any]],
    hypotheses: Iterable[Mapping[str, Any]] = (),
    *,
    run_status: str = "",
    ledgers: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    require_ledger_manifest: bool = False,
) -> dict[str, Any]:
    return verify_trace_chain(
        run_id,
        events,
        hypotheses,
        run_status=run_status,
        ledgers=ledgers or {},
        require_ledger_manifest=require_ledger_manifest,
        policy=_trace_integrity_policy(),
    )


def _reviewer_evaluation_policy() -> ReviewerEvaluationPolicy:
    return ReviewerEvaluationPolicy(
        reviewer_purpose=REVIEWER_REPAIR_PURPOSE,
        reviewer_call_ids=REVIEWER_REPAIR_CALL_IDS,
        supplemental_purpose=SUPPLEMENTAL_REVIEW_PURPOSE,
        supplemental_call_id=SUPPLEMENTAL_REVIEW_CALL_ID,
        material_fields=MATERIAL_REVIEW_FIELDS,
        normalize_status=normalize_status,
        nonnegative_int=nonnegative_int,
    )


def decision_payloads(
    decisions: Iterable[Mapping[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, dict[str, Any]]:
    return parse_decision_payloads(decisions, malformed)


def reviewer_result(
    model_calls: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, Any]:
    return evaluate_reviewer_result(
        model_calls, decisions, malformed, _reviewer_evaluation_policy()
    )


def reviewer_completion_contract(
    reviewer: Mapping[str, Any],
    purpose_completion: Mapping[str, Any],
) -> dict[str, Any]:
    return evaluate_reviewer_completion(
        reviewer, purpose_completion, _reviewer_evaluation_policy()
    )


def _model_call_contract_policy() -> ModelCallContractPolicy:
    return ModelCallContractPolicy(
        schema=MODEL_CALL_CONTRACT_SCHEMA,
        maximum_calls=MAX_RUNTIME_MODEL_CALLS,
        primary_initial_id=PRIMARY_INITIAL_CALL_ID,
        primary_initial_purpose=PRIMARY_INITIAL_PURPOSE,
        query_planning_id=QUERY_PLANNING_CALL_ID,
        query_planning_purpose=QUERY_PLANNING_PURPOSE,
        query_planning_repair_id=QUERY_PLANNING_REPAIR_CALL_ID,
        query_planning_repair_purpose=QUERY_PLANNING_REPAIR_PURPOSE,
        followup_pattern=FOLLOWUP_CALL_RE,
        reviewer_ids=REVIEWER_REPAIR_CALL_IDS,
        reviewer_purpose=REVIEWER_REPAIR_PURPOSE,
        supplemental_id=SUPPLEMENTAL_REVIEW_CALL_ID,
        supplemental_purpose=SUPPLEMENTAL_REVIEW_PURPOSE,
        adjudication_ids=ADJUDICATION_CALL_IDS,
        adjudication_purpose=ADJUDICATION_PURPOSE,
        validation_failed_status=VALIDATION_FAILED_STATUS,
        normalize_status=normalize_status,
        digest_value=digest_json,
    )


def canonical_model_call_contract(
    model_calls: list[dict[str, Any]],
) -> dict[str, Any]:
    return build_model_call_contract(model_calls, _model_call_contract_policy())


def _model_purpose_policy() -> ModelPurposePolicy:
    return ModelPurposePolicy(
        success_statuses=SUCCESS_STATUSES,
        validation_failed_status=VALIDATION_FAILED_STATUS,
        reviewer_purpose=REVIEWER_REPAIR_PURPOSE,
        reviewer_ids=REVIEWER_REPAIR_CALL_IDS,
        supplemental_purpose=SUPPLEMENTAL_REVIEW_PURPOSE,
        supplemental_id=SUPPLEMENTAL_REVIEW_CALL_ID,
        adjudication_purpose=ADJUDICATION_PURPOSE,
        adjudication_ids=ADJUDICATION_CALL_IDS,
        maximum_reported=MAX_REPORTED_IDS,
        normalize_status=normalize_status,
    )


def model_purpose_completion(
    model_calls: list[dict[str, Any]],
    reviewer: Mapping[str, Any],
) -> dict[str, Any]:
    return evaluate_model_purpose_completion(
        model_calls, reviewer, _model_purpose_policy()
    )


def terminal_execution_summary(
    events: Iterable[Mapping[str, Any]],
    run_status: object,
    malformed: collections.Counter[str],
) -> dict[str, Any]:
    """Project collector-owned completion controls without exporting content."""

    normalized_status = normalize_status(run_status)
    terminal_event = next(
        (
            event
            for event in reversed(list(events))
            if str(event.get("event_type") or "")
            == f"run.{normalized_status}"
        ),
        None,
    )
    if terminal_event is None:
        return {}
    payload = safe_json(
        terminal_event.get("payload_json"),
        {},
        malformed,
        "event.terminal.payload_json",
    )
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        return {}
    output: dict[str, Any] = {}
    for field in (
        "analysis_id",
        "submitted_response_sha256",
        "stored_response_sha256",
        "evaluation_memory_frozen",
    ):
        value = summary.get(field)
        if isinstance(value, (str, int, float, bool, type(None))):
            output[field] = value
    return output


def budget_operation_id(
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> str:
    """Return a stable operation identity across preflight and legacy events."""
    event_type = str(event.get("event_type") or "")
    idempotency_key = str(event.get("idempotency_key") or "")
    if event_type == "policy.budget":
        if payload.get("operation_id"):
            return str(payload["operation_id"])
        prefix = "policy.budget:"
        if idempotency_key.startswith(prefix) and idempotency_key[len(prefix) :]:
            suffix = idempotency_key[len(prefix) :]
            operation_id, separator, decision_digest = suffix.rpartition(":")
            if (
                separator
                and operation_id
                and len(decision_digest) == 24
                and all(character in "0123456789abcdef" for character in decision_digest)
            ):
                return operation_id
            return suffix
        observed = payload.get("observed")
        if isinstance(observed, dict):
            if observed.get("call_id"):
                return f"model:{observed['call_id']}"
            if observed.get("round") is not None:
                return f"query-round:{observed['round']}"
        operation = str(payload.get("operation") or "budget-preflight")
        return f"{operation}:{event.get('sequence') or 'unknown'}"
    if event_type == "queries.completed":
        if payload.get("round") is not None:
            return f"query-round:{payload['round']}"
        prefix = "queries.completed:"
        if idempotency_key.startswith(prefix) and idempotency_key[len(prefix) :]:
            return f"query-round:{idempotency_key[len(prefix) :]}"
    return f"{event_type or 'budget'}:{event.get('sequence') or 'unknown'}"


def _model_route_policy() -> ModelRoutePolicy:
    return ModelRoutePolicy(
        success_statuses=SUCCESS_STATUSES,
        validation_failed_status=VALIDATION_FAILED_STATUS,
        maximum_reported=MAX_REPORTED_IDS,
        normalize_status=normalize_status,
        safe_json=safe_json,
    )


def model_route_consistency(
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
    model_calls: list[dict[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, Any]:
    return evaluate_model_route_consistency(
        run, events, model_calls, malformed, _model_route_policy()
    )


def evaluate_run(
    connection: sqlite3.Connection,
    available_tables: set[str],
    run: Mapping[str, Any],
    malformed: collections.Counter[str],
    *,
    require_ledger_manifest: bool = False,
) -> dict[str, Any]:
    run_id = str(run.get("run_id") or "")
    events = rows_for_run(
        connection, available_tables, "harness_events", run_id, "sequence"
    )
    evidence = rows_for_run(
        connection,
        available_tables,
        "harness_evidence",
        run_id,
        "evidence_ref",
    )
    hypotheses = rows_for_run(
        connection,
        available_tables,
        "harness_hypotheses",
        run_id,
        "hypothesis_id",
    )
    decisions = rows_for_run(
        connection,
        available_tables,
        "harness_decisions",
        run_id,
        "created_at, decision_id",
    )
    model_calls = rows_for_run(
        connection,
        available_tables,
        "harness_model_calls",
        run_id,
        "created_at, call_id",
    )
    tool_calls = rows_for_run(
        connection,
        available_tables,
        "harness_tool_calls",
        run_id,
        "round_number, call_id",
    )
    budget_reservations = rows_for_run(
        connection,
        available_tables,
        "harness_budget_reservations",
        run_id,
        "reservation_type, reservation_id",
    )
    ledgers = {
        "harness_run_identity": [
            {
                key: run[key]
                for key in RUN_IDENTITY_COLUMNS
                if key in run
            }
        ],
        "harness_evidence": evidence,
        "harness_hypotheses": hypotheses,
        "harness_decisions": decisions,
        "harness_model_calls": model_calls,
        "harness_tool_calls": tool_calls,
        "harness_budget_reservations": budget_reservations,
    }

    source_classes = sorted(
        {
            str(row.get("source_class") or "unknown")
            for row in evidence
            if str(row.get("source_class") or "")
            and int(row.get("corroborating") or 0) == 1
            and normalize_status(row.get("trust_tier"))
            in {
                "trusted-collector",
                "read-only-backend",
                "human-confirmed",
            }
        }
    )
    rejected_tools = [
        str(row.get("call_id") or "")
        for row in tool_calls
        if normalize_status(row.get("status")) in REJECTION_STATUSES
    ]
    failed_tools = [
        str(row.get("call_id") or "")
        for row in tool_calls
        if normalize_status(row.get("status")) in FAILURE_STATUSES
    ]
    coverage_gaps = unresolved_tool_coverage_gaps(tool_calls)
    truncated_tools = [
        str(row.get("call_id") or "")
        for row in tool_calls
        if int(row.get("truncated") or 0) == 1
    ]
    read_only_violations = [
        str(row.get("call_id") or "")
        for row in tool_calls
        if int(row.get("read_only") or 0) != 1
    ]
    successful_tools = [
        str(row.get("call_id") or "")
        for row in tool_calls
        if normalize_status(row.get("status")) in SUCCESS_STATUSES
    ]
    read_only_tools = [
        str(row.get("call_id") or "")
        for row in tool_calls
        if int(row.get("read_only") or 0) == 1
    ]
    successful_read_only_call_bindings = []
    for row in tool_calls:
        if (
            normalize_status(row.get("status")) not in SUCCESS_STATUSES
            or int(row.get("read_only") or 0) != 1
        ):
            continue
        round_number = nonnegative_int(row.get("round_number"))
        call_id = str(row.get("call_id") or "")
        call_prefix = f"round-{round_number}-"
        successful_read_only_call_bindings.append(
            {
                "call_id": call_id,
                "round_number": round_number,
                "query_id": (
                    call_id[len(call_prefix) :]
                    if call_id.startswith(call_prefix)
                    else ""
                ),
                "backend": str(row.get("backend") or ""),
                "status": normalize_status(row.get("status")),
                "request_digest": str(row.get("request_digest") or ""),
                "result_digest": str(row.get("result_digest") or ""),
                "read_only": True,
            }
        )
    successful_read_only_call_bindings.sort(
        key=lambda item: (
            int(item["round_number"]),
            str(item["call_id"]),
        )
    )

    budget_violation_sources: dict[tuple[str, str], set[str]] = {}
    memory_promotions: list[dict[str, Any]] = []
    event_type_counts: collections.Counter[str] = collections.Counter()
    stages: set[str] = set()
    for event in events:
        event_type = str(event.get("event_type") or "")
        event_type_counts[event_type] += 1
        stages.add(str(event.get("stage") or ""))
        payload = safe_json(
            event.get("payload_json"),
            {},
            malformed,
            "event.payload_json",
        )
        if event_type in {"policy.budget", "queries.completed"}:
            key = (
                "violations"
                if event_type == "policy.budget"
                else "budget_violations"
            )
            values = payload.get(key)
            if isinstance(values, list):
                operation_id = budget_operation_id(event, payload)
                for value in values:
                    violation = str(value or "").strip()
                    if not violation:
                        continue
                    budget_violation_sources.setdefault(
                        (operation_id, violation),
                        set(),
                    ).add(event_type)
        elif event_type == "policy.memory-promotion":
            memory_promotions.append(
                {
                    "allowed": bool(payload.get("allowed")),
                    "requires_approval": bool(payload.get("requires_approval")),
                    "candidate_count": nonnegative_int(
                        payload.get("candidate_count")
                    ),
                    "reason": str(payload.get("reason") or "")[:500],
                }
            )

    budget_violations: collections.Counter[str] = collections.Counter(
        violation for _operation_id, violation in budget_violation_sources
    )
    budget_violation_operations = [
        {
            "operation_id": operation_id,
            "violation": violation,
            "sources": sorted(sources),
        }
        for (operation_id, violation), sources in sorted(
            budget_violation_sources.items()
        )
    ]
    reviewer = reviewer_result(model_calls, decisions, malformed)
    purpose_completion = model_purpose_completion(
        model_calls,
        reviewer,
    )
    reviewer.update(
        reviewer_completion_contract(reviewer, purpose_completion)
    )
    model_call_contract = canonical_model_call_contract(model_calls)
    route_consistency = model_route_consistency(
        run,
        events,
        model_calls,
        malformed,
    )
    skill_selection = skill_selection_attestation_result(
        run,
        events,
        malformed,
    )
    unresolved_hypotheses = sum(
        normalize_status(row.get("status"))
        in {"", "unknown", "unresolved", "open", "proposed"}
        for row in hypotheses
    )
    coverage_reasons: list[str] = []
    if not evidence:
        coverage_reasons.append("no-evidence-catalogue")
    if not model_calls:
        coverage_reasons.append("no-model-call-ledger")
    if not tool_calls:
        coverage_reasons.append("no-tool-call-ledger")
    elif not successful_tools:
        coverage_reasons.append("no-successful-tool-call-ledger")
    if coverage_gaps:
        coverage_reasons.append("tool-evidence-gap")
    if truncated_tools:
        coverage_reasons.append("truncated-tool-results")
    if len(source_classes) < 2:
        coverage_reasons.append("fewer-than-two-evidence-source-classes")
    if read_only_violations:
        coverage_reasons.append("non-read-only-tool-call")
    if reviewer["missing_reviewer_decision"]:
        coverage_reasons.append("reviewer-call-without-decision")
    if reviewer["completion_contract_satisfied"] is not True:
        coverage_reasons.append("reviewer-completion-contract-failed")
    if model_call_contract["valid"] is not True:
        coverage_reasons.append("noncanonical-model-call-contract")
    if purpose_completion["incomplete_purpose_count"]:
        coverage_reasons.append("model-purpose-incomplete")
    if purpose_completion["malformed_purpose_sequence_count"]:
        coverage_reasons.append("model-purpose-sequence-malformed")
    if purpose_completion["unexpected_unsuccessful_call_count"]:
        coverage_reasons.append("unexpected-unsuccessful-model-call")
    if route_consistency["authorization_failure_count"]:
        coverage_reasons.append("model-route-authorization-failure")
    if route_consistency["identity_mismatch_count"]:
        coverage_reasons.append("model-runtime-identity-mismatch")

    return {
        "run_id": run_id,
        "trace_id": str(run.get("trace_id") or ""),
        "correlation_id": str(run.get("correlation_id") or ""),
        "case_id": str(run.get("case_id") or ""),
        "alert_id": str(run.get("alert_id") or ""),
        "role": str(run.get("role") or ""),
        "task_kind": str(run.get("task_kind") or ""),
        "status": str(run.get("status") or ""),
        "stage": str(run.get("stage") or ""),
        "assigned_route": str(run.get("assigned_route") or ""),
        "assigned_reviewer_route": str(
            run.get("assigned_reviewer_route") or ""
        ),
        "policy_mode": str(run.get("policy_mode") or ""),
        "started_at": str(run.get("started_at") or ""),
        "completed_at": str(run.get("completed_at") or ""),
        "terminal_execution_summary": terminal_execution_summary(
            events,
            run.get("status"),
            malformed,
        ),
        "skill_selection_attestation": skill_selection,
        "integrity": verify_chain(
            run_id,
            events,
            hypotheses,
            run_status=str(run.get("status") or ""),
            ledgers=ledgers,
            require_ledger_manifest=require_ledger_manifest,
        ),
        "counts": {
            "events": len(events),
            "evidence": len(evidence),
            "hypotheses": len(hypotheses),
            "unresolved_hypotheses": unresolved_hypotheses,
            "decisions": len(decisions),
            "model_calls": len(model_calls),
            "tool_calls": len(tool_calls),
            "budget_reservations": len(budget_reservations),
        },
        "event_type_counts": dict(sorted(event_type_counts.items())),
        "stage_count": len({stage for stage in stages if stage}),
        "models": {
            "observed": sorted(
                {
                    str(row.get("observed_model") or row.get("requested_route") or "")
                    for row in model_calls
                    if str(
                        row.get("observed_model")
                        or row.get("requested_route")
                        or ""
                    )
                }
            ),
            "independent_review_calls": reviewer["model_call_count"],
            "successful_call_count": sum(
                normalize_status(row.get("status")) in SUCCESS_STATUSES
                for row in model_calls
            ),
            "successful_primary_call_count": sum(
                normalize_status(row.get("status")) in SUCCESS_STATUSES
                and int(row.get("independent_review") or 0) == 0
                for row in model_calls
            ),
            **purpose_completion,
            "model_call_contract": model_call_contract,
            "duration_ms": sum(
                nonnegative_int(row.get("duration_ms")) for row in model_calls
            ),
            "route_consistency": route_consistency,
        },
        "tools": {
            "backends": sorted(
                {
                    str(row.get("backend") or "unknown")
                    for row in tool_calls
                    if str(row.get("backend") or "")
                }
            ),
            "rejected_call_ids": rejected_tools[:MAX_REPORTED_IDS],
            "rejected_count": len(rejected_tools),
            "failed_call_ids": failed_tools[:MAX_REPORTED_IDS],
            "failed_count": len(failed_tools),
            "coverage_gap_call_ids": coverage_gaps[:MAX_REPORTED_IDS],
            "coverage_gap_count": len(coverage_gaps),
            "truncated_call_ids": truncated_tools[:MAX_REPORTED_IDS],
            "truncated_count": len(truncated_tools),
            "read_only_violation_call_ids": read_only_violations[
                :MAX_REPORTED_IDS
            ],
            "read_only_violation_count": len(read_only_violations),
            "successful_call_count": len(successful_tools),
            "read_only_call_count": len(read_only_tools),
            "successful_read_only_call_bindings": (
                successful_read_only_call_bindings
            ),
            "successful_read_only_call_bindings_sha256": digest_json(
                successful_read_only_call_bindings
            ),
        },
        "evidence": {
            "source_classes": source_classes,
            "distinct_source_classes": len(source_classes),
            "corroborating_count": sum(
                int(row.get("corroborating") or 0) == 1 for row in evidence
            ),
        },
        "reviewer": reviewer,
        "budget_violations": dict(sorted(budget_violations.items())),
        "budget_violation_operations": budget_violation_operations,
        "memory_promotions": memory_promotions,
        "coverage_gap_reasons": coverage_reasons,
    }


def counter_dict(counter: collections.Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def summarize(
    connection: sqlite3.Connection,
    db_path: Path,
    run_results: list[dict[str, Any]],
    available_tables: set[str],
    malformed: collections.Counter[str],
    selected_run_id: str | None,
    database_schema: int | None,
) -> dict[str, Any]:
    statuses: collections.Counter[str] = collections.Counter()
    roles: collections.Counter[str] = collections.Counter()
    task_kinds: collections.Counter[str] = collections.Counter()
    policy_modes: collections.Counter[str] = collections.Counter()
    model_names: collections.Counter[str] = collections.Counter()
    model_providers: collections.Counter[str] = collections.Counter()
    model_purposes: collections.Counter[str] = collections.Counter()
    model_statuses: collections.Counter[str] = collections.Counter()
    tool_backends: collections.Counter[str] = collections.Counter()
    tool_capabilities: collections.Counter[str] = collections.Counter()
    tool_statuses: collections.Counter[str] = collections.Counter()
    tool_coverage: collections.Counter[str] = collections.Counter()
    source_classes: collections.Counter[str] = collections.Counter()
    trust_tiers: collections.Counter[str] = collections.Counter()
    review_disputes: collections.Counter[str] = collections.Counter()
    budget_names: collections.Counter[str] = collections.Counter()
    memory_reasons: collections.Counter[str] = collections.Counter()
    coverage_reasons: collections.Counter[str] = collections.Counter()
    route_authorization_reasons: collections.Counter[str] = (
        collections.Counter()
    )
    model_identity_reasons: collections.Counter[str] = collections.Counter()

    total_events = total_evidence = total_hypotheses = total_decisions = 0
    total_model_calls = total_model_ms = independent_review_calls = 0
    total_tool_calls = successful_tools = read_only_tools = 0
    rejected_tools = failed_tools = 0
    coverage_gap_tools = truncated_tools = read_only_violations = 0
    corroborating_evidence = 0
    reviewer_runs = comparable_reviews = reviewer_disagreements = 0
    missing_reviewer_decisions = 0
    reviewer_completion_failure_runs = 0
    budget_violation_runs = 0
    budget_violation_operation_count = 0
    memory_decisions = memory_allowed = memory_blocked = 0
    memory_requires_approval = memory_candidates = 0
    integrity_invalid_ids: list[str] = []
    coverage_gap_ids: list[str] = []
    source_diversity_values: list[int] = []
    route_authorization_failures = route_authorization_denials = 0
    model_observation_denials = 0
    route_authorization_unverified = model_identity_mismatches = 0
    model_identity_unverified = 0
    model_purpose_count = terminally_successful_model_purposes = 0
    incomplete_model_purposes = exact_reviewer_repairs = 0
    superseded_validation_failures = unexpected_unsuccessful_model_calls = 0
    malformed_model_purpose_sequences = 0
    noncanonical_model_calls = invalid_model_call_contract_runs = 0
    route_authorization_failure_run_ids: list[str] = []
    model_identity_failure_run_ids: list[str] = []
    skill_attestation_present = skill_attestation_valid = 0
    skill_attestation_ready = skill_attestation_legacy = 0
    skill_attestation_unavailable = 0
    skill_attestation_invalid_run_ids: list[str] = []

    for result in run_results:
        run_id = result["run_id"]
        skill_attestation = result["skill_selection_attestation"]
        skill_attestation_present += int(skill_attestation["present"])
        skill_attestation_valid += int(skill_attestation["valid"])
        skill_attestation_ready += int(skill_attestation["mandatory_ready"])
        skill_attestation_legacy += int(skill_attestation["legacy"])
        skill_attestation_unavailable += int(
            not skill_attestation["available"]
        )
        if not skill_attestation["valid"]:
            skill_attestation_invalid_run_ids.append(run_id)
        statuses[normalize_status(result["status"])] += 1
        roles[result["role"] or "unknown"] += 1
        task_kinds[result["task_kind"] or "unknown"] += 1
        policy_modes[result["policy_mode"] or "unknown"] += 1
        total_events += result["counts"]["events"]
        total_evidence += result["counts"]["evidence"]
        total_hypotheses += result["counts"]["hypotheses"]
        total_decisions += result["counts"]["decisions"]
        total_model_calls += result["counts"]["model_calls"]
        total_tool_calls += result["counts"]["tool_calls"]
        successful_tools += result["tools"]["successful_call_count"]
        read_only_tools += result["tools"]["read_only_call_count"]
        total_model_ms += result["models"]["duration_ms"]
        independent_review_calls += result["models"][
            "independent_review_calls"
        ]
        model_purpose_count += result["models"]["purpose_count"]
        terminally_successful_model_purposes += result["models"][
            "terminally_successful_purpose_count"
        ]
        incomplete_model_purposes += result["models"][
            "incomplete_purpose_count"
        ]
        exact_reviewer_repairs += result["models"][
            "exact_reviewer_repair_count"
        ]
        superseded_validation_failures += result["models"][
            "superseded_validation_failure_count"
        ]
        unexpected_unsuccessful_model_calls += result["models"][
            "unexpected_unsuccessful_call_count"
        ]
        malformed_model_purpose_sequences += result["models"][
            "malformed_purpose_sequence_count"
        ]
        model_call_contract = result["models"]["model_call_contract"]
        noncanonical_model_calls += model_call_contract[
            "noncanonical_model_call_count"
        ]
        if model_call_contract["valid"] is not True:
            invalid_model_call_contract_runs += 1
        route_consistency = result["models"]["route_consistency"]
        route_authorization_failures += route_consistency[
            "authorization_failure_count"
        ]
        route_authorization_denials += route_consistency[
            "authorization_denied_event_count"
        ]
        model_observation_denials += route_consistency[
            "observation_denied_event_count"
        ]
        route_authorization_unverified += route_consistency[
            "authorization_unverified_call_count"
        ]
        model_identity_mismatches += route_consistency[
            "identity_mismatch_count"
        ]
        model_identity_unverified += route_consistency[
            "identity_unverified_call_count"
        ]
        if route_consistency["authorization_failure_count"]:
            route_authorization_failure_run_ids.append(run_id)
        if route_consistency["identity_mismatch_count"]:
            model_identity_failure_run_ids.append(run_id)
        for failure in route_consistency["authorization_failures"]:
            route_authorization_reasons.update(failure["reasons"])
        for failure in route_consistency["identity_failures"]:
            model_identity_reasons.update(failure["reasons"])
        rejected_tools += result["tools"]["rejected_count"]
        failed_tools += result["tools"]["failed_count"]
        coverage_gap_tools += result["tools"]["coverage_gap_count"]
        truncated_tools += result["tools"]["truncated_count"]
        read_only_violations += result["tools"]["read_only_violation_count"]
        corroborating_evidence += result["evidence"]["corroborating_count"]
        source_diversity_values.append(
            result["evidence"]["distinct_source_classes"]
        )
        if not result["integrity"]["valid"]:
            integrity_invalid_ids.append(run_id)
        if result["coverage_gap_reasons"]:
            coverage_gap_ids.append(run_id)
            coverage_reasons.update(result["coverage_gap_reasons"])
        for name, count in result["budget_violations"].items():
            budget_names[name] += count
        if result["budget_violations"]:
            budget_violation_runs += 1
        budget_violation_operation_count += len(
            result["budget_violation_operations"]
        )
        reviewer = result["reviewer"]
        if reviewer["model_call_count"]:
            reviewer_runs += 1
        if reviewer["decision_comparable"]:
            comparable_reviews += 1
        if reviewer["material_disagreement"]:
            reviewer_disagreements += 1
            review_disputes.update(reviewer["disputed_fields"])
        if reviewer["missing_reviewer_decision"]:
            missing_reviewer_decisions += 1
        if reviewer["completion_contract_satisfied"] is not True:
            reviewer_completion_failure_runs += 1
        for promotion in result["memory_promotions"]:
            memory_decisions += 1
            memory_candidates += promotion["candidate_count"]
            if promotion["allowed"]:
                memory_allowed += 1
            else:
                memory_blocked += 1
            if promotion["requires_approval"]:
                memory_requires_approval += 1
            memory_reasons[promotion["reason"] or "unspecified"] += 1

        for row in rows_for_run(
            connection,
            available_tables,
            "harness_model_calls",
            run_id,
            "created_at, call_id",
        ):
            model_names[
                str(
                    row.get("observed_model")
                    or row.get("requested_route")
                    or "unknown"
                )
            ] += 1
            model_providers[str(row.get("observed_provider") or "unknown")] += 1
            model_purposes[str(row.get("purpose") or "unknown")] += 1
            model_statuses[normalize_status(row.get("status")) or "unknown"] += 1
        for row in rows_for_run(
            connection,
            available_tables,
            "harness_tool_calls",
            run_id,
            "round_number, call_id",
        ):
            tool_backends[str(row.get("backend") or "unknown")] += 1
            tool_capabilities[str(row.get("capability") or "unknown")] += 1
            tool_statuses[normalize_status(row.get("status")) or "unknown"] += 1
            tool_coverage[normalize_status(row.get("coverage")) or "unknown"] += 1
        for row in rows_for_run(
            connection,
            available_tables,
            "harness_evidence",
            run_id,
            "evidence_ref",
        ):
            source_classes[str(row.get("source_class") or "unknown")] += 1
            trust_tiers[str(row.get("trust_tier") or "unknown")] += 1

    run_count = len(run_results)
    terminal_runs = sum(
        count for status, count in statuses.items() if status in TERMINAL_STATUSES
    )
    succeeded_runs = statuses.get("succeeded", 0)
    source_diversity_average = (
        round(sum(source_diversity_values) / len(source_diversity_values), 3)
        if source_diversity_values
        else None
    )
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now(),
        "database": str(db_path.expanduser()),
        "selected_run_id": selected_run_id,
        "run_count": run_count,
        "completion": {
            "status_counts": counter_dict(statuses),
            "terminal_runs": terminal_runs,
            "terminal_rate": ratio(terminal_runs, run_count),
            "succeeded_runs": succeeded_runs,
            "success_rate": ratio(succeeded_runs, run_count),
        },
        "integrity": {
            "all_chains_valid": not integrity_invalid_ids and run_count > 0,
            "valid_run_count": run_count - len(integrity_invalid_ids),
            "invalid_run_count": len(integrity_invalid_ids),
            "invalid_run_ids": integrity_invalid_ids[:MAX_REPORTED_IDS],
            "event_count": total_events,
        },
        "workload": {
            "role_counts": counter_dict(roles),
            "task_kind_counts": counter_dict(task_kinds),
            "policy_mode_counts": counter_dict(policy_modes),
        },
        "skill_selection_attestation": {
            "present_run_count": skill_attestation_present,
            "valid_run_count": skill_attestation_valid,
            "mandatory_ready_run_count": skill_attestation_ready,
            "legacy_run_count": skill_attestation_legacy,
            "unavailable_run_count": skill_attestation_unavailable,
            "invalid_run_count": len(skill_attestation_invalid_run_ids),
            "invalid_run_ids": skill_attestation_invalid_run_ids[
                :MAX_REPORTED_IDS
            ],
        },
        "models": {
            "call_count": total_model_calls,
            "calls_per_run": ratio(total_model_calls, run_count),
            "duration_ms": total_model_ms,
            "average_duration_ms": (
                round(total_model_ms / total_model_calls)
                if total_model_calls
                else None
            ),
            "independent_review_call_count": independent_review_calls,
            "purpose_count": model_purpose_count,
            "terminally_successful_purpose_count": (
                terminally_successful_model_purposes
            ),
            "incomplete_purpose_count": incomplete_model_purposes,
            "exact_reviewer_repair_count": exact_reviewer_repairs,
            "superseded_validation_failure_count": (
                superseded_validation_failures
            ),
            "unexpected_unsuccessful_call_count": (
                unexpected_unsuccessful_model_calls
            ),
            "malformed_purpose_sequence_count": (
                malformed_model_purpose_sequences
            ),
            "noncanonical_call_count": noncanonical_model_calls,
            "invalid_call_contract_run_count": (
                invalid_model_call_contract_runs
            ),
            "by_model": counter_dict(model_names),
            "by_provider": counter_dict(model_providers),
            "by_purpose": counter_dict(model_purposes),
            "by_status": counter_dict(model_statuses),
            "route_authorization": {
                "failure_count": route_authorization_failures,
                "failure_run_count": len(
                    route_authorization_failure_run_ids
                ),
                "failure_run_ids": route_authorization_failure_run_ids[
                    :MAX_REPORTED_IDS
                ],
                "denied_event_count": route_authorization_denials,
                "observation_denied_event_count": (
                    model_observation_denials
                ),
                "unverified_call_count": route_authorization_unverified,
                "reason_counts": counter_dict(
                    route_authorization_reasons
                ),
            },
            "runtime_identity": {
                "mismatch_count": model_identity_mismatches,
                "mismatch_run_count": len(model_identity_failure_run_ids),
                "mismatch_run_ids": model_identity_failure_run_ids[
                    :MAX_REPORTED_IDS
                ],
                "unverified_call_count": model_identity_unverified,
                "reason_counts": counter_dict(model_identity_reasons),
            },
        },
        "tools": {
            "call_count": total_tool_calls,
            "successful_call_count": successful_tools,
            "read_only_call_count": read_only_tools,
            "calls_per_run": ratio(total_tool_calls, run_count),
            "rejected_count": rejected_tools,
            "rejection_rate": ratio(rejected_tools, total_tool_calls),
            "failed_count": failed_tools,
            "failure_rate": ratio(failed_tools, total_tool_calls),
            "coverage_gap_count": coverage_gap_tools,
            "coverage_gap_rate": ratio(coverage_gap_tools, total_tool_calls),
            "truncated_count": truncated_tools,
            "truncation_rate": ratio(truncated_tools, total_tool_calls),
            "read_only_violation_count": read_only_violations,
            "by_backend": counter_dict(tool_backends),
            "by_capability": counter_dict(tool_capabilities),
            "by_status": counter_dict(tool_statuses),
            "by_coverage": counter_dict(tool_coverage),
        },
        "evidence": {
            "catalogued_count": total_evidence,
            "corroborating_count": corroborating_evidence,
            "hypothesis_count": total_hypotheses,
            "decision_count": total_decisions,
            "source_class_counts": counter_dict(source_classes),
            "trust_tier_counts": counter_dict(trust_tiers),
            "average_distinct_source_classes_per_run": source_diversity_average,
            "minimum_distinct_source_classes_per_run": (
                min(source_diversity_values) if source_diversity_values else None
            ),
            "runs_with_fewer_than_two_source_classes": sum(
                value < 2 for value in source_diversity_values
            ),
        },
        "reviewer": {
            "runs_with_reviewer_calls": reviewer_runs,
            "comparable_decision_runs": comparable_reviews,
            "material_disagreement_runs": reviewer_disagreements,
            "material_disagreement_rate": ratio(
                reviewer_disagreements, comparable_reviews
            ),
            "missing_reviewer_decision_runs": missing_reviewer_decisions,
            "completion_contract_failure_runs": (
                reviewer_completion_failure_runs
            ),
            "disputed_field_counts": counter_dict(review_disputes),
        },
        "budgets": {
            "violation_runs": budget_violation_runs,
            "violation_run_rate": ratio(budget_violation_runs, run_count),
            "violation_operation_count": budget_violation_operation_count,
            "violation_counts": counter_dict(budget_names),
        },
        "memory_promotion": {
            "decision_count": memory_decisions,
            "allowed_count": memory_allowed,
            "blocked_count": memory_blocked,
            "requires_approval_count": memory_requires_approval,
            "candidate_count": memory_candidates,
            "reason_counts": counter_dict(memory_reasons),
        },
        "coverage": {
            "runs_with_gaps": len(coverage_gap_ids),
            "run_gap_rate": ratio(len(coverage_gap_ids), run_count),
            "run_ids": coverage_gap_ids[:MAX_REPORTED_IDS],
            "reason_counts": counter_dict(coverage_reasons),
        },
        "data_quality": {
            "database_schema_version": database_schema,
            "available_tables": sorted(available_tables),
            "missing_optional_tables": sorted(OPTIONAL_TABLES - available_tables),
            "malformed_json_counts": counter_dict(malformed),
        },
        "runs": run_results,
    }


def evaluate_database(
    db_path: Path,
    run_id: str | None = None,
) -> dict[str, Any]:
    malformed: collections.Counter[str] = collections.Counter()
    with contextlib.closing(connect_read_only(db_path)) as connection:
        available = table_names(connection)
        missing = REQUIRED_TABLES - available
        if missing:
            raise EvaluationError(
                "harness database is missing required table(s): "
                + ", ".join(sorted(missing))
            )
        schema_version = database_schema_version(connection, available)
        require_ledger_manifest = (
            schema_version is not None
            and schema_version >= CURRENT_SQL_SCHEMA_VERSION
        )
        runs = selected_runs(connection, run_id)
        results = [
            evaluate_run(
                connection,
                available,
                run,
                malformed,
                require_ledger_manifest=require_ledger_manifest,
            )
            for run in runs
        ]
        return summarize(
            connection,
            db_path,
            results,
            available,
            malformed,
            selected_run_id=run_id,
            database_schema=schema_version,
        )


def atomic_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def human_report(report: Mapping[str, Any]) -> str:
    completion = report["completion"]
    integrity = report["integrity"]
    skill_selection = report["skill_selection_attestation"]
    models = report["models"]
    tools = report["tools"]
    evidence = report["evidence"]
    reviewer = report["reviewer"]
    budgets = report["budgets"]
    memory = report["memory_promotion"]
    coverage = report["coverage"]
    return "\n".join(
        [
            "Onion Sentinel harness trace evaluation",
            f"Runs: {report['run_count']} | statuses: "
            f"{json.dumps(completion['status_counts'], sort_keys=True)}",
            f"Completion: {completion['terminal_rate']} terminal | "
            f"{completion['success_rate']} succeeded",
            f"Integrity: {integrity['valid_run_count']} valid, "
            f"{integrity['invalid_run_count']} invalid "
            f"({integrity['event_count']} events)",
            "Skill selection: "
            f"{skill_selection['mandatory_ready_run_count']} evaluation-ready, "
            f"{skill_selection['legacy_run_count']} legacy, "
            f"{skill_selection['invalid_run_count']} invalid",
            f"Models: {models['call_count']} calls, "
            f"{models['independent_review_call_count']} reviewer calls",
            f"Tools: {tools['call_count']} calls, "
            f"{tools['rejected_count']} rejected, "
            f"{tools['failed_count']} failed, "
            f"{tools['coverage_gap_count']} coverage gaps, "
            f"{tools['truncated_count']} truncated",
            f"Evidence: {evidence['catalogued_count']} references, "
            f"{evidence['average_distinct_source_classes_per_run']} "
            "average source classes/run",
            f"Reviewer: {reviewer['material_disagreement_runs']} material "
            f"disagreements across {reviewer['comparable_decision_runs']} "
            "comparable runs",
            f"Budgets: {budgets['violation_runs']} violating runs | "
            f"{json.dumps(budgets['violation_counts'], sort_keys=True)}",
            f"Memory: {memory['allowed_count']} allowed, "
            f"{memory['blocked_count']} blocked, "
            f"{memory['requires_approval_count']} awaiting approval",
            f"Coverage: {coverage['runs_with_gaps']} runs with gaps | "
            f"{json.dumps(coverage['reason_counts'], sort_keys=True)}",
        ]
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--run-id", help="Evaluate exactly one harness run")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete machine-readable JSON report",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Write the complete JSON report to an owner-only file",
    )
    parser.add_argument(
        "--fail-on-invalid-chain",
        action="store_true",
        help="Exit 1 if any selected trace has a broken event chain",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = evaluate_database(args.db, args.run_id)
        if args.out:
            atomic_private_json(args.out, report)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(human_report(report))
            if args.out:
                print(f"JSON report: {args.out.expanduser()}")
        if args.fail_on_invalid_chain and not report["integrity"]["all_chains_valid"]:
            return 1
        return 0
    except (EvaluationError, sqlite3.Error, OSError, ValueError) as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
