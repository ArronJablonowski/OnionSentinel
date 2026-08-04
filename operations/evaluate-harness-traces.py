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
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote


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


def skill_selection_attestation_result(
    run: Mapping[str, Any],
    events: Iterable[Mapping[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, Any]:
    """Validate and project the content-free skill selection attestation."""
    started_event = next(
        (
            event
            for event in events
            if str(event.get("event_type") or "") == "run.started"
        ),
        None,
    )
    if started_event is None:
        return {
            "present": False,
            "legacy": True,
            "valid": True,
            "available": False,
            "job_digest_bound": False,
            "mandatory_ready": False,
            "registry_version": None,
            "registry_sha256": "",
            "selected": [],
            "selected_count": 0,
            "truncated": False,
            "advisory_mode": "",
            "error_count": 0,
            "errors": [],
        }
    payload = safe_json(
        started_event.get("payload_json"),
        {},
        malformed,
        "event.run_started.payload_json",
    )
    if "skill_selection_attestation" not in payload:
        # Traces written before skill attestation remain readable and valid.
        return {
            "present": False,
            "legacy": True,
            "valid": True,
            "available": False,
            "job_digest_bound": False,
            "mandatory_ready": False,
            "registry_version": None,
            "registry_sha256": "",
            "selected": [],
            "selected_count": 0,
            "truncated": False,
            "advisory_mode": "",
            "error_count": 0,
            "errors": [],
        }

    raw = payload.get("skill_selection_attestation")
    errors: list[str] = []
    if not isinstance(raw, dict):
        raw = {}
        errors.append("skill selection attestation is not an object")
    unexpected_keys = sorted(set(raw) - SKILL_SELECTION_ATTESTATION_KEYS)
    missing_keys = sorted(SKILL_SELECTION_ATTESTATION_KEYS - set(raw))
    if unexpected_keys:
        errors.append("skill selection attestation has unexpected fields")
    if missing_keys:
        errors.append("skill selection attestation is missing fields")

    registry_version = raw.get("registry_version")
    if (
        not isinstance(registry_version, int)
        or isinstance(registry_version, bool)
        or registry_version < 0
    ):
        registry_version = None
        errors.append("skill selection registry version is invalid")
    registry_sha256 = str(raw.get("registry_sha256") or "")
    advisory_mode = str(raw.get("advisory_mode") or "")
    selected_raw = raw.get("selected")
    selected: list[dict[str, Any]] = []
    identities: set[tuple[str, int]] = set()
    if (
        not isinstance(selected_raw, list)
        or len(selected_raw) > MAX_ATTESTED_INVESTIGATION_SKILLS
    ):
        errors.append("skill selection identities are not a bounded list")
        selected_raw = []
    for item in selected_raw:
        if not isinstance(item, dict):
            errors.append("selected skill identity is not an object")
            continue
        if set(item) != {"id", "version", "skill_sha256"}:
            errors.append("selected skill identity has invalid fields")
        skill_id = str(item.get("id") or "")
        version = item.get("version")
        skill_sha256 = str(item.get("skill_sha256") or "")
        identity_valid = True
        if not SKILL_SELECTION_ID_RE.fullmatch(skill_id):
            errors.append("selected skill id is invalid")
            identity_valid = False
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
        ):
            errors.append("selected skill version is invalid")
            identity_valid = False
        if not SHA256_RE.fullmatch(skill_sha256):
            errors.append("selected skill digest is invalid")
            identity_valid = False
        if not identity_valid:
            continue
        identity = (skill_id, version)
        if identity in identities:
            errors.append("selected skill identity is duplicated")
            continue
        identities.add(identity)
        selected.append(
            {
                "id": skill_id,
                "version": version,
                "skill_sha256": skill_sha256,
            }
        )
    expected_order = sorted(
        selected,
        key=lambda item: (
            str(item["id"]),
            int(item["version"]),
            str(item["skill_sha256"]),
        ),
    )
    if selected != expected_order:
        errors.append("selected skill identities are not in canonical order")
    selected_count = raw.get("selected_count")
    if (
        not isinstance(selected_count, int)
        or isinstance(selected_count, bool)
        or selected_count != len(selected_raw)
        or selected_count != len(selected)
    ):
        errors.append("skill selection count does not match identities")
        selected_count = len(selected)
    truncated = raw.get("truncated")
    if not isinstance(truncated, bool):
        errors.append("skill selection truncation flag is invalid")
        truncated = False
    available = (
        registry_version is not None
        and registry_version > 0
        and SHA256_RE.fullmatch(registry_sha256) is not None
        and advisory_mode == "advisory_only"
    )
    if advisory_mode not in {"advisory_only", "unavailable"}:
        errors.append("skill selection advisory mode is invalid")
    if advisory_mode == "advisory_only" and not SHA256_RE.fullmatch(
        registry_sha256
    ):
        errors.append("skill selection registry digest is invalid")
    if advisory_mode == "advisory_only" and (
        registry_version is None or registry_version < 1
    ):
        errors.append("version-zero skill registry is unavailable")
    if advisory_mode == "unavailable" and (
        registry_version != 0
        or selected
        or selected_count
        or truncated
        or (
            registry_sha256
            and SHA256_RE.fullmatch(registry_sha256) is None
        )
    ):
        errors.append("unavailable skill selection is not empty")

    job_digest_bound = False
    if all(field in run for field in JOB_ENVELOPE_DIGEST_FIELDS):
        expected_job = {
            field: run.get(field) for field in JOB_ENVELOPE_DIGEST_FIELDS
        }
        expected_job["skill_selection_attestation"] = {
            key: raw.get(key)
            for key in SKILL_SELECTION_ATTESTATION_KEYS
        }
        expected_digest = digest_json(expected_job)
        stored_digest = str(run.get("job_digest") or "")
        event_digest = str(payload.get("job_digest") or "")
        job_digest_bound = (
            SHA256_RE.fullmatch(stored_digest) is not None
            and stored_digest == expected_digest
            and event_digest == stored_digest
        )
        if not job_digest_bound:
            errors.append("skill selection attestation is not job-digest bound")
    else:
        errors.append("skill selection job identity is incomplete")

    errors = list(dict.fromkeys(errors))
    valid = not errors
    return {
        "present": True,
        "legacy": False,
        "valid": valid,
        "available": available,
        "job_digest_bound": job_digest_bound,
        "mandatory_ready": valid and available and job_digest_bound,
        "registry_version": registry_version,
        "registry_sha256": registry_sha256,
        "selected": selected,
        "selected_count": selected_count,
        "truncated": truncated,
        "advisory_mode": advisory_mode,
        "error_count": len(errors),
        "errors": errors[:MAX_REPORTED_IDS],
    }


def connect_read_only(path: Path) -> sqlite3.Connection:
    """Open an existing SQLite database without creating or migrating it."""
    try:
        resolved = path.expanduser().resolve(strict=True)
    except FileNotFoundError as exc:
        raise EvaluationError(f"harness database does not exist: {path}") from exc
    if not resolved.is_file():
        raise EvaluationError(f"harness database is not a regular file: {resolved}")
    uri = f"file:{quote(str(resolved), safe='/')}?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        # Hold one consistent read snapshot across run, event, and aggregate
        # queries even while a production worker appends newer traces.
        connection.execute("BEGIN")
        return connection
    except sqlite3.Error as exc:
        if connection is not None:
            connection.close()
        raise EvaluationError(f"cannot open harness database read-only: {exc}") from exc


def table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }


def database_schema_version(
    connection: sqlite3.Connection,
    available_tables: set[str],
) -> int | None:
    if "harness_metadata" not in available_tables:
        return None
    try:
        row = connection.execute(
            """
            SELECT value
            FROM harness_metadata
            WHERE key = 'schema_version'
            """
        ).fetchone()
    except sqlite3.Error as exc:
        raise EvaluationError(
            f"cannot read harness database schema version: {exc}"
        ) from exc
    if row is None:
        return None
    try:
        version = int(row[0])
    except (TypeError, ValueError) as exc:
        raise EvaluationError(
            "harness database schema version is invalid"
        ) from exc
    if version > CURRENT_SQL_SCHEMA_VERSION:
        raise EvaluationError(
            "harness database was created by a newer runtime"
        )
    return version


def selected_runs(
    connection: sqlite3.Connection,
    run_id: str | None,
) -> list[dict[str, Any]]:
    if run_id:
        rows = connection.execute(
            "SELECT * FROM harness_runs WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        if not rows:
            raise EvaluationError(f"unknown harness run_id: {run_id}")
    else:
        rows = connection.execute(
            "SELECT * FROM harness_runs ORDER BY started_at, run_id"
        ).fetchall()
    return [dict(row) for row in rows]


def rows_for_run(
    connection: sqlite3.Connection,
    available_tables: set[str],
    table: str,
    run_id: str,
    order_by: str,
) -> list[dict[str, Any]]:
    if table not in available_tables:
        return []
    # Table and ordering names are closed constants owned by this program.
    rows = connection.execute(
        f"SELECT * FROM {table} WHERE run_id = ? ORDER BY {order_by}",
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def hypothesis_manifest_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    return digest_json(
        [
            {
                "hypothesis_id": str(row["hypothesis_id"]),
                "statement_digest": str(row["statement_digest"]),
                "status": str(row["status"]),
                "supporting_refs_json": str(row["supporting_refs_json"]),
                "contradicting_refs_json": str(
                    row["contradicting_refs_json"]
                ),
                "next_discriminator_digest": digest_json(
                    str(row["next_discriminator"])
                ),
                "revision": int(row["revision"]),
            }
            for row in rows
        ]
    )


def ledger_manifest(
    ledgers: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    schema: str = LEDGER_MANIFEST_SCHEMA,
) -> dict[str, Any]:
    if schema == LEDGER_MANIFEST_SCHEMA:
        run_identity_columns = RUN_IDENTITY_COLUMNS
    elif schema == LEDGER_MANIFEST_SCHEMA_V1:
        run_identity_columns = LEGACY_RUN_IDENTITY_COLUMNS_V1
    else:
        raise EvaluationError(
            f"unsupported ledger manifest schema: {schema}"
        )
    normalized_ledgers: dict[str, list[dict[str, Any]]] = {}
    for table, source_rows in ledgers.items():
        rows = [dict(row) for row in source_rows]
        if table == "harness_run_identity":
            rows = [
                {
                    key: row[key]
                    for key in run_identity_columns
                    if key in row
                }
                for row in rows
            ]
        normalized_ledgers[table] = rows
    return {
        "schema": schema,
        "tables": {
            table: {
                "count": len(rows),
                "sha256": digest_json(rows),
            }
            for table, rows in sorted(normalized_ledgers.items())
        },
    }


def verify_chain(
    run_id: str,
    events: Iterable[Mapping[str, Any]],
    hypotheses: Iterable[Mapping[str, Any]] = (),
    *,
    run_status: str = "",
    ledgers: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    require_ledger_manifest: bool = False,
) -> dict[str, Any]:
    events = list(events)
    hypotheses = list(hypotheses)
    previous = "0" * 64
    expected_sequence = 1
    errors: list[str] = []
    error_count = 0
    event_count = 0

    def record_error(message: str) -> None:
        nonlocal error_count
        error_count += 1
        if len(errors) < MAX_REPORTED_IDS:
            errors.append(message)

    for row in events:
        event_count += 1
        try:
            sequence = int(row.get("sequence"))
            payload_json = str(row.get("payload_json"))
            payload_digest = hashlib.sha256(
                payload_json.encode("utf-8")
            ).hexdigest()
            body = {
                "run_id": run_id,
                "sequence": sequence,
                "idempotency_key": row.get("idempotency_key"),
                "event_type": row.get("event_type"),
                "stage": row.get("stage"),
                "created_at": row.get("created_at"),
                "payload_sha256": row.get("payload_sha256"),
                "previous_event_sha256": row.get("previous_event_sha256"),
            }
            expected_hash = digest_json(body)
            if sequence != expected_sequence:
                record_error(f"sequence gap at {sequence}")
            if row.get("payload_sha256") != payload_digest:
                record_error(f"payload digest mismatch at {sequence}")
            if row.get("previous_event_sha256") != previous:
                record_error(f"previous hash mismatch at {sequence}")
            if row.get("event_sha256") != expected_hash:
                record_error(f"event hash mismatch at {sequence}")
            if row.get("event_id") != f"evt-{expected_hash[:32]}":
                record_error(f"event id mismatch at {sequence}")
            previous = str(row.get("event_sha256") or "")
            expected_sequence += 1
        except (TypeError, ValueError, OverflowError) as exc:
            record_error(f"malformed event at position {event_count}: {exc}")
    if event_count == 0:
        record_error("run has no events")
    latest_hypothesis_event = next(
        (
            row
            for row in reversed(events)
            if row.get("event_type") == "hypotheses.updated"
        ),
        None,
    )
    if latest_hypothesis_event is not None:
        try:
            payload = json.loads(
                str(latest_hypothesis_event.get("payload_json") or "")
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        expected_manifest = str(payload.get("manifest_digest") or "")
        actual_manifest = hypothesis_manifest_digest(hypotheses)
        if not expected_manifest:
            record_error("latest hypothesis event has no manifest digest")
        elif expected_manifest != actual_manifest:
            record_error("hypothesis ledger manifest mismatch")
    ledger_manifest_bound = False
    ledger_manifest_schema = ""
    started_event = next(
        (
            row
            for row in events
            if row.get("event_type") == "run.started"
        ),
        None,
    )
    try:
        started_payload = (
            json.loads(str(started_event.get("payload_json") or ""))
            if started_event is not None
            else {}
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        started_payload = {}
    legacy_manifest_eligible = (
        started_event is not None
        and isinstance(started_payload, dict)
        and "assigned_reviewer_route" not in started_payload
    )
    normalized_run_status = normalize_status(run_status)
    if normalized_run_status in TERMINAL_STATUSES:
        terminal_event = next(
            (
                row
                for row in reversed(events)
                if row.get("event_type") == f"run.{normalized_run_status}"
            ),
            None,
        )
        if terminal_event is None:
            record_error("terminal run has no matching terminal event")
        else:
            try:
                terminal_payload = json.loads(
                    str(terminal_event.get("payload_json") or "")
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                terminal_payload = {}
            expected_ledger_manifest = terminal_payload.get(
                "ledger_manifest"
            )
            if not isinstance(expected_ledger_manifest, dict):
                if require_ledger_manifest:
                    record_error(
                        "terminal ledger manifest is missing or malformed"
                    )
            else:
                ledger_manifest_schema = str(
                    expected_ledger_manifest.get("schema") or ""
                )
                if ledger_manifest_schema not in (
                    SUPPORTED_LEDGER_MANIFEST_SCHEMAS
                ):
                    record_error(
                        "unsupported terminal ledger manifest schema"
                    )
                elif (
                    ledger_manifest_schema == LEDGER_MANIFEST_SCHEMA_V1
                    and not legacy_manifest_eligible
                ):
                    record_error(
                        "terminal ledger manifest schema downgrade"
                    )
                else:
                    ledger_manifest_bound = True
                    actual_ledger_manifest = ledger_manifest(
                        ledgers or {},
                        schema=ledger_manifest_schema,
                    )
            if ledger_manifest_bound:
                if digest_json(expected_ledger_manifest) != digest_json(
                    actual_ledger_manifest
                ):
                    record_error("terminal ledger manifest mismatch")
    return {
        "valid": error_count == 0,
        "event_count": event_count,
        "head_sha256": previous if event_count else "",
        "ledger_manifest_bound": ledger_manifest_bound,
        "ledger_manifest_schema": ledger_manifest_schema,
        "ledger_manifest_required": require_ledger_manifest,
        "error_count": error_count,
        "errors": errors,
    }


def decision_payloads(
    decisions: Iterable[Mapping[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for row in decisions:
        decision_id = str(row.get("decision_id") or "")
        decision_type = str(row.get("decision_type") or "")
        payload = safe_json(
            row.get("payload_json"),
            {},
            malformed,
            "decision.payload_json",
        )
        output[decision_id or decision_type] = payload
        if decision_type:
            output.setdefault(decision_type, payload)
    return output


def reviewer_result(
    model_calls: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, Any]:
    reviewer_calls = [
        row
        for row in model_calls
        if int(row.get("independent_review") or 0) == 1
        and str(row.get("purpose") or "") == REVIEWER_REPAIR_PURPOSE
        and str(row.get("call_id") or "") in REVIEWER_REPAIR_CALL_IDS
    ]
    payloads = decision_payloads(decisions, malformed)
    primary = payloads.get("primary")
    reviewer = payloads.get("independent-review")
    primary_decision_count = sum(
        str(row.get("decision_id") or "") == "primary"
        and str(row.get("decision_type") or "") == "primary-analysis"
        for row in decisions
    )
    reviewer_decision_count = sum(
        str(row.get("decision_id") or "") == "independent-review"
        and str(row.get("decision_type") or "") == "independent-review"
        for row in decisions
    )
    disputed_fields: list[str] = []
    if isinstance(primary, dict) and isinstance(reviewer, dict):
        disputed_fields = [
            field
            for field in MATERIAL_REVIEW_FIELDS
            if primary.get(field) != reviewer.get(field)
        ]
    return {
        "model_call_count": len(reviewer_calls),
        "completed_model_call_count": sum(
            normalize_status(row.get("status")) == "completed"
            for row in reviewer_calls
        ),
        "primary_decision_count": primary_decision_count,
        "reviewer_decision_count": reviewer_decision_count,
        "has_primary_decision": isinstance(primary, dict),
        "has_reviewer_decision": isinstance(reviewer, dict),
        "comparison_basis": (
            "primary_vs_independent-review"
            if isinstance(primary, dict) and isinstance(reviewer, dict)
            else ""
        ),
        "decision_comparable": (
            isinstance(primary, dict) and isinstance(reviewer, dict)
        ),
        "material_disagreement": bool(disputed_fields),
        "disputed_fields": disputed_fields,
        "missing_reviewer_decision": bool(reviewer_calls)
        and not isinstance(reviewer, dict),
    }


def reviewer_completion_contract(
    reviewer: Mapping[str, Any],
    purpose_completion: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail closed on incomplete reviewer evidence only when review ran."""

    call_count = nonnegative_int(reviewer.get("model_call_count"))
    exact_repair_count = nonnegative_int(
        purpose_completion.get("exact_reviewer_repair_count")
    )
    required = call_count > 0
    failures: list[str] = []
    if required:
        if nonnegative_int(reviewer.get("completed_model_call_count")) != 1:
            failures.append("completed-reviewer-call-count-not-one")
        if nonnegative_int(reviewer.get("primary_decision_count")) != 1:
            failures.append("primary-decision-count-not-one")
        if nonnegative_int(reviewer.get("reviewer_decision_count")) != 1:
            failures.append("reviewer-decision-count-not-one")
        if reviewer.get("has_primary_decision") is not True:
            failures.append("primary-decision-missing")
        if reviewer.get("has_reviewer_decision") is not True:
            failures.append("reviewer-decision-missing")
        if reviewer.get("decision_comparable") is not True:
            failures.append("reviewer-decision-not-comparable")
        if reviewer.get("missing_reviewer_decision") is not False:
            failures.append("reviewer-decision-marked-missing")
        if call_count != 1 + exact_repair_count:
            failures.append("reviewer-call-count-does-not-match-repair")
    return {
        "completion_contract_required": required,
        "completion_contract_satisfied": not failures,
        "completion_contract_failure_reasons": failures,
    }


def canonical_model_call_contract(
    model_calls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate the closed model-call grammar emitted by the current runtime."""

    ordered_calls = sorted(
        (
            (ordinal, row)
            for ordinal, row in enumerate(model_calls)
            if isinstance(row, dict)
        ),
        key=lambda item: (
            str(item[1].get("created_at") or ""),
            str(item[1].get("call_id") or ""),
            item[0],
        ),
    )
    facts: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    followup_rounds: list[int] = []
    query_planning_repair_rounds: list[int] = []
    primary_initial_count = 0
    query_planning_count = 0
    query_planning_repair_count = 0
    next_primary_round = 1
    canonical_count = 0
    for ordinal, row in ordered_calls:
        call_id = str(row.get("call_id") or "")
        purpose = str(row.get("purpose") or "")
        requested_route = str(row.get("requested_route") or "")
        status = normalize_status(row.get("status"))
        independent_review = int(row.get("independent_review") or 0) == 1
        reasons: list[str] = []
        followup_match = FOLLOWUP_CALL_RE.fullmatch(call_id)
        if call_id == PRIMARY_INITIAL_CALL_ID:
            primary_initial_count += 1
            if purpose != PRIMARY_INITIAL_PURPOSE:
                reasons.append("primary-initial-purpose-mismatch")
            if independent_review:
                reasons.append("primary-initial-marked-reviewer")
            if status != "completed":
                reasons.append("primary-initial-status-not-completed")
        elif call_id == QUERY_PLANNING_CALL_ID:
            query_planning_count += 1
            if purpose != QUERY_PLANNING_PURPOSE:
                reasons.append("query-planning-purpose-mismatch")
            if independent_review:
                reasons.append("query-planning-marked-reviewer")
            if status != "completed":
                reasons.append("query-planning-status-not-completed")
        elif call_id == QUERY_PLANNING_REPAIR_CALL_ID:
            query_planning_repair_count += 1
            # The runtime intentionally spends the current follow-up round on
            # this bounded repair. Its next ordinary call therefore retains
            # the following round number (repair-1, then followup-2).
            query_planning_repair_rounds.append(next_primary_round)
            next_primary_round += 1
            if purpose != QUERY_PLANNING_REPAIR_PURPOSE:
                reasons.append("query-planning-repair-purpose-mismatch")
            if independent_review:
                reasons.append("query-planning-repair-marked-reviewer")
            if status != "completed":
                reasons.append("query-planning-repair-status-not-completed")
        elif followup_match:
            round_number = int(followup_match.group(1))
            followup_rounds.append(round_number)
            if round_number != next_primary_round:
                reasons.append("primary-followup-round-out-of-sequence")
            next_primary_round += 1
            if purpose != (
                f"primary investigation follow-up round {round_number}"
            ):
                reasons.append("primary-followup-purpose-mismatch")
            if independent_review:
                reasons.append("primary-followup-marked-reviewer")
            if status != "completed":
                reasons.append("primary-followup-status-not-completed")
        elif call_id in REVIEWER_REPAIR_CALL_IDS:
            attempt = REVIEWER_REPAIR_CALL_IDS.index(call_id) + 1
            if purpose != REVIEWER_REPAIR_PURPOSE:
                reasons.append("reviewer-purpose-mismatch")
            if not independent_review:
                reasons.append("reviewer-call-not-marked-independent")
            allowed_statuses = (
                {"completed", VALIDATION_FAILED_STATUS}
                if attempt == 1
                else {"completed"}
            )
            if status not in allowed_statuses:
                reasons.append("reviewer-status-not-canonical")
        elif call_id in ADJUDICATION_CALL_IDS:
            attempt = ADJUDICATION_CALL_IDS.index(call_id) + 1
            if purpose != ADJUDICATION_PURPOSE:
                reasons.append("adjudication-purpose-mismatch")
            if not independent_review:
                reasons.append("adjudication-call-not-marked-independent")
            allowed_statuses = (
                {"completed", VALIDATION_FAILED_STATUS}
                if attempt == 1
                else {"completed"}
            )
            if status not in allowed_statuses:
                reasons.append("adjudication-status-not-canonical")
        else:
            reasons.append("unknown-model-call-id")
        if not requested_route:
            reasons.append("requested-route-missing")
        fact = {
            "call_id": call_id,
            "purpose": purpose,
            "requested_route": requested_route,
            "independent_review": independent_review,
            "status": status,
        }
        if len(facts) < MAX_RUNTIME_MODEL_CALLS:
            facts.append(fact)
        if reasons:
            if len(violations) < MAX_RUNTIME_MODEL_CALLS:
                violations.append(
                    {
                        "call_id": call_id or f"ordinal-{ordinal}",
                        "reasons": reasons,
                    }
                )
        else:
            canonical_count += 1

    global_reasons: list[str] = []
    if len(ordered_calls) > MAX_RUNTIME_MODEL_CALLS:
        global_reasons.append("model-call-budget-exceeded")
    if primary_initial_count != 1:
        global_reasons.append("primary-initial-count-not-one")
    if query_planning_count not in {0, 1}:
        global_reasons.append("query-planning-count-invalid")
    if query_planning_repair_count not in {0, 1}:
        global_reasons.append("query-planning-repair-count-invalid")
    unique_followups = sorted(set(followup_rounds))
    if len(unique_followups) != len(followup_rounds):
        global_reasons.append("duplicate-primary-followup-round")
    primary_rounds = sorted(
        followup_rounds + query_planning_repair_rounds
    )
    unique_primary_rounds = sorted(set(primary_rounds))
    if len(unique_primary_rounds) != len(primary_rounds):
        global_reasons.append("duplicate-primary-round-slot")
    if unique_primary_rounds and unique_primary_rounds != list(
        range(1, max(unique_primary_rounds) + 1)
    ):
        global_reasons.append("noncontiguous-primary-rounds")
    maximum_primary_rounds = 2 if query_planning_count else 3
    if len(unique_primary_rounds) > maximum_primary_rounds:
        global_reasons.append("too-many-primary-rounds")
    return {
        "schema": MODEL_CALL_CONTRACT_SCHEMA,
        "valid": not violations and not global_reasons,
        "model_call_count": len(ordered_calls),
        "canonical_model_call_count": canonical_count,
        "noncanonical_model_call_count": len(ordered_calls) - canonical_count,
        "primary_initial_call_count": primary_initial_count,
        "query_planning_call_count": query_planning_count,
        "query_planning_repair_call_count": query_planning_repair_count,
        "primary_followup_call_count": len(followup_rounds),
        "reviewer_model_call_count": sum(
            int(row.get("independent_review") or 0) == 1
            for _ordinal, row in ordered_calls
        ),
        "facts": facts,
        "facts_sha256": digest_json(facts),
        "violation_count": len(violations) + len(global_reasons),
        "violations": violations,
        "global_reasons": global_reasons,
    }


def model_purpose_completion(
    model_calls: list[dict[str, Any]],
    reviewer: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify bounded model retries without treating bad output as success.

    The runtime has one explicit schema-repair path: the independent reviewer
    may return one deterministically invalid response and then one successful
    repair. Every invocation remains in the budget and audit ledgers. No other
    failed call or duplicate purpose is allowed to hide behind a later success.
    """

    ordered_calls = sorted(
        (
            (ordinal, row)
            for ordinal, row in enumerate(model_calls)
            if isinstance(row, dict)
        ),
        key=lambda item: (
            str(item[1].get("created_at") or ""),
            str(item[1].get("call_id") or ""),
            item[0],
        ),
    )
    groups: dict[tuple[bool, str, str], list[dict[str, Any]]] = {}
    call_classifications: dict[str, str] = {}
    for ordinal, row in ordered_calls:
        independent_review = int(row.get("independent_review") or 0) == 1
        purpose = str(row.get("purpose") or "")
        requested_route = str(row.get("requested_route") or "")
        groups.setdefault(
            (independent_review, purpose, requested_route),
            [],
        ).append(row)
        call_id = str(row.get("call_id") or f"ordinal-{ordinal}")
        call_classifications[call_id] = (
            "successful"
            if normalize_status(row.get("status")) in SUCCESS_STATUSES
            else "unexpected-unsuccessful"
        )

    terminally_successful = 0
    exact_reviewer_repairs = 0
    exact_adjudication_repairs = 0
    superseded_validation_failures = 0
    malformed_sequences = 0
    purpose_summaries: list[dict[str, Any]] = []
    for (
        independent_review,
        purpose,
        requested_route,
    ), calls in groups.items():
        call_ids = [str(row.get("call_id") or "") for row in calls]
        statuses = [normalize_status(row.get("status")) for row in calls]
        terminal_success = bool(
            statuses and statuses[-1] in SUCCESS_STATUSES
        )
        if terminal_success:
            terminally_successful += 1

        adjudication_like = bool(
            purpose == ADJUDICATION_PURPOSE
            or any(
                call_id.startswith("disagreement-adjudication-")
                for call_id in call_ids
            )
        )
        reviewer_like = bool(
            (independent_review and not adjudication_like)
            or purpose == REVIEWER_REPAIR_PURPOSE
            or any(
                call_id.startswith("independent-review-")
                for call_id in call_ids
            )
        )
        valid_single = bool(
            len(calls) == 1
            and terminal_success
            and bool(purpose)
            and bool(requested_route)
            and (
                not reviewer_like and not adjudication_like
                or (
                    independent_review
                    and purpose == REVIEWER_REPAIR_PURPOSE
                    and call_ids == [REVIEWER_REPAIR_CALL_IDS[0]]
                    and reviewer.get("has_reviewer_decision") is True
                )
                or (
                    independent_review
                    and purpose == ADJUDICATION_PURPOSE
                    and call_ids == [ADJUDICATION_CALL_IDS[0]]
                )
            )
        )
        exact_repair = bool(
            reviewer_like
            and independent_review
            and purpose == REVIEWER_REPAIR_PURPOSE
            and bool(requested_route)
            and call_ids == list(REVIEWER_REPAIR_CALL_IDS)
            and statuses[0] == VALIDATION_FAILED_STATUS
            and statuses[1] in SUCCESS_STATUSES
            and reviewer.get("has_reviewer_decision") is True
        )
        exact_adjudication_repair = bool(
            adjudication_like
            and independent_review
            and purpose == ADJUDICATION_PURPOSE
            and bool(requested_route)
            and call_ids == list(ADJUDICATION_CALL_IDS)
            and statuses[0] == VALIDATION_FAILED_STATUS
            and statuses[1] in SUCCESS_STATUSES
        )
        if exact_repair or exact_adjudication_repair:
            if exact_repair:
                exact_reviewer_repairs += 1
            else:
                exact_adjudication_repairs += 1
            superseded_validation_failures += 1
            call_classifications[call_ids[0]] = (
                "superseded-validation-failure"
            )
            sequence_classification = (
                "exact-reviewer-repair"
                if exact_repair
                else "exact-adjudication-repair"
            )
        elif valid_single:
            sequence_classification = "single-success"
        else:
            malformed_sequences += 1
            sequence_classification = "malformed"
        purpose_summaries.append(
            {
                "independent_review": independent_review,
                "purpose": purpose[:160],
                "requested_route": requested_route[:256],
                "call_ids": call_ids,
                "statuses": statuses,
                "terminally_successful": terminal_success,
                "sequence_classification": sequence_classification,
            }
        )

    classified_calls = [
        {
            "call_id": str(row.get("call_id") or f"ordinal-{ordinal}"),
            "status": normalize_status(row.get("status")),
            "classification": call_classifications[
                str(row.get("call_id") or f"ordinal-{ordinal}")
            ],
        }
        for ordinal, row in ordered_calls
    ]
    classification_counts = collections.Counter(
        item["classification"] for item in classified_calls
    )
    return {
        "purpose_count": len(groups),
        "terminally_successful_purpose_count": terminally_successful,
        "incomplete_purpose_count": len(groups) - terminally_successful,
        "exact_reviewer_repair_count": exact_reviewer_repairs,
        "exact_adjudication_repair_count": exact_adjudication_repairs,
        "superseded_validation_failure_count": (
            superseded_validation_failures
        ),
        "unexpected_unsuccessful_call_count": classification_counts.get(
            "unexpected-unsuccessful",
            0,
        ),
        "malformed_purpose_sequence_count": malformed_sequences,
        "call_status_classification_counts": counter_dict(
            classification_counts
        ),
        "call_status_classifications": classified_calls[
            :MAX_REPORTED_IDS
        ],
        "purpose_summaries": purpose_summaries[:MAX_REPORTED_IDS],
    }


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


def expected_route_identity(route: object) -> dict[str, str] | None:
    """Project a supported assigned route into collector-owned model metadata."""
    normalized = str(route or "").strip()
    if normalized.startswith("codex-cli:"):
        value = normalized.removeprefix("codex-cli:")
        model, separator, _effort = value.rpartition(":")
        if separator and model:
            return {
                "model": model,
                "provider": "codex-cli",
                "path": "frontier-codex-cli",
                "harness": "",
            }
        return None
    if normalized.startswith("ollama:"):
        model = normalized.removeprefix("ollama:")
        if model:
            return {
                "model": model,
                "provider": "ollama",
                "path": "ollama",
                "harness": "",
            }
        return None
    for provider in ("hermes-agent", "openclaw"):
        prefix = f"{provider}:"
        if not normalized.startswith(prefix):
            continue
        value = normalized.removeprefix(prefix)
        model, separator, _effort = value.rpartition(":")
        if separator and model:
            return {
                "model": model,
                "provider": (
                    "openai-codex"
                    if provider == "hermes-agent"
                    else model.split("/", 1)[0]
                    if "/" in model
                    else "openclaw"
                ),
                "path": provider,
                "harness": provider,
            }
        return None
    return None


def model_route_consistency(
    run: Mapping[str, Any],
    events: list[dict[str, Any]],
    model_calls: list[dict[str, Any]],
    malformed: collections.Counter[str],
) -> dict[str, Any]:
    """Evaluate requested-route authorization and observed runtime identity."""
    authorization_events: dict[str, list[dict[str, Any]]] = {}
    observation_events: dict[str, list[dict[str, Any]]] = {}
    denied_call_ids: list[str] = []
    denied_observation_call_ids: list[str] = []
    malformed_authorization_events = 0
    malformed_observation_events = 0
    for event in events:
        event_type = str(event.get("event_type") or "")
        if event_type not in {
            "policy.model-route",
            "policy.model-observation",
        }:
            continue
        payload = safe_json(
            event.get("payload_json"),
            {},
            malformed,
            (
                "event.policy_model_route.payload_json"
                if event_type == "policy.model-route"
                else "event.policy_model_observation.payload_json"
            ),
        )
        call_id = str(payload.get("call_id") or "")
        if not call_id:
            if event_type == "policy.model-route":
                malformed_authorization_events += 1
            else:
                malformed_observation_events += 1
            continue
        if event_type == "policy.model-route":
            authorization_events.setdefault(call_id, []).append(payload)
            if not bool(payload.get("allowed")):
                denied_call_ids.append(call_id)
        else:
            observation_events.setdefault(call_id, []).append(payload)
            if not bool(payload.get("allowed")):
                denied_observation_call_ids.append(call_id)

    current_contract = all(
        key in run for key in ("assigned_route", "assigned_reviewer_route")
    )
    model_call_ids = {
        str(row.get("call_id") or "")
        for row in model_calls
        if str(row.get("call_id") or "")
    }
    route_failures: list[dict[str, Any]] = []
    authorized_call_count = 0
    authorization_unverified_call_ids: list[str] = []
    identity_failures: list[dict[str, Any]] = []
    identity_verified_call_count = 0
    identity_unverified_call_ids: list[str] = []
    identity_not_applicable_count = 0

    for row in model_calls:
        call_id = str(row.get("call_id") or "")
        independent_review = int(row.get("independent_review") or 0) == 1
        requested_route = str(row.get("requested_route") or "")
        expected_route = str(
            run.get(
                "assigned_reviewer_route"
                if independent_review
                else "assigned_route"
            )
            or ""
        )
        matching_events = authorization_events.get(call_id, [])
        matching_observations = observation_events.get(call_id, [])
        authorization_reasons: list[str] = []
        if current_contract:
            if not expected_route:
                authorization_reasons.append("assigned-route-missing")
            if requested_route != expected_route:
                authorization_reasons.append(
                    "model-ledger-requested-route-mismatch"
                )
            if not matching_events:
                authorization_reasons.append(
                    "authorization-event-missing"
                )
            elif len(matching_events) != 1:
                authorization_reasons.append(
                    "authorization-event-count-mismatch"
                )
            else:
                authorization = matching_events[0]
                if not bool(authorization.get("allowed")):
                    authorization_reasons.append(
                        "authorization-denied-but-model-recorded"
                    )
                if (
                    str(authorization.get("requested_route") or "")
                    != requested_route
                ):
                    authorization_reasons.append(
                        "authorization-requested-route-mismatch"
                    )
                if (
                    str(authorization.get("expected_route") or "")
                    != expected_route
                ):
                    authorization_reasons.append(
                        "authorization-assignment-mismatch"
                    )
                if bool(authorization.get("independent_review")) != (
                    independent_review
                ):
                    authorization_reasons.append(
                        "authorization-role-mismatch"
                    )
            if not matching_observations:
                authorization_reasons.append(
                    "model-observation-event-missing"
                )
            elif len(matching_observations) != 1:
                authorization_reasons.append(
                    "model-observation-event-count-mismatch"
                )
            else:
                observation = matching_observations[0]
                if (
                    str(observation.get("requested_route") or "")
                    != requested_route
                ):
                    authorization_reasons.append(
                        "model-observation-requested-route-mismatch"
                    )
                if bool(observation.get("independent_review")) != (
                    independent_review
                ):
                    authorization_reasons.append(
                        "model-observation-role-mismatch"
                    )
            if authorization_reasons:
                route_failures.append(
                    {
                        "call_id": call_id,
                        "reasons": sorted(set(authorization_reasons)),
                    }
                )
            else:
                authorized_call_count += 1
        else:
            authorization_unverified_call_ids.append(call_id)

        if normalize_status(row.get("status")) not in (
            SUCCESS_STATUSES | {VALIDATION_FAILED_STATUS}
        ):
            identity_not_applicable_count += 1
            continue
        expected_identity = expected_route_identity(requested_route)
        if expected_identity is None:
            identity_unverified_call_ids.append(call_id)
            continue
        observed = {
            "model": str(row.get("observed_model") or ""),
            "provider": str(row.get("observed_provider") or ""),
            "path": str(row.get("observed_model_path") or ""),
            "harness": str(row.get("observed_harness") or ""),
        }
        identity_reasons: list[str] = []
        if len(matching_observations) == 1:
            observed_route = str(
                matching_observations[0].get("observed_route") or ""
            )
            if observed_route != requested_route:
                identity_reasons.append("observed-route-mismatch")
        for field in ("model", "path", "harness"):
            expected_value = expected_identity[field]
            if expected_value and observed[field] != expected_value:
                identity_reasons.append(f"observed-{field}-mismatch")
        expected_provider = expected_identity["provider"]
        if expected_provider and observed["provider"] != expected_provider:
            identity_reasons.append("observed-provider-mismatch")
        if identity_reasons:
            identity_failures.append(
                {
                    "call_id": call_id,
                    "requested_route": requested_route,
                    "observed_model": observed["model"],
                    "observed_model_path": observed["path"],
                    "observed_provider": observed["provider"],
                    "observed_harness": observed["harness"],
                    "reasons": sorted(set(identity_reasons)),
                }
            )
        else:
            identity_verified_call_count += 1

    orphan_authorization_call_ids = sorted(
        set(authorization_events) - model_call_ids
    )
    orphan_observation_call_ids = sorted(
        set(observation_events) - model_call_ids
    )
    return {
        "contract_available": current_contract,
        "authorization_event_count": sum(
            len(items) for items in authorization_events.values()
        ),
        "authorization_allowed_event_count": sum(
            bool(item.get("allowed"))
            for items in authorization_events.values()
            for item in items
        ),
        "authorization_denied_event_count": len(denied_call_ids),
        "authorization_denied_call_ids": sorted(set(denied_call_ids))[
            :MAX_REPORTED_IDS
        ],
        "authorization_malformed_event_count": (
            malformed_authorization_events
        ),
        "authorization_orphan_event_count": len(
            orphan_authorization_call_ids
        ),
        "authorization_orphan_call_ids": orphan_authorization_call_ids[
            :MAX_REPORTED_IDS
        ],
        "observation_event_count": sum(
            len(items) for items in observation_events.values()
        ),
        "observation_denied_event_count": len(
            denied_observation_call_ids
        ),
        "observation_denied_call_ids": sorted(
            set(denied_observation_call_ids)
        )[:MAX_REPORTED_IDS],
        "observation_malformed_event_count": malformed_observation_events,
        "observation_orphan_event_count": len(
            orphan_observation_call_ids
        ),
        "observation_orphan_call_ids": orphan_observation_call_ids[
            :MAX_REPORTED_IDS
        ],
        "authorized_call_count": authorized_call_count,
        "authorization_failure_count": len(route_failures),
        "authorization_failures": route_failures[:MAX_REPORTED_IDS],
        "authorization_unverified_call_count": len(
            authorization_unverified_call_ids
        ),
        "authorization_unverified_call_ids": sorted(
            set(authorization_unverified_call_ids)
        )[:MAX_REPORTED_IDS],
        "identity_verified_call_count": identity_verified_call_count,
        "identity_mismatch_count": len(identity_failures),
        "identity_failures": identity_failures[:MAX_REPORTED_IDS],
        "identity_unverified_call_count": len(identity_unverified_call_ids),
        "identity_unverified_call_ids": sorted(
            set(identity_unverified_call_ids)
        )[:MAX_REPORTED_IDS],
        "identity_not_applicable_count": identity_not_applicable_count,
    }


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
    coverage_gaps = [
        str(row.get("call_id") or "")
        for row in tool_calls
        if normalize_status(row.get("coverage")) in GAP_COVERAGE
        or normalize_status(row.get("status"))
        not in (SUCCESS_STATUSES | REJECTION_STATUSES)
    ]
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
