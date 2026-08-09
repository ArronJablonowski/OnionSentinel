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
import json
import os
import sqlite3
import sys
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
from trace_evaluation_run import (
    TraceRunPolicy,
    TraceRunServices,
    evaluate_run as evaluate_trace_run,
)
from trace_evaluation_output import atomic_private_json, human_report
from trace_evaluation_summary import (
    TraceSummaryPolicy,
    TraceSummaryServices,
    summarize as summarize_trace_runs,
)
from trace_evaluation_events import (
    TraceEventPolicy,
    budget_operation_id as trace_budget_operation_id,
    terminal_execution_summary as evaluate_terminal_execution_summary,
    tool_query_id as trace_tool_query_id,
    unresolved_tool_coverage_gaps as evaluate_tool_coverage_gaps,
)
from trace_evaluation_contract import (
    ADJUDICATION_CALL_IDS,
    ADJUDICATION_PURPOSE,
    CURRENT_SQL_SCHEMA_VERSION,
    DEFAULT_DB,
    EvaluationError,
    FAILURE_STATUSES,
    FOLLOWUP_CALL_RE,
    GAP_COVERAGE,
    JOB_ENVELOPE_DIGEST_FIELDS,
    LEDGER_MANIFEST_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
    LEGACY_RUN_IDENTITY_COLUMNS_V1,
    MATERIAL_REVIEW_FIELDS,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    MAX_REPORTED_IDS,
    MAX_RUNTIME_MODEL_CALLS,
    MODEL_CALL_CONTRACT_SCHEMA,
    OPTIONAL_TABLES,
    PRIMARY_INITIAL_CALL_ID,
    PRIMARY_INITIAL_PURPOSE,
    QUERY_PLANNING_CALL_ID,
    QUERY_PLANNING_PURPOSE,
    QUERY_PLANNING_REPAIR_CALL_ID,
    QUERY_PLANNING_REPAIR_PURPOSE,
    REJECTION_STATUSES,
    REPORT_SCHEMA,
    REQUIRED_TABLES,
    REVIEWER_REPAIR_CALL_IDS,
    REVIEWER_REPAIR_PURPOSE,
    RUN_IDENTITY_COLUMNS,
    SHA256_RE,
    SKILL_SELECTION_ATTESTATION_KEYS,
    SKILL_SELECTION_ID_RE,
    SUCCESS_STATUSES,
    SUPPLEMENTAL_REVIEW_CALL_ID,
    SUPPLEMENTAL_REVIEW_PURPOSE,
    SUPPORTED_LEDGER_MANIFEST_SCHEMAS,
    TERMINAL_STATUSES,
    VALIDATION_FAILED_STATUS,
    canonical_json,
    digest_json,
    nonnegative_int,
    normalize_status,
    ratio,
    safe_json,
    utc_now,
)


def _trace_event_policy() -> TraceEventPolicy:
    return TraceEventPolicy(
        success_statuses=SUCCESS_STATUSES,
        rejection_statuses=REJECTION_STATUSES,
        gap_coverage=GAP_COVERAGE,
        normalize_status=normalize_status,
        nonnegative_int=nonnegative_int,
        safe_json=safe_json,
    )


def tool_query_id(row: Mapping[str, Any]) -> str:
    return trace_tool_query_id(row, _trace_event_policy())


def unresolved_tool_coverage_gaps(
    tool_calls: Iterable[Mapping[str, Any]],
) -> list[str]:
    return evaluate_tool_coverage_gaps(tool_calls, _trace_event_policy())
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
    return evaluate_terminal_execution_summary(
        events, run_status, malformed, _trace_event_policy()
    )


def budget_operation_id(
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> str:
    return trace_budget_operation_id(event, payload)


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


def _trace_run_policy() -> TraceRunPolicy:
    return TraceRunPolicy(
        run_identity_columns=RUN_IDENTITY_COLUMNS,
        trusted_source_tiers=frozenset(
            {"trusted-collector", "read-only-backend", "human-confirmed"}
        ),
        rejection_statuses=REJECTION_STATUSES,
        failure_statuses=FAILURE_STATUSES,
        success_statuses=SUCCESS_STATUSES,
        unresolved_hypothesis_statuses=frozenset(
            {"", "unknown", "unresolved", "open", "proposed"}
        ),
        maximum_reported=MAX_REPORTED_IDS,
    )


def _trace_run_services() -> TraceRunServices:
    return TraceRunServices(
        rows_for_run=rows_for_run,
        normalize_status=normalize_status,
        safe_json=safe_json,
        nonnegative_int=nonnegative_int,
        unresolved_tool_coverage_gaps=unresolved_tool_coverage_gaps,
        budget_operation_id=budget_operation_id,
        reviewer_result=reviewer_result,
        model_purpose_completion=model_purpose_completion,
        reviewer_completion_contract=reviewer_completion_contract,
        canonical_model_call_contract=canonical_model_call_contract,
        model_route_consistency=model_route_consistency,
        skill_selection_attestation_result=skill_selection_attestation_result,
        terminal_execution_summary=terminal_execution_summary,
        verify_chain=verify_chain,
        digest_json=digest_json,
    )


def evaluate_run(
    connection: sqlite3.Connection,
    available_tables: set[str],
    run: Mapping[str, Any],
    malformed: collections.Counter[str],
    *,
    require_ledger_manifest: bool = False,
) -> dict[str, Any]:
    return evaluate_trace_run(
        connection,
        available_tables,
        run,
        malformed,
        _trace_run_policy(),
        _trace_run_services(),
        require_ledger_manifest=require_ledger_manifest,
    )


def counter_dict(counter: collections.Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def _trace_summary_policy() -> TraceSummaryPolicy:
    return TraceSummaryPolicy(
        report_schema=REPORT_SCHEMA,
        terminal_statuses=TERMINAL_STATUSES,
        optional_tables=OPTIONAL_TABLES,
        maximum_reported=MAX_REPORTED_IDS,
    )


def _trace_summary_services() -> TraceSummaryServices:
    return TraceSummaryServices(
        normalize_status=normalize_status,
        counter_dict=counter_dict,
        ratio=ratio,
        utc_now=utc_now,
        rows_for_run=rows_for_run,
    )


def summarize(
    connection: sqlite3.Connection,
    db_path: Path,
    run_results: list[dict[str, Any]],
    available_tables: set[str],
    malformed: collections.Counter[str],
    selected_run_id: str | None,
    database_schema: int | None,
) -> dict[str, Any]:
    return summarize_trace_runs(
        connection,
        db_path,
        run_results,
        available_tables,
        malformed,
        selected_run_id,
        database_schema,
        _trace_summary_policy(),
        _trace_summary_services(),
    )


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
