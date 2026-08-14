"""Harness ledger manifests and conservative evidence accounting."""
from __future__ import annotations

import sqlite3
from typing import Any, Iterable, Mapping, Sequence

from harness_policy import (
    HarnessIntegrityError,
    LEDGER_MANIFEST_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
    LEDGER_MANIFEST_SCHEMA_V2,
    digest_json,
)


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
    "execution_contract_json",
    "execution_contract_digest",
    "policy_version",
    "policy_digest",
    "policy_mode",
    "parent_run_id",
    "job_digest",
    "started_at",
)
LEGACY_RUN_IDENTITY_COLUMNS_V2 = tuple(
    column
    for column in RUN_IDENTITY_COLUMNS
    if column not in {"execution_contract_json", "execution_contract_digest"}
)
LEGACY_RUN_IDENTITY_COLUMNS_V1 = tuple(
    column
    for column in LEGACY_RUN_IDENTITY_COLUMNS_V2
    if column != "assigned_reviewer_route"
)
SUPPORTED_LEDGER_MANIFEST_SCHEMAS = frozenset(
    {
        LEDGER_MANIFEST_SCHEMA_V1,
        LEDGER_MANIFEST_SCHEMA_V2,
        LEDGER_MANIFEST_SCHEMA,
    }
)


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


def ledger_manifest(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    schema: str = LEDGER_MANIFEST_SCHEMA,
) -> dict[str, Any]:
    """Digest every non-event ledger at a terminal state."""
    run_identity_columns = _run_identity_columns(schema)
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


def _run_identity_columns(schema: str) -> tuple[str, ...]:
    if schema == LEDGER_MANIFEST_SCHEMA:
        return RUN_IDENTITY_COLUMNS
    if schema == LEDGER_MANIFEST_SCHEMA_V2:
        return LEGACY_RUN_IDENTITY_COLUMNS_V2
    if schema == LEDGER_MANIFEST_SCHEMA_V1:
        return LEGACY_RUN_IDENTITY_COLUMNS_V1
    raise HarnessIntegrityError(
        f"unsupported ledger manifest schema: {schema}"
    )


def approximate_evidence_rows(value: Any, *, depth: int = 0) -> int:
    """Conservatively count model-visible evidence records for budget checks."""
    if depth > 12:
        return 0
    if isinstance(value, Mapping):
        return _mapping_evidence_rows(value, depth=depth)
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        return sum(
            approximate_evidence_rows(item, depth=depth + 1)
            for item in value
        )
    return 0


def _mapping_evidence_rows(
    value: Mapping[Any, Any],
    *,
    depth: int,
) -> int:
    total = 0
    row_keys = {
        "events",
        "hits",
        "parsed_evidence",
        "records",
        "results",
        "rows",
        "rows_preview",
        "samples",
    }
    for raw_key, child in value.items():
        key = str(raw_key).strip().lower()
        if isinstance(child, list) and key in row_keys:
            total += len(child)
            if key == "results":
                total += sum(
                    approximate_evidence_rows(item, depth=depth + 1)
                    for item in child
                )
        else:
            total += approximate_evidence_rows(child, depth=depth + 1)
    return total
