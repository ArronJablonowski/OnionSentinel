"""Read bounded second-opinion metadata for cohort monitoring and export."""

from __future__ import annotations

import sqlite3
from typing import Any

from cohort_storage_core import table_columns, table_exists


SECOND_OPINION_EXPORT_COLUMNS = (
    "analysis_id",
    "group_id",
    "alert_id",
    "agent_role",
    "trigger",
    "status",
    "primary_model",
    "primary_model_path",
    "primary_outcome",
    "primary_confidence",
    "reviewer_model",
    "reviewer_model_path",
    "reviewer_outcome",
    "reviewer_confidence",
    "agreement",
    "material_disagreement",
    "reviewer_runtime_seconds",
    "generated_at",
    "created_at",
    "updated_at",
)


def second_opinion_metadata(
    connection: sqlite3.Connection,
    analysis_id: str,
) -> dict[str, Any] | None:
    """Return only approved metadata for an analysis's reviewer run."""
    table = "ai_second_opinion_runs"
    if not table_exists(connection, table):
        return None
    columns = table_columns(connection, table)
    allowed = [item for item in SECOND_OPINION_EXPORT_COLUMNS if item in columns]
    if "analysis_id" not in allowed:
        return None
    row = connection.execute(
        "SELECT "
        + ", ".join(allowed)
        + " FROM ai_second_opinion_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    return dict(row) if row else None
