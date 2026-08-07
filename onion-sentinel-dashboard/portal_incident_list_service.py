"""Application service for composing Incident Response list rows."""
from __future__ import annotations

import sqlite3

from portal_incident_read_model import (
    IncidentRowCallbacks,
    compose_incident_row,
    select_incident_analysis,
)
from portal_incident_repository import (
    IncidentListRecords,
    load_current_incident_analysis,
    load_incident_review_records,
)
from portal_incident_review_model import (
    compose_incident_review_state,
    parse_analysis_response,
)


def _analysis_and_fallback_review(
    conn: sqlite3.Connection,
    item: dict,
    records: IncidentListRecords,
    review_defaults: dict,
    callbacks: IncidentRowCallbacks,
) -> tuple[dict, dict | None]:
    analysis = select_incident_analysis(
        item, records.analyses, records.run_columns
    )
    if analysis or not records.run_columns:
        return analysis, None
    analysis = load_current_incident_analysis(conn, item)
    if not analysis:
        return {}, None
    response = parse_analysis_response(analysis)
    review_records = load_incident_review_records(conn, item, analysis)
    review = compose_incident_review_state(
        item,
        analysis,
        response,
        review_records.evidence_updated_at,
        review_records.reviewer,
        review_records.adjudication,
        review_defaults,
        callbacks,
    )
    return analysis, review


def compose_incident_list_rows(
    conn: sqlite3.Connection,
    records: IncidentListRecords,
    inventory: dict,
    inventory_error: object,
    review_defaults: dict,
    callbacks: IncidentRowCallbacks,
) -> list[dict]:
    """Compose one list page, including resilient legacy-analysis fallback."""
    incidents = []
    for row in records.rows:
        item = dict(row)
        analysis, fallback_review = _analysis_and_fallback_review(
            conn, item, records, review_defaults, callbacks
        )
        analysis_id = str(analysis.get("analysis_id") or "")
        adjudication = records.adjudications.get((
            str(item.get("case_id") or ""), analysis_id
        ))
        incidents.append(compose_incident_row(
            item,
            analysis,
            records.second_opinions.get(analysis_id),
            adjudication,
            fallback_review,
            inventory,
            inventory_error,
            callbacks,
        ))
    return incidents
