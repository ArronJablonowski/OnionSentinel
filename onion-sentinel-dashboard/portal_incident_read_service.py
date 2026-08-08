"""Incident Response list and detail read orchestration."""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass

from portal_incident_read_model import IncidentQueryError, IncidentRowCallbacks
from portal_incident_repository import (
    IncidentCaseNotFound,
    IncidentSchemaUnavailable,
)


@dataclass(frozen=True)
class IncidentReadServiceSources:
    connect: Callable[[], AbstractContextManager[sqlite3.Connection]]
    api_error: Callable[..., tuple[int, dict]]
    parse_list_request: Callable[..., object]
    schema_ready: Callable[[sqlite3.Connection], bool]
    empty_page: Callable[[object], dict]
    load_list_records: Callable[[sqlite3.Connection, object], object]
    load_inventory: Callable[[], tuple[dict, object]]
    compose_list_rows: Callable[..., list[dict]]
    load_detail_records: Callable[[sqlite3.Connection, str], object]
    parse_analysis_response: Callable[[dict], dict]
    compose_review_state: Callable[..., dict]
    review_defaults: Callable[[], dict]
    row_callbacks: IncidentRowCallbacks
    render_incident_report: Callable[..., tuple[str, int]]
    render_prior_analysis: Callable[[dict, dict], str]
    compose_detail_payload: Callable[..., dict]


def incident_list_response(
    sources: IncidentReadServiceSources,
    query: dict[str, list[str]],
    *,
    max_per_page: int,
) -> tuple[int, dict]:
    """Return one bounded page of durable Incident Response cases."""
    try:
        request = sources.parse_list_request(
            query,
            max_per_page=max_per_page,
        )
    except IncidentQueryError as exc:
        return sources.api_error(str(exc))

    try:
        with sources.connect() as conn:
            if not sources.schema_ready(conn):
                return 200, sources.empty_page(request)
            records = sources.load_list_records(conn, request)
            inventory, inventory_error = sources.load_inventory()
            incidents = sources.compose_list_rows(
                conn,
                records,
                inventory,
                inventory_error,
                sources.review_defaults(),
                sources.row_callbacks,
            )
    except (FileNotFoundError, sqlite3.Error) as exc:
        return sources.api_error(
            f"Incident Response data unavailable: {exc}", 503
        )

    return 200, {
        "ok": True,
        "incidents": incidents,
        "page": records.page,
        "per_page": request.per_page,
        "total": records.total,
        "pages": records.pages,
        "status_counts": records.status_counts,
        "agent_status_counts": records.agent_status_counts,
        "schema_ready": True,
        "sort": request.sort,
        "direction": request.direction,
        "asset_inventory_status": (
            "invalid"
            if inventory_error
            else str(inventory.get("inventory_status") or "loaded")
        ),
    }


def incident_detail_response(
    sources: IncidentReadServiceSources,
    case_id: object,
) -> tuple[int, dict]:
    """Return one bounded IR report, exact query audit, and prior SOC analysis."""
    normalized_case_id = str(case_id or "").strip().lower()
    if not re.fullmatch(r"ir-[a-z0-9_-]{1,64}", normalized_case_id):
        return sources.api_error("Invalid incident case id")

    try:
        with sources.connect() as conn:
            records = sources.load_detail_records(conn, normalized_case_id)
    except IncidentSchemaUnavailable:
        return sources.api_error("Incident Response schema is unavailable", 503)
    except IncidentCaseNotFound:
        return sources.api_error("Incident case not found", 404)
    except (FileNotFoundError, sqlite3.Error) as exc:
        return sources.api_error(
            f"Incident Response detail unavailable: {exc}", 503
        )

    response = sources.parse_analysis_response(records.analysis)
    prior_response = sources.parse_analysis_response(records.prior_analysis)
    review = sources.compose_review_state(
        records.case,
        records.analysis,
        response,
        records.review.evidence_updated_at,
        records.review.reviewer,
        records.review.adjudication,
        sources.review_defaults(),
        sources.row_callbacks,
    )
    incident_html, query_count = sources.render_incident_report(
        records.case,
        response,
        records.analysis,
        review,
    )
    prior_html = sources.render_prior_analysis(
        prior_response,
        records.prior_analysis,
    )
    return 200, sources.compose_detail_payload(
        normalized_case_id,
        records.case,
        response,
        review,
        incident_html,
        prior_html,
        query_count,
    )
