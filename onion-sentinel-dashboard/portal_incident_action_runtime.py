"""Runtime composition for SOC adjudication and incident action APIs."""
from __future__ import annotations

from typing import Any


def forward_controlled_dispatch_contract(r: Any, payload: dict, request_payload: dict) -> None:
    r.forward_controlled_dispatch_contract(payload, request_payload)


def soc_action_service_sources(r: Any) -> Any:
    return r.SocActionServiceSources(
        post_json=r.alert_store_post_json,
        api_error=r.soc_alert_api_error,
        now_local=r.now_iso_local,
        request_error_status=lambda exc: (
            exc.status_code if isinstance(exc, r.AlertStoreRequestError) else None
        ),
    )


def soc_alert_queue_analysis_response(r: Any, group_id: str, payload: dict | None = None) -> tuple[int, dict]:
    return r.queue_soc_alert_analysis(r.soc_action_service_sources(), group_id, payload)


def soc_alert_escalate_response(r: Any, group_id: str, payload: dict | None = None) -> tuple[int, dict]:
    return r.escalate_soc_alert(r.soc_action_service_sources(), group_id, payload)


def soc_legacy_verdict_factors(r: Any, outcome: str) -> dict[str, str | None]:
    return r.legacy_verdict_factors(outcome)


def soc_derive_legacy_detection_outcome(r: Any, factors: dict[str, str | None]) -> str:
    return r.derive_legacy_detection_outcome(factors)


def soc_adjudication_verdict_contradictions(
    r: Any, outcome: str, explicit_factors: dict[str, str | None]
) -> list[str]:
    return r.adjudication_verdict_contradictions(outcome, explicit_factors)


def normalize_soc_adjudication_payload(
    r: Any, payload: dict | None, *, group_id: str, case_id: str = ""
) -> tuple[bool, dict]:
    return r.normalize_adjudication_payload(payload, group_id=group_id, case_id=case_id)


def soc_alert_store_mutation(
    r: Any, path: str, payload: dict, *, success_status: int = 200
) -> tuple[int, dict]:
    if not r.SOC_ALERT_STORE_API_URL:
        return r.soc_alert_api_error(
            "Alert-store API is required for append-only analyst review writes.", 503
        )
    try:
        result = r.alert_store_post_json(path, payload, timeout=10.0)
    except r.AlertStoreRequestError as exc:
        return r.soc_alert_api_error(str(exc), exc.status_code)
    return success_status, result


def soc_alert_adjudication_response(
    r: Any, group_id: str, payload: dict | None = None
) -> tuple[int, dict]:
    ok, normalized = r.normalize_soc_adjudication_payload(
        payload, group_id=str(group_id or "").strip().lower()
    )
    if not ok:
        return r.HTTPStatus.BAD_REQUEST, normalized
    return r._soc_alert_store_mutation(
        "/adjudications", normalized, success_status=r.HTTPStatus.CREATED
    )


def soc_incident_case_group_id(r: Any, case_id: str) -> tuple[int, str]:
    case_id = str(case_id or "").strip().lower()
    if not r.re.fullmatch(r"ir-[a-z0-9_-]{1,64}", case_id):
        return r.HTTPStatus.BAD_REQUEST, ""
    try:
        with r.soc_alert_db_connect() as conn:
            row = conn.execute(
                "SELECT dashboard_group_id FROM incident_response_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
    except (FileNotFoundError, r.sqlite3.Error):
        row = None
    return (
        (r.HTTPStatus.OK, str(row["dashboard_group_id"] or ""))
        if row else (r.HTTPStatus.NOT_FOUND, "")
    )


def soc_incident_adjudication_response(
    r: Any, case_id: str, payload: dict | None = None
) -> tuple[int, dict]:
    status, group_id = r._soc_incident_case_group_id(case_id)
    if status != r.HTTPStatus.OK:
        return r.soc_alert_api_error(
            "Incident case not found" if status == r.HTTPStatus.NOT_FOUND
            else "Invalid incident case id",
            status,
        )
    ok, normalized = r.normalize_soc_adjudication_payload(
        payload, group_id=group_id, case_id=case_id
    )
    if not ok:
        return r.HTTPStatus.BAD_REQUEST, normalized
    return r._soc_alert_store_mutation(
        "/adjudications", normalized, success_status=r.HTTPStatus.CREATED
    )


def soc_incident_status_response(
    r: Any, case_id: str, payload: dict | None = None
) -> tuple[int, dict]:
    status, _ = r._soc_incident_case_group_id(case_id)
    if status != r.HTTPStatus.OK:
        return r.soc_alert_api_error(
            "Incident case not found" if status == r.HTTPStatus.NOT_FOUND
            else "Invalid incident case id",
            status,
        )
    try:
        request_payload = r.normalize_incident_status_payload(case_id, payload)
    except r.IncidentStatusPayloadError as exc:
        return r.soc_alert_api_error(str(exc))
    return r._soc_alert_store_mutation("/incidents/status", request_payload)


def soc_incident_reanalysis_response(
    r: Any, case_id: str, payload: dict | None = None
) -> tuple[int, dict]:
    status, _ = r._soc_incident_case_group_id(case_id)
    if status != r.HTTPStatus.OK:
        return r.soc_alert_api_error(
            "Incident case not found" if status == r.HTTPStatus.NOT_FOUND
            else "Invalid incident case id",
            status,
        )
    payload = payload if isinstance(payload, dict) else {}
    request_payload = {
        "case_id": case_id,
        "reason": str(payload.get("reason") or "Analyst requested fresh Incident Responder analysis")[:1000],
        "requested_by": str(payload.get("requested_by") or "dashboard")[:100],
    }
    for field in (
        "representative_alert_id", "stable_group_id", "stable_group_key",
        "cohort_id", "dispatch_id",
    ):
        if field in payload:
            request_payload[field] = payload[field]
    r._forward_controlled_dispatch_contract(payload, request_payload)
    return r._soc_alert_store_mutation(
        "/incidents/reanalyze", request_payload,
        success_status=r.HTTPStatus.ACCEPTED,
    )


def soc_incident_bulk_reanalysis_response(
    r: Any, payload: dict | None = None
) -> tuple[int, dict]:
    payload = payload if isinstance(payload, dict) else {}
    return r._soc_alert_store_mutation(
        "/incidents/reanalyze-all",
        {
            "reason": str(payload.get("reason") or "Analyst requested fresh analysis of all incident cases")[:1000],
            "requested_by": str(payload.get("requested_by") or "dashboard")[:100],
        },
        success_status=r.HTTPStatus.ACCEPTED,
    )


def soc_incident_reanalysis_runs_response(
    r: Any, query: dict[str, list[str]]
) -> tuple[int, dict]:
    try:
        run_id = r.parse_reanalysis_run_id(query)
    except r.IncidentReanalysisQueryError as exc:
        return r.soc_alert_api_error(str(exc))
    try:
        with r.soc_alert_db_connect() as conn:
            progress = r.load_reanalysis_progress(conn, run_id)
    except (FileNotFoundError, r.sqlite3.Error) as exc:
        return r.soc_alert_api_error(
            f"Incident reanalysis progress unavailable: {exc}",
            r.HTTPStatus.SERVICE_UNAVAILABLE,
        )
    return 200, r.compose_reanalysis_progress_payload(progress)


def soc_incident_current_analysis(r: Any, conn: Any, case: dict[str, object]) -> dict[str, object]:
    return r.load_current_incident_analysis(conn, case)


def soc_adjudication_history_sources(r: Any) -> Any:
    return r.SocAdjudicationHistorySources(
        connect=r.soc_alert_db_connect,
        table_exists=r.sqlite_table_exists,
        table_columns=r.sqlite_table_columns,
        review_defaults=r._soc_review_defaults,
        alert_review_state=r.soc_alert_review_state_for_group,
        current_incident_analysis=r.soc_incident_current_analysis,
        parse_review_json=r._soc_review_json,
        incident_review_state=r.soc_incident_review_state,
    )


def soc_adjudication_history_response(
    r: Any, group_id: str, *, case_id: str = "", limit: int = 25
) -> tuple[int, dict]:
    return r.read_soc_adjudication_history(
        r.soc_adjudication_history_sources(), group_id,
        case_id=case_id, limit=limit,
    )


def soc_incident_agent_display_state(
    r: Any, agent_status: object, analysis_id: object, reviewer_status: object
) -> tuple[str, str]:
    status = str(agent_status or "queued").strip().lower()
    has_analysis = bool(str(analysis_id or "").strip())
    review = str(reviewer_status or "not_requested").strip().lower()
    if status != "failed":
        return status, status.replace("_", " ")
    if not has_analysis:
        return "analysis_failed", "Analysis failed"
    if review in {"failed", "invalid"}:
        return "review_failed", "Primary ready · review failed"
    return "refresh_failed", "Analysis ready · refresh failed"
