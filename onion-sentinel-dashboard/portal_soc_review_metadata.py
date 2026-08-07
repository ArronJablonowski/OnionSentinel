"""Page-bounded SOC analysis, reviewer, and adjudication read model."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Callable


JsonObject = dict[str, object]
Row = sqlite3.Row | dict


REVIEW_FAILURE_STATUSES = {
    "failed", "invalid", "invalid_response", "not_configured",
    "not_independent", "review_required_failed",
}


@dataclass(frozen=True)
class SocReviewDependencies:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]
    dashboard_group_id: Callable[[str], str]
    outcome_label: Callable[[object], str]
    parse_timestamp: Callable[[object], object]


def review_defaults() -> JsonObject:
    return {
        "analysis_id": "", "analysis_confidence": "", "analysis_generated_at": "",
        "analysis_evidence_hash": "", "primary_outcome": "", "primary_confidence": "",
        "primary_event_status": "", "primary_detection_validity": "",
        "primary_activity_disposition": "", "primary_handling": "", "primary_duplicate_of": None,
        "effective_outcome": "", "effective_outcome_label": "Not analyzed",
        "effective_confidence": "", "freshness_status": "not_analyzed",
        "evidence_updated_at": "", "coverage_status": "unknown", "evidence_used_count": 0,
        "evidence_gap_count": 0, "reviewer_status": "not_requested", "reviewer_error": "",
        "reviewer_outcome": "", "reviewer_confidence": "", "reviewer_agreement": "",
        "automation_authorization": {}, "material_disagreement": False,
        "disputed_fields": [], "final_review_status": "unreviewed", "adjudication": None,
    }


def parse_review_json(value: object) -> dict:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _first(mapping: dict, *keys: str, default: object = "") -> object:
    for key in keys:
        value = mapping.get(key)
        if value:
            return value
    return default


def _text(mapping: dict, *keys: str, default: str = "") -> str:
    return str(_first(mapping, *keys, default=default))


def _list_count(value: object) -> int:
    if isinstance(value, list):
        return len([item for item in value if str(item or "").strip()])
    return int(bool(str(value or "").strip()))


def review_epoch(value: object, parse_timestamp: Callable[[object], object]) -> float:
    try:
        return parse_timestamp(value).timestamp() if value else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def embedded_reviewer(response: JsonObject, analysis: JsonObject | None = None) -> JsonObject:
    analysis = _mapping(analysis)
    embedded = _mapping(response.get("_second_opinion"))
    comparison = _mapping(embedded.get("comparison"))
    reviewer_response = _mapping(embedded.get("response"))
    authorization = _mapping(embedded.get("automation_authorization"))
    return {
        "status": _first(embedded, "status", default="not_requested"),
        "reviewer_error": _text(embedded, "error")[:1000],
        "primary_outcome": _first(analysis, "detection_outcome"),
        "primary_confidence": _first(analysis, "confidence"),
        "reviewer_outcome": _first(reviewer_response, "detection_outcome"),
        "reviewer_confidence": _first(reviewer_response, "confidence"),
        "agreement": _first(comparison, "agreement"),
        "automation_authorization": authorization,
        "material_disagreement": bool(comparison.get("material_disagreement")),
        "disputed_fields_json": json.dumps(_first(comparison, "disputed_fields", default=[])),
    }


def reviewer_automation_authorization(reviewer: JsonObject) -> JsonObject:
    """Read explicit authorization, preserving the legacy confidence fallback."""
    authorization = reviewer.get("automation_authorization")
    authorization = authorization if isinstance(authorization, dict) else {}
    explicit = isinstance(authorization.get("authorized"), bool)
    confidence = str(reviewer.get("reviewer_confidence") or "").strip().lower()
    legacy_denied = bool(not explicit and confidence != "high")
    return {
        **authorization,
        "authorized": bool(authorization["authorized"]) if explicit else not legacy_denied,
        "explicitly_recorded": explicit,
        "legacy_confidence_fallback": legacy_denied,
    }


def review_final_status(reviewer: JsonObject, material_disagreement: bool,
                        adjudication: JsonObject | None) -> str:
    if adjudication:
        return "adjudicated"
    if material_disagreement:
        return "disputed_pending_human"
    status = str(reviewer.get("status") or "").strip().lower()
    if status in REVIEW_FAILURE_STATUSES:
        return "review_required_failed"
    if status != "completed":
        return "unreviewed"
    if not reviewer_automation_authorization(reviewer)["authorized"]:
        return "review_completed_not_authorized"
    if str(reviewer.get("agreement") or "").strip().lower() == "agreement":
        return "model_consensus"
    return "reviewer_advisory"


def _row_value(row: Row, key: str) -> str:
    if isinstance(row, dict):
        return str(row.get(key) or "").strip()
    return str(row[key] or "").strip() if key in row.keys() else ""


def _stable_group_map(conn: sqlite3.Connection, metadata: dict[str, JsonObject],
                      group_by_alert: dict[str, str], deps: SocReviewDependencies) -> dict[str, str]:
    stable: dict[str, str] = {}
    group_ids = sorted(metadata)
    if deps.table_exists(conn, "alert_group_alias"):
        placeholders = ",".join("?" for _ in group_ids)
        try:
            for item in conn.execute(
                f"SELECT legacy_group_id, stable_group_id FROM alert_group_alias "
                f"WHERE legacy_group_id IN ({placeholders})", group_ids,
            ):
                stable[str(item["legacy_group_id"])] = str(item["stable_group_id"] or "")
        except sqlite3.Error:
            pass
    _merge_alert_stable_groups(conn, stable, group_by_alert, deps)
    return stable


def _merge_alert_stable_groups(conn: sqlite3.Connection, stable: dict[str, str],
                               group_by_alert: dict[str, str], deps: SocReviewDependencies) -> None:
    if "stable_group_id" not in deps.table_columns(conn, "alerts") or not group_by_alert:
        return
    alert_ids = sorted(group_by_alert)
    placeholders = ",".join("?" for _ in alert_ids)
    try:
        rows = conn.execute(
            f"SELECT alert_id, stable_group_id FROM alerts WHERE alert_id IN ({placeholders})", alert_ids,
        )
        for item in rows:
            dashboard_id = group_by_alert.get(str(item["alert_id"] or ""))
            if dashboard_id and item["stable_group_id"]:
                stable[dashboard_id] = str(item["stable_group_id"])
    except sqlite3.Error:
        pass


def _dashboards_by_stable(stable: dict[str, str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for dashboard_id, stable_id in stable.items():
        if stable_id:
            result.setdefault(stable_id, []).append(dashboard_id)
    return result


def _selected_analysis_columns(columns: set[str]) -> list[str]:
    available = (
        "analysis_id", "group_id", "alert_id", "agent_role", "generated_at", "created_at",
        "model", "detection_outcome", "confidence", "evidence_hash", "response_json",
    )
    return [column for column in available if column in columns]


def _analysis_filters(columns: set[str], stable_ids: list[str],
                      alert_ids: list[str]) -> tuple[list[str], list[object]]:
    clauses: list[str] = []
    arguments: list[object] = []
    if stable_ids and "group_id" in columns:
        clauses.append(f"group_id IN ({','.join('?' for _ in stable_ids)})")
        arguments.extend(stable_ids)
    if alert_ids and "alert_id" in columns:
        clauses.append(f"alert_id IN ({','.join('?' for _ in alert_ids)})")
        arguments.extend(alert_ids)
    return clauses, arguments


def _analysis_role_filter(columns: set[str]) -> str:
    if "agent_role" not in columns:
        return ""
    return " AND COALESCE(NULLIF(agent_role, ''), 'soc-analyst') = 'soc-analyst'"


def _analysis_order_column(columns: set[str]) -> str:
    return "generated_at" if "generated_at" in columns else "rowid"


def _analysis_query(conn: sqlite3.Connection, stable_ids: list[str], alert_ids: list[str],
                    deps: SocReviewDependencies) -> list[sqlite3.Row]:
    columns = deps.table_columns(conn, "ai_analysis_runs")
    selected = _selected_analysis_columns(columns)
    clauses, arguments = _analysis_filters(columns, stable_ids, alert_ids)
    if not clauses:
        return []
    if not selected:
        return []
    role = _analysis_role_filter(columns)
    order = _analysis_order_column(columns)
    try:
        return conn.execute(
            f"SELECT {', '.join(selected)} FROM ai_analysis_runs "
            f"WHERE ({' OR '.join(clauses)}){role} ORDER BY {order} DESC, rowid DESC", arguments,
        ).fetchall()
    except sqlite3.Error:
        return []


def _current_analyses(rows: list[sqlite3.Row], dashboards_by_stable: dict[str, list[str]],
                      group_by_alert: dict[str, str]) -> dict[str, JsonObject]:
    current: dict[str, JsonObject] = {}
    for item in rows:
        record = dict(item)
        dashboard_ids = list(dashboards_by_stable.get(str(record.get("group_id") or ""), []))
        alert_dashboard = group_by_alert.get(str(record.get("alert_id") or ""))
        if alert_dashboard and alert_dashboard not in dashboard_ids:
            dashboard_ids.append(alert_dashboard)
        for dashboard_id in dashboard_ids:
            current.setdefault(dashboard_id, record)
    return current


def _reviewer_runs(conn: sqlite3.Connection, analysis_ids: list[str],
                   deps: SocReviewDependencies) -> dict[str, JsonObject]:
    if not analysis_ids or not deps.table_exists(conn, "ai_second_opinion_runs"):
        return {}
    placeholders = ",".join("?" for _ in analysis_ids)
    error_column = (
        "reviewer_error" if "reviewer_error" in deps.table_columns(conn, "ai_second_opinion_runs")
        else "'' AS reviewer_error"
    )
    try:
        rows = conn.execute(
            "SELECT analysis_id, status, primary_outcome, primary_confidence, reviewer_outcome, "
            "reviewer_confidence, agreement, material_disagreement, disputed_fields_json, "
            f"{error_column}, generated_at FROM ai_second_opinion_runs "
            f"WHERE analysis_id IN ({placeholders})", analysis_ids,
        )
        return {str(item["analysis_id"]): dict(item) for item in rows}
    except sqlite3.Error:
        return {}


def _adjudications(conn: sqlite3.Connection, analysis_ids: list[str],
                   deps: SocReviewDependencies) -> dict[tuple[str, str], JsonObject]:
    if not analysis_ids or not deps.table_exists(conn, "analyst_adjudications"):
        return {}
    placeholders = ",".join("?" for _ in analysis_ids)
    try:
        rows = conn.execute(
            "SELECT adjudication_id, dashboard_group_id, stable_group_id, analysis_id, "
            "outcome_override, confidence, rationale, evidence_gap, next_action, reviewer, "
            "event_status, detection_validity, activity_disposition, handling, duplicate_of, "
            "case_resolution_reason, created_at FROM analyst_adjudications "
            f"WHERE analysis_id IN ({placeholders}) ORDER BY created_at DESC, rowid DESC", analysis_ids,
        ).fetchall()
    except sqlite3.Error:
        return {}
    result: dict[tuple[str, str], JsonObject] = {}
    for item in rows:
        key = (str(item["analysis_id"] or ""), str(item["stable_group_id"] or ""))
        if all(key):
            result.setdefault(key, dict(item))
    return result


def _last_seen(rows: list[Row], metadata: dict[str, JsonObject],
               deps: SocReviewDependencies) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in rows:
        group_key = _row_value(row, "group_key")
        dashboard_id = deps.dashboard_group_id(group_key) if group_key else _row_value(row, "group_id")
        if dashboard_id in metadata:
            result[dashboard_id] = (
                _row_value(row, "group_last_seen") or _row_value(row, "last_seen")
                or _row_value(row, "timestamp")
            )
    return result


def _merged_reviewer(response: JsonObject, analysis: JsonObject,
                     persisted: JsonObject | None) -> JsonObject:
    embedded = embedded_reviewer(response, analysis)
    if not persisted:
        return embedded
    reviewer = dict(persisted)
    if not reviewer.get("reviewer_error"):
        reviewer["reviewer_error"] = embedded.get("reviewer_error") or ""
    reviewer["automation_authorization"] = embedded.get("automation_authorization") or {}
    return reviewer


def _disputed_fields(value: object) -> list[object]:
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return parsed[:20] if isinstance(parsed, list) else []


def _freshness_status(evidence_updated: str, generated: str,
                      deps: SocReviewDependencies) -> str:
    evidence_epoch = review_epoch(evidence_updated, deps.parse_timestamp)
    generated_epoch = review_epoch(generated, deps.parse_timestamp)
    return "stale" if evidence_epoch > generated_epoch else "current"


def _coverage_status(used_count: int, gap_count: int) -> str:
    if gap_count:
        return "gaps"
    return "complete" if used_count else "unknown"


def _material_disagreement(reviewer: JsonObject) -> bool:
    value = _text(reviewer, "material_disagreement").strip().lower()
    return value in {"1", "true", "yes"}


def _effective_value(adjudication: JsonObject | None, key: str, fallback: str) -> str:
    if adjudication is None:
        return fallback
    return str(adjudication.get(key))


def _apply_analysis(target: JsonObject, analysis: JsonObject, reviewer: JsonObject,
                    adjudication: JsonObject | None, evidence_updated: str,
                    deps: SocReviewDependencies) -> None:
    response = parse_review_json(analysis.get("response_json"))
    used_count = _list_count(response.get("evidence_used"))
    gap_count = _list_count(response.get("evidence_gaps"))
    generated = _text(analysis, "generated_at", "created_at")
    freshness = _freshness_status(evidence_updated, generated, deps)
    coverage = _coverage_status(used_count, gap_count)
    material = _material_disagreement(reviewer)
    primary_outcome = _text(reviewer, "primary_outcome") or _text(analysis, "detection_outcome")
    primary_confidence = _text(reviewer, "primary_confidence") or _text(analysis, "confidence")
    effective_outcome = _effective_value(adjudication, "outcome_override", primary_outcome)
    effective_confidence = _effective_value(adjudication, "confidence", primary_confidence)
    target.update(_analysis_fields(
        analysis, response, reviewer, adjudication, evidence_updated, generated, freshness, coverage,
        used_count, gap_count, material, primary_outcome, primary_confidence,
        effective_outcome, effective_confidence, deps,
    ))


def _primary_analysis_fields(analysis: JsonObject, response: dict, evidence_updated: str,
                             generated: str, freshness: str, coverage: str,
                             used_count: int, gap_count: int, primary_outcome: str,
                             primary_confidence: str, effective_outcome: str,
                             effective_confidence: str,
                             deps: SocReviewDependencies) -> JsonObject:
    return {
        "analysis_id": _text(analysis, "analysis_id"),
        "detection_outcome": _text(analysis, "detection_outcome"),
        "detection_outcome_label": deps.outcome_label(analysis.get("detection_outcome")),
        "primary_outcome": primary_outcome, "primary_confidence": primary_confidence,
        "primary_event_status": _text(response, "event_status"),
        "primary_detection_validity": _text(response, "detection_validity"),
        "primary_activity_disposition": _text(response, "activity_disposition"),
        "primary_handling": _text(response, "handling"),
        "primary_duplicate_of": response.get("duplicate_of"),
        "effective_outcome": effective_outcome,
        "effective_outcome_label": deps.outcome_label(effective_outcome),
        "effective_confidence": effective_confidence,
        "analysis_confidence": _text(analysis, "confidence"),
        "analysis_generated_at": generated,
        "analysis_evidence_hash": _text(analysis, "evidence_hash"),
        "freshness_status": freshness, "evidence_updated_at": evidence_updated,
        "coverage_status": coverage, "evidence_used_count": used_count, "evidence_gap_count": gap_count,
    }


def _review_analysis_fields(reviewer: JsonObject, adjudication: JsonObject | None,
                            material: bool) -> JsonObject:
    return {
        "reviewer_status": _text(reviewer, "status", default="not_requested"),
        "reviewer_error": _text(reviewer, "reviewer_error")[:1000],
        "reviewer_outcome": _text(reviewer, "reviewer_outcome"),
        "reviewer_confidence": _text(reviewer, "reviewer_confidence"),
        "reviewer_agreement": _text(reviewer, "agreement"),
        "automation_authorization": reviewer_automation_authorization(reviewer),
        "material_disagreement": material,
        "disputed_fields": _disputed_fields(reviewer.get("disputed_fields_json")),
        "final_review_status": review_final_status(reviewer, material, adjudication),
        "adjudication": adjudication,
    }


def _analysis_fields(analysis: JsonObject, response: dict, reviewer: JsonObject,
                     adjudication: JsonObject | None, evidence_updated: str, generated: str,
                     freshness: str, coverage: str, used_count: int, gap_count: int,
                     material: bool, primary_outcome: str, primary_confidence: str,
                     effective_outcome: str, effective_confidence: str,
                     deps: SocReviewDependencies) -> JsonObject:
    primary = _primary_analysis_fields(
        analysis, response, evidence_updated, generated, freshness, coverage, used_count,
        gap_count, primary_outcome, primary_confidence, effective_outcome,
        effective_confidence, deps,
    )
    return {**primary, **_review_analysis_fields(reviewer, adjudication, material)}


def apply_soc_review_metadata(conn: sqlite3.Connection, rows: list[Row],
                              metadata: dict[str, JsonObject], group_by_alert: dict[str, str],
                              dependencies: SocReviewDependencies) -> None:
    """Attach the latest SOC analysis, reviewer, adjudication, freshness, and coverage."""
    if not metadata or not dependencies.table_exists(conn, "ai_analysis_runs"):
        return
    stable = _stable_group_map(conn, metadata, group_by_alert, dependencies)
    dashboards = _dashboards_by_stable(stable)
    analyses = _current_analyses(
        _analysis_query(conn, sorted(dashboards), sorted(group_by_alert), dependencies),
        dashboards, group_by_alert,
    )
    analysis_ids = sorted({str(item.get("analysis_id") or "") for item in analyses.values() if item.get("analysis_id")})
    reviewers = _reviewer_runs(conn, analysis_ids, dependencies)
    adjudications = _adjudications(conn, analysis_ids, dependencies)
    seen = _last_seen(rows, metadata, dependencies)
    for dashboard_id, analysis in analyses.items():
        target = metadata.get(dashboard_id)
        if target is None:
            continue
        analysis_id = str(analysis.get("analysis_id") or "")
        response = parse_review_json(analysis.get("response_json"))
        reviewer = _merged_reviewer(response, analysis, reviewers.get(analysis_id))
        adjudication = adjudications.get((analysis_id, stable.get(dashboard_id) or dashboard_id))
        _apply_analysis(target, analysis, reviewer, adjudication, seen.get(dashboard_id, ""), dependencies)
