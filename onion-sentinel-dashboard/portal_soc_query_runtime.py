"""Runtime composition for grouped SOC alert reads and bounded detail APIs."""
from __future__ import annotations

from typing import Any


def soc_alert_status_bucket_counts(r: Any, rows: list[Any], statuses: dict) -> dict[str, int]:
    return r.soc_alert_api.status_bucket_counts(
        rows, statuses, r.soc_alert_group_id_for_query_row
    )


def soc_alert_top_endpoint_metrics(r: Any, rows: list[Any]) -> dict[str, str]:
    return r.soc_alert_api.top_endpoint_metrics(rows)


def soc_alert_group_id_for_query_row(r: Any, row: Any) -> str:
    keys = row.keys()
    if "group_id" in keys and row["group_id"]:
        return str(row["group_id"])
    return r.soc_alert_group_id(row["group_key"])


def soc_alert_enriched_page_rows(r: Any, page_rows: list[Any]) -> list[Any]:
    if not page_rows:
        return []
    try:
        with r.soc_alert_db_connect() as conn:
            enrichment_by_group = r.soc_alert_group_enrichment_json_map(
                conn, r.page_group_keys(page_rows)
            )
    except Exception:
        return [dict(row) for row in page_rows]
    return r.merge_page_enrichment(page_rows, enrichment_by_group)


def soc_alert_group_query_snapshot(
    r: Any,
    rows: list[Any],
    *,
    analyst_status: str,
    cursor_seen: str,
    cursor_id: str,
    limit: int,
    requested_page: int,
    excluded_group_ids: set[str] | None = None,
) -> Any:
    dependencies = r.SocGroupSnapshotDependencies(
        load_statuses=r.load_soc_alert_statuses,
        status_counts=r.soc_alert_status_bucket_counts,
        severity_summary=r.soc_alert_visible_severity_summary,
        top_endpoints=r.soc_alert_top_endpoint_metrics,
        enrich_page_rows=r.soc_alert_enriched_page_rows,
        group_id=r.soc_alert_group_id_for_query_row,
    )
    return r.compose_group_query_snapshot(
        rows,
        analyst_status=analyst_status,
        cursor_seen=cursor_seen,
        cursor_id=cursor_id,
        limit=limit,
        requested_page=requested_page,
        excluded_group_ids=excluded_group_ids,
        dependencies=dependencies,
    )


def soc_alert_group_query_payload(
    r: Any,
    *,
    source: str,
    snapshot: Any,
    limit: int,
    sort_key: str,
    sort_direction: str,
) -> dict:
    dependencies = r.SocGroupQueryDependencies(
        db_path=str(r.SOC_ALERT_STORE_DB),
        load_ai_reports=r.soc_alert_static_ai_reports,
        load_ai_artifacts=r.soc_alert_page_ai_artifact_context,
        load_analysis_min_severity=r._soc_analysis_min_severity,
        load_pcap_analysis=r.soc_alert_pcap_analysis_index,
        load_page_evidence=r._soc_group_page_evidence,
        present_alert=r.soc_alert_group_row_to_api,
    )
    return r.compose_group_query_payload(
        source=source,
        snapshot=snapshot,
        limit=limit,
        sort_key=sort_key,
        sort_direction=sort_direction,
        dependencies=dependencies,
    )


def soc_analysis_min_severity(r: Any) -> str:
    response = r.read_soc_ai_settings()
    settings = response.get("settings", {}) if isinstance(response, dict) else {}
    return str(settings.get("soc_analyst_analysis_min_severity") or "informational")


def soc_group_page_evidence(
    r: Any, page_rows: list[Any], ai_artifacts: dict, pcap_analysis: dict
) -> tuple[dict, dict]:
    try:
        with r.soc_alert_db_connect() as conn:
            pcap_requests = r.soc_alert_pcap_request_statuses(conn, page_rows)
            evidence_metadata = r.soc_alert_group_evidence_metadata(
                conn, page_rows, ai_artifacts, pcap_analysis
            )
    except Exception:
        pcap_requests = {}
        evidence_metadata = r.soc_alert_group_evidence_metadata(
            None, page_rows, ai_artifacts, pcap_analysis
        )
    return pcap_requests, evidence_metadata


def soc_alert_group_query_request(r: Any, query: dict[str, list[str]]) -> Any:
    policy = r.SocGroupQueryRequestPolicy(
        parse_since=r.parse_soc_alert_since,
        parse_levels=r.soc_alert_level_names,
        parse_cursor=r.soc_alert_cursor_parts,
        parse_limit=r.soc_alert_limit,
        parse_page=r.soc_alert_page,
        parse_sort=lambda values, fallback: r.soc_alert_sort_clause(
            values, fallback=fallback
        ),
    )
    return r.parse_group_query_request(query, policy)


def soc_alerts_summary_query_response(r: Any, request: Any) -> tuple[int, dict] | None:
    """Serve the grouped summary-table plan when its durable table is available."""
    plan = r.summary_query_plan(request)
    try:
        with r.soc_alert_db_connect() as conn:
            if not r.soc_alert_group_summary_available(conn):
                return None
            rows = conn.execute(plan.sql, plan.args).fetchall()
            excluded = r.soc_alert_manually_escalated_group_ids(conn)
    except Exception as exc:
        return r.soc_alert_api_error(str(exc), 503)
    snapshot = r.soc_alert_group_query_snapshot(
        rows,
        analyst_status=request.analyst_status,
        cursor_seen=request.cursor_seen,
        cursor_id=request.cursor_id,
        limit=request.limit,
        requested_page=request.requested_page,
        excluded_group_ids=excluded,
    )
    return 200, r.soc_alert_group_query_payload(
        source="sqlite-summary",
        snapshot=snapshot,
        limit=request.limit,
        sort_key=request.sort_key,
        sort_direction=request.sort_direction,
    )


def soc_alerts_query_response(r: Any, query: dict[str, list[str]]) -> tuple[int, dict]:
    request = r.soc_alert_group_query_request(query)
    summary_response = r.soc_alerts_summary_query_response(request)
    if summary_response is not None:
        return summary_response
    plan = r.fallback_query_plan(request, r.soc_alert_group_key_sql())
    try:
        with r.soc_alert_db_connect() as conn:
            rows = conn.execute(plan.sql, plan.args).fetchall()
            excluded = r.soc_alert_manually_escalated_group_ids(conn)
    except Exception as exc:
        return r.soc_alert_api_error(str(exc), 503)
    snapshot = r.soc_alert_group_query_snapshot(
        rows,
        analyst_status=request.analyst_status,
        cursor_seen=request.cursor_seen,
        cursor_id=request.cursor_id,
        limit=request.limit,
        requested_page=request.requested_page,
        excluded_group_ids=excluded,
    )
    return 200, r.soc_alert_group_query_payload(
        source="sqlite",
        snapshot=snapshot,
        limit=request.limit,
        sort_key=request.sort_key,
        sort_direction=request.sort_direction,
    )


def cached_soc_alerts_query_response(r: Any, query: dict[str, list[str]]) -> tuple[int, bytes]:
    """Coalesce query and JSON encoding work during multi-analyst bursts."""
    key = r.json.dumps(query, sort_keys=True, separators=(",", ":"))

    def build_response() -> tuple[int, bytes]:
        status, data = r.soc_alerts_query_response(query)
        return status, r.json.dumps(data, separators=(",", ":")).encode()

    return r.SOC_ALERT_RESPONSE_CACHE.get_or_compute(("soc-alerts", key), build_response)


def soc_alert_detail_fragment_response(r: Any, group_id: str) -> tuple[int, dict]:
    group_id = str(group_id or "").strip().lower()
    if not r.re.fullmatch(r"[a-f0-9]{12}", group_id):
        return r.soc_alert_api_error("Invalid SOC alert group id")
    detail_path = r.SOC_ALERT_DETAIL_DIR / f"{group_id}.html"
    try:
        base = r.SOC_ALERT_DETAIL_DIR.resolve()
        target = detail_path.resolve()
    except Exception:
        return r.soc_alert_api_error("SOC alert detail path unavailable", 503)
    if base not in target.parents or target.suffix != ".html":
        return r.soc_alert_api_error("Invalid SOC alert detail path")
    if not target.exists():
        return r.soc_alert_api_error("SOC alert detail fragment not found", 404)
    try:
        if target.stat().st_size > r.SOC_ALERT_DETAIL_FRAGMENT_MAX_BYTES:
            return r.soc_alert_api_error(
                "SOC alert detail fragment exceeded the safe render limit", 413
            )
        detail_html = target.read_text(encoding="utf-8")
    except OSError as exc:
        return r.soc_alert_api_error(str(exc), 503)
    review = _soc_alert_fragment_review(r, group_id)
    detail_html = r.soc_alert_append_live_pcap_detail(group_id, detail_html)
    detail_html = r.soc_alert_collapse_detail_sections(detail_html)
    detail_html = r.render_analyst_review_panel(review, group_id=group_id) + detail_html
    detail_html, layout_issues = _soc_alert_fragment_layout(r, detail_html)
    return 200, {
        "ok": True,
        "source": "detail-fragment",
        "group_id": group_id,
        "layout_version": r.SOC_ALERT_DETAIL_LAYOUT_VERSION,
        "layout_valid": not layout_issues,
        "layout_issues": layout_issues,
        "review": review,
        "detail_html": detail_html,
    }


def _soc_alert_fragment_review(r: Any, group_id: str) -> dict:
    review = r._soc_review_defaults()
    try:
        with r.soc_alert_db_connect() as conn:
            review = r.soc_alert_review_state_for_group(conn, group_id)
    except (FileNotFoundError, r.sqlite3.Error):
        pass
    return review


def _soc_alert_fragment_layout(r: Any, detail_html: str) -> tuple[str, list[str]]:
    layout_issues = r.soc_alert_validate_detail_layout_html(detail_html)
    if layout_issues and "detail-layout-error" not in detail_html:
        detail_html = r.soc_alert_layout_error_html(layout_issues) + detail_html
    return detail_html, layout_issues


def soc_alert_detail_response(r: Any, alert_id: str) -> tuple[int, dict]:
    alert_id = r.valid_soc_alert_store_id(alert_id)
    if not alert_id:
        return r.soc_alert_api_error("Invalid SOC alert id")
    try:
        with r.soc_alert_db_connect() as conn:
            row = conn.execute("""
                select alert_id, first_seen, last_seen, seen_count, timestamp, rule_name,
                       event_dataset, severity, severity_label, source_ip, destination_ip,
                       traffic_direction, triage_score, triage_level, routing, filter_status,
                       filter_reason, suppression_key, alert_json
                from alerts where alert_id = ?
            """, (alert_id,)).fetchone()
    except Exception as exc:
        return r.soc_alert_api_error(str(exc), 503)
    if not row:
        return r.soc_alert_api_error("SOC alert not found", 404)
    return 200, {
        "ok": True,
        "source": "sqlite",
        "alert": r.soc_alert_row_to_api(row, include_payload=True),
    }


def soc_alert_metrics_response(r: Any, query: dict[str, list[str]]) -> tuple[int, dict]:
    since = r.parse_soc_alert_since((query.get("since") or ["24h"])[0])
    try:
        with r.soc_alert_db_connect() as conn:
            plan = r.metrics_query_plan(
                since, r.soc_alert_group_key_sql(),
                r.soc_alert_group_summary_available(conn),
            )
            total = conn.execute(plan.total_sql, plan.args).fetchone()[0]
            latest = conn.execute(plan.latest_sql, plan.args).fetchone()[0]
            grouped_rows = conn.execute(plan.grouped_sql, plan.args).fetchall()
            grouped_rows = r.exclude_group_rows(
                grouped_rows,
                r.soc_alert_manually_escalated_group_ids(conn),
                r.soc_alert_group_id_for_query_row,
            )
            by_filter = {
                row[0] or "accepted": row[1]
                for row in conn.execute(plan.filter_status_sql, plan.args)
            }
            by_level = {
                row[0] or "unknown": row[1]
                for row in conn.execute(plan.level_sql, plan.args)
            }
            top_rules = [
                dict(rule_name=row[0] or "unknown", count=row[1])
                for row in conn.execute(plan.top_rules_sql, plan.args)
            ]
            suppression_windows = conn.execute(plan.suppression_sql).fetchone()
    except Exception as exc:
        return r.soc_alert_api_error(str(exc), 503)
    statuses = r.load_soc_alert_statuses()
    by_analyst_status = r.soc_alert_status_bucket_counts(grouped_rows, statuses)
    return 200, r.compose_metrics_payload(
        source=plan.source,
        since=since,
        total=total,
        latest_seen=latest,
        grouped_rows=grouped_rows,
        pcap_ingest_size_bytes=r.directory_size_bytes(r.SOC_ALERT_PCAP_ARTIFACT_DIR),
        by_filter_status=by_filter,
        by_analyst_status=by_analyst_status,
        by_level=by_level,
        top_rules=top_rules,
        suppression_totals=suppression_windows,
    )


def soc_alert_suppressions_response(r: Any, query: dict[str, list[str]]) -> tuple[int, dict]:
    limit = r.soc_alert_limit((query.get("limit") or [100])[0])
    try:
        with r.soc_alert_db_connect() as conn:
            rows = conn.execute("""
                select suppression_key, rule_name, reason, window_start, last_seen,
                       seen_count, suppressed_count, escalated_count, ttl_seconds,
                       escalation_threshold
                from suppression_log
                order by last_seen desc, suppression_key asc
                limit ?
            """, (limit,)).fetchall()
    except Exception as exc:
        return r.soc_alert_api_error(str(exc), 503)
    return 200, {
        "ok": True,
        "source": "sqlite",
        "count": len(rows),
        "suppressions": [dict(row) for row in rows],
    }
