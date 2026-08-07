"""Grouped SOC alert page orchestration and public response composition."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


JsonObject = dict[str, object]
Row = object


@dataclass(frozen=True)
class SocAlertQuerySnapshot:
    statuses: dict
    status_counts: dict[str, int]
    active_total: int
    active_severity_counts: dict[str, int]
    active_highest_severity: str
    severity_counts: dict[str, int]
    highest_severity: str
    top_endpoints: dict[str, str]
    filtered_rows: list[Row]
    page_rows: list[Row]
    total_matching: int
    total_pages: int
    current_page: int
    offset: int
    next_cursor: str | None


@dataclass(frozen=True)
class SocGroupQueryDependencies:
    db_path: str
    load_ai_reports: Callable[[], dict]
    load_ai_artifacts: Callable[[list[Row]], dict]
    load_analysis_min_severity: Callable[[], str]
    load_pcap_analysis: Callable[[], dict]
    load_page_evidence: Callable[[list[Row], dict, dict], tuple[dict, dict]]
    present_alert: Callable[..., JsonObject]


@dataclass(frozen=True)
class SocGroupQueryRequestPolicy:
    parse_since: Callable[[str], str]
    parse_levels: Callable[[str], list[str]]
    parse_cursor: Callable[[str], tuple[str, str]]
    parse_limit: Callable[[object], int]
    parse_page: Callable[[object], int]
    parse_sort: Callable[[dict[str, list[str]], bool], tuple[str, str, str]]


@dataclass(frozen=True)
class SocGroupQueryRequest:
    since: str
    levels: list[str]
    filter_status: str
    analyst_status: str
    search: str
    cursor_seen: str
    cursor_id: str
    limit: int
    requested_page: int
    sort_key: str
    sort_direction: str
    summary_order_sql: str
    fallback_order_sql: str


@dataclass(frozen=True)
class SocGroupQueryPlan:
    sql: str
    args: list[object]


@dataclass(frozen=True)
class SocGroupSnapshotDependencies:
    load_statuses: Callable[[], dict]
    status_counts: Callable[[list[Row], dict], dict[str, int]]
    severity_summary: Callable[[list[Row]], dict]
    top_endpoints: Callable[[list[Row]], dict[str, str]]
    enrich_page_rows: Callable[[list[Row]], list[Row]]
    group_id: Callable[[Row], str]


SUMMARY_QUERY_SQL = """
    SELECT group_id, group_key, representative_alert_id AS alert_id,
           first_seen AS group_first_seen, first_seen,
           last_seen AS group_last_seen, last_seen,
           raw_alert_count, total_seen_count, total_seen_count AS seen_count,
           timestamp, rule_name, event_dataset, severity, severity_label,
           source_ip, source_port, destination_ip, destination_port,
           transport_protocol, traffic_direction, triage_score, triage_level,
           routing, filter_status, filter_reason, suppression_key,
           (
             SELECT LENGTH(COALESCE(alert_json, ''))
             FROM alerts
             WHERE alert_id = alert_group_summary.representative_alert_id
             LIMIT 1
           ) AS payload_size_bytes
    FROM alert_group_summary
    {where_sql}
    ORDER BY {order_sql}
"""


FALLBACK_QUERY_SQL = """
    WITH ranked AS (
      SELECT alert_id, first_seen, last_seen, seen_count, timestamp, rule_name,
             event_dataset, severity, severity_label, source_ip, source_port,
             destination_ip, destination_port, transport_protocol,
             traffic_direction, triage_score, triage_level, routing, filter_status,
             filter_reason, suppression_key, alert_json, enrichment_json,
             LENGTH(COALESCE(alert_json, '')) AS payload_size_bytes,
             {group_expr} AS group_key,
             COUNT(*) OVER (PARTITION BY {group_expr}) AS raw_alert_count,
             SUM(MAX(1, COALESCE(seen_count, 1))) OVER (PARTITION BY {group_expr}) AS total_seen_count,
             MIN(first_seen) OVER (PARTITION BY {group_expr}) AS group_first_seen,
             MAX(last_seen) OVER (PARTITION BY {group_expr}) AS group_last_seen,
             ROW_NUMBER() OVER (
               PARTITION BY {group_expr}
               ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                        alert_id DESC
             ) AS rn
      FROM alerts
      {where_sql}
    )
    SELECT *
    FROM ranked
    WHERE rn = 1
    ORDER BY {order_sql}
"""


def _first(query: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = query.get(key)
        if values:
            return str(values[0] or "")
    return default


def parse_group_query_request(query: dict[str, list[str]],
                              policy: SocGroupQueryRequestPolicy) -> SocGroupQueryRequest:
    """Normalize grouped-query aliases once for summary and fallback paths."""
    sort_key, sort_direction, summary_order = policy.parse_sort(query, False)
    _, _, fallback_order = policy.parse_sort(query, True)
    cursor_seen, cursor_id = policy.parse_cursor(_first(query, "cursor"))
    return SocGroupQueryRequest(
        since=policy.parse_since(_first(query, "since")),
        levels=policy.parse_levels(_first(query, "level", "levels")),
        filter_status=_first(query, "filter_status", "status").strip().lower(),
        analyst_status=_first(query, "analyst_status").strip().lower(),
        search=_first(query, "q", "search").strip(),
        cursor_seen=cursor_seen,
        cursor_id=cursor_id,
        limit=policy.parse_limit(_first(query, "limit")),
        requested_page=policy.parse_page(_first(query, "page", default="1")),
        sort_key=sort_key,
        sort_direction=sort_direction,
        summary_order_sql=summary_order,
        fallback_order_sql=fallback_order,
    )


def _where_plan(request: SocGroupQueryRequest, accepted_statuses: frozenset[str],
                search_columns: tuple[str, ...]) -> tuple[str, list[object]]:
    clauses: list[str] = []
    args: list[object] = []
    if request.since:
        clauses.append("last_seen >= ?")
        args.append(request.since)
    if request.levels:
        placeholders = ",".join("?" for _ in request.levels)
        clauses.append(
            f"lower(coalesce(triage_level, severity_label, 'unknown')) in ({placeholders})"
        )
        args.extend(request.levels)
    if request.filter_status in accepted_statuses:
        clauses.append("lower(coalesce(filter_status, 'accepted')) = ?")
        args.append(request.filter_status)
    if request.search:
        clauses.append("(" + " or ".join(f"{column} like ?" for column in search_columns) + ")")
        args.extend([f"%{request.search}%"] * len(search_columns))
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), args


def summary_query_plan(request: SocGroupQueryRequest) -> SocGroupQueryPlan:
    """Build the parameterized hot-path alert_group_summary query."""
    where_sql, args = _where_plan(
        request,
        frozenset({"accepted", "suppressed", "dropped", "duplicate"}),
        ("rule_name", "source_ip", "destination_ip", "event_dataset",
         "representative_alert_id", "group_key"),
    )
    return SocGroupQueryPlan(
        SUMMARY_QUERY_SQL.format(
            where_sql=where_sql,
            order_sql=request.summary_order_sql,
        ),
        args,
    )


def fallback_query_plan(request: SocGroupQueryRequest, group_expr: str) -> SocGroupQueryPlan:
    """Build the parameterized legacy window-function grouped query."""
    where_sql, args = _where_plan(
        request,
        frozenset({"accepted", "suppressed", "dropped"}),
        ("rule_name", "source_ip", "destination_ip", "alert_json"),
    )
    return SocGroupQueryPlan(
        FALLBACK_QUERY_SQL.format(
            group_expr=group_expr,
            where_sql=where_sql,
            order_sql=request.fallback_order_sql,
        ),
        args,
    )


def _row_value(row: Row, key: str, default: object = "") -> object:
    try:
        return row[key]
    except (KeyError, TypeError, IndexError):
        return default


def row_matches_analyst_status(row: Row, group_id: str, statuses: object,
                               analyst_status: str) -> bool:
    """Apply analyst state and backend suppression as one visible-state policy."""
    status_map = statuses if isinstance(statuses, dict) else {}
    state = status_map.get(group_id)
    state = state if isinstance(state, dict) else {}
    current_status = state.get("status", "open")
    filter_status = str(_row_value(row, "filter_status", "accepted") or "accepted").strip().lower()
    if analyst_status in {"open", "new"}:
        return current_status == "open" and filter_status != "suppressed"
    if analyst_status == "suppressed":
        return current_status == "suppressed" or filter_status == "suppressed"
    if analyst_status == "acknowledged":
        return current_status == "acknowledged"
    return True


def filter_group_rows(rows: list[Row], statuses: dict, analyst_status: str,
                      cursor_seen: str, cursor_id: str,
                      group_id: Callable[[Row], str]) -> list[Row]:
    """Apply analyst bucket and stable descending cursor boundaries."""
    filtered: list[Row] = []
    for row in rows:
        resolved_group_id = group_id(row)
        if not row_matches_analyst_status(row, resolved_group_id, statuses, analyst_status):
            continue
        if cursor_seen and cursor_id:
            last_seen = str(
                _row_value(row, "group_last_seen") or _row_value(row, "last_seen") or ""
            )
            if not (
                last_seen < cursor_seen
                or (last_seen == cursor_seen and resolved_group_id < cursor_id)
            ):
                continue
        filtered.append(row)
    return filtered


def group_next_cursor(filtered_rows: list[Row], page_rows: list[Row], offset: int,
                      limit: int, group_id: Callable[[Row], str]) -> str | None:
    """Return the next stable descending cursor only when another row exists."""
    if len(filtered_rows) <= offset + limit or not page_rows:
        return None
    tail = page_rows[-1]
    last_seen = _row_value(tail, "group_last_seen") or _row_value(tail, "last_seen") or ""
    return f"{last_seen}|{group_id(tail)}"


def compose_group_query_snapshot(
    rows: list[Row],
    *,
    analyst_status: str,
    cursor_seen: str,
    cursor_id: str,
    limit: int,
    requested_page: int,
    excluded_group_ids: set[str] | None,
    dependencies: SocGroupSnapshotDependencies,
) -> SocAlertQuerySnapshot:
    """Compose one grouped page and full-query metrics before page slicing."""
    if excluded_group_ids:
        rows = [row for row in rows if dependencies.group_id(row) not in excluded_group_ids]
    statuses = dependencies.load_statuses()
    status_counts = dependencies.status_counts(rows, statuses)
    active_rows = filter_group_rows(rows, statuses, "open", "", "", dependencies.group_id)
    active_severity = dependencies.severity_summary(active_rows)
    filtered_rows = filter_group_rows(
        rows, statuses, analyst_status, cursor_seen, cursor_id, dependencies.group_id,
    )
    severity = dependencies.severity_summary(filtered_rows)
    total_matching = len(filtered_rows)
    total_pages = max(1, (total_matching + limit - 1) // limit)
    current_page = min(requested_page, total_pages)
    offset = (current_page - 1) * limit
    page_rows = dependencies.enrich_page_rows(filtered_rows[offset:offset + limit])
    return SocAlertQuerySnapshot(
        statuses=statuses,
        status_counts=status_counts,
        active_total=len(active_rows),
        active_severity_counts=active_severity["counts"],
        active_highest_severity=active_severity["highest"],
        severity_counts=severity["counts"],
        highest_severity=severity["highest"],
        top_endpoints=dependencies.top_endpoints(filtered_rows),
        filtered_rows=filtered_rows,
        page_rows=page_rows,
        total_matching=total_matching,
        total_pages=total_pages,
        current_page=current_page,
        offset=offset,
        next_cursor=group_next_cursor(
            filtered_rows, page_rows, offset, limit, dependencies.group_id,
        ),
    )


def _present_alerts(snapshot: SocAlertQuerySnapshot, dependencies: SocGroupQueryDependencies,
                    ai_reports: dict, ai_artifacts: dict, pcap_analysis: dict,
                    pcap_requests: dict, evidence_metadata: dict,
                    analysis_min_severity: str) -> list[JsonObject]:
    return [
        dependencies.present_alert(
            row, snapshot.statuses, ai_reports, pcap_analysis, pcap_requests,
            ai_artifacts, evidence_metadata, analysis_min_severity,
        )
        for row in snapshot.page_rows
    ]


def _response(source: str, snapshot: SocAlertQuerySnapshot, limit: int,
              sort_key: str, sort_direction: str, db_path: str,
              alerts: list[JsonObject]) -> JsonObject:
    return {
        "ok": True, "source": source, "mode": "grouped", "db_path": db_path,
        "count": len(snapshot.page_rows), "total_matching": snapshot.total_matching,
        "status_counts": snapshot.status_counts, "active_total": snapshot.active_total,
        "active_severity_counts": snapshot.active_severity_counts,
        "active_highest_severity": snapshot.active_highest_severity,
        "severity_counts": snapshot.severity_counts,
        "highest_severity": snapshot.highest_severity,
        "top_endpoints": snapshot.top_endpoints, "limit": limit,
        "page": snapshot.current_page, "page_size": limit,
        "total_pages": snapshot.total_pages, "sort": sort_key,
        "direction": sort_direction, "next_cursor": snapshot.next_cursor,
        "alerts": alerts,
    }


def compose_group_query_payload(
    *,
    source: str,
    snapshot: SocAlertQuerySnapshot,
    limit: int,
    sort_key: str,
    sort_direction: str,
    dependencies: SocGroupQueryDependencies,
) -> JsonObject:
    """Load page-scoped metadata once and compose the grouped public response."""
    ai_reports = dependencies.load_ai_reports()
    ai_artifacts = dependencies.load_ai_artifacts(snapshot.page_rows)
    analysis_min_severity = dependencies.load_analysis_min_severity()
    pcap_analysis = dependencies.load_pcap_analysis()
    pcap_requests, evidence_metadata = dependencies.load_page_evidence(
        snapshot.page_rows, ai_artifacts, pcap_analysis,
    )
    alerts = _present_alerts(
        snapshot, dependencies, ai_reports, ai_artifacts, pcap_analysis,
        pcap_requests, evidence_metadata, analysis_min_severity,
    )
    return _response(
        source, snapshot, limit, sort_key, sort_direction, dependencies.db_path, alerts,
    )
