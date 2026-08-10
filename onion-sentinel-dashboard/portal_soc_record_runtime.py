"""Runtime composition for SOC AI artifacts, review metadata, and row presentation."""
from __future__ import annotations

from typing import Any


def soc_alert_row_to_api(r: Any, row: Any, include_payload: bool = False) -> dict:
    alert_id = row["alert_id"]
    statuses = r.load_soc_alert_statuses()
    local = statuses.get(alert_id, {}) if isinstance(statuses, dict) else {}
    data = {
        "alert_id": alert_id, "first_seen": row["first_seen"],
        "last_seen": row["last_seen"], "seen_count": row["seen_count"],
        "timestamp": row["timestamp"], "rule_name": row["rule_name"],
        "event_dataset": row["event_dataset"], "severity": row["severity"],
        "severity_label": row["severity_label"], "triage_score": row["triage_score"],
        "triage_level": row["triage_level"], "routing": row["routing"],
        "traffic_direction": row["traffic_direction"], "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "filter_status": row["filter_status"] or "accepted",
        "filter_reason": row["filter_reason"], "suppression_key": row["suppression_key"],
        "analyst_status": local.get("status", "open") if isinstance(local, dict) else "open",
        "analyst_status_reason": local.get("reason") if isinstance(local, dict) else "",
        "analyst_status_updated_at": local.get("updated_at") if isinstance(local, dict) else None,
    }
    if include_payload:
        try:
            data["alert"] = r.json.loads(row["alert_json"] or "{}")
        except Exception:
            data["alert"] = None
    return data


def soc_alert_static_ai_reports(r: Any) -> dict:
    data = r.read_soc_alert_json_file(r.SOC_ALERT_STATIC_STATUS_FILE)
    reports = data.get("reports") if isinstance(data, dict) else {}
    return reports if isinstance(reports, dict) else {}


def soc_ai_artifact_sources(r: Any) -> Any:
    return r.AiArtifactSources(
        prompt_paths=lambda: r.SOC_ALERT_AI_PROMPT_DIR.glob("*-ai-prompt.json"),
        analysis_paths=lambda: r.SOC_ALERT_AI_ANALYSIS_DIR.glob("*-local-ai-analysis.json"),
        read_record=lambda path: r.json.loads(path.read_text(encoding="utf-8")),
        modified_time=lambda path: path.stat().st_mtime,
    )


def soc_alert_latest_prompt_mtime(r: Any, alert_id: str) -> float:
    if not alert_id or not r.SOC_ALERT_AI_PROMPT_DIR.exists():
        return 0
    return r._modular_latest_prompt_mtime(alert_id, r._soc_ai_artifact_sources())


def soc_alert_latest_analysis_mtime(r: Any, alert_id: str) -> float:
    if not alert_id or not r.SOC_ALERT_AI_ANALYSIS_DIR.exists():
        return 0
    return r._modular_latest_analysis_mtime(alert_id, r._soc_ai_artifact_sources())


def soc_alert_ai_artifact_index(r: Any) -> dict[str, object]:
    cache_path = r.SOC_ALERT_AI_ANALYSIS_DIR.parent
    sources = r._soc_ai_artifact_sources()
    include_prompts = (
        r.SOC_ALERT_AI_PROMPT_DIR.exists()
        and r.SOC_ALERT_AI_ANALYSIS_DIR.exists()
        and r.SOC_ALERT_AI_PROMPT_DIR.parent == r.SOC_ALERT_AI_ANALYSIS_DIR.parent
    )
    return r.SOC_ALERT_ARTIFACT_CACHE.get_or_compute(
        "ai-artifact-index", cache_path,
        lambda: r.build_ai_artifact_index(sources, include_prompts=include_prompts),
    )


def soc_ai_group_members(r: Any, group_keys: list[str]) -> list[tuple[str, str]]:
    if not group_keys:
        return []
    placeholders = ",".join("?" for _ in group_keys)
    try:
        with r.soc_alert_db_connect() as conn:
            rows = conn.execute(
                f"SELECT {r.soc_alert_group_key_sql()} AS group_key, alert_id FROM alerts "
                f"WHERE {r.soc_alert_group_key_sql()} IN ({placeholders})",
                group_keys,
            ).fetchall()
    except Exception:
        return []
    return [
        (str(row["group_key"] or "").strip(), str(row["alert_id"] or "").strip())
        for row in rows if row["group_key"] and row["alert_id"]
    ]


def soc_alert_page_ai_artifact_context(r: Any, rows: list[Any]) -> dict[str, object]:
    dependencies = r.AiArtifactContextDependencies(
        dashboard_group_id=r.soc_alert_group_id,
        group_members=r._soc_ai_group_members,
    )
    return r.compose_page_ai_artifact_context(
        rows, r.soc_alert_ai_artifact_index(), dependencies
    )


def soc_alert_group_has_analysis_artifact(r: Any, row: Any) -> bool:
    if not r.SOC_ALERT_AI_ANALYSIS_DIR.exists():
        return False
    dependencies = r.AiGroupArtifactDependencies(
        group_members=lambda group_key: [
            alert_id for _, alert_id in r._soc_ai_group_members([group_key])
        ],
        latest_analysis_mtime=r.soc_alert_latest_analysis_mtime,
    )
    return r._modular_group_has_analysis_artifact(row, dependencies)


def soc_alert_severity_meets_analysis_threshold(r: Any, severity: object, threshold: object) -> bool:
    return r._modular_severity_meets_threshold(
        severity, threshold, tuple(r.SOC_ANALYSIS_SEVERITY_ORDER)
    )


def soc_alert_group_ai_status(
    r: Any, row: Any, group_id: str, ai_reports: dict | None = None,
    ai_artifacts: dict[str, object] | None = None,
    analysis_min_severity: str = "informational",
) -> dict:
    policy = r.SocAiStatusPolicy(
        severity_order=tuple(r.SOC_ANALYSIS_SEVERITY_ORDER),
        eligible_filter_statuses=frozenset(r.SOC_ALERT_AI_ELIGIBLE_FILTER_STATUSES),
        test_prefixes=r.SOC_ALERT_TEST_PREFIXES,
        latest_prompt_mtime=r.soc_alert_latest_prompt_mtime,
        latest_analysis_mtime=r.soc_alert_latest_analysis_mtime,
        static_reports=r.soc_alert_static_ai_reports,
        group_has_artifact=r.soc_alert_group_has_analysis_artifact,
    )
    return r.compose_soc_ai_status(
        row, group_id, ai_reports, ai_artifacts, analysis_min_severity, policy
    )


def soc_alert_detection_outcome_label(r: Any, value: object) -> str:
    key = r.re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    if not key:
        return "n/a"
    return r.SOC_ALERT_DETECTION_OUTCOME_LABELS.get(key, key.replace("_", " ").title())


def soc_review_epoch(r: Any, value: object) -> float:
    return r._modular_soc_review_epoch(value, r.parse_iso_timestamp)


def soc_alert_apply_review_metadata(
    r: Any, conn: Any, rows: list[Any], metadata: dict[str, dict[str, object]],
    group_by_alert: dict[str, str],
) -> None:
    dependencies = r.SocReviewDependencies(
        table_exists=r.sqlite_table_exists,
        table_columns=r.sqlite_table_columns,
        dashboard_group_id=r.soc_alert_group_id,
        outcome_label=r.soc_alert_detection_outcome_label,
        parse_timestamp=r.parse_iso_timestamp,
    )
    r.apply_soc_review_metadata(conn, rows, metadata, group_by_alert, dependencies)


def soc_alert_review_state_for_group(r: Any, conn: Any, group_id: str) -> dict[str, object]:
    defaults = r._soc_review_defaults()
    if not r.re.fullmatch(r"[a-f0-9]{12}", str(group_id or "")):
        return defaults
    if not r.sqlite_table_exists(conn, "alert_group_summary"):
        return defaults
    row = conn.execute(
        "SELECT * FROM alert_group_summary WHERE group_id = ?", (group_id,)
    ).fetchone()
    if not row:
        return defaults
    alert_id = str(row["representative_alert_id"] or "")
    metadata = {group_id: {
        "pcap_size_bytes": 0, "detection_outcome": "",
        "detection_outcome_label": "n/a", **r._soc_incident_defaults(), **defaults,
    }}
    mapping = {alert_id: group_id} if alert_id else {}
    r.soc_alert_apply_review_metadata(conn, [row], metadata, mapping)
    r.soc_alert_apply_incident_metadata(conn, [row], metadata, mapping)
    return metadata[group_id]


def soc_alert_apply_incident_metadata(
    r: Any, conn: Any, rows: list[Any], metadata: dict[str, dict[str, object]],
    group_by_alert: dict[str, str],
) -> None:
    dependencies = r.SocIncidentDependencies(
        table_exists=r.sqlite_table_exists, table_columns=r.sqlite_table_columns
    )
    r.apply_soc_incident_metadata(conn, metadata, group_by_alert, dependencies)


def soc_alert_group_evidence_metadata(
    r: Any, conn: Any | None, rows: list[Any],
    ai_artifacts: dict[str, object] | None = None,
    pcap_analysis: dict[str, object] | None = None,
) -> dict[str, dict[str, object]]:
    dependencies = r.SocEvidenceDependencies(
        table_exists=r.sqlite_table_exists, table_columns=r.sqlite_table_columns,
        dashboard_group_id=r.soc_alert_group_id,
        outcome_label=r.soc_alert_detection_outcome_label,
        incident_defaults=r._soc_incident_defaults,
        review_defaults=r._soc_review_defaults,
        apply_review=r.soc_alert_apply_review_metadata,
        apply_incident=r.soc_alert_apply_incident_metadata,
    )
    return r.compose_soc_evidence_metadata(
        conn, rows, ai_artifacts, pcap_analysis, dependencies
    )


def soc_alert_group_row_to_api(
    r: Any, row: Any, statuses: dict, ai_reports: dict | None = None,
    pcap_analysis: dict[str, object] | None = None,
    pcap_requests: dict[str, dict] | None = None,
    ai_artifacts: dict[str, object] | None = None,
    evidence_metadata: dict[str, dict[str, object]] | None = None,
    analysis_min_severity: str = "informational",
) -> dict:
    dependencies = r.SocAlertPresentationDependencies(
        dashboard_group_id=r.soc_alert_group_id,
        ai_status=r.soc_alert_group_ai_status,
        enrichment_status=r.soc_alert_public_enrichment_status,
        pcap_status=r.soc_alert_pcap_status,
        incident_defaults=r._soc_incident_defaults,
        review_defaults=r._soc_review_defaults,
    )
    return r.compose_soc_alert_row(
        row, statuses, ai_reports, pcap_analysis, pcap_requests, ai_artifacts,
        evidence_metadata, analysis_min_severity, dependencies,
    )


def soc_alert_group_representative_alert_id(r: Any, group_id: str) -> str:
    group_id = str(group_id or "").strip().lower()
    if not r.re.fullmatch(r"[a-f0-9]{12}", group_id):
        return ""
    group_expr = r.soc_alert_group_key_sql()
    newest = "COALESCE(NULLIF(last_seen, ''), NULLIF(timestamp, ''), NULLIF(first_seen, ''))"
    sql = f"""
        SELECT alert_id, {group_expr} AS group_key FROM alerts
        ORDER BY replace(replace({newest}, 'T', ' '), 'Z', '') DESC, alert_id DESC
    """
    with r.soc_alert_db_connect() as conn:
        for row in conn.execute(sql):
            if r.soc_alert_group_id(row["group_key"]) == group_id:
                return str(row["alert_id"] or "").strip()
    return ""
