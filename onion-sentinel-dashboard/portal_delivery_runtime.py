"""Runtime composition for live revisions, event snapshots, and route callbacks."""
from __future__ import annotations

from typing import Any


def read_soc_alert_json_file(r: Any, path: Any) -> dict:
    try:
        if path.exists() and path.is_file():
            data = r.json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}
    return {}


def soc_alert_events_snapshot(r: Any) -> dict:
    analyst_status = r.soc_alert_status_response()
    static_status = r.read_soc_alert_json_file(r.SOC_ALERT_STATIC_STATUS_FILE)
    current_analysis = r.read_llm_current_analysis()
    beacon = r.read_soc_alert_json_file(r.SOC_ALERT_N8N_BEACON_FILE)
    metrics_status, metrics = r.soc_alert_metrics_response({"since": [""]})
    if metrics_status != 200:
        metrics = {"ok": False, "error": metrics.get("error", "SOC alert metrics unavailable")}
    return {
        "ok": True, "event": "soc-alerts", "time": r.now_iso_utc(),
        "revisions": r.dashboard_live_revisions(),
        "counts": analyst_status.get("counts", {}),
        "statuses": analyst_status.get("statuses", {}),
        "ai": r.merge_live_llm_activity(static_status.get("ai", {}), current_analysis),
        "reports": static_status.get("reports", {}),
        "status_updated_at": static_status.get("updated_at"),
        "metrics": metrics, "beacon": beacon,
    }


def asset_inventory_live_revision(r: Any) -> str:
    _, payload = r.asset_inventory_response()
    stable = dict(payload)
    stable.pop("observed_at", None)
    return r._revision_digest(stable)


def dhcp_asset_discovery_live_revision(r: Any, asset_revision: str) -> str:
    state_revision = r._bounded_file_revision(
        r.Path(r.DHCP_ASSET_DISCOVERY_STATE_FILE), r.DHCP_ASSET_DISCOVERY_MAX_BYTES
    )
    return r._revision_digest((state_revision, asset_revision))


def software_inventory_live_revision(r: Any) -> str:
    return r._bounded_file_revision(
        r.Path(r.SOFTWARE_INVENTORY_STATE_FILE), r.SOFTWARE_INVENTORY_MAX_BYTES
    )


def incident_response_live_revision(r: Any) -> str:
    try:
        with r.soc_alert_db_connect() as conn:
            return r.incident_response_revision(
                conn,
                r.RevisionSchemaDependencies(
                    table_exists=r.sqlite_table_exists,
                    table_columns=r.sqlite_table_columns,
                ),
            )
    except (FileNotFoundError, r.sqlite3.Error):
        return r._revision_digest(("unavailable",))


def dashboard_live_revisions(r: Any) -> dict[str, str]:
    asset_revision = r.asset_inventory_live_revision()
    return {
        "incidents": r.incident_response_live_revision(),
        "asset_inventory": asset_revision,
        "dhcp_asset_discovery": r.dhcp_asset_discovery_live_revision(asset_revision),
        "software_inventory": r.software_inventory_live_revision(),
        "ac_hunter": r.ac_hunter_live_revision(),
    }


def ac_hunter_live_revision(r: Any) -> str:
    try:
        payload = r.alert_store_get_json("/ac-hunter/snapshot", timeout=2.0)
        cache = payload.get("cache")
        if isinstance(cache, dict):
            digest = str(cache.get("dataset_digest") or "").strip().lower()
            if r.re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    except RuntimeError:
        pass
    return r._revision_digest(("unavailable",))


def cached_soc_alert_events_snapshot(r: Any) -> dict:
    return r.SOC_ALERT_EVENTS_CACHE.get_or_compute(
        "soc-alert-events", r.soc_alert_events_snapshot
    )


def ack_soc_alert_store_id(r: Any, alert_id: str, payload: dict) -> tuple[int, dict]:
    alert_id = r.valid_soc_alert_store_id(alert_id)
    if not alert_id:
        return r.soc_alert_api_error("Invalid SOC alert id")
    payload = {**payload, "id": alert_id}
    ok, data = r.update_soc_alert_status(payload)
    status = r.HTTPStatus.OK if ok else int(data.get("status") or r.HTTPStatus.BAD_REQUEST)
    if ok:
        alert_status = r.load_soc_alert_statuses().get(alert_id, {})
        data = {
            **data, "alert_id": alert_id,
            "analyst_status": alert_status.get("status", "open") if isinstance(alert_status, dict) else "open",
            "analyst_status_reason": alert_status.get("reason", "") if isinstance(alert_status, dict) else "",
        }
    return int(status), data


def portal_soc_read_callbacks(r: Any) -> Any:
    return r.SocReadCallbacks(
        llm_current=r.read_llm_current_analysis,
        llm_logs=r.llm_analysis_logs_response,
        alert_status=r.soc_alert_status_response,
        settings_prompt=r.read_settings_prompt,
        agent_memory=r.read_agent_memory,
        ai_settings=r.read_soc_ai_settings,
        ollama_models=r.ollama_models_response,
        alerts=r.cached_soc_alerts_query_response,
        alert_metrics=r.soc_alert_metrics_response,
        alert_suppressions=r.soc_alert_suppressions_response,
        incidents=r.soc_incidents_query_response,
        reanalysis_runs=r.soc_incident_reanalysis_runs_response,
        incident_case_group=r._soc_incident_case_group_id,
        api_error=r.soc_alert_api_error,
        adjudication_history=r.soc_adjudication_history_response,
        incident_detail=r.soc_incident_detail_response,
        alert_detail_fragment=r.soc_alert_detail_fragment_response,
        alert_detail=r.soc_alert_detail_response,
    )


def portal_general_read_callbacks(r: Any, home: Any) -> Any:
    def cti_program_read() -> tuple[int, dict]:
        result = r.read_cti_program(r.portal_cti_program_callbacks(lambda _program: None))
        return result.status, result.payload
    return r.GeneralReadCallbacks(
        home=home,
        health=lambda: r.compose_portal_health(
            r.scan_reports(), r.SCAN_ROOTS,
            local_address=r.local_ip(), generated_at=r.now_iso_local(),
        ),
        resource_favorites=r.resource_favorites,
        system_health_beacons=r.n8n_beacon_history_response,
        asset_inventory=lambda query: r.asset_inventory_response(query=query),
        dhcp_asset_discovery=r.dhcp_asset_discovery_response,
        software_inventory=lambda query: r.software_inventory_response(query=query),
        cti_program=cti_program_read,
    )


def portal_json_write_callbacks(r: Any, handler: Any) -> Any:
    return r.JsonWriteCallbacks(
        same_origin_authorized=lambda: handler._soc_review_write_authorized(),
        cti_admin_authenticated=lambda: handler._cti_program_write_authorized(),
        cti_program=r.portal_cti_program_callbacks(
            lambda program: handler._cti_program_mutation_audit(program)
        ),
        asset_admin_authenticated=lambda: handler._admin_authenticated(),
        asset_dispatcher=r.dispatch_asset_write,
        soc_dispatcher=r.dispatch_authorized_soc_write,
        soc=r.PORTAL_SOC_WRITE_CALLBACKS,
        clear_soc_cache=r.SOC_ALERT_RESPONSE_CACHE.clear,
        status_update=r.update_soc_alert_status,
        settings_admin_authenticated=lambda: handler._soc_settings_write_authorized(),
        settings=r.SocSettingsWriteCallbacks(
            save_prompt=r.save_settings_prompt,
            save_ai_settings=r.save_soc_ai_settings,
            save_agent_model=r.save_soc_agent_model,
        ),
        admin_authenticated=lambda: handler._admin_authenticated(),
        admin_service=r.AdminServiceWriteCallbacks(
            r.ensure_admin_token, r.start_admin_service
        ),
        resource_library=r.ResourceLibraryWriteCallbacks(
            r.move_resource_to_removal, r.set_resource_tags,
            r.rename_resource_file, r.set_resource_favorite,
        ),
    )
