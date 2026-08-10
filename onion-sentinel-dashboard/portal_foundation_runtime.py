"""Foundation runtime for timestamps, asset reads, and operational health."""
from __future__ import annotations

from typing import Any


def format_iso_timestamp(r: Any, value: Any, *, timespec: str = "seconds", utc_z: bool = False) -> str:
    if value.tzinfo is None:
        value = value.astimezone()
    if utc_z:
        value = value.astimezone(r.dt.timezone.utc)
    rendered = value.isoformat(timespec=timespec).replace("T", "  ")
    return rendered.replace("+00:00", "Z") if utc_z else rendered


def now_iso_local(r: Any) -> str:
    return r.format_iso_timestamp(r.dt.datetime.now().astimezone())


def now_iso_utc(r: Any) -> str:
    return r.format_iso_timestamp(r.dt.datetime.now(r.dt.timezone.utc), utc_z=True)


def parse_iso_timestamp(r: Any, value: object) -> Any:
    cleaned = str(value).strip()
    cleaned = r.ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1T", cleaned).replace("Z", "+00:00")
    return r.dt.datetime.fromisoformat(cleaned)


def asset_inventory_module(r: Any):
    return r.portal_asset_runtime.asset_inventory_module(r)


def load_asset_inventory_data(r: Any) -> tuple[dict, str]:
    return r.portal_asset_runtime.load_asset_inventory_data(r)


def asset_record_state(r: Any, asset: dict, observed_at: Any) -> str:
    return r.asset_record_state(asset, observed_at, r.parse_iso_timestamp)


def asset_public_record(r: Any, asset: dict, state: str) -> dict:
    return r.asset_public_record(asset, state)


def load_dhcp_asset_discovery_state_data(r: Any) -> tuple[dict, str]:
    return r.DhcpStateRepository(
        database_enabled=r.ASSET_DATABASE_READ_ENABLED,
        fetch_json=r.alert_store_get_json,
        state_path=r.Path(r.DHCP_ASSET_DISCOVERY_STATE_FILE),
        maximum_bytes=r.DHCP_ASSET_DISCOVERY_MAX_BYTES,
    ).load()


def mac_address_scope(r: Any, value: object) -> str:
    return r.mac_address_scope(value)


def annotate_exact_ip_dhcp_macs(r: Any, records: list[dict], observed_at: Any) -> dict:
    return r.portal_asset_runtime.annotate_exact_ip_dhcp_macs(r, records, observed_at)


def dhcp_asset_inventory_overlay(
    r: Any, inventory: dict, observed_at: Any
) -> tuple[dict[str, dict], list[dict], dict]:
    return r.portal_asset_runtime.dhcp_asset_inventory_overlay(r, inventory, observed_at)


def asset_inventory_response(
    r: Any, *, observed_at: Any | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    return r.portal_asset_runtime.asset_inventory_response(
        r, observed_at=observed_at, query=query
    )


def software_asset_label_snapshot(r: Any) -> Any:
    return r.portal_asset_runtime.software_asset_label_snapshot(r)


def software_inventory_response(
    r: Any, *, observed_at: Any | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    return r.portal_asset_runtime.software_inventory_response(
        r, observed_at=observed_at, query=query
    )


def resolve_asset_ip(
    r: Any, value: object, observed_at: object, inventory: dict | None = None
) -> dict:
    return r.portal_asset_runtime.resolve_asset_ip(r, value, observed_at, inventory)


def dhcp_asset_discovery_response(r: Any, *, observed_at: Any | None = None) -> tuple[int, dict]:
    return r.portal_asset_runtime.dhcp_asset_discovery_response(r, observed_at=observed_at)


def pcap_transfer_duration_seconds(r: Any, row: Any, *, has_transfer_duration: bool) -> int | None:
    if has_transfer_duration and row["transfer_duration_seconds"] is not None:
        return max(0, int(row["transfer_duration_seconds"]))
    if not row["claimed_at"] or not row["completed_at"]:
        return None
    try:
        started = r.parse_iso_timestamp(row["claimed_at"])
        completed = r.parse_iso_timestamp(row["completed_at"])
        return max(0, round((completed - started).total_seconds()))
    except (TypeError, ValueError):
        return None


def format_timestamp_text(r: Any, value: object, *, fallback: str = "unknown time") -> str:
    if not value:
        return fallback
    try:
        parsed = value if isinstance(value, r.dt.datetime) else r.parse_iso_timestamp(value)
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return r.format_iso_timestamp(parsed.astimezone())
    except Exception:
        text = str(value).strip()
        return r.ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1  ", text) if text else fallback


def safe_read_json(r: Any, path: Any, fallback: object) -> object:
    try:
        return r.json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def freshest_existing_path(r: Any, paths: list[Any]) -> Any | None:
    existing = [path for path in paths if path.exists()]
    return max(existing, key=lambda path: path.stat().st_mtime) if existing else None


def n8n_beacon_history_response(r: Any, query: dict[str, list[str]]) -> dict[str, object]:
    now = r.dt.datetime.now(r.dt.timezone.utc)
    history_path = r._freshest_existing_path([
        r.SOC_ALERT_N8N_BEACON_HISTORY_FILE,
        r.HOME / "SOC Alerts Web" / "n8n-beacon-history.json",
        r.HOME / "n8n-local" / "alert_store_data" / "n8n-beacon-history.json",
    ])
    raw_history = r._safe_read_json(history_path, []) if history_path else []
    history = raw_history if isinstance(raw_history, list) else []
    latest_path = r._freshest_existing_path([
        r.SOC_ALERT_N8N_BEACON_FILE, r.HOME / "SOC Alerts Web" / "n8n-beacon.json",
        r.HOME / "n8n-local" / "alert_store_data" / "n8n-beacon.json",
    ])
    if not history and latest_path:
        latest = r._safe_read_json(latest_path, {})
        if isinstance(latest, dict):
            history = [latest]
    pipeline: dict[str, object] = {"available": False, "stages": [], "disk": {}}
    try:
        metrics = r.alert_store_get_json("/metrics", timeout=2.0)
        pipeline = dict((metrics.get("metrics") or {}).get("pipeline") or {})
        pipeline["available"] = True
    except RuntimeError as exc:
        pipeline["error"] = str(exc)
    return r.project_beacon_history(
        query, history, now=now, generated_at=r.now_iso_local(),
        history_source=str(history_path) if history_path else None,
        pcap=r.pcap_workflow_health_response(), pipeline=pipeline,
        parse_timestamp=r.parse_iso_timestamp, format_timestamp=r.format_iso_timestamp,
    )


def pcap_workflow_health_response(r: Any) -> dict[str, object]:
    sources = r.PcapHealthSources(
        store_db=r.SOC_ALERT_STORE_DB,
        artifact_dir=r.SOC_ALERT_PCAP_ARTIFACT_DIR,
        analysis_dir=r.SOC_ALERT_PCAP_ANALYSIS_DIR,
        relay_state_paths=(
            r.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE,
            r.HOME / "SOC Alerts Web" / "pcap-workflow-state.json",
            r.HOME / "n8n-local" / "alert_store_data" / "pcap-workflow-state.json",
        ),
        db_connect=r.soc_alert_db_connect, table_exists=r.sqlite_table_exists,
        parse_timestamp=r.parse_iso_timestamp, format_timestamp=r.format_iso_timestamp,
        directory_size=r.directory_size_bytes,
        freshest_path=r._freshest_existing_path, read_json=r._safe_read_json,
    )
    return r.compose_pcap_workflow_health(sources, r.pcap_transfer_duration_seconds)
