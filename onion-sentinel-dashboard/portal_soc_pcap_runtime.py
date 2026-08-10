"""Runtime wiring for SOC PCAP artifacts, request policy, and request storage."""
from __future__ import annotations

from typing import Any


def soc_alert_has_parsed_pcap(runtime: Any, record: dict) -> bool:
    """Return true only for admitted parsed capture artifacts."""
    return runtime._modular_has_parsed_pcap(record)


def read_artifact_cache(runtime: Any, name: str, path: Any) -> object | None:
    return runtime.SOC_ALERT_ARTIFACT_CACHE.get(name, path)


def write_artifact_cache(runtime: Any, name: str, path: Any, value: object) -> object:
    return runtime.SOC_ALERT_ARTIFACT_CACHE.put(name, path, value)


def soc_pcap_artifact_sources(runtime: Any) -> Any:
    return runtime.PcapArtifactSources(
        paths=lambda: runtime.SOC_ALERT_PCAP_ANALYSIS_DIR.glob("*-pcap-analysis.json"),
        read_record=lambda path: runtime.json.loads(path.read_text(encoding="utf-8")),
        modified_time=lambda path: path.stat().st_mtime,
    )


def soc_alert_pcap_analysis_index(runtime: Any) -> dict[str, object]:
    """Index parsed Zeek/TShark artifacts once per API response."""
    return runtime.SOC_ALERT_ARTIFACT_CACHE.get_or_compute(
        "pcap-analysis-index",
        runtime.SOC_ALERT_PCAP_ANALYSIS_DIR,
        lambda: runtime.build_pcap_analysis_index(runtime._soc_pcap_artifact_sources()),
    )


def soc_alert_pcap_request_statuses(runtime: Any, conn: Any, rows: list[Any]) -> dict[str, dict]:
    """Return page-bounded PCAP request state through the modular repository."""
    dependencies = runtime.SocPcapStatusDependencies(
        table_exists=runtime.sqlite_table_exists,
        dashboard_group_id=runtime.soc_alert_group_id,
    )
    return runtime.load_pcap_request_statuses(conn, rows, dependencies)


def soc_alert_pcap_status(
    runtime: Any,
    group_id: str,
    alert_id: str,
    analysis_index: dict[str, object],
    request_statuses: dict[str, dict],
) -> dict:
    """Return the compact PCAP status through the modular policy."""
    return runtime.compose_pcap_status(
        group_id, alert_id, analysis_index, request_statuses
    )


def soc_alert_pcap_analysis_record(runtime: Any, group_id: str) -> dict | None:
    """Return newest parsed PCAP evidence for a grouped alert detail fragment."""
    if not runtime.SOC_ALERT_PCAP_ANALYSIS_DIR.exists():
        return None
    return runtime.newest_pcap_analysis_record(
        group_id, runtime._soc_pcap_artifact_sources()
    )


def soc_alert_pcap_summary_html(runtime: Any, record: dict) -> str:
    """Render bounded parsed packet evidence through the modular renderer."""
    return runtime.render_pcap_summary(record)


def sqlite_table_exists(runtime: Any, conn: Any, table_name: str) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
    except runtime.sqlite3.Error:
        return False
    return bool(row)


def sqlite_table_columns(runtime: Any, conn: Any, table_name: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except runtime.sqlite3.Error:
        return set()
    return {str(row[1]) for row in rows}


def bounded_int(runtime: Any, value: object, default: int, low: int, high: int) -> int:
    return runtime.bounded_pcap_int(value, default, low, high)


def pcap_request_id(runtime: Any, seed: dict) -> str:
    return runtime.projected_pcap_request_id(seed)


def normalize_pcap_timestamp(runtime: Any, value: object) -> str:
    if not value:
        return ""
    try:
        return runtime.format_iso_timestamp(runtime.parse_iso_timestamp(value), utc_z=True)
    except Exception:
        return ""


def pcap_capture_file_from_json(runtime: Any, *values: object) -> str | None:
    return runtime.extract_pcap_capture_file(*values)


def pcap_request_store_sources(runtime: Any) -> Any:
    return runtime.PcapRequestStoreSources(
        table_exists=runtime.sqlite_table_exists,
        table_columns=runtime.sqlite_table_columns,
        now_iso=runtime.now_iso_utc,
    )


def pcap_request_candidate_from_group(runtime: Any, conn: Any, group_id: str) -> dict:
    return runtime.read_pcap_request_candidate(
        runtime.pcap_request_store_sources(), conn, group_id
    )


def pcap_request_policy_sources(runtime: Any) -> Any:
    return runtime.PcapRequestPolicySources(
        normalize_timestamp=runtime.normalize_pcap_timestamp
    )


def normalize_pcap_request(runtime: Any, payload: dict, candidate: dict) -> tuple[dict | None, str]:
    return runtime.normalize_pcap_request_policy(
        runtime.pcap_request_policy_sources(), payload, candidate
    )


def insert_pcap_request(runtime: Any, conn: Any, request: dict) -> Any:
    return runtime.store_pcap_request(runtime.pcap_request_store_sources(), conn, request)


def pcap_request_service_sources(runtime: Any) -> Any:
    return runtime.PcapRequestServiceSources(
        connect_write=runtime.soc_alert_db_write_connect,
        table_exists=runtime.sqlite_table_exists,
        read_candidate=runtime.pcap_request_candidate_from_group,
        normalize_request=runtime.normalize_pcap_request,
        insert_request=runtime.insert_pcap_request,
        post_alert_store=runtime.alert_store_post_json,
        alert_store_configured=bool(runtime.SOC_ALERT_STORE_API_URL),
    )


def soc_alert_pcap_request_response(runtime: Any, group_id: str, payload: dict) -> tuple[int, dict]:
    return runtime.request_soc_alert_pcap(
        runtime.pcap_request_service_sources(), group_id, payload
    )
