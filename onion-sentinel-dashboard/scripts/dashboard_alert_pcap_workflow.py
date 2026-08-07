"""PCAP artifact, broker request, and dashboard status resolution."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from dashboard_alert_detail_values import row_value
from dashboard_alert_repository import alert_group_key
from dashboard_pcap_components import build_pcap_analysis_index
from dashboard_pcap_request_index import load_pcap_request_index, request_for_alert


StatusTuple = tuple[str, str, str]


@dataclass(frozen=True)
class PcapWorkflowConfig:
    """Runtime paths needed to join parsed evidence and broker state."""

    database_path: Path
    analysis_directory: Path


def grouped_alert_id(row: object) -> str:
    """Return the stable short group ID used by PCAP broker records."""
    key = row_value(row, "alert_group_key")
    if not key:
        key = alert_group_key(row)
    return hashlib.sha1(str(key).encode("utf-8")).hexdigest()[:12]


def pcap_analysis_index(config: PcapWorkflowConfig) -> dict[str, object]:
    """Index parsed PCAP artifacts once for dashboard-wide reuse."""
    return build_pcap_analysis_index(config.analysis_directory)


def pcap_request_status_for_row(
    row: object,
    config: PcapWorkflowConfig,
    index: dict[str, object] | None = None,
) -> dict:
    """Resolve newest broker state by stable group ID before representative ID."""
    request_index = index or load_pcap_request_index(config.database_path)
    alert_id = str(row_value(row, "alert_id") or "").strip()
    return request_for_alert(
        request_index,
        group_id=grouped_alert_id(row),
        alert_id=alert_id,
    )


def failed_pcap_status(request_record: dict) -> StatusTuple:
    """Map broker failures into actionable retry/no-packets/failure states."""
    error = str(request_record.get("error") or "").strip()
    if "no matching packets" in error.lower():
        if not request_record.get("used_capture_file"):
            return (
                "error", "Retry",
                "Older PCAP request did not include the Security Onion capture file hint; "
                "retry the request before treating this as no packets",
            )
        return (
            "no-packets", "No Packets",
            "Security Onion found no matching packets for the requested flow/window",
        )
    return "error", "Failed", error[:180] if error else "PCAP request failed before parsed analysis was produced"


def pcap_status_for_row(
    row: object,
    config: PcapWorkflowConfig,
    index: dict[str, object] | None = None,
) -> StatusTuple:
    """Return parsed, queued, failed, no-packets, or absent PCAP status."""
    pcap_index = index or pcap_analysis_index(config)
    group_id = grouped_alert_id(row)
    alert_id = str(row_value(row, "alert_id") or "").strip()
    if group_id in pcap_index.get("group_ids", set()) or alert_id in pcap_index.get("alert_ids", set()):
        return "analyzed", "Analyzed", "Parsed Zeek/TShark PCAP analysis is available for this detection group"
    request = pcap_request_status_for_row(row, config, pcap_index)
    request_status = str(request.get("status") or "").strip().lower()
    if request_status in {"pending", "claimed", "fulfilled"}:
        label = "Queued" if request_status in {"pending", "claimed"} else "Parsing"
        return "queued", label, f"PCAP request is {request_status}; parsed analysis is not available yet"
    if request_status == "failed":
        return failed_pcap_status(request)
    return "none", "None", "No parsed PCAP analysis is available for this detection group"


def indexed_record(index: dict[str, object], bucket: str, key: str) -> dict | None:
    """Return one parsed record from a typed index bucket."""
    records = index.get(bucket)
    if not isinstance(records, dict):
        return None
    record = records.get(key)
    return record if isinstance(record, dict) else None


def pcap_analysis_for_row(
    row: object,
    config: PcapWorkflowConfig,
    index: dict[str, object] | None = None,
) -> dict | None:
    """Return parsed evidence by group, alert, then broker request identity."""
    pcap_index = index or pcap_analysis_index(config)
    group_id = grouped_alert_id(row)
    alert_id = str(row_value(row, "alert_id") or "").strip()
    for bucket, key in (
        ("records_by_group_id", group_id),
        ("records_by_alert_id", alert_id),
    ):
        record = indexed_record(pcap_index, bucket, key)
        if record is not None:
            return record
    request = pcap_request_status_for_row(row, config, pcap_index)
    request_id = str(request.get("request_id") or "").strip()
    return indexed_record(pcap_index, "records_by_request_id", request_id)
