"""Production/offline orchestration for SOC PCAP evidence requests."""
from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from http import HTTPStatus


@dataclass(frozen=True)
class PcapRequestServiceSources:
    connect_write: Callable[[], AbstractContextManager]
    table_exists: Callable[[object, str], bool]
    read_candidate: Callable[[object, str], dict]
    normalize_request: Callable[[dict, dict], tuple[dict | None, str]]
    insert_request: Callable[[object, dict], object]
    post_alert_store: Callable[[str, dict], dict]
    alert_store_configured: bool


def _api_error(message: str, status: int = 400) -> tuple[int, dict]:
    return status, {"ok": False, "error": message}


def _queued_payload(data: dict) -> tuple[int, dict]:
    return HTTPStatus.ACCEPTED, {
        **data,
        "pcap_status_key": "queued",
        "pcap_status_label": "Queued",
    }


def _row_mapping(row: object) -> dict:
    if row is None:
        return {}
    if isinstance(row, dict):
        return dict(row)
    keys = getattr(row, "keys", lambda: ())()
    return {key: row[key] for key in keys}


def _offline_request(
    sources: PcapRequestServiceSources,
    group_id: str,
    payload: dict,
) -> tuple[int, dict]:
    try:
        with sources.connect_write() as conn:
            if not sources.table_exists(conn, "pcap_requests"):
                return _api_error(
                    "PCAP broker queue is unavailable",
                    HTTPStatus.SERVICE_UNAVAILABLE,
                )
            candidate = sources.read_candidate(conn, group_id)
            if not candidate:
                return _api_error("SOC alert group not found", HTTPStatus.NOT_FOUND)
            request, error = sources.normalize_request(
                payload, {**candidate, "group_id": group_id}
            )
            if not request:
                return _api_error(error)
            row = sources.insert_request(conn, request)
    except Exception as exc:
        return _api_error(str(exc), HTTPStatus.SERVICE_UNAVAILABLE)
    row_payload = _row_mapping(row)
    return _queued_payload({
        "ok": True,
        "status": row_payload.get("status") or "pending",
        "request": row_payload or request,
    })


def request_soc_alert_pcap(
    sources: PcapRequestServiceSources,
    group_id: object,
    payload: object,
) -> tuple[int, dict]:
    normalized_group = str(group_id or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{12}", normalized_group):
        return _api_error("Invalid SOC alert group id")
    current = payload if isinstance(payload, dict) else {}
    if not sources.alert_store_configured:
        return _offline_request(sources, normalized_group, current)
    try:
        data = sources.post_alert_store(
            "/pcap/request", {**current, "group_id": normalized_group}
        )
    except RuntimeError as exc:
        return _api_error(
            f"Alert-store PCAP request failed: {exc}",
            HTTPStatus.SERVICE_UNAVAILABLE,
        )
    return _queued_payload(data)
