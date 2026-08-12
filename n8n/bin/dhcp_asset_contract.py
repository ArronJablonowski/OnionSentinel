#!/usr/bin/env python3
"""Pure DHCP discovery response, timestamp, and identity contracts."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re


CONTRACT = "onion-sentinel-dhcp-asset-discovery-v1"
STATE_SCHEMA = "onion-sentinel-dhcp-asset-observations-v1"
MAX_RESPONSE_OBSERVATIONS = 1000
HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})?))*\.?"
)
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(
        str(value or "").strip().replace("Z", "+00:00")
    )
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks offset")
    return parsed.astimezone(dt.timezone.utc)


def format_timestamp(value: dt.datetime) -> str:
    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _validate_accounting(payload: dict, observations: object) -> list[object]:
    if (
        not isinstance(observations, list)
        or len(observations) > MAX_RESPONSE_OBSERVATIONS
    ):
        raise ValueError("relay response contains an invalid observation list")
    if payload.get("status") not in {"ok", "partial"}:
        raise ValueError("relay response contains an invalid status")
    hits_total = payload.get("hits_total")
    returned = payload.get("returned")
    if (
        isinstance(hits_total, bool)
        or not isinstance(hits_total, int)
        or hits_total < 0
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(observations)
        or not isinstance(payload.get("truncated"), bool)
    ):
        raise ValueError("relay response contains invalid result accounting")
    return observations


def _validated_window(
    payload: dict,
    expected_window: dict | None,
) -> tuple[dt.datetime, dt.datetime]:
    audit = payload.get("query_audit")
    if (
        not isinstance(audit, dict)
        or audit.get("index") != "logs-zeek-so"
        or audit.get("dataset") != "zeek.dhcp"
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(audit.get("query_digest") or "")
        )
    ):
        raise ValueError("relay response contains an invalid fixed-query audit")
    response_window = payload.get("window")
    if (
        not isinstance(response_window, dict)
        or set(response_window) != {"start", "end"}
    ):
        raise ValueError("relay response contains an invalid query window")
    window_start = parse_timestamp(response_window["start"])
    window_end = parse_timestamp(response_window["end"])
    if (
        window_start >= window_end
        or window_end - window_start > dt.timedelta(hours=24)
    ):
        raise ValueError("relay response query window is out of bounds")
    if expected_window is not None and (
        format_timestamp(window_start)
        != format_timestamp(parse_timestamp(expected_window["start"]))
        or format_timestamp(window_end)
        != format_timestamp(parse_timestamp(expected_window["end"]))
    ):
        raise ValueError("relay response query window does not match the request")
    return window_start, window_end


def _normalize_observation(
    item: object,
    window_start: dt.datetime,
    window_end: dt.datetime,
) -> dict:
    if not isinstance(item, dict):
        raise ValueError("relay response contains a non-object observation")
    observed = parse_timestamp(item.get("observed_at"))
    if observed < window_start or observed > window_end + dt.timedelta(minutes=5):
        raise ValueError("relay response observation is outside the requested window")
    address, mac_raw, hostname_raw = _normalize_identity(item)
    lease, evidence_id = _normalize_lease_evidence(item)
    return {
        "observed_at": format_timestamp(observed),
        "ip_address": address,
        "mac_address": mac_raw.lower(),
        "hostname": hostname_raw,
        "message_type": str(item.get("message_type") or "")[:80],
        "lease_seconds": lease,
        "sensor": str(item.get("sensor") or "")[:160],
        "evidence_id": evidence_id,
    }


def _normalize_identity(item: dict) -> tuple[str, str, str]:
    address = str(ipaddress.ip_address(str(item.get("ip_address") or "").strip()))
    mac_raw = str(item.get("mac_address") or "").strip()
    if mac_raw and not MAC_RE.fullmatch(mac_raw):
        raise ValueError("relay response contains an invalid MAC address")
    hostname_raw = str(item.get("hostname") or "").strip().rstrip(".").lower()
    if hostname_raw and not HOSTNAME_RE.fullmatch(hostname_raw):
        raise ValueError("relay response contains an invalid hostname")
    return address, mac_raw, hostname_raw


def _normalize_lease_evidence(item: dict) -> tuple[int, str]:
    lease = item.get("lease_seconds", 0)
    if (
        isinstance(lease, bool)
        or not isinstance(lease, int)
        or not 0 <= lease <= 31 * 24 * 60 * 60
    ):
        raise ValueError("relay response contains an invalid lease duration")
    evidence_id = str(item.get("evidence_id") or "")
    if not re.fullmatch(r"[0-9a-f]{24}", evidence_id):
        raise ValueError("relay response contains an invalid evidence identifier")
    return lease, evidence_id


def validate_response(
    payload: object,
    expected_window: dict | None = None,
) -> dict:
    if (
        not isinstance(payload, dict)
        or payload.get("ok") is not True
        or payload.get("contract") != CONTRACT
    ):
        raise ValueError("relay response failed the DHCP discovery contract")
    observations = _validate_accounting(payload, payload.get("observations"))
    window_start, window_end = _validated_window(payload, expected_window)
    cleaned = [
        _normalize_observation(item, window_start, window_end)
        for item in observations
    ]
    result = dict(payload)
    result["observations"] = cleaned
    return result


def observation_identity(item: dict) -> tuple[str, str]:
    if item["mac_address"]:
        return "mac", item["mac_address"]
    if item["hostname"]:
        return "hostname", item["hostname"]
    return "ip", item["ip_address"]
