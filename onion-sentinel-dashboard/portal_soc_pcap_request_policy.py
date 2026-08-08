"""Pure normalization policy for analyst-requested SOC PCAP evidence."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class PcapRequestPolicySources:
    normalize_timestamp: Callable[[object], str]


def bounded_int(value: object, default: int, low: int, high: int) -> int:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError, OverflowError):
        number = default
    return max(low, min(high, number))


def pcap_request_id(seed: dict) -> str:
    raw = json.dumps(seed, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _request_times(
    sources: PcapRequestPolicySources,
    merged: dict,
) -> tuple[str, str]:
    first_seen = sources.normalize_timestamp(
        merged.get("first_seen")
        or merged.get("timestamp")
        or merged.get("last_seen")
    )
    last_seen = sources.normalize_timestamp(
        merged.get("last_seen")
        or merged.get("timestamp")
        or merged.get("first_seen")
    )
    return first_seen, last_seen


def _request_identity_seed(request: dict) -> dict:
    return {
        key: request[key]
        for key in (
            "alert_id",
            "group_id",
            "first_seen",
            "last_seen",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "community_id",
            "capture_file",
            "reason",
        )
    }


def _optional_text(value: object, limit: int, *, lower: bool = False) -> str | None:
    text = str(value or "").strip()
    text = text.lower() if lower else text
    return text[:limit] or None


def _default_text(value: object, default: str, limit: int) -> str:
    return str(value or default).strip()[:limit] or default


def _optional_port(value: object) -> int | None:
    return bounded_int(value, 0, 0, 65535) or None


def _normalized_request(
    merged: dict,
    source_ip: str,
    destination_ip: str,
    first_seen: str,
    last_seen: str,
) -> dict:
    return {
        "alert_id": _optional_text(merged.get("alert_id"), 512),
        "group_id": _optional_text(merged.get("group_id"), 64),
        "group_key": _optional_text(merged.get("group_key"), 512),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "source_ip": source_ip,
        "source_port": _optional_port(merged.get("source_port")),
        "destination_ip": destination_ip,
        "destination_port": _optional_port(merged.get("destination_port")),
        "network_protocol": _optional_text(
            merged.get("network_protocol"), 32
        ),
        "transport_protocol": _optional_text(
            merged.get("transport_protocol"), 32, lower=True
        ),
        "community_id": _optional_text(merged.get("community_id"), 128),
        "capture_file": _optional_text(merged.get("capture_file"), 512),
        "requested_by": _default_text(
            merged.get("requested_by"), "dashboard", 80
        ),
        "reason": _default_text(
            merged.get("reason"), "SOC analyst requested PCAP evidence", 240
        ),
        "max_window_seconds": bounded_int(
            merged.get("max_window_seconds"), 120, 30, 300
        ),
        "require_source_port": bool(merged.get("require_source_port")),
    }


def normalize_pcap_request(
    sources: PcapRequestPolicySources,
    payload: object,
    candidate: object,
) -> tuple[dict | None, str]:
    base = candidate if isinstance(candidate, dict) else {}
    overrides = payload if isinstance(payload, dict) else {}
    merged = {**base, **overrides}
    source_ip = str(merged.get("source_ip") or "").strip()[:64]
    destination_ip = str(merged.get("destination_ip") or "").strip()[:64]
    first_seen, last_seen = _request_times(sources, merged)
    if not source_ip or not destination_ip:
        return None, "PCAP request requires source and destination IPs"
    if not first_seen or not last_seen:
        return None, "PCAP request requires first_seen and last_seen timestamps"
    request = _normalized_request(
        merged, source_ip, destination_ip, first_seen, last_seen
    )
    request["request_id"] = pcap_request_id(_request_identity_seed(request))
    return request, ""
