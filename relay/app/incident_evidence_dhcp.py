#!/usr/bin/env python3
"""Fail-closed DHCP discovery request contract for incident evidence."""
from __future__ import annotations

import datetime as dt


DHCP_DISCOVERY_CONTRACT = "onion-sentinel-dhcp-asset-discovery-v1"
DHCP_DISCOVERY_OPERATION = "dhcp_observations"

__all__ = [
    "DHCP_DISCOVERY_CONTRACT",
    "DHCP_DISCOVERY_OPERATION",
    "validate_dhcp_request",
]


def _parse_dhcp_timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(
        str(value or "").strip().replace("Z", "+00:00")
    )
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks offset")
    return parsed.astimezone(dt.timezone.utc)


def validate_dhcp_request(request: object) -> None:
    if not isinstance(request, dict) or set(request) != {
        "contract",
        "operation",
        "window",
        "size",
    }:
        raise ValueError(
            "request fields do not match the DHCP discovery contract"
        )
    if (
        request["contract"] != DHCP_DISCOVERY_CONTRACT
        or request["operation"] != DHCP_DISCOVERY_OPERATION
    ):
        raise ValueError("unsupported DHCP discovery operation")
    window = request["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError("invalid DHCP discovery window")
    start = _parse_dhcp_timestamp(window["start"])
    end = _parse_dhcp_timestamp(window["end"])
    if start >= end or end - start > dt.timedelta(hours=24):
        raise ValueError(
            "DHCP discovery window must be positive and no longer than 24 hours"
        )
    size = request["size"]
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= 1000
    ):
        raise ValueError("DHCP discovery size must be from 1 through 1000")
