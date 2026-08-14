#!/usr/bin/env python3
"""Fail-closed DHCP discovery request contract for incident evidence."""
from __future__ import annotations

import datetime as dt


DHCP_DISCOVERY_CONTRACT = "onion-sentinel-dhcp-asset-discovery-v1"
DHCP_DISCOVERY_OPERATION = "dhcp_observations"
DHCP_REQUEST_FIELDS = {"contract", "operation", "window", "size"}

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


def _request_fields(request: object) -> dict:
    if not isinstance(request, dict) or set(request) != DHCP_REQUEST_FIELDS:
        raise ValueError(
            "request fields do not match the DHCP discovery contract"
        )
    return request


def _validate_operation(request: dict) -> None:
    if (
        request["contract"] != DHCP_DISCOVERY_CONTRACT
        or request["operation"] != DHCP_DISCOVERY_OPERATION
    ):
        raise ValueError("unsupported DHCP discovery operation")


def _request_window(request: dict) -> dict:
    window = request["window"]
    if not isinstance(window, dict) or set(window) != {"start", "end"}:
        raise ValueError("invalid DHCP discovery window")
    return window


def _validate_window(window: dict) -> None:
    start = _parse_dhcp_timestamp(window["start"])
    end = _parse_dhcp_timestamp(window["end"])
    if start >= end or end - start > dt.timedelta(hours=24):
        raise ValueError(
            "DHCP discovery window must be positive and no longer than 24 hours"
        )


def _validate_size(size: object) -> None:
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= 1000
    ):
        raise ValueError("DHCP discovery size must be from 1 through 1000")


def validate_dhcp_request(request: object) -> None:
    admitted = _request_fields(request)
    _validate_operation(admitted)
    _validate_window(_request_window(admitted))
    _validate_size(admitted["size"])
