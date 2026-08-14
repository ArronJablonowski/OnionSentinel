"""Pure transport envelopes and receipts for incident evidence."""

from __future__ import annotations

import hashlib
import json
import re
import uuid

from incident_evidence_inventory_contract import (
    DHCP_DISCOVERY_CONTRACT,
    DHCP_DISCOVERY_OPERATION,
    HEX_64_RE,
    SOFTWARE_INVENTORY_CONTRACT,
    SOFTWARE_INVENTORY_OPERATION,
)


MAX_REQUEST_BYTES = 16 * 1024
TRANSPORT_AUDIT_CONTRACT = "onion-sentinel-evidence-transport-v1"
TRANSPORT_RECEIPT_CONTRACT = "onion-sentinel-evidence-receipt-v1"
CORRELATION_ID_RE = re.compile(r"^[a-f0-9]{32}$")


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _transport_envelope(value: object) -> tuple[dict, dict]:
    if not isinstance(value, dict):
        raise ValueError("request root must be an object")
    if value.get("transport_contract") == TRANSPORT_AUDIT_CONTRACT:
        if set(value) != {
            "transport_contract", "correlation_id", "request_digest", "payload"
        }:
            raise ValueError("transport envelope fields are invalid")
        payload = value.get("payload")
        correlation_id = value.get("correlation_id")
        request_digest = value.get("request_digest")
        if (
            not isinstance(payload, dict)
            or not isinstance(correlation_id, str)
            or not CORRELATION_ID_RE.fullmatch(correlation_id)
            or not isinstance(request_digest, str)
            or not HEX_64_RE.fullmatch(request_digest)
            or request_digest != _canonical_digest(payload)
        ):
            raise ValueError("transport envelope failed validation")
    else:
        payload = value
        correlation_id = uuid.uuid4().hex
        request_digest = _canonical_digest(payload)
    if len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()) > MAX_REQUEST_BYTES:
        raise ValueError("request payload exceeds the broker byte limit")
    audit = {
        "transport_contract": TRANSPORT_AUDIT_CONTRACT,
        "correlation_id": correlation_id,
        "request_digest": request_digest,
    }
    return payload, {**audit, "payload": payload}


def _validate_receipt(response: dict, audit: dict, request: dict) -> dict:
    receipt = response.get("audit_receipt")
    if not isinstance(receipt, dict) or set(receipt) != {
        "receipt_contract",
        "correlation_id",
        "request_digest",
        "response_payload_digest",
        "elastic_search_count",
        "osquery_query_count",
        "helper_invocation_count",
        "read_only",
        "terminal_status",
    }:
        raise ValueError("Security Onion response omitted its audit receipt")
    without_receipt = {
        key: value for key, value in response.items() if key != "audit_receipt"
    }
    if (
        receipt.get("receipt_contract") != TRANSPORT_RECEIPT_CONTRACT
        or receipt.get("correlation_id") != audit["correlation_id"]
        or receipt.get("request_digest") != audit["request_digest"]
        or receipt.get("response_payload_digest") != _canonical_digest(without_receipt)
        or receipt.get("read_only") is not True
        or receipt.get("terminal_status")
        != ("complete" if response.get("complete") is True else "partial")
        or any(
            not isinstance(receipt.get(field), int)
            or isinstance(receipt.get(field), bool)
            or receipt.get(field) < 0
            for field in (
                "elastic_search_count",
                "osquery_query_count",
                "helper_invocation_count",
            )
        )
    ):
        raise ValueError("Security Onion audit receipt failed validation")
    if request.get("operation") == "investigation_pivots":
        expected = len(request.get("queries") or []) + 2
        if (
            receipt.get("elastic_search_count") != expected
            or receipt.get("osquery_query_count") != 0
            or receipt.get("helper_invocation_count") != 0
        ):
            raise ValueError("Security Onion search accounting is inconsistent")
    elif (
        request.get("contract") == DHCP_DISCOVERY_CONTRACT
        or request.get("operation") == DHCP_DISCOVERY_OPERATION
        or request.get("contract") == SOFTWARE_INVENTORY_CONTRACT
        or request.get("operation") == SOFTWARE_INVENTORY_OPERATION
    ):
        if (
            receipt.get("elastic_search_count") != 0
            or receipt.get("osquery_query_count") != 0
            or receipt.get("helper_invocation_count") != 1
        ):
            raise ValueError("Security Onion helper accounting is inconsistent")
    else:
        controls = response.get("controls") if isinstance(response.get("controls"), dict) else {}
        expected_control_searches = sum(
            1
            for name in ("positive_anchor", "negative_filter")
            if isinstance(controls.get(name), dict)
            and controls[name].get("status") != "not_requested"
        )
        if (
            receipt.get("elastic_search_count")
            != len(response.get("results") or []) + expected_control_searches
            or receipt.get("osquery_query_count")
            != len(response.get("osquery_results") or [])
            or receipt.get("helper_invocation_count") != 0
        ):
            raise ValueError("Security Onion evidence accounting is inconsistent")
    return receipt
