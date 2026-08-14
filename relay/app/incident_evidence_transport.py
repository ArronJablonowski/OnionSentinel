"""Transport-envelope and audit-receipt contracts for incident evidence."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Callable


TRANSPORT_AUDIT_CONTRACT = "onion-sentinel-evidence-transport-v1"
TRANSPORT_RECEIPT_CONTRACT = "onion-sentinel-evidence-receipt-v1"
HEX_64_RE = re.compile(r"[0-9a-f]{64}")
CORRELATION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
TRANSPORT_ENVELOPE_FIELDS = {
    "transport_contract",
    "correlation_id",
    "request_digest",
    "payload",
}
RECEIPT_FIELDS = {
    "receipt_contract",
    "correlation_id",
    "request_digest",
    "response_payload_digest",
    "elastic_search_count",
    "osquery_query_count",
    "helper_invocation_count",
    "read_only",
    "terminal_status",
}


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _audited_transport_fields(value: dict) -> tuple[dict, str, str]:
    if set(value) != TRANSPORT_ENVELOPE_FIELDS:
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
    return payload, correlation_id, request_digest


def _transport_payload_size(payload: dict) -> int:
    return len(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )


def _transport_fields(
    value: dict,
    uuid_factory: Callable[[], object],
) -> tuple[dict, str, str]:
    if value.get("transport_contract") == TRANSPORT_AUDIT_CONTRACT:
        return _audited_transport_fields(value)
    return value, str(uuid_factory().hex), _canonical_digest(value)


def transport_envelope(
    value: object,
    *,
    maximum_payload_bytes: int,
    uuid_factory: Callable[[], object],
) -> tuple[dict, dict]:
    if not isinstance(value, dict):
        raise ValueError("request root must be an object")
    payload, correlation_id, request_digest = _transport_fields(
        value,
        uuid_factory,
    )
    if _transport_payload_size(payload) > maximum_payload_bytes:
        raise ValueError("request payload exceeds the broker byte limit")
    audit = {
        "transport_contract": TRANSPORT_AUDIT_CONTRACT,
        "correlation_id": correlation_id,
        "request_digest": request_digest,
    }
    return payload, {**audit, "payload": payload}


def _receipt_counters_valid(receipt: dict) -> bool:
    return not any(
        not isinstance(receipt.get(field), int)
        or isinstance(receipt.get(field), bool)
        or receipt.get(field) < 0
        for field in (
            "elastic_search_count",
            "osquery_query_count",
            "helper_invocation_count",
        )
    )


def _receipt_fields(response: dict) -> dict:
    receipt = response.get("audit_receipt")
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise ValueError("Security Onion response omitted its audit receipt")
    return receipt


def _response_payload_digest(response: dict) -> str:
    return _canonical_digest(
        {key: value for key, value in response.items() if key != "audit_receipt"}
    )


def _receipt_contract_matches(
    receipt: dict,
    audit: dict,
    response_payload_digest: str,
) -> bool:
    return receipt.get("read_only") is True and (
        receipt.get("receipt_contract"),
        receipt.get("correlation_id"),
        receipt.get("request_digest"),
        receipt.get("response_payload_digest"),
    ) == (
        TRANSPORT_RECEIPT_CONTRACT,
        audit["correlation_id"],
        audit["request_digest"],
        response_payload_digest,
    )


def _receipt_terminal_matches(receipt: dict, response: dict) -> bool:
    expected = "complete" if response.get("complete") is True else "partial"
    return receipt.get("terminal_status") == expected


def receipt_identity(response: dict, audit: dict) -> dict:
    receipt = _receipt_fields(response)
    if (
        not _receipt_contract_matches(
            receipt,
            audit,
            _response_payload_digest(response),
        )
        or not _receipt_terminal_matches(receipt, response)
        or not _receipt_counters_valid(receipt)
    ):
        raise ValueError("Security Onion audit receipt failed validation")
    return receipt
