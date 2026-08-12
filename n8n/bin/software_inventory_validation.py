"""Pure endpoint-cache and relay-response validation for Software Inventory."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional, Set

from software_inventory_contract import (
    AUDIT_RECEIPT_KEYS,
    CONTRACT,
    MAX_TOTAL_RECORDS,
    QUERY_AUDIT_KEYS,
    RESPONSE_KEY_SETS,
    SOURCE_POLICY,
    TRANSPORT_RECEIPT_CONTRACT,
    _CORRELATION_ID,
    _HEX_24,
    _HEX_64,
    format_timestamp,
    parse_timestamp,
)
from software_inventory_normalization import (
    _cursor_order,
    _cursor_public_identity,
    _normalize_cursor,
    _normalize_record,
    _normalize_window,
)


BuildRequest = Callable[
    [str, Dict[str, str], int, Optional[Dict[str, Any]]],
    Dict[str, Any],
]


def _target_asset_refs(targets: object) -> Set[str]:
    if not isinstance(targets, list) or not targets or len(targets) > 64:
        raise ValueError("endpoint software inventory cache is out of bounds")
    assets: Set[str] = set()
    for target in targets:
        if (
            not isinstance(target, dict)
            or set(target) != {"asset_ref", "status", "records", "observed_at"}
            or target.get("status") != "ok"
            or not _HEX_24.fullmatch(str(target.get("asset_ref") or ""))
        ):
            raise ValueError("endpoint software inventory target status is invalid")
        assets.add(str(target["asset_ref"]))
    return assets


def validated_endpoint_cache(
    value: object,
    now: dt.datetime,
    maximum_age: dt.timedelta,
) -> Optional[Dict[str, Any]]:
    """Validate one already-loaded endpoint cache without filesystem access."""
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "version", "updated_at", "complete", "targets", "records"
        }
        or value.get("schema") != "onion-sentinel-endpoint-software-cache-v1"
        or value.get("version") != 1
        or value.get("complete") is not True
    ):
        raise ValueError("endpoint software inventory cache is invalid")
    updated = parse_timestamp(value.get("updated_at"))
    current = now.astimezone(dt.timezone.utc)
    if updated > current + dt.timedelta(minutes=5) or current - updated > maximum_age:
        return None
    records = value.get("records")
    if not isinstance(records, list) or len(records) > MAX_TOTAL_RECORDS:
        raise ValueError("endpoint software inventory cache is out of bounds")
    assets = _target_asset_refs(value.get("targets"))
    normalized = [
        _normalize_record(record, expected_source="osquery_apps")
        for record in records
    ]
    if any(record["asset_ref"] not in assets for record in normalized):
        raise ValueError("endpoint software inventory record has no target coverage")
    return {
        "updated_at": format_timestamp(updated),
        "targets": len(assets),
        "records": normalized,
    }


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _receipt_identity_valid(receipt: Dict[str, Any]) -> bool:
    return (
        set(receipt) == AUDIT_RECEIPT_KEYS
        and receipt.get("receipt_contract") == TRANSPORT_RECEIPT_CONTRACT
        and bool(
            _CORRELATION_ID.fullmatch(
                str(receipt.get("correlation_id") or "")
            )
        )
    )


def _receipt_digests_valid(
    receipt: Dict[str, Any],
    expected_request: Dict[str, Any],
    response_without_receipt: Dict[str, Any],
) -> bool:
    return (
        receipt.get("request_digest") == _canonical_digest(expected_request)
        and receipt.get("response_payload_digest")
        == _canonical_digest(response_without_receipt)
    )


def _receipt_execution_valid(
    receipt: Dict[str, Any],
    value: Dict[str, Any],
) -> bool:
    count_fields = (
        "elastic_search_count",
        "osquery_query_count",
        "helper_invocation_count",
    )
    return (
        receipt.get("read_only") is True
        and receipt.get("terminal_status")
        == ("complete" if value.get("complete") is True else "partial")
        and all(
            not isinstance(receipt.get(field), bool)
            and isinstance(receipt.get(field), int)
            for field in count_fields
        )
        and tuple(receipt.get(field) for field in count_fields) == (0, 0, 1)
    )


def _validate_audit_receipt(
    receipt: object,
    *,
    value: Dict[str, Any],
    expected_request: Dict[str, Any],
) -> None:
    response_without_receipt = {
        key: item for key, item in value.items() if key != "audit_receipt"
    }
    if (
        not isinstance(receipt, dict)
        or not _receipt_identity_valid(receipt)
        or not _receipt_digests_valid(
            receipt,
            expected_request,
            response_without_receipt,
        )
        or not _receipt_execution_valid(receipt, value)
    ):
        raise ValueError("relay response audit receipt failed validation")


def _validated_result_accounting(
    value: Dict[str, Any],
    requested_page_size: int,
) -> tuple[List[object], bool, bool]:
    records = value.get("records")
    returned = value.get("returned")
    if (
        not isinstance(records, list)
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(records)
        or returned > requested_page_size
    ):
        raise ValueError("relay response result accounting is invalid")
    complete = value.get("complete")
    truncated = value.get("truncated")
    if not isinstance(complete, bool) or not isinstance(truncated, bool):
        raise ValueError("relay response pagination state is invalid")
    return records, complete, truncated


def _validated_page_cursor(
    value: Dict[str, Any],
    *,
    expected_source: str,
    complete: bool,
    truncated: bool,
    returned: int,
    requested_page_size: int,
) -> Optional[Dict[str, Any]]:
    after = _normalize_cursor(
        value.get("after"),
        allow_none=True,
        expected_source=expected_source,
    )
    if complete:
        if truncated or after is not None:
            raise ValueError("terminal software inventory page is inconsistent")
    elif (
        not truncated
        or after is None
        or returned != requested_page_size
        or returned == 0
    ):
        raise ValueError("non-terminal software inventory page is inconsistent")
    return after


def _validated_query_audit(
    value: Dict[str, Any],
    expected_source: str,
) -> Dict[str, str]:
    audit = value.get("query_audit")
    policy = SOURCE_POLICY[expected_source]
    if (
        not isinstance(audit, dict)
        or set(audit) != QUERY_AUDIT_KEYS
        or audit.get("index") != policy["index"]
        or audit.get("dataset") != policy["dataset"]
        or not _HEX_64.fullmatch(str(audit.get("query_digest") or ""))
    ):
        raise ValueError("relay response fixed-query audit is invalid")
    return {
        "index": policy["index"],
        "dataset": policy["dataset"],
        "query_digest": str(audit["query_digest"]),
    }


def _normalize_response_records(
    records: List[object],
    *,
    expected_source: str,
    window: Dict[str, str],
) -> List[Dict[str, Any]]:
    return [
        _normalize_record(
            raw,
            expected_source=expected_source,
            expected_window=window,
        )
        for raw in records
    ]


def _validate_cursor_binding(
    after: Optional[Dict[str, Any]],
    previous_after: Optional[Dict[str, Any]],
    normalized_records: List[Dict[str, Any]],
    expected_source: str,
) -> None:
    previous_cursor = (
        _normalize_cursor(
            previous_after,
            allow_none=False,
            expected_source=expected_source,
        )
        if previous_after is not None
        else None
    )
    if after is None:
        return
    if previous_cursor is not None and (
        _cursor_order(after) <= _cursor_order(previous_cursor)
    ):
        raise ValueError("software inventory cursor did not advance")
    if not normalized_records or _cursor_public_identity(
        expected_source,
        after,
    ) != (
        normalized_records[-1]["asset_ref"],
        normalized_records[-1]["product"],
        normalized_records[-1]["version"],
    ):
        raise ValueError(
            "software inventory cursor does not identify the last public record"
        )


def validate_relay_response(
    value: object,
    *,
    expected_source: str,
    expected_window: Dict[str, str],
    requested_page_size: int,
    previous_after: Optional[Dict[str, Any]],
    build_request: BuildRequest,
) -> Dict[str, Any]:
    """Validate one already-loaded response from the fixed read-only relay."""
    if not isinstance(value, dict) or frozenset(value) not in RESPONSE_KEY_SETS:
        raise ValueError("relay response has an invalid software inventory shape")
    if (
        value.get("ok") is not True
        or value.get("contract") != CONTRACT
        or value.get("read_only") is not True
        or value.get("source") != expected_source
    ):
        raise ValueError("relay response failed the software inventory contract")
    window = _normalize_window(value.get("window"))
    if window != _normalize_window(expected_window):
        raise ValueError("relay response window does not match the request")
    receipt = value.get("audit_receipt")
    if receipt is not None:
        _validate_audit_receipt(
            receipt,
            value=value,
            expected_request=build_request(
                expected_source,
                expected_window,
                requested_page_size,
                previous_after,
            ),
        )
    records, complete, truncated = _validated_result_accounting(
        value,
        requested_page_size,
    )
    after = _validated_page_cursor(
        value,
        expected_source=expected_source,
        complete=complete,
        truncated=truncated,
        returned=len(records),
        requested_page_size=requested_page_size,
    )
    query_audit = _validated_query_audit(value, expected_source)
    normalized_records = _normalize_response_records(
        records,
        expected_source=expected_source,
        window=window,
    )
    _validate_cursor_binding(
        after,
        previous_after,
        normalized_records,
        expected_source,
    )
    normalized = dict(value)
    normalized["window"] = window
    normalized["after"] = after
    normalized["records"] = normalized_records
    normalized["query_audit"] = query_audit
    return normalized
