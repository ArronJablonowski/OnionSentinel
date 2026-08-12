#!/usr/bin/env python3
"""Provenance-bound result validation for the live-host OSQuery contract."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from live_osquery_contract_query import (
    normalize_query,
    projected_columns,
    query_row_limit,
)
from live_osquery_contract_schema import (
    MAX_PURPOSE_CHARS,
    MAX_REPORTED_ROWS,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_RESULT_DURATION_MS,
    MAX_ROWS,
    SCHEMA,
    LiveOsqueryContractError,
    _RESULT_STATUSES,
    _bounded_text,
)


def _normalize_expected_requests(
    values: Iterable[Any],
) -> dict[tuple[str, str], dict[str, Any]]:
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_request in values:
        if not isinstance(raw_request, dict):
            raise LiveOsqueryContractError("expected request must be an object")
        target_alias = _bounded_text(
            raw_request.get("target_alias"),
            label="expected target_alias",
            maximum=64,
        ).lower()
        query = normalize_query(raw_request.get("query"))
        digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
        request = {
            "target_alias": target_alias,
            "query": query,
            "purpose": _bounded_text(
                raw_request.get("purpose"),
                label="expected purpose",
                maximum=MAX_PURPOSE_CHARS,
            ),
            "query_digest": digest,
        }
        key = (target_alias, digest)
        if key in expected:
            raise LiveOsqueryContractError("expected request list contains duplicates")
        expected[key] = request
    return expected


def _normalize_result_rows(
    value: Any,
    *,
    expected_columns: set[str],
) -> list[dict[str, str]]:
    rows_value = [] if value is None else value
    if not isinstance(rows_value, list) or len(rows_value) > MAX_ROWS:
        raise LiveOsqueryContractError("result rows exceed the configured bound")
    rows: list[dict[str, str]] = []
    for raw_row in rows_value:
        if not isinstance(raw_row, dict) or len(raw_row) > 64:
            raise LiveOsqueryContractError("result row has an invalid shape")
        row: dict[str, str] = {}
        for key, cell in raw_row.items():
            column = _bounded_text(key, label="result column", maximum=128).lower()
            if column in row:
                raise LiveOsqueryContractError(
                    "result row contains duplicate column identities"
                )
            row[column] = _bounded_text(
                cell, label="result value", maximum=2000, required=False
            )
        if set(row) != expected_columns:
            raise LiveOsqueryContractError(
                "result row columns do not match the submitted query projection"
            )
        rows.append(row)
    return rows


def _normalize_result_accounting(
    raw: dict[str, Any],
    *,
    rows: list[dict[str, str]],
    expected_row_limit: int,
) -> tuple[int, int, bool]:
    try:
        total_rows = int(raw.get("total_rows") or len(rows))
        duration_ms = int(raw.get("duration_ms") or 0)
    except (TypeError, ValueError) as exc:
        raise LiveOsqueryContractError(
            "result row count or duration is not an integer"
        ) from exc
    if total_rows < len(rows) or total_rows > MAX_REPORTED_ROWS:
        raise LiveOsqueryContractError("result total_rows is outside its bound")
    if total_rows > expected_row_limit:
        raise LiveOsqueryContractError(
            "result total_rows exceeds the submitted query LIMIT"
        )
    if duration_ms < 0 or duration_ms > MAX_RESULT_DURATION_MS:
        raise LiveOsqueryContractError("result duration exceeds its bound")
    truncated = bool(raw.get("truncated"))
    if truncated != (total_rows > len(rows)):
        raise LiveOsqueryContractError(
            "result truncated flag does not match its row counts"
        )
    return total_rows, duration_ms, truncated


def _normalize_result(
    raw: Any,
    *,
    expected: dict[tuple[str, str], dict[str, Any]] | None,
    observed: set[tuple[str, str]],
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise LiveOsqueryContractError("each live OSQuery result must be an object")
    target_alias = _bounded_text(
        raw.get("target_alias"), label="result target_alias", maximum=64
    ).lower()
    query = normalize_query(raw.get("query"))
    expected_columns = set(projected_columns(query))
    expected_row_limit = query_row_limit(query)
    query_digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
    purpose = _bounded_text(
        raw.get("purpose"), label="result purpose", maximum=MAX_PURPOSE_CHARS
    )
    key = (target_alias, query_digest)
    if key in observed:
        raise LiveOsqueryContractError("live OSQuery result contains duplicates")
    observed.add(key)
    if expected is not None:
        submitted = expected.get(key)
        if submitted is None:
            raise LiveOsqueryContractError(
                "result query or target does not match a submitted request"
            )
        if purpose != submitted["purpose"]:
            raise LiveOsqueryContractError(
                "result purpose does not match its submitted request"
            )
    rows = _normalize_result_rows(
        raw.get("rows"), expected_columns=expected_columns
    )
    status = _bounded_text(
        raw.get("status") or "invalid_response",
        label="result status",
        maximum=40,
    ).lower()
    if status not in _RESULT_STATUSES:
        raise LiveOsqueryContractError(f"unsupported result status: {status}")
    total_rows, duration_ms, truncated = _normalize_result_accounting(
        raw,
        rows=rows,
        expected_row_limit=expected_row_limit,
    )
    return {
        "target_alias": target_alias,
        "query": query,
        "purpose": purpose,
        "query_digest": query_digest,
        "status": status,
        "rows": rows,
        "total_rows": total_rows,
        "truncated": truncated,
        "duration_ms": duration_ms,
        "error": _bounded_text(
            raw.get("error"),
            label="result error",
            maximum=1000,
            required=False,
        ),
    }


def validate_result_artifact(
    value: Any,
    *,
    expected_requests: Iterable[Any] | None = None,
) -> dict[str, Any]:
    """Validate a bounded result and optionally bind it to submitted requests."""
    if not isinstance(value, dict):
        raise LiveOsqueryContractError("live OSQuery result must be an object")
    if str(value.get("schema") or "") != SCHEMA:
        raise LiveOsqueryContractError(f"result schema must be {SCHEMA}")
    case_id = _bounded_text(value.get("case_id"), label="case_id", maximum=160)
    raw_results = value.get("results")
    if not isinstance(raw_results, list) or len(raw_results) > MAX_REQUESTS:
        raise LiveOsqueryContractError("result list is missing or exceeds its bound")
    expected = (
        _normalize_expected_requests(expected_requests)
        if expected_requests is not None
        else None
    )
    if expected is not None and len(expected) != len(raw_results):
        raise LiveOsqueryContractError(
            "result count does not match the submitted live OSQuery requests"
        )

    observed: set[tuple[str, str]] = set()
    results = [
        _normalize_result(raw, expected=expected, observed=observed)
        for raw in raw_results
    ]
    if expected is not None and observed != set(expected):
        raise LiveOsqueryContractError(
            "live OSQuery result coverage does not match submitted requests"
        )
    if value.get("read_only") is not True:
        raise LiveOsqueryContractError("live OSQuery result is not marked read-only")
    expected_complete = all(result["status"] == "ok" for result in results)
    if bool(value.get("complete")) is not expected_complete:
        raise LiveOsqueryContractError(
            "result complete flag does not match individual query outcomes"
        )
    return {
        "schema": SCHEMA,
        "case_id": case_id,
        "generated_at": _bounded_text(
            value.get("generated_at"),
            label="generated_at",
            maximum=100,
            required=False,
        ),
        "read_only": True,
        "complete": expected_complete,
        "partial": not expected_complete,
        "results": results,
    }


def bounded_json_bytes(value: Any, maximum: int = MAX_RESPONSE_BYTES) -> bytes:
    """Serialize a compact JSON payload and enforce its transport ceiling."""
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    if len(encoded) > maximum:
        raise LiveOsqueryContractError(f"JSON payload exceeds {maximum} bytes")
    return encoded
