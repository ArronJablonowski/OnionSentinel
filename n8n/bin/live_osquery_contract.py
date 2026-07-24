#!/usr/bin/env python3
"""Validate the restricted Onion Sentinel live-host OSQuery contract.

The model may choose a read-only query that is useful to an investigation, but
operators retain control of endpoint targeting and data scope.  This module is
copied unchanged to the Mac Studio, relay, and Security Onion so every trust
boundary independently enforces the same limits.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable


SCHEMA = "onion-sentinel-live-osquery-v1"
MAX_REQUESTS = 8
MAX_QUERY_CHARS = 4096
MAX_PURPOSE_CHARS = 500
MAX_ROWS = 200
DEFAULT_ROWS = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TARGET_ALIASES = 64
MAX_RESULT_DURATION_MS = 10 * 60 * 1000
MAX_REPORTED_ROWS = 1_000_000

ALLOWED_TABLES = frozenset(
    {
        "arp_cache",
        "crontab",
        "deb_packages",
        "groups",
        "homebrew_packages",
        "interface_addresses",
        "kernel_info",
        "listening_ports",
        "logged_in_users",
        "process_open_sockets",
        "processes",
        "routes",
        "rpm_packages",
        "startup_items",
        "suid_bin",
        "system_info",
        "users",
    }
)

_FORBIDDEN_TARGETS = frozenset({"*", "all", "agent_all", "all_agents", "_all"})
_FORBIDDEN_SQL = re.compile(
    r"\b("
    r"alter|attach|create|delete|detach|drop|insert|into|load_extension|"
    r"pragma|reindex|replace|update|vacuum"
    r")\b",
    re.IGNORECASE,
)
_FORBIDDEN_QUERY_SHAPES = re.compile(
    r"\b(?:except|intersect|union|with)\b|\(\s*select\b|\b(?:from|join)\s*\(",
    re.IGNORECASE,
)
_TABLE_REFERENCE = re.compile(
    r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_FROM_CLAUSE = re.compile(
    r"\bfrom\b(?P<body>.*?)(?=\bwhere\b|\bgroup\s+by\b|\border\s+by\b|\blimit\b|$)",
    re.IGNORECASE | re.DOTALL,
)
_LIMIT = re.compile(r"\blimit\s+(\d+)\b", re.IGNORECASE)
_ALIAS = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_RESULT_STATUSES = frozenset(
    {"ok", "timeout", "error", "invalid_response", "cancelled"}
)


class LiveOsqueryContractError(ValueError):
    """A request or response crossed the bounded live-query contract."""


def _bounded_text(value: Any, *, label: str, maximum: int, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise LiveOsqueryContractError(f"{label} is required")
    if len(text) > maximum:
        raise LiveOsqueryContractError(f"{label} exceeds {maximum} characters")
    if any(ord(char) < 32 and char not in "\t\r\n" for char in text):
        raise LiveOsqueryContractError(f"{label} contains control characters")
    return text


def normalize_target_aliases(values: Iterable[Any]) -> list[str]:
    """Return a bounded, lower-case, duplicate-free endpoint alias roster."""
    aliases: list[str] = []
    for raw in list(values)[: MAX_TARGET_ALIASES + 1]:
        alias = str(raw or "").strip().lower()
        if not alias:
            continue
        if alias in _FORBIDDEN_TARGETS or "*" in alias or "?" in alias:
            raise LiveOsqueryContractError("wildcard or all-endpoint targets are forbidden")
        if not _ALIAS.fullmatch(alias):
            raise LiveOsqueryContractError(f"invalid endpoint target alias: {alias!r}")
        if alias not in aliases:
            aliases.append(alias)
    if len(aliases) > MAX_TARGET_ALIASES:
        raise LiveOsqueryContractError(
            f"target alias roster exceeds {MAX_TARGET_ALIASES} entries"
        )
    return aliases


def normalize_query(value: Any) -> str:
    """Validate and normalize one single-statement SELECT query.

    A terminal semicolon is accepted for readability. Any additional semicolon,
    SQL comment, mutation keyword, unknown table, or excessive LIMIT is rejected
    before the query reaches a relay or endpoint.
    """
    query = _bounded_text(value, label="query", maximum=MAX_QUERY_CHARS)
    if "\x00" in query or "--" in query or "/*" in query or "*/" in query:
        raise LiveOsqueryContractError("SQL comments and NUL bytes are forbidden")
    query = query.rstrip()
    if query.endswith(";"):
        query = query[:-1].rstrip()
    if ";" in query:
        raise LiveOsqueryContractError("only one SQL statement is allowed")
    if not re.match(r"^\s*select\b", query, flags=re.IGNORECASE):
        raise LiveOsqueryContractError("only SELECT queries are allowed")
    if _FORBIDDEN_SQL.search(query):
        raise LiveOsqueryContractError("query contains a forbidden SQL operation")
    if _FORBIDDEN_QUERY_SHAPES.search(query):
        raise LiveOsqueryContractError(
            "compound queries, CTEs, subqueries, and derived tables are forbidden"
        )
    from_clause = _FROM_CLAUSE.search(query)
    if from_clause and "," in from_clause.group("body"):
        raise LiveOsqueryContractError(
            "comma joins are forbidden; use an explicit JOIN between allowed tables"
        )

    tables = {match.group(1).lower() for match in _TABLE_REFERENCE.finditer(query)}
    if not tables:
        raise LiveOsqueryContractError("query must reference an allowed OSQuery table")
    unknown = sorted(tables.difference(ALLOWED_TABLES))
    if unknown:
        raise LiveOsqueryContractError(
            "query references a table outside the allowlist: " + ", ".join(unknown)
        )

    limits = [int(match.group(1)) for match in _LIMIT.finditer(query)]
    if len(limits) > 1:
        raise LiveOsqueryContractError("query may contain only one LIMIT clause")
    if limits and (limits[0] < 1 or limits[0] > MAX_ROWS):
        raise LiveOsqueryContractError(f"query LIMIT must be between 1 and {MAX_ROWS}")
    if not limits:
        query = f"{query} LIMIT {DEFAULT_ROWS}"
    return f"{query};"


def normalize_request(
    value: Any,
    *,
    allowed_aliases: Iterable[Any],
) -> dict[str, Any]:
    """Normalize one model-authored live-host request."""
    if not isinstance(value, dict):
        raise LiveOsqueryContractError("live OSQuery request must be an object")
    roster = normalize_target_aliases(allowed_aliases)
    target_alias = _bounded_text(
        value.get("target_alias"),
        label="target_alias",
        maximum=64,
    ).lower()
    if target_alias not in roster:
        raise LiveOsqueryContractError(
            f"target alias {target_alias!r} is not configured for this deployment"
        )
    query = normalize_query(value.get("query"))
    purpose = _bounded_text(
        value.get("purpose"),
        label="purpose",
        maximum=MAX_PURPOSE_CHARS,
    )
    return {
        "target_alias": target_alias,
        "query": query,
        "purpose": purpose,
        "query_digest": hashlib.sha256(query.encode("utf-8")).hexdigest(),
    }


def normalize_requests(
    values: Any,
    *,
    allowed_aliases: Iterable[Any],
) -> list[dict[str, Any]]:
    """Normalize a bounded request list and remove exact duplicates."""
    if values in (None, ""):
        return []
    if not isinstance(values, list):
        raise LiveOsqueryContractError("live_osquery_requests must be an array")
    if len(values) > MAX_REQUESTS:
        raise LiveOsqueryContractError(
            f"live_osquery_requests exceeds the {MAX_REQUESTS}-query limit"
        )
    requests: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        request = normalize_request(value, allowed_aliases=allowed_aliases)
        key = (request["target_alias"], request["query_digest"])
        if key in seen:
            continue
        seen.add(key)
        requests.append(request)
    return requests


def validate_transport_payload(
    value: Any,
    *,
    allowed_aliases: Iterable[Any],
) -> dict[str, Any]:
    """Validate the JSON payload carried across both restricted SSH hops."""
    if not isinstance(value, dict):
        raise LiveOsqueryContractError("live OSQuery payload must be an object")
    if str(value.get("schema") or "") != SCHEMA:
        raise LiveOsqueryContractError(f"live OSQuery schema must be {SCHEMA}")
    case_id = _bounded_text(
        value.get("case_id"),
        label="case_id",
        maximum=160,
    )
    requests = normalize_requests(
        value.get("requests"),
        allowed_aliases=allowed_aliases,
    )
    if not requests:
        raise LiveOsqueryContractError("at least one live OSQuery request is required")
    return {
        "schema": SCHEMA,
        "case_id": case_id,
        "requests": requests,
    }


def validate_result_artifact(
    value: Any,
    *,
    expected_requests: Iterable[Any] | None = None,
) -> dict[str, Any]:
    """Validate a bounded result and optionally bind it to submitted requests.

    The optional request binding prevents a compromised intermediate hop from
    replacing the model-approved query, endpoint alias, or investigative
    purpose while retaining otherwise valid-looking JSON.
    """
    if not isinstance(value, dict):
        raise LiveOsqueryContractError("live OSQuery result must be an object")
    if str(value.get("schema") or "") != SCHEMA:
        raise LiveOsqueryContractError(f"result schema must be {SCHEMA}")
    case_id = _bounded_text(
        value.get("case_id"),
        label="case_id",
        maximum=160,
    )
    raw_results = value.get("results")
    if not isinstance(raw_results, list) or len(raw_results) > MAX_REQUESTS:
        raise LiveOsqueryContractError("result list is missing or exceeds its bound")
    expected: dict[tuple[str, str], dict[str, Any]] | None = None
    if expected_requests is not None:
        expected = {}
        for raw_request in expected_requests:
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
        if len(expected) != len(raw_results):
            raise LiveOsqueryContractError(
                "result count does not match the submitted live OSQuery requests"
            )

    results: list[dict[str, Any]] = []
    observed: set[tuple[str, str]] = set()
    for raw in raw_results:
        if not isinstance(raw, dict):
            raise LiveOsqueryContractError("each live OSQuery result must be an object")
        target_alias = _bounded_text(
            raw.get("target_alias"),
            label="result target_alias",
            maximum=64,
        ).lower()
        query = normalize_query(raw.get("query"))
        query_digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
        purpose = _bounded_text(
            raw.get("purpose"),
            label="result purpose",
            maximum=MAX_PURPOSE_CHARS,
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
        rows_value = raw.get("rows")
        if rows_value is None:
            rows_value = []
        if not isinstance(rows_value, list) or len(rows_value) > MAX_ROWS:
            raise LiveOsqueryContractError("result rows exceed the configured bound")
        rows: list[dict[str, str]] = []
        for raw_row in rows_value:
            if not isinstance(raw_row, dict) or len(raw_row) > 64:
                raise LiveOsqueryContractError("result row has an invalid shape")
            rows.append(
                {
                    _bounded_text(key, label="result column", maximum=128): _bounded_text(
                        cell,
                        label="result value",
                        maximum=2000,
                        required=False,
                    )
                    for key, cell in raw_row.items()
                }
            )
        status = _bounded_text(
            raw.get("status") or "invalid_response",
            label="result status",
            maximum=40,
        ).lower()
        if status not in _RESULT_STATUSES:
            raise LiveOsqueryContractError(f"unsupported result status: {status}")
        try:
            total_rows = int(raw.get("total_rows") or len(rows))
            duration_ms = int(raw.get("duration_ms") or 0)
        except (TypeError, ValueError) as exc:
            raise LiveOsqueryContractError(
                "result row count or duration is not an integer"
            ) from exc
        if total_rows < len(rows) or total_rows > MAX_REPORTED_ROWS:
            raise LiveOsqueryContractError("result total_rows is outside its bound")
        if duration_ms < 0 or duration_ms > MAX_RESULT_DURATION_MS:
            raise LiveOsqueryContractError("result duration exceeds its bound")
        truncated = bool(raw.get("truncated"))
        if truncated != (total_rows > len(rows)):
            raise LiveOsqueryContractError(
                "result truncated flag does not match its row counts"
            )
        results.append(
            {
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
        )
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
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) > maximum:
        raise LiveOsqueryContractError(f"JSON payload exceeds {maximum} bytes")
    return encoded
