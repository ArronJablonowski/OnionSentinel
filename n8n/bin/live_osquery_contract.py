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

TARGET_PLATFORM = "darwin"
TARGET_OSQUERY_VERSION = "5.15.0"
ALLOWED_TABLE_COLUMNS = {
    "arp_cache": frozenset({"address", "mac", "interface", "permanent"}),
    "crontab": frozenset(
        {
            "event",
            "minute",
            "hour",
            "day_of_month",
            "month",
            "day_of_week",
            "command",
            "path",
        }
    ),
    "groups": frozenset({"gid", "gid_signed", "groupname", "is_hidden"}),
    "homebrew_packages": frozenset(
        {"name", "path", "version", "type", "prefix"}
    ),
    "interface_addresses": frozenset(
        {"interface", "address", "mask", "broadcast", "point_to_point", "type"}
    ),
    "kernel_info": frozenset({"version", "arguments", "path", "device"}),
    "listening_ports": frozenset(
        {"pid", "port", "protocol", "family", "address", "fd", "socket", "path"}
    ),
    "logged_in_users": frozenset({"type", "user", "tty", "host", "time", "pid"}),
    "os_version": frozenset(
        {
            "name",
            "version",
            "major",
            "minor",
            "patch",
            "build",
            "platform",
            "platform_like",
            "codename",
            "arch",
            "extra",
        }
    ),
    "osquery_info": frozenset(
        {
            "pid",
            "uuid",
            "instance_id",
            "version",
            "config_hash",
            "config_valid",
            "extensions",
            "build_platform",
            "build_distro",
            "start_time",
            "watcher",
            "platform_mask",
        }
    ),
    "process_open_sockets": frozenset(
        {
            "pid",
            "fd",
            "socket",
            "family",
            "protocol",
            "local_address",
            "remote_address",
            "local_port",
            "remote_port",
            "path",
            "state",
        }
    ),
    "processes": frozenset(
        {
            "pid",
            "name",
            "path",
            "cmdline",
            "state",
            "cwd",
            "root",
            "uid",
            "gid",
            "euid",
            "egid",
            "suid",
            "sgid",
            "on_disk",
            "wired_size",
            "resident_size",
            "total_size",
            "user_time",
            "system_time",
            "disk_bytes_read",
            "disk_bytes_written",
            "start_time",
            "parent",
            "pgroup",
            "threads",
            "nice",
            "upid",
            "uppid",
            "cpu_type",
            "cpu_subtype",
            "translated",
        }
    ),
    "routes": frozenset(
        {
            "destination",
            "netmask",
            "gateway",
            "source",
            "flags",
            "interface",
            "mtu",
            "metric",
            "type",
            "hopcount",
        }
    ),
    "startup_items": frozenset(
        {"name", "path", "args", "type", "source", "status", "username"}
    ),
    "system_info": frozenset(
        {
            "hostname",
            "uuid",
            "cpu_type",
            "cpu_subtype",
            "cpu_brand",
            "cpu_physical_cores",
            "cpu_logical_cores",
            "cpu_sockets",
            "cpu_microcode",
            "physical_memory",
            "hardware_vendor",
            "hardware_model",
            "hardware_version",
            "hardware_serial",
            "board_vendor",
            "board_model",
            "board_version",
            "board_serial",
            "computer_name",
            "local_hostname",
        }
    ),
    "users": frozenset(
        {
            "uid",
            "gid",
            "uid_signed",
            "gid_signed",
            "username",
            "description",
            "directory",
            "shell",
            "uuid",
            "is_hidden",
        }
    ),
}
ALLOWED_TABLES = frozenset(ALLOWED_TABLE_COLUMNS)

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
_SQL_STRING_LITERAL = re.compile(r"'(?:''|[^'])*'")
_FUNCTION_CALL = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_SQL_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_SQL_KEYWORDS = frozenset(
    {
        "and",
        "asc",
        "between",
        "by",
        "desc",
        "escape",
        "false",
        "from",
        "glob",
        "in",
        "is",
        "like",
        "limit",
        "match",
        "not",
        "null",
        "or",
        "order",
        "regexp",
        "select",
        "true",
        "where",
    }
)
_SELECT_PROJECTION = re.compile(
    r"^\s*select\s+(?P<body>.*?)\s+from\b",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_PROJECTION_ITEM = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:\*|[A-Za-z_][A-Za-z0-9_]*)$"
)
_TABLE_REFERENCE = re.compile(
    r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
_FROM_CLAUSE = re.compile(
    r"\bfrom\b(?P<body>.*?)(?=\bwhere\b|\bgroup\s+by\b|\border\s+by\b|\blimit\b|$)",
    re.IGNORECASE | re.DOTALL,
)
_TERMINAL_LIMIT = re.compile(r"\s+limit\s+([0-9]+)\s*$", re.IGNORECASE)
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
    structural = _SQL_STRING_LITERAL.sub("__string_literal__", query)
    if "'" in structural:
        raise LiveOsqueryContractError("query contains an unterminated SQL string")
    if any(character in structural for character in ('"', "`", "[", "]")):
        raise LiveOsqueryContractError(
            "quoted or bracketed SQL identifiers are forbidden"
        )
    if _FORBIDDEN_SQL.search(structural):
        raise LiveOsqueryContractError("query contains a forbidden SQL operation")
    if _FORBIDDEN_QUERY_SHAPES.search(structural):
        raise LiveOsqueryContractError(
            "compound queries, CTEs, subqueries, and derived tables are forbidden"
        )
    if re.search(r"\bjoin\b", structural, flags=re.IGNORECASE):
        raise LiveOsqueryContractError("JOIN queries are forbidden")
    function_calls = [
        match.group("name").lower()
        for match in _FUNCTION_CALL.finditer(structural)
        if match.group("name").lower() != "in"
    ]
    if function_calls:
        raise LiveOsqueryContractError("SQL function calls are forbidden")
    projection = _SELECT_PROJECTION.search(structural)
    if projection is None:
        raise LiveOsqueryContractError("query must have a bounded column projection")
    projection_items = [
        item.strip() for item in projection.group("body").split(",")
    ]
    if (
        not projection_items
        or len(projection_items) > 64
        or any(not _SAFE_PROJECTION_ITEM.fullmatch(item) for item in projection_items)
    ):
        raise LiveOsqueryContractError(
            "SELECT projection must contain only native column identifiers"
        )
    from_clause = _FROM_CLAUSE.search(structural)
    if from_clause and "," in from_clause.group("body"):
        raise LiveOsqueryContractError("comma joins are forbidden")

    table_references = [
        match.group(1).lower()
        for match in _TABLE_REFERENCE.finditer(structural)
    ]
    if len(table_references) != 1:
        raise LiveOsqueryContractError(
            "query must reference exactly one allowed OSQuery table"
        )
    tables = set(table_references)
    unknown = sorted(tables.difference(ALLOWED_TABLES))
    if unknown:
        raise LiveOsqueryContractError(
            "query references a table outside the allowlist: " + ", ".join(unknown)
        )
    table = table_references[0]
    projected_columns = [
        item.rsplit(".", 1)[-1].lower()
        for item in projection_items
    ]
    if "*" in projected_columns:
        raise LiveOsqueryContractError(
            "SELECT * is forbidden; choose explicit platform-valid columns"
        )
    unknown_columns = sorted(
        set(projected_columns).difference(ALLOWED_TABLE_COLUMNS[table])
    )
    if unknown_columns:
        raise LiveOsqueryContractError(
            f"query projects columns unavailable for {table} on "
            f"{TARGET_PLATFORM}: " + ", ".join(unknown_columns)
        )
    invalid_identifiers = sorted(
        {
            match.group(0).lower()
            for match in _SQL_IDENTIFIER.finditer(structural)
        }.difference(
            _SQL_KEYWORDS,
            {"__string_literal__", table},
            ALLOWED_TABLE_COLUMNS[table],
        )
    )
    if invalid_identifiers:
        raise LiveOsqueryContractError(
            f"query references identifiers unavailable for {table} on "
            f"{TARGET_PLATFORM}: " + ", ".join(invalid_identifiers)
        )

    terminal_limit = _TERMINAL_LIMIT.search(structural)
    if re.search(r"\boffset\b", structural, flags=re.IGNORECASE):
        raise LiveOsqueryContractError("query OFFSET clauses are forbidden")
    limit_tokens = list(re.finditer(r"\blimit\b", structural, flags=re.IGNORECASE))
    if limit_tokens and (
        terminal_limit is None
        or len(limit_tokens) != 1
    ):
        raise LiveOsqueryContractError(
            "query must use only one terminal LIMIT with a decimal row count"
        )
    limit_value = int(terminal_limit.group(1)) if terminal_limit else None
    if limit_value is not None and (limit_value < 1 or limit_value > MAX_ROWS):
        raise LiveOsqueryContractError(f"query LIMIT must be between 1 and {MAX_ROWS}")
    if limit_value is None:
        query = f"{query} LIMIT {DEFAULT_ROWS}"
    return f"{query};"


def projected_columns(value: Any) -> tuple[str, ...]:
    """Return the canonical columns from an already restricted query."""
    query = normalize_query(value)
    structural = _SQL_STRING_LITERAL.sub("__string_literal__", query)
    projection = _SELECT_PROJECTION.search(structural)
    if projection is None:  # normalize_query already guarantees this
        raise LiveOsqueryContractError("query must have a bounded column projection")
    return tuple(
        item.strip().rsplit(".", 1)[-1].lower()
        for item in projection.group("body").split(",")
    )


def query_row_limit(value: Any) -> int:
    """Return the enforced terminal row limit from a restricted query."""
    query = normalize_query(value)
    structural = _SQL_STRING_LITERAL.sub("__string_literal__", query.rstrip(";"))
    terminal_limit = _TERMINAL_LIMIT.search(structural)
    if terminal_limit is None:  # normalize_query always appends a limit
        raise LiveOsqueryContractError("query is missing its enforced row limit")
    return int(terminal_limit.group(1))


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
        expected_columns = set(projected_columns(query))
        expected_row_limit = query_row_limit(query)
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
            row: dict[str, str] = {}
            for key, cell in raw_row.items():
                column = _bounded_text(
                    key,
                    label="result column",
                    maximum=128,
                ).lower()
                if column in row:
                    raise LiveOsqueryContractError(
                        "result row contains duplicate column identities"
                    )
                row[column] = _bounded_text(
                    cell,
                    label="result value",
                    maximum=2000,
                    required=False,
                )
            if set(row) != expected_columns:
                raise LiveOsqueryContractError(
                    "result row columns do not match the submitted query projection"
                )
            rows.append(row)
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
