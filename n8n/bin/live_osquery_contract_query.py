#!/usr/bin/env python3
"""Fail-closed SQL normalization for the shared live-OSQuery contract."""

from __future__ import annotations

import re
from typing import Any

from live_osquery_contract_schema import (
    ALLOWED_TABLE_COLUMNS,
    ALLOWED_TABLES,
    DEFAULT_ROWS,
    MAX_QUERY_CHARS,
    MAX_ROWS,
    TARGET_PLATFORM,
    LiveOsqueryContractError,
    _bounded_text,
    _FORBIDDEN_QUERY_SHAPES,
    _FORBIDDEN_SQL,
    _FROM_CLAUSE,
    _FUNCTION_CALL,
    _SAFE_PROJECTION_ITEM,
    _SELECT_PROJECTION,
    _SQL_IDENTIFIER,
    _SQL_KEYWORDS,
    _SQL_STRING_LITERAL,
    _TABLE_REFERENCE,
    _TERMINAL_LIMIT,
)


def _normalize_statement_text(value: Any) -> str:
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
    return query


def _validate_structural_shape(query: str) -> str:
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
    return structural


def _projection_items(structural: str) -> list[str]:
    projection = _SELECT_PROJECTION.search(structural)
    if projection is None:
        raise LiveOsqueryContractError("query must have a bounded column projection")
    projection_items = [item.strip() for item in projection.group("body").split(",")]
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
    return projection_items


def _query_table(structural: str) -> str:
    table_references = [
        match.group(1).lower() for match in _TABLE_REFERENCE.finditer(structural)
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
    return table_references[0]


def _validate_projected_columns(
    structural: str,
    *,
    table: str,
    projection_items: list[str],
) -> None:
    projected = [item.rsplit(".", 1)[-1].lower() for item in projection_items]
    if "*" in projected:
        raise LiveOsqueryContractError(
            "SELECT * is forbidden; choose explicit platform-valid columns"
        )
    unknown_columns = sorted(set(projected).difference(ALLOWED_TABLE_COLUMNS[table]))
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


def _enforce_limit(query: str, structural: str) -> str:
    terminal_limit = _TERMINAL_LIMIT.search(structural)
    if re.search(r"\boffset\b", structural, flags=re.IGNORECASE):
        raise LiveOsqueryContractError("query OFFSET clauses are forbidden")
    limit_tokens = list(re.finditer(r"\blimit\b", structural, flags=re.IGNORECASE))
    if limit_tokens and (terminal_limit is None or len(limit_tokens) != 1):
        raise LiveOsqueryContractError(
            "query must use only one terminal LIMIT with a decimal row count"
        )
    limit_value = int(terminal_limit.group(1)) if terminal_limit else None
    if limit_value is not None and (limit_value < 1 or limit_value > MAX_ROWS):
        raise LiveOsqueryContractError(f"query LIMIT must be between 1 and {MAX_ROWS}")
    if limit_value is None:
        query = f"{query} LIMIT {DEFAULT_ROWS}"
    return f"{query};"


def normalize_query(value: Any) -> str:
    """Validate and normalize one single-statement SELECT query."""
    query = _normalize_statement_text(value)
    structural = _validate_structural_shape(query)
    projection_items = _projection_items(structural)
    table = _query_table(structural)
    _validate_projected_columns(
        structural,
        table=table,
        projection_items=projection_items,
    )
    return _enforce_limit(query, structural)


def projected_columns(value: Any) -> tuple[str, ...]:
    """Return the canonical columns from an already restricted query."""
    query = normalize_query(value)
    structural = _SQL_STRING_LITERAL.sub("__string_literal__", query)
    projection = _SELECT_PROJECTION.search(structural)
    if projection is None:
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
    if terminal_limit is None:
        raise LiveOsqueryContractError("query is missing its enforced row limit")
    return int(terminal_limit.group(1))
