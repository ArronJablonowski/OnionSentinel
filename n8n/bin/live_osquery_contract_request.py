#!/usr/bin/env python3
"""Target, request, and transport normalization for live-host OSQuery."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from live_osquery_contract_query import normalize_query
from live_osquery_contract_schema import (
    MAX_PURPOSE_CHARS,
    MAX_REQUESTS,
    MAX_TARGET_ALIASES,
    SCHEMA,
    LiveOsqueryContractError,
    _ALIAS,
    _FORBIDDEN_TARGETS,
    _bounded_text,
)


def normalize_target_aliases(values: Iterable[Any]) -> list[str]:
    """Return a bounded, lower-case, duplicate-free endpoint alias roster."""
    aliases: list[str] = []
    for raw in list(values)[: MAX_TARGET_ALIASES + 1]:
        alias = str(raw or "").strip().lower()
        if not alias:
            continue
        if alias in _FORBIDDEN_TARGETS or "*" in alias or "?" in alias:
            raise LiveOsqueryContractError(
                "wildcard or all-endpoint targets are forbidden"
            )
        if not _ALIAS.fullmatch(alias):
            raise LiveOsqueryContractError(f"invalid endpoint target alias: {alias!r}")
        if alias not in aliases:
            aliases.append(alias)
    if len(aliases) > MAX_TARGET_ALIASES:
        raise LiveOsqueryContractError(
            f"target alias roster exceeds {MAX_TARGET_ALIASES} entries"
        )
    return aliases


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
        value.get("target_alias"), label="target_alias", maximum=64
    ).lower()
    if target_alias not in roster:
        raise LiveOsqueryContractError(
            f"target alias {target_alias!r} is not configured for this deployment"
        )
    query = normalize_query(value.get("query"))
    purpose = _bounded_text(
        value.get("purpose"), label="purpose", maximum=MAX_PURPOSE_CHARS
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
    case_id = _bounded_text(value.get("case_id"), label="case_id", maximum=160)
    requests = normalize_requests(
        value.get("requests"), allowed_aliases=allowed_aliases
    )
    if not requests:
        raise LiveOsqueryContractError("at least one live OSQuery request is required")
    return {"schema": SCHEMA, "case_id": case_id, "requests": requests}
