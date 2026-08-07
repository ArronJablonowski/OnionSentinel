"""Canonical bounded facts for investigation-query prompt provenance."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from . import primitives


@dataclass(frozen=True)
class Policy:
    maximum_result_count: int


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def bounded(value: Any, *, maximum_bytes: int = 256) -> str:
    """Return one complete bounded fact; never truncate into new semantics."""
    if value in (None, "", {}, []):
        return ""
    if isinstance(value, str):
        text = value.strip()
        encoded = text.encode("utf-8")
    else:
        encoded = canonical_bytes(value)
        text = encoded.decode("utf-8")
    return text if len(encoded) <= maximum_bytes else ""


def canonical_count(value: Any, *, policy: Policy) -> int | None:
    """Return an exact non-negative integer count without coercion."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= policy.maximum_result_count else None


def provenance_count(
    containers: tuple[dict[str, Any], ...], keys: tuple[str, ...], *,
    policy: Policy,
) -> int | None:
    """Use the most-specific present count, including an invalid one."""
    for key in keys:
        for container in containers:
            if key in container:
                return canonical_count(container.get(key), policy=policy)
    return None


def _first_text(
    containers: tuple[dict[str, Any], ...], key: str, limit: int,
) -> str:
    for container in containers:
        text = primitives.text(container.get(key), limit)
        if text:
            return text
    return ""


def _first_bounded_value(
    containers: tuple[dict[str, Any], ...], key: str, maximum_bytes: int,
) -> tuple[bool, Any]:
    for container in containers:
        value = container.get(key)
        if value in (None, "", {}, []):
            continue
        normalized = value.strip() if isinstance(value, str) else value
        encoded = (
            normalized.encode("utf-8")
            if isinstance(normalized, str)
            else canonical_bytes(normalized)
        )
        return (True, normalized) if len(encoded) <= maximum_bytes else (True, None)
    return False, None


def query_semantics(containers: tuple[dict[str, Any], ...]) -> str:
    """Build a bounded description of exactly what one query tested."""
    summary: dict[str, Any] = {}
    backend = _first_text(containers, "dialect", 40) or _first_text(
        containers, "backend", 40
    )
    if backend:
        summary["backend"] = backend
    for key, limit in (
        ("pack", 100), ("aggregation", 40), ("operation", 80),
        ("target_alias", 160), ("indicator", 253),
    ):
        text = _first_text(containers, key, limit)
        if text:
            summary[key] = text
    for key, maximum_bytes in (
        ("semantics", 256), ("purpose", 180), ("observables", 256),
        ("window", 192), ("match_semantics", 192), ("query", 256),
        ("filters", 192),
    ):
        present, fact = _first_bounded_value(containers, key, maximum_bytes)
        if present and fact is None:
            return ""
        if present:
            summary[key] = fact
    concrete = {
        "purpose", "observables", "match_semantics", "semantics", "query",
        "filters", "indicator",
    }
    return bounded(summary, maximum_bytes=1024) if concrete.intersection(summary) else ""


def _first_boolean(
    containers: tuple[dict[str, Any], ...], key: str,
) -> bool | None:
    for container in containers:
        value = container.get(key)
        if isinstance(value, bool):
            return value
    return None


def _first_fact(
    containers: tuple[dict[str, Any], ...], key: str, maximum_bytes: int,
) -> str:
    for container in containers:
        value = bounded(container.get(key), maximum_bytes=maximum_bytes)
        if value:
            return value
    return ""


def result_summary(
    containers: tuple[dict[str, Any], ...], *, status: str,
    returned: int | None, policy: Policy,
) -> str:
    """Retain bounded collector facts needed to interpret a result digest."""
    supplied = _first_fact(containers, "evidence_summary", 256)
    if supplied:
        return supplied
    facts: dict[str, Any] = {"status": status}
    if returned is not None:
        facts["returned"] = returned
    total = provenance_count(containers, ("total_hits", "total_rows"), policy=policy)
    if total is not None:
        facts["total"] = total
    for key in (
        "semantic_valid", "truncated", "result_truncated",
        "index_scan_truncated", "timed_out",
    ):
        value = _first_boolean(containers, key)
        if value is not None:
            facts[key] = value
    error = _first_fact(containers, "error", 120)
    if error:
        facts["error"] = error
    return "" if len(facts) == 1 else bounded(facts)
