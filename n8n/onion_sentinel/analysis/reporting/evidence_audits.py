"""Bounded public audit projections for restricted collector evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    maximum_security_onion_queries: int = 100
    maximum_osquery_queries: int = 32
    maximum_osquery_rows: int = 25
    maximum_osquery_columns: int = 64


@dataclass(frozen=True)
class Dependencies:
    bounded_text: Callable[[Any, int], str]
    safe_nonnegative_int: Callable[[Any], int]


def _collector_context(
    prompt_package: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    evidence = prompt_package.get("incident_response_evidence")
    response = (
        evidence.get("security_onion_response")
        if isinstance(evidence, dict)
        else None
    )
    return (
        evidence if isinstance(evidence, dict) else None,
        response if isinstance(response, dict) else None,
    )


def _empty_security_onion_audit() -> dict[str, Any]:
    return {
        "trusted_source": "restricted-security-onion-wrapper",
        "complete": False,
        "partial": True,
        "read_only": True,
        "queries": [],
        "error": "Restricted Security Onion query evidence was unavailable.",
    }


def _security_onion_query(
    result: dict[str, Any],
    dependencies: Dependencies,
) -> dict[str, Any]:
    query_dsl = result.get("query_dsl")
    query_dsl = query_dsl if isinstance(query_dsl, dict) else {}
    window = result.get("window")
    window = window if isinstance(window, dict) else {}
    projection = result.get("prompt_projection")
    projection = projection if isinstance(projection, dict) else {}
    returned_hits = result.get("returned_hits")
    return {
        "pack": dependencies.bounded_text(result.get("pack"), 100),
        "status": dependencies.bounded_text(result.get("status"), 40),
        "query_digest": dependencies.bounded_text(
            result.get("query_digest"), 128
        ),
        "kql_equivalent": dependencies.bounded_text(
            result.get("kql_equivalent"), 12000
        ),
        "query_dsl": query_dsl,
        "window_index": result.get("window_index"),
        "window": {
            "start": dependencies.bounded_text(window.get("start"), 100),
            "end": dependencies.bounded_text(window.get("end"), 100),
        },
        "total_hits": dependencies.safe_nonnegative_int(
            result.get("total_hits")
        ),
        "returned_hits": dependencies.safe_nonnegative_int(returned_hits),
        "source_returned_hits": dependencies.safe_nonnegative_int(
            projection.get("source_returned_hits", returned_hits)
        ),
        "prompt_projection_applied": bool(projection),
        "truncated": bool(result.get("truncated")),
        "duration_ms": dependencies.safe_nonnegative_int(
            result.get("duration_ms")
        ),
        "error": dependencies.bounded_text(result.get("error"), 1000),
    }


def security_onion(
    prompt_package: dict[str, Any],
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Project immutable Security Onion query provenance without event bodies."""
    evidence, response = _collector_context(prompt_package)
    if response is None:
        return _empty_security_onion_audit()
    results = response.get("results")
    results = results if isinstance(results, list) else []
    queries = [
        _security_onion_query(item, dependencies)
        for item in results[:policy.maximum_security_onion_queries]
        if isinstance(item, dict)
    ]
    return {
        "trusted_source": "restricted-security-onion-wrapper",
        "generated_at": dependencies.bounded_text(
            evidence.get("generated_at") if evidence is not None else "", 100
        ),
        "complete": bool(response.get("complete")),
        "partial": bool(response.get("partial")),
        "read_only": bool(response.get("read_only", True)),
        "query_contract": dependencies.bounded_text(
            response.get("query_contract"), 200
        ),
        "queries": queries,
    }


def _empty_appliance_osquery_audit() -> dict[str, Any]:
    return {
        "trusted_source": "restricted-security-onion-osquery-wrapper",
        "read_only": True,
        "queries": [],
        "error": "Restricted live OSquery evidence was unavailable.",
    }


def _bounded_osquery_rows(
    result: dict[str, Any],
    policy: Policy,
    dependencies: Dependencies,
) -> list[dict[str, str]]:
    source = result.get("rows")
    source = source if isinstance(source, list) else []
    return [
        {
            dependencies.bounded_text(key, 128): dependencies.bounded_text(
                value, 2000
            )
            for key, value in list(row.items())[
                :policy.maximum_osquery_columns
            ]
        }
        for row in source[:policy.maximum_osquery_rows]
        if isinstance(row, dict)
    ]


def _appliance_osquery_entry(
    result: dict[str, Any],
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    return {
        "pack": dependencies.bounded_text(result.get("pack"), 100),
        "target": dependencies.bounded_text(result.get("target"), 100),
        "status": dependencies.bounded_text(result.get("status"), 40),
        "query_digest": dependencies.bounded_text(
            result.get("query_digest"), 128
        ),
        "query": dependencies.bounded_text(result.get("query"), 16000),
        "total_rows": dependencies.safe_nonnegative_int(
            result.get("total_rows")
        ),
        "returned_rows": dependencies.safe_nonnegative_int(
            result.get("returned_rows")
        ),
        "truncated": bool(result.get("truncated")),
        "duration_ms": dependencies.safe_nonnegative_int(
            result.get("duration_ms")
        ),
        "rows_preview": _bounded_osquery_rows(result, policy, dependencies),
        "error": dependencies.bounded_text(result.get("error"), 1000),
    }


def appliance_osquery(
    prompt_package: dict[str, Any],
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Project trusted appliance OSQuery snapshot provenance and bounded rows."""
    evidence, response = _collector_context(prompt_package)
    if response is None:
        return _empty_appliance_osquery_audit()
    results = response.get("osquery_results")
    results = results if isinstance(results, list) else []
    queries = [
        _appliance_osquery_entry(item, policy, dependencies)
        for item in results[:policy.maximum_osquery_queries]
        if isinstance(item, dict)
    ]
    return {
        "trusted_source": (
            "restricted-security-onion-appliance-osquery-wrapper"
        ),
        "generated_at": dependencies.bounded_text(
            evidence.get("generated_at") if evidence is not None else "", 100
        ),
        "read_only": bool(response.get("read_only", True)),
        "query_contract": dependencies.bounded_text(
            response.get("query_contract"), 200
        ),
        "queries": queries,
    }
