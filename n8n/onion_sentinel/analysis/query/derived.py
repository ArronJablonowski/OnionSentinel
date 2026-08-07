"""Governed normalization for derived PCAP and Zeek evidence requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Type

from . import primitives


@dataclass(frozen=True)
class Policy:
    operations: frozenset[str]
    filters_by_operation: Mapping[str, frozenset[str] | set[str]]
    maximum_filters: int = 16
    default_limit: int = 10
    maximum_limit: int = 20


@dataclass(frozen=True)
class Dependencies:
    normalize_filters: Callable[[str, dict[str, Any]], dict[str, Any]]
    filter_error: Type[Exception]
    positive_integer: Callable[[Any, int, int, str], int]


def _filters(
    operation: str, value: Any, *, policy: Policy,
    dependencies: Dependencies, error_type: Type[Exception],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise error_type("derived-evidence filters must be an object")
    unsupported = set(value).difference(
        policy.filters_by_operation.get(operation, set())
    )
    if unsupported:
        raise error_type(
            f"unsupported {operation} filters: "
            + ", ".join(sorted(str(item) for item in unsupported))
        )
    if len(value) > policy.maximum_filters or any(
        isinstance(item, (dict, list)) for item in value.values()
    ):
        raise error_type(
            "derived-evidence filters must contain at most "
            f"{policy.maximum_filters} scalar exact values"
        )
    try:
        return dependencies.normalize_filters(operation, value)
    except dependencies.filter_error as exc:
        raise error_type(str(exc)) from exc


def normalize(
    parameters: dict[str, Any], *, policy: Policy, dependencies: Dependencies,
    error_type: Type[Exception] = ValueError,
) -> dict[str, Any]:
    """Admit one bounded derived-evidence operation and exact filter set."""
    operation = primitives.text(parameters.get("operation"), 64).lower()
    if operation not in policy.operations:
        raise error_type(
            f"unsupported derived-evidence operation: {operation or 'missing'}"
        )
    return {
        "operation": operation,
        "filters": _filters(
            operation, parameters.get("filters", {}), policy=policy,
            dependencies=dependencies, error_type=error_type,
        ),
        "indicator": primitives.text(parameters.get("indicator"), 253),
        "limit": dependencies.positive_integer(
            parameters.get("limit"), policy.default_limit,
            policy.maximum_limit, "derived-evidence query limit",
        ),
    }
