"""Governed normalization for live endpoint OSQuery requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Type

from . import primitives


@dataclass(frozen=True)
class Dependencies:
    normalize_query: Callable[[str], str]
    query_error: Type[Exception]


def normalize(
    parameters: dict[str, Any], *, dependencies: Dependencies,
    error_type: Type[Exception] = ValueError,
) -> dict[str, str]:
    """Require a bounded target alias and provider-validated read-only SELECT."""
    target_alias = primitives.text(parameters.get("target_alias"), 64)
    query = primitives.text(parameters.get("query"), 4096)
    if not target_alias or not query:
        raise error_type(
            "osquery request requires target_alias and a read-only SELECT"
        )
    try:
        query = dependencies.normalize_query(query)
    except dependencies.query_error as exc:
        raise error_type(str(exc)) from exc
    return {"target_alias": target_alias, "query": query}
