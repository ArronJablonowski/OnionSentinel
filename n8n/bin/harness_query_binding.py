"""Provenance-bound per-query status resolution for batch query results."""
from __future__ import annotations

from typing import Any, Mapping

from harness_query_binding_envelope import bound_query_objects, outer_query_status
from harness_query_binding_validation import (
    semantic_binding_is_valid,
    successful_shards_are_valid,
    validated_nested_status,
)


def resolve_query_binding(
    result: Mapping[str, Any],
    query_id: str,
) -> tuple[str, Any]:
    """Resolve one durable tool status from a provenance-bound batch result."""
    outer_status = outer_query_status(result)
    binding = bound_query_objects(result, query_id, outer_status)
    if binding is None:
        return outer_status, result
    nested, audit = binding
    nested_status = validated_nested_status(nested, audit)
    if nested_status is None:
        return outer_status, result
    observation = {"result": nested, "audit": audit}
    if not semantic_binding_is_valid(nested, audit, nested_status):
        return outer_status, observation
    if not successful_shards_are_valid(audit, nested_status):
        return outer_status, observation
    return nested_status, observation
