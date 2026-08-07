"""Artifacts for one deterministic non-widening query-repair stage."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable


INSTRUCTION = (
    "Repair only the listed rejected query IDs. Preserve each backend, purpose, "
    "pack, aggregation, and exact observable set; the repaired time window must "
    "be equal or narrower, size must not increase, and any valid event_tuple "
    "must be preserved exactly. Do not emit any unrelated query. This is the "
    "only planning repair attempt."
)


@dataclass(frozen=True)
class Dependencies:
    canonical_digest: Callable[[Any], str]
    error_digest: Callable[[Any], str]
    prompt_entry: Callable[..., dict[str, Any]]
    request_from_scope: Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class Result:
    scheduled: bool
    audit_candidates: tuple[dict[str, Any], ...]
    pending_scopes: dict[str, dict[str, Any]]
    prompt: dict[str, Any] | None
    requests: tuple[dict[str, Any], ...]
    not_attempted_reason: str


def _audit_candidate(
    item: dict[str, Any], dependencies: Dependencies,
) -> dict[str, Any]:
    scope = item["scope"]
    event_tuple = scope.get("event_tuple")
    return {
        "query_id": scope["query_id"],
        "backend": scope["backend"],
        "pack": scope["pack"],
        "trigger": item["trigger"],
        "scope_digest": dependencies.canonical_digest(scope),
        "original_event_tuple_fields": sorted(
            event_tuple if isinstance(event_tuple, dict) else {}
        ),
        "observable_scope_source": scope.get(
            "observable_scope_source", "original_valid_scope"
        ),
        "error_digest": dependencies.error_digest(item["reason"]),
    }


def build(
    decision: Any,
    *,
    remaining_queries: int,
    dependencies: Dependencies,
) -> Result:
    """Build exact repair artifacts from an authoritative engine decision."""
    considered = list(decision.considered)
    candidates = list(decision.candidates)
    audit = tuple(_audit_candidate(item, dependencies) for item in considered)
    if not decision.scheduled:
        return Result(
            scheduled=False,
            audit_candidates=audit,
            pending_scopes={},
            prompt=None,
            requests=(),
            not_attempted_reason=(
                decision.not_attempted_reason if considered else ""
            ),
        )
    pending = {
        item["scope"]["query_id"]: copy.deepcopy(item["scope"])
        for item in candidates
    }
    prompt = {
        "attempt": 1,
        "maximum_attempts": 1,
        "remaining_query_rounds": 1,
        "remaining_queries": min(len(candidates), max(0, remaining_queries)),
        "instruction": INSTRUCTION,
        "rejected_queries": [
            dependencies.prompt_entry(
                item["scope"],
                reason=item["reason"],
                trigger=item["trigger"],
            )
            for item in candidates
        ],
    }
    requests = tuple(
        dependencies.request_from_scope(item["scope"])
        for item in candidates
    )
    return Result(True, audit, pending, prompt, requests, "")
