"""Mixed-backend composition for one governed investigation query round."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    result_schema: str


@dataclass(frozen=True)
class Dependencies:
    security_onion: Callable[[list[dict[str, Any]]], Any]
    endpoint: Callable[[list[dict[str, Any]]], Any]
    derived: Callable[[list[dict[str, Any]]], Any]
    enrichment: Callable[[list[dict[str, Any]]], Any]
    now: Callable[[], str]


def _select(
    requests: list[dict[str, Any]], backends: frozenset[str],
) -> list[dict[str, Any]]:
    return [item for item in requests if item["backend"] in backends]


def execute(
    requests: list[dict[str, Any]], *, round_number: int, policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Execute backend transitions in stable order and assemble one artifact."""
    transitions = (
        dependencies.security_onion(_select(requests, frozenset({"elastic", "oql"}))),
        dependencies.endpoint(_select(requests, frozenset({"osquery"}))),
        dependencies.derived(_select(requests, frozenset({"pcap_zeek"}))),
        dependencies.enrichment(_select(requests, frozenset({"enrichment"}))),
    )
    results: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    for transition in transitions:
        results.extend(transition.results)
        audits.extend(transition.audits)
    return {
        "schema": policy.result_schema,
        "round": round_number,
        "generated_at": dependencies.now(),
        "requests": requests,
        "results": results,
        "audit": audits,
    }
