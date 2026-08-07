"""Canonical result envelopes for one governed investigation-query round."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Sequence


INVALID_ENVELOPE_ERROR = "query broker returned an invalid result envelope"


@dataclass(frozen=True)
class Policy:
    schema: str


@dataclass(frozen=True)
class Dependencies:
    execute: Callable[[list[dict[str, Any]]], Any]
    repair_failures: Callable[[dict[str, Any]], dict[str, str]]
    now: Callable[[], str]


@dataclass(frozen=True)
class Result:
    envelope: dict[str, Any]
    repair_failures: dict[str, str]


def _valid_envelope(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and isinstance(value.get("results"), list)
        and isinstance(value.get("requests"), list)
    )


def _empty_envelope(round_number: int, policy: Policy, now: str) -> dict[str, Any]:
    return {
        "schema": policy.schema,
        "round": round_number,
        "generated_at": now,
        "requests": [],
        "results": [],
        "audit": [],
    }


def _invalid_envelope(
    requests: Sequence[dict[str, Any]],
    round_number: int,
    policy: Policy,
    now: str,
) -> dict[str, Any]:
    return {
        "schema": policy.schema,
        "round": round_number,
        "generated_at": now,
        "requests": copy.deepcopy(list(requests)),
        "results": [
            {
                "query_id": request["query_id"],
                "backend": request["backend"],
                "status": "invalid_response",
                "read_only": True,
                "error": INVALID_ENVELOPE_ERROR,
            }
            for request in requests
        ],
        "audit": [],
    }


def run(
    normalized_requests: Sequence[dict[str, Any]],
    rejected_results: Sequence[dict[str, Any]],
    *,
    round_number: int,
    policy: Policy,
    dependencies: Dependencies,
) -> Result:
    """Execute admitted requests and return one validated, read-only envelope."""
    admitted = list(normalized_requests)
    if not admitted:
        envelope = _empty_envelope(round_number, policy, dependencies.now())
    else:
        candidate = dependencies.execute(admitted)
        envelope = (
            candidate
            if _valid_envelope(candidate)
            else _invalid_envelope(
                admitted, round_number, policy, dependencies.now()
            )
        )
    failures = dict(dependencies.repair_failures(envelope))
    envelope.setdefault("results", []).extend(copy.deepcopy(list(rejected_results)))
    return Result(envelope=envelope, repair_failures=failures)
