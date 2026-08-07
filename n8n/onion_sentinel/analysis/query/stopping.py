"""Pure stopping and bounded repair-scheduling decisions for query rounds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


NO_ROUND_REASON = "no query round remained within the configured call budget"
NO_QUERY_REASON = "no query request budget remained"


@dataclass(frozen=True)
class RepairDecision:
    considered: tuple[dict[str, Any], ...]
    candidates: tuple[dict[str, Any], ...]
    scheduled: bool
    not_attempted_reason: str


@dataclass(frozen=True)
class StopDecision:
    stop: bool
    reason: str


def round_entry(raw_requests: Any) -> StopDecision:
    """Stop before admission when the model produced no request batch."""
    return StopDecision(
        stop=not bool(raw_requests),
        reason="no investigation query requests" if not raw_requests else "",
    )


def schedule_repair(
    scopes: list[dict[str, Any]],
    *,
    already_attempted: bool,
    remaining_rounds: int,
    remaining_queries: int,
    maximum_queries_per_round: int,
) -> RepairDecision:
    """Admit at most one bounded, non-widening deterministic repair round."""
    if not scopes or already_attempted:
        return RepairDecision((), (), False, "")
    bounded = tuple(scopes[:maximum_queries_per_round])
    candidates = bounded[:max(0, remaining_queries)]
    if candidates and remaining_rounds > 0:
        return RepairDecision(bounded, candidates, True, "")
    if remaining_rounds <= 0:
        return RepairDecision(bounded, candidates, False, NO_ROUND_REASON)
    if remaining_queries <= 0:
        return RepairDecision(bounded, candidates, False, NO_QUERY_REASON)
    return RepairDecision(bounded, candidates, False, "")


def after_follow_up(remaining_rounds: int, remaining_queries: int) -> StopDecision:
    """Stop after synthesis when either checked-in query budget is exhausted."""
    if remaining_rounds <= 0:
        return StopDecision(True, NO_ROUND_REASON)
    if remaining_queries <= 0:
        return StopDecision(True, NO_QUERY_REASON)
    return StopDecision(False, "")
