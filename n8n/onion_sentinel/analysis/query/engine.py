"""Immutable state transitions for the governed investigation query engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import state as budget_state
from . import stopping


@dataclass(frozen=True)
class InvestigationState:
    limits: budget_state.Limits
    queries_admitted: int = 0
    requests_ignored: int = 0
    terminal_requests_ignored: int = 0
    repair_attempted: bool = False


@dataclass(frozen=True)
class Transition:
    action: str
    state: InvestigationState
    admitted_requests: tuple[Any, ...]
    remaining: budget_state.Remaining
    audit: dict[str, Any]
    repair: stopping.RepairDecision | None = None


def begin(limits: budget_state.Limits) -> InvestigationState:
    return InvestigationState(limits=limits)


def remaining(
    current: InvestigationState,
    round_number: int,
    *,
    repair_round: bool = False,
) -> budget_state.Remaining:
    return budget_state.Remaining(
        rounds=(
            0
            if repair_round
            else max(0, current.limits.rounds - round_number)
        ),
        queries=max(0, current.limits.queries - current.queries_admitted),
    )


def _audit(
    before: InvestigationState,
    after: InvestigationState,
    *,
    action: str,
    raw_count: int,
    admitted_count: int,
) -> dict[str, Any]:
    return {
        "action": action,
        "raw_request_count": raw_count,
        "admitted_request_count": admitted_count,
        "queries_admitted_before": before.queries_admitted,
        "queries_admitted_after": after.queries_admitted,
        "requests_ignored_after": after.requests_ignored,
        "terminal_requests_ignored_after": after.terminal_requests_ignored,
        "repair_attempted_after": after.repair_attempted,
    }


def admit_round(
    current: InvestigationState,
    raw_requests: list[Any],
    *,
    round_number: int,
) -> Transition:
    entry = stopping.round_entry(raw_requests)
    if entry.stop:
        return Transition(
            action="stop_empty",
            state=current,
            admitted_requests=(),
            remaining=remaining(current, round_number),
            audit=_audit(
                current, current, action="stop_empty", raw_count=0, admitted_count=0
            ),
        )
    capacity = max(0, current.limits.queries - current.queries_admitted)
    allowed = min(current.limits.queries_per_round, capacity)
    admitted = tuple(raw_requests[:allowed])
    ignored = max(0, len(raw_requests) - len(admitted))
    updated = InvestigationState(
        limits=current.limits,
        queries_admitted=current.queries_admitted + len(admitted),
        requests_ignored=current.requests_ignored + ignored,
        terminal_requests_ignored=current.terminal_requests_ignored,
        repair_attempted=current.repair_attempted,
    )
    return Transition(
        action="admit",
        state=updated,
        admitted_requests=admitted,
        remaining=remaining(updated, round_number),
        audit=_audit(
            current,
            updated,
            action="admit",
            raw_count=len(raw_requests),
            admitted_count=len(admitted),
        ),
    )


def ignore(
    current: InvestigationState,
    count: int,
    *,
    terminal: bool = False,
) -> InvestigationState:
    bounded = max(0, int(count))
    return InvestigationState(
        limits=current.limits,
        queries_admitted=current.queries_admitted,
        requests_ignored=current.requests_ignored + bounded,
        terminal_requests_ignored=(
            current.terminal_requests_ignored + bounded
            if terminal
            else current.terminal_requests_ignored
        ),
        repair_attempted=current.repair_attempted,
    )


def plan_repair(
    current: InvestigationState,
    scopes: list[dict[str, Any]],
    *,
    round_number: int,
    repair_round: bool,
) -> Transition:
    capacity = remaining(current, round_number, repair_round=repair_round)
    decision = stopping.schedule_repair(
        scopes,
        already_attempted=current.repair_attempted,
        remaining_rounds=capacity.rounds,
        remaining_queries=capacity.queries,
        maximum_queries_per_round=current.limits.queries_per_round,
    )
    updated = (
        InvestigationState(
            limits=current.limits,
            queries_admitted=current.queries_admitted,
            requests_ignored=current.requests_ignored,
            terminal_requests_ignored=current.terminal_requests_ignored,
            repair_attempted=True,
        )
        if decision.scheduled
        else current
    )
    action = "schedule_repair" if decision.scheduled else "no_repair"
    return Transition(
        action=action,
        state=updated,
        admitted_requests=(),
        remaining=capacity,
        audit=_audit(
            current,
            updated,
            action=action,
            raw_count=len(scopes),
            admitted_count=len(decision.candidates),
        ),
        repair=decision,
    )
