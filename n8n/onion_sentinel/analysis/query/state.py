"""Bounded multi-round state for iterative investigation queries."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    maximum_rounds: int
    maximum_queries: int
    maximum_queries_per_round: int


@dataclass(frozen=True)
class Limits:
    rounds: int
    queries: int
    queries_per_round: int

    def evaluation_retry(self, policy: Policy) -> "Limits":
        rounds = max(1, policy.maximum_rounds - 1)
        return Limits(
            rounds=rounds,
            queries=min(
                policy.maximum_queries,
                rounds * policy.maximum_queries_per_round,
            ),
            queries_per_round=policy.maximum_queries_per_round,
        )


@dataclass(frozen=True)
class Remaining:
    rounds: int
    queries: int


def resolve(
    policy: Policy, *, rounds_override: int | None = None,
    queries_override: int | None = None,
) -> Limits:
    """Clamp operator overrides within checked-in safety maxima."""
    rounds = min(
        policy.maximum_rounds,
        max(1, int(rounds_override or policy.maximum_rounds)),
    )
    queries = min(
        policy.maximum_queries,
        max(1, int(queries_override or policy.maximum_queries)),
    )
    return Limits(
        rounds=rounds,
        queries=queries,
        queries_per_round=policy.maximum_queries_per_round,
    )


class Budget:
    """Mutable ledger for one loop; every mutation is monotonic and bounded."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.admitted = 0
        self.ignored = 0
        self.terminal_ignored = 0

    def admit(self, raw_requests: list) -> list:
        remaining = max(0, self.limits.queries - self.admitted)
        allowed = min(self.limits.queries_per_round, remaining)
        admitted = raw_requests[:allowed]
        self.admitted += len(admitted)
        self.ignore(len(raw_requests) - len(admitted))
        return admitted

    def ignore(self, count: int, *, terminal: bool = False) -> None:
        bounded = max(0, int(count))
        self.ignored += bounded
        if terminal:
            self.terminal_ignored += bounded

    def remaining(self, round_number: int, *, repair_round: bool = False) -> Remaining:
        return Remaining(
            rounds=(0 if repair_round else max(0, self.limits.rounds - round_number)),
            queries=max(0, self.limits.queries - self.admitted),
        )
