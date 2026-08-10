"""Harness run identity, counters, budget, and authorization preflights."""
from __future__ import annotations

import datetime as dt
from typing import Any, Mapping, Sequence

from harness_contracts import JobEnvelope, _redacted_string, approximate_evidence_rows
from harness_policy import (
    HARNESS_SCHEMA,
    HarnessPolicy,
    HarnessPolicyError,
    Stage,
    _model_route,
    _valid_identifier,
    canonical_json,
    digest_json,
    policy_decision_is_effective,
    query_backend_capability,
    query_backend_is_approval_gated,
)
from harness_store_foundation import _connect


class HarnessRunFoundation:
    """Durable run identity, counters, budgets, and preflight decisions."""

    def __init__(
        self,
        store: Any,
        envelope: JobEnvelope,
        policy: HarnessPolicy,
    ):
        self.store = store
        self.envelope = envelope
        self.policy = policy
        self.store.start_run(envelope, policy)
        with _connect(self.store.path) as connection:
            usage = connection.execute(
                """
                SELECT
                  (
                    SELECT COUNT(*)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'query-round'
                  ) query_rounds,
                  (
                    SELECT COALESCE(SUM(amount), 0)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'query-round'
                  ) queries_total,
                  (
                    SELECT COUNT(*)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'model-call'
                  ) model_calls
                """,
                (self.run_id, self.run_id, self.run_id),
            ).fetchone()
            phase_rows = connection.execute(
                """
                SELECT stage, COUNT(*) phase_count
                FROM harness_events
                WHERE run_id = ? AND event_type = 'run.stage'
                GROUP BY stage
                """,
                (self.run_id,),
            ).fetchall()
        self._phase_counts = {
            str(row["stage"]): int(row["phase_count"])
            for row in phase_rows
        }
        self._query_rounds = int(usage["query_rounds"])
        self._queries_total = int(usage["queries_total"])
        self._model_calls = int(usage["model_calls"])

    @property
    def run_id(self) -> str:
        return self.envelope.run_id

    def remaining_model_calls(self) -> int:
        """Return the hard remaining call budget for bounded orchestration."""
        return max(
            0,
            int(self.policy.budgets["max_model_calls"])
            - int(self._model_calls),
        )

    def query_rounds_used(self) -> int:
        """Return the highest globally reserved query-round ordinal."""
        return max(0, int(self._query_rounds))

    def remaining_query_rounds(self) -> int:
        """Return the hard remaining global query-round budget."""
        return max(
            0,
            int(self.policy.budgets["max_query_rounds"])
            - self.query_rounds_used(),
        )

    def remaining_queries(self) -> int:
        """Return the hard remaining admitted-query budget."""
        return max(
            0,
            int(self.policy.budgets["max_queries_total"])
            - int(self._queries_total),
        )

    def trace_context(self) -> dict[str, Any]:
        return {
            "schema": HARNESS_SCHEMA,
            "run_id": self.envelope.run_id,
            "trace_id": self.envelope.trace_id,
            "correlation_id": self.envelope.correlation_id,
            "policy_version": self.policy.version,
            "policy_mode": self.policy.mode,
        }

    def catalogue_prompt_evidence(self, prompt_package: Mapping[str, Any]) -> int:
        contract = prompt_package.get("evidence_reference_contract")
        return self.store.register_evidence_contract(
            self.run_id,
            contract if isinstance(contract, Mapping) else {},
        )

    def _elapsed_seconds(self) -> float:
        snapshot = self.store.snapshot(self.run_id)
        raw = str(snapshot.get("started_at") or "")
        try:
            started = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return 0.0
        if started.tzinfo is None:
            started = started.replace(tzinfo=dt.timezone.utc)
        return max(
            0.0,
            (dt.datetime.now(dt.timezone.utc) - started).total_seconds(),
        )

    def _enforce_budget(
        self,
        *,
        operation_id: str,
        operation: str,
        stage: str,
        observed: Mapping[str, Any],
        violations: Sequence[str],
    ) -> None:
        payload = {
            "operation_id": operation_id,
            "operation": operation,
            "observed": dict(observed),
            "limits": dict(self.policy.budgets),
            "violations": sorted(set(violations)),
            "policy_mode": self.policy.mode,
        }
        decision_digest = digest_json(payload)[:24]
        self.store.append_event(
            self.run_id,
            "policy.budget",
            stage,
            payload,
            idempotency_key=(
                f"policy.budget:{operation_id}:{decision_digest}"
            ),
        )
        if violations and self.policy.mode == "enforce":
            raise HarnessPolicyError(
                f"{operation} exceeds harness budget: "
                + ", ".join(sorted(set(violations)))
            )

    def preflight_model_call(
        self,
        *,
        call_id: str,
        input_value: Any,
        requested_route: str,
        purpose: str,
        independent_review: bool = False,
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        requested_route = _model_route(
            requested_route,
            "requested model route",
        )
        expected_route = (
            self.envelope.assigned_reviewer_route
            if independent_review
            else self.envelope.assigned_route
        )
        route_allowed = (
            bool(expected_route) and requested_route == expected_route
        )
        route_reason = (
            "requested route matches the immutable reviewer assignment"
            if route_allowed and independent_review
            else "requested route matches the immutable primary assignment"
            if route_allowed
            else "no reviewer route was assigned to this run"
            if independent_review and not expected_route
            else "no primary route was assigned to this run"
            if not expected_route
            else "requested route does not match the immutable run assignment"
        )
        model_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        )
        self.store.append_event(
            self.run_id,
            "policy.model-route",
            model_stage,
            {
                "call_id": call_id,
                "purpose": _redacted_string(purpose, 160),
                "requested_route": requested_route,
                "expected_route": expected_route,
                "independent_review": independent_review,
                "allowed": route_allowed,
                "reason": route_reason,
                "policy_mode": self.policy.mode,
            },
            idempotency_key=f"policy.model-route:{call_id}",
        )
        if not route_allowed and self.policy.mode == "enforce":
            raise HarnessPolicyError(route_reason)
        prompt_bytes = len(canonical_json(input_value).encode("utf-8"))
        evidence_rows = approximate_evidence_rows(input_value)
        elapsed_seconds = self._elapsed_seconds()
        violations: list[str] = []
        if prompt_bytes > self.policy.budgets["max_prompt_evidence_bytes"]:
            violations.append("max_prompt_evidence_bytes")
        if evidence_rows > self.policy.budgets["max_prompt_evidence_rows"]:
            violations.append("max_prompt_evidence_rows")
        if elapsed_seconds > self.policy.budgets["max_run_seconds"]:
            violations.append("max_run_seconds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="model-call",
            reservation_id=call_id,
            amount=1,
            max_total=self.policy.budgets["max_model_calls"],
            max_operations=self.policy.budgets["max_model_calls"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=violations,
        )
        violations = list(reservation["violations"])
        if reservation["reserved"]:
            self._model_calls = max(
                self._model_calls,
                int(reservation["total"]),
            )
        next_model_call = int(reservation["operation_count"])
        self._enforce_budget(
            operation_id=f"model:{call_id}",
            operation="model call",
            stage=model_stage,
            observed={
                "call_id": call_id,
                "purpose": _redacted_string(purpose, 160),
                "requested_route": requested_route,
                "expected_route": expected_route,
                "route_allowed": route_allowed,
                "independent_review": independent_review,
                "next_model_call": next_model_call,
                "prompt_bytes": prompt_bytes,
                "approximate_evidence_rows": evidence_rows,
                "reserved": bool(
                    reservation["reserved"]
                ),
            },
            violations=violations,
        )

    def authorize_tool(
        self,
        *,
        round_number: int,
        query_id: str,
        backend: str,
        approved: bool = False,
    ) -> PolicyDecision:
        capability = query_backend_capability(backend)
        decision = self.policy.authorize(
            self.envelope.role,
            capability,
            approved=approved,
        )
        event_key = digest_json(
            {
                "round": round_number,
                "query_id": str(query_id),
                "backend": str(backend),
                "capability": capability,
                "approved": approved,
            }
        )[:24]
        self.store.append_event(
            self.run_id,
            "policy.tool-authorization",
            Stage.QUERY_PLANNING.value,
            {
                "round": max(0, int(round_number)),
                "query_id": str(query_id)[:128],
                "backend": str(backend)[:80],
                "capability": capability,
                "allowed": decision.allowed,
                "approved": approved,
                "effective_in_shadow": policy_decision_is_effective(
                    "shadow",
                    decision,
                ),
                "requires_approval": decision.requires_approval,
                "reason": decision.reason,
            },
            idempotency_key=f"policy.tool:{event_key}",
        )
        return decision

    def preflight_query_batch(
        self,
        *,
        round_number: int,
        request_count: int,
    ) -> None:
        round_number = int(round_number)
        if round_number < 1:
            raise HarnessPolicyError("query round_number must be positive")
        request_count = max(0, int(request_count))
        elapsed_seconds = self._elapsed_seconds()
        violations: list[str] = []
        if round_number > self.policy.budgets["max_query_rounds"]:
            violations.append("max_query_rounds")
        if request_count > self.policy.budgets["max_queries_per_round"]:
            violations.append("max_queries_per_round")
        if elapsed_seconds > self.policy.budgets["max_run_seconds"]:
            violations.append("max_run_seconds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="query-round",
            reservation_id=str(round_number),
            amount=request_count,
            max_total=self.policy.budgets["max_queries_total"],
            max_operations=self.policy.budgets["max_query_rounds"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=violations,
        )
        violations = list(reservation["violations"])
        if reservation["reserved"]:
            self._query_rounds = max(self._query_rounds, round_number)
            self._queries_total = max(
                self._queries_total,
                int(reservation["total"]),
            )
        queries_after_batch = int(reservation["total"])
        self._enforce_budget(
            operation_id=f"query-round:{round_number}",
            operation="query batch",
            stage=Stage.QUERY_PLANNING.value,
            observed={
                "round": round_number,
                "request_count": request_count,
                "queries_after_batch": queries_after_batch,
                "reserved": bool(
                    reservation["reserved"]
                ),
            },
            violations=violations,
        )
