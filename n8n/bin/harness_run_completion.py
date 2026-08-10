"""Harness response recording and terminal run lifecycle."""
from __future__ import annotations

from typing import Any, Mapping

from harness_memory import memory_promotion_decision
from harness_policy import PolicyDecision, RunStatus, Stage, _valid_identifier


class HarnessRunCompletion:
    """Record analysis decisions and settle a harness run."""

    def record_response(
        self,
        response: Mapping[str, Any],
        *,
        decision_id: str,
        decision_type: str,
        hypothesis_revision: int,
    ) -> None:
        decision_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if decision_type == "independent-review"
            else Stage.POST_PROCESSING.value
            if decision_type == "post-review-analysis"
            else Stage.EVIDENCE_SYNTHESIS.value
        )
        self.store.record_hypotheses(
            self.run_id,
            response.get("hypotheses"),
            revision=hypothesis_revision,
        )
        self.store.record_decision(
            self.run_id,
            decision_id=decision_id,
            decision_type=decision_type,
            response=response,
            stage=decision_stage,
        )

    def memory_promotion_decision(
        self,
        response: Mapping[str, Any],
        *,
        has_shared_candidates: bool,
        human_approved: bool = False,
    ) -> PolicyDecision:
        return memory_promotion_decision(
            self.policy,
            response,
            role=self.envelope.role,
            has_shared_candidates=has_shared_candidates,
            human_approved=human_approved,
        )

    def preflight_completion(
        self,
        *,
        operation_id: str = "run-complete",
    ) -> None:
        operation_id = _valid_identifier(
            operation_id,
            "completion operation_id",
            128,
        )
        elapsed_seconds = self._elapsed_seconds()
        self._enforce_budget(
            operation_id=operation_id,
            operation="run completion",
            stage=Stage.PERSISTENCE.value,
            observed={"elapsed_seconds": round(elapsed_seconds, 3)},
            violations=(
                ["max_run_seconds"]
                if elapsed_seconds > self.policy.budgets["max_run_seconds"]
                else []
            ),
        )

    def record_memory_writeback(
        self,
        receipt: Mapping[str, Any],
    ) -> None:
        """Record bounded post-commit results without storing memory content."""
        self.store.append_event(
            self.run_id,
            "memory.writeback",
            Stage.PERSISTENCE.value,
            receipt,
            idempotency_key="memory.writeback:post-commit",
        )

    def observe_postcommit_runtime(self) -> dict[str, Any]:
        """Audit an SLO breach after commit without invalidating durable work."""
        elapsed_seconds = self._elapsed_seconds()
        exceeded = elapsed_seconds > self.policy.budgets["max_run_seconds"]
        payload = {
            "elapsed_seconds": round(elapsed_seconds, 3),
            "max_run_seconds": self.policy.budgets["max_run_seconds"],
            "exceeded": exceeded,
            "enforcement_boundary": "post-commit-observation",
        }
        self.store.append_event(
            self.run_id,
            "slo.runtime",
            Stage.PERSISTENCE.value,
            payload,
            idempotency_key="slo.runtime:post-commit",
        )
        return payload

    def complete(
        self,
        summary: Mapping[str, Any] | None = None,
        *,
        check_budget: bool = True,
    ) -> None:
        if check_budget:
            self.preflight_completion()
        self.store.finish(
            self.run_id,
            status=RunStatus.SUCCEEDED.value,
            summary=summary,
        )

    def fail(self, reason: str) -> None:
        self.store.finish(
            self.run_id,
            status=RunStatus.FAILED.value,
            reason=reason,
        )
