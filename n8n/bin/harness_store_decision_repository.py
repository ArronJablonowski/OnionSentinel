"""Stable facade for evidence-bound hypothesis and decision persistence."""
from __future__ import annotations

from typing import Any, Mapping

from harness_policy import Stage
from harness_store_decision_persistence import record_decision
from harness_store_foundation import _connect
from harness_store_hypothesis_persistence import record_hypotheses


class HarnessStoreDecisionRepository:
    """Atomic, evidence-bound hypothesis and decision writes."""

    def record_hypotheses(
        self,
        run_id: str,
        hypotheses: Any,
        *,
        revision: int,
    ) -> dict[str, int]:
        return record_hypotheses(
            self,
            run_id,
            hypotheses,
            revision=revision,
            connect=_connect,
        )

    def record_decision(
        self,
        run_id: str,
        *,
        decision_id: str,
        decision_type: str,
        response: Mapping[str, Any],
        stage: str = Stage.EVIDENCE_SYNTHESIS.value,
    ) -> None:
        record_decision(
            self,
            run_id,
            decision_id=decision_id,
            decision_type=decision_type,
            response=response,
            stage=stage,
            connect=_connect,
        )
