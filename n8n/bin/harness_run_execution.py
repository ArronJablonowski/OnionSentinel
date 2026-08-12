"""Stable mixin facade for harness phase, model, and query execution."""
from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from harness_contracts import _redacted_string
from harness_policy import (
    DIGEST_RE,
    HarnessPolicyError,
    Stage,
    TrustTier,
    _digest_or_hash,
    _model_route,
    _valid_identifier,
    digest_json,
    query_backend_capability,
)
from harness_query_contract import (
    QUERY_SUCCESS_STATUSES,
    observed_returned_count,
    observed_truncation,
    resolve_query_binding,
)
from harness_run_model_execution import record_model_call
from harness_run_query_execution import record_query_round
from harness_store_foundation import _connect


PHASE_STAGE_MAP = {
    "preparing": Stage.CONTEXT_ASSEMBLY.value,
    "primary_analysis": Stage.PRIMARY_ANALYSIS.value,
    "investigation_query_planning": Stage.QUERY_PLANNING.value,
    "investigation_query_execution": Stage.QUERY_EXECUTION.value,
    "evidence_synthesis": Stage.EVIDENCE_SYNTHESIS.value,
    "second_opinion": Stage.INDEPENDENT_REVIEW.value,
    "post_processing": Stage.POST_PROCESSING.value,
    "persistence": Stage.PERSISTENCE.value,
}


class HarnessRunExecution:
    """Phase transitions plus durable model and governed-query observations."""

    def phase(
        self,
        phase: str,
        route: str = "",
        reason: str = "",
    ) -> None:
        stage = PHASE_STAGE_MAP.get(phase, Stage.POST_PROCESSING.value)
        ordinal = self._phase_counts.get(stage, 0) + 1
        self._phase_counts[stage] = ordinal
        self.store.transition(
            self.run_id,
            stage,
            route=route,
            reason=reason,
            ordinal=ordinal,
        )

    def model_call(
        self,
        *,
        call_id: str,
        purpose: str,
        requested_route: str,
        response: Mapping[str, Any],
        input_value: Any,
        duration_seconds: float,
        independent_review: bool = False,
        status: str = "completed",
    ) -> None:
        record_model_call(
            self,
            call_id=call_id,
            purpose=purpose,
            requested_route=requested_route,
            response=response,
            input_value=input_value,
            duration_seconds=duration_seconds,
            independent_review=independent_review,
            status=status,
            connect=_connect,
        )

    def query_round(
        self,
        round_result: Mapping[str, Any],
    ) -> None:
        record_query_round(
            self,
            round_result,
            connect=_connect,
        )
