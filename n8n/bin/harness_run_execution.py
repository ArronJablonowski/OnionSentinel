"""Harness phase, model-call, and governed query execution recording."""
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
        call_id = _valid_identifier(call_id, "model call_id", 128)
        requested_route = _model_route(
            requested_route,
            "completed model route",
        )
        with _connect(self.store.path) as connection:
            authorization_row = connection.execute(
                """
                SELECT payload_json
                FROM harness_events
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (
                    self.run_id,
                    f"policy.model-route:{call_id}",
                ),
            ).fetchone()
        authorization = (
            json.loads(str(authorization_row["payload_json"]))
            if authorization_row is not None
            else {}
        )
        observed_route = str(
            response.get("_analysis_model_route") or ""
        ).strip()
        route_authorized = bool(
            authorization.get("allowed") is True
            and authorization.get("requested_route") == requested_route
            and bool(authorization.get("independent_review"))
            is bool(independent_review)
        )
        observed_matches = (
            not response
            or (
                bool(observed_route)
                and observed_route == requested_route
            )
        )
        observation_allowed = route_authorized and observed_matches
        observation_reason = (
            "authorized route and collector-observed route agree"
            if observation_allowed and response
            else "authorized failed invocation has no model response"
            if observation_allowed
            else "model call has no matching allowed preflight"
            if not route_authorized
            else "collector-observed route differs from the authorized route"
        )
        observation_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        )
        self.store.append_event(
            self.run_id,
            "policy.model-observation",
            observation_stage,
            {
                "call_id": call_id,
                "requested_route": requested_route,
                "observed_route": observed_route,
                "independent_review": independent_review,
                "response_present": bool(response),
                "allowed": observation_allowed,
                "reason": observation_reason,
                "policy_mode": self.policy.mode,
            },
            idempotency_key=f"policy.model-observation:{call_id}",
        )
        if not observation_allowed and self.policy.mode == "enforce":
            raise HarnessPolicyError(observation_reason)
        # The runner performs the full prompt/runtime preflight before invoking
        # a model. This idempotent reservation is a final hard-count backstop
        # for callers using the record API directly.
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="model-call",
            reservation_id=call_id,
            amount=1,
            max_total=self.policy.budgets["max_model_calls"],
            max_operations=self.policy.budgets["max_model_calls"],
            enforce=self.policy.mode == "enforce",
        )
        if reservation["violations"] and self.policy.mode == "enforce":
            self._enforce_budget(
                operation_id=f"model:{call_id}",
                operation="model call",
                stage=(
                    Stage.INDEPENDENT_REVIEW.value
                    if independent_review
                    else Stage.PRIMARY_ANALYSIS.value
                ),
                observed={
                    "call_id": call_id,
                    "next_model_call": reservation["operation_count"],
                    "reserved": False,
                },
                violations=reservation["violations"],
            )
        self.store.record_model_call(
            self.run_id,
            call_id=call_id,
            purpose=purpose,
            requested_route=requested_route,
            response=response,
            independent_review=independent_review,
            input_digest=digest_json(input_value),
            duration_ms=max(0, round(float(duration_seconds) * 1_000)),
            status=status,
        )
        self._model_calls = max(self._model_calls, int(reservation["total"]))

    def query_round(
        self,
        round_result: Mapping[str, Any],
    ) -> None:
        round_number = int(round_result.get("round") or self._query_rounds + 1)
        if round_number < 1:
            raise HarnessPolicyError("query round_number must be positive")
        requests = (
            round_result.get("requests")
            if isinstance(round_result.get("requests"), list)
            else []
        )
        results = (
            round_result.get("results")
            if isinstance(round_result.get("results"), list)
            else []
        )
        # The typed query broker is expected to call the full preflight before
        # execution. Reserve again idempotently so direct record-API users
        # cannot exceed hard count/round limits without a durable denial.
        direct_violations: list[str] = []
        if len(requests) > self.policy.budgets["max_queries_per_round"]:
            direct_violations.append("max_queries_per_round")
        if round_number > self.policy.budgets["max_query_rounds"]:
            direct_violations.append("max_query_rounds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="query-round",
            reservation_id=str(round_number),
            amount=len(requests),
            max_total=self.policy.budgets["max_queries_total"],
            max_operations=self.policy.budgets["max_query_rounds"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=direct_violations,
        )
        direct_violations = list(reservation["violations"])
        if direct_violations and self.policy.mode == "enforce":
            self._enforce_budget(
                operation_id=f"query-round:{round_number}",
                operation="query batch",
                stage=Stage.QUERY_PLANNING.value,
                observed={
                    "round": round_number,
                    "request_count": len(requests),
                    "queries_after_batch": (
                        reservation["total"]
                    ),
                    "reserved": bool(
                        reservation["reserved"]
                    ),
                },
                violations=direct_violations,
            )
        if reservation["reserved"]:
            self._queries_total = max(
                self._queries_total,
                int(reservation["total"]),
            )
        self._query_rounds = max(self._query_rounds, round_number)
        status_counts: dict[str, int] = {}
        backend_counts: dict[str, int] = {}
        trusted_query_digests: list[str] = []
        request_by_id = {
            str(item.get("query_id")): item
            for item in requests
            if isinstance(item, dict) and item.get("query_id")
        }
        result_by_id: dict[str, dict[str, Any]] = {}
        for item in results:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "unknown")[:40]
            backend = str(item.get("backend") or "unknown")[:40]
            status_counts[status] = status_counts.get(status, 0) + 1
            backend_counts[backend] = backend_counts.get(backend, 0) + 1
            item_ids = (
                [str(value) for value in item.get("query_ids", [])]
                if isinstance(item.get("query_ids"), list)
                else [str(item.get("query_id"))]
                if item.get("query_id")
                else []
            )
            for item_id in item_ids:
                result_by_id[item_id] = item
            audits = (
                item.get("trusted_query_audit")
                if isinstance(item.get("trusted_query_audit"), list)
                else []
            )
            for audit in audits:
                if not isinstance(audit, dict):
                    continue
                digest = str(audit.get("query_digest") or "")
                if DIGEST_RE.fullmatch(digest):
                    trusted_query_digests.append(digest)
                    returned_count = observed_returned_count(audit)
                    result_digest = str(
                        audit.get("result_digest") or ""
                    ).lower()
                    if not DIGEST_RE.fullmatch(result_digest):
                        result_digest = ""
                    supplied_ref = str(
                        audit.get("evidence_ref")
                        or f"query:{digest}"
                    ).strip()
                    if not supplied_ref or supplied_ref.startswith("query:"):
                        ref = f"query:{digest}"
                        if DIGEST_RE.fullmatch(result_digest):
                            ref += f":{result_digest}"
                    else:
                        ref = supplied_ref[:512]
                    self.store.register_evidence(
                        self.run_id,
                        evidence_ref=ref,
                        source=backend,
                        source_class=(
                            "live_endpoint_osquery"
                            if backend == "osquery"
                            else "packet_evidence"
                            if backend == "pcap_zeek"
                            else "security_onion_investigation_query"
                        ),
                        trust_tier=TrustTier.READ_ONLY_BACKEND.value,
                        corroborating=(
                            str(audit.get("status") or status)
                            in {"ok", "completed", "success"}
                            and returned_count is not None
                            and returned_count > 0
                        ),
                        status=str(audit.get("status") or status),
                        evidence_digest=str(
                            result_digest or digest
                        ),
                        metadata={
                            "query_id": audit.get("query_id"),
                            "query_digest": digest,
                            "returned": returned_count,
                            "truncated": audit.get("truncated"),
                        },
                    )
        # Policy/schema/backend rejections may never have entered the admitted
        # request list. They still need a durable tool ledger row so denial and
        # evidence-gap metrics reflect the actual investigation trajectory.
        for query_id, result in result_by_id.items():
            if query_id not in request_by_id:
                request_by_id[query_id] = {
                    "query_id": query_id,
                    "backend": result.get("backend"),
                    "purpose": result.get("purpose")
                    or "proposal rejected before execution",
                    "rejected_before_execution": True,
                }
        for query_id, request in request_by_id.items():
            result = result_by_id.get(query_id, {})
            backend = str(request.get("backend") or result.get("backend") or "")
            evidence = (
                result.get("evidence")
                if isinstance(result.get("evidence"), dict)
                else {}
            )
            result_status, result_observation = resolve_query_binding(
                result,
                query_id,
            )
            returned_count = observed_returned_count(result_observation)
            coverage = str(
                evidence.get("coverage")
                or evidence.get("coverage_semantics")
                or (
                    "exact-zero"
                    if result_status == "ok"
                    and returned_count == 0
                    else "bounded-result"
                    if result_status == "ok"
                    and returned_count is not None
                    and returned_count > 0
                    else "unknown"
                    if result_status == "ok"
                    else "evidence-gap"
                )
            )
            self.store.record_tool_call(
                self.run_id,
                call_id=f"round-{round_number}-{query_id}"[:128],
                round_number=round_number,
                backend=backend,
                capability=query_backend_capability(backend),
                purpose=str(request.get("purpose") or ""),
                request_digest=digest_json(request),
                result_digest=digest_json(result),
                status=result_status,
                read_only=result.get("read_only") is True,
                coverage=coverage,
                truncated=observed_truncation(result_observation),
            )
        with _connect(self.store.path) as connection:
            usage = connection.execute(
                """
                SELECT COUNT(*) executed_queries
                FROM harness_tool_calls
                WHERE run_id = ?
                  AND lower(status) NOT IN (
                    'rejected', 'denied', 'blocked',
                    'unauthorized', 'forbidden'
                  )
                """,
                (self.run_id,),
            ).fetchone()
        self._queries_total = max(
            self._queries_total,
            int(usage["executed_queries"]),
        )
        budget_violations = list(direct_violations)
        if self._query_rounds > self.policy.budgets["max_query_rounds"]:
            budget_violations.append("max_query_rounds")
        # Rejected proposals are audit rows but did not consume an execution
        # budget. The preflight reservation is authoritative when present;
        # this post-execution fallback counts admitted requests for callers that
        # use the harness API directly.
        admitted_total = max(self._queries_total, len(requests))
        if admitted_total > self.policy.budgets["max_queries_total"]:
            budget_violations.append("max_queries_total")
        if len(requests) > self.policy.budgets["max_queries_per_round"]:
            budget_violations.append("max_queries_per_round")
        self.store.append_event(
            self.run_id,
            "queries.completed",
            Stage.QUERY_EXECUTION.value,
            {
                "round": round_number,
                "request_count": len(requests),
                "result_count": len(results),
                "rejected_proposal_count": sum(
                    1
                    for request in request_by_id.values()
                    if request.get("rejected_before_execution") is True
                ),
                "status_counts": status_counts,
                "backend_counts": backend_counts,
                "trusted_query_digests": sorted(set(trusted_query_digests)),
                "budget_violations": budget_violations,
            },
            idempotency_key=f"queries.completed:{round_number}",
        )
        if budget_violations and self.policy.mode == "enforce":
            raise HarnessPolicyError(
                "investigation exceeded harness budget: "
                + ", ".join(budget_violations)
            )
