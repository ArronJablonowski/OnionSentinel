"""Governed query-round budget, evidence, tool-ledger, and summary execution."""
from __future__ import annotations

from typing import Any, Callable, Mapping

from harness_policy import (
    DIGEST_RE,
    HarnessPolicyError,
    Stage,
    TrustTier,
    digest_json,
    query_backend_capability,
)
from harness_query_contract import (
    observed_returned_count,
    observed_truncation,
    resolve_query_binding,
)


def record_query_round(
    run: Any,
    round_result: Mapping[str, Any],
    *,
    connect: Callable[[Any], Any],
) -> None:
    round_number, requests, results = _round_inputs(run, round_result)
    direct_violations = _reserve_query_round(
        run,
        round_number,
        requests,
    )
    (
        status_counts,
        backend_counts,
        trusted_query_digests,
        result_by_id,
    ) = _index_query_results(run, results)
    request_by_id = _request_index(requests, result_by_id)
    _record_query_tools(
        run,
        round_number,
        request_by_id,
        result_by_id,
    )
    run._queries_total = max(
        run._queries_total,
        _executed_query_count(run, connect=connect),
    )
    budget_violations = _post_execution_violations(
        run,
        requests,
        direct_violations,
    )
    _append_query_summary(
        run,
        round_number=round_number,
        requests=requests,
        results=results,
        request_by_id=request_by_id,
        status_counts=status_counts,
        backend_counts=backend_counts,
        trusted_query_digests=trusted_query_digests,
        budget_violations=budget_violations,
    )
    if budget_violations and run.policy.mode == "enforce":
        raise HarnessPolicyError(
            "investigation exceeded harness budget: "
            + ", ".join(budget_violations)
        )


def _round_inputs(
    run: Any,
    round_result: Mapping[str, Any],
) -> tuple[int, list[Any], list[Any]]:
    round_number = int(
        round_result.get("round") or run._query_rounds + 1
    )
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
    return round_number, requests, results


def _reserve_query_round(
    run: Any,
    round_number: int,
    requests: list[Any],
) -> list[str]:
    direct_violations: list[str] = []
    if len(requests) > run.policy.budgets["max_queries_per_round"]:
        direct_violations.append("max_queries_per_round")
    if round_number > run.policy.budgets["max_query_rounds"]:
        direct_violations.append("max_query_rounds")
    reservation = run.store.reserve_budget_operation(
        run.run_id,
        reservation_type="query-round",
        reservation_id=str(round_number),
        amount=len(requests),
        max_total=run.policy.budgets["max_queries_total"],
        max_operations=run.policy.budgets["max_query_rounds"],
        enforce=run.policy.mode == "enforce",
        preexisting_violations=direct_violations,
    )
    direct_violations = list(reservation["violations"])
    if direct_violations and run.policy.mode == "enforce":
        run._enforce_budget(
            operation_id=f"query-round:{round_number}",
            operation="query batch",
            stage=Stage.QUERY_PLANNING.value,
            observed={
                "round": round_number,
                "request_count": len(requests),
                "queries_after_batch": reservation["total"],
                "reserved": bool(reservation["reserved"]),
            },
            violations=direct_violations,
        )
    if reservation["reserved"]:
        run._queries_total = max(
            run._queries_total,
            int(reservation["total"]),
        )
    run._query_rounds = max(run._query_rounds, round_number)
    return direct_violations


def _index_query_results(
    run: Any,
    results: list[Any],
) -> tuple[
    dict[str, int],
    dict[str, int],
    list[str],
    dict[str, dict[str, Any]],
]:
    status_counts: dict[str, int] = {}
    backend_counts: dict[str, int] = {}
    trusted_query_digests: list[str] = []
    result_by_id: dict[str, dict[str, Any]] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unknown")[:40]
        backend = str(item.get("backend") or "unknown")[:40]
        status_counts[status] = status_counts.get(status, 0) + 1
        backend_counts[backend] = backend_counts.get(backend, 0) + 1
        _bind_result_ids(result_by_id, item)
        _register_trusted_audits(
            run,
            item,
            backend=backend,
            status=status,
            trusted_query_digests=trusted_query_digests,
        )
    return (
        status_counts,
        backend_counts,
        trusted_query_digests,
        result_by_id,
    )


def _bind_result_ids(
    result_by_id: dict[str, dict[str, Any]],
    item: dict[str, Any],
) -> None:
    item_ids = (
        [str(value) for value in item.get("query_ids", [])]
        if isinstance(item.get("query_ids"), list)
        else [str(item.get("query_id"))]
        if item.get("query_id")
        else []
    )
    for item_id in item_ids:
        result_by_id[item_id] = item


def _register_trusted_audits(
    run: Any,
    item: Mapping[str, Any],
    *,
    backend: str,
    status: str,
    trusted_query_digests: list[str],
) -> None:
    audits = (
        item.get("trusted_query_audit")
        if isinstance(item.get("trusted_query_audit"), list)
        else []
    )
    for audit in audits:
        if not isinstance(audit, dict):
            continue
        digest = str(audit.get("query_digest") or "")
        if not DIGEST_RE.fullmatch(digest):
            continue
        trusted_query_digests.append(digest)
        _register_query_evidence(
            run,
            audit,
            backend=backend,
            status=status,
            digest=digest,
        )


def _register_query_evidence(
    run: Any,
    audit: Mapping[str, Any],
    *,
    backend: str,
    status: str,
    digest: str,
) -> None:
    returned_count = observed_returned_count(audit)
    result_digest = str(audit.get("result_digest") or "").lower()
    if not DIGEST_RE.fullmatch(result_digest):
        result_digest = ""
    ref = _evidence_ref(audit, digest, result_digest)
    run.store.register_evidence(
        run.run_id,
        evidence_ref=ref,
        source=backend,
        source_class=_query_source_class(backend),
        trust_tier=TrustTier.READ_ONLY_BACKEND.value,
        corroborating=(
            str(audit.get("status") or status)
            in {"ok", "completed", "success"}
            and returned_count is not None
            and returned_count > 0
        ),
        status=str(audit.get("status") or status),
        evidence_digest=str(result_digest or digest),
        metadata={
            "query_id": audit.get("query_id"),
            "query_digest": digest,
            "returned": returned_count,
            "truncated": audit.get("truncated"),
        },
    )


def _evidence_ref(
    audit: Mapping[str, Any],
    digest: str,
    result_digest: str,
) -> str:
    supplied_ref = str(
        audit.get("evidence_ref") or f"query:{digest}"
    ).strip()
    if supplied_ref and not supplied_ref.startswith("query:"):
        return supplied_ref[:512]
    ref = f"query:{digest}"
    if DIGEST_RE.fullmatch(result_digest):
        ref += f":{result_digest}"
    return ref


def _query_source_class(backend: str) -> str:
    if backend == "osquery":
        return "live_endpoint_osquery"
    if backend == "pcap_zeek":
        return "packet_evidence"
    return "security_onion_investigation_query"


def _request_index(
    requests: list[Any],
    result_by_id: Mapping[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    request_by_id = {
        str(item.get("query_id")): item
        for item in requests
        if isinstance(item, dict) and item.get("query_id")
    }
    for query_id, result in result_by_id.items():
        if query_id not in request_by_id:
            request_by_id[query_id] = {
                "query_id": query_id,
                "backend": result.get("backend"),
                "purpose": result.get("purpose")
                or "proposal rejected before execution",
                "rejected_before_execution": True,
            }
    return request_by_id


def _record_query_tools(
    run: Any,
    round_number: int,
    request_by_id: Mapping[str, dict[str, Any]],
    result_by_id: Mapping[str, dict[str, Any]],
) -> None:
    for query_id, request in request_by_id.items():
        result = result_by_id.get(query_id, {})
        backend = str(
            request.get("backend") or result.get("backend") or ""
        )
        result_status, result_observation = resolve_query_binding(
            result,
            query_id,
        )
        run.store.record_tool_call(
            run.run_id,
            call_id=f"round-{round_number}-{query_id}"[:128],
            round_number=round_number,
            backend=backend,
            capability=query_backend_capability(backend),
            purpose=str(request.get("purpose") or ""),
            request_digest=digest_json(request),
            result_digest=digest_json(result),
            status=result_status,
            read_only=result.get("read_only") is True,
            coverage=_query_coverage(result, result_status, result_observation),
            truncated=observed_truncation(result_observation),
        )


def _query_coverage(
    result: Mapping[str, Any],
    result_status: str,
    result_observation: Any,
) -> str:
    evidence = (
        result.get("evidence")
        if isinstance(result.get("evidence"), dict)
        else {}
    )
    returned_count = observed_returned_count(result_observation)
    return str(
        evidence.get("coverage")
        or evidence.get("coverage_semantics")
        or (
            "exact-zero"
            if result_status == "ok" and returned_count == 0
            else "bounded-result"
            if result_status == "ok"
            and returned_count is not None
            and returned_count > 0
            else "unknown"
            if result_status == "ok"
            else "evidence-gap"
        )
    )


def _executed_query_count(
    run: Any,
    *,
    connect: Callable[[Any], Any],
) -> int:
    with connect(run.store.path) as connection:
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
            (run.run_id,),
        ).fetchone()
    return int(usage["executed_queries"])


def _post_execution_violations(
    run: Any,
    requests: list[Any],
    direct_violations: list[str],
) -> list[str]:
    budget_violations = list(direct_violations)
    if run._query_rounds > run.policy.budgets["max_query_rounds"]:
        budget_violations.append("max_query_rounds")
    admitted_total = max(run._queries_total, len(requests))
    if admitted_total > run.policy.budgets["max_queries_total"]:
        budget_violations.append("max_queries_total")
    if len(requests) > run.policy.budgets["max_queries_per_round"]:
        budget_violations.append("max_queries_per_round")
    return budget_violations


def _append_query_summary(
    run: Any,
    *,
    round_number: int,
    requests: list[Any],
    results: list[Any],
    request_by_id: Mapping[str, dict[str, Any]],
    status_counts: Mapping[str, int],
    backend_counts: Mapping[str, int],
    trusted_query_digests: list[str],
    budget_violations: list[str],
) -> None:
    run.store.append_event(
        run.run_id,
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
            "status_counts": dict(status_counts),
            "backend_counts": dict(backend_counts),
            "trusted_query_digests": sorted(
                set(trusted_query_digests)
            ),
            "budget_violations": budget_violations,
        },
        idempotency_key=f"queries.completed:{round_number}",
    )
