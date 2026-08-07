"""Execution transition for governed Security Onion Elastic/OQL requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Type


@dataclass(frozen=True)
class Policy:
    query_contract: str
    require_anchor_time: bool
    maximum_requests: int = 4
    maximum_observables: int = 24


@dataclass(frozen=True)
class Dependencies:
    project_context: Callable[[Any], dict[str, Any]]
    authorize: Callable[[dict[str, Any], dict[str, Any]], Any]
    executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    text: Callable[[Any, int], str]
    random_hex: Callable[[int], str]
    bounded_audit: Callable[[Any], list[dict[str, Any]]]
    safe_audit_summary: Callable[[Any], dict[str, Any]]
    contract_error: Type[Exception]
    query_error: Type[Exception]


@dataclass(frozen=True)
class Outcome:
    results: list[dict[str, Any]]
    audits: list[dict[str, Any]]


def _query(request: dict[str, Any]) -> dict[str, Any]:
    parameters = request["parameters"]
    return {
        "query_id": request["query_id"],
        "dialect": request["backend"],
        "pack": parameters["pack"],
        "purpose": request["purpose"],
        "window": parameters["window"],
        "observables": parameters["observables"],
        **(
            {"event_tuple": parameters["event_tuple"]}
            if parameters.get("event_tuple") else {}
        ),
        "size": parameters["size"],
        "aggregation": parameters["aggregation"],
    }


def _rejected(request: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "query_id": request["query_id"],
        "backend": request["backend"],
        "status": "rejected",
        "read_only": True,
        "error": reason,
        "normalization": request.get("normalization") or {},
    }


def _observable_set(request: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (kind, value)
        for kind, values in request["parameters"]["observables"].items()
        for value in values
    }


def _can_preflight(context: dict[str, Any], policy: Policy) -> bool:
    required = {
        "context_id", "case_id", "actor_role", "anchor", "time_envelope",
        "permitted_observables",
    }
    if policy.require_anchor_time:
        required.add("anchor_time")
    return required.issubset(context)


def _preflight_reason(
    request: dict[str, Any], index: int, round_number: int,
    context: dict[str, Any], policy: Policy, dependencies: Dependencies,
) -> str:
    if not _can_preflight(context, policy):
        return ""
    proposal = {
        "query_contract": policy.query_contract,
        "batch_id": f"preflight-r{round_number}-q{index}",
        "queries": [_query(request)],
    }
    try:
        dependencies.authorize(proposal, context)
        return ""
    except dependencies.contract_error as exc:
        return (
            "Security Onion query failed isolated local authorization: "
            f"{str(exc)[:700]}"
        )


def _admit(
    requests: list[dict[str, Any]], round_number: int,
    context: dict[str, Any], context_error: str, policy: Policy,
    dependencies: Dependencies,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    admitted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    observables: set[tuple[str, str]] = set()
    for index, request in enumerate(requests, 1):
        request_observables = _observable_set(request)
        reason = context_error
        if not reason and len(admitted) >= policy.maximum_requests:
            reason = (
                "at most four Security Onion Elastic/OQL queries are allowed "
                "per round"
            )
        if not reason and len(observables | request_observables) > policy.maximum_observables:
            reason = "Security Onion query batch exceeds 24 distinct observables"
        if not reason:
            reason = _preflight_reason(
                request, index, round_number, context, policy, dependencies
            )
        if reason:
            rejected.append(_rejected(request, reason))
        else:
            admitted.append(request)
            observables.update(request_observables)
    return admitted, rejected


def _project_context(
    value: Any, dependencies: Dependencies,
) -> tuple[dict[str, Any], str]:
    try:
        return dependencies.project_context(value), ""
    except dependencies.contract_error as exc:
        return {}, (
            "Security Onion query failed isolated local authorization: "
            f"{str(exc)[:700]}"
        )


def _success(
    requests: list[dict[str, Any]], artifact: dict[str, Any],
    dependencies: Dependencies,
) -> Outcome:
    evidence = artifact.get("model_evidence")
    if not isinstance(evidence, (dict, list)):
        raise dependencies.query_error(
            "Security Onion pivot broker returned no model evidence"
        )
    artifact_audit = (
        artifact.get("audit") if isinstance(artifact.get("audit"), dict) else {}
    )
    status = (
        "ok" if artifact.get("complete") is True and artifact.get("partial") is not True
        else "partial" if artifact.get("partial") is True else "error"
    )
    result = {
        "backend": "security_onion",
        "query_ids": [item["query_id"] for item in requests],
        "status": status,
        "read_only": True,
        "evidence": evidence,
        "security_onion_response_digest": dependencies.text(
            artifact_audit.get("security_onion_response_digest"), 64
        ),
        "trusted_query_audit": dependencies.bounded_audit(
            artifact.get("query_audit")
            or artifact_audit.get("query_audit")
            or []
        ),
    }
    audit = {
        "backend": "security_onion",
        **dependencies.safe_audit_summary({
            **artifact_audit, "complete": artifact.get("complete")
        }),
    }
    return Outcome(results=[result], audits=[audit])


def execute(
    requests: list[dict[str, Any]], local_context: Any, *, round_number: int,
    policy: Policy, dependencies: Dependencies,
) -> Outcome:
    """Authorize, execute, and bind one Security Onion broker batch."""
    context, context_error = _project_context(local_context, dependencies)
    admitted, results = _admit(
        requests, round_number, context, context_error, policy, dependencies
    )
    if not admitted:
        return Outcome(results=results, audits=[])
    case_id = dependencies.text(context.get("case_id"), 80) or "investigation"
    proposal = {
        "query_contract": policy.query_contract,
        "batch_id": (
            f"{case_id}-r{round_number}-{dependencies.random_hex(8)}"
        ),
        "queries": [_query(request) for request in admitted],
    }
    try:
        success = _success(
            admitted, dependencies.executor(proposal, context), dependencies
        )
        return Outcome(results=results + success.results, audits=success.audits)
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"[:1000]
        results.extend({
            "query_id": request["query_id"],
            "backend": request["backend"],
            "status": "error",
            "read_only": True,
            "error": message,
        } for request in admitted)
        return Outcome(results=results, audits=[])
