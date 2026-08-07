"""Execution transition for live endpoint OSQuery requests."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
from typing import Any, Callable, Type


Identity = tuple[str, str]


@dataclass(frozen=True)
class Dependencies:
    executor: Callable[..., dict[str, Any]]
    validate_artifact: Callable[..., dict[str, Any]]
    case_id: Callable[[dict[str, Any]], str]
    target_bound: Callable[[dict[str, Any], str, dict[str, Any]], bool]
    support_bindings: Callable[
        [dict[str, Any], dict[str, Any], dict[str, Any]], list[dict[str, Any]]
    ]
    accumulate_evidence: Callable[[dict[str, Any], dict[str, Any]], None]
    accumulate_failure: Callable[..., None]
    normalize_query: Callable[[str], str]
    text: Callable[[Any, int], str]
    bounded_audit: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    safe_audit_summary: Callable[[Any], dict[str, Any]]
    client_error: Type[Exception]
    handled_errors: tuple[Type[BaseException], ...]


@dataclass(frozen=True)
class Outcome:
    results: list[dict[str, Any]]
    audits: list[dict[str, Any]]


def _collector_requests(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "target_alias": item["parameters"]["target_alias"],
        "query": item["parameters"]["query"],
        "purpose": item["purpose"],
    } for item in requests]


def _returned_by_identity(
    evidence: dict[str, Any], dependencies: Dependencies,
) -> dict[Identity, dict[str, Any]]:
    returned = evidence.get("results")
    if not isinstance(returned, list):
        raise dependencies.client_error(
            "live OSQuery evidence did not contain a result list"
        )
    indexed: dict[Identity, dict[str, Any]] = {}
    for item in returned:
        if not isinstance(item, dict):
            raise dependencies.client_error(
                "live OSQuery evidence contained a non-object result"
            )
        identity = (
            dependencies.text(item.get("target_alias"), 64).lower(),
            dependencies.text(item.get("query_digest"), 64).lower(),
        )
        if not all(identity) or identity in indexed:
            raise dependencies.client_error(
                "live OSQuery evidence contained a missing or duplicate result identity"
            )
        indexed[identity] = item
    return indexed


def _expected_by_identity(
    requests: list[dict[str, Any]], dependencies: Dependencies,
) -> dict[Identity, dict[str, Any]]:
    indexed: dict[Identity, dict[str, Any]] = {}
    for request in requests:
        query = dependencies.normalize_query(request["parameters"]["query"])
        identity = (
            dependencies.text(
                request["parameters"].get("target_alias"), 64
            ).lower(),
            hashlib.sha256(query.encode()).hexdigest(),
        )
        if identity in indexed:
            raise dependencies.client_error(
                "live OSQuery submission contained a duplicate query identity"
            )
        indexed[identity] = request
    return indexed


def _binding(
    request: dict[str, Any], item: dict[str, Any], dependencies: Dependencies,
) -> list[dict[str, Any]]:
    return dependencies.bounded_audit([{
        "query_id": request["query_id"],
        "backend": "osquery",
        "purpose": item.get("purpose"),
        "target_alias": item.get("target_alias"),
        "query": item.get("query"),
        "query_digest": item.get("query_digest"),
        "status": item.get("status"),
        "total_rows": item.get("total_rows"),
        "returned_rows": len(item.get("rows") or []),
        "truncated": item.get("truncated"),
        "duration_ms": item.get("duration_ms"),
        "error": item.get("error"),
    }])


def _bound_results(
    requests: list[dict[str, Any]], evidence: dict[str, Any],
    dependencies: Dependencies,
) -> list[dict[str, Any]]:
    returned = _returned_by_identity(evidence, dependencies)
    expected = _expected_by_identity(requests, dependencies)
    if set(returned) != set(expected):
        raise dependencies.client_error(
            "live OSQuery evidence coverage did not match submitted query digests"
        )
    results: list[dict[str, Any]] = []
    for identity, request in expected.items():
        item = returned[identity]
        if str(item.get("purpose") or "") != request["purpose"]:
            raise dependencies.client_error(
                "live OSQuery evidence did not bind to the submitted query digest"
            )
        results.append({
            "query_id": request["query_id"],
            "backend": "osquery",
            "status": dependencies.text(item.get("status"), 40) or "error",
            "read_only": True,
            "evidence": item,
            "trusted_query_audit": _binding(request, item, dependencies),
        })
    return results


def _audit_evidence(
    prompt_package: dict[str, Any], evidence: dict[str, Any],
    config: dict[str, Any], dependencies: Dependencies,
) -> None:
    audit = copy.deepcopy(evidence)
    for item in audit.get("results", []):
        if isinstance(item, dict):
            item["support_bindings"] = dependencies.support_bindings(
                prompt_package, item, config
            )
    dependencies.accumulate_evidence(prompt_package, audit)


def _authorize_targets(
    requests: list[dict[str, Any]], prompt_package: dict[str, Any],
    config: dict[str, Any] | None, dependencies: Dependencies,
) -> dict[str, Any]:
    if not config or not config.get("enabled"):
        raise dependencies.client_error(
            "live-host OSQuery is not enabled for this deployment"
        )
    if any(
        not dependencies.target_bound(prompt_package, item["target_alias"], config)
        for item in requests
    ):
        raise dependencies.client_error(
            "live-host OSQuery target is not bound to a trusted endpoint "
            "observable for this alert"
        )
    return config


def execute(
    requests: list[dict[str, Any]], prompt_package: dict[str, Any],
    config: dict[str, Any] | None, *, dependencies: Dependencies,
) -> Outcome:
    """Dispatch and bind a live OSQuery batch to its exact request identities."""
    if not requests:
        return Outcome(results=[], audits=[])
    collector_requests = _collector_requests(requests)
    collector_case_id = dependencies.case_id(prompt_package)
    dispatch_started = False
    try:
        authorized_config = _authorize_targets(
            collector_requests, prompt_package, config, dependencies
        )
        dispatch_started = True
        evidence = dependencies.validate_artifact(
            dependencies.executor(
                case_id=collector_case_id, requests=collector_requests,
                config=authorized_config, persist=True,
            ),
            expected_requests=collector_requests,
        )
        if evidence.get("case_id") != collector_case_id:
            raise dependencies.client_error(
                "live OSQuery evidence case_id did not match the investigation"
            )
        _audit_evidence(
            prompt_package, evidence, authorized_config, dependencies
        )
        results = _bound_results(requests, evidence, dependencies)
        return Outcome(results=results, audits=[{
            "backend": "osquery",
            **dependencies.safe_audit_summary(evidence),
        }])
    except dependencies.handled_errors as exc:
        message = f"{type(exc).__name__}: {exc}"[:1000]
        dependencies.accumulate_failure(
            prompt_package, case_id=collector_case_id,
            requests=collector_requests, error=message,
            dispatch_possible=dispatch_started,
        )
        return Outcome(results=[{
            "query_id": request["query_id"],
            "backend": "osquery",
            "status": "error",
            "read_only": True,
            "error": message,
        } for request in requests], audits=[])
