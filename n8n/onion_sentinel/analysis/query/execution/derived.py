"""Execution transition for governed PCAP/Zeek-derived evidence requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Type


@dataclass(frozen=True)
class Policy:
    maximum_requests: int = 4


@dataclass(frozen=True)
class Dependencies:
    executor: Callable[[dict[str, Any], list[dict[str, Any]]], dict[str, Any]]
    validate_evidence: Callable[
        [Any, list[dict[str, Any]]], dict[str, Any]
    ]
    source_digest: Callable[[dict[str, Any]], str]
    bounded_audit: Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
    safe_audit_summary: Callable[[Any], dict[str, Any]]
    handled_errors: tuple[Type[BaseException], ...]


@dataclass(frozen=True)
class Outcome:
    results: list[dict[str, Any]]
    audits: list[dict[str, Any]]


def _terminal(request: dict[str, Any], status: str, error: str) -> dict[str, Any]:
    return {
        "query_id": request["query_id"],
        "backend": request["backend"],
        "status": status,
        "read_only": True,
        "error": error,
    }


def _submitted(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {key: item["parameters"][key] for key in (
            "operation", "filters", "indicator", "limit"
        )}
        for item in requests
    ]


def _evidence_ref(item: dict[str, Any], source_digest: str) -> str:
    return (
        "derived-pcap-zeek:"
        f"{source_digest[:16]}:"
        f"{str(item.get('query_digest') or '')[:16]}:"
        f"{str(item.get('result_digest') or '')[:16]}"
    )


def _binding(
    request: dict[str, Any], item: dict[str, Any], evidence_ref: str,
) -> dict[str, Any]:
    query = item.get("query") if isinstance(item.get("query"), dict) else {}
    audit = item.get("audit") if isinstance(item.get("audit"), dict) else {}
    return {
        "query_id": request["query_id"],
        "backend": request["backend"],
        "purpose": request["purpose"],
        **{key: query.get(key) for key in (
            "operation", "filters", "indicator", "limit"
        )},
        "status": "ok",
        **{key: audit.get(key) for key in (
            "candidate_records_scanned", "unique_records_matched",
            "records_returned", "result_truncated", "index_scan_truncated",
            "derived_views_considered",
        )},
        "query_digest": item.get("query_digest"),
        "result_digest": item.get("result_digest"),
        "evidence_ref": evidence_ref,
    }


def _success_results(
    requests: list[dict[str, Any]], evidence: dict[str, Any],
    source_digest: str, dependencies: Dependencies,
) -> list[dict[str, Any]]:
    returned = evidence.get("results")
    rows = returned if isinstance(returned, list) else []
    results: list[dict[str, Any]] = []
    for index, request in enumerate(requests):
        item = rows[index] if index < len(rows) and isinstance(rows[index], dict) else {}
        evidence_ref = _evidence_ref(item, source_digest)
        model_item = dict(item)
        model_item["evidence_ref"] = evidence_ref
        results.append({
            "query_id": request["query_id"],
            "backend": request["backend"],
            "status": "ok",
            "read_only": True,
            "evidence": model_item,
            "trusted_query_audit": dependencies.bounded_audit([
                _binding(request, item, evidence_ref)
            ]),
        })
    return results


def execute(
    requests: list[dict[str, Any]], pcap_context: dict[str, Any], *,
    policy: Policy = Policy(), dependencies: Dependencies,
) -> Outcome:
    """Execute one capped derived-evidence batch with digest-bound results."""
    admitted = requests[:policy.maximum_requests]
    results = [
        _terminal(
            request, "rejected",
            "at most four combined PCAP/Zeek derived-evidence queries are "
            "allowed per round",
        )
        for request in requests[policy.maximum_requests:]
    ]
    if not admitted:
        return Outcome(results=results, audits=[])
    submitted = _submitted(admitted)
    try:
        evidence = dependencies.validate_evidence(
            dependencies.executor(pcap_context, submitted), submitted
        )
        results.extend(_success_results(
            admitted, evidence, dependencies.source_digest(pcap_context),
            dependencies,
        ))
        audit = {
            "backend": "derived-pcap-zeek",
            **dependencies.safe_audit_summary(evidence.get("executed")),
        }
        return Outcome(results=results, audits=[audit])
    except dependencies.handled_errors as exc:
        message = f"{type(exc).__name__}: {exc}"[:1000]
        results.extend(_terminal(item, "error", message) for item in admitted)
        return Outcome(results=results, audits=[])
