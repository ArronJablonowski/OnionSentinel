"""Execution transition for evidence-bound public enrichment requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Type


SCHEMA = "onion-sentinel-investigation-enrichment-evidence-v1"


@dataclass(frozen=True)
class Dependencies:
    executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    error_type: Type[Exception]
    handled_errors: tuple[Type[BaseException], ...]


@dataclass(frozen=True)
class Outcome:
    results: list[dict[str, Any]]
    audits: list[dict[str, Any]]


def _success(request: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "query_id": request["query_id"],
        "backend": "enrichment",
        "status": "ok",
        "read_only": True,
        "evidence": evidence,
        "trusted_query_audit": [{
            "query_id": request["query_id"],
            "backend": "enrichment",
            "status": "ok",
            **{
                key: evidence.get(key) for key in (
                    "indicator_type", "indicator", "cache_checked_first",
                    "n8n_invoked", "query_digest", "result_digest",
                    "evidence_ref",
                )
            },
        }],
    }


def _audit(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "backend": "enrichment",
        **{
            key: evidence.get(key) for key in (
                "cache_checked_first", "n8n_invoked", "query_digest",
                "result_digest",
            )
        },
    }


def execute(
    requests: list[dict[str, Any]], config: dict[str, Any] | None,
    *, dependencies: Dependencies,
) -> Outcome:
    """Execute requests independently and retain every terminal outcome."""
    results: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    for request in requests:
        try:
            if not config or config.get("enabled") is not True:
                raise dependencies.error_type("investigation enrichment is not enabled")
            evidence = dependencies.executor(request, config)
            if (
                not isinstance(evidence, dict)
                or evidence.get("schema") != SCHEMA
                or evidence.get("status") != "ok"
            ):
                raise dependencies.error_type(
                    "enrichment orchestrator returned invalid evidence"
                )
            results.append(_success(request, evidence))
            audits.append(_audit(evidence))
        except dependencies.handled_errors as exc:
            results.append({
                "query_id": request["query_id"],
                "backend": "enrichment",
                "status": "error",
                "read_only": True,
                "error": f"{type(exc).__name__}: {exc}"[:1000],
            })
    return Outcome(results=results, audits=audits)
