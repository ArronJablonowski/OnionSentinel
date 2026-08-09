"""Execution transition for evidence-bound public enrichment requests."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
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


@dataclass(frozen=True)
class CollectionPolicy:
    schema: str = SCHEMA
    maximum_records: int = 16


@dataclass(frozen=True)
class CollectionDependencies:
    post_json: Callable[[str, dict[str, Any], dict[str, str], int], dict[str, Any]]
    project_record: Callable[[Any], dict[str, Any]]


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


def collect(
    request: dict[str, Any], config: dict[str, Any], *,
    policy: CollectionPolicy = CollectionPolicy(),
    dependencies: CollectionDependencies,
) -> dict[str, Any]:
    """Collect cache-first public enrichment through injected transports."""
    parameters = request.get("parameters")
    values = parameters if isinstance(parameters, dict) else {}
    payload = {
        "indicator_type": values.get("indicator_type"),
        "indicator": values.get("indicator"),
    }
    token, timeout = str(config.get("token") or ""), int(config.get("timeout") or 120)
    headers = {"X-Onion-Sentinel-Asset-Token": token}
    cache = dependencies.post_json(
        str(config["alert_store_url"]) + "/investigations/enrichment/cache",
        payload, headers, timeout,
    )
    invoked, source = _source(cache, config, payload, token, timeout, dependencies)
    records = _project_records(source, policy, dependencies)
    query_digest = _digest(payload)
    result_digest = _digest(records)
    result_context = source.get("enrichment") or source
    return {
        "schema": policy.schema, "status": "ok",
        "indicator_type": payload["indicator_type"], "indicator": payload["indicator"],
        "cache_checked_first": True, "cache_complete": bool(cache.get("cache_complete")),
        "n8n_invoked": invoked,
        "rate_limits_enforced_by": "alert-store-persisted-provider-scheduler",
        "records": records, "skipped": result_context.get("skipped", []),
        "errors": result_context.get("errors", []),
        "query_digest": query_digest, "result_digest": result_digest,
        "evidence_ref": f"enrichment:{query_digest[:20]}:{result_digest[:20]}",
    }


def _source(
    cache: dict[str, Any], config: dict[str, Any], payload: dict[str, Any],
    token: str, timeout: int, dependencies: CollectionDependencies,
) -> tuple[bool, dict[str, Any]]:
    if bool(cache.get("cache_complete")):
        return False, cache
    return True, dependencies.post_json(
        str(config["n8n_url"]), payload, {"X-Relay-Token": token}, timeout,
    )


def _project_records(
    source: dict[str, Any], policy: CollectionPolicy,
    dependencies: CollectionDependencies,
) -> list[dict[str, Any]]:
    raw_records = source.get("records")
    if not isinstance(raw_records, list):
        enrichment = source.get("enrichment")
        raw_records = enrichment.get("records", []) if isinstance(enrichment, dict) else []
    return [
        projected for item in raw_records[:policy.maximum_records]
        if (projected := dependencies.project_record(item))
    ]


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
