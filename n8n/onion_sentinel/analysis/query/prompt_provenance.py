"""Result-bound provenance projection for investigation-query prompts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Callable

from . import primitives, prompt_facts


@dataclass(frozen=True)
class Policy:
    maximum_queries: int
    success_statuses: frozenset[str]
    result_schema: str
    columnar_schema: str
    columns: tuple[str, ...]
    empty_ref_instruction: str
    facts: prompt_facts.Policy


@dataclass(frozen=True)
class Dependencies:
    result_bound_reference: Callable[[Any, Any], tuple[str, str]]


def exact_query_id(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    query_id = primitives.text(value, 128)
    return (
        query_id
        if query_id == value
        and re.fullmatch(r"[A-Za-z0-9_.:@+=-]{1,128}", query_id)
        else ""
    )


def _dict_list(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        return None
    return list(value)


def _declared_ids(result: dict[str, Any]) -> list[str] | None:
    scalar = "query_id" in result
    grouped = "query_ids" in result
    if scalar == grouped:
        return None
    raw = result.get("query_ids") if grouped else [result.get("query_id")]
    if not isinstance(raw, list):
        return None
    declared = [exact_query_id(value) for value in raw]
    if not declared or not all(declared) or len(set(declared)) != len(declared):
        return None
    return declared


def _exact_coverage(
    candidates: list[dict[str, Any]], declared: list[str],
) -> bool:
    candidate_ids = [exact_query_id(item.get("query_id")) for item in candidates]
    return bool(
        len(candidate_ids) == len(declared)
        and all(candidate_ids)
        and len(set(candidate_ids)) == len(candidate_ids)
        and set(candidate_ids) == set(declared)
    )


def _result_sources(
    result: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]] | None:
    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    nested = _dict_list(evidence.get("results", []))
    trusted = _dict_list(result.get("trusted_query_audit", []))
    declared = _declared_ids(result)
    if nested is None or trusted is None or declared is None:
        return None
    if trusted and not _exact_coverage(trusted, declared):
        return None
    if nested and not _exact_coverage(nested, declared):
        return None
    if len(declared) > 1 and not trusted and not nested:
        return None
    return evidence, nested, trusted or nested or [result]


def _first_value(containers: tuple[dict[str, Any], ...], key: str) -> Any:
    for container in containers:
        if container.get(key) not in (None, ""):
            return container.get(key)
    return ""


def _query_status(
    containers: tuple[dict[str, Any], ...], *, controls_valid: Any,
    policy: Policy,
) -> str:
    status = primitives.text(
        containers[0].get("status")
        or containers[1].get("status")
        or containers[-1].get("status"),
        40,
    )
    invalid = controls_valid is False or any(
        container.get("semantic_valid") is False for container in containers[:2]
    )
    return "partial" if invalid and status.lower() in policy.success_statuses else status


def _provenance_row(
    round_number: Any, result: dict[str, Any], evidence: dict[str, Any],
    source: dict[str, Any], nested_by_id: dict[str, dict[str, Any]], *,
    policy: Policy,
) -> dict[str, Any]:
    query_id = primitives.text(source.get("query_id") or result.get("query_id"), 128)
    nested = nested_by_id.get(query_id, {})
    containers = (nested, source, evidence, result)
    status = _query_status(
        containers, controls_valid=evidence.get("controls_valid"), policy=policy
    )
    returned = prompt_facts.provenance_count(
        containers,
        ("returned_hits", "returned_rows", "records_returned", "total_hits", "total_rows"),
        policy=policy.facts,
    )
    return {
        "round": round_number,
        "query_id": query_id,
        "backend": primitives.text(
            source.get("backend") or source.get("dialect") or result.get("backend"), 40
        ),
        "status": status,
        "read_only": result.get("read_only") is True,
        "query_digest": primitives.text(_first_value(containers, "query_digest"), 128),
        "result_digest": primitives.text(_first_value(containers, "result_digest"), 128),
        "evidence_ref": primitives.text(_first_value(containers, "evidence_ref"), 512),
        "returned": returned,
        "semantics": prompt_facts.query_semantics(containers),
        "result_summary": prompt_facts.result_summary(
            containers, status=status, returned=returned, policy=policy.facts
        ),
    }


def rows(
    rounds: list[dict[str, Any]], *, policy: Policy,
) -> list[dict[str, Any]] | None:
    """Extract one compact, ordered record per exactly covered logical query."""
    output: list[dict[str, Any]] = []
    for round_item in rounds:
        if not isinstance(round_item, dict):
            return None
        results = round_item.get("results", [])
        if not isinstance(results, list):
            return None
        for result in results:
            if not isinstance(result, dict):
                return None
            resolved = _result_sources(result)
            if resolved is None:
                return None
            evidence, nested, sources = resolved
            nested_by_id = {exact_query_id(item.get("query_id")): item for item in nested}
            output.extend(
                _provenance_row(
                    round_item.get("round"), result, evidence, source, nested_by_id,
                    policy=policy,
                )
                for source in sources
            )
    return output


def _valid_rows(provenance: list[dict[str, Any]], policy: Policy) -> bool:
    return bool(
        provenance
        and len(provenance) <= policy.maximum_queries
        and all(
            item["query_id"]
            and item["backend"]
            and item["status"]
            and re.fullmatch(r"[a-f0-9]{64}", item["query_digest"])
            and item["semantics"]
            and item["result_summary"]
            for item in provenance
        )
    )


def _dictionary(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _encoded_rows(
    provenance: list[dict[str, Any]], backends: list[str], statuses: list[str],
    semantics: list[str], summaries: list[str], dependencies: Dependencies,
) -> list[list[Any]]:
    encoded = []
    for item in provenance:
        canonical_ref, _ = dependencies.result_bound_reference(
            item["query_digest"], item["result_digest"]
        )
        evidence_ref = "" if canonical_ref and item["evidence_ref"] == canonical_ref else item["evidence_ref"]
        encoded.append([
            item["round"], item["query_id"], backends.index(item["backend"]),
            statuses.index(item["status"]), item["read_only"], item["query_digest"],
            item["result_digest"], evidence_ref, item["returned"],
            semantics.index(item["semantics"]), summaries.index(item["result_summary"]),
        ])
    return encoded


def _converge_size(value: dict[str, Any]) -> int:
    for _ in range(8):
        actual = len(prompt_facts.canonical_bytes(value))
        if value["prompt_projection"]["encoded_bytes"] == actual:
            return actual
        value["prompt_projection"]["encoded_bytes"] = actual
    return len(prompt_facts.canonical_bytes(value))


def columnar_payload(
    rounds: list[dict[str, Any]], *, maximum_bytes: int, policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any] | None:
    """Return the smallest complete, result-bound provenance projection."""
    try:
        source_bytes = prompt_facts.canonical_bytes(rounds)
    except (TypeError, ValueError, OverflowError):
        return None
    provenance = rows(rounds, policy=policy)
    if provenance is None or not _valid_rows(provenance, policy):
        return None
    backends = _dictionary([item["backend"] for item in provenance])
    statuses = _dictionary([item["status"] for item in provenance])
    semantics = _dictionary([item["semantics"] for item in provenance])
    summaries = _dictionary([item["result_summary"] for item in provenance])
    value = {
        "schema": policy.result_schema,
        "rounds": [{
            "schema": policy.columnar_schema,
            "prompt_projection": "columnar_provenance_due_to_cumulative_byte_budget",
            "source_bytes": len(source_bytes),
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "source_provenance_rows": len(provenance),
            "columns": list(policy.columns),
            "backend_values": backends,
            "status_values": statuses,
            "semantics_values": semantics,
            "result_summary_values": summaries,
            "empty_evidence_ref": policy.empty_ref_instruction,
            "rows": _encoded_rows(
                provenance, backends, statuses, semantics, summaries, dependencies
            ),
            "omitted_rows": 0,
        }],
        "prompt_projection": {
            "max_bytes": maximum_bytes,
            "truncated": True,
            "columnar_provenance_fallback": True,
            "encoded_bytes": 0,
        },
    }
    encoded_size = _converge_size(value)
    return value if value["prompt_projection"]["encoded_bytes"] == encoded_size <= maximum_bytes else None
