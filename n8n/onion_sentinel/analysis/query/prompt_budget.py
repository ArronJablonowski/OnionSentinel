"""Exact cumulative byte-budget orchestration for query prompt evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Callable, Type

from . import prompt_facts


@dataclass(frozen=True)
class Policy:
    maximum_rows: int
    result_schema: str


@dataclass(frozen=True)
class Dependencies:
    project_rows: Callable[[Any, dict[str, int | bool]], Any]
    compact_audit: Callable[[Any], dict[str, Any]]
    columnar_payload: Callable[[list[dict[str, Any]], int], dict[str, Any] | None]


def _state() -> dict[str, int | bool]:
    return {
        "rows": 0,
        "truncated": False,
        "trusted_query_audits_compacted": 0,
        "evidence_bodies_omitted": 0,
        "round_metadata_omitted": 0,
    }


def _envelope(
    projected: list[Any], state: dict[str, int | bool], *, policy: Policy,
    maximum_bytes: int, encoded_bytes: int | None = None,
) -> dict[str, Any]:
    projection = {
        "max_bytes": maximum_bytes,
        "max_rows": policy.maximum_rows,
        "rows_included": int(state["rows"]),
        "truncated": bool(state["truncated"]),
        "trusted_query_audits_compacted": int(state["trusted_query_audits_compacted"]),
        "evidence_bodies_omitted": int(state["evidence_bodies_omitted"]),
        "round_metadata_omitted": int(state["round_metadata_omitted"]),
    }
    if encoded_bytes is not None:
        projection["encoded_bytes"] = encoded_bytes
    return {
        "schema": policy.result_schema,
        "rounds": projected,
        "prompt_projection": projection,
    }


def _encoded_size(value: Any) -> int:
    return len(prompt_facts.canonical_bytes(value))


def _within_budget(
    projected: list[Any], state: dict[str, int | bool], *, policy: Policy,
    maximum_bytes: int,
) -> bool:
    reservation = (10 ** len(str(maximum_bytes))) - 1
    return _encoded_size(
        _envelope(
            projected, state, policy=policy, maximum_bytes=maximum_bytes,
            encoded_bytes=reservation,
        )
    ) <= maximum_bytes


def _audit_candidates(
    projected: list[Any], dependencies: Dependencies,
) -> list[tuple[int, dict[str, Any], int, dict[str, Any]]]:
    candidates = []
    for round_item in projected:
        if not isinstance(round_item, dict):
            continue
        for result in round_item.get("results") or []:
            if not isinstance(result, dict):
                continue
            trusted = result.get("trusted_query_audit")
            if not isinstance(trusted, list):
                continue
            for index, audit in enumerate(trusted):
                if isinstance(audit, dict) and audit.get("prompt_projection") == "compacted_due_to_cumulative_byte_budget":
                    continue
                compact = dependencies.compact_audit(audit)
                savings = _encoded_size(audit) - _encoded_size(compact)
                if savings > 0:
                    candidates.append((savings, result, index, compact))
    return candidates


def _compact_audits(
    projected: list[Any], state: dict[str, int | bool], *, policy: Policy,
    maximum_bytes: int, dependencies: Dependencies,
) -> None:
    while not _within_budget(
        projected, state, policy=policy, maximum_bytes=maximum_bytes
    ):
        candidates = _audit_candidates(projected, dependencies)
        if not candidates:
            return
        _, result, index, compact = max(candidates, key=lambda item: item[0])
        result["trusted_query_audit"][index] = compact
        state["trusted_query_audits_compacted"] = int(
            state["trusted_query_audits_compacted"]
        ) + 1
        state["truncated"] = True


def _evidence_candidates(projected: list[Any]) -> list[tuple[int, dict[str, Any]]]:
    candidates = []
    for round_item in projected:
        if not isinstance(round_item, dict):
            continue
        for result in round_item.get("results") or []:
            if not isinstance(result, dict) or "evidence" not in result:
                continue
            evidence = result["evidence"]
            if isinstance(evidence, dict) and evidence.get("prompt_projection") == "omitted_due_to_cumulative_byte_budget":
                continue
            candidates.append((_encoded_size(evidence), result))
    return candidates


def _evidence_summary(evidence: Any) -> dict[str, Any]:
    encoded = prompt_facts.canonical_bytes(evidence)
    summary = {
        "prompt_projection": "omitted_due_to_cumulative_byte_budget",
        "evidence_bytes": len(encoded),
        "evidence_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    if isinstance(evidence, dict):
        for key in ("query_digest", "result_digest", "evidence_ref"):
            if key in evidence:
                summary[key] = evidence[key]
    return summary


def _omit_evidence(
    projected: list[Any], state: dict[str, int | bool], *, policy: Policy,
    maximum_bytes: int,
) -> None:
    while not _within_budget(
        projected, state, policy=policy, maximum_bytes=maximum_bytes
    ):
        candidates = _evidence_candidates(projected)
        if not candidates:
            return
        _, result = max(candidates, key=lambda item: item[0])
        result["evidence"] = _evidence_summary(result.pop("evidence"))
        state["evidence_bodies_omitted"] = int(state["evidence_bodies_omitted"]) + 1
        state["truncated"] = True


def _metadata_summary(value: Any) -> dict[str, Any]:
    encoded = prompt_facts.canonical_bytes(value)
    return {
        "prompt_projection": "omitted_due_to_cumulative_byte_budget",
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _omit_metadata(
    projected: list[Any], state: dict[str, int | bool], *, policy: Policy,
    maximum_bytes: int,
) -> None:
    if _within_budget(projected, state, policy=policy, maximum_bytes=maximum_bytes):
        return
    for round_item in projected:
        if not isinstance(round_item, dict):
            continue
        for key in ("requests", "audit"):
            original = round_item.get(key)
            if original:
                round_item[key] = _metadata_summary(original)
                state["round_metadata_omitted"] = int(state["round_metadata_omitted"]) + 1
                state["truncated"] = True
                if _within_budget(
                    projected, state, policy=policy, maximum_bytes=maximum_bytes
                ):
                    return


def _finalize(
    projected: list[Any], state: dict[str, int | bool], *, policy: Policy,
    maximum_bytes: int,
) -> dict[str, Any]:
    payload = _envelope(
        projected, state, policy=policy, maximum_bytes=maximum_bytes, encoded_bytes=0
    )
    for _ in range(8):
        actual = _encoded_size(payload)
        if payload["prompt_projection"]["encoded_bytes"] == actual:
            break
        payload["prompt_projection"]["encoded_bytes"] = actual
    return payload


def payload(
    rounds: list[dict[str, Any]], *, maximum_bytes: int, policy: Policy,
    dependencies: Dependencies, error_type: Type[Exception] = ValueError,
) -> dict[str, Any]:
    """Project all query rounds below cumulative row and byte caps."""
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
        raise error_type("investigation query prompt byte budget must be a positive integer")
    state = _state()
    projected = [dependencies.project_rows(item, state) for item in rounds]
    _compact_audits(
        projected, state, policy=policy, maximum_bytes=maximum_bytes,
        dependencies=dependencies,
    )
    _omit_evidence(projected, state, policy=policy, maximum_bytes=maximum_bytes)
    _omit_metadata(projected, state, policy=policy, maximum_bytes=maximum_bytes)
    result = _finalize(
        projected, state, policy=policy, maximum_bytes=maximum_bytes
    )
    final_size = _encoded_size(result)
    if result["prompt_projection"]["encoded_bytes"] == final_size <= maximum_bytes:
        return result
    fallback = dependencies.columnar_payload(rounds, maximum_bytes)
    if fallback is not None:
        return fallback
    raise error_type(
        "investigation query prompt projection exceeds its cumulative byte budget"
    )
