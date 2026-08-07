"""Exact whole-package admission for investigation-query follow-up prompts."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
from typing import Any, Callable, Type

from . import prompt_facts


@dataclass(frozen=True)
class Policy:
    maximum_evidence_bytes: int


@dataclass(frozen=True)
class Dependencies:
    projection: Callable[[list[dict[str, Any]], int], dict[str, Any]]
    attach_contract: Callable[[dict[str, Any]], Any]
    synchronize_hosted: Callable[[dict[str, Any]], Any]
    model_safe_copy: Callable[[dict[str, Any], bool], Any]


class Catalog:
    """Memoized deterministic projection states for one admission attempt."""

    def __init__(
        self, base: dict[str, Any], rounds: list[dict[str, Any]], *, hosted: bool,
        dependencies: Dependencies, error_type: Type[Exception],
    ) -> None:
        self.base = base
        self.rounds = rounds
        self.hosted = hosted
        self.dependencies = dependencies
        self.error_type = error_type
        self.cache: dict[int, dict[str, Any] | None] = {}

    def projection_at(self, evidence_bytes: int) -> dict[str, Any] | None:
        if evidence_bytes not in self.cache:
            try:
                self.cache[evidence_bytes] = self.dependencies.projection(
                    self.rounds, evidence_bytes
                )
            except self.error_type:
                self.cache[evidence_bytes] = None
        return self.cache[evidence_bytes]

    @staticmethod
    def signature(projection: dict[str, Any]) -> str:
        signature_value = dict(projection)
        metadata = (
            dict(projection.get("prompt_projection"))
            if isinstance(projection.get("prompt_projection"), dict)
            else {}
        )
        metadata.pop("max_bytes", None)
        metadata.pop("encoded_bytes", None)
        signature_value["prompt_projection"] = metadata
        return hashlib.sha256(prompt_facts.canonical_bytes(signature_value)).hexdigest()

    def complete(self, evidence_bytes: int) -> tuple[dict[str, Any], int] | None:
        projection = self.projection_at(evidence_bytes)
        if projection is None:
            return None
        candidate = dict(self.base)
        candidate["investigation_query_results"] = projection
        self.dependencies.attach_contract(candidate)
        if self.hosted:
            self.dependencies.synchronize_hosted(candidate)
        safe = self.dependencies.model_safe_copy(candidate, self.hosted)
        return candidate, len(prompt_facts.canonical_bytes(safe))

    def first_projection_budget(self, low: int, high: int) -> int | None:
        first = None
        while low <= high:
            midpoint = low + ((high - low) // 2)
            if self.projection_at(midpoint) is None:
                low = midpoint + 1
            else:
                first = midpoint
                high = midpoint - 1
        return first

    def next_transition(
        self, state_start: int, high: int, signature: str,
    ) -> int | None:
        high_projection = self.projection_at(high)
        if high_projection is None:
            raise self.error_type("investigation prompt projection admission did not converge")
        if self.signature(high_projection) == signature:
            return None
        low = state_start + 1
        while low < high:
            midpoint = low + ((high - low) // 2)
            projection = self.projection_at(midpoint)
            if projection is None or self.signature(projection) == signature:
                low = midpoint + 1
            else:
                high = midpoint
        projection = self.projection_at(low)
        if projection is None or self.signature(projection) == signature:
            raise self.error_type(
                "investigation prompt projection transition did not converge"
            )
        return low


def _select_candidate(
    catalog: Catalog, first: int, high: int, maximum_prompt_bytes: int,
) -> tuple[dict[str, Any], int] | None:
    admitted = None
    seen: set[str] = set()
    state_start = first
    while state_start <= high:
        projection = catalog.projection_at(state_start)
        if projection is None:
            raise catalog.error_type(
                "investigation prompt projection admission did not converge"
            )
        signature = catalog.signature(projection)
        if signature in seen:
            raise catalog.error_type(
                "investigation prompt projection states are not monotonic"
            )
        seen.add(signature)
        candidate = catalog.complete(state_start)
        if candidate is not None and candidate[1] <= maximum_prompt_bytes:
            admitted = candidate
        if state_start == high:
            break
        transition = catalog.next_transition(state_start, high, signature)
        if transition is None:
            break
        state_start = transition
    return admitted


def _prepared_candidate(
    prompt_package: dict[str, Any], candidate: dict[str, Any], *, hosted: bool,
    dependencies: Dependencies,
) -> dict[str, Any]:
    prepared = copy.deepcopy(prompt_package)
    prepared.pop("investigation_query_results", None)
    prepared.pop("evidence_reference_contract", None)
    prepared["investigation_query_results"] = candidate["investigation_query_results"]
    prepared["evidence_reference_contract"] = candidate["evidence_reference_contract"]
    if hosted:
        dependencies.synchronize_hosted(prepared)
    return prepared


def admit(
    prompt_package: dict[str, Any], rounds: list[dict[str, Any]], *,
    maximum_prompt_bytes: int, hosted: bool, policy: Policy,
    dependencies: Dependencies, error_type: Type[Exception] = ValueError,
) -> int:
    """Install the richest complete, citation-refreshed projection that fits."""
    if isinstance(maximum_prompt_bytes, bool) or not isinstance(maximum_prompt_bytes, int) or maximum_prompt_bytes <= 0:
        raise error_type("investigation follow-up prompt byte budget is invalid")
    base = dict(prompt_package)
    base.pop("investigation_query_results", None)
    base.pop("evidence_reference_contract", None)
    high = min(policy.maximum_evidence_bytes, maximum_prompt_bytes)
    catalog = Catalog(
        base, rounds, hosted=hosted, dependencies=dependencies, error_type=error_type
    )
    first = catalog.first_projection_budget(1, high)
    if first is None:
        raise error_type(
            "no safe prompt budget remains for complete investigation query evidence "
            "and its refreshed citation contract"
        )
    admitted = _select_candidate(catalog, first, high, maximum_prompt_bytes)
    if admitted is None:
        raise error_type(
            "no safe prompt budget remains for complete investigation query evidence "
            "and its refreshed citation contract"
        )
    candidate, measured_size = admitted
    prepared = _prepared_candidate(
        prompt_package, candidate, hosted=hosted, dependencies=dependencies
    )
    safe = dependencies.model_safe_copy(prepared, hosted)
    final_size = len(prompt_facts.canonical_bytes(safe))
    if final_size > maximum_prompt_bytes:
        raise error_type("investigation follow-up prompt exceeds max_prompt_bytes")
    if final_size != measured_size:
        raise error_type(
            "investigation follow-up prompt changed after admission "
            f"(measured={measured_size}, finalized={final_size})"
        )
    prompt_package.pop("investigation_query_results", None)
    prompt_package.pop("evidence_reference_contract", None)
    prompt_package["investigation_query_results"] = prepared["investigation_query_results"]
    prompt_package["evidence_reference_contract"] = prepared["evidence_reference_contract"]
    return final_size
