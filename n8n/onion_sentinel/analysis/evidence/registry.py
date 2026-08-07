"""Bounded collector-owned evidence reference registry."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    bounded_reference: Callable[[Any], str]
    source_class: Callable[[Any], str]
    canonical_count: Callable[[Any], int | None]


@dataclass
class Registry:
    maximum_references: int
    deps: Dependencies
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(
        self,
        reference: Any,
        *,
        source: str,
        corroborating: bool = True,
        status: Any = "",
        returned: Any = None,
        source_class: Any = "",
        evidence_digest: Any = "",
        require_valid_count: bool = False,
    ) -> None:
        ref = self.deps.bounded_reference(reference)
        if not ref or len(self.entries) >= self.maximum_references:
            return
        returned_count = self.deps.canonical_count(returned)
        count_invalid = returned_count is None and (
            require_valid_count or returned not in (None, "")
        )
        if count_invalid:
            corroborating = False
            status = "invalid_result_count"
        if returned_count == 0:
            corroborating = False
        candidate = self._candidate(
            ref, source, source_class, corroborating, status,
            returned_count, evidence_digest,
        )
        current = self.entries.get(ref)
        if current is None or (
            candidate["corroborating"] and not current["corroborating"]
        ):
            self.entries[ref] = candidate

    def _candidate(
        self, ref: str, source: Any, source_class: Any,
        corroborating: bool, status: Any, returned: int | None,
        evidence_digest: Any,
    ) -> dict[str, Any]:
        digest = str(evidence_digest or "")
        return {
            "ref": ref,
            "source": self.deps.bounded_reference(source)[:80],
            "source_class": self.deps.source_class(source_class or source)[:80],
            "corroborating": bool(corroborating),
            "status": self.deps.bounded_reference(status)[:40],
            "returned": returned,
            "evidence_digest": (
                self.deps.bounded_reference(evidence_digest)[:64]
                if re.fullmatch(r"[a-fA-F0-9]{64}", digest) else ""
            ),
        }

    def contract(self) -> dict[str, Any]:
        return {
            "schema": "onion-sentinel-evidence-reference-contract-v1",
            "instruction": (
                "Every evidence_used item must exactly equal one listed ref. "
                "Zero-row or non-ok query references may document absence or "
                "collection limits but are not positive corroboration."
            ),
            "references": sorted(
                self.entries.values(), key=lambda item: item["ref"]
            ),
        }
