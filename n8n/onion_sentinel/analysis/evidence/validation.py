"""Validation of model citations against collector-owned evidence catalogs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    bounded_reference: Callable[[Any], str]


def _catalog(references: Any) -> dict[str, dict[str, Any]] | None:
    if not isinstance(references, list):
        return None
    return {
        str(item.get("ref")): item
        for item in references
        if isinstance(item, dict) and str(item.get("ref") or "")
    }


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _validate_citations(
    cited: Any, catalog: dict[str, dict[str, Any]], deps: Dependencies,
) -> dict[str, list[str]]:
    result = {
        "valid": [], "invalid": [], "corroborating": [],
        "source_classes": [], "non_corroborating": [],
    }
    values = cited if isinstance(cited, list) else []
    for raw in values[:100]:
        reference = deps.bounded_reference(raw)
        item = catalog.get(reference)
        if item is None:
            _append_unique(result["invalid"], reference)
            continue
        _append_unique(result["valid"], reference)
        if item.get("corroborating") is True:
            _append_unique(result["corroborating"], reference)
            _append_unique(
                result["source_classes"],
                deps.bounded_reference(item.get("source_class")),
            )
        else:
            _append_unique(result["non_corroborating"], reference)
    return result


def _record_invalid_gap(response: dict[str, Any], invalid: list[str]) -> None:
    if not invalid:
        return
    gaps = response.get("evidence_gaps")
    gaps = list(gaps) if isinstance(gaps, list) else []
    gap = (
        f"{len(invalid)} model-supplied evidence reference(s) did not resolve "
        "to the collector-owned evidence catalog."
    )
    if gap not in gaps:
        gaps.append(gap)
    response["evidence_gaps"] = gaps


def apply(
    response: dict[str, Any], prompt_package: dict[str, Any] | None,
    deps: Dependencies,
) -> dict[str, Any]:
    """Remove unverified citations from confidence inputs while retaining audit."""
    if not isinstance(prompt_package, dict):
        return response
    contract = prompt_package.get("evidence_reference_contract")
    if not isinstance(contract, dict):
        return response
    catalog = _catalog(contract.get("references"))
    if catalog is None:
        return response
    result = _validate_citations(response.get("evidence_used"), catalog, deps)
    response["evidence_used"] = result["valid"]
    response["_evidence_reference_validation"] = {
        "schema": "onion-sentinel-evidence-reference-validation-v1",
        "valid_refs": result["valid"],
        "invalid_refs": result["invalid"],
        "corroborating_refs": result["corroborating"],
        "corroborating_source_classes": result["source_classes"],
        "non_corroborating_refs": result["non_corroborating"],
        "catalog_size": len(catalog),
    }
    _record_invalid_gap(response, result["invalid"])
    return response
