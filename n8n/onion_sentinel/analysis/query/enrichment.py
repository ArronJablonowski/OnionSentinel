"""Evidence-bound normalization for public enrichment pivots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Type

from . import primitives


@dataclass(frozen=True)
class Policy:
    indicator_types: frozenset[str] = frozenset(
        {"ip", "domain", "url", "hash", "cve"}
    )


def _canonical(kind: Any, value: Any) -> tuple[str, str]:
    indicator_type = str(kind or "").lower()
    indicator = str(value or "").strip()
    if indicator_type == "domain":
        indicator = indicator.rstrip(".")
    return indicator_type, indicator.lower()


def _network_observables(context: dict[str, Any]) -> set[tuple[str, str]]:
    permitted: set[tuple[str, str]] = set()
    value = context.get("permitted_observables")
    if not isinstance(value, dict):
        return permitted
    for source_kind, indicator_type in (("ips", "ip"), ("domains", "domain")):
        values = value.get(source_kind, [])
        if isinstance(values, list):
            permitted.update(
                _canonical(indicator_type, item) for item in values
                if str(item).strip()
            )
    return permitted


def _initial_indicators(context: dict[str, Any]) -> set[tuple[str, str]]:
    permitted: set[tuple[str, str]] = set()
    value = context.get("permitted_enrichment_indicators")
    if not isinstance(value, dict):
        return permitted
    for kind, values in value.items():
        if isinstance(values, list):
            permitted.update(
                _canonical(kind, item) for item in values if str(item).strip()
            )
    return permitted


def _discovered_indicators(context: dict[str, Any]) -> set[tuple[str, str]]:
    permitted: set[tuple[str, str]] = set()
    values = context.get("discovered_observables", [])
    if not isinstance(values, list):
        return permitted
    kind_map = {"ips": "ip", "domains": "domain"}
    for item in values:
        if not isinstance(item, dict):
            continue
        indicator_type = kind_map.get(str(item.get("kind") or ""))
        if indicator_type and str(item.get("value") or "").strip():
            permitted.add(_canonical(indicator_type, item.get("value")))
    return permitted


def permitted_indicators(context: Any) -> set[tuple[str, str]]:
    """Return the exact indicator identities authorized by trusted evidence."""
    if not isinstance(context, dict):
        return set()
    return (
        _network_observables(context)
        | _initial_indicators(context)
        | _discovered_indicators(context)
    )


def normalize(
    parameters: dict[str, Any], *, authorization_context: Any,
    policy: Policy = Policy(), error_type: Type[Exception] = ValueError,
) -> dict[str, str]:
    """Admit one exact public-enrichment indicator already present in evidence."""
    indicator_type = primitives.text(parameters.get("indicator_type"), 16).lower()
    indicator = primitives.text(parameters.get("indicator"), 2048).strip()
    if indicator_type not in policy.indicator_types:
        raise error_type("unsupported enrichment indicator type")
    if not indicator:
        raise error_type("enrichment request requires one exact indicator")
    normalized = indicator.rstrip(".") if indicator_type == "domain" else indicator
    if _canonical(indicator_type, normalized) not in permitted_indicators(
        authorization_context
    ):
        raise error_type(
            "enrichment indicator is not bound to original or "
            "provenance-validated evidence"
        )
    return {"indicator_type": indicator_type, "indicator": normalized}
