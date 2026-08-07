"""Trusted observable-catalog intersection for query repair."""

from __future__ import annotations

from typing import Any

from . import primitives


OBSERVABLE_KINDS = ("ips", "domains", "hosts", "users")


def _raw_values(value: Any) -> set[str]:
    found: set[str] = set()

    def visit(item: Any, depth: int = 0) -> None:
        if depth > 4 or len(found) > 32:
            return
        if isinstance(item, str):
            text = primitives.text(item, 255)
            if text:
                found.add(text)
            return
        children = item[:32] if isinstance(item, list) else (
            list(item.values())[:32] if isinstance(item, dict) else []
        )
        for child in children:
            visit(child, depth + 1)

    visit(value)
    return found


def _trusted_catalog(
    permitted: dict[str, Any],
) -> dict[str, list[tuple[str, str]]]:
    catalog: dict[str, list[tuple[str, str]]] = {}
    for kind in OBSERVABLE_KINDS:
        values = permitted.get(kind)
        for raw_value in values[:100] if isinstance(values, list) else []:
            value = primitives.text(raw_value, 255)
            if not value:
                continue
            comparison = value.lower().rstrip(".") if kind == "domains" else value
            catalog.setdefault(comparison, []).append((kind, value))
    return catalog


def recover(
    value: Any, authorization_context: Any,
) -> dict[str, list[str]] | None:
    """Recover only exact, unambiguous values in the trusted catalog."""
    if not isinstance(authorization_context, dict):
        return None
    permitted = authorization_context.get("permitted_observables")
    if not isinstance(permitted, dict):
        return None
    raw_values = _raw_values(value)
    if not raw_values or len(raw_values) > 32:
        return None
    catalog = _trusted_catalog(permitted)
    recovered = {kind: [] for kind in OBSERVABLE_KINDS}
    for raw_value in sorted(raw_values):
        candidates = catalog.get(raw_value, []) or catalog.get(
            raw_value.lower().rstrip("."), []
        )
        unique = sorted(set(candidates))
        if len(unique) == 1:
            kind, trusted_value = unique[0]
            recovered[kind].append(trusted_value)
    for kind in recovered:
        recovered[kind] = sorted(set(recovered[kind]))
    total = sum(len(values) for values in recovered.values())
    return recovered if 1 <= total <= 8 else None
