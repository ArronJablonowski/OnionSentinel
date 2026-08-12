"""Deterministic numeric detection-predicate evaluation."""

from __future__ import annotations

from typing import Any


_FEATURE_KEYS = {
    "icmp.type": "icmp_types",
    "icmp.code": "icmp_codes",
    "icmp.identifier": "icmp_identifiers",
    "icmp.sequence": "icmp_sequences",
    "icmp.payload_length": "payload_lengths",
    "frame.length": "frame_lengths",
}


def _observed_values(features: dict[str, Any], field: str) -> list[int]:
    key = _FEATURE_KEYS.get(field)
    if not key:
        return []
    return [
        int(item["value"])
        for item in features.get(key, [])
        if isinstance(item, dict) and isinstance(item.get("value"), int)
    ]


def _normalized_expected(predicate: dict[str, Any]) -> list[int] | list[str]:
    expected = predicate.get("expected", predicate.get("value"))
    expected_values = expected if isinstance(expected, list) else [expected]
    try:
        return [int(value) for value in expected_values]
    except (TypeError, ValueError):
        return [str(value)[:80] for value in expected_values]


def _predicate_status(
    operator: str,
    observed: list[int],
    expected: list[int] | list[str],
) -> str:
    if operator not in {"equals", "contains"}:
        return "unknown"
    if not observed or not expected or not all(isinstance(value, int) for value in expected):
        return "unknown"
    if operator == "equals":
        return "matched" if set(observed).issubset(set(expected)) else "mismatched"
    return "matched" if set(expected).intersection(observed) else "mismatched"


def _evaluate_numeric_predicate(
    predicate: dict[str, Any],
    features: dict[str, Any],
    *,
    source: str,
) -> dict[str, Any]:
    field = str(predicate.get("field") or "")
    observed = _observed_values(features, field)
    operator = str(predicate.get("operator") or "equals")
    normalized_expected = _normalized_expected(predicate)
    return {
        "id": str(predicate.get("id") or field)[:100],
        "field": field,
        "operator": operator,
        "expected": normalized_expected,
        "observed": observed,
        "status": _predicate_status(operator, observed, normalized_expected),
        "required": bool(predicate.get("required")),
        "source": source,
        "reason": str(predicate.get("reason") or "")[:1000],
    }
