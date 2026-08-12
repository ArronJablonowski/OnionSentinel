"""Bounded counters, entropy, and marker policy for detection validation."""

from __future__ import annotations

import collections
import math
from typing import Any

from detection_validation_rule import MAX_COUNTER_VALUES, MAX_MARKERS


def _bounded_counter(counter: collections.Counter[int]) -> list[dict[str, int]]:
    return [
        {"value": int(value), "count": int(count)}
        for value, count in counter.most_common(MAX_COUNTER_VALUES)
    ]


def _bounded_text_counter(counter: collections.Counter[str]) -> list[dict[str, Any]]:
    return [
        {"value": str(value)[:80], "count": int(count)}
        for value, count in counter.most_common(MAX_COUNTER_VALUES)
    ]


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = collections.Counter(payload)
    length = len(payload)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _deployed_marker_specs(rule_context: dict[str, Any]) -> list[dict[str, Any]]:
    parsed_rule = rule_context.get("parsed_rule")
    if not isinstance(parsed_rule, dict):
        return []
    contents = parsed_rule.get("contents")
    specs: list[dict[str, Any]] = []
    for item in contents if isinstance(contents, list) else []:
        if not isinstance(item, dict) or not str(item.get("hex") or ""):
            continue
        specs.append(
            {
                "id": str(item.get("id") or f"deployed-content-{len(specs) + 1}")[:100],
                "hex": str(item.get("hex") or "")[:512],
                "modifiers": (
                    dict(item.get("modifiers") or {})
                    if isinstance(item.get("modifiers"), dict)
                    else {}
                ),
                "buffer": str(item.get("buffer") or "")[:80],
                "negated": bool(item.get("negated")),
                "source": "deployed_rule",
            }
        )
    return specs


def _playbook_marker_specs(
    rule_context: dict[str, Any],
    playbook: dict[str, Any] | None,
    *,
    start: int,
) -> list[dict[str, Any]]:
    if not isinstance(playbook, dict):
        return []
    values = playbook.get("marker_predicates")
    specs: list[dict[str, Any]] = []
    for item in values if isinstance(values, list) else []:
        if not isinstance(item, dict) or not str(item.get("hex") or ""):
            continue
        applies = (
            {str(value) for value in item.get("applies_to_sids", [])}
            if isinstance(item.get("applies_to_sids"), list)
            else set()
        )
        if applies and str(rule_context.get("sid") or "") not in applies:
            continue
        specs.append(
            {
                "id": str(
                    item.get("id") or f"playbook-marker-{start + len(specs) + 1}"
                )[:100],
                "hex": str(item.get("hex") or "")[:512],
                "expected_offset": item.get("expected_offset"),
                "modifiers": {},
                "negated": False,
                "source": "playbook",
            }
        )
    return specs


def marker_specs(
    rule_context: dict[str, Any],
    playbook: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    specs = _deployed_marker_specs(rule_context)
    specs.extend(_playbook_marker_specs(rule_context, playbook, start=len(specs)))
    unique: list[dict[str, Any]] = []
    seen = set()
    for item in specs:
        key = (item["id"], item["hex"].lower())
        if key not in seen and len(unique) < MAX_MARKERS:
            seen.add(key)
            unique.append(item)
    return unique
