"""Deterministic correlation assessment normalization and episode identity."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def _related_group(item: Any) -> dict[str, str] | None:
    if isinstance(item, str):
        group_id, reason = item, ""
    elif isinstance(item, dict):
        group_id, reason = item.get("group_id"), item.get("reason")
    else:
        return None
    normalized_id = str(group_id or "").strip().lower()[:64]
    if not normalized_id:
        return None
    return {
        "group_id": normalized_id,
        "reason": str(reason or "")[:1000],
    }


def _related_groups(value: Any, limit: int) -> list[dict[str, str]]:
    candidates: Iterable[Any] = value[:limit] if isinstance(value, list) else ()
    return [group for item in candidates if (group := _related_group(item))]


def _episode_id(group_ids: list[str]) -> str:
    if not group_ids:
        return ""
    encoded = json.dumps(
        group_ids,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "episode-" + hashlib.sha256(encoded).hexdigest()[:20]


def normalize(
    value: Any,
    *,
    confidence_values: frozenset[str],
    group_limit: int = 20,
    text_limit: int = 4000,
) -> dict[str, Any]:
    """Normalize untrusted model correlation output into a bounded contract."""
    assessment = value if isinstance(value, dict) else {}
    related_groups = _related_groups(assessment.get("related_groups"), group_limit)
    group_ids = sorted({item["group_id"] for item in related_groups})
    confidence = str(assessment.get("confidence") or "low").lower()
    if confidence not in confidence_values:
        confidence = "low"
    return {
        "correlation_found": bool(assessment.get("correlation_found"))
        and bool(related_groups),
        "confidence": confidence,
        "episode_id": _episode_id(group_ids),
        "episode_basis": [f"related_group:{group_id}" for group_id in group_ids],
        "related_groups": related_groups,
        "shared_evidence": _string_list(
            assessment.get("shared_evidence")
        )[:group_limit],
        "contradicting_evidence": _string_list(
            assessment.get("contradicting_evidence")
        )[:group_limit],
        "attack_chain_hypothesis": str(
            assessment.get("attack_chain_hypothesis") or ""
        )[:text_limit],
        "recommended_pivots": _string_list(
            assessment.get("recommended_pivots")
        )[:group_limit],
    }
