"""Selected-event and grouped-history disposition normalization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    disposition_values: frozenset[str]
    handling_values: frozenset[str]
    schema: str = "onion-sentinel-scope-disposition-v1"
    maximum_evidence_items: int = 20
    maximum_evidence_item_length: int = 1000


@dataclass(frozen=True)
class Dependencies:
    bounded_text_list: Callable[[Any, int, int], list[str]]


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _observation_count(prompt_package: dict[str, Any] | None) -> int:
    grouped = (
        prompt_package.get("grouped_alert_context")
        if isinstance(prompt_package, dict)
        else None
    )
    grouped = _object(grouped)
    try:
        return max(1, int(grouped.get("total_observations") or 1))
    except (TypeError, ValueError, OverflowError):
        return 1


def _vocabulary(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def _group_values(
    response: dict[str, Any],
    raw_group: dict[str, Any],
    observation_count: int,
    policy: Policy,
) -> tuple[str, str, list[str]]:
    disposition = _vocabulary(raw_group.get("activity_disposition"))
    handling = _vocabulary(raw_group.get("handling"))
    invalid: list[str] = []
    if disposition not in policy.disposition_values:
        if disposition:
            invalid.append(
                "scope_dispositions.group_history.activity_disposition"
            )
        disposition = (
            str(response.get("activity_disposition") or "unknown")
            if observation_count == 1 else "unknown"
        )
    if handling not in policy.handling_values:
        if handling:
            invalid.append("scope_dispositions.group_history.handling")
        handling = (
            str(response.get("handling") or "investigate")
            if observation_count == 1 else "monitor"
        )
    return disposition, handling, invalid


def _evidence_basis(
    value: Any,
    policy: Policy,
    dependencies: Dependencies,
) -> list[str]:
    return dependencies.bounded_text_list(
        value,
        policy.maximum_evidence_items,
        policy.maximum_evidence_item_length,
    )


def normalize(
    response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Keep the selected event distinct from broader grouped history."""
    raw = _object(response.get("scope_dispositions"))
    raw_group = _object(raw.get("group_history"))
    selected = _object(raw.get("selected_event"))
    observation_count = _observation_count(prompt_package)
    disposition, handling, invalid = _group_values(
        response, raw_group, observation_count, policy
    )
    supplied_group = bool(raw_group)
    response["scope_dispositions"] = {
        "selected_event": {
            "activity_disposition": str(
                response.get("activity_disposition") or "unknown"
            ),
            "handling": str(response.get("handling") or "investigate"),
            "evidence_basis": _evidence_basis(
                selected.get("evidence_basis"), policy, dependencies
            ),
        },
        "group_history": {
            "activity_disposition": disposition,
            "handling": handling,
            "evidence_basis": _evidence_basis(
                raw_group.get("evidence_basis"), policy, dependencies
            ),
        },
    }
    response["_scope_disposition_validation"] = {
        "schema": policy.schema,
        "selected_event_is_top_level_verdict": True,
        "group_observation_count": observation_count,
        "group_history_model_supplied": supplied_group,
        "group_history_defaulted_to_unresolved": bool(
            observation_count > 1 and not supplied_group
        ),
        "invalid_fields": invalid,
    }
    return response
