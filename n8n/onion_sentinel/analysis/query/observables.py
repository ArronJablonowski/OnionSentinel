"""Bounded promotion of validated observables from query results."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Sequence


TRUSTED_BACKENDS = frozenset({"security_onion", "pcap_zeek"})
PROMOTABLE_STATUSES = frozenset({"ok", "partial"})


@dataclass(frozen=True)
class Result:
    observables: tuple[dict[str, Any], ...]
    source_count: int
    promoted_count: int


def _sources(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        return []
    return [
        item for item in results
        if isinstance(item, dict)
        and item.get("backend") in TRUSTED_BACKENDS
        and item.get("status") in PROMOTABLE_STATUSES
    ]


def promote(
    existing: Any,
    round_results: Any,
    *,
    limit: int,
    validate: Callable[..., Sequence[dict[str, Any]]],
) -> Result:
    """Return a deduplicated bounded observable set from trusted result rows."""
    bounded_limit = max(0, int(limit))
    retained = (
        copy.deepcopy(existing[:bounded_limit])
        if isinstance(existing, list)
        else []
    )
    sources = _sources(round_results)
    candidates = validate(sources, limit=max(0, bounded_limit - len(retained)))
    known = {
        (str(item.get("kind")), str(item.get("value")))
        for item in retained if isinstance(item, dict)
    }
    promoted = 0
    for item in candidates:
        key = (str(item.get("kind")), str(item.get("value")))
        if key in known or len(retained) >= bounded_limit:
            continue
        retained.append(copy.deepcopy(item))
        known.add(key)
        promoted += 1
    return Result(
        observables=tuple(retained),
        source_count=len(sources),
        promoted_count=promoted,
    )
