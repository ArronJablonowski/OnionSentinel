"""Metadata-only change ledger for revisioned CTI workspace edits."""
from __future__ import annotations

import hashlib
import json

from cti_program_contract import MAX_AUDIT_HISTORY


COLLECTIONS = ("sources", "technologies", "requirements", "intelligence")


def content_digest(program: dict[str, object]) -> str:
    payload = {name: program.get(name, []) for name in COLLECTIONS}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _item_digest(item: dict[str, object]) -> str:
    encoded = json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _index(program: dict[str, object], collection: str) -> dict[str, str]:
    values = program.get(collection)
    if not isinstance(values, list):
        return {}
    return {
        str(item["id"]): _item_digest(item)
        for item in values
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def change_summary(
    before: dict[str, object], after: dict[str, object]
) -> list[str]:
    changes: list[str] = []
    for collection in COLLECTIONS:
        previous = _index(before, collection)
        current = _index(after, collection)
        for identifier in sorted(previous.keys() - current.keys()):
            changes.append(f"{collection}:{identifier}:removed")
        for identifier in sorted(current.keys() - previous.keys()):
            changes.append(f"{collection}:{identifier}:added")
        for identifier in sorted(previous.keys() & current.keys()):
            if previous[identifier] != current[identifier]:
                changes.append(f"{collection}:{identifier}:updated")
    return changes


def append_audit_event(
    before: dict[str, object],
    after: dict[str, object],
    *,
    revision: int,
    changed_at: str,
) -> list[dict[str, object]]:
    history = list(before.get("audit_history") or [])
    history.append(
        {
            "revision": revision,
            "event": "workspace-updated",
            "changed_at": changed_at,
            "changes": change_summary(before, after),
            "before_digest": content_digest(before),
            "after_digest": content_digest(after),
        }
    )
    return history[-MAX_AUDIT_HISTORY:]


def _collection(program: dict[str, object], name: str) -> list[dict[str, object]]:
    values = program.get(name)
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, dict)]


def program_audit_metrics(
    program: dict[str, object], freshness: dict[str, object]
) -> dict[str, int]:
    sources = _collection(program, "sources")
    technologies = _collection(program, "technologies")
    requirements = _collection(program, "requirements")
    intelligence = _collection(program, "intelligence")
    audit_history = _collection(program, "audit_history")
    return {
        "source_count": len(sources),
        "enabled_source_count": sum(item.get("enabled") is True for item in sources),
        "technology_count": len(technologies),
        "enabled_technology_count": sum(
            item.get("enabled") is True for item in technologies
        ),
        "requirement_count": len(requirements),
        "active_requirement_count": sum(
            item.get("active") is True for item in requirements
        ),
        "intelligence_count": len(intelligence),
        "stale_intelligence_count": sum(
            freshness.get(str(item.get("id") or "")) == "stale"
            for item in intelligence
        ),
        "audit_event_count": len(audit_history),
    }


__all__ = (
    "COLLECTIONS",
    "append_audit_event",
    "change_summary",
    "content_digest",
    "program_audit_metrics",
)
