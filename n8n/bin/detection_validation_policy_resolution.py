"""Exact deployed-rule to detection-playbook resolution."""

from __future__ import annotations

from typing import Any


def _collection_constraint_matches(expected: set[Any], actual: Any) -> bool:
    return not expected or actual in expected


def _text_constraint_matches(expected: str, actual: str) -> bool:
    return not expected or expected == actual


def _identity_conflicted(rule_context: dict[str, Any]) -> bool:
    conflicts = rule_context.get("identity_conflicts")
    return isinstance(conflicts, dict) and any(
        conflicts.get(key) for key in ("sid", "revision")
    )


def _rule_hash(rule_context: dict[str, Any]) -> str:
    parsed_rule = rule_context.get("parsed_rule")
    return (
        str(parsed_rule.get("rule_sha256") or "")
        if isinstance(parsed_rule, dict)
        else ""
    )


def _playbook_matches(
    playbook: dict[str, Any],
    *,
    sid: str,
    revision: Any,
    ruleset: str,
    rule_sha256: str,
) -> bool:
    match = playbook.get("match") if isinstance(playbook.get("match"), dict) else {}
    sids = (
        {str(value) for value in match.get("sids", [])}
        if isinstance(match.get("sids"), list)
        else set()
    )
    revisions = (
        set(match.get("revisions", []))
        if isinstance(match.get("revisions"), list)
        else set()
    )
    expected_ruleset = str(match.get("ruleset") or "").strip().casefold()
    expected_rule_sha256 = str(match.get("rule_sha256") or "")
    return all(
        (
            _collection_constraint_matches(sids, sid),
            _collection_constraint_matches(revisions, revision),
            _text_constraint_matches(expected_ruleset, ruleset),
            _text_constraint_matches(expected_rule_sha256, rule_sha256),
            bool(sids or revisions or expected_ruleset),
        )
    )


def resolve_detection_playbook(
    registry: dict[str, Any],
    rule_context: dict[str, Any],
) -> dict[str, Any] | None:
    sid = str(rule_context.get("sid") or "")
    revision = rule_context.get("revision")
    ruleset = str(rule_context.get("ruleset") or "").strip().casefold()
    if _identity_conflicted(rule_context):
        return None
    rule_sha256 = _rule_hash(rule_context)
    playbooks = registry.get("playbooks")
    for playbook in playbooks if isinstance(playbooks, list) else []:
        if isinstance(playbook, dict) and _playbook_matches(
            playbook,
            sid=sid,
            revision=revision,
            ruleset=ruleset,
            rule_sha256=rule_sha256,
        ):
            return playbook
    return None
