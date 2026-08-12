"""Exact alert and deployed-rule identity context projection."""

from __future__ import annotations

from typing import Any

from detection_validation_rule_contract import _json_object, _nested, re
from detection_validation_rule_parser import parse_suricata_rule


def _numeric_suricata_sid(value: object) -> str:
    if isinstance(value, bool) or value in (None, ""):
        return ""
    text = str(value).strip()
    if not re.fullmatch(r"[0-9]{1,20}", text):
        return ""
    number = int(text)
    if number < 1 or number > 0xFFFFFFFF:
        return ""
    return str(number)


def _rule_source(
    alert: dict[str, Any],
    raw: dict[str, Any],
    message: dict[str, Any],
) -> str:
    return str(
        _nested(raw, "rule.rule")
        or _nested(message, "alert.rule")
        or _nested(alert, "security_onion.raw_event.rule.rule")
        or ""
    )[:16000]


def _sid_values(
    alert: dict[str, Any],
    raw: dict[str, Any],
    message: dict[str, Any],
    parsed: dict[str, Any],
    database_rule_id: object,
) -> list[object]:
    return [
        _nested(message, "alert.signature_id"),
        _nested(raw, "alert.signature_id"),
        _nested(alert, "alert.signature_id"),
        alert.get("signature_id"),
        parsed.get("sid"),
        database_rule_id,
        alert.get("rule_id"),
        _nested(raw, "rule.id"),
    ]


def _normalized_sid_values(values: list[object]) -> list[str]:
    return [candidate for candidate in map(_numeric_suricata_sid, values) if candidate]


def _revision_values(
    raw: dict[str, Any],
    message: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[object, object, object]:
    return (
        _nested(raw, "rule.rev"),
        _nested(message, "alert.rev"),
        parsed.get("revision"),
    )


def _revision_candidates(values: tuple[object, ...]) -> set[int]:
    candidates: set[int] = set()
    for value in values:
        try:
            if value not in (None, ""):
                candidates.add(int(value))
        except (TypeError, ValueError):
            continue
    return candidates


def _selected_revision(values: tuple[object, ...]) -> int | None:
    revision_value = next((value for value in values if value), None)
    try:
        return int(revision_value) if revision_value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _bounded_text(*values: object, limit: int) -> str:
    return str(next((value for value in values if value), ""))[:limit]


def _record_rule_id(
    alert: dict[str, Any], raw: dict[str, Any], database_rule_id: object
) -> str:
    return str(
        database_rule_id or alert.get("rule_id") or _nested(raw, "rule.id") or ""
    ).strip()[:200]


def extract_rule_context(
    alert_payload: object,
    raw_event_payload: object = None,
    database_rule_id: object = None,
) -> dict[str, Any]:
    alert = _json_object(alert_payload)
    raw = _json_object(raw_event_payload)
    if not raw:
        raw = _json_object(_nested(alert, "security_onion.raw_event"))
    message = _json_object(raw.get("message"))
    raw_rule = _rule_source(alert, raw, message)
    parsed = parse_suricata_rule(raw_rule)
    sid_values = _sid_values(alert, raw, message, parsed, database_rule_id)
    normalized_sids = _normalized_sid_values(sid_values)
    revisions = _revision_values(raw, message, parsed)
    revision_candidates = _revision_candidates(revisions)
    return {
        "sid": normalized_sids[0] if normalized_sids else "",
        "record_rule_id": _record_rule_id(alert, raw, database_rule_id),
        "revision": _selected_revision(revisions),
        "name": _bounded_text(
            alert.get("rule_name"),
            _nested(raw, "rule.name"),
            _nested(message, "alert.signature"),
            limit=500,
        ),
        "ruleset": _bounded_text(
            alert.get("rule_ruleset"),
            _nested(raw, "rule.ruleset"),
            limit=200,
        ),
        "category": _bounded_text(
            alert.get("rule_category"),
            _nested(message, "alert.category"),
            limit=300,
        ),
        "reference": str(alert.get("rule_reference") or "")[:1000],
        "raw_rule": raw_rule,
        "parsed_rule": parsed,
        "identity_conflicts": {
            "sid": sorted(set(normalized_sids)) if len(set(normalized_sids)) > 1 else [],
            "revision": (
                sorted(revision_candidates) if len(revision_candidates) > 1 else []
            ),
        },
    }
