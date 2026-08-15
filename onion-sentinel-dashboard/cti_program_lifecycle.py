"""Validation and reference integrity for durable CTI lifecycle records."""
from __future__ import annotations

import datetime as dt
import uuid
from urllib.parse import urlsplit

from cti_program_contract import *  # noqa: F403


def _life_text(value: object, field: str, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise CTIProgramError(f"{field} must be text.")  # noqa: F405
    normalized = value.strip()
    if required and not normalized:
        raise CTIProgramError(f"{field} is required.")  # noqa: F405
    if len(normalized) > limit:
        raise CTIProgramError(f"{field} exceeds {limit} characters.")  # noqa: F405
    if any(ord(char) < 32 and char not in "\n\t" for char in normalized):
        raise CTIProgramError(  # noqa: F405
            f"{field} contains an unsupported control character."
        )
    return normalized


def _life_enum(value: object, field: str, allowed: frozenset[str]) -> str:
    normalized = _life_text(value, field, 64, required=True)
    if normalized not in allowed:
        raise CTIProgramError(f"{field} has an unsupported value.")  # noqa: F405
    return normalized


def _life_identifier(value: object, field: str, *, generate: bool = False) -> str:
    normalized = _life_text(value, field, 64)
    if not normalized and generate:
        normalized = uuid.uuid4().hex
    if not normalized:
        raise CTIProgramError(f"{field} is required.")  # noqa: F405
    if not IDENTIFIER_RE.fullmatch(normalized):  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"{field} must contain only lowercase letters, digits, hyphens, or underscores."
        )
    return normalized


def _life_list(
    value: object,
    field: str,
    *,
    maximum: int = 32,
    item_limit: int = 240,
    identifiers: bool = False,
) -> list[str]:
    if not isinstance(value, list):
        raise CTIProgramError(f"{field} must be a list.")  # noqa: F405
    if len(value) > maximum:
        raise CTIProgramError(f"{field} exceeds {maximum} entries.")  # noqa: F405
    result: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(value):
        item_field = f"{field}[{index}]"
        normalized = (
            _life_identifier(entry, item_field)
            if identifiers
            else _life_text(entry, item_field, item_limit, required=True)
        )
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            result.append(normalized)
    return result


def _life_date(value: object, field: str) -> str:
    normalized = _life_text(value, field, 10)
    if not normalized:
        return ""
    if not DATE_RE.fullmatch(normalized):  # noqa: F405
        raise CTIProgramError(f"{field} must use YYYY-MM-DD.")  # noqa: F405
    try:
        dt.date.fromisoformat(normalized)
    except ValueError as exc:
        raise CTIProgramError(f"{field} is not a valid date.") from exc  # noqa: F405
    return normalized


def _timestamp(value: object, field: str, *, required: bool = False) -> str:
    normalized = _life_text(value, field, 40, required=required)
    if not normalized:
        return ""
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise CTIProgramError(f"{field} must be an ISO 8601 timestamp.") from exc  # noqa: F405
    if parsed.tzinfo is None:
        raise CTIProgramError(f"{field} must include a timezone.")  # noqa: F405
    return (
        parsed.astimezone(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _evidence_reference(value: object, field: str) -> str:
    normalized = _life_text(value, field, 500, required=True)
    parsed = urlsplit(normalized)
    if parsed.scheme in {"http", "https"}:
        if (
            not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise CTIProgramError(  # noqa: F405
                f"{field} must not contain credentials, query parameters, or fragments."
            )
        return normalized
    if not REFERENCE_RE.fullmatch(normalized):  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"{field} must be a bounded URL or internal evidence reference."
        )
    return normalized


def _parsed_timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value[:-1] + "+00:00")


def _require_timestamp_order(
    *,
    collected_at: str,
    analyzed_at: str,
    published_at: str,
    expires_at: str,
    prefix: str,
) -> None:
    collected = _parsed_timestamp(collected_at)
    if analyzed_at and _parsed_timestamp(analyzed_at) < collected:
        raise CTIProgramError(f"{prefix}.analyzed_at cannot precede collected_at.")  # noqa: F405
    analysis_floor = _parsed_timestamp(analyzed_at) if analyzed_at else collected
    if published_at and _parsed_timestamp(published_at) < analysis_floor:
        raise CTIProgramError(  # noqa: F405
            f"{prefix}.published_at cannot precede collected or analyzed time."
        )
    if _parsed_timestamp(expires_at) <= collected:
        raise CTIProgramError(f"{prefix}.expires_at must follow collected_at.")  # noqa: F405


def _require_handling_coverage(
    handling: str, evidence: list[dict[str, object]], prefix: str
) -> None:
    rank = {
        "TLP:CLEAR": 0,
        "TLP:GREEN": 1,
        "TLP:AMBER": 2,
        "TLP:AMBER+STRICT": 3,
        "TLP:RED": 4,
    }
    if any(rank[str(entry["handling"])] > rank[handling] for entry in evidence):
        raise CTIProgramError(  # noqa: F405
            f"{prefix}.handling cannot be less restrictive than linked evidence."
        )


def _requirement(value: object, index: int) -> dict[str, object]:
    prefix = f"requirements[{index}]"
    if not isinstance(value, dict):
        raise CTIProgramError(f"{prefix} must be an object.")  # noqa: F405
    unknown = set(value) - REQUIREMENT_FIELDS  # noqa: F405
    if unknown:
        raise CTIProgramError(  # noqa: F405
            f"{prefix} contains unsupported fields: {', '.join(sorted(unknown))}."
        )
    active = value.get("active")
    if not isinstance(active, bool):
        raise CTIProgramError(f"{prefix}.active must be true or false.")  # noqa: F405
    return {
        "id": _life_identifier(value.get("id", ""), f"{prefix}.id", generate=True),
        "active": active,
        "title": _life_text(value.get("title", ""), f"{prefix}.title", 180, required=True),
        "decision": _life_text(value.get("decision", ""), f"{prefix}.decision", 1000, required=True),
        "sponsor": _life_text(value.get("sponsor", ""), f"{prefix}.sponsor", 120, required=True),
        "consumers": _life_list(value.get("consumers", []), f"{prefix}.consumers"),
        "priority": _life_enum(value.get("priority", ""), f"{prefix}.priority", PRIORITIES),  # noqa: F405
        "horizon": _life_text(value.get("horizon", ""), f"{prefix}.horizon", 120, required=True),
        "cadence": _life_enum(value.get("cadence", ""), f"{prefix}.cadence", CADENCES),  # noqa: F405
        "collection_gaps": _life_list(value.get("collection_gaps", []), f"{prefix}.collection_gaps"),
        "deliverable": _life_text(value.get("deliverable", ""), f"{prefix}.deliverable", 500, required=True),
        "success_criteria": _life_text(value.get("success_criteria", ""), f"{prefix}.success_criteria", 1000, required=True),
        "review_date": _life_date(value.get("review_date", ""), f"{prefix}.review_date"),
        "status": _life_enum(value.get("status", ""), f"{prefix}.status", REQUIREMENT_STATUSES),  # noqa: F405
    }


def normalize_requirements(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_REQUIREMENTS:  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"requirements must be a list with at most {MAX_REQUIREMENTS} entries."  # noqa: F405
        )
    requirements = [_requirement(item, index) for index, item in enumerate(value)]
    identifiers = [str(item["id"]) for item in requirements]
    if len(identifiers) != len(set(identifiers)):
        raise CTIProgramError("Requirement ids must be unique.")  # noqa: F405
    return requirements


def _evidence(value: object, item_index: int, index: int) -> dict[str, object]:
    prefix = f"intelligence[{item_index}].evidence[{index}]"
    if not isinstance(value, dict):
        raise CTIProgramError(f"{prefix} must be an object.")  # noqa: F405
    unknown = set(value) - EVIDENCE_FIELDS  # noqa: F405
    if unknown:
        raise CTIProgramError(f"{prefix} contains unsupported fields: {', '.join(sorted(unknown))}.")  # noqa: F405,E501
    return {
        "id": _life_identifier(value.get("id", ""), f"{prefix}.id"),
        "kind": _life_enum(value.get("kind", ""), f"{prefix}.kind", EVIDENCE_KINDS),  # noqa: F405
        "reference": _evidence_reference(value.get("reference", ""), f"{prefix}.reference"),
        "description": _life_text(value.get("description", ""), f"{prefix}.description", 1000, required=True),
        "observed_at": _timestamp(value.get("observed_at", ""), f"{prefix}.observed_at", required=True),
        "source_id": _life_identifier(value.get("source_id", ""), f"{prefix}.source_id"),
        "handling": _life_enum(value.get("handling", ""), f"{prefix}.handling", HANDLING_LEVELS),  # noqa: F405
    }


def _entity(value: object, item_index: int, index: int) -> dict[str, object]:
    prefix = f"intelligence[{item_index}].entities[{index}]"
    if not isinstance(value, dict):
        raise CTIProgramError(f"{prefix} must be an object.")  # noqa: F405
    unknown = set(value) - ENTITY_FIELDS  # noqa: F405
    if unknown:
        raise CTIProgramError(f"{prefix} contains unsupported fields: {', '.join(sorted(unknown))}.")  # noqa: F405,E501
    evidence_ids = _life_list(
        value.get("evidence_ids", []),
        f"{prefix}.evidence_ids",
        identifiers=True,
    )
    if not evidence_ids:
        raise CTIProgramError(f"{prefix}.evidence_ids must link admitted evidence.")  # noqa: F405
    return {
        "id": _life_identifier(value.get("id", ""), f"{prefix}.id"),
        "entity_type": _life_enum(value.get("entity_type", ""), f"{prefix}.entity_type", ENTITY_TYPES),  # noqa: F405,E501
        "value": _life_text(value.get("value", ""), f"{prefix}.value", 500, required=True),
        "evidence_ids": evidence_ids,
        "affected_technology_ids": _life_list(value.get("affected_technology_ids", []), f"{prefix}.affected_technology_ids", identifiers=True),
    }


def _intelligence_collections(
    value: dict[object, object], index: int, prefix: str
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    evidence_value = value.get("evidence", [])
    entities_value = value.get("entities", [])
    if not isinstance(evidence_value, list) or len(evidence_value) > 50:
        raise CTIProgramError(f"{prefix}.evidence must be a list with at most 50 entries.")  # noqa: F405
    if not isinstance(entities_value, list) or len(entities_value) > 100:
        raise CTIProgramError(f"{prefix}.entities must be a list with at most 100 entries.")  # noqa: F405
    evidence = [_evidence(item, index, position) for position, item in enumerate(evidence_value)]
    entities = [_entity(item, index, position) for position, item in enumerate(entities_value)]
    for records, label in ((evidence, "Evidence"), (entities, "Entity")):
        identifiers = [str(item["id"]) for item in records]
        if len(identifiers) != len(set(identifiers)):
            raise CTIProgramError(f"{label} ids in {prefix} must be unique.")  # noqa: F405
    return evidence, entities


def _intelligence_timing(
    value: dict[object, object], prefix: str, evidence: list[dict[str, object]]
) -> dict[str, str]:
    result = {
        "handling": _life_enum(value.get("handling", ""), f"{prefix}.handling", HANDLING_LEVELS),  # noqa: F405,E501
        "collected_at": _timestamp(value.get("collected_at", ""), f"{prefix}.collected_at", required=True),
        "analyzed_at": _timestamp(value.get("analyzed_at", ""), f"{prefix}.analyzed_at"),
        "published_at": _timestamp(value.get("published_at", ""), f"{prefix}.published_at"),
        "expires_at": _timestamp(value.get("expires_at", ""), f"{prefix}.expires_at", required=True),
    }
    _require_timestamp_order(prefix=prefix, **{key: result[key] for key in ("collected_at", "analyzed_at", "published_at", "expires_at")})
    _require_handling_coverage(result["handling"], evidence, prefix)
    return result


def _intelligence(value: object, index: int) -> dict[str, object]:
    prefix = f"intelligence[{index}]"
    if not isinstance(value, dict):
        raise CTIProgramError(f"{prefix} must be an object.")  # noqa: F405
    unknown = set(value) - INTELLIGENCE_FIELDS  # noqa: F405
    if unknown:
        raise CTIProgramError(f"{prefix} contains unsupported fields: {', '.join(sorted(unknown))}.")  # noqa: F405,E501
    evidence, entities = _intelligence_collections(value, index, prefix)
    investigation_use = _life_text(value.get("investigation_use", ""), f"{prefix}.investigation_use", 32, required=True)
    if investigation_use != INVESTIGATION_USE:  # noqa: F405
        raise CTIProgramError(f"{prefix}.investigation_use must be context-only.")  # noqa: F405
    timing = _intelligence_timing(value, prefix, evidence)
    return {
        "id": _life_identifier(value.get("id", ""), f"{prefix}.id", generate=True),
        "deduplication_key": _life_text(value.get("deduplication_key", ""), f"{prefix}.deduplication_key", 180, required=True),
        "title": _life_text(value.get("title", ""), f"{prefix}.title", 240, required=True),
        "lifecycle_state": _life_enum(value.get("lifecycle_state", ""), f"{prefix}.lifecycle_state", LIFECYCLE_STATE_SET),  # noqa: F405,E501
        "requirement_ids": _life_list(value.get("requirement_ids", []), f"{prefix}.requirement_ids", identifiers=True),
        "source_ids": _life_list(value.get("source_ids", []), f"{prefix}.source_ids", identifiers=True),
        "affected_technology_ids": _life_list(value.get("affected_technology_ids", []), f"{prefix}.affected_technology_ids", identifiers=True),
        "source_reliability": _life_enum(value.get("source_reliability", ""), f"{prefix}.source_reliability", RELIABILITY_LEVELS),  # noqa: F405,E501
        "information_credibility": _life_enum(value.get("information_credibility", ""), f"{prefix}.information_credibility", INFORMATION_CREDIBILITY_LEVELS),  # noqa: F405,E501
        "confidence": _life_enum(value.get("confidence", ""), f"{prefix}.confidence", CONFIDENCE_LEVELS),  # noqa: F405,E501
        **timing,
        "summary": _life_text(value.get("summary", ""), f"{prefix}.summary", 2000, required=True),
        "analytic_judgment": _life_text(value.get("analytic_judgment", ""), f"{prefix}.analytic_judgment", 2000, required=True),
        "assumptions": _life_list(value.get("assumptions", []), f"{prefix}.assumptions", item_limit=500),
        "alternatives": _life_list(value.get("alternatives", []), f"{prefix}.alternatives", item_limit=500),
        "evidence": evidence,
        "entities": entities,
        "investigation_use": investigation_use,
    }


def normalize_intelligence(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_INTELLIGENCE:  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"intelligence must be a list with at most {MAX_INTELLIGENCE} entries."  # noqa: F405
        )
    intelligence = [_intelligence(item, index) for index, item in enumerate(value)]
    identifiers = [str(item["id"]) for item in intelligence]
    deduplication_keys = [str(item["deduplication_key"]).casefold() for item in intelligence]
    if len(identifiers) != len(set(identifiers)):
        raise CTIProgramError("Intelligence ids must be unique.")  # noqa: F405
    if len(deduplication_keys) != len(set(deduplication_keys)):
        raise CTIProgramError("Intelligence deduplication keys must be unique.")  # noqa: F405
    return intelligence


def validate_intelligence_links(
    intelligence: list[dict[str, object]],
    *,
    source_ids: set[str],
    requirement_ids: set[str],
    technology_ids: set[str],
) -> None:
    for index, item in enumerate(intelligence):
        prefix = f"intelligence[{index}]"
        _validate_primary_links(
            item,
            prefix=prefix,
            source_ids=source_ids,
            requirement_ids=requirement_ids,
            technology_ids=technology_ids,
        )
        _validate_evidence_links(item, prefix=prefix, source_ids=source_ids)
        _validate_entity_links(item, prefix=prefix, technology_ids=technology_ids)


def _validate_primary_links(
    item: dict[str, object],
    *,
    prefix: str,
    source_ids: set[str],
    requirement_ids: set[str],
    technology_ids: set[str],
) -> None:
    checks = (
        (item["source_ids"], source_ids, "source"),
        (item["requirement_ids"], requirement_ids, "requirement"),
        (item["affected_technology_ids"], technology_ids, "technology"),
    )
    for references, admitted, kind in checks:
        for reference in references:
            if reference not in admitted:
                raise CTIProgramError(  # noqa: F405
                    f"{prefix} references unknown {kind} {reference}."
                )


def _validate_evidence_links(
    item: dict[str, object], *, prefix: str, source_ids: set[str]
) -> None:
    linked = set(item["source_ids"])
    for evidence in item["evidence"]:
        source_id = evidence["source_id"]
        if source_id not in source_ids:
            raise CTIProgramError(  # noqa: F405
                f"{prefix} evidence references unknown source {source_id}."
            )
        if source_id not in linked:
            raise CTIProgramError(  # noqa: F405
                f"{prefix} evidence source is not linked by source_ids."
            )


def _validate_entity_links(
    item: dict[str, object], *, prefix: str, technology_ids: set[str]
) -> None:
    evidence_ids = {str(entry["id"]) for entry in item["evidence"]}
    linked_technologies = set(item["affected_technology_ids"])
    for entity in item["entities"]:
        for evidence_id in entity["evidence_ids"]:
            if evidence_id not in evidence_ids:
                raise CTIProgramError(  # noqa: F405
                    f"{prefix} entity references unknown evidence {evidence_id}."
                )
        for technology_id in entity["affected_technology_ids"]:
            if technology_id not in technology_ids:
                raise CTIProgramError(  # noqa: F405
                    f"{prefix} entity references unknown technology {technology_id}."
                )
            if technology_id not in linked_technologies:
                raise CTIProgramError(  # noqa: F405
                    f"{prefix} entity technology is not linked by affected_technology_ids."
                )


def intelligence_freshness(
    item: dict[str, object], *, now: dt.datetime | None = None
) -> str:
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    expires = _timestamp(item.get("expires_at", ""), "expires_at", required=True)
    parsed = dt.datetime.fromisoformat(expires[:-1] + "+00:00")
    return "stale" if current.astimezone(dt.timezone.utc) > parsed else "current"


def project_investigation_context(
    program: dict[str, object],
    intelligence_ids: list[str] | None = None,
    *,
    now: dt.datetime | None = None,
) -> dict[str, object]:
    """Project admitted CTI as bounded context with explicitly non-factual authority."""
    values = program.get("intelligence", [])
    if not isinstance(values, list):
        raise CTIProgramError("intelligence must be a list.")  # noqa: F405
    admitted = {
        str(item["id"]): item
        for item in values
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    requested = list(admitted) if intelligence_ids is None else _life_list(
        intelligence_ids,
        "intelligence_ids",
        maximum=MAX_INTELLIGENCE,  # noqa: F405
        identifiers=True,
    )
    unknown = [identifier for identifier in requested if identifier not in admitted]
    if unknown:
        raise CTIProgramError(  # noqa: F405
            f"Unknown intelligence context id: {unknown[0]}."
        )
    items = []
    for identifier in requested:
        item = admitted[identifier]
        items.append(
            {
                "id": identifier,
                "title": item["title"],
                "summary": item["summary"],
                "analytic_judgment": item["analytic_judgment"],
                "confidence": item["confidence"],
                "handling": item["handling"],
                "freshness": intelligence_freshness(item, now=now),
                "source_ids": list(item["source_ids"]),
                "evidence": list(item["evidence"]),
                "entities": list(item["entities"]),
            }
        )
    return {
        "authority": INVESTIGATION_USE,  # noqa: F405
        "may_assert_fact": False,
        "may_set_detection_outcome": False,
        "requires_independent_evidence": True,
        "items": items,
    }


def _audit_entry(entry: object, index: int) -> dict[str, object]:
    prefix = f"audit_history[{index}]"
    if not isinstance(entry, dict):
        raise CTIProgramError(f"{prefix} must be an object.")  # noqa: F405
    unknown = set(entry) - AUDIT_FIELDS  # noqa: F405
    if unknown:
        raise CTIProgramError(f"{prefix} contains unsupported fields: {', '.join(sorted(unknown))}.")  # noqa: F405,E501
    revision = entry.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise CTIProgramError(f"{prefix}.revision must be a positive integer.")  # noqa: F405
    before = _life_text(entry.get("before_digest", ""), f"{prefix}.before_digest", 64, required=True)
    after = _life_text(entry.get("after_digest", ""), f"{prefix}.after_digest", 64, required=True)
    if not DIGEST_RE.fullmatch(before) or not DIGEST_RE.fullmatch(after):  # noqa: F405
        raise CTIProgramError(f"{prefix} digests must be lowercase SHA-256 values.")  # noqa: F405
    return {
        "revision": revision,
        "event": _life_enum(entry.get("event", ""), f"{prefix}.event", frozenset({"workspace-updated"})),
        "changed_at": _timestamp(entry.get("changed_at", ""), f"{prefix}.changed_at", required=True),
        "changes": _life_list(entry.get("changes", []), f"{prefix}.changes", maximum=100, item_limit=160),
        "before_digest": before,
        "after_digest": after,
    }


def normalize_audit_history(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_AUDIT_HISTORY:  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"audit_history must be a list with at most {MAX_AUDIT_HISTORY} entries."  # noqa: F405
        )
    return [_audit_entry(entry, index) for index, entry in enumerate(value)]


__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
)
