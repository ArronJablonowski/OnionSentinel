"""Pure normalization and secret-reference policy for CTI program data."""
from __future__ import annotations

import datetime as dt
import uuid
from urllib.parse import urlsplit

from cti_program_contract import *  # noqa: F403
from cti_program_lifecycle import *  # noqa: F403


def _text(value: object, field: str, limit: int, *, required: bool = False) -> str:
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


def _enum(value: object, field: str, allowed: frozenset[str]) -> str:
    normalized = _text(value, field, 64, required=True)
    if normalized not in allowed:
        raise CTIProgramError(f"{field} has an unsupported value.")  # noqa: F405
    return normalized


def _identifier(value: object, field: str) -> str:
    normalized = _text(value, field, 64)
    if not normalized:
        normalized = uuid.uuid4().hex
    if not IDENTIFIER_RE.fullmatch(normalized):  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"{field} must contain only lowercase letters, digits, hyphens, or underscores."
        )
    return normalized


def _date(value: object, field: str) -> str:
    normalized = _text(value, field, 10)
    if not normalized:
        return ""
    if not DATE_RE.fullmatch(normalized):  # noqa: F405
        raise CTIProgramError(f"{field} must use YYYY-MM-DD.")  # noqa: F405
    try:
        dt.date.fromisoformat(normalized)
    except ValueError as exc:
        raise CTIProgramError(f"{field} is not a valid date.") from exc  # noqa: F405
    return normalized


def _string_list(value: object, field: str, *, maximum: int = 16) -> list[str]:
    if not isinstance(value, list):
        raise CTIProgramError(f"{field} must be a list.")  # noqa: F405
    if len(value) > maximum:
        raise CTIProgramError(f"{field} exceeds {maximum} entries.")  # noqa: F405
    result: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(value):
        normalized = _text(entry, f"{field}[{index}]", 120, required=True)
        key = normalized.casefold()
        if key not in seen:
            seen.add(key)
            result.append(normalized)
    return result


def _endpoint(value: object, field: str) -> str:
    normalized = _text(value, field, 500)
    if not normalized:
        return ""
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise CTIProgramError(  # noqa: F405
            f"{field} must be an http(s) URL without credentials, query parameters, or fragments."
        )
    return normalized


def _secret_reference(value: object, field: str) -> str:
    normalized = _text(value, field, 80)
    if normalized and not SECRET_REFERENCE_RE.fullmatch(normalized):  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"{field} must be an environment-variable name, not a credential value."
        )
    return normalized


def _failure_code(value: object, field: str) -> str:
    normalized = _text(value, field, 120)
    if normalized and not IDENTIFIER_RE.fullmatch(normalized):  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"{field} must be a redacted lowercase identifier."
        )
    return normalized


def _source_collection_state(
    value: dict[object, object], prefix: str
) -> dict[str, str]:
    status = _enum(
        value.get("collection_status", "unknown"),
        f"{prefix}.collection_status",
        SOURCE_COLLECTION_STATUSES,  # noqa: F405
    )
    attempt = _timestamp(value.get("last_attempt_at", ""), f"{prefix}.last_attempt_at")
    success = _timestamp(value.get("last_success_at", ""), f"{prefix}.last_success_at")
    failure = _failure_code(value.get("failure_code", ""), f"{prefix}.failure_code")
    if status in {"degraded", "failed"} and (not attempt or not failure):
        raise CTIProgramError(  # noqa: F405
            f"{prefix} {status} collection state requires last_attempt_at and failure_code."
        )
    if status == "healthy" and not success:
        raise CTIProgramError(  # noqa: F405
            f"{prefix} healthy collection state requires last_success_at."
        )
    if status in {"unknown", "healthy"} and failure:
        raise CTIProgramError(  # noqa: F405
            f"{prefix}.failure_code requires degraded or failed collection status."
        )
    if attempt and success and _parsed_timestamp(success) > _parsed_timestamp(attempt):
        raise CTIProgramError(  # noqa: F405
            f"{prefix}.last_success_at cannot follow last_attempt_at."
        )
    return {
        "collection_status": status,
        "last_attempt_at": attempt,
        "last_success_at": success,
        "failure_code": failure,
    }


def _source_values(value: dict[object, object], index: int) -> dict[str, object]:
    prefix = f"sources[{index}]"
    return {
        "id": _identifier(value.get("id", ""), f"{prefix}.id"),
        "enabled": value["enabled"],
        "name": _text(value.get("name", ""), f"{prefix}.name", 120, required=True),
        "source_type": _enum(value.get("source_type", ""), f"{prefix}.source_type", SOURCE_TYPES),  # noqa: F405,E501
        "acquisition": _enum(value.get("acquisition", ""), f"{prefix}.acquisition", ACQUISITION_METHODS),  # noqa: F405,E501
        "endpoint": _endpoint(value.get("endpoint", ""), f"{prefix}.endpoint"),
        "credential_reference": _secret_reference(value.get("credential_reference", ""), f"{prefix}.credential_reference"),  # noqa: E501
        "owner": _text(value.get("owner", ""), f"{prefix}.owner", 100, required=True),
        "cadence": _enum(value.get("cadence", ""), f"{prefix}.cadence", CADENCES),  # noqa: F405,E501
        "reliability": _enum(value.get("reliability", ""), f"{prefix}.reliability", RELIABILITY_LEVELS),  # noqa: F405,E501
        "handling": _enum(value.get("handling", ""), f"{prefix}.handling", HANDLING_LEVELS),  # noqa: F405,E501
        "requirements": _string_list(value.get("requirements", []), f"{prefix}.requirements"),  # noqa: E501
        "review_date": _date(value.get("review_date", ""), f"{prefix}.review_date"),
        "disposition": _enum(value.get("disposition", ""), f"{prefix}.disposition", SOURCE_DISPOSITIONS),  # noqa: F405,E501
        **_source_collection_state(value, prefix),
        "notes": _text(value.get("notes", ""), f"{prefix}.notes", 1200),
    }


def _normalize_source(value: object, index: int) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CTIProgramError(f"sources[{index}] must be an object.")  # noqa: F405
    unknown = set(value) - SOURCE_FIELDS  # noqa: F405
    if unknown:
        raise CTIProgramError(  # noqa: F405
            f"sources[{index}] contains unsupported fields: {', '.join(sorted(unknown))}."
        )
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        raise CTIProgramError(  # noqa: F405
            f"sources[{index}].enabled must be true or false."
        )
    return _source_values(value, index)


def _technology_values(value: dict[object, object], index: int) -> dict[str, object]:
    prefix = f"technologies[{index}]"
    return {
        "id": _identifier(value.get("id", ""), f"{prefix}.id"),
        "enabled": value["enabled"],
        "vendor": _text(value.get("vendor", ""), f"{prefix}.vendor", 100, required=True),  # noqa: E501
        "product": _text(value.get("product", ""), f"{prefix}.product", 120, required=True),  # noqa: E501
        "category": _enum(value.get("category", ""), f"{prefix}.category", TECHNOLOGY_CATEGORIES),  # noqa: F405,E501
        "versions": _text(value.get("versions", ""), f"{prefix}.versions", 180),
        "deployment_scope": _text(value.get("deployment_scope", ""), f"{prefix}.deployment_scope", 240),  # noqa: E501
        "criticality": _enum(value.get("criticality", ""), f"{prefix}.criticality", PRIORITIES),  # noqa: F405,E501
        "priority": _enum(value.get("priority", ""), f"{prefix}.priority", PRIORITIES),  # noqa: F405,E501
        "exposure": _enum(value.get("exposure", ""), f"{prefix}.exposure", EXPOSURES),  # noqa: F405,E501
        "owner": _text(value.get("owner", ""), f"{prefix}.owner", 100, required=True),
        "monitor_for": _string_list(value.get("monitor_for", []), f"{prefix}.monitor_for", maximum=24),  # noqa: E501
        "requirements": _string_list(value.get("requirements", []), f"{prefix}.requirements"),  # noqa: E501
        "review_date": _date(value.get("review_date", ""), f"{prefix}.review_date"),
        "notes": _text(value.get("notes", ""), f"{prefix}.notes", 1200),
    }


def _normalize_technology(value: object, index: int) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CTIProgramError(  # noqa: F405
            f"technologies[{index}] must be an object."
        )
    unknown = set(value) - TECHNOLOGY_FIELDS  # noqa: F405
    if unknown:
        raise CTIProgramError(  # noqa: F405
            f"technologies[{index}] contains unsupported fields: {', '.join(sorted(unknown))}."
        )
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        raise CTIProgramError(  # noqa: F405
            f"technologies[{index}].enabled must be true or false."
        )
    return _technology_values(value, index)


def _program_header(value: object) -> tuple[dict[object, object], int, str]:
    if not isinstance(value, dict):
        raise CTIProgramError("CTI workspace must be a JSON object.")  # noqa: F405
    allowed = {
        "schema_version",
        "revision",
        "updated_at",
        "sources",
        "technologies",
        "requirements",
        "intelligence",
        "audit_history",
    }
    unknown = set(value) - allowed
    if unknown:
        raise CTIProgramError(  # noqa: F405
            f"CTI workspace contains unsupported fields: {', '.join(sorted(unknown))}."
        )
    schema_version = value.get("schema_version", SCHEMA_VERSION)  # noqa: F405
    if schema_version != SCHEMA_VERSION:  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"Unsupported CTI workspace schema version: {schema_version!r}."
        )
    revision = value.get("revision", 0)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise CTIProgramError("revision must be a non-negative integer.")  # noqa: F405
    return value, revision, _text(value.get("updated_at", ""), "updated_at", 40)


def _program_collections(value: dict[object, object]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:  # noqa: E501
    sources_value = value.get("sources", [])
    technologies_value = value.get("technologies", [])
    if not isinstance(sources_value, list) or len(sources_value) > MAX_SOURCES:  # noqa: F405
        raise CTIProgramError(  # noqa: F405
            f"sources must be a list with at most {MAX_SOURCES} entries."  # noqa: F405
        )
    if not isinstance(technologies_value, list) or len(technologies_value) > MAX_TECHNOLOGIES:  # noqa: F405,E501
        raise CTIProgramError(  # noqa: F405
            f"technologies must be a list with at most {MAX_TECHNOLOGIES} entries."  # noqa: F405,E501
        )
    sources = [_normalize_source(item, index) for index, item in enumerate(sources_value)]
    technologies = [_normalize_technology(item, index) for index, item in enumerate(technologies_value)]  # noqa: E501
    return sources, technologies


def _require_unique_sources(sources: list[dict[str, object]]) -> None:
    identifiers: set[str] = set()
    names: set[str] = set()
    for source in sources:
        identifier = str(source["id"])
        name = str(source["name"]).casefold()
        if identifier in identifiers or name in names:
            raise CTIProgramError("CTI source ids and names must be unique.")  # noqa: F405
        identifiers.add(identifier)
        names.add(name)


def _require_unique_technologies(technologies: list[dict[str, object]]) -> None:
    identifiers: set[str] = set()
    names: set[tuple[str, str]] = set()
    for technology in technologies:
        identifier = str(technology["id"])
        name = (str(technology["vendor"]).casefold(), str(technology["product"]).casefold())
        if identifier in identifiers or name in names:
            raise CTIProgramError("Technology ids and vendor/product pairs must be unique.")  # noqa: F405,E501
        identifiers.add(identifier)
        names.add(name)


def normalize_program(value: object, *, stored: bool = False) -> dict[str, object]:
    value, revision, updated_at = _program_header(value)
    sources, technologies = _program_collections(value)
    _require_unique_sources(sources)
    _require_unique_technologies(technologies)
    requirements = normalize_requirements(value.get("requirements", []))
    intelligence = normalize_intelligence(value.get("intelligence", []))
    validate_intelligence_links(
        intelligence,
        source_ids={str(source["id"]) for source in sources},
        requirement_ids={str(requirement["id"]) for requirement in requirements},
        technology_ids={str(technology["id"]) for technology in technologies},
    )
    audit_history = normalize_audit_history(value.get("audit_history", []))
    return {
        "schema_version": SCHEMA_VERSION,  # noqa: F405
        "revision": revision,
        "updated_at": updated_at if stored else "",
        "sources": sources,
        "technologies": technologies,
        "requirements": requirements,
        "intelligence": intelligence,
        "audit_history": audit_history,
    }


for __compat_function__ in (
    _text,
    _enum,
    _identifier,
    _date,
    _string_list,
    _endpoint,
    _secret_reference,
    _failure_code,
    _normalize_source,
    _normalize_technology,
    normalize_program,
):
    __compat_function__.__module__ = "cti_program"
del __compat_function__

__all__ = tuple(
    name for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
    and name not in {
        "_source_values",
        "_technology_values",
        "_program_header",
        "_program_collections",
        "_require_unique_sources",
        "_require_unique_technologies",
        "_source_collection_state",
    }
)
