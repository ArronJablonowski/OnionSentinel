"""Bounded mapping discovery for indexed historical OSQuery evidence."""
from __future__ import annotations

from typing import Any

from investigation_query_schema import (
    PACKS,
    InvestigationQueryContractError,
    _HISTORICAL_OSQUERY_IDENTITY_FIELDS,
    _HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
    _HISTORICAL_OSQUERY_SCHEMA_PROFILES,
    _HISTORICAL_OSQUERY_SCHEMA_STATUSES,
    canonical_digest,
)


def historical_osquery_field_caps_endpoint(index_scope: list[str]) -> str:
    """Return the fixed read-only mapping-discovery endpoint."""
    if (
        not isinstance(index_scope, list)
        or not index_scope
        or index_scope != PACKS["osquery_history"]["indices"]
    ):
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery index scope is invalid"
        )
    return (
        f"{','.join(index_scope)}/_field_caps"
        "?ignore_unavailable=true&expand_wildcards=open"
    )


def historical_osquery_field_caps_body(
    projection_fields: list[str],
) -> dict[str, list[str]]:
    """Build the exact field-capabilities body without accepting query DSL."""
    if (
        not isinstance(projection_fields, list)
        or projection_fields != PACKS["osquery_history"]["fields"]
    ):
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery projection is invalid"
        )
    return {"fields": list(projection_fields)}


def _field_capabilities(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("fields"), dict):
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery response is malformed"
        )
    return value["fields"]


def _field_is_searchable(capabilities: dict[str, Any]) -> bool:
    return any(
        isinstance(details, dict) and details.get("searchable") is True
        for details in capabilities.values()
    )


def _historical_osquery_capability_fields(
    field_caps: object,
    projection_fields: list[str],
) -> tuple[list[str], list[str]]:
    fields = _field_capabilities(field_caps)
    if set(fields) - set(projection_fields):
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery returned an unreviewed field"
        )
    mapped: list[str] = []
    searchable: list[str] = []
    for field in projection_fields:
        capabilities = fields.get(field)
        if capabilities is None:
            continue
        if not isinstance(capabilities, dict) or not capabilities:
            raise InvestigationQueryContractError(
                "historical OSQuery schema discovery field capabilities are malformed"
            )
        mapped.append(field)
        if _field_is_searchable(capabilities):
            searchable.append(field)
    return sorted(mapped), sorted(searchable)


def _historical_osquery_compatible_profiles(
    mapped_fields: list[str],
) -> list[str]:
    mapped = set(mapped_fields)
    if not {"@timestamp", "event.dataset"}.issubset(mapped):
        return []
    return [
        name
        for name, profile in _HISTORICAL_OSQUERY_SCHEMA_PROFILES.items()
        if mapped.intersection(profile["identity_fields"])
        and mapped.intersection(profile["marker_fields"])
    ]


def _discovery_digest(value: dict[str, object]) -> str:
    return canonical_digest({
        key: item for key, item in value.items()
        if key != "discovery_digest"
    })


def _validate_request_shape(
    index_scope: list[str],
    projection_fields: list[str],
    observable_fields: list[str],
) -> tuple[str, dict[str, list[str]]]:
    endpoint = historical_osquery_field_caps_endpoint(index_scope)
    body = historical_osquery_field_caps_body(projection_fields)
    if (
        not isinstance(observable_fields, list)
        or not observable_fields
        or any(field not in projection_fields for field in observable_fields)
    ):
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery observable fields are invalid"
        )
    return endpoint, body


def compile_historical_osquery_schema_discovery(
    field_caps: object,
    *,
    index_scope: list[str],
    projection_fields: list[str],
    observable_fields: list[str],
) -> dict[str, object]:
    """Project untrusted field capabilities into a bounded mapping verdict."""
    endpoint, body = _validate_request_shape(
        index_scope, projection_fields, observable_fields
    )
    mapped, searchable = _historical_osquery_capability_fields(
        field_caps, projection_fields
    )
    compatible_profiles = _historical_osquery_compatible_profiles(mapped)
    mapped_observables = sorted(set(observable_fields).intersection(searchable))
    base_searchable = {"@timestamp", "event.dataset"}.issubset(searchable)
    discovery: dict[str, object] = {
        "schema_contract": _HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
        "status": "ok",
        "index_scope": list(index_scope),
        "field_caps_endpoint": endpoint,
        "field_caps_body_digest": canonical_digest(body),
        "projection_fields_digest": canonical_digest(projection_fields),
        "mapped_fields": mapped,
        "searchable_fields": searchable,
        "unmapped_fields": sorted(set(projection_fields) - set(mapped)),
        "mapped_identity_fields": sorted(
            _HISTORICAL_OSQUERY_IDENTITY_FIELDS.intersection(mapped)
        ),
        "mapped_observable_fields": mapped_observables,
        "compatible_profiles": compatible_profiles,
        "mapping_compatible": bool(
            base_searchable and mapped_observables and compatible_profiles
        ),
    }
    discovery["discovery_digest"] = _discovery_digest(discovery)
    return discovery


def historical_osquery_schema_failure(
    status: str,
    *,
    index_scope: list[str],
    projection_fields: list[str],
    error: str,
) -> dict[str, object]:
    """Create a redacted, digest-bound mapping-discovery failure."""
    if status not in _HISTORICAL_OSQUERY_SCHEMA_STATUSES - {"ok"}:
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery status is invalid"
        )
    endpoint = historical_osquery_field_caps_endpoint(index_scope)
    body = historical_osquery_field_caps_body(projection_fields)
    bounded_error = " ".join(str(error or "").split())[:1000]
    if not bounded_error:
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery failure has no error"
        )
    discovery: dict[str, object] = {
        "schema_contract": _HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
        "status": status,
        "index_scope": list(index_scope),
        "field_caps_endpoint": endpoint,
        "field_caps_body_digest": canonical_digest(body),
        "projection_fields_digest": canonical_digest(projection_fields),
        "mapped_fields": [],
        "searchable_fields": [],
        "unmapped_fields": list(projection_fields),
        "mapped_identity_fields": [],
        "mapped_observable_fields": [],
        "compatible_profiles": [],
        "mapping_compatible": False,
        "error": bounded_error,
    }
    discovery["discovery_digest"] = _discovery_digest(discovery)
    return discovery


def _reconstructed_field_caps(value: dict[str, Any]) -> dict[str, object]:
    searchable = set(value.get("searchable_fields") or [])
    return {
        "fields": {
            field: {
                "keyword": {
                    "type": "keyword",
                    "searchable": field in searchable,
                    "aggregatable": False,
                }
            }
            for field in value.get("mapped_fields") or []
        }
    }


def _expected_discovery(
    value: dict[str, Any],
    *,
    index_scope: list[str],
    projection_fields: list[str],
    observable_fields: list[str],
) -> dict[str, object]:
    status = str(value.get("status") or "")
    if status == "ok":
        return compile_historical_osquery_schema_discovery(
            _reconstructed_field_caps(value),
            index_scope=index_scope,
            projection_fields=projection_fields,
            observable_fields=observable_fields,
        )
    return historical_osquery_schema_failure(
        status,
        index_scope=index_scope,
        projection_fields=projection_fields,
        error=str(value.get("error") or ""),
    )


def validate_historical_osquery_schema_discovery(
    value: object,
    *,
    index_scope: list[str],
    projection_fields: list[str],
    observable_fields: list[str],
) -> dict[str, object]:
    """Authenticate the compact schema verdict without trusting its claims."""
    if not isinstance(value, dict):
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery must be an object"
        )
    try:
        expected = _expected_discovery(
            value,
            index_scope=index_scope,
            projection_fields=projection_fields,
            observable_fields=observable_fields,
        )
    except (TypeError, ValueError) as exc:
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery is invalid"
        ) from exc
    if value != expected:
        raise InvestigationQueryContractError(
            "historical OSQuery schema discovery is inconsistent"
        )
    return value


__all__ = [
    "compile_historical_osquery_schema_discovery",
    "historical_osquery_field_caps_body",
    "historical_osquery_field_caps_endpoint",
    "historical_osquery_schema_failure",
    "validate_historical_osquery_schema_discovery",
]
