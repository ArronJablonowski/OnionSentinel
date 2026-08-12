"""Source projection and evidence-binding validation for investigation hits."""
from __future__ import annotations

from typing import Any

from investigation_query_schema import (  # noqa: F401
    EVENT_TUPLE_PATHS,
    PACKS,
    InvestigationQueryContractError,
)
from investigation_query_normalization import (
    _normalize_event_tuple,
    _normalize_observable,
    _parse_utc,
    _require_mapping,
)
from investigation_query_rendering import (
    _event_tuple_query_fields,
    pack_observable_fields,
)


def _leaf_items(value: object, prefix: str = "") -> list[tuple[str, object]]:
    """Flatten source leaves while preserving ECS paths through arrays."""
    leaves: list[tuple[str, object]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            leaves.extend(_leaf_items(child, path))
    elif isinstance(value, list):
        for child in value:
            leaves.extend(_leaf_items(child, prefix))
    else:
        leaves.append((prefix, value))
    return leaves


def _path_values(source: dict[str, Any], path: str) -> list[object]:
    current: list[object] = [source]
    for part in path.split("."):
        following: list[object] = []
        for item in current:
            if isinstance(item, dict) and part in item:
                value = item[part]
                following.extend(value if isinstance(value, list) else [value])
            elif isinstance(item, list):
                for child in item:
                    if isinstance(child, dict) and part in child:
                        value = child[part]
                        following.extend(value if isinstance(value, list) else [value])
        current = following
    return [item for item in current if not isinstance(item, (dict, list))]


def _observable_matches(kind: str, expected: str, candidate: object) -> bool:
    try:
        return _normalize_observable(kind, candidate) == expected
    except InvestigationQueryContractError:
        return False


def _event_tuple_value_matches(field: str, expected: Any, candidate: object) -> bool:
    try:
        normalized = _normalize_event_tuple(
            {field: candidate},
            label="investigation hit event tuple",
        )
    except InvestigationQueryContractError:
        return False
    return normalized.get(field) == expected


def _validate_source_projection(
    source: dict[str, Any], expected_query: dict[str, Any]
) -> None:
    allowed_fields = set(PACKS[expected_query["pack"]]["fields"])
    if any(path not in allowed_fields for path, _value in _leaf_items(source)):
        raise InvestigationQueryContractError(
            "investigation hit source contains a field outside its reviewed projection"
        )


def _validate_source_timestamp(
    source: dict[str, Any], expected_query: dict[str, Any]
) -> None:
    timestamp_values = _path_values(source, "@timestamp")
    if len(timestamp_values) != 1:
        raise InvestigationQueryContractError(
            "investigation hit source has no singular timestamp"
        )
    timestamp = _parse_utc(timestamp_values[0], "investigation hit timestamp")
    start = _parse_utc(expected_query["window"]["start"], "investigation window start")
    end = _parse_utc(expected_query["window"]["end"], "investigation window end")
    if timestamp < start or timestamp > end:
        raise InvestigationQueryContractError(
            "investigation hit timestamp escaped its authorized window"
        )


def _validate_source_dataset(
    source: dict[str, Any], expected_query: dict[str, Any]
) -> None:
    datasets = [str(item) for item in _path_values(source, "event.dataset")]
    allowed_datasets = PACKS[expected_query["pack"]]["datasets"]
    if len(datasets) != 1 or datasets[0] not in allowed_datasets:
        raise InvestigationQueryContractError(
            "investigation hit dataset escaped its reviewed pack"
        )


def _source_matches_observable(
    source: dict[str, Any], expected_query: dict[str, Any]
) -> bool:
    for kind, fields in pack_observable_fields(expected_query["pack"]).items():
        for expected in expected_query["observables"].get(kind, []):
            if any(
                _observable_matches(kind, expected, candidate)
                for field in fields
                for candidate in _path_values(source, field)
            ):
                return True
    return False


def _validate_source_event_tuple(
    source: dict[str, Any], expected_query: dict[str, Any]
) -> None:
    event_tuple = expected_query.get("event_tuple") or {}
    for field in _event_tuple_query_fields(expected_query):
        if not any(
            _event_tuple_value_matches(field, event_tuple[field], candidate)
            for path in EVENT_TUPLE_PATHS[field]
            for candidate in _path_values(source, path)
        ):
            raise InvestigationQueryContractError(
                "investigation hit does not match its authorized event tuple"
            )


def _validate_hit_source(
    source: object,
    expected_query: dict[str, Any],
) -> None:
    source_map = _require_mapping(source, "investigation hit source")
    _validate_source_projection(source_map, expected_query)
    _validate_source_timestamp(source_map, expected_query)
    _validate_source_dataset(source_map, expected_query)
    if not _source_matches_observable(source_map, expected_query):
        raise InvestigationQueryContractError(
            "investigation hit does not contain an authorized matching observable"
        )
    _validate_source_event_tuple(source_map, expected_query)


__all__ = [
    "_event_tuple_value_matches",
    "_leaf_items",
    "_observable_matches",
    "_path_values",
    "_validate_hit_source",
]
