"""Compatibility facade for investigation-query response validation."""
from __future__ import annotations

from typing import Any

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_normalization import *  # noqa: F401,F403
from investigation_query_normalization import (  # noqa: F401
    _index_matches_scope,
    _normalize_event_tuple,
    _normalize_observable,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
)
from investigation_query_authorization import *  # noqa: F401,F403
from investigation_query_rendering import *  # noqa: F401,F403
from investigation_query_rendering import (  # noqa: F401
    _event_tuple_query_fields,
    _expected_execution_digest,
)
from investigation_query_response_source import (  # noqa: F401
    _event_tuple_value_matches,
    _leaf_items,
    _observable_matches,
    _path_values,
    _validate_hit_source,
)
from investigation_query_response_result import (  # noqa: F401
    _validate_pivot_result,
    result_coverage,
)
from investigation_query_response_control import _validate_control  # noqa: F401


def _validate_response_identity(
    value: dict[str, Any], expected_request: dict[str, Any]
) -> None:
    if value.get("query_contract") != INVESTIGATION_QUERY_CONTRACT:
        raise InvestigationQueryContractError("response query contract is unsupported")
    if value.get("batch_id") != expected_request["batch_id"]:
        raise InvestigationQueryContractError("response batch id does not match")
    if value.get("request_digest") != canonical_digest(expected_request):
        raise InvestigationQueryContractError("response request digest does not match")
    if value.get("read_only") is not True or value.get("ok") is not True:
        raise InvestigationQueryContractError(
            "response is not a successful read-only protocol result"
        )


def _validate_response_results(
    value: dict[str, Any], expected_request: dict[str, Any]
) -> list[bool]:
    results = value.get("results")
    if not isinstance(results, list) or len(results) != len(expected_request["queries"]):
        raise InvestigationQueryContractError("response result coverage is incomplete")
    return [
        _validate_pivot_result(result, query)
        for result, query in zip(results, expected_request["queries"])
    ]


def _validate_response_controls(
    value: dict[str, Any], expected_request: dict[str, Any]
) -> bool:
    controls = _require_mapping(value.get("controls"), "investigation controls")
    anchor = expected_request["authorization"]["anchor"]
    if controls.get("anchor") != anchor:
        raise InvestigationQueryContractError("response control anchor does not match")
    control_validity: list[bool] = []
    control_errors: list[str] = []
    for field, positive in (("positive_anchor", True), ("negative_filter", False)):
        try:
            control_validity.append(
                _validate_control(controls.get(field), anchor=anchor, positive=positive)
            )
        except InvestigationQueryContractError as exc:
            control_validity.append(False)
            control_errors.append(f"{field}: {exc}")
    if control_errors:
        raise InvestigationQueryContractError(
            "investigation query controls are invalid: " + "; ".join(control_errors)
        )
    return all(control_validity)


def _validate_response_semantics(
    value: dict[str, Any], query_valid: list[bool], controls_valid: bool
) -> None:
    complete = all(query_valid) and controls_valid
    if value.get("complete") is not complete or value.get("partial") is not (not complete):
        raise InvestigationQueryContractError("response completion flags are inconsistent")
    semantic = _require_mapping(
        value.get("semantic_validity"), "response semantic_validity"
    )
    if (
        semantic.get("transport_valid") is not True
        or semantic.get("controls_valid") is not controls_valid
        or semantic.get("query_execution_valid") is not all(query_valid)
        or semantic.get("semantic_valid") is not complete
    ):
        raise InvestigationQueryContractError("response semantic validity is inconsistent")


def validate_investigation_query_response(
    response: object,
    request: object,
) -> dict[str, Any]:
    """Authenticate the forced-command response against the exact request."""
    expected_request = validate_authorized_investigation_query_request(request)
    value = _require_mapping(response, "investigation query response")
    _validate_response_identity(value, expected_request)
    query_valid = _validate_response_results(value, expected_request)
    controls_valid = _validate_response_controls(value, expected_request)
    _validate_response_semantics(value, query_valid, controls_valid)
    return value


__all__ = [
    "ALLOWED_AGGREGATIONS",
    "ALLOWED_DIALECTS",
    "ALLOWED_PURPOSES",
    "EVENT_TUPLE_FIELDS",
    "EVENT_TUPLE_PATHS",
    "INVESTIGATION_QUERY_CONTRACT",
    "InvestigationQueryContractError",
    "SAFE_ATOM_RE",
    "authorize_investigation_query_request",
    "build_query_dsl",
    "canonical_digest",
    "kql_equivalent",
    "oql_equivalent",
    "pack_event_tuple_fields",
    "result_coverage",
    "tuple_match_semantics",
    "validate_pack_observables",
    "validate_authorized_investigation_query_request",
    "validate_investigation_query_request",
    "validate_investigation_query_response",
]
