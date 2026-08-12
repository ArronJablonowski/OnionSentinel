"""Representative-alert control validation for incident evidence."""

from __future__ import annotations

from typing import Any

from incident_evidence_primitives import (
    ALERT_INDEX_SCOPE,
    negative_control_dsl,
    positive_control_dsl,
)
from incident_evidence_search_contract import validate_search_result
from incident_evidence_validation import (
    IncidentEvidenceContractError,
    require_mapping,
)


def _validate_unrequested_controls(
    positive: dict[str, Any], negative: dict[str, Any]
) -> bool:
    for label, control in (
        ("positive anchor control", positive),
        ("negative filter control", negative),
    ):
        if (
            control.get("status") != "not_requested"
            or control.get("passed") is not False
            or control.get("semantic_valid") is not False
        ):
            raise IncidentEvidenceContractError(
                f"{label} must fail closed without an anchor"
            )
    return False


def _validate_positive_control(
    anchor: dict[str, str], control: dict[str, Any]
) -> bool:
    valid = validate_search_result(
        control,
        label="positive anchor control",
        expected_scope=[anchor["index"]],
        max_hits=1,
    )
    if control.get("query_dsl") != positive_control_dsl(anchor):
        raise IncidentEvidenceContractError(
            "positive anchor control query is not the reviewed query"
        )
    exact_hits = [
        item
        for item in control["hits"]
        if item["id"] == anchor["id"] and item["index"] == anchor["index"]
    ]
    expected = (
        valid
        and control["total_hits_relation"] == "eq"
        and control["total_hits"] == 1
        and len(exact_hits) == 1
    )
    if control.get("passed") is not expected:
        raise IncidentEvidenceContractError(
            "positive anchor control passed flag is inconsistent"
        )
    return expected


def _validate_negative_control(
    anchor: dict[str, str], control: dict[str, Any]
) -> bool:
    valid = validate_search_result(
        control,
        label="negative filter control",
        expected_scope=ALERT_INDEX_SCOPE,
        max_hits=1,
    )
    if control.get("query_dsl") != negative_control_dsl(anchor):
        raise IncidentEvidenceContractError(
            "negative filter control query is not the reviewed query"
        )
    expected = (
        valid
        and control["total_hits_relation"] == "eq"
        and control["total_hits"] == 0
        and control["returned_hits"] == 0
    )
    if control.get("passed") is not expected:
        raise IncidentEvidenceContractError(
            "negative filter control passed flag is inconsistent"
        )
    return expected


def validate_controls(
    request_anchor: dict[str, str] | None,
    response: dict[str, Any],
) -> bool:
    controls = require_mapping(response.get("controls"), "query controls")
    if controls.get("anchor") != request_anchor:
        raise IncidentEvidenceContractError(
            "query control anchor does not match the request"
        )
    positive = require_mapping(
        controls.get("positive_anchor"), "positive anchor control"
    )
    negative = require_mapping(
        controls.get("negative_filter"), "negative filter control"
    )
    if request_anchor is None:
        return _validate_unrequested_controls(positive, negative)
    positive_passed = _validate_positive_control(request_anchor, positive)
    negative_passed = _validate_negative_control(request_anchor, negative)
    return positive_passed and negative_passed
