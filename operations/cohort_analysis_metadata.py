#!/usr/bin/env python3
"""Load bounded, identity-bound cohort analysis metadata from SQLite."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
from typing import Any


REQUIRED_COLUMNS = {
    "analysis_id",
    "group_id",
    "alert_id",
    "agent_role",
    "response_json",
}
OPTIONAL_COLUMNS = (
    "analysis_id",
    "group_id",
    "alert_id",
    "agent_role",
    "generated_at",
    "model",
    "model_path",
    "detection_outcome",
    "confidence",
    "evidence_hash",
    "created_at",
    "response_json",
)
RESULT_FIELDS = (
    "event_status",
    "detection_validity",
    "activity_disposition",
    "handling",
    "duplicate_of",
    "final_disposition_status",
    "_analysis_model",
    "_analysis_model_path",
    "_analysis_provider",
    "_analysis_harness",
    "_analysis_model_route",
    "_analysis_input_mode",
    "_analysis_evaluation_memory_frozen",
)
SCALAR_TYPES = (str, int, float, bool, type(None))


@dataclass(frozen=True)
class AnalysisMetadataPolicy:
    error: type[RuntimeError]
    require_columns: Callable[[Any, str, set[str]], set[str]]
    response_sha256: Callable[[str], str]
    query_audit_projection: Callable[[Mapping[str, Any]], dict[str, Any]]


def _load_row(
    connection: Any,
    analysis_id: str,
    columns: set[str],
    error: type[RuntimeError],
) -> dict[str, Any]:
    allowed = [field for field in OPTIONAL_COLUMNS if field in columns]
    row = connection.execute(
        "SELECT " + ", ".join(allowed)
        + " FROM ai_analysis_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    if not row:
        raise error(f"analysis result is missing: {analysis_id}")
    return dict(row)


def _require_identity(
    item: Mapping[str, Any],
    analysis_id: str,
    stable_group_id: str,
    expected_alert_id: str,
    expected_agent_role: str,
    error: type[RuntimeError],
) -> None:
    valid = (
        str(item.get("group_id") or "") == stable_group_id
        and str(item.get("alert_id") or "") == expected_alert_id
        and str(item.get("agent_role") or "") == expected_agent_role
    )
    if not valid:
        raise error(
            f"analysis {analysis_id} is not bound to the frozen "
            f"{expected_agent_role} identity"
        )


def _parse_response(
    raw_response: str,
    analysis_id: str,
    error: type[RuntimeError],
) -> dict[str, Any]:
    try:
        response = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        raise error(f"analysis {analysis_id} response JSON is malformed") from exc
    if not isinstance(response, dict):
        raise error(f"analysis {analysis_id} response is not an object")
    return response


def _second_opinion(response: Mapping[str, Any]) -> dict[str, Any] | None:
    value = response.get("_second_opinion")
    if not isinstance(value, dict):
        return None
    reviewer = value.get("response")
    reviewer = reviewer if isinstance(reviewer, dict) else {}
    return {
        "status": str(value.get("status") or ""),
        "model_route": str(value.get("model_route") or ""),
        "response": {
            "_analysis_model_route": str(
                reviewer.get("_analysis_model_route") or ""
            )
        },
    }


def _result_projection(response: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        key: response.get(key)
        for key in RESULT_FIELDS
        if key in response and isinstance(response.get(key), SCALAR_TYPES)
    }
    second_opinion = _second_opinion(response)
    if second_opinion is not None:
        result["_second_opinion"] = second_opinion
    return result


def load_analysis_metadata(
    connection: Any,
    analysis_id: str,
    stable_group_id: str,
    *,
    expected_alert_id: str,
    expected_agent_role: str,
    policy: AnalysisMetadataPolicy,
) -> dict[str, Any]:
    """Return bounded analysis metadata after exact frozen-identity validation."""
    columns = policy.require_columns(
        connection, "ai_analysis_runs", REQUIRED_COLUMNS
    )
    item = _load_row(connection, analysis_id, columns, policy.error)
    _require_identity(
        item,
        analysis_id,
        stable_group_id,
        expected_alert_id,
        expected_agent_role,
        policy.error,
    )
    raw_response = str(item.pop("response_json", "") or "")
    item["response_bytes"] = len(raw_response.encode("utf-8"))
    item["response_sha256"] = hashlib.sha256(
        raw_response.encode("utf-8")
    ).hexdigest()
    response = _parse_response(raw_response, analysis_id, policy.error)
    item["response_canonical_sha256"] = policy.response_sha256(raw_response)
    item["result"] = _result_projection(response)
    item["query_audit"] = policy.query_audit_projection(response)
    return item
