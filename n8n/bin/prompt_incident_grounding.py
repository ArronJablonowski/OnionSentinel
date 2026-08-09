#!/usr/bin/env python3
"""Authenticate mandatory incident prompt grounding and query provenance."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Callable


@dataclass(frozen=True)
class IncidentGroundingSources:
    """Trusted validation port required before incident evidence is digested."""

    validate_incident_evidence: Callable[[dict], object]


ELASTIC_MUTABLE_FIELDS = frozenset({
    "hits",
    "returned_hits",
    "truncated",
    "prompt_projection",
})
OSQUERY_MUTABLE_FIELDS = frozenset({
    "rows",
    "returned_rows",
    "truncated",
    "prompt_projection",
})
RESPONSE_GROUNDING_FIELDS = (
    "ok",
    "complete",
    "partial",
    "read_only",
    "query_contract",
    "observables",
    "controls",
    "semantic_validity",
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _source_provenance(
    result: dict,
    *,
    samples_key: str,
    returned_key: str,
    total_key: str,
    projection_prefix: str,
) -> dict:
    projection = result.get("prompt_projection")
    if isinstance(projection, dict):
        return {
            "source_returned": projection[f"source_returned_{projection_prefix}"],
            "source_total": projection[f"source_total_{projection_prefix}"],
            "source_truncated": projection["source_truncated"],
            "source_samples_bytes": projection[f"source_{samples_key}_bytes"],
            "source_samples_sha256": projection[f"source_{samples_key}_sha256"],
        }
    encoded = _canonical_bytes(result.get(samples_key))
    return {
        "source_returned": result.get(returned_key),
        "source_total": result.get(total_key),
        "source_truncated": result.get("truncated"),
        "source_samples_bytes": len(encoded),
        "source_samples_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _immutable_result(
    result: dict,
    *,
    mutable: frozenset[str],
    samples_key: str,
    returned_key: str,
    total_key: str,
    projection_prefix: str,
) -> dict:
    return {
        **{key: value for key, value in result.items() if key not in mutable},
        "source_evidence_provenance": _source_provenance(
            result,
            samples_key=samples_key,
            returned_key=returned_key,
            total_key=total_key,
            projection_prefix=projection_prefix,
        ),
    }


def _project_result_list(
    results: object,
    *,
    mutable: frozenset[str],
    samples_key: str,
    returned_key: str,
    total_key: str,
    projection_prefix: str,
) -> list[dict]:
    if not isinstance(results, list):
        return []
    return [
        _immutable_result(
            result,
            mutable=mutable,
            samples_key=samples_key,
            returned_key=returned_key,
            total_key=total_key,
            projection_prefix=projection_prefix,
        )
        for result in results
        if isinstance(result, dict)
    ]


def immutable_query_provenance(incident: dict) -> dict:
    """Return all query fields that prompt compaction may not change."""
    response = incident.get("security_onion_response")
    if not isinstance(response, dict):
        return {"elastic_results": [], "osquery_results": []}
    return {
        "elastic_results": _project_result_list(
            response.get("results"),
            mutable=ELASTIC_MUTABLE_FIELDS,
            samples_key="hits",
            returned_key="returned_hits",
            total_key="total_hits",
            projection_prefix="hits",
        ),
        "osquery_results": _project_result_list(
            response.get("osquery_results"),
            mutable=OSQUERY_MUTABLE_FIELDS,
            samples_key="rows",
            returned_key="returned_rows",
            total_key="total_rows",
            projection_prefix="rows",
        ),
    }


def _validate_package_identity(package: dict) -> tuple[dict, dict]:
    if package.get("package_type") != "soc-ai-investigation-prompt":
        raise ValueError("incident prompt is missing its package identity")
    if package.get("agent_role") != "incident-responder":
        raise ValueError("incident prompt is missing its incident-responder role")
    alert = package.get("alert")
    if not isinstance(alert, dict) or not str(alert.get("alert_id") or "").strip():
        raise ValueError("incident prompt is missing its mandatory alert identity")
    if not str(package.get("group_id") or "").strip():
        raise ValueError("incident prompt is missing its mandatory group identity")
    incident = package.get("incident_response_evidence")
    if not isinstance(incident, dict):
        raise ValueError("incident prompt is missing restricted incident evidence")
    return alert, incident


def _valid_grounding_instructions(instructions: object) -> bool:
    if not isinstance(instructions, dict):
        return False
    grounding = instructions.get("grounding")
    return bool(
        str(instructions.get("role") or "").strip()
        and str(instructions.get("task") or "").strip()
        and isinstance(grounding, list)
        and grounding
        and all(isinstance(item, str) and item.strip() for item in grounding)
    )


def _validate_prompt_grounding(package: dict) -> tuple[dict, dict, dict]:
    instructions = package.get("instructions")
    if not _valid_grounding_instructions(instructions):
        raise ValueError("incident prompt is missing mandatory grounding instructions")
    response_schema = package.get("response_schema")
    if not isinstance(response_schema, dict) or not response_schema:
        raise ValueError("incident prompt is missing its mandatory response schema")
    detection_validation = package.get("detection_validation")
    if not isinstance(detection_validation, dict) or not detection_validation:
        raise ValueError("incident prompt is missing mandatory detection grounding")
    return instructions, response_schema, detection_validation


def _validate_evidence_identity(package, alert, incident, sources) -> None:
    sources.validate_incident_evidence(incident)
    if str(incident.get("alert_id") or "") != str(alert["alert_id"]):
        raise ValueError("incident evidence identity does not match the prompt alert group")
    if str(incident.get("group_id") or "") != str(package["group_id"]):
        raise ValueError("incident evidence identity does not match the prompt alert group")


def _incident_identity(incident: dict) -> dict:
    response = incident.get("security_onion_response")
    immutable_response = {
        key: response.get(key)
        for key in RESPONSE_GROUNDING_FIELDS
    }
    return {
        "schema": incident.get("schema"),
        "alert_id": incident.get("alert_id"),
        "group_id": incident.get("group_id"),
        "request": incident.get("request"),
        "response": immutable_response,
        "query_provenance": immutable_query_provenance(incident),
    }


def mandatory_grounding_digest(
    sources: IncidentGroundingSources,
    package: dict,
) -> str:
    """Authenticate incident identity, grounding, and query provenance."""
    alert, incident = _validate_package_identity(package)
    instructions, response_schema, detection_validation = (
        _validate_prompt_grounding(package)
    )
    _validate_evidence_identity(package, alert, incident, sources)
    mandatory = {
        "package_type": package["package_type"],
        "agent_role": package["agent_role"],
        "group_id": package["group_id"],
        "manual_reanalysis": package.get("manual_reanalysis"),
        "alert": alert,
        "instructions": instructions,
        "response_schema": response_schema,
        "detection_validation": detection_validation,
        "incident_identity": _incident_identity(incident),
    }
    return hashlib.sha256(_canonical_bytes(mandatory)).hexdigest()
