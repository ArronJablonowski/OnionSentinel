"""Top-level composition for restricted incident-evidence validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from incident_evidence_control_contract import validate_controls
from incident_evidence_osquery_contract import validate_osquery_results
from incident_evidence_primitives import (
    ALLOWED_PACKS,
    ALLOWED_STATUSES,
    INCIDENT_EVIDENCE_CONTRACT,
    LEGACY_INCIDENT_EVIDENCE_CONTRACT,
    MAX_ELASTIC_HITS,
    PACK_INDEX_SCOPES,
    SHA256_RE,
    canonical_dsl_digest,
    validate_anchor,
)
from incident_evidence_search_contract import validate_search_result
from incident_evidence_validation import (
    IncidentEvidenceContractError,
    require_mapping,
    require_nonempty_text,
)


@dataclass(frozen=True)
class ArtifactContext:
    artifact: dict[str, Any]
    schema: str
    request: dict[str, Any]
    response: dict[str, Any]


@dataclass(frozen=True)
class RequestContext:
    packs: list[object]
    windows: list[object]
    anchor: dict[str, str] | None
    result_size: int | None


def _artifact_context(artifact: object) -> ArtifactContext:
    artifact_map = require_mapping(artifact, "incident evidence artifact")
    schema = artifact_map.get("schema")
    if schema not in {
        INCIDENT_EVIDENCE_CONTRACT,
        LEGACY_INCIDENT_EVIDENCE_CONTRACT,
    }:
        raise IncidentEvidenceContractError(
            "incident evidence schema is unsupported"
        )
    request = require_mapping(
        artifact_map.get("request"), "incident evidence request"
    )
    response = require_mapping(
        artifact_map.get("security_onion_response"),
        "Security Onion incident evidence response",
    )
    if response.get("ok") is not True:
        raise IncidentEvidenceContractError(
            "Security Onion evidence response is not successful"
        )
    if response.get("read_only") is not True:
        raise IncidentEvidenceContractError(
            "Security Onion evidence response is not read-only"
        )
    if response.get("query_contract") != schema:
        raise IncidentEvidenceContractError(
            "Security Onion query contract is unsupported"
        )
    return ArtifactContext(artifact_map, schema, request, response)


def _request_context(context: ArtifactContext) -> RequestContext:
    request = context.request
    packs, windows = _request_lists(request)
    observables = require_mapping(
        request.get("observables"), "incident evidence observables"
    )
    if context.response.get("observables") != observables:
        raise IncidentEvidenceContractError(
            "response observables do not match the request"
        )
    anchor, result_size = _v2_request_identity(context)
    return RequestContext(packs, windows, anchor, result_size)


def _request_lists(
    request: dict[str, Any]
) -> tuple[list[object], list[object]]:
    packs = request.get("packs")
    windows = request.get("windows")
    if not isinstance(packs, list) or not packs:
        raise IncidentEvidenceContractError(
            "incident evidence request has no query packs"
        )
    if not isinstance(windows, list) or not windows:
        raise IncidentEvidenceContractError(
            "incident evidence request has no time windows"
        )
    if len(packs) != len(set(str(item) for item in packs)):
        raise IncidentEvidenceContractError(
            "incident evidence request contains duplicate packs"
        )
    if any(str(pack) not in ALLOWED_PACKS for pack in packs):
        raise IncidentEvidenceContractError(
            "incident evidence request contains an unsupported pack"
        )
    return packs, windows


def _v2_request_identity(
    context: ArtifactContext,
) -> tuple[dict[str, str] | None, int | None]:
    anchor = None
    result_size = context.request.get("size")
    if context.schema == INCIDENT_EVIDENCE_CONTRACT:
        anchor = validate_anchor(context.request.get("anchor"))
        if (
            isinstance(result_size, bool)
            or not isinstance(result_size, int)
            or result_size < 1
            or result_size > MAX_ELASTIC_HITS
        ):
            raise IncidentEvidenceContractError(
                "incident evidence request size is invalid"
            )
    return anchor, result_size


def _validate_result_query(
    result: dict[str, Any], pack: str
) -> None:
    kql = require_nonempty_text(
        result.get("kql_equivalent"), "query KQL equivalent"
    )
    if len(kql) > 64 * 1024:
        raise IncidentEvidenceContractError(
            "query KQL equivalent exceeds its byte contract"
        )
    query_dsl = require_mapping(result.get("query_dsl"), "exact query DSL")
    if not query_dsl:
        raise IncidentEvidenceContractError(
            "exact query DSL must be non-empty"
        )
    digest = require_nonempty_text(result.get("query_digest"), "query digest")
    if not SHA256_RE.fullmatch(digest):
        raise IncidentEvidenceContractError(
            "query digest is not a SHA-256 value"
        )
    if canonical_dsl_digest(query_dsl) != digest:
        raise IncidentEvidenceContractError(
            "exact query DSL does not match its wrapper digest"
        )


def _validate_result(
    raw_result: object,
    result_index: int,
    request: RequestContext,
    expected_pairs: set[tuple[int, str]],
    observed_pairs: set[tuple[int, str]],
    schema: str,
) -> tuple[str, bool | None]:
    result = require_mapping(raw_result, f"query result {result_index + 1}")
    pack = require_nonempty_text(result.get("pack"), "query pack")
    status = require_nonempty_text(result.get("status"), "query status")
    if status not in ALLOWED_STATUSES:
        raise IncidentEvidenceContractError(f"unsupported query status: {status}")
    window_index = result.get("window_index")
    if isinstance(window_index, bool) or not isinstance(window_index, int):
        raise IncidentEvidenceContractError(
            "query window_index must be an integer"
        )
    pair = (window_index, pack)
    if pair not in expected_pairs or pair in observed_pairs:
        raise IncidentEvidenceContractError(
            "query pack/window coverage is invalid or duplicated"
        )
    observed_pairs.add(pair)
    window = require_mapping(result.get("window"), "query window")
    requested_window = require_mapping(
        request.windows[window_index], "requested query window"
    )
    if window != requested_window:
        raise IncidentEvidenceContractError(
            "query result window does not match the request"
        )
    _validate_result_query(result, pack)
    semantic = None
    if schema == INCIDENT_EVIDENCE_CONTRACT:
        semantic = validate_search_result(
            result,
            label=f"{pack} query result",
            expected_scope=PACK_INDEX_SCOPES[pack],
            max_hits=request.result_size,
        )
    return status, semantic


def _validate_results(
    context: ArtifactContext, request: RequestContext
) -> tuple[list[str], list[bool]]:
    results = context.response.get("results")
    expected_count = len(request.packs) * len(request.windows)
    if not isinstance(results, list) or len(results) != expected_count:
        raise IncidentEvidenceContractError(
            "incident evidence response must contain "
            f"{expected_count} query result(s)"
        )
    expected_pairs = {
        (index, str(pack))
        for index in range(len(request.windows))
        for pack in request.packs
    }
    observed_pairs: set[tuple[int, str]] = set()
    statuses: list[str] = []
    semantic_results: list[bool] = []
    for index, raw_result in enumerate(results):
        status, semantic = _validate_result(
            raw_result,
            index,
            request,
            expected_pairs,
            observed_pairs,
            context.schema,
        )
        statuses.append(status)
        if semantic is not None:
            semantic_results.append(semantic)
    if observed_pairs != expected_pairs:
        raise IncidentEvidenceContractError(
            "query result coverage is incomplete"
        )
    return statuses, semantic_results


def _validate_semantic_flags(
    response: dict[str, Any],
    controls_valid: bool,
    query_execution_valid: bool,
    coverage_valid: bool,
    expected_complete: bool,
) -> None:
    validity = require_mapping(
        response.get("semantic_validity"), "semantic validity"
    )
    expected = {
        "transport_valid": True,
        "controls_valid": controls_valid,
        "query_execution_valid": query_execution_valid,
        "coverage_valid": coverage_valid,
        "semantic_valid": expected_complete,
    }
    for key, value in expected.items():
        if validity.get(key) is not value:
            raise IncidentEvidenceContractError(
                f"semantic validity {key} flag is inconsistent"
            )
    if not _semantic_reasons_match(
        validity.get("reasons"), expected_complete
    ):
        raise IncidentEvidenceContractError(
            "semantic validity reasons are inconsistent"
        )


def _semantic_reasons_match(reasons: object, complete: bool) -> bool:
    if not isinstance(reasons, list):
        return False
    if any(not isinstance(item, str) or not item.strip() for item in reasons):
        return False
    return not reasons if complete else bool(reasons)


def _expected_complete(
    context: ArtifactContext,
    request: RequestContext,
    statuses: list[str],
    semantic_results: list[bool],
) -> bool:
    if context.schema != INCIDENT_EVIDENCE_CONTRACT:
        return all(status == "ok" for status in statuses)
    osquery_statuses = validate_osquery_results(context.request, context.response)
    statuses.extend(osquery_statuses)
    controls_valid = validate_controls(request.anchor, context.response)
    query_execution_valid = all(semantic_results)
    coverage_valid = query_execution_valid and all(
        status == "ok" for status in osquery_statuses
    )
    complete = controls_valid and coverage_valid
    _validate_semantic_flags(
        context.response,
        controls_valid,
        query_execution_valid,
        coverage_valid,
        complete,
    )
    return complete


def validate_incident_evidence_artifact(artifact: object) -> dict[str, Any]:
    """Return a validated artifact while preserving explicit evidence gaps."""
    context = _artifact_context(artifact)
    request = _request_context(context)
    statuses, semantic_results = _validate_results(context, request)
    complete = _expected_complete(
        context, request, statuses, semantic_results
    )
    if context.response.get("complete") is not complete:
        raise IncidentEvidenceContractError(
            "response complete flag does not match query results"
        )
    if context.response.get("partial") is not (not complete):
        raise IncidentEvidenceContractError(
            "response partial flag does not match query results"
        )
    return context.artifact
