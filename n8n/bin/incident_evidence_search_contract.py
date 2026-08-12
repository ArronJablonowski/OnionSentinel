"""Fail-closed Elasticsearch result validation for incident evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from incident_evidence_primitives import (
    ALLOWED_STATUSES,
    ELASTIC_PROMPT_PROJECTION_FIELDS,
    SAFE_ELASTIC_ID_RE,
    SHA256_RE,
    canonical_dsl_digest,
    canonical_execution_digest,
    index_matches_scope,
    query_endpoint,
)
from incident_evidence_validation import (
    IncidentEvidenceContractError,
    require_mapping,
    require_nonempty_text,
    require_nonnegative_int,
)


def _validate_query_identity(
    result: dict[str, Any],
    label: str,
    expected_scope: list[str],
) -> tuple[str, list[str], str]:
    status = require_nonempty_text(result.get("status"), f"{label} status")
    if status not in ALLOWED_STATUSES:
        raise IncidentEvidenceContractError(f"unsupported {label} status: {status}")
    index_scope = result.get("index_scope")
    if index_scope != expected_scope:
        raise IncidentEvidenceContractError(
            f"{label} index scope does not match its reviewed pack"
        )
    endpoint = require_nonempty_text(
        result.get("query_endpoint"), f"{label} query endpoint"
    )
    if endpoint != query_endpoint(expected_scope):
        raise IncidentEvidenceContractError(
            f"{label} query endpoint is outside its reviewed index scope"
        )
    query_dsl = require_mapping(
        result.get("query_dsl"), f"{label} exact query DSL"
    )
    if not query_dsl:
        raise IncidentEvidenceContractError(
            f"{label} exact query DSL must be non-empty"
        )
    digest = require_nonempty_text(
        result.get("query_digest"), f"{label} query digest"
    )
    if not SHA256_RE.fullmatch(digest) or canonical_dsl_digest(query_dsl) != digest:
        raise IncidentEvidenceContractError(
            f"{label} exact query DSL does not match its wrapper digest"
        )
    execution_digest = require_nonempty_text(
        result.get("execution_digest"), f"{label} execution digest"
    )
    if (
        not SHA256_RE.fullmatch(execution_digest)
        or canonical_execution_digest(query_dsl, index_scope, endpoint)
        != execution_digest
    ):
        raise IncidentEvidenceContractError(
            f"{label} query DSL/index execution manifest does not match its wrapper digest"
        )
    return status, index_scope, endpoint


def _validate_hits(
    result: dict[str, Any],
    label: str,
    expected_scope: list[str],
    max_hits: int,
) -> tuple[list[dict[str, Any]], int, int, str]:
    hits = result.get("hits")
    if not isinstance(hits, list) or len(hits) > max_hits:
        raise IncidentEvidenceContractError(
            f"{label} hits exceed their result contract"
        )
    for item in hits:
        _validate_hit(item, label, expected_scope)
    returned, total, relation = _validate_hit_counts(result, label, hits)
    return hits, returned, total, relation


def _validate_hit(item: object, label: str, expected_scope: list[str]) -> None:
    hit = require_mapping(item, f"{label} hit")
    document_id = require_nonempty_text(hit.get("id"), f"{label} hit id")
    index_name = require_nonempty_text(hit.get("index"), f"{label} hit index")
    if not SAFE_ELASTIC_ID_RE.fullmatch(document_id):
        raise IncidentEvidenceContractError(f"{label} hit id is invalid")
    if not index_matches_scope(index_name, expected_scope):
        raise IncidentEvidenceContractError(
            f"{label} returned an out-of-scope hit index"
        )
    require_mapping(hit.get("source"), f"{label} hit source")


def _validate_hit_counts(
    result: dict[str, Any], label: str, hits: list[dict[str, Any]]
) -> tuple[int, int, str]:
    returned = require_nonnegative_int(
        result.get("returned_hits"), f"{label} returned_hits"
    )
    total = require_nonnegative_int(
        result.get("total_hits"), f"{label} total_hits"
    )
    if returned != len(hits) or total < returned:
        raise IncidentEvidenceContractError(
            f"{label} hit counts do not match its result set"
        )
    relation = result.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise IncidentEvidenceContractError(
            f"{label} total_hits_relation is invalid"
        )
    expected_truncated = relation != "eq" or total > returned
    if result.get("truncated") is not expected_truncated:
        raise IncidentEvidenceContractError(
            f"{label} truncated flag does not match its hit counts"
        )
    return returned, total, relation


def _validate_projection_counts(
    projection: dict[str, Any],
    label: str,
    returned: int,
    total: int,
    relation: str,
    max_hits: int,
) -> tuple[int, int]:
    source_returned = require_nonnegative_int(
        projection.get("source_returned_hits"),
        f"{label} prompt projection source_returned_hits",
    )
    source_total = require_nonnegative_int(
        projection.get("source_total_hits"),
        f"{label} prompt projection source_total_hits",
    )
    if (
        source_returned <= returned
        or source_returned > max_hits
        or source_total != total
        or source_total < source_returned
    ):
        raise IncidentEvidenceContractError(
            f"{label} prompt projection source counts are inconsistent"
        )
    expected_truncated = relation != "eq" or source_total > source_returned
    if projection.get("source_truncated") is not expected_truncated:
        raise IncidentEvidenceContractError(
            f"{label} prompt projection source truncated flag is inconsistent"
        )
    return source_returned, source_total


def _validate_prompt_projection(
    projection: object,
    *,
    label: str,
    hits: list[dict[str, Any]],
    returned: int,
    total: int,
    relation: str,
    max_hits: int,
) -> None:
    if projection is None:
        return
    projected = _validated_projection_object(projection, label)
    _validate_projection_counts(
        projected, label, returned, total, relation, max_hits
    )
    source_digest = projected.get("source_hits_sha256")
    if not isinstance(source_digest, str) or not SHA256_RE.fullmatch(source_digest):
        raise IncidentEvidenceContractError(
            f"{label} prompt projection source digest is invalid"
        )
    source_bytes = require_nonnegative_int(
        projected.get("source_hits_bytes"),
        f"{label} prompt projection source_hits_bytes",
    )
    retained = require_nonnegative_int(
        projected.get("retained_hits"),
        f"{label} prompt projection retained_hits",
    )
    encoded = json.dumps(hits, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    retained_bytes = require_nonnegative_int(
        projected.get("retained_hits_bytes"),
        f"{label} prompt projection retained_hits_bytes",
    )
    retained_digest = projected.get("retained_hits_sha256")
    if not _retained_projection_matches(
        retained,
        returned,
        source_bytes,
        retained_bytes,
        encoded,
        retained_digest,
    ) or not _valid_projection_reasons(projected.get("reasons")):
        raise IncidentEvidenceContractError(
            f"{label} prompt projection metadata is inconsistent"
        )


def _validated_projection_object(
    projection: object, label: str
) -> dict[str, Any]:
    projected = require_mapping(projection, f"{label} prompt projection")
    if set(projected) != ELASTIC_PROMPT_PROJECTION_FIELDS:
        raise IncidentEvidenceContractError(
            f"{label} prompt projection fields are invalid"
        )
    if projected.get("version") != 1:
        raise IncidentEvidenceContractError(
            f"{label} prompt projection version is invalid"
        )
    return projected


def _retained_projection_matches(
    retained: int,
    returned: int,
    source_bytes: int,
    retained_bytes: int,
    encoded: bytes,
    retained_digest: object,
) -> bool:
    return bool(
        retained == returned
        and source_bytes > retained_bytes
        and retained_bytes == len(encoded)
        and isinstance(retained_digest, str)
        and SHA256_RE.fullmatch(retained_digest)
        and hashlib.sha256(encoded).hexdigest() == retained_digest
    )


def _valid_projection_reasons(reasons: object) -> bool:
    return bool(
        isinstance(reasons, list)
        and reasons
        and all(
            isinstance(reason, str)
            and bool(reason.strip())
            and len(reason) <= 100
            for reason in reasons
        )
    )


def _validate_runtime(
    result: dict[str, Any], label: str
) -> tuple[bool, int, int, int]:
    require_nonnegative_int(result.get("duration_ms"), f"{label} duration_ms")
    timed_out = result.get("timed_out")
    if not isinstance(timed_out, bool):
        raise IncidentEvidenceContractError(
            f"{label} timed_out must be boolean"
        )
    require_nonnegative_int(result.get("took_ms"), f"{label} took_ms")
    shards = require_mapping(result.get("shards"), f"{label} shards")
    total = require_nonnegative_int(shards.get("total"), f"{label} shard total")
    successful = require_nonnegative_int(
        shards.get("successful"), f"{label} successful shards"
    )
    failed = require_nonnegative_int(
        shards.get("failed"), f"{label} failed shards"
    )
    require_nonnegative_int(shards.get("skipped"), f"{label} skipped shards")
    failures = shards.get("failures")
    if not isinstance(failures, list) or any(
        not isinstance(item, dict) for item in failures
    ):
        raise IncidentEvidenceContractError(
            f"{label} shard failures must be an array of objects"
        )
    if failed > total or successful > total:
        raise IncidentEvidenceContractError(
            f"{label} shard counts are inconsistent"
        )
    return timed_out, total, successful, failed


def validate_search_result(
    result: dict[str, Any],
    *,
    label: str,
    expected_scope: list[str],
    max_hits: int,
) -> bool:
    status, _, _ = _validate_query_identity(result, label, expected_scope)
    hits, returned, total, relation = _validate_hits(
        result, label, expected_scope, max_hits
    )
    _validate_prompt_projection(
        result.get("prompt_projection"),
        label=label,
        hits=hits,
        returned=returned,
        total=total,
        relation=relation,
        max_hits=max_hits,
    )
    timed_out, total_shards, successful_shards, failed_shards = _validate_runtime(
        result, label
    )
    expected_valid = (
        status == "ok"
        and not timed_out
        and failed_shards == 0
        and total_shards > 0
        and successful_shards > 0
    )
    if result.get("semantic_valid") is not expected_valid:
        raise IncidentEvidenceContractError(
            f"{label} semantic_valid flag is inconsistent"
        )
    if status != "ok" and hits:
        raise IncidentEvidenceContractError(
            f"{label} failed response must not expose partial hits"
        )
    return expected_valid
