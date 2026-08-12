"""Fail-closed OSQuery result validation for incident evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from incident_evidence_primitives import (
    ALLOWED_STATUSES,
    MAX_OSQUERY_ROWS,
    OSQUERY_PACKS,
    OSQUERY_PROMPT_PROJECTION_FIELDS,
    SHA256_RE,
    query_digest,
)
from incident_evidence_validation import (
    IncidentEvidenceContractError,
    require_mapping,
    require_nonempty_text,
    require_nonnegative_int,
)


def _requested_packs(request: dict[str, Any]) -> list[str]:
    requested = request.get("osquery_packs")
    if not isinstance(requested, list) or not requested:
        raise IncidentEvidenceContractError(
            "incident evidence request has no OSquery packs"
        )
    names = [str(item) for item in requested]
    if len(names) != len(set(names)):
        raise IncidentEvidenceContractError(
            "incident evidence request contains duplicate OSquery packs"
        )
    if any(name not in OSQUERY_PACKS for name in names):
        raise IncidentEvidenceContractError(
            "incident evidence request contains an unsupported OSquery pack"
        )
    return names


def _validate_result_identity(
    result: dict[str, Any],
    requested_names: list[str],
    observed: set[str],
) -> tuple[str, str]:
    pack = require_nonempty_text(result.get("pack"), "OSquery pack")
    if pack not in requested_names or pack in observed:
        raise IncidentEvidenceContractError(
            "OSquery pack coverage is invalid or duplicated"
        )
    observed.add(pack)
    status = require_nonempty_text(result.get("status"), "OSquery status")
    if status not in ALLOWED_STATUSES:
        raise IncidentEvidenceContractError(f"unsupported OSquery status: {status}")
    target = require_nonempty_text(result.get("target"), "OSquery target")
    if target != "security-onion-local-host":
        raise IncidentEvidenceContractError(
            "OSquery target is not the Security Onion local host"
        )
    query = require_nonempty_text(result.get("query"), "exact OSquery SQL")
    if query != OSQUERY_PACKS[pack]:
        raise IncidentEvidenceContractError(
            "exact OSquery SQL does not match its reviewed pack"
        )
    digest = require_nonempty_text(result.get("query_digest"), "OSquery digest")
    if not SHA256_RE.fullmatch(digest) or query_digest(query) != digest:
        raise IncidentEvidenceContractError(
            "exact OSquery SQL does not match its wrapper digest"
        )
    return pack, status


def _validate_rows(
    result: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, int]:
    rows = result.get("rows")
    if not isinstance(rows, list) or len(rows) > MAX_OSQUERY_ROWS:
        raise IncidentEvidenceContractError(
            "OSquery rows exceed their result contract"
        )
    if any(not isinstance(row, dict) for row in rows):
        raise IncidentEvidenceContractError("OSquery rows must contain objects")
    returned, total = _validate_row_counts(result, rows)
    return rows, returned, total


def _validate_row_counts(
    result: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[int, int]:
    returned = result.get("returned_rows")
    if isinstance(returned, bool) or not isinstance(returned, int):
        raise IncidentEvidenceContractError(
            "OSquery returned_rows must be an integer"
        )
    if returned != len(rows):
        raise IncidentEvidenceContractError(
            "OSquery returned_rows does not match its row set"
        )
    total = result.get("total_rows")
    if isinstance(total, bool) or not isinstance(total, int) or total < returned:
        raise IncidentEvidenceContractError("OSquery total_rows is invalid")
    if result.get("truncated") is not (total > returned):
        raise IncidentEvidenceContractError(
            "OSquery truncated flag does not match its row counts"
        )
    return returned, total


def _projection_source_counts(
    projection: dict[str, Any], returned: int, total: int
) -> tuple[int, int]:
    source_returned = require_nonnegative_int(
        projection.get("source_returned_rows"),
        "OSquery prompt projection source_returned_rows",
    )
    source_total = require_nonnegative_int(
        projection.get("source_total_rows"),
        "OSquery prompt projection source_total_rows",
    )
    if (
        source_returned <= returned
        or source_returned > MAX_OSQUERY_ROWS
        or source_total != total
        or source_total < source_returned
    ):
        raise IncidentEvidenceContractError(
            "OSquery prompt projection source counts are inconsistent"
        )
    if projection.get("source_truncated") is not (source_total > source_returned):
        raise IncidentEvidenceContractError(
            "OSquery prompt projection source truncated flag is inconsistent"
        )
    return source_returned, source_total


def _projection_limits(projection: dict[str, Any]) -> tuple[int, int, int]:
    max_rows = require_nonnegative_int(
        projection.get("max_retained_rows"),
        "OSquery prompt projection max_retained_rows",
    )
    max_bytes = require_nonnegative_int(
        projection.get("max_retained_bytes"),
        "OSquery prompt projection max_retained_bytes",
    )
    max_row_bytes = require_nonnegative_int(
        projection.get("max_row_bytes"),
        "OSquery prompt projection max_row_bytes",
    )
    return max_rows, max_bytes, max_row_bytes


def _row_exceeds_limit(row: dict[str, Any], maximum: int) -> bool:
    encoded = json.dumps(row, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return len(encoded) > maximum


def _validate_projection_metadata(
    projection: dict[str, Any],
    rows: list[dict[str, Any]],
    returned: int,
) -> None:
    source_bytes = require_nonnegative_int(
        projection.get("source_rows_bytes"),
        "OSquery prompt projection source_rows_bytes",
    )
    if source_bytes < 2:
        raise IncidentEvidenceContractError(
            "OSquery prompt projection source byte count is invalid"
        )
    retained = require_nonnegative_int(
        projection.get("retained_rows"),
        "OSquery prompt projection retained_rows",
    )
    encoded = json.dumps(rows, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    retained_bytes = require_nonnegative_int(
        projection.get("retained_rows_bytes"),
        "OSquery prompt projection retained_rows_bytes",
    )
    retained_digest = projection.get("retained_rows_sha256")
    max_rows, max_bytes, max_row_bytes = _projection_limits(projection)
    if not _retained_rows_match(
        retained,
        returned,
        max_rows,
        source_bytes,
        retained_bytes,
        max_bytes,
        encoded,
        retained_digest,
    ) or any(
        _row_exceeds_limit(row, max_row_bytes) for row in rows
    ) or not _valid_projection_reasons(projection.get("reasons")):
        raise IncidentEvidenceContractError(
            "OSquery prompt projection metadata is inconsistent"
        )


def _retained_rows_match(
    retained: int,
    returned: int,
    max_rows: int,
    source_bytes: int,
    retained_bytes: int,
    max_bytes: int,
    encoded: bytes,
    retained_digest: object,
) -> bool:
    return bool(
        retained == returned
        and retained <= max_rows
        and source_bytes > retained_bytes
        and retained_bytes == len(encoded)
        and retained_bytes <= max_bytes
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


def _validate_prompt_projection(
    projection: object,
    rows: list[dict[str, Any]],
    returned: int,
    total: int,
) -> None:
    if projection is None:
        return
    projected = require_mapping(projection, "OSquery prompt projection")
    if set(projected) != OSQUERY_PROMPT_PROJECTION_FIELDS:
        raise IncidentEvidenceContractError(
            "OSquery prompt projection fields are invalid"
        )
    if projected.get("version") != 1:
        raise IncidentEvidenceContractError(
            "OSquery prompt projection version is invalid"
        )
    _projection_source_counts(projected, returned, total)
    source_digest = projected.get("source_rows_sha256")
    if not isinstance(source_digest, str) or not SHA256_RE.fullmatch(source_digest):
        raise IncidentEvidenceContractError(
            "OSquery prompt projection source digest is invalid"
        )
    _validate_projection_metadata(projected, rows, returned)


def _validate_result(
    raw_result: object,
    result_index: int,
    requested_names: list[str],
    observed: set[str],
) -> str:
    result = require_mapping(raw_result, f"OSquery result {result_index + 1}")
    _, status = _validate_result_identity(result, requested_names, observed)
    rows, returned, total = _validate_rows(result)
    _validate_prompt_projection(
        result.get("prompt_projection"), rows, returned, total
    )
    duration = result.get("duration_ms")
    if isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
        raise IncidentEvidenceContractError(
            "OSquery duration_ms must be a non-negative integer"
        )
    return status


def validate_osquery_results(
    request: dict[str, Any], response: dict[str, Any]
) -> list[str]:
    requested_names = _requested_packs(request)
    results = response.get("osquery_results")
    if not isinstance(results, list) or len(results) != len(requested_names):
        raise IncidentEvidenceContractError(
            "incident evidence response must contain "
            f"{len(requested_names)} OSquery result(s)"
        )
    observed: set[str] = set()
    statuses = [
        _validate_result(result, index, requested_names, observed)
        for index, result in enumerate(results)
    ]
    if observed != set(requested_names):
        raise IncidentEvidenceContractError(
            "OSquery result coverage is incomplete"
        )
    return statuses
