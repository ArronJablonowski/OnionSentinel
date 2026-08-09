#!/usr/bin/env python3
"""Bound incident-evidence bodies while preserving auditable provenance."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _append_reason(projection: dict, reason: str) -> None:
    reasons = projection.get("reasons")
    if not isinstance(reasons, list):
        reasons = []
        projection["reasons"] = reasons
    if reason not in reasons:
        reasons.append(reason)


def _hit_projection(result: dict, hits: list) -> dict:
    projection = result.get("prompt_projection")
    if isinstance(projection, dict):
        return projection
    encoded = _canonical_bytes(hits)
    projection = {
        "version": 1,
        "source_returned_hits": int(result.get("returned_hits") or len(hits)),
        "source_total_hits": int(result.get("total_hits") or len(hits)),
        "source_truncated": bool(result.get("truncated")),
        "source_hits_bytes": len(encoded),
        "source_hits_sha256": hashlib.sha256(encoded).hexdigest(),
        "reasons": [],
    }
    result["prompt_projection"] = projection
    return projection


def _project_hit_result(result: dict, limit: int, reason: str) -> bool:
    hits = result.get("hits")
    if not isinstance(hits, list) or len(hits) <= limit:
        return False
    projection = _hit_projection(result, hits)
    _append_reason(projection, reason)
    retained = hits[:limit]
    result["hits"] = retained
    result["returned_hits"] = len(retained)
    total_hits = int(result.get("total_hits") or 0)
    result["truncated"] = (
        result.get("total_hits_relation") != "eq"
        or total_hits > len(retained)
    )
    retained_bytes = _canonical_bytes(retained)
    projection.update(
        {
            "retained_hits": len(retained),
            "retained_hits_bytes": len(retained_bytes),
            "retained_hits_sha256": hashlib.sha256(retained_bytes).hexdigest(),
        }
    )
    return True


def project_incident_evidence_hits(
    incident_evidence: dict,
    *,
    limit: int,
    reason: str,
) -> int:
    """Bound Elastic hit bodies and retain source/retained digests."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(
            "incident evidence hit projection limit must be non-negative"
        )
    response = incident_evidence.get("security_onion_response")
    results = response.get("results") if isinstance(response, dict) else None
    if not isinstance(results, list):
        return 0
    return sum(
        _project_hit_result(result, limit, reason)
        for result in results
        if isinstance(result, dict)
    )


def _validate_osquery_limits(
    limit: int,
    max_retained_bytes: int,
    max_row_bytes: int,
    reason: str,
) -> None:
    values = (
        (limit, "row limit"),
        (max_retained_bytes, "retained byte limit"),
        (max_row_bytes, "individual row byte limit"),
    )
    for value, label in values:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"incident evidence OSQuery {label} must be non-negative"
            )
    if not str(reason or "").strip() or len(str(reason)) > 100:
        raise ValueError(
            "incident evidence OSQuery projection reason must contain "
            "1 through 100 characters"
        )


def _retained_row_prefix(
    rows: list,
    limit: int,
    max_retained_bytes: int,
    max_row_bytes: int,
) -> list:
    retained = []
    for candidate in rows:
        if len(_canonical_bytes(candidate)) > max_row_bytes:
            break
        proposed = [*retained, candidate]
        if len(proposed) > limit:
            break
        if len(_canonical_bytes(proposed)) > max_retained_bytes:
            break
        retained = proposed
    return retained


def _osquery_projection(result: dict, rows: list) -> dict:
    projection = result.get("prompt_projection")
    if isinstance(projection, dict):
        return projection
    encoded = _canonical_bytes(rows)
    projection = {
        "version": 1,
        "source_returned_rows": int(result.get("returned_rows") or len(rows)),
        "source_total_rows": int(result.get("total_rows") or len(rows)),
        "source_truncated": bool(result.get("truncated")),
        "source_rows_bytes": len(encoded),
        "source_rows_sha256": hashlib.sha256(encoded).hexdigest(),
        "reasons": [],
    }
    result["prompt_projection"] = projection
    return projection


def _project_osquery_result(
    result: dict,
    *,
    limit: int,
    max_retained_bytes: int,
    max_row_bytes: int,
    reason: str,
) -> bool:
    rows = result.get("rows")
    if not isinstance(rows, list):
        return False
    retained = _retained_row_prefix(
        rows,
        limit,
        max_retained_bytes,
        max_row_bytes,
    )
    if len(retained) == len(rows):
        return False
    projection = _osquery_projection(result, rows)
    _append_reason(projection, reason)
    retained_bytes = _canonical_bytes(retained)
    result["rows"] = retained
    result["returned_rows"] = len(retained)
    result["truncated"] = int(result.get("total_rows") or 0) > len(retained)
    projection.update(
        {
            "retained_rows": len(retained),
            "retained_rows_bytes": len(retained_bytes),
            "retained_rows_sha256": hashlib.sha256(retained_bytes).hexdigest(),
            "max_retained_rows": limit,
            "max_retained_bytes": max_retained_bytes,
            "max_row_bytes": max_row_bytes,
        }
    )
    return True


def project_incident_evidence_osquery_rows(
    incident_evidence: dict,
    *,
    limit: int,
    max_retained_bytes: int,
    max_row_bytes: int,
    reason: str,
) -> int:
    """Bound OSQuery row bodies and retain exact row-set provenance."""
    _validate_osquery_limits(limit, max_retained_bytes, max_row_bytes, reason)
    response = incident_evidence.get("security_onion_response")
    results = (
        response.get("osquery_results") if isinstance(response, dict) else None
    )
    if not isinstance(results, list):
        return 0
    return sum(
        _project_osquery_result(
            result,
            limit=limit,
            max_retained_bytes=max_retained_bytes,
            max_row_bytes=max_row_bytes,
            reason=reason,
        )
        for result in results
        if isinstance(result, dict)
    )


def reject_preprojected_incident_evidence_source(
    incident_evidence: dict,
) -> None:
    """Reject collector input that already claims a prompt projection."""
    response = incident_evidence.get("security_onion_response")
    if not isinstance(response, dict):
        return
    for collection_name in ("results", "osquery_results"):
        results = response.get(collection_name)
        if not isinstance(results, list):
            continue
        if any(
            isinstance(result, dict) and "prompt_projection" in result
            for result in results
        ):
            raise ValueError(
                "raw incident evidence collector artifact must not contain "
                f"prompt_projection metadata in {collection_name}"
            )
