"""Digest, provenance, audit, and output-budget composition."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable


def execute_request(
    request: dict[str, Any],
    candidates: list[Any],
    *,
    source_views: list[str],
    scan_truncated: bool,
    contract: str,
    matches_indicator: Callable[[Any, str], bool],
    filter_matches: Callable[[Any, str, Any], bool],
    project_record: Callable[[str, Any], Any],
) -> dict[str, Any]:
    operation = request["operation"]
    filters = request["filters"]
    indicator = request["indicator"]
    limit = request["limit"]
    found: list[Any] = []
    seen: set[str] = set()
    matched = 0
    for candidate in candidates:
        if not matches_indicator(candidate, indicator):
            continue
        if not all(
            filter_matches(candidate, field, expected)
            for field, expected in filters.items()
        ):
            continue
        projected = project_record(operation, candidate)
        if projected in ({}, [], None, ""):
            continue
        fingerprint = canonical_json(projected, default_str=True)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        matched += 1
        if len(found) < limit:
            found.append(projected)
    query_digest = digest({"contract": contract, "request": request})
    return {
        "query": request,
        "query_digest": query_digest,
        "result_digest": digest(found),
        "evidence_ref": f"derived-pcap-zeek:{query_digest[:20]}",
        "records": found,
        "audit": {
            "candidate_records_scanned": len(candidates),
            "unique_records_matched": matched,
            "records_returned": len(found),
            "result_truncated": matched > len(found),
            "index_scan_truncated": scan_truncated,
            "derived_views_considered": source_views,
            "time_filter_requires_timestamped_record": bool(
                {"start_epoch", "end_epoch"}.intersection(filters)
            ),
        },
    }


def canonical_json(value: Any, *, default_str: bool = False) -> str:
    options = {"default": str} if default_str else {}
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        **options,
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def compose_payload(
    *,
    contract: str,
    executed: list[dict[str, Any]],
    results: list[dict[str, Any]],
    max_result_bytes: int,
    error: type[ValueError],
) -> dict[str, Any]:
    payload = {
        "schema": contract,
        "executed": executed,
        "results": results,
        "source": "sanitized-derived-pcap-evidence",
        "provenance": {
            "raw_pcap_access": False,
            "raw_payloads_included": False,
            "parser_or_shell_invocation": False,
            "network_access": False,
            "evidence_scope": (
                "bounded-derived-index; sampled or aggregated records are "
                "investigative leads, not completeness proof"
            ),
        },
    }
    if len(canonical_json(payload).encode("utf-8")) > max_result_bytes:
        raise error("PCAP evidence query result exceeded its output budget")
    return payload
