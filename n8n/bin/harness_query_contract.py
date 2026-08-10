"""Query-result observation and provenance-bound status resolution."""
from __future__ import annotations

import hmac
from typing import Any, Mapping, Sequence

from harness_policy import DIGEST_RE, MAX_EVENT_ITEMS


RETURNED_COUNT_KEYS = frozenset(
    {
        "returned",
        "returned_hits",
        "returned_rows",
        "records_returned",
        "total_hits",
        "total_rows",
    }
)


def observed_returned_count(value: Any, *, depth: int = 0) -> int | None:
    """Find an explicit bounded result count without inventing a zero or one."""
    if depth > 8:
        return None
    counts: list[int] = []
    if isinstance(value, Mapping):
        for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
            key = str(raw_key).strip().lower()
            if key in RETURNED_COUNT_KEYS and not isinstance(child, bool):
                try:
                    number = int(child)
                except (TypeError, ValueError, OverflowError):
                    number = -1
                if number >= 0:
                    counts.append(number)
            nested = observed_returned_count(child, depth=depth + 1)
            if nested is not None:
                counts.append(nested)
    elif isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        for child in list(value)[:MAX_EVENT_ITEMS]:
            nested = observed_returned_count(child, depth=depth + 1)
            if nested is not None:
                counts.append(nested)
    return max(counts) if counts else None


def observed_truncation(value: Any, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if isinstance(value, Mapping):
        for raw_key, child in list(value.items())[:MAX_EVENT_ITEMS]:
            key = str(raw_key).strip().lower()
            if (key == "truncated" or key.endswith("_truncated")) and child is True:
                return True
            if observed_truncation(child, depth=depth + 1):
                return True
    elif isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    ):
        return any(
            observed_truncation(child, depth=depth + 1)
            for child in list(value)[:MAX_EVENT_ITEMS]
        )
    return False


QUERY_SUCCESS_STATUSES = frozenset(
    {"ok", "complete", "completed", "success", "succeeded"}
)
SECURITY_ONION_QUERY_STATUSES = frozenset(
    {"ok", "timeout", "output_limit", "error", "invalid_response"}
)


def resolve_query_binding(
    result: Mapping[str, Any],
    query_id: str,
) -> tuple[str, Any]:
    """Resolve one durable tool status from a provenance-bound batch result.

    The Security Onion broker returns one envelope for a batch. A mixed batch
    is correctly marked ``partial`` even when some nested queries succeeded.
    A successful batch may likewise contain one model-projected result that
    was truncated while its other query results were complete. Copying either
    coarse status to every tool row loses per-query semantics and can
    incorrectly fail a controlled evaluation. Only unwrap an individual
    observation when the trusted response digest, semantic controls,
    per-query audit, and both query/result digests agree exactly.

    The caller must continue hashing the full outer result for durable result
    provenance. The returned observation is only for per-query status,
    coverage, and truncation semantics.
    """
    outer_status = str(result.get("status") or "missing").strip().lower()[:40]
    if (
        outer_status not in {"ok", "partial"}
        or str(result.get("backend") or "") != "security_onion"
        or result.get("read_only") is not True
    ):
        return outer_status, result

    response_digest = str(
        result.get("security_onion_response_digest") or ""
    ).strip()
    evidence = (
        result.get("evidence")
        if isinstance(result.get("evidence"), Mapping)
        else None
    )
    query_ids = (
        [str(value) for value in result.get("query_ids", [])]
        if isinstance(result.get("query_ids"), list)
        else []
    )
    if (
        not DIGEST_RE.fullmatch(response_digest)
        or not isinstance(evidence, Mapping)
        or evidence.get("read_only") is not True
        or evidence.get("partial") is not (outer_status == "partial")
        or evidence.get("complete") is not (outer_status == "ok")
        or evidence.get("controls_valid") is not True
        or not query_ids
        or len(query_ids) != len(set(query_ids))
        or query_ids.count(query_id) != 1
    ):
        return outer_status, result

    nested_results = (
        evidence.get("results")
        if isinstance(evidence.get("results"), list)
        else []
    )
    audits = (
        result.get("trusted_query_audit")
        if isinstance(result.get("trusted_query_audit"), list)
        else []
    )
    nested_ids = [
        str(item.get("query_id") or "")
        for item in nested_results
        if isinstance(item, Mapping)
    ]
    audit_ids = [
        str(item.get("query_id") or "")
        for item in audits
        if isinstance(item, Mapping)
    ]
    if (
        len(nested_ids) != len(nested_results)
        or len(audit_ids) != len(audits)
        or nested_ids != query_ids
        or audit_ids != query_ids
        or len(nested_ids) != len(set(nested_ids))
        or len(audit_ids) != len(set(audit_ids))
    ):
        return outer_status, result
    matching_results = [
        item
        for item in nested_results
        if isinstance(item, Mapping)
        and str(item.get("query_id") or "") == query_id
    ]
    matching_audits = [
        item
        for item in audits
        if isinstance(item, Mapping)
        and str(item.get("query_id") or "") == query_id
    ]
    if len(matching_results) != 1 or len(matching_audits) != 1:
        return outer_status, result
    nested = matching_results[0]
    audit = matching_audits[0]

    nested_status = str(nested.get("status") or "").strip().lower()[:40]
    audit_status = str(audit.get("status") or "").strip().lower()[:40]
    nested_query_digest = str(
        nested.get("query_digest") or ""
    ).strip()
    audit_query_digest = str(
        audit.get("query_digest") or ""
    ).strip()
    nested_result_digest = str(
        nested.get("result_digest") or ""
    ).strip()
    audit_result_digest = str(
        audit.get("result_digest") or ""
    ).strip()
    if (
        not nested_status
        or nested_status not in SECURITY_ONION_QUERY_STATUSES
        or nested_status != audit_status
        or not DIGEST_RE.fullmatch(nested_query_digest)
        or not DIGEST_RE.fullmatch(audit_query_digest)
        or not hmac.compare_digest(nested_query_digest, audit_query_digest)
        or not DIGEST_RE.fullmatch(nested_result_digest)
        or not DIGEST_RE.fullmatch(audit_result_digest)
        or not hmac.compare_digest(nested_result_digest, audit_result_digest)
    ):
        return outer_status, result

    observation = {"result": nested, "audit": audit}
    expected_semantic_valid = nested_status == "ok"
    if (
        nested.get("semantic_valid") is not expected_semantic_valid
        or audit.get("semantic_valid") is not expected_semantic_valid
        or not isinstance(audit.get("timed_out"), bool)
        or (
            "timed_out" in nested
            and nested.get("timed_out") is not audit.get("timed_out")
        )
        or audit.get("timed_out") is not (nested_status == "timeout")
    ):
        return outer_status, observation
    if nested_status in QUERY_SUCCESS_STATUSES:
        shards = (
            audit.get("shards")
            if isinstance(audit.get("shards"), Mapping)
            else None
        )
        shard_total = (
            shards.get("total")
            if isinstance(shards, Mapping)
            else None
        )
        shard_successful = (
            shards.get("successful")
            if isinstance(shards, Mapping)
            else None
        )
        shard_skipped = (
            shards.get("skipped")
            if isinstance(shards, Mapping)
            else None
        )
        shard_failed = (
            shards.get("failed")
            if isinstance(shards, Mapping)
            else None
        )
        if (
            not isinstance(shard_total, int)
            or isinstance(shard_total, bool)
            or shard_total <= 0
            or not isinstance(shard_successful, int)
            or isinstance(shard_successful, bool)
            or shard_successful != shard_total
            or not isinstance(shard_skipped, int)
            or isinstance(shard_skipped, bool)
            or shard_skipped < 0
            or shard_skipped > shard_successful
            or not isinstance(shard_failed, int)
            or isinstance(shard_failed, bool)
            or shard_failed != 0
            or shards.get("failures") != []
        ):
            return outer_status, observation
    return nested_status, observation

