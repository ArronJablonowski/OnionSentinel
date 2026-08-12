"""Digest, semantic, timeout, and shard validation for bound query rows."""
from __future__ import annotations

import hmac
from typing import Any, Mapping

from harness_policy import DIGEST_RE


QUERY_SUCCESS_STATUSES = frozenset(
    {"ok", "complete", "completed", "success", "succeeded"}
)
SECURITY_ONION_QUERY_STATUSES = frozenset(
    {"ok", "timeout", "output_limit", "error", "invalid_response"}
)


def _normalized_status(value: Any) -> str:
    return str(value or "").strip().lower()[:40]


def _matching_digest(left: Any, right: Any) -> bool:
    left_digest = str(left or "").strip()
    right_digest = str(right or "").strip()
    return bool(
        DIGEST_RE.fullmatch(left_digest)
        and DIGEST_RE.fullmatch(right_digest)
        and hmac.compare_digest(left_digest, right_digest)
    )


def validated_nested_status(
    nested: Mapping[str, Any], audit: Mapping[str, Any]
) -> str | None:
    nested_status = _normalized_status(nested.get("status"))
    audit_status = _normalized_status(audit.get("status"))
    if (
        not nested_status
        or nested_status not in SECURITY_ONION_QUERY_STATUSES
        or nested_status != audit_status
        or not _matching_digest(
            nested.get("query_digest"), audit.get("query_digest")
        )
        or not _matching_digest(
            nested.get("result_digest"), audit.get("result_digest")
        )
    ):
        return None
    return nested_status


def semantic_binding_is_valid(
    nested: Mapping[str, Any], audit: Mapping[str, Any], nested_status: str
) -> bool:
    expected_semantic_valid = nested_status == "ok"
    return not (
        nested.get("semantic_valid") is not expected_semantic_valid
        or audit.get("semantic_valid") is not expected_semantic_valid
        or not isinstance(audit.get("timed_out"), bool)
        or (
            "timed_out" in nested
            and nested.get("timed_out") is not audit.get("timed_out")
        )
        or audit.get("timed_out") is not (nested_status == "timeout")
    )


def _valid_shard_count(value: Any, *, positive: bool = False) -> bool:
    return bool(
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
    )


def _skipped_within_successful(skipped: Any, successful: Any) -> bool:
    return bool(
        _valid_shard_count(skipped)
        and _valid_shard_count(successful)
        and skipped <= successful
    )


def successful_shards_are_valid(
    audit: Mapping[str, Any], nested_status: str
) -> bool:
    if nested_status not in QUERY_SUCCESS_STATUSES:
        return True
    shards = audit.get("shards") if isinstance(audit.get("shards"), Mapping) else None
    if not isinstance(shards, Mapping):
        return False
    shard_total = shards.get("total")
    shard_successful = shards.get("successful")
    shard_skipped = shards.get("skipped")
    shard_failed = shards.get("failed")
    checks = (
        _valid_shard_count(shard_total, positive=True),
        _valid_shard_count(shard_successful),
        shard_successful == shard_total,
        _skipped_within_successful(shard_skipped, shard_successful),
        _valid_shard_count(shard_failed),
        shard_failed == 0,
        shards.get("failures") == [],
    )
    return all(checks)
