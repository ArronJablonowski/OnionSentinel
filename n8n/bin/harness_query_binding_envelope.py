"""Admission and ordered selection for Security Onion batch query bindings."""
from __future__ import annotations

from typing import Any, Mapping

from harness_policy import DIGEST_RE


def outer_query_status(result: Mapping[str, Any]) -> str:
    return str(result.get("status") or "missing").strip().lower()[:40]


def _eligible_batch(result: Mapping[str, Any], outer_status: str) -> bool:
    return (
        outer_status in {"ok", "partial"}
        and str(result.get("backend") or "") == "security_onion"
        and result.get("read_only") is True
    )


def _admitted_evidence(
    result: Mapping[str, Any], outer_status: str, query_id: str
) -> tuple[Mapping[str, Any], list[str]] | None:
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
    if not _evidence_matches_outer(
        evidence, response_digest, query_ids, outer_status, query_id
    ):
        return None
    return evidence, query_ids


def _evidence_matches_outer(
    evidence: Mapping[str, Any] | None,
    response_digest: str,
    query_ids: list[str],
    outer_status: str,
    query_id: str,
) -> bool:
    return bool(
        DIGEST_RE.fullmatch(response_digest)
        and isinstance(evidence, Mapping)
        and evidence.get("read_only") is True
        and evidence.get("partial") is (outer_status == "partial")
        and evidence.get("complete") is (outer_status == "ok")
        and evidence.get("controls_valid") is True
        and query_ids
        and len(query_ids) == len(set(query_ids))
        and query_ids.count(query_id) == 1
    )


def _ordered_mapping_ids(values: list[Any]) -> list[str] | None:
    identifiers = [
        str(item.get("query_id") or "")
        for item in values
        if isinstance(item, Mapping)
    ]
    if len(identifiers) != len(values) or len(identifiers) != len(set(identifiers)):
        return None
    return identifiers


def _one_query(values: list[Any], query_id: str) -> Mapping[str, Any] | None:
    matching = [
        item
        for item in values
        if isinstance(item, Mapping)
        and str(item.get("query_id") or "") == query_id
    ]
    return matching[0] if len(matching) == 1 else None


def bound_query_objects(
    result: Mapping[str, Any], query_id: str, outer_status: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    if not _eligible_batch(result, outer_status):
        return None
    admitted = _admitted_evidence(result, outer_status, query_id)
    if admitted is None:
        return None
    evidence, query_ids = admitted
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
    nested_ids = _ordered_mapping_ids(nested_results)
    audit_ids = _ordered_mapping_ids(audits)
    if nested_ids != query_ids or audit_ids != query_ids:
        return None
    nested = _one_query(nested_results, query_id)
    audit = _one_query(audits, query_id)
    if nested is None or audit is None:
        return None
    return nested, audit
