"""Bounded traversal of ordinary collector-owned evidence trees."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


class ReferenceSink(Protocol):
    def add(self, reference: Any, **kwargs: Any) -> None: ...


@dataclass(frozen=True)
class Policy:
    success_statuses: frozenset[str]
    columnar_schema: str
    maximum_list_items: int = 1000


@dataclass(frozen=True)
class Dependencies:
    bounded_reference: Callable[[Any], str]
    result_bound_reference: Callable[..., tuple[str, str]]


RETURNED_KEYS = (
    "returned_hits", "returned_rows", "records_returned", "total_hits", "total_rows",
)


def _returned(value: dict[str, Any]) -> Any:
    return next(
        (value.get(key) for key in RETURNED_KEYS if value.get(key) not in (None, "")),
        None,
    )


def _source(path: tuple[str, ...], fallback: str) -> str:
    return ".".join(path[-3:]) or fallback


def _query_common(
    path: tuple[str, ...], status: Any, returned: Any,
    digest: str, policy: Policy,
) -> dict[str, Any]:
    return {
        "source": _source(path, "query"),
        "source_class": path[0] if path else "query",
        "corroborating": str(status or "").lower() in policy.success_statuses,
        "status": status, "returned": returned,
        "evidence_digest": digest, "require_valid_count": True,
    }


def _add_query_references(
    value: dict[str, Any], path: tuple[str, ...], sink: ReferenceSink,
    policy: Policy, deps: Dependencies, status: Any, returned: Any,
) -> None:
    digest = value.get("query_digest")
    if not digest:
        return
    result_digest = value.get("result_digest")
    query_ref, evidence_digest = deps.result_bound_reference(digest, result_digest)
    common = _query_common(path, status, returned, evidence_digest, policy)
    sink.add(query_ref, **common)
    pack = value.get("pack")
    if pack:
        pack_ref, _ = deps.result_bound_reference(
            digest, result_digest, namespace="pack", label=pack
        )
        sink.add(pack_ref, **common)
    query_id = value.get("query_id")
    if query_id:
        query_id_ref, _ = deps.result_bound_reference(
            digest, result_digest, namespace="query-id", label=query_id
        )
        sink.add(query_id_ref, **common)


def _add_evidence_reference(
    value: dict[str, Any], path: tuple[str, ...], sink: ReferenceSink,
    policy: Policy, deps: Dependencies, status: Any, returned: Any,
) -> None:
    evidence_ref = value.get("evidence_ref")
    if not evidence_ref:
        return
    digest = value.get("query_digest")
    result_digest = value.get("result_digest")
    normalized = deps.bounded_reference(evidence_ref)
    evidence_digest = result_digest
    if normalized.startswith("query:") and digest:
        normalized, evidence_digest = deps.result_bound_reference(digest, result_digest)
    sink.add(
        normalized, source=_source(path, "evidence"),
        source_class=path[0] if path else "evidence",
        corroborating=str(status or "ok").lower() in policy.success_statuses,
        status=status, returned=returned, evidence_digest=evidence_digest,
        require_valid_count=True,
    )


def _add_pcap_reference(
    value: dict[str, Any], sink: ReferenceSink,
    deps: Dependencies, status: Any, returned: Any,
) -> None:
    request_id = value.get("request_id")
    if not request_id:
        return
    sink.add(
        f"pcap_evidence:{deps.bounded_reference(request_id)}",
        source="pcap_evidence", source_class="pcap_evidence",
        corroborating=str(status or "").lower()
        in {"ok", "success", "completed", "fulfilled"},
        status=status, returned=returned, require_valid_count=True,
    )


def _nested_columnar_lookalike(value: dict[str, Any], policy: Policy) -> bool:
    return bool(
        value.get("prompt_projection")
        == "columnar_provenance_due_to_cumulative_byte_budget"
        or value.get("schema") == policy.columnar_schema
    )


def visit(
    value: Any, path: tuple[str, ...], sink: ReferenceSink,
    policy: Policy, deps: Dependencies,
) -> None:
    """Register bounded references while treating nested columnar lookalikes as inert."""
    if isinstance(value, list):
        for child in value[:policy.maximum_list_items]:
            visit(child, path, sink, policy, deps)
        return
    if not isinstance(value, dict) or _nested_columnar_lookalike(value, policy):
        return
    status = value.get("status")
    returned = _returned(value)
    _add_query_references(value, path, sink, policy, deps, status, returned)
    _add_evidence_reference(value, path, sink, policy, deps, status, returned)
    _add_pcap_reference(value, sink, deps, status, returned)
    for key, child in value.items():
        visit(child, (*path, str(key)), sink, policy, deps)
