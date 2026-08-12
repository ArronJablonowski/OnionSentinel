"""Trusted-context authorization of untrusted investigation proposals."""
from __future__ import annotations

import datetime as dt
from typing import Any

from investigation_query_schema import (
    ALLOWED_AGGREGATIONS,
    ALLOWED_DIALECTS,
    ALLOWED_PURPOSES,
    INVESTIGATION_QUERY_CONTRACT,
    INVESTIGATION_QUERY_OPERATION,
    MAX_BATCH_HITS,
    MAX_BATCH_OBSERVABLES,
    MAX_QUERIES,
    MAX_QUERY_HITS,
    MAX_QUERY_OBSERVABLES,
    MAX_WINDOW,
    OBSERVABLE_KINDS,
    PACKS,
    InvestigationQueryContractError,
    canonical_digest,
)
from investigation_query_normalization import (
    _event_tuple_authorization,
    _normalize_authorization_context,
    _normalize_event_tuple,
    _normalize_observables,
    _normalize_window,
    _observable_authorizations,
    _require_exact_keys,
    _require_mapping,
    _safe_id,
    tuple_match_semantics,
    validate_pack_observables,
)


def _proposal_root(proposal: object) -> tuple[dict[str, Any], list[object]]:
    proposed = _require_mapping(proposal, "investigation query proposal")
    _require_exact_keys(
        proposed,
        allowed={"query_contract", "batch_id", "queries"},
        required={"batch_id", "queries"},
        label="investigation query proposal",
    )
    if (
        "query_contract" in proposed
        and proposed["query_contract"] != INVESTIGATION_QUERY_CONTRACT
    ):
        raise InvestigationQueryContractError(
            "investigation query contract is unsupported"
        )
    queries = proposed["queries"]
    if not isinstance(queries, list) or not queries or len(queries) > MAX_QUERIES:
        raise InvestigationQueryContractError(
            f"investigation query proposal must contain 1-{MAX_QUERIES} queries"
        )
    return proposed, queries


def _proposal_query_root(raw_query: object, index: int) -> dict[str, Any]:
    query = _require_mapping(raw_query, f"investigation query {index}")
    _require_exact_keys(
        query,
        allowed={
            "query_id", "dialect", "pack", "purpose", "window",
            "observables", "event_tuple", "size", "aggregation",
        },
        required={
            "query_id", "dialect", "pack", "purpose", "window",
            "observables", "size", "aggregation",
        },
        label=f"investigation query {index}",
    )
    return query


def _proposal_query_identity(
    query: dict[str, Any], index: int, query_ids: set[str]
) -> tuple[str, str, str, str, str]:
    query_id = _safe_id(query["query_id"], f"investigation query {index} query_id")
    if query_id in query_ids:
        raise InvestigationQueryContractError("investigation query ids must be unique")
    query_ids.add(query_id)
    dialect = str(query["dialect"] or "").strip()
    pack = str(query["pack"] or "").strip()
    purpose = str(query["purpose"] or "").strip()
    aggregation = str(query["aggregation"] or "").strip()
    if dialect not in ALLOWED_DIALECTS:
        raise InvestigationQueryContractError("investigation dialect is unsupported")
    if pack not in PACKS:
        raise InvestigationQueryContractError("investigation pack is unsupported")
    if purpose not in ALLOWED_PURPOSES:
        raise InvestigationQueryContractError("investigation purpose is unsupported")
    if aggregation not in ALLOWED_AGGREGATIONS:
        raise InvestigationQueryContractError("investigation aggregation is unsupported")
    return query_id, dialect, pack, purpose, aggregation


def _proposal_query_window(
    query: dict[str, Any], query_id: str, context: dict[str, Any]
) -> tuple[dict[str, str], dt.timedelta]:
    window, start, end = _normalize_window(
        query["window"],
        label=f"investigation query {query_id} window",
        max_duration=MAX_WINDOW,
    )
    if start < context["_envelope_start"] or end > context["_envelope_end"]:
        raise InvestigationQueryContractError(
            f"investigation query {query_id} escapes its trusted time envelope"
        )
    return window, end - start


def _proposal_query_observables(
    query: dict[str, Any],
    query_id: str,
    pack: str,
    authorized_values: dict[tuple[str, str], dict[str, str]],
    used_authorizations: dict[tuple[str, str], dict[str, str]],
    batch_value_keys: set[tuple[str, str]],
) -> tuple[dict[str, list[str]], dict[str, list[dict[str, str]]]]:
    observables = _normalize_observables(
        query["observables"],
        per_kind_limit=MAX_QUERY_OBSERVABLES,
        total_limit=MAX_QUERY_OBSERVABLES,
        require_one=True,
        label=f"investigation query {query_id} observables",
    )
    validate_pack_observables(observables, pack, label=f"investigation query {query_id}")
    provenance: dict[str, list[dict[str, str]]] = {
        kind: [] for kind in OBSERVABLE_KINDS
    }
    for kind, values in observables.items():
        for observable in values:
            key = (kind, observable)
            authorization = authorized_values.get(key)
            if authorization is None:
                raise InvestigationQueryContractError(
                    f"investigation query {query_id} uses an observable "
                    "outside its trusted authorization context"
                )
            provenance[kind].append(dict(authorization))
            used_authorizations[key] = dict(authorization)
            batch_value_keys.add(key)
    return observables, provenance


def _proposal_query_event_tuple(
    query: dict[str, Any],
    query_id: str,
    context: dict[str, Any],
    pack: str,
    observables: dict[str, list[str]],
    used_authorizations: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if "event_tuple" not in query:
        return None, None
    event_tuple = _normalize_event_tuple(
        query["event_tuple"], label=f"investigation query {query_id} event_tuple"
    )
    provenance = _event_tuple_authorization(
        event_tuple,
        context,
        pack_name=pack,
        observables=observables,
        label=f"investigation query {query_id} event_tuple",
    )
    if provenance not in used_authorizations:
        used_authorizations.append(provenance)
    return event_tuple, provenance


def _proposal_query_size(query: dict[str, Any], aggregation: str) -> tuple[int, int]:
    try:
        size = int(query["size"])
    except (TypeError, ValueError) as exc:
        raise InvestigationQueryContractError(
            "investigation size must be an integer"
        ) from exc
    if isinstance(query["size"], bool) or size < 1 or size > MAX_QUERY_HITS:
        raise InvestigationQueryContractError(
            f"investigation size must be between 1 and {MAX_QUERY_HITS}"
        )
    return size, 0 if aggregation == "count" else size


def _clean_proposal_query(
    *,
    query_id: str,
    dialect: str,
    pack: str,
    purpose: str,
    window: dict[str, str],
    observables: dict[str, list[str]],
    provenance: dict[str, list[dict[str, str]]],
    size: int,
    aggregation: str,
    context: dict[str, Any],
    event_tuple: dict[str, Any] | None,
    tuple_provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    normalized = {
        "query_id": query_id,
        "dialect": dialect,
        "pack": pack,
        "purpose": purpose,
        "window": window,
        "observables": observables,
        "observable_provenance": provenance,
        "size": size,
        "aggregation": aggregation,
        "match_semantics": tuple_match_semantics(
            pack,
            event_tuple,
            tuple_provenance.get("role_semantics") if tuple_provenance else None,
        ),
    }
    if aggregation == "anchor_nearest":
        normalized["anchor_time"] = context["anchor_time"]
    if event_tuple is not None:
        normalized["event_tuple"] = event_tuple
        normalized["event_tuple_provenance"] = dict(tuple_provenance or {})
    return normalized


def _authorized_proposal_query(
    raw_query: object,
    index: int,
    context: dict[str, Any],
    authorized_values: dict[tuple[str, str], dict[str, str]],
    trackers: dict[str, Any],
) -> tuple[dict[str, Any], dt.timedelta, int]:
    query = _proposal_query_root(raw_query, index)
    query_id, dialect, pack, purpose, aggregation = _proposal_query_identity(
        query, index, trackers["query_ids"]
    )
    window, duration = _proposal_query_window(query, query_id, context)
    observables, provenance = _proposal_query_observables(
        query,
        query_id,
        pack,
        authorized_values,
        trackers["used_authorizations"],
        trackers["batch_value_keys"],
    )
    event_tuple, tuple_provenance = _proposal_query_event_tuple(
        query,
        query_id,
        context,
        pack,
        observables,
        trackers["used_event_tuple_authorizations"],
    )
    if aggregation == "anchor_nearest" and dialect != "elastic":
        raise InvestigationQueryContractError(
            "anchor_nearest is available only through compiled Elastic DSL"
        )
    size, hit_budget = _proposal_query_size(query, aggregation)
    normalized = _clean_proposal_query(
        query_id=query_id,
        dialect=dialect,
        pack=pack,
        purpose=purpose,
        window=window,
        observables=observables,
        provenance=provenance,
        size=size,
        aggregation=aggregation,
        context=context,
        event_tuple=event_tuple,
        tuple_provenance=tuple_provenance,
    )
    return normalized, duration, hit_budget


def _validate_proposal_budgets(
    batch_value_keys: set[tuple[str, str]], total_hits: int, total_window: dt.timedelta
) -> None:
    if len(batch_value_keys) > MAX_BATCH_OBSERVABLES:
        raise InvestigationQueryContractError(
            f"investigation batch exceeds {MAX_BATCH_OBSERVABLES} distinct observables"
        )
    if total_hits > MAX_BATCH_HITS:
        raise InvestigationQueryContractError(
            f"investigation batch exceeds its {MAX_BATCH_HITS}-hit budget"
        )
    if total_window > dt.timedelta(hours=96):
        raise InvestigationQueryContractError(
            "investigation batch exceeds its cumulative 96-hour window budget"
        )


def _proposal_authorization_manifest(
    context: dict[str, Any], trackers: dict[str, Any]
) -> dict[str, Any]:
    context_for_digest = {
        key: value for key, value in context.items() if not key.startswith("_")
    }
    authorization = {
        "context_id": context["context_id"],
        "case_id": context["case_id"],
        "group_id": context["group_id"],
        "actor_role": context["actor_role"],
        "anchor": context["anchor"],
        "anchor_time": context["anchor_time"],
        "time_envelope": context["time_envelope"],
        "context_digest": canonical_digest(context_for_digest),
        "observables": sorted(
            trackers["used_authorizations"].values(),
            key=lambda item: (item["kind"], item["value"], item["evidence_ref"]),
        ),
    }
    if trackers["used_event_tuple_authorizations"]:
        authorization["event_tuples"] = sorted(
            trackers["used_event_tuple_authorizations"], key=canonical_digest
        )
    authorization["manifest_digest"] = canonical_digest(authorization)
    return authorization


def authorize_investigation_query_request(
    proposal: object,
    authorization_context: object,
) -> dict[str, Any]:
    """Combine an untrusted model proposal with a trusted local context."""
    proposed, queries = _proposal_root(proposal)
    context = _normalize_authorization_context(authorization_context)
    authorized_values = _observable_authorizations(context)
    trackers: dict[str, Any] = {
        "query_ids": set(),
        "batch_value_keys": set(),
        "used_authorizations": {},
        "used_event_tuple_authorizations": [],
    }
    normalized_queries: list[dict[str, Any]] = []
    total_hits = 0
    total_window = dt.timedelta()
    for index, raw_query in enumerate(queries):
        normalized, duration, hit_budget = _authorized_proposal_query(
            raw_query, index, context, authorized_values, trackers
        )
        normalized_queries.append(normalized)
        total_window += duration
        total_hits += hit_budget
    _validate_proposal_budgets(
        trackers["batch_value_keys"], total_hits, total_window
    )
    authorization = _proposal_authorization_manifest(context, trackers)
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "operation": INVESTIGATION_QUERY_OPERATION,
        "batch_id": _safe_id(proposed["batch_id"], "investigation batch_id"),
        "authorization": authorization,
        "queries": normalized_queries,
    }
