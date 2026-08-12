"""Reauthentication of already-authorized investigation requests."""
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
    _iso_utc,
    _normalize_context_event_tuples,
    _normalize_event_tuple,
    _normalize_observables,
    _normalize_window,
    _require_exact_keys,
    _require_mapping,
    _safe_id,
    _validate_tuple_role_compatibility,
    pack_event_tuple_fields,
    tuple_match_semantics,
    validate_pack_observables,
)
from investigation_query_authorization_manifest import (
    _authorization_context,
    _authorization_observables,
    _authorized_request_root,
    _clean_authorization,
)


def _authorized_query_root(raw_query: object, index: int) -> dict[str, Any]:
    query = _require_mapping(raw_query, f"authorized query {index}")
    _require_exact_keys(
        query,
        allowed={
            "query_id", "dialect", "pack", "purpose", "window",
            "observables", "observable_provenance", "size", "aggregation",
            "event_tuple", "event_tuple_provenance", "match_semantics",
            "anchor_time",
        },
        required={
            "query_id", "dialect", "pack", "purpose", "window",
            "observables", "observable_provenance", "size", "aggregation",
            "match_semantics",
        },
        label=f"authorized query {index}",
    )
    return query


def _authorized_query_identity(
    query: dict[str, Any], index: int, query_ids: set[str]
) -> tuple[str, str, str, str, str]:
    query_id = _safe_id(query["query_id"], f"authorized query {index} query_id")
    if query_id in query_ids:
        raise InvestigationQueryContractError("authorized query ids must be unique")
    query_ids.add(query_id)
    dialect = str(query["dialect"] or "")
    pack = str(query["pack"] or "")
    purpose = str(query["purpose"] or "")
    aggregation = str(query["aggregation"] or "")
    if dialect not in ALLOWED_DIALECTS or pack not in PACKS:
        raise InvestigationQueryContractError(
            "authorized query dialect or pack is invalid"
        )
    if purpose not in ALLOWED_PURPOSES or aggregation not in ALLOWED_AGGREGATIONS:
        raise InvestigationQueryContractError(
            "authorized query purpose or aggregation is invalid"
        )
    return query_id, dialect, pack, purpose, aggregation


def _authorized_query_window_observables(
    query: dict[str, Any],
    query_id: str,
    pack: str,
    envelope_start: dt.datetime,
    envelope_end: dt.datetime,
) -> tuple[dict[str, str], dt.timedelta, dict[str, list[str]]]:
    window, start, end = _normalize_window(
        query["window"],
        label=f"authorized query {query_id} window",
        max_duration=MAX_WINDOW,
    )
    if start < envelope_start or end > envelope_end:
        raise InvestigationQueryContractError("authorized query escapes its time envelope")
    observables = _normalize_observables(
        query["observables"],
        per_kind_limit=MAX_QUERY_OBSERVABLES,
        total_limit=MAX_QUERY_OBSERVABLES,
        require_one=True,
        label=f"authorized query {query_id} observables",
    )
    validate_pack_observables(observables, pack, label=f"authorized query {query_id}")
    return window, end - start, observables


def _authorized_query_provenance(
    query: dict[str, Any],
    query_id: str,
    observables: dict[str, list[str]],
    authorized_values: dict[tuple[str, str], dict[str, str]],
    used_values: set[tuple[str, str]],
) -> dict[str, list[dict[str, str]]]:
    provenance = _require_mapping(
        query["observable_provenance"],
        f"authorized query {query_id} observable_provenance",
    )
    if set(provenance) != set(OBSERVABLE_KINDS):
        raise InvestigationQueryContractError(
            "authorized query observable provenance kinds are incomplete"
        )
    clean: dict[str, list[dict[str, str]]] = {}
    for kind in OBSERVABLE_KINDS:
        entries = provenance[kind]
        if not isinstance(entries, list):
            raise InvestigationQueryContractError(
                "authorized query observable provenance must be arrays"
            )
        expected = []
        for value in observables[kind]:
            entry = authorized_values.get((kind, value))
            if entry is None:
                raise InvestigationQueryContractError(
                    "authorized query uses an observable absent from its manifest"
                )
            expected.append(entry)
            used_values.add((kind, value))
        if entries != expected:
            raise InvestigationQueryContractError(
                "authorized query observable provenance does not match its manifest"
            )
        clean[kind] = [dict(item) for item in entries]
    return clean


def _authorized_tuple_provenance(
    query: dict[str, Any],
    query_id: str,
    pack: str,
    event_tuple: dict[str, Any],
    authorized_event_tuples: list[dict[str, Any]],
    used_digests: set[str],
) -> dict[str, Any]:
    provenance = _require_mapping(
        query["event_tuple_provenance"],
        f"authorized query {query_id} event_tuple_provenance",
    )
    if (
        provenance not in authorized_event_tuples
        or not all(
            provenance["event_tuple"].get(field) == value
            for field, value in event_tuple.items()
        )
    ):
        raise InvestigationQueryContractError(
            "authorized query event tuple provenance does not match its manifest"
        )
    trusted_ips = {"source_ip", "destination_ip"}.intersection(
        provenance["event_tuple"]
    )
    if trusted_ips and not trusted_ips.intersection(event_tuple):
        raise InvestigationQueryContractError(
            "authorized query event tuple dropped its trusted IP role"
        )
    _validate_tuple_role_compatibility(
        event_tuple,
        pack_name=pack,
        role_semantics=provenance["role_semantics"],
        label=f"authorized query {query_id} event_tuple",
    )
    used_digests.add(canonical_digest(provenance))
    return provenance


def _authorized_query_event_tuple(
    query: dict[str, Any],
    query_id: str,
    pack: str,
    observables: dict[str, list[str]],
    authorized_event_tuples: list[dict[str, Any]],
    used_digests: set[str],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    present = {
        field for field in ("event_tuple", "event_tuple_provenance") if field in query
    }
    if present and present != {"event_tuple", "event_tuple_provenance"}:
        raise InvestigationQueryContractError(
            "authorized query event tuple and provenance must be supplied together"
        )
    if not present:
        return None, None
    event_tuple = _normalize_event_tuple(
        query["event_tuple"], label=f"authorized query {query_id} event_tuple"
    )
    if set(event_tuple) - set(pack_event_tuple_fields(pack)):
        raise InvestigationQueryContractError(
            f"authorized query {query_id} event tuple is unsupported by its pack"
        )
    for field in ("source_ip", "destination_ip"):
        if field in event_tuple and event_tuple[field] not in observables["ips"]:
            raise InvestigationQueryContractError(
                "authorized query role-aware IP is absent from observables"
            )
    provenance = _authorized_tuple_provenance(
        query,
        query_id,
        pack,
        event_tuple,
        authorized_event_tuples,
        used_digests,
    )
    return event_tuple, provenance


def _authorized_query_semantics(
    query: dict[str, Any],
    query_id: str,
    dialect: str,
    pack: str,
    aggregation: str,
    anchor_time: dt.datetime,
    event_tuple: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
) -> str:
    expected_semantics = tuple_match_semantics(
        pack,
        event_tuple,
        provenance.get("role_semantics") if provenance else None,
    )
    if query["match_semantics"] != expected_semantics:
        raise InvestigationQueryContractError(
            f"authorized query {query_id} match semantics are invalid"
        )
    if aggregation == "anchor_nearest":
        if dialect != "elastic":
            raise InvestigationQueryContractError(
                "anchor_nearest is available only through compiled Elastic DSL"
            )
        if query.get("anchor_time") != _iso_utc(anchor_time):
            raise InvestigationQueryContractError(
                f"authorized query {query_id} anchor_time is invalid"
            )
    elif "anchor_time" in query:
        raise InvestigationQueryContractError(
            f"authorized query {query_id} unexpectedly supplied anchor_time"
        )
    return expected_semantics


def _authorized_query_size(
    query: dict[str, Any], aggregation: str
) -> tuple[int, int]:
    try:
        size = int(query["size"])
    except (TypeError, ValueError) as exc:
        raise InvestigationQueryContractError("authorized query size is invalid") from exc
    if isinstance(query["size"], bool) or size < 1 or size > MAX_QUERY_HITS:
        raise InvestigationQueryContractError("authorized query size is out of bounds")
    return size, 0 if aggregation == "count" else size


def _clean_authorized_query(
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
    semantics: str,
    anchor_time: dt.datetime,
    event_tuple: dict[str, Any] | None,
    tuple_provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    clean = {
        "query_id": query_id,
        "dialect": dialect,
        "pack": pack,
        "purpose": purpose,
        "window": window,
        "observables": observables,
        "observable_provenance": provenance,
        "size": size,
        "aggregation": aggregation,
        "match_semantics": semantics,
    }
    if aggregation == "anchor_nearest":
        clean["anchor_time"] = _iso_utc(anchor_time)
    if event_tuple is not None:
        clean["event_tuple"] = event_tuple
        clean["event_tuple_provenance"] = dict(tuple_provenance or {})
    return clean


def _authorized_query_evidence(
    query: dict[str, Any],
    query_id: str,
    pack: str,
    context: dict[str, Any],
    trackers: dict[str, Any],
) -> tuple[
    dict[str, str],
    dt.timedelta,
    dict[str, list[str]],
    dict[str, list[dict[str, str]]],
    dict[str, Any] | None,
    dict[str, Any] | None,
]:
    window, duration, observables = _authorized_query_window_observables(
        query, query_id, pack, context["envelope_start"], context["envelope_end"]
    )
    provenance = _authorized_query_provenance(
        query,
        query_id,
        observables,
        context["authorized_values"],
        trackers["used_values"],
    )
    event_tuple, tuple_provenance = _authorized_query_event_tuple(
        query,
        query_id,
        pack,
        observables,
        context["authorized_event_tuples"],
        trackers["used_event_tuple_digests"],
    )
    return (
        window, duration, observables, provenance,
        event_tuple, tuple_provenance,
    )


def _validated_authorized_query(
    raw_query: object,
    index: int,
    context: dict[str, Any],
    trackers: dict[str, Any],
) -> tuple[dict[str, Any], dt.timedelta, int]:
    query = _authorized_query_root(raw_query, index)
    query_id, dialect, pack, purpose, aggregation = _authorized_query_identity(
        query, index, trackers["query_ids"]
    )
    (
        window, duration, observables, clean_provenance,
        event_tuple, tuple_provenance,
    ) = _authorized_query_evidence(
        query, query_id, pack, context, trackers
    )
    semantics = _authorized_query_semantics(
        query,
        query_id,
        dialect,
        pack,
        aggregation,
        context["anchor_time"],
        event_tuple,
        tuple_provenance,
    )
    size, hit_budget = _authorized_query_size(query, aggregation)
    clean = _clean_authorized_query(
        query_id=query_id,
        dialect=dialect,
        pack=pack,
        purpose=purpose,
        window=window,
        observables=observables,
        provenance=clean_provenance,
        size=size,
        aggregation=aggregation,
        semantics=semantics,
        anchor_time=context["anchor_time"],
        event_tuple=event_tuple,
        tuple_provenance=tuple_provenance,
    )
    return clean, duration, hit_budget


def _authorized_queries(
    value: object, context: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any], int, dt.timedelta]:
    if not isinstance(value, list) or not value or len(value) > MAX_QUERIES:
        raise InvestigationQueryContractError(
            f"authorized request must contain 1-{MAX_QUERIES} queries"
        )
    trackers: dict[str, Any] = {
        "query_ids": set(),
        "used_values": set(),
        "used_event_tuple_digests": set(),
    }
    clean_queries: list[dict[str, Any]] = []
    total_hits = 0
    total_window = dt.timedelta()
    for index, raw_query in enumerate(value):
        clean, duration, hit_budget = _validated_authorized_query(
            raw_query, index, context, trackers
        )
        clean_queries.append(clean)
        total_hits += hit_budget
        total_window += duration
    return clean_queries, trackers, total_hits, total_window


def _validate_manifest_usage_and_budgets(
    context: dict[str, Any],
    trackers: dict[str, Any],
    total_hits: int,
    total_window: dt.timedelta,
) -> None:
    if trackers["used_values"] != set(context["authorized_values"]):
        raise InvestigationQueryContractError(
            "authorization manifest contains unused or missing observable entries"
        )
    expected_tuple_digests = {
        canonical_digest(item) for item in context["authorized_event_tuples"]
    }
    if trackers["used_event_tuple_digests"] != expected_tuple_digests:
        raise InvestigationQueryContractError(
            "authorization event tuple manifest contains unused or missing entries"
        )
    if total_hits > MAX_BATCH_HITS:
        raise InvestigationQueryContractError("authorized request exceeds its hit budget")
    if total_window > dt.timedelta(hours=96):
        raise InvestigationQueryContractError("authorized request exceeds its window budget")


def validate_authorized_investigation_query_request(payload: object) -> dict[str, Any]:
    """Validate and normalize the already-authorized forced-command payload."""
    request, authorization = _authorized_request_root(payload)
    envelope, start, end, actor_role, anchor_time = _authorization_context(
        authorization
    )
    authorized_values, clean_entries = _authorization_observables(authorization)
    authorized_event_tuples = _normalize_context_event_tuples(
        authorization.get("event_tuples"),
        limit=MAX_QUERIES,
        reject_duplicates=True,
    )
    context = {
        "envelope": envelope,
        "envelope_start": start,
        "envelope_end": end,
        "actor_role": actor_role,
        "anchor_time": anchor_time,
        "authorized_values": authorized_values,
        "clean_entries": clean_entries,
        "authorized_event_tuples": authorized_event_tuples,
    }
    clean_queries, trackers, total_hits, total_window = _authorized_queries(
        request["queries"], context
    )
    _validate_manifest_usage_and_budgets(
        context, trackers, total_hits, total_window
    )
    clean_authorization = _clean_authorization(authorization, context)
    return {
        "query_contract": INVESTIGATION_QUERY_CONTRACT,
        "operation": INVESTIGATION_QUERY_OPERATION,
        "batch_id": _safe_id(request["batch_id"], "investigation batch_id"),
        "authorization": clean_authorization,
        "queries": clean_queries,
    }
