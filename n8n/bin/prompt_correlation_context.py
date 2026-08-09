#!/usr/bin/env python3
"""Build bounded cross-alert correlation context for investigation prompts.

The module owns read-only correlation projection. Database access and trusted
fact/scoring helpers are injected so the prompt-builder entry point remains a
composition root rather than a second implementation of correlation policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class CorrelationContextSources:
    """Trusted read and projection ports used by correlation context."""

    rows: Callable[[sqlite3.Connection, str, Iterable[object]], list[sqlite3.Row]]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]
    row_value: Callable[..., object]
    observable_weight: Callable[[str, str], int]
    time_bonus: Callable[[object, object], tuple[int, str | None]]
    row_facts: Callable[[sqlite3.Row | dict], dict[str, Any]]
    relationships: Callable[[dict[str, Any], dict[str, Any]], list[dict[str, Any]]]
    safe_int: Callable[[object], int]
    max_raw_json_bytes: int


def _empty_context(
    group_id: str | None,
    limit: int,
    min_score: int,
    status: str,
) -> dict:
    return {
        "selected_group_id": group_id,
        "candidates": [],
        "candidate_limit": limit,
        "minimum_score": min_score,
        "status": status,
    }


def _load_observable_candidates(sources, conn, selected_group_id: str):
    matches = sources.rows(
        conn,
        """
        SELECT related.group_id,
               selected.observable_type,
               selected.observable_value,
               selected.role AS selected_role,
               related.role AS related_role
        FROM alert_observables AS selected
        JOIN alert_observables AS related
          ON related.observable_type = selected.observable_type
         AND related.observable_value = selected.observable_value
         AND related.group_id != selected.group_id
        WHERE selected.group_id = ?
        LIMIT 4000
        """,
        [selected_group_id],
    )
    candidates: dict[str, dict] = {}
    for match in matches:
        group_id = str(match["group_id"] or "")
        observable_type = str(match["observable_type"] or "")
        observable_value = str(match["observable_value"] or "")
        key = (
            observable_type,
            observable_value,
            str(match["selected_role"] or ""),
            str(match["related_role"] or ""),
        )
        candidate = candidates.setdefault(
            group_id,
            {"matches": {}, "persisted": None},
        )
        candidate["matches"][key] = sources.observable_weight(
            observable_type,
            observable_value,
        )
    return candidates


def _load_persisted_candidates(sources, conn, selected_group_id: str):
    return sources.rows(
        conn,
        """
        SELECT source_group_id, related_group_id, correlation_score,
               reasons_json, shared_observables_json, model_status,
               model_confidence, model_hypothesis, updated_at
        FROM alert_correlations
        WHERE source_group_id = ? OR related_group_id = ?
        ORDER BY correlation_score DESC, updated_at DESC
        LIMIT 100
        """,
        [selected_group_id, selected_group_id],
    )


def _attach_persisted_candidates(candidates, persisted, selected_group_id):
    for item in persisted:
        source_id = str(item["source_group_id"] or "")
        related_id = str(item["related_group_id"] or "")
        group_id = related_id if source_id == selected_group_id else source_id
        if not group_id or group_id == selected_group_id:
            continue
        candidate = candidates.setdefault(
            group_id,
            {"matches": {}, "persisted": None},
        )
        candidate["persisted"] = dict(item)


def _load_candidate_data(sources, conn, selected_group_id: str) -> dict[str, dict]:
    candidates = _load_observable_candidates(sources, conn, selected_group_id)
    persisted = _load_persisted_candidates(sources, conn, selected_group_id)
    _attach_persisted_candidates(candidates, persisted, selected_group_id)
    return candidates


def _rank_candidate_ids(candidate_data: dict[str, dict]) -> list[str]:
    def ranking_score(group_id: str) -> int:
        candidate = candidate_data[group_id]
        persisted = candidate["persisted"] or {}
        return max(
            sum(candidate["matches"].values()),
            int(float(persisted.get("correlation_score") or 0)),
        )

    return sorted(candidate_data, key=ranking_score, reverse=True)[:100]


def _representative_query_parts(alert_columns: set[str]) -> tuple[str, str, str]:
    optional_projection = ", ".join(
        name if name in alert_columns else f"NULL AS {name}"
        for name in ("source_port", "network_protocol")
    )
    timestamp_projection = (
        "timestamp" if "timestamp" in alert_columns else "NULL AS timestamp"
    )
    time_value_sql = (
        "COALESCE(last_seen, timestamp, first_seen)"
        if "timestamp" in alert_columns
        else "COALESCE(last_seen, first_seen)"
    )
    normalized_time_sql = (
        "julianday(replace(replace("
        f"{time_value_sql}, '  ', ' '), 'T', ' '))"
    )
    return optional_projection, timestamp_projection, normalized_time_sql


def _load_representatives(sources, conn, ranked_ids: list[str]):
    placeholders = ",".join("?" for _ in ranked_ids)
    alert_columns = sources.table_columns(conn, "alerts")
    optional, timestamp, normalized_time = _representative_query_parts(
        alert_columns
    )
    found = sources.rows(
        conn,
        f"""
        WITH ranked_candidates AS (
          SELECT alert_id, stable_group_id, last_seen, first_seen,
                 {timestamp}, rule_name, source_ip, destination_ip,
                 destination_port, transport_protocol, triage_level,
                 triage_score, filter_status, seen_count,
                 {optional},
                 ROW_NUMBER() OVER (
                   PARTITION BY stable_group_id
                   ORDER BY {normalized_time} DESC, alert_id DESC
                 ) AS correlation_rank
          FROM alerts
          WHERE stable_group_id IN ({placeholders})
        )
        SELECT *
        FROM ranked_candidates
        WHERE correlation_rank = 1
        ORDER BY {normalized_time} DESC, alert_id DESC
        LIMIT 100
        """,
        ranked_ids,
    )
    representatives: dict[str, dict] = {}
    for item in found:
        representatives.setdefault(str(item["stable_group_id"] or ""), dict(item))
    _attach_bounded_raw_json(
        sources,
        conn,
        representatives,
        alert_columns,
    )
    return representatives, placeholders


def _attach_bounded_raw_json(
    sources,
    conn,
    representatives: dict[str, dict],
    alert_columns: set[str],
) -> None:
    representative_ids = [
        str(item.get("alert_id") or "")
        for item in representatives.values()
        if item.get("alert_id")
    ][:100]
    if not representative_ids or not {
        "alert_json",
        "raw_event_json",
    }.intersection(alert_columns):
        return
    placeholders = ",".join("?" for _ in representative_ids)
    raw_projection = _raw_json_projection(
        alert_columns,
        sources.max_raw_json_bytes,
    )
    raw_by_id = _load_bounded_raw_json(
        sources,
        conn,
        representative_ids,
        placeholders,
        raw_projection,
    )
    for item in representatives.values():
        raw_item = raw_by_id.get(str(item.get("alert_id") or ""), {})
        item["alert_json"] = raw_item.get("alert_json")
        item["raw_event_json"] = raw_item.get("raw_event_json")


def _raw_json_projection(alert_columns: set[str], maximum_bytes: int) -> str:
    def projection(name: str) -> str:
        if name not in alert_columns:
            return f"NULL AS {name}"
        return (
            "CASE WHEN length(CAST("
            f"{name} AS BLOB)) <= {maximum_bytes} "
            f"THEN {name} ELSE NULL END AS {name}"
        )

    return ", ".join(
        projection(name) for name in ("alert_json", "raw_event_json")
    )


def _load_bounded_raw_json(
    sources,
    conn,
    representative_ids,
    placeholders,
    raw_projection,
) -> dict[str, dict]:
    raw_by_id = {
        str(item["alert_id"]): dict(item)
        for item in sources.rows(
            conn,
            f"""
            SELECT alert_id, {raw_projection}
            FROM alerts
            WHERE alert_id IN ({placeholders})
            LIMIT 100
            """,
            representative_ids,
        )
    }
    return raw_by_id


def _load_prior_analysis(sources, conn, ranked_ids, placeholders):
    analysis_rows = sources.rows(
        conn,
        f"""
        SELECT analysis_id, group_id, generated_at, model, detection_outcome,
               bluf, summary, confidence
        FROM ai_analysis_runs
        WHERE group_id IN ({placeholders})
        ORDER BY generated_at DESC, analysis_id DESC
        """,
        ranked_ids,
    )
    prior: dict[str, dict] = {}
    for item in analysis_rows:
        prior.setdefault(str(item["group_id"] or ""), dict(item))
    return prior


def _shared_observables(candidate: dict) -> list[dict]:
    return [
        {
            "type": key[0],
            "value": key[1],
            "selected_role": key[2],
            "related_role": key[3],
            "weight": weight,
        }
        for key, weight in sorted(
            candidate["matches"].items(),
            key=lambda pair: (-pair[1], pair[0]),
        )
    ]


def _relationship_reasons(relationships: list[dict]) -> list[str]:
    labels = {
        "same_community_id": "same collector-observed Community ID",
        "reversed_five_tuple": "collector-observed reversed five-tuple",
        "dns_answer_to_destination": (
            "same-client DNS answer followed by a connection to that IP"
        ),
    }
    return [
        labels.get(
            str(relationship.get("kind") or ""),
            "deterministic alert relationship",
        )
        for relationship in relationships
    ]


def _correlation_score(sources, shared, persisted, relationships, time_score):
    relationship_score = max(
        (
            sources.safe_int(relationship.get("weight"))
            + min(time_score, 10)
            for relationship in relationships
        ),
        default=0,
    )
    return min(
        100,
        max(
            min(80, sum(match["weight"] for match in shared)) + time_score,
            int(float(persisted.get("correlation_score") or 0)),
            relationship_score,
        ),
    )


def _correlation_reasons(shared, relationships, time_reason, persisted):
    reasons = [f"shared {match['type']}: {match['value']}" for match in shared[:8]]
    reasons.extend(_relationship_reasons(relationships))
    if time_reason:
        reasons.append(time_reason)
    if persisted:
        reasons.append("previous correlation record exists")
    return reasons


PUBLIC_ALERT_FIELDS = (
    "alert_id",
    "stable_group_id",
    "last_seen",
    "first_seen",
    "rule_name",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "network_protocol",
    "transport_protocol",
    "triage_level",
    "triage_score",
    "filter_status",
    "seen_count",
)


def _project_candidate(
    sources,
    selected,
    selected_facts,
    group_id,
    item,
    data,
    prior_analysis,
) -> dict:
    shared = _shared_observables(data)
    time_score, time_reason = sources.time_bonus(
        sources.row_value(selected, "last_seen"),
        item.get("last_seen"),
    )
    persisted = data["persisted"] or {}
    relationships = sources.relationships(
        selected_facts,
        sources.row_facts(item),
    )
    score = _correlation_score(
        sources,
        shared,
        persisted,
        relationships,
        time_score,
    )
    return {
        "group_id": group_id,
        "score": score,
        "correlation_reasons": _correlation_reasons(
            shared,
            relationships,
            time_reason,
            persisted,
        ),
        "shared_observables": shared[:12],
        "deterministic_relationships": relationships,
        "alert": {key: item.get(key) for key in PUBLIC_ALERT_FIELDS},
        "prior_analysis": prior_analysis.get(group_id),
        "previous_correlation": {
            "model_status": persisted.get("model_status"),
            "model_confidence": persisted.get("model_confidence"),
            "model_hypothesis": persisted.get("model_hypothesis"),
            "updated_at": persisted.get("updated_at"),
        }
        if persisted
        else None,
    }


def _project_candidates(
    sources,
    selected,
    ranked_ids,
    representatives,
    candidate_data,
    prior_analysis,
    min_score,
) -> list[dict]:
    selected_facts = sources.row_facts(selected)
    candidates = []
    for group_id in ranked_ids:
        item = representatives.get(group_id)
        if not item:
            continue
        candidate = _project_candidate(
            sources,
            selected,
            selected_facts,
            group_id,
            item,
            candidate_data[group_id],
            prior_analysis,
        )
        if candidate["score"] >= min_score:
            candidates.append(candidate)
    candidates.sort(
        key=lambda item: (
            item["score"],
            str(item["alert"].get("last_seen") or ""),
        ),
        reverse=True,
    )
    return candidates


def _complete_context(selected_group_id, candidates, limit, min_score):
    return {
        "selected_group_id": selected_group_id,
        "candidates": candidates[:limit],
        "candidate_count_before_limit": len(candidates),
        "candidate_limit": limit,
        "minimum_score": min_score,
        "usage_guidance": (
            "Treat candidates as correlation leads, not confirmed incidents. "
            "Shared observables and timestamps are facts; "
            "deterministic_relationships are collector-derived joins with "
            "explicit interpretation limits; prior_analysis and "
            "previous_correlation are earlier hypotheses. Require current "
            "evidence before asserting incident scope, authorization, or "
            "maliciousness."
        ),
    }


def build_correlated_alert_context(
    sources: CorrelationContextSources,
    conn: sqlite3.Connection,
    selected: sqlite3.Row,
    limit: int,
    min_score: int,
) -> dict:
    """Return deterministic correlation leads without promoting hypotheses."""
    selected_group_id = str(
        sources.row_value(selected, "stable_group_id") or ""
    ).strip().lower()
    if not selected_group_id:
        return _empty_context(None, limit, min_score, "stable group identity unavailable")
    try:
        candidate_data = _load_candidate_data(sources, conn, selected_group_id)
    except sqlite3.Error:
        return _empty_context(
            selected_group_id,
            limit, min_score,
            "correlation index unavailable",
        )
    ranked_ids = _rank_candidate_ids(candidate_data)
    if not ranked_ids:
        return _empty_context(
            selected_group_id,
            limit, min_score,
            "no indexed correlation candidates",
        )
    representatives, placeholders = _load_representatives(
        sources,
        conn,
        ranked_ids,
    )
    prior_analysis = _load_prior_analysis(
        sources,
        conn,
        ranked_ids,
        placeholders,
    )
    candidates = _project_candidates(
        sources,
        selected,
        ranked_ids,
        representatives,
        candidate_data,
        prior_analysis,
        min_score,
    )
    return _complete_context(selected_group_id, candidates, limit, min_score)
