#!/usr/bin/env python3
"""Collect bounded prior-analysis context for investigation prompts."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable


CASE_SUMMARY_SCHEMA = "onion-sentinel-case-summary-v1"
MAX_CASE_CITATIONS = 32
MAX_CASE_GAPS = 16
MAX_CASE_HYPOTHESES = 8
MAX_CASE_CONTRADICTIONS = 16
MAX_CASE_TEXT = 2_000


@dataclass(frozen=True)
class PriorAnalysisSources:
    """Database, row, and bounded artifact operations supplied by the facade."""

    row_value: Callable[[Any, str], Any]
    query_rows: Callable[[Any, str, list[Any]], list[Any]]
    load_json_bounded: Callable[[Path], dict]


@dataclass(frozen=True)
class PriorAnalysisRequest:
    """Selected detection and explicit historical evidence bounds."""

    connection: Any
    analysis_dir: Path
    selected: Any
    result_limit: int = 3
    legacy_scan_limit: int = 200


def _bounded_text(value: object, limit: int = MAX_CASE_TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def _bounded_text_list(value: object, limit: int) -> tuple[list[str], bool]:
    raw = value if isinstance(value, list) else []
    projected = [
        text
        for text in (_bounded_text(item) for item in raw[:limit])
        if text
    ]
    return projected, len(raw) > limit


def _bounded_hypotheses(value: object) -> tuple[list[dict[str, Any]], bool]:
    raw = value if isinstance(value, list) else []
    projected: list[dict[str, Any]] = []
    for item in raw[:MAX_CASE_HYPOTHESES]:
        if not isinstance(item, dict):
            continue
        supporting, supporting_truncated = _bounded_text_list(
            item.get("supporting_evidence"),
            MAX_CASE_CITATIONS,
        )
        contradicting, contradicting_truncated = _bounded_text_list(
            item.get("contradicting_evidence"),
            MAX_CASE_CONTRADICTIONS,
        )
        hypothesis = {
            "id": _bounded_text(item.get("id"), 128),
            "statement": _bounded_text(item.get("statement")),
            "status": _bounded_text(item.get("status"), 32),
            "supporting_evidence": supporting,
            "contradicting_evidence": contradicting,
            "next_discriminator": _bounded_text(item.get("next_discriminator")),
        }
        truncated = supporting_truncated or contradicting_truncated
        if truncated:
            hypothesis["truncated"] = True
        projected.append(hypothesis)
    return projected, len(raw) > MAX_CASE_HYPOTHESES


def _response_mapping(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _case_summary_projection(response: dict[str, Any]) -> dict[str, Any]:
    citations, citations_truncated = _bounded_text_list(
        response.get("evidence_used"),
        MAX_CASE_CITATIONS,
    )
    gaps, gaps_truncated = _bounded_text_list(
        response.get("evidence_gaps"),
        MAX_CASE_GAPS,
    )
    hypotheses, hypotheses_truncated = _bounded_hypotheses(
        response.get("hypotheses")
    )
    correlation = response.get("correlation_assessment")
    correlation = correlation if isinstance(correlation, dict) else {}
    contradictions, contradictions_truncated = _bounded_text_list(
        correlation.get("contradicting_evidence"),
        MAX_CASE_CONTRADICTIONS,
    )
    truncated_fields = [
        name
        for name, truncated in (
            ("evidence_used", citations_truncated),
            ("evidence_gaps", gaps_truncated),
            ("hypotheses", hypotheses_truncated),
            ("correlation_contradictions", contradictions_truncated),
        )
        if truncated
    ]
    return {
        "case_memory_schema": CASE_SUMMARY_SCHEMA,
        "confidence_score": response.get("confidence_score"),
        "evidence_used": citations,
        "evidence_gaps": gaps,
        "hypotheses": hypotheses,
        "correlation_contradictions": contradictions,
        "projection": {
            "limits": {
                "citations": MAX_CASE_CITATIONS,
                "telemetry_gaps": MAX_CASE_GAPS,
                "hypotheses": MAX_CASE_HYPOTHESES,
                "contradictions": MAX_CASE_CONTRADICTIONS,
                "text_characters": MAX_CASE_TEXT,
            },
            "truncated_fields": truncated_fields,
        },
    }


def _indexed_projection(item: Any, sources: PriorAnalysisSources) -> dict:
    projection = {
        "analysis_id": sources.row_value(item, "analysis_id"),
        "artifact": sources.row_value(item, "artifact_path"),
        "generated_at": sources.row_value(item, "generated_at"),
        "model": sources.row_value(item, "model"),
        "model_path": sources.row_value(item, "model_path"),
        "detection_outcome": sources.row_value(item, "detection_outcome"),
        "bluf": sources.row_value(item, "bluf"),
        "summary": sources.row_value(item, "summary"),
        "confidence": sources.row_value(item, "confidence"),
    }
    response = _response_mapping(sources.row_value(item, "response_json"))
    if response is not None:
        projection.update(_case_summary_projection(response))
        role = sources.row_value(item, "agent_role")
        if role:
            projection["agent_role"] = role
    return projection


def _indexed_context(
    sources: PriorAnalysisSources,
    request: PriorAnalysisRequest,
    alert_id: str,
    stable_group_id: str,
) -> list[dict]:
    parameters = [
        alert_id,
        stable_group_id,
        stable_group_id,
        request.result_limit,
    ]
    try:
        indexed = sources.query_rows(
            request.connection,
            """
            SELECT analysis_id, agent_role, generated_at, model, model_path,
                   detection_outcome, bluf, summary, confidence, artifact_path,
                   response_json
            FROM ai_analysis_runs
            WHERE alert_id = ? OR (? <> '' AND group_id = ?)
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            parameters,
        )
    except sqlite3.Error:
        try:
            indexed = sources.query_rows(
                request.connection,
                """
                SELECT analysis_id, generated_at, model, model_path,
                       detection_outcome, bluf, summary, confidence,
                       artifact_path
                FROM ai_analysis_runs
                WHERE alert_id = ? OR (? <> '' AND group_id = ?)
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                parameters,
            )
        except sqlite3.Error:
            return []
    return [_indexed_projection(item, sources) for item in indexed]


def _legacy_projection(path: Path, payload: dict) -> dict:
    result = payload.get("analysis")
    if not isinstance(result, dict):
        result = payload.get("response")
    if not isinstance(result, dict):
        result = payload
    projection = {
        "analysis_id": payload.get("analysis_id"),
        "artifact": str(path),
        "generated_at": payload.get("generated_at") or result.get("generated_at"),
        "model": payload.get("analysis_model") or payload.get("model"),
        "detection_outcome": result.get("detection_outcome"),
        "bluf": result.get("bluf"),
        "summary": result.get("summary"),
        "confidence": result.get("confidence"),
        "tuning_recommendation": result.get("tuning_recommendation"),
    }
    projection.update(_case_summary_projection(result))
    if payload.get("agent_role"):
        projection["agent_role"] = payload.get("agent_role")
    return projection


def _exact_legacy_identity(payload: dict, key: str) -> set[str]:
    values: set[str] = set()
    containers = [payload]
    for name in ("alert", "analysis", "response"):
        value = payload.get(name)
        if isinstance(value, dict):
            containers.append(value)
    for container in containers:
        value = str(container.get(key) or "").strip()
        if value:
            values.add(value)
    return values


def _legacy_matches_case(
    payload: dict,
    *,
    alert_id: str,
    stable_group_id: str,
) -> bool:
    alert_ids = _exact_legacy_identity(payload, "alert_id")
    group_ids = _exact_legacy_identity(payload, "group_id")
    return bool(
        (alert_id and alert_id in alert_ids)
        or (stable_group_id and stable_group_id in group_ids)
    )


def _legacy_context(
    sources: PriorAnalysisSources,
    request: PriorAnalysisRequest,
    alert_id: str,
    stable_group_id: str,
) -> list[dict]:
    if not request.analysis_dir.exists():
        return []
    found: list[dict] = []
    candidates = sorted(
        request.analysis_dir.glob("*-local-ai-analysis.json"),
        reverse=True,
    )[: request.legacy_scan_limit]
    for path in candidates:
        try:
            payload = sources.load_json_bounded(path)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            continue
        if not _legacy_matches_case(
            payload,
            alert_id=alert_id,
            stable_group_id=stable_group_id,
        ):
            continue
        found.append(_legacy_projection(path, payload))
        if len(found) >= request.result_limit:
            break
    return found


def build_prior_analysis_context(
    sources: PriorAnalysisSources,
    request: PriorAnalysisRequest,
) -> list[dict]:
    """Prefer indexed prior analyses, with a bounded legacy file fallback."""
    alert_id = str(sources.row_value(request.selected, "alert_id") or "")
    stable_group_id = str(
        sources.row_value(request.selected, "stable_group_id") or ""
    ).strip()
    indexed = _indexed_context(sources, request, alert_id, stable_group_id)
    if indexed:
        return indexed
    return _legacy_context(
        sources,
        request,
        alert_id,
        stable_group_id,
    )
