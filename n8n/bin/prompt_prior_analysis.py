#!/usr/bin/env python3
"""Collect bounded prior-analysis context for investigation prompts."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable


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


def _indexed_projection(item: Any, sources: PriorAnalysisSources) -> dict:
    return {
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


def _indexed_context(
    sources: PriorAnalysisSources,
    request: PriorAnalysisRequest,
    alert_id: str,
    stable_group_id: str,
) -> list[dict]:
    try:
        indexed = sources.query_rows(
            request.connection,
            """
            SELECT analysis_id, generated_at, model, model_path,
                   detection_outcome, bluf, summary, confidence, artifact_path
            FROM ai_analysis_runs
            WHERE alert_id = ? OR (? <> '' AND group_id = ?)
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            [alert_id, stable_group_id, stable_group_id, request.result_limit],
        )
    except sqlite3.Error:
        return []
    return [_indexed_projection(item, sources) for item in indexed]


def _legacy_projection(path: Path, payload: dict) -> dict:
    result = (
        payload.get("analysis")
        if isinstance(payload.get("analysis"), dict)
        else payload
    )
    return {
        "artifact": str(path),
        "generated_at": payload.get("generated_at") or result.get("generated_at"),
        "model": payload.get("analysis_model") or payload.get("model"),
        "detection_outcome": result.get("detection_outcome"),
        "bluf": result.get("bluf"),
        "summary": result.get("summary"),
        "confidence": result.get("confidence"),
        "tuning_recommendation": result.get("tuning_recommendation"),
    }


def _legacy_context(
    sources: PriorAnalysisSources,
    request: PriorAnalysisRequest,
    alert_id: str,
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
        if alert_id not in json.dumps(payload, sort_keys=True):
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
    return _legacy_context(sources, request, alert_id)
