"""Compose bounded offline analysis-replay report summaries.

This leaf owns deterministic report projection only. Callers inject field and
calibration metric functions; the module performs no I/O or network access.
"""

from __future__ import annotations

from typing import Any, Callable


def _field_metrics(
    results: list[dict[str, Any]],
    factored_fields: tuple[str, ...],
    classification_metrics: Callable[[list[dict[str, Any]], str], dict[str, Any]],
) -> dict[str, Any]:
    return {
        field: classification_metrics(results, field)
        for field in (*factored_fields, "detection_outcome")
        if any(field in item["fields"] for item in results)
    }


def _reviewer_counts(
    results: list[dict[str, Any]],
    factored_fields: tuple[str, ...],
) -> tuple[list[dict[str, Any]], int, int]:
    reviewer_cases = [item for item in results if isinstance(item.get("reviewer"), dict)]
    reviewer_correct = 0
    primary_correct = 0
    for item in reviewer_cases:
        expected = {
            field: data["expected"]
            for field, data in item["fields"].items()
            if field in factored_fields
        }
        reviewer_correct += int(
            bool(expected)
            and all(item["reviewer"].get(field) == value for field, value in expected.items())
        )
        primary_correct += int(item["exact_factored_verdict"])
    return reviewer_cases, reviewer_correct, primary_correct


def _exact_count(results: list[dict[str, Any]]) -> int:
    return sum(1 for item in results if item["exact_factored_verdict"])


def _case_ids(results: list[dict[str, Any]], flag: str) -> list[Any]:
    return [item["case_id"] for item in results if item[flag]]


def _unsupported_evidence_cases(results: list[dict[str, Any]]) -> dict[Any, Any]:
    return {
        item["case_id"]: item["unsupported_evidence_refs"]
        for item in results
        if item["unsupported_evidence_refs"]
    }


def _deterministic_guard_cases(results: list[dict[str, Any]]) -> list[Any]:
    return [
        item["case_id"]
        for item in results
        if isinstance(item.get("deterministic_guard"), dict)
        and (
            item["deterministic_guard"].get("override_applied")
            or item["deterministic_guard"].get("confidence_cap") is not None
        )
    ]


def summarize(
    suite: dict[str, Any],
    results: list[dict[str, Any]],
    factored_fields: tuple[str, ...],
    classification_metrics: Callable[[list[dict[str, Any]], str], dict[str, Any]],
    calibration_metrics: Callable[[list[dict[str, Any]]], dict[str, Any]],
) -> dict[str, Any]:
    field_metrics = _field_metrics(results, factored_fields, classification_metrics)
    reviewer_cases, reviewer_correct, primary_correct_on_reviewer_cases = _reviewer_counts(
        results,
        factored_fields,
    )
    return {
        "schema": "onion-sentinel-analysis-replay-report-v1",
        "suite_name": suite.get("suite_name"),
        "suite_version": suite.get("version"),
        "case_count": len(results),
        "exact_factored_verdicts": _exact_count(results),
        "exact_factored_accuracy": round(
            _exact_count(results) / len(results),
            6,
        ),
        "dangerous_dismissals": _case_ids(results, "dangerous_dismissal"),
        "over_escalations": _case_ids(results, "over_escalation"),
        "schema_repair_cases": _case_ids(results, "schema_repaired"),
        "unsupported_evidence_reference_cases": _unsupported_evidence_cases(results),
        "deterministic_guard_cases": _deterministic_guard_cases(results),
        "field_metrics": field_metrics,
        "calibration": calibration_metrics(results),
        "reviewer": {
            "case_count": len(reviewer_cases),
            "primary_exact": primary_correct_on_reviewer_cases,
            "reviewer_exact": reviewer_correct,
            "net_exact_gain": reviewer_correct - primary_correct_on_reviewer_cases,
        },
        "cases": results,
    }
