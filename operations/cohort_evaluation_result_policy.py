#!/usr/bin/env python3
"""Normalize safe cohort-export content and observed verdict labels."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


FORBIDDEN_CONTENT_FLAGS = (
    "contains_raw_alerts",
    "contains_prompts",
    "contains_raw_model_responses",
    "contains_query_text",
    "contains_query_results",
    "contains_credentials",
)


def validate_safe_export_content(
    document: Mapping[str, Any],
    label: str,
    error: type[RuntimeError],
) -> None:
    """Require an explicit metadata-only, credential-free export policy."""
    policy = document.get("content_policy")
    if not isinstance(policy, dict) or any(
        policy.get(field) is not False for field in FORBIDDEN_CONTENT_FLAGS
    ):
        raise error(f"{label} is not a metadata-only, secret-free export")


def observed_labels(
    analysis: Mapping[str, Any],
    normalize_duplicate_of: Callable[[Any, str], str | None],
    error: type[RuntimeError],
) -> dict[str, Any]:
    """Project bounded verdict labels while marking invalid duplicate IDs."""
    result = analysis.get("result")
    if not isinstance(result, dict):
        result = {}
    output: dict[str, Any] = {
        "detection_outcome": str(
            analysis.get("detection_outcome") or ""
        ).strip().lower(),
        "event_status": str(result.get("event_status") or "").strip().lower(),
        "detection_validity": str(
            result.get("detection_validity") or ""
        ).strip().lower(),
        "activity_disposition": str(
            result.get("activity_disposition") or ""
        ).strip().lower(),
        "handling": str(result.get("handling") or "").strip().lower(),
        "duplicate_of": None,
    }
    try:
        output["duplicate_of"] = normalize_duplicate_of(
            result.get("duplicate_of"), "analysis duplicate_of"
        )
    except error:
        output["duplicate_of"] = "__invalid__"
    return output
