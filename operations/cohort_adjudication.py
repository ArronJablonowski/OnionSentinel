#!/usr/bin/env python3
"""Strict normalization contract for independent cohort adjudication."""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any, Mapping, Pattern, Sequence


TOP_LEVEL_ADJUDICATION_KEYS = frozenset(
    {
        "schema", "experiment_id", "expected_count", "independent_review",
        "reviewer_count", "adjudicated_at", "methodology_sha256",
        "source_cohorts", "cases",
    }
)
CASE_ADJUDICATION_KEYS = frozenset(
    {"stable_group_id", "ground_truth", "role_assessments"}
)
GROUND_TRUTH_KEYS = frozenset(
    {
        "labels", "confidence", "detection_sha256", "evidence_basis_sha256",
        "scope_timeline_sha256", "attribution_sha256",
        "required_query_classes", "telemetry_gap_codes",
    }
)
ROLE_ASSESSMENT_KEYS = frozenset(
    {"analysis_id", "scores", "hard_failures", "failure_modes", "improvement_codes"}
)


@dataclass(frozen=True)
class AdjudicationPolicy:
    error: type[RuntimeError]
    schema: str
    stable_group_id_pattern: Pattern[str]
    sha256_pattern: Pattern[str]
    code_pattern: Pattern[str]
    maximum_code_items: int
    maximum_code_length: int
    verdict_fields: tuple[str, ...]
    verdict_value_sets: Mapping[str, frozenset[str]]
    rubric_weights: Mapping[str, int]
    hard_failure_codes: frozenset[str]
    query_classes: frozenset[str]


def unexpected_keys(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    label: str,
    error: type[RuntimeError],
) -> None:
    unexpected = set(value) - allowed
    if unexpected:
        raise error(
            f"{label} contains unsupported fields: "
            + ", ".join(sorted(unexpected))
        )


def validate_code_list(
    value: Any,
    label: str,
    policy: AdjudicationPolicy,
) -> list[str]:
    if not isinstance(value, list) or len(value) > policy.maximum_code_items:
        raise policy.error(
            f"{label} must be an array of at most "
            f"{policy.maximum_code_items} codes"
        )
    output: list[str] = []
    for item in value:
        code = str(item or "").strip()
        valid = (
            len(code) <= policy.maximum_code_length
            and policy.code_pattern.fullmatch(code) is not None
            and code not in output
        )
        if not valid:
            raise policy.error(f"{label} contains an invalid code")
        output.append(code)
    return output


def normalize_duplicate_of(
    value: Any,
    label: str,
    error: type[RuntimeError],
) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    invalid = (
        not normalized
        or len(normalized) > 160
        or re.search(r"[\x00-\x1f\x7f]", normalized) is not None
    )
    if invalid:
        raise error(f"{label} is invalid")
    return normalized


def validate_labels(
    value: Any,
    label: str,
    policy: AdjudicationPolicy,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(policy.verdict_fields):
        raise policy.error(
            f"{label} must contain exactly: "
            + ", ".join(policy.verdict_fields)
        )
    output: dict[str, Any] = {}
    for field in policy.verdict_fields:
        if field == "duplicate_of":
            output[field] = normalize_duplicate_of(
                value.get(field), f"{label}.{field}", policy.error
            )
            continue
        normalized = str(value.get(field) or "").strip().lower()
        if normalized not in policy.verdict_value_sets[field]:
            raise policy.error(f"{label}.{field} is invalid")
        output[field] = normalized
    return output


def validate_scores(
    value: Any,
    label: str,
    policy: AdjudicationPolicy,
) -> dict[str, float]:
    if not isinstance(value, dict) or set(value) != set(policy.rubric_weights):
        raise policy.error(
            f"{label} must contain exactly the nine rubric criteria"
        )
    output: dict[str, float] = {}
    for criterion, maximum in policy.rubric_weights.items():
        raw = value.get(criterion)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise policy.error(f"{label}.{criterion} must be numeric")
        score = float(raw)
        if not math.isfinite(score) or score < 0 or score > maximum:
            raise policy.error(
                f"{label}.{criterion} must be between 0 and {maximum}"
            )
        output[criterion] = round(score, 2)
    return output


def _metadata(
    document: Mapping[str, Any],
    expected_count: int,
    policy: AdjudicationPolicy,
) -> dict[str, Any]:
    unexpected_keys(
        document, TOP_LEVEL_ADJUDICATION_KEYS, "adjudication", policy.error
    )
    if document.get("schema") != policy.schema:
        raise policy.error("unsupported adjudication schema")
    experiment_id = str(document.get("experiment_id") or "").strip()
    experiment_valid = (
        3 <= len(experiment_id) <= 100
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]+", experiment_id)
    )
    if not experiment_valid:
        raise policy.error("adjudication experiment_id is invalid")
    if document.get("independent_review") is not True:
        raise policy.error("adjudication must affirm independent_review=true")
    try:
        count = int(document.get("expected_count"))
        reviewer_count = int(document.get("reviewer_count"))
    except (TypeError, ValueError) as exc:
        raise policy.error("adjudication counts must be integers") from exc
    if count != expected_count:
        raise policy.error(
            "adjudication expected_count does not match the evaluation"
        )
    if reviewer_count < 1 or reviewer_count > 20:
        raise policy.error("reviewer_count must be between 1 and 20")
    return {"experiment_id": experiment_id, "reviewer_count": reviewer_count}


def _metadata_strings(
    document: Mapping[str, Any],
    policy: AdjudicationPolicy,
) -> tuple[str, str]:
    adjudicated_at = str(document.get("adjudicated_at") or "").strip()
    if len(adjudicated_at) < 10 or len(adjudicated_at) > 64:
        raise policy.error("adjudicated_at is missing or invalid")
    methodology = str(document.get("methodology_sha256") or "")
    if not policy.sha256_pattern.fullmatch(methodology):
        raise policy.error("methodology_sha256 is missing or invalid")
    return adjudicated_at, methodology


def _sources(
    value: Any,
    roles: Sequence[str],
    policy: AdjudicationPolicy,
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(roles):
        raise policy.error(
            "source_cohorts must identify every evaluated role exactly once"
        )
    output: dict[str, str] = {}
    for role in roles:
        cohort_id = str(value.get(role) or "").strip()
        if not cohort_id or len(cohort_id) > 100:
            raise policy.error(f"source cohort for {role} is invalid")
        output[role] = cohort_id
    return output


def _ground_truth(
    value: Any,
    label: str,
    policy: AdjudicationPolicy,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise policy.error(f"{label} is invalid")
    unexpected_keys(value, GROUND_TRUTH_KEYS, label, policy.error)
    labels = validate_labels(value.get("labels"), f"{label}.labels", policy)
    confidence = str(value.get("confidence") or "").lower()
    if confidence not in policy.verdict_value_sets["confidence"]:
        raise policy.error(f"{label}.confidence is invalid")
    digests = _ground_truth_digests(value, label, policy)
    queries = _required_queries(value.get("required_query_classes"), label, policy)
    gaps = validate_code_list(
        value.get("telemetry_gap_codes"), f"{label}.telemetry_gap_codes", policy
    )
    return {
        "labels": labels,
        "confidence": confidence,
        **digests,
        "required_query_classes": queries,
        "telemetry_gap_codes": gaps,
    }


def validate_ground_truth(
    value: Any,
    label: str,
    policy: AdjudicationPolicy,
) -> dict[str, Any]:
    """Normalize one evidence-bound ground-truth record."""
    return _ground_truth(value, label, policy)


def _ground_truth_digests(
    value: Mapping[str, Any],
    label: str,
    policy: AdjudicationPolicy,
) -> dict[str, str]:
    output: dict[str, str] = {}
    for field in (
        "detection_sha256", "evidence_basis_sha256",
        "scope_timeline_sha256", "attribution_sha256",
    ):
        digest = str(value.get(field) or "")
        if not policy.sha256_pattern.fullmatch(digest):
            raise policy.error(f"{label}.{field} is invalid")
        output[field] = digest
    return output


def _required_queries(
    value: Any,
    label: str,
    policy: AdjudicationPolicy,
) -> list[str]:
    if not isinstance(value, list) or len(value) > len(policy.query_classes):
        raise policy.error(f"{label}.required_query_classes is invalid")
    output: list[str] = []
    for item in value:
        query_class = str(item or "").strip().lower()
        if query_class not in policy.query_classes or query_class in output:
            raise policy.error(f"{label} has an invalid query class")
        output.append(query_class)
    return output


def _analysis_id(value: Any, label: str, policy: AdjudicationPolicy) -> str | None:
    analysis_id = None if value is None else str(value).strip()
    if analysis_id is None:
        return None
    invalid = (
        not analysis_id
        or len(analysis_id) > 200
        or re.search(r"[\x00-\x1f\x7f]", analysis_id) is not None
    )
    if invalid:
        raise policy.error(f"{label}.analysis_id is invalid")
    return analysis_id


def _assessment(
    value: Any,
    label: str,
    policy: AdjudicationPolicy,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise policy.error(f"{label} must be an object")
    unexpected_keys(value, ROLE_ASSESSMENT_KEYS, label, policy.error)
    hard_failures = validate_code_list(
        value.get("hard_failures"), f"{label}.hard_failures", policy
    )
    unknown = set(hard_failures) - policy.hard_failure_codes
    if unknown:
        raise policy.error(
            f"{label} contains unsupported hard failures: "
            + ", ".join(sorted(unknown))
        )
    return {
        "analysis_id": _analysis_id(value.get("analysis_id"), label, policy),
        "scores": validate_scores(value.get("scores"), f"{label}.scores", policy),
        "hard_failures": hard_failures,
        "failure_modes": validate_code_list(
            value.get("failure_modes"), f"{label}.failure_modes", policy
        ),
        "improvement_codes": validate_code_list(
            value.get("improvement_codes"), f"{label}.improvement_codes", policy
        ),
    }


def _assessments(
    value: Any,
    roles: Sequence[str],
    label: str,
    policy: AdjudicationPolicy,
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != set(roles):
        raise policy.error(f"{label} must grade every role")
    return {
        role: _assessment(value[role], f"{label}.{role}", policy)
        for role in roles
    }


def _case(
    value: Any,
    index: int,
    roles: Sequence[str],
    seen: set[str],
    policy: AdjudicationPolicy,
) -> dict[str, Any]:
    label = f"adjudication.cases[{index}]"
    if not isinstance(value, dict):
        raise policy.error(f"{label} must be an object")
    unexpected_keys(value, CASE_ADJUDICATION_KEYS, label, policy.error)
    stable_id = str(value.get("stable_group_id") or "").strip().lower()
    if not policy.stable_group_id_pattern.fullmatch(stable_id) or stable_id in seen:
        raise policy.error(f"{label}.stable_group_id is invalid or duplicated")
    seen.add(stable_id)
    return {
        "stable_group_id": stable_id,
        "ground_truth": _ground_truth(
            value.get("ground_truth"), f"{label}.ground_truth", policy
        ),
        "role_assessments": _assessments(
            value.get("role_assessments"),
            roles,
            f"{label}.role_assessments",
            policy,
        ),
    }


def validate_adjudication(
    document: Mapping[str, Any],
    *,
    expected_roles: Sequence[str],
    expected_count: int,
    policy: AdjudicationPolicy,
) -> dict[str, Any]:
    metadata = _metadata(document, expected_count, policy)
    adjudicated_at, methodology = _metadata_strings(document, policy)
    sources = _sources(document.get("source_cohorts"), expected_roles, policy)
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != expected_count:
        raise policy.error(
            f"adjudication must contain exactly {expected_count} cases"
        )
    seen: set[str] = set()
    normalized_cases = [
        _case(item, index, expected_roles, seen, policy)
        for index, item in enumerate(cases)
    ]
    return {
        "schema": policy.schema,
        **metadata,
        "expected_count": expected_count,
        "independent_review": True,
        "adjudicated_at": adjudicated_at,
        "methodology_sha256": methodology,
        "source_cohorts": sources,
        "cases": normalized_cases,
    }
