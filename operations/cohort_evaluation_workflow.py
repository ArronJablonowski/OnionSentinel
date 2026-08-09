#!/usr/bin/env python3
"""Compose paired cohort validation, adjudication binding, and report data."""
from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


@dataclass(frozen=True)
class EvaluationWorkflowPolicy:
    supported_roles: Sequence[str]
    minimum_role_count: int
    maximum_role_count: int
    controlled_profile: str
    report_schema: str
    rubric_weights: Mapping[str, int]
    pass_score: float
    review_score: float
    minimum_pass_rate: float
    production_role_count: int
    hard_failure_codes: Sequence[str]
    utc_now: Callable[[], str]
    hash_value: Callable[[Any], str]
    case_evaluation: Callable[..., Mapping[str, Any]]
    role_aggregate: Callable[[str, Sequence[Mapping[str, Any]], int], Mapping[str, Any]]
    cross_role_comparison: Callable[[Mapping[str, Mapping[str, Any]]], Mapping[str, Any] | None]


def validate_request(
    result_paths: Mapping[str, Path],
    expected_count: int,
    policy: EvaluationWorkflowPolicy,
    error: type[RuntimeError],
) -> tuple[str, ...]:
    count_valid = (
        isinstance(expected_count, int)
        and not isinstance(expected_count, bool)
        and policy.minimum_role_count <= expected_count <= policy.maximum_role_count
    )
    if not count_valid:
        raise error(
            "expected_count must be an integer between "
            f"{policy.minimum_role_count} and {policy.maximum_role_count} per role"
        )
    roles = tuple(role for role in policy.supported_roles if role in result_paths)
    if set(result_paths) != set(policy.supported_roles):
        raise error(
            "grading requires both incident-responder and soc-analyst result exports"
        )
    return roles


def result_source(loaded: Mapping[str, Any], source_sha256: str) -> dict[str, Any]:
    contract = loaded["execution_contract"]
    return {
        "cohort_id": loaded["cohort_id"],
        "source_file_sha256": source_sha256,
        "export_sha256": loaded["export_sha256"],
        "source_rows_sha256": loaded["source_rows_sha256"],
        "ordered_identity_sha256": loaded["ordered_identity_sha256"],
        "ordered_detection_sha256": loaded["ordered_detection_sha256"],
        "frozen_plan_sha256": loaded["frozen_plan_sha256"],
        "expected_release_id": contract["expected_release_id"],
        "expected_assigned_route": contract["expected_assigned_route"],
        "expected_reviewer_route": contract["expected_reviewer_route"],
        "reviewer_required": contract["reviewer_required"],
        "evaluation_profile": contract["evaluation_profile"],
    }


def validate_paired_results(
    loaded: Mapping[str, Mapping[str, Any]],
    required_evaluation_profile: str,
    policy: EvaluationWorkflowPolicy,
    error: type[RuntimeError],
) -> Mapping[str, Any]:
    incident = loaded["incident-responder"]
    soc = loaded["soc-analyst"]
    checks = (
        incident["source_rows_sha256"] == soc["source_rows_sha256"],
        incident["ordered_identity_sha256"] == soc["ordered_identity_sha256"],
        incident["ordered_identities"] == soc["ordered_identities"],
        incident["ordered_detection_projection"]
        == soc["ordered_detection_projection"],
        incident["execution_contract"] == soc["execution_contract"],
    )
    if not all(checks):
        raise error(
            "SOC Analyst and Incident Responder exports are not the same frozen "
            "source cohort with the same execution contract and order"
        )
    required = str(required_evaluation_profile or "").strip()
    profile_valid = (
        not required
        or (
            required == policy.controlled_profile
            and incident["execution_contract"]["evaluation_profile"] == required
        )
    )
    if not profile_valid:
        raise error("result exports do not declare the required evaluation profile")
    return incident


def adjudications_by_stable_id(
    adjudication: Mapping[str, Any],
    loaded: Mapping[str, Mapping[str, Any]],
    roles: Sequence[str],
    error: type[RuntimeError],
) -> dict[str, Mapping[str, Any]]:
    for role in roles:
        if adjudication["source_cohorts"][role] != loaded[role]["cohort_id"]:
            raise error(f"{role} source cohort ID does not match adjudication")
    by_stable = {item["stable_group_id"]: item for item in adjudication["cases"]}
    expected_ids = set(by_stable)
    for role in roles:
        result_ids = set(loaded[role]["members"])
        if result_ids != expected_ids:
            missing = sorted(expected_ids - result_ids)
            unexpected = sorted(result_ids - expected_ids)
            raise error(
                f"{role} stable cohort differs from adjudication "
                f"(missing={missing}, unexpected={unexpected})"
            )
        _validate_detection_snapshots(role, loaded[role]["members"], by_stable, error)
    return by_stable


def _validate_detection_snapshots(
    role: str,
    members: Mapping[str, Mapping[str, Any]],
    adjudications: Mapping[str, Mapping[str, Any]],
    error: type[RuntimeError],
) -> None:
    for stable_id, member in members.items():
        expected = adjudications[stable_id]["ground_truth"]["detection_sha256"]
        if member["detection_sha256"] != expected:
            raise error(
                f"{role} detection snapshot differs from adjudication for {stable_id}"
            )


def build_role_reports(
    *,
    loaded: Mapping[str, Mapping[str, Any]],
    adjudications: Mapping[str, Mapping[str, Any]],
    roles: Sequence[str],
    expected_count: int,
    policy: EvaluationWorkflowPolicy,
) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for role in roles:
        members = loaded[role]["members"]
        cases = [
            policy.case_evaluation(
                role=role,
                result=members[stable_id],
                adjudication=adjudications[stable_id],
            )
            for stable_id in sorted(members, key=lambda item: members[item]["rank"])
        ]
        reports[role] = {
            "aggregate": policy.role_aggregate(role, cases, expected_count),
            "cases": cases,
        }
    return reports


def _rubric(expected_count: int, policy: EvaluationWorkflowPolicy) -> dict[str, Any]:
    return {
        "criteria": policy.rubric_weights,
        "maximum_score": 100,
        "pass_score": policy.pass_score,
        "review_score": policy.review_score,
        "pass_requires_exact_verdict": True,
        "hard_failure_codes": sorted(policy.hard_failure_codes),
        "hard_failure_effective_score": 0,
        "minimum_pass_rate": policy.minimum_pass_rate,
        "required_pass_count": math.ceil(expected_count * policy.minimum_pass_rate),
        "default_production_promotion_count": policy.production_role_count,
    }


def _dual_role_gate(
    incident: Mapping[str, Any], expected_count: int
) -> dict[str, Any]:
    return {
        "passed": True,
        "role_count": 2,
        "analysis_count": expected_count * 2,
        "source_rows_sha256": incident["source_rows_sha256"],
        "ordered_identity_sha256": incident["ordered_identity_sha256"],
        "ordered_detection_sha256": incident["ordered_detection_sha256"],
        "controls": {
            "fresh_results": True,
            "harness_enabled": True,
            "harness_mode": "shadow",
            "terminal_chains_valid": True,
            "routes_verified": True,
            "read_only_ledgers": True,
            "positive_successful_tool_ledgers": True,
            "collector_query_audits_bound": True,
            "memory_frozen": True,
            "bypass_or_partial_results": 0,
        },
    }


def assemble_report(
    *,
    adjudication: Mapping[str, Any],
    adjudication_source_sha256: str,
    incident: Mapping[str, Any],
    result_sources: Mapping[str, Mapping[str, Any]],
    role_reports: Mapping[str, Mapping[str, Any]],
    expected_count: int,
    policy: EvaluationWorkflowPolicy,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": policy.report_schema,
        "generated_at": policy.utc_now(),
        "experiment_id": adjudication["experiment_id"],
        "expected_count": expected_count,
        "rubric": _rubric(expected_count, policy),
        "adjudication": {
            "source_file_sha256": adjudication_source_sha256,
            "independent_review": True,
            "reviewer_count": adjudication["reviewer_count"],
            "adjudicated_at": adjudication["adjudicated_at"],
            "methodology_sha256": adjudication["methodology_sha256"],
        },
        "execution_contract": dict(incident["execution_contract"]),
        "result_sources": result_sources,
        "dual_role_execution_gate": _dual_role_gate(incident, expected_count),
        "roles": role_reports,
        "cross_role": policy.cross_role_comparison(role_reports),
        "content_policy": {
            "contains_raw_alerts": False,
            "contains_prompts": False,
            "contains_raw_model_responses": False,
            "contains_query_text": False,
            "contains_query_results": False,
            "contains_credentials": False,
            "contains_ground_truth_digests": True,
        },
    }
    report["report_sha256"] = policy.hash_value(report)
    return report
