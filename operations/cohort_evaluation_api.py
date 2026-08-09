#!/usr/bin/env python3
"""Public orchestration API for sealed offline cohort evaluation."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cohort_evaluation_workflow import (
    EvaluationWorkflowPolicy,
    adjudications_by_stable_id,
    assemble_report,
    build_role_reports,
    result_source,
    validate_paired_results,
    validate_request,
)


@dataclass(frozen=True)
class EvaluationApiPolicy:
    workflow: EvaluationWorkflowPolicy
    load_result_export: Callable[..., tuple[dict[str, Any], str]]
    load_private_json: Callable[[Path, str], tuple[dict[str, Any], str]]
    validate_adjudication: Callable[..., dict[str, Any]]
    error: type[RuntimeError]


def _load_result_sources(
    result_paths: Mapping[str, Path],
    roles: Sequence[str],
    expected_count: int,
    policy: EvaluationApiPolicy,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    loaded_results: dict[str, dict[str, Any]] = {}
    result_sources: dict[str, dict[str, Any]] = {}
    for role in roles:
        loaded, source_sha256 = policy.load_result_export(
            result_paths[role], role=role, expected_count=expected_count
        )
        loaded_results[role] = loaded
        result_sources[role] = result_source(loaded, source_sha256)
    return loaded_results, result_sources


def evaluate_cohorts(
    *,
    result_paths: Mapping[str, Path],
    adjudication_path: Path,
    expected_count: int,
    required_evaluation_profile: str,
    policy: EvaluationApiPolicy,
) -> dict[str, Any]:
    """Evaluate sealed role exports against one independent adjudication."""
    workflow = policy.workflow
    roles = validate_request(result_paths, expected_count, workflow, policy.error)
    loaded_results, result_sources = _load_result_sources(
        result_paths, roles, expected_count, policy
    )
    incident_result = validate_paired_results(
        loaded_results,
        required_evaluation_profile,
        workflow,
        policy.error,
    )
    adjudication_raw, adjudication_source_sha256 = policy.load_private_json(
        adjudication_path, "independent adjudication"
    )
    adjudication = policy.validate_adjudication(
        adjudication_raw,
        expected_roles=roles,
        expected_count=expected_count,
    )
    by_stable = adjudications_by_stable_id(
        adjudication, loaded_results, roles, policy.error
    )
    role_reports = build_role_reports(
        loaded=loaded_results,
        adjudications=by_stable,
        roles=roles,
        expected_count=expected_count,
        policy=workflow,
    )
    return assemble_report(
        adjudication=adjudication,
        adjudication_source_sha256=adjudication_source_sha256,
        incident=incident_result,
        result_sources=result_sources,
        role_reports=role_reports,
        expected_count=expected_count,
        policy=workflow,
    )
