#!/usr/bin/env python3
"""Render and atomically persist content-free trace evaluation reports."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping


def atomic_private_json(path: Path, value: Mapping[str, Any]) -> None:
    """Atomically write an owner-only JSON report beside its destination."""
    destination = path.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        _write_private(descriptor, temporary, destination, payload)
    finally:
        temporary.unlink(missing_ok=True)


def _write_private(
    descriptor: int,
    temporary: Path,
    destination: Path,
    payload: str,
) -> None:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    os.chmod(destination, 0o600)


def human_report(report: Mapping[str, Any]) -> str:
    """Render the stable concise terminal report from an aggregate result."""
    completion = report["completion"]
    integrity = report["integrity"]
    skills = report["skill_selection_attestation"]
    models = report["models"]
    tools = report["tools"]
    evidence = report["evidence"]
    reviewer = report["reviewer"]
    budgets = report["budgets"]
    memory = report["memory_promotion"]
    coverage = report["coverage"]
    return "\n".join(
        [
            "Onion Sentinel harness trace evaluation",
            _completion_line(report, completion),
            f"Completion: {completion['terminal_rate']} terminal | "
            f"{completion['success_rate']} succeeded",
            f"Integrity: {integrity['valid_run_count']} valid, "
            f"{integrity['invalid_run_count']} invalid "
            f"({integrity['event_count']} events)",
            "Skill selection: "
            f"{skills['mandatory_ready_run_count']} evaluation-ready, "
            f"{skills['legacy_run_count']} legacy, "
            f"{skills['invalid_run_count']} invalid",
            f"Models: {models['call_count']} calls, "
            f"{models['independent_review_call_count']} reviewer calls",
            _tools_line(tools),
            f"Evidence: {evidence['catalogued_count']} references, "
            f"{evidence['average_distinct_source_classes_per_run']} "
            "average source classes/run",
            f"Reviewer: {reviewer['material_disagreement_runs']} material "
            f"disagreements across {reviewer['comparable_decision_runs']} "
            "comparable runs",
            f"Budgets: {budgets['violation_runs']} violating runs | "
            f"{_sorted_json(budgets['violation_counts'])}",
            f"Memory: {memory['allowed_count']} allowed, "
            f"{memory['blocked_count']} blocked, "
            f"{memory['requires_approval_count']} awaiting approval",
            f"Coverage: {coverage['runs_with_gaps']} runs with gaps | "
            f"{_sorted_json(coverage['reason_counts'])}",
        ]
    )


def _completion_line(
    report: Mapping[str, Any], completion: Mapping[str, Any]
) -> str:
    return (
        f"Runs: {report['run_count']} | statuses: "
        f"{_sorted_json(completion['status_counts'])}"
    )


def _tools_line(tools: Mapping[str, Any]) -> str:
    return (
        f"Tools: {tools['call_count']} calls, "
        f"{tools['rejected_count']} rejected, "
        f"{tools['failed_count']} failed, "
        f"{tools['coverage_gap_count']} coverage gaps, "
        f"{tools['truncated_count']} truncated"
    )


def _sorted_json(value: object) -> str:
    return json.dumps(value, sort_keys=True)
