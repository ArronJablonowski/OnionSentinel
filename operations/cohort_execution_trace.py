#!/usr/bin/env python3
"""Harness trace identity, integrity, terminal, and temporal proof gates."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Pattern


@dataclass(frozen=True)
class TraceExecutionPolicy:
    timestamp_error: type[Exception]
    parse_timestamp: Callable[[Any, str], Any]
    sha256_pattern: Pattern[str]


@dataclass(frozen=True)
class TraceExecutionExpectation:
    analysis_id: str
    role: str
    task_kind: str
    stable_group_id: str
    representative_alert_id: str
    harness_mode: str
    assigned_route: str
    reviewer_route: str


@dataclass(frozen=True)
class TraceExecutionEvidence:
    integrity: Mapping[str, Any]
    terminal: Mapping[str, Any]
    canonical_response_sha256: str
    submitted_response_sha256: str
    failures: tuple[str, ...]


def _identity_failures(
    trace: Mapping[str, Any],
    expected: TraceExecutionExpectation,
) -> list[str]:
    checks = (
        ("run_id", expected.analysis_id, "harness-run-analysis-binding-failed"),
        ("status", "succeeded", "harness-run-not-succeeded"),
        ("stage", "complete", "harness-run-not-complete"),
        ("role", expected.role, "harness-role-mismatch"),
        ("task_kind", expected.task_kind, "harness-task-kind-mismatch"),
        (
            "correlation_id",
            expected.stable_group_id,
            "harness-stable-group-binding-failed",
        ),
        (
            "alert_id",
            expected.representative_alert_id,
            "harness-alert-binding-failed",
        ),
        ("policy_mode", expected.harness_mode, "harness-mode-mismatch"),
        (
            "assigned_route",
            expected.assigned_route,
            "harness-assigned-route-mismatch",
        ),
        (
            "assigned_reviewer_route",
            expected.reviewer_route,
            "harness-reviewer-route-mismatch",
        ),
    )
    return [
        failure
        for field, value, failure in checks
        if str(trace.get(field) or "") != value
    ]


def _integrity_failures(
    integrity: Mapping[str, Any],
    models: Mapping[str, Any],
) -> list[str]:
    failures: list[str] = []
    if not integrity.get("valid"):
        failures.append("harness-chain-invalid")
    if not integrity.get("ledger_manifest_bound"):
        failures.append("harness-terminal-ledger-unbound")
    if int(models.get("successful_primary_call_count") or 0) < 1:
        failures.append("harness-primary-model-call-missing")
    return failures


def _terminal_failures(
    terminal: Mapping[str, Any],
    analysis_id: str,
    canonical_digest: str,
    policy: TraceExecutionPolicy,
) -> tuple[list[str], str]:
    failures: list[str] = []
    if terminal.get("evaluation_memory_frozen") is not True:
        failures.append("harness-memory-freeze-not-attested")
    if str(terminal.get("analysis_id") or "") != analysis_id:
        failures.append("harness-terminal-analysis-binding-failed")
    submitted = str(terminal.get("submitted_response_sha256") or "")
    stored = str(terminal.get("stored_response_sha256") or "")
    if not policy.sha256_pattern.fullmatch(submitted):
        failures.append("harness-terminal-submitted-response-digest-invalid")
    if not policy.sha256_pattern.fullmatch(stored) or stored != canonical_digest:
        failures.append("harness-terminal-stored-response-digest-mismatch")
    return failures, submitted


def _timestamp_failures(
    trace: Mapping[str, Any],
    dispatch_started: Any,
    analysis_generated: Any,
    policy: TraceExecutionPolicy,
) -> list[str]:
    try:
        harness_started = policy.parse_timestamp(
            trace.get("started_at"), "harness started_at"
        )
        harness_completed = policy.parse_timestamp(
            trace.get("completed_at"), "harness completed_at"
        )
    except policy.timestamp_error:
        return ["harness-timestamp-invalid"]
    failures: list[str] = []
    if dispatch_started and harness_started < dispatch_started:
        failures.append("harness-run-predates-dispatch")
    if analysis_generated and harness_completed < analysis_generated:
        failures.append("harness-completed-before-analysis")
    return failures


def evaluate_trace_execution(
    trace_report: Mapping[str, Any],
    trace: Mapping[str, Any],
    models: Mapping[str, Any],
    analysis: Mapping[str, Any],
    expected: TraceExecutionExpectation,
    policy: TraceExecutionPolicy,
    *,
    dispatch_started: Any,
    analysis_generated: Any,
) -> TraceExecutionEvidence:
    integrity = trace.get("integrity")
    integrity = integrity if isinstance(integrity, dict) else {}
    terminal = trace.get("terminal_execution_summary")
    terminal = terminal if isinstance(terminal, dict) else {}
    canonical_digest = str(analysis.get("response_canonical_sha256") or "")
    failures = _identity_failures(trace, expected)
    failures.extend(_integrity_failures(integrity, models))
    if trace_report.get("data_quality", {}).get("malformed_json_counts"):
        failures.append("harness-trace-malformed-json")
    terminal_failures, submitted_digest = _terminal_failures(
        terminal, expected.analysis_id, canonical_digest, policy
    )
    failures.extend(terminal_failures)
    failures.extend(
        _timestamp_failures(
            trace,
            dispatch_started,
            analysis_generated,
            policy,
        )
    )
    return TraceExecutionEvidence(
        integrity=integrity,
        terminal=terminal,
        canonical_response_sha256=canonical_digest,
        submitted_response_sha256=submitted_digest,
        failures=tuple(failures),
    )
