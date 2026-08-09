#!/usr/bin/env python3
"""Orchestrate sealed cohort execution-proof admission."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import datetime as dt
from typing import Any, Pattern

from cohort_evaluation_execution_admission import (
    ExecutionAdmission,
    admit_fresh_analysis,
    admit_public_proof,
    validate_harness_freshness,
    validate_harness_identity,
    validate_response_binding,
)
from cohort_evaluation_harness_gate import (
    HarnessGatePolicy,
    validate_harness_gate,
)


@dataclass(frozen=True)
class ExecutionProofPolicy:
    digest_pattern: Pattern[str]
    error: type[RuntimeError]
    prior_analysis_ids: Callable[[Mapping[str, Any]], set[str]]
    parse_timestamp: Callable[[Any, str], dt.datetime]
    validate_embedded_digest: Callable[[Mapping[str, Any], str], None]
    validate_durable_job_proof: Callable[..., dict[str, Any]]
    validate_skill_summary: Callable[[Mapping[str, Any], str], Any]
    expected_task_kind: Callable[[str, str], str]
    query_audit_binding: Callable[[Mapping[str, Any]], dict[str, Any]]
    harness_gate_policy: HarnessGatePolicy


def _admit_execution_harness(
    *,
    member: Mapping[str, Any],
    admission: ExecutionAdmission,
    role: str,
    contract: Mapping[str, Any],
    label: str,
    policy: ExecutionProofPolicy,
) -> tuple[Mapping[str, Any], Mapping[str, Any], str]:
    response_sha256 = validate_response_binding(
        admission=admission,
        role=role,
        contract=contract,
        digest_pattern=policy.digest_pattern,
        label=label,
        error=policy.error,
    )
    proof, harness = admit_public_proof(
        member=member,
        admission=admission,
        contract=contract,
        label=label,
        validate_embedded_digest=policy.validate_embedded_digest,
        parse_timestamp=policy.parse_timestamp,
        error=policy.error,
    )
    policy.validate_skill_summary(harness, label)
    validate_harness_identity(
        harness=harness,
        member=member,
        admission=admission,
        role=role,
        contract=contract,
        expected_task_kind=policy.expected_task_kind,
        label=label,
        error=policy.error,
    )
    return proof, harness, response_sha256


def _validate_query_bound_harness(
    *,
    harness: Mapping[str, Any],
    admission: ExecutionAdmission,
    role: str,
    canonical_response_sha256: str,
    label: str,
    policy: ExecutionProofPolicy,
) -> None:
    query_audit = policy.query_audit_binding(admission.analysis)
    if harness.get("query_audit") != query_audit:
        raise policy.error(f"{label} collector query-audit binding does not match")
    validate_harness_gate(
        harness=harness,
        query_audit=query_audit,
        role=role,
        canonical_response_sha256=canonical_response_sha256,
        label=label,
        policy=policy.harness_gate_policy,
        error=policy.error,
    )


def _admit_fresh_and_durable(
    *,
    member: Mapping[str, Any],
    contract: Mapping[str, Any],
    cohort_id: str,
    frozen_plan_sha256: str,
    label: str,
    policy: ExecutionProofPolicy,
) -> ExecutionAdmission:
    admission = admit_fresh_analysis(
        member=member,
        label=label,
        prior_analysis_ids=policy.prior_analysis_ids,
        parse_timestamp=policy.parse_timestamp,
        error=policy.error,
    )
    policy.validate_durable_job_proof(
        member=member,
        result=admission.result,
        analysis=admission.analysis,
        contract=contract,
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        label=label,
    )
    return admission


def validate_execution_proof(
    *,
    member: Mapping[str, Any],
    role: str,
    contract: Mapping[str, Any],
    cohort_id: str,
    frozen_plan_sha256: str,
    label: str,
    policy: ExecutionProofPolicy,
) -> dict[str, Any]:
    """Admit fresh execution, durable dispatch, trace, query, and route proof."""
    admission = _admit_fresh_and_durable(
        member=member,
        contract=contract,
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        label=label,
        policy=policy,
    )
    proof, harness, response_sha256 = _admit_execution_harness(
        member=member,
        admission=admission,
        role=role,
        contract=contract,
        label=label,
        policy=policy,
    )
    _validate_query_bound_harness(
        harness=harness,
        admission=admission,
        role=role,
        canonical_response_sha256=response_sha256,
        label=label,
        policy=policy,
    )
    validate_harness_freshness(
        harness=harness,
        admission=admission,
        label=label,
        parse_timestamp=policy.parse_timestamp,
        error=policy.error,
    )
    return dict(proof)
