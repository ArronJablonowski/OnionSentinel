#!/usr/bin/env python3
"""Configure sealed cohort grading, proof admission, and bounded reporting."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))

from cohort_model_call_proof import (
    ADJUDICATION_CALL_IDS,
    ADJUDICATION_PURPOSE,
    FOLLOWUP_CALL_RE,
    MAX_RUNTIME_MODEL_CALLS,
    MODEL_CALL_CONTRACT_SCHEMA,
    MODEL_CALL_FACT_KEYS,
    PRIMARY_MODEL_CALLS,
    QUERY_PLANNING_REPAIR_CALL_ID,
    QUERY_PLANNING_REPAIR_PURPOSE,
    REVIEWER_CALL_IDS,
    REVIEWER_PURPOSE,
    SAFE_ROUTE_RE,
    SUPPLEMENTAL_REVIEW_CALL_ID,
    SUPPLEMENTAL_REVIEW_PURPOSE,
    bounded_model_call_proof_valid as validate_bounded_model_call_proof,
)
from cohort_adjudication import (
    AdjudicationPolicy,
    normalize_duplicate_of as normalize_adjudication_duplicate,
    validate_adjudication as normalize_adjudication,
)
from cohort_execution_skills import (
    SkillAttestationPolicy,
    validate_exported_skill_summary,
)
from cohort_evaluation_job_proof import (
    DurableJobPolicy,
    expected_dispatch_id as derive_expected_dispatch_id,
    validate_durable_job_proof,
)
from cohort_evaluation_harness_gate import HarnessGatePolicy
from cohort_evaluation_execution_proof import (
    ExecutionProofPolicy,
    validate_execution_proof as admit_execution_proof,
)
from cohort_evaluation_result_member import normalize_export_member
from cohort_evaluation_scoring import (
    ScoringPolicy,
    case_evaluation as evaluate_case_score,
    cross_role_comparison as compare_roles,
    mean as _mean,
    median as _median,
    role_aggregate as aggregate_role_scores,
    round_stat as _round_stat,
)
from cohort_evaluation_workflow import (
    EvaluationWorkflowPolicy,
)
from cohort_evaluation_api import (
    EvaluationApiPolicy,
    evaluate_cohorts as run_cohort_evaluation,
)
from cohort_evaluation_markdown import render_markdown as render_report_markdown
from cohort_evaluation_private_output import (
    write_private_bytes as write_report_bytes,
    write_private_json as write_report_json,
)
from cohort_evaluation_query_audit import (
    QueryAuditPolicy,
    query_audit_execution_binding as evaluate_query_audit_binding,
    query_audit_summary as summarize_query_audit,
)
from cohort_evaluation_execution_contract import (
    ExecutionContractPolicy,
    validate_execution_contract,
)
from cohort_evaluation_result_policy import (
    observed_labels as normalize_observed_labels,
    validate_safe_export_content,
)
from cohort_execution_result import (
    expected_task_kind as derive_expected_task_kind,
    prior_analysis_ids as collect_prior_analysis_ids,
)
from cohort_evaluation_private_input import (
    PrivateInputPolicy,
    file_sha256 as hash_file,
    load_private_json as read_private_json,
)
from cohort_evaluation_result_loader import (
    ResultLoaderPolicy,
    load_result_export as normalize_result_file,
)
from cohort_evaluation_contracts import (
    ADJUDICATION_SCHEMA,
    CODE_RE,
    COHORT_ID_RE,
    CONTROLLED_EVALUATION_PROFILE,
    CONTROLLED_ROUTE_RE,
    DASHBOARD_GROUP_ID_RE,
    DISPATCH_ID_SCHEMA,
    EXPECTED_ROLE_COUNT,
    HARD_FAILURE_CODES,
    MANIFEST_SCHEMA,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    MAX_CODE_ITEMS,
    MAX_CODE_LENGTH,
    MAX_COHORT_SIZE,
    MAX_GRADED_ROLE_COUNT,
    MAX_INPUT_BYTES,
    MAX_JSON_REPORT_BYTES,
    MAX_MARKDOWN_BYTES,
    MAX_STABLE_GROUP_KEY_BYTES,
    MIN_GRADED_ROLE_COUNT,
    MINIMUM_PASS_RATE,
    PASS_SCORE,
    PROFILE_ASSIGNED_ROUTE,
    PROFILE_REVIEWER_ROUTE,
    QUERY_CLASSES,
    RELEASE_ID_RE,
    REPORT_SCHEMA,
    REPRESENTATIVE_ALERT_ID_RE,
    RESULT_SCHEMA,
    REVIEW_SCORE,
    ROLE_LABELS,
    RUBRIC_WEIGHTS,
    SHA256_RE,
    SKILL_ID_RE,
    STABLE_GROUP_ID_RE,
    SUPPORTED_ROLES,
    VERDICT_FIELDS,
    VERDICT_VALUE_SETS,
)


class CohortEvaluationError(RuntimeError):
    """The cohort cannot be evaluated safely or reproducibly."""


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _stable_group_key(value: Any, label: str) -> str:
    """Validate an opaque stable-group key without normalizing it."""

    if not isinstance(value, str) or not value:
        raise CohortEvaluationError(f"{label} is missing or malformed")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CohortEvaluationError(f"{label} is not valid UTF-8") from exc
    if len(encoded) > MAX_STABLE_GROUP_KEY_BYTES or "\x00" in value:
        raise CohortEvaluationError(
            f"{label} exceeds the bounded stable-group-key contract"
        )
    return value


def _bounded_model_call_proof_valid(harness: Mapping[str, Any]) -> bool:
    """Compatibility adapter for canonical offline model-call proof validation."""
    return validate_bounded_model_call_proof(harness, sha256_value)


def file_sha256(path: Path) -> str:
    return hash_file(path)


def _validate_embedded_digest(document: Mapping[str, Any], field: str) -> None:
    expected = str(document.get(field) or "")
    unsigned = dict(document)
    unsigned.pop(field, None)
    if not SHA256_RE.fullmatch(expected):
        raise CohortEvaluationError(f"{field} is missing or malformed")
    import hmac

    if not hmac.compare_digest(expected, sha256_value(unsigned)):
        raise CohortEvaluationError(f"{field} does not match the document")


def _private_input_policy() -> PrivateInputPolicy:
    return PrivateInputPolicy(
        maximum_bytes=MAX_INPUT_BYTES,
        error=CohortEvaluationError,
    )


def load_private_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    return read_private_json(path, label, _private_input_policy())


def _adjudication_policy() -> AdjudicationPolicy:
    return AdjudicationPolicy(
        error=CohortEvaluationError,
        schema=ADJUDICATION_SCHEMA,
        stable_group_id_pattern=STABLE_GROUP_ID_RE,
        sha256_pattern=SHA256_RE,
        code_pattern=CODE_RE,
        maximum_code_items=MAX_CODE_ITEMS,
        maximum_code_length=MAX_CODE_LENGTH,
        verdict_fields=VERDICT_FIELDS,
        verdict_value_sets=VERDICT_VALUE_SETS,
        rubric_weights=RUBRIC_WEIGHTS,
        hard_failure_codes=HARD_FAILURE_CODES,
        query_classes=QUERY_CLASSES,
    )


def _normalize_duplicate_of(value: Any, label: str) -> str | None:
    """Compatibility adapter for optional duplicate identity."""
    return normalize_adjudication_duplicate(
        value, label, CohortEvaluationError
    )
def validate_adjudication(
    document: Mapping[str, Any],
    *,
    expected_roles: Sequence[str],
    expected_count: int,
) -> dict[str, Any]:
    """Normalize a complete independent adjudication document."""
    return normalize_adjudication(
        document,
        expected_roles=expected_roles,
        expected_count=expected_count,
        policy=_adjudication_policy(),
    )


def _safe_export_content_policy(document: Mapping[str, Any], label: str) -> None:
    validate_safe_export_content(document, label, CohortEvaluationError)


def _observed_labels(analysis: Mapping[str, Any]) -> dict[str, Any]:
    return normalize_observed_labels(
        analysis, _normalize_duplicate_of, CohortEvaluationError
    )


def _query_audit_policy() -> QueryAuditPolicy:
    return QueryAuditPolicy(
        successful_statuses=frozenset(
            {"ok", "complete", "completed", "success", "succeeded"}
        ),
        sha256_pattern=SHA256_RE,
        sha256_value=sha256_value,
    )


def _query_audit_summary(analysis: Mapping[str, Any]) -> dict[str, Any]:
    return summarize_query_audit(analysis)


def _query_audit_execution_binding(
    analysis: Mapping[str, Any],
) -> dict[str, Any]:
    return evaluate_query_audit_binding(analysis, _query_audit_policy())


def _parse_timestamp(value: Any, label: str) -> dt.datetime:
    text = str(value or "").strip()
    text = re.sub(
        r"^(\d{4}-\d{2}-\d{2})\s+",
        r"\1T",
        text,
        count=1,
    )
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CohortEvaluationError(
            f"{label} is not an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise CohortEvaluationError(f"{label} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def _execution_contract_policy() -> ExecutionContractPolicy:
    return ExecutionContractPolicy(
        controlled_route_pattern=CONTROLLED_ROUTE_RE,
        release_id_pattern=RELEASE_ID_RE,
        controlled_profile=CONTROLLED_EVALUATION_PROFILE,
        profile_assigned_route=PROFILE_ASSIGNED_ROUTE,
        profile_reviewer_route=PROFILE_REVIEWER_ROUTE,
        error=CohortEvaluationError,
    )


def _execution_contract(value: Any, label: str) -> dict[str, Any]:
    return validate_execution_contract(
        value, label, _execution_contract_policy()
    )


def _prior_analysis_ids(member: Mapping[str, Any]) -> set[str]:
    return collect_prior_analysis_ids(member)


def _expected_task_kind(role: str, dispatch_kind: str) -> str:
    return derive_expected_task_kind(
        role, dispatch_kind, CohortEvaluationError
    )


def _expected_dispatch_id(
    *,
    cohort_id: str,
    frozen_plan_sha256: str,
    member: Mapping[str, Any],
    dispatch_kind: str,
) -> str:
    return derive_expected_dispatch_id(
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        member=member,
        dispatch_kind=dispatch_kind,
        policy=_durable_job_policy(),
        error=CohortEvaluationError,
    )


def _durable_job_policy() -> DurableJobPolicy:
    return DurableJobPolicy(
        cohort_id_pattern=COHORT_ID_RE,
        frozen_digest_pattern=SHA256_RE,
        dashboard_group_id_pattern=DASHBOARD_GROUP_ID_RE,
        stable_group_id_pattern=STABLE_GROUP_ID_RE,
        representative_alert_id_pattern=REPRESENTATIVE_ALERT_ID_RE,
        payload_digest_pattern=SHA256_RE,
        dispatch_id_schema=DISPATCH_ID_SCHEMA,
        hash_value=sha256_value,
        stable_group_key=_stable_group_key,
        parse_timestamp=_parse_timestamp,
    )


def _validate_durable_job_proof(
    *,
    member: Mapping[str, Any],
    result: Mapping[str, Any],
    analysis: Mapping[str, Any],
    contract: Mapping[str, Any],
    cohort_id: str,
    frozen_plan_sha256: str,
    label: str,
) -> dict[str, Any]:
    return validate_durable_job_proof(
        member=member,
        result=result,
        analysis=analysis,
        contract=contract,
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        label=label,
        policy=_durable_job_policy(),
        error=CohortEvaluationError,
    )


def _validate_skill_selection_attestation_proof(
    harness: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    """Require the collector's bounded, content-free skill proof."""
    return validate_exported_skill_summary(
        harness,
        label,
        SkillAttestationPolicy(
            skill_id_pattern=SKILL_ID_RE,
            sha256_pattern=SHA256_RE,
            maximum_selected=MAX_ATTESTED_INVESTIGATION_SKILLS,
        ),
        CohortEvaluationError,
    )


def _execution_proof_policy() -> ExecutionProofPolicy:
    return ExecutionProofPolicy(
        digest_pattern=SHA256_RE,
        error=CohortEvaluationError,
        prior_analysis_ids=_prior_analysis_ids,
        parse_timestamp=_parse_timestamp,
        validate_embedded_digest=_validate_embedded_digest,
        validate_durable_job_proof=_validate_durable_job_proof,
        validate_skill_summary=_validate_skill_selection_attestation_proof,
        expected_task_kind=_expected_task_kind,
        query_audit_binding=_query_audit_execution_binding,
        harness_gate_policy=HarnessGatePolicy(
            sha256_pattern=SHA256_RE,
            hash_value=sha256_value,
            bounded_model_call_proof_valid=_bounded_model_call_proof_valid,
        ),
    )


def _validate_execution_proof(
    *,
    member: Mapping[str, Any],
    role: str,
    contract: Mapping[str, Any],
    cohort_id: str,
    frozen_plan_sha256: str,
    label: str,
) -> dict[str, Any]:
    return admit_execution_proof(
        member=member,
        role=role,
        contract=contract,
        cohort_id=cohort_id,
        frozen_plan_sha256=frozen_plan_sha256,
        label=label,
        policy=_execution_proof_policy(),
    )


def load_result_export(
    path: Path,
    *,
    role: str,
    expected_count: int,
) -> tuple[dict[str, Any], str]:
    return normalize_result_file(
        path,
        role=role,
        expected_count=expected_count,
        policy=ResultLoaderPolicy(
            role_labels=ROLE_LABELS,
            result_schema=RESULT_SCHEMA,
            manifest_schema=MANIFEST_SCHEMA,
            digest_pattern=SHA256_RE,
            stable_group_id_pattern=STABLE_GROUP_ID_RE,
            verdict_fields=VERDICT_FIELDS,
            hash_value=sha256_value,
            load_private_json=load_private_json,
            validate_embedded_digest=_validate_embedded_digest,
            safe_content_policy=_safe_export_content_policy,
            execution_contract=_execution_contract,
            stable_group_key=_stable_group_key,
            validate_execution_proof=_validate_execution_proof,
            observed_labels=_observed_labels,
            query_audit_summary=_query_audit_summary,
            error=CohortEvaluationError,
        ),
    )


def _scoring_policy() -> ScoringPolicy:
    return ScoringPolicy(
        verdict_fields=VERDICT_FIELDS,
        rubric_weights=RUBRIC_WEIGHTS,
        pass_score=PASS_SCORE,
        review_score=REVIEW_SCORE,
        minimum_pass_rate=MINIMUM_PASS_RATE,
        production_role_count=EXPECTED_ROLE_COUNT,
    )


def _case_evaluation(
    *,
    role: str,
    result: Mapping[str, Any],
    adjudication: Mapping[str, Any],
) -> dict[str, Any]:
    return evaluate_case_score(
        role=role,
        result=result,
        adjudication=adjudication,
        policy=_scoring_policy(),
        error=CohortEvaluationError,
    )


def _role_aggregate(
    role: str,
    cases: Sequence[Mapping[str, Any]],
    expected_count: int,
) -> dict[str, Any]:
    return aggregate_role_scores(
        role, cases, expected_count, _scoring_policy()
    )


def _cross_role_comparison(
    roles: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any] | None:
    return compare_roles(roles, SUPPORTED_ROLES, _scoring_policy())


def _workflow_policy() -> EvaluationWorkflowPolicy:
    return EvaluationWorkflowPolicy(
        supported_roles=SUPPORTED_ROLES,
        minimum_role_count=MIN_GRADED_ROLE_COUNT,
        maximum_role_count=MAX_GRADED_ROLE_COUNT,
        controlled_profile=CONTROLLED_EVALUATION_PROFILE,
        report_schema=REPORT_SCHEMA,
        rubric_weights=RUBRIC_WEIGHTS,
        pass_score=PASS_SCORE,
        review_score=REVIEW_SCORE,
        minimum_pass_rate=MINIMUM_PASS_RATE,
        production_role_count=EXPECTED_ROLE_COUNT,
        hard_failure_codes=tuple(HARD_FAILURE_CODES),
        utc_now=utc_now,
        hash_value=sha256_value,
        case_evaluation=_case_evaluation,
        role_aggregate=_role_aggregate,
        cross_role_comparison=_cross_role_comparison,
    )


def _evaluation_api_policy() -> EvaluationApiPolicy:
    return EvaluationApiPolicy(
        workflow=_workflow_policy(),
        load_result_export=load_result_export,
        load_private_json=load_private_json,
        validate_adjudication=validate_adjudication,
        error=CohortEvaluationError,
    )


def evaluate_cohorts(
    *,
    result_paths: Mapping[str, Path],
    adjudication_path: Path,
    expected_count: int = EXPECTED_ROLE_COUNT,
    required_evaluation_profile: str = "",
) -> dict[str, Any]:
    return run_cohort_evaluation(
        result_paths=result_paths,
        adjudication_path=adjudication_path,
        expected_count=expected_count,
        required_evaluation_profile=required_evaluation_profile,
        policy=_evaluation_api_policy(),
    )


def write_private_bytes(
    path: Path,
    payload: bytes,
    *,
    replace: bool = False,
) -> None:
    write_report_bytes(
        path, payload, replace=replace, error=CohortEvaluationError
    )


def write_private_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    replace: bool = False,
) -> None:
    write_report_json(
        path,
        document,
        maximum_bytes=MAX_JSON_REPORT_BYTES,
        replace=replace,
        error=CohortEvaluationError,
    )


def render_markdown(report: Mapping[str, Any]) -> str:
    return render_report_markdown(
        report,
        role_labels=ROLE_LABELS,
        maximum_bytes=MAX_MARKDOWN_BYTES,
        error=CohortEvaluationError,
    )
