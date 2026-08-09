#!/usr/bin/env python3
"""Load and normalize one sealed cohort result export."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

from cohort_evaluation_result_export import (
    ResultExportPolicy,
    normalize_result_export,
)
from cohort_evaluation_result_member import ResultMemberPolicy


@dataclass(frozen=True)
class ResultLoaderPolicy:
    role_labels: Mapping[str, str]
    result_schema: str
    manifest_schema: str
    digest_pattern: Pattern[str]
    stable_group_id_pattern: Pattern[str]
    verdict_fields: Sequence[str]
    hash_value: Callable[[Any], str]
    load_private_json: Callable[[Path, str], tuple[dict[str, Any], str]]
    validate_embedded_digest: Callable[[Mapping[str, Any], str], None]
    safe_content_policy: Callable[[Mapping[str, Any], str], None]
    execution_contract: Callable[[Any, str], Mapping[str, Any]]
    stable_group_key: Callable[[Any, str], str]
    validate_execution_proof: Callable[..., Mapping[str, Any]]
    observed_labels: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    query_audit_summary: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    error: type[RuntimeError]


def load_result_export(
    path: Path,
    *,
    role: str,
    expected_count: int,
    policy: ResultLoaderPolicy,
) -> tuple[dict[str, Any], str]:
    """Load, execution-gate, and normalize one metadata-only result export."""
    label = f"{policy.role_labels[role]} result export"
    document, source_file_sha256 = policy.load_private_json(path, label)
    normalized = normalize_result_export(
        document=document,
        role=role,
        expected_count=expected_count,
        label=label,
        policy=ResultExportPolicy(
            result_schema=policy.result_schema,
            manifest_schema=policy.manifest_schema,
            digest_pattern=policy.digest_pattern,
            hash_value=policy.hash_value,
            validate_embedded_digest=policy.validate_embedded_digest,
            safe_content_policy=policy.safe_content_policy,
            execution_contract=policy.execution_contract,
            member_policy=ResultMemberPolicy(
                stable_group_id_pattern=policy.stable_group_id_pattern,
                verdict_fields=policy.verdict_fields,
                stable_group_key=policy.stable_group_key,
                hash_value=policy.hash_value,
                validate_execution_proof=policy.validate_execution_proof,
                observed_labels=policy.observed_labels,
                query_audit_summary=policy.query_audit_summary,
            ),
        ),
        error=policy.error,
    )
    return normalized, source_file_sha256
