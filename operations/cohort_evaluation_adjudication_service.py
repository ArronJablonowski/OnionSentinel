#!/usr/bin/env python3
"""Compose independent adjudication and pre-dispatch evidence-seal policy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from cohort_adjudication import (
    AdjudicationPolicy,
    normalize_duplicate_of,
    validate_adjudication,
    validate_ground_truth,
)
from cohort_evidence_seal import (
    EvidenceSealPolicy,
    bind_adjudication_ground_truth,
    bind_evidence_seal,
    validate_evidence_seal,
)
from cohort_evaluation_contracts import (
    ADJUDICATION_SCHEMA,
    CODE_RE,
    COHORT_ID_RE,
    EVIDENCE_SEAL_SCHEMA,
    HARD_FAILURE_CODES,
    MAX_CODE_ITEMS,
    MAX_CODE_LENGTH,
    QUERY_CLASSES,
    RUBRIC_WEIGHTS,
    SHA256_RE,
    STABLE_GROUP_ID_RE,
    SUPPORTED_ROLES,
    VERDICT_FIELDS,
    VERDICT_VALUE_SETS,
)


@dataclass(frozen=True)
class AdjudicationSealService:
    error: type[RuntimeError]
    parse_timestamp: Callable[[Any, str], Any]
    hash_value: Callable[[Any], str]
    validate_embedded_digest: Callable[[Mapping[str, Any], str], None]

    def adjudication_policy(self) -> AdjudicationPolicy:
        return AdjudicationPolicy(
            error=self.error,
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

    def normalize_ground_truth(self, value: Any, label: str) -> Mapping[str, Any]:
        return validate_ground_truth(value, label, self.adjudication_policy())

    def evidence_seal_policy(self) -> EvidenceSealPolicy:
        return EvidenceSealPolicy(
            error=self.error,
            schema=EVIDENCE_SEAL_SCHEMA,
            roles=SUPPORTED_ROLES,
            cohort_id_pattern=COHORT_ID_RE,
            stable_group_id_pattern=STABLE_GROUP_ID_RE,
            sha256_pattern=SHA256_RE,
            parse_timestamp=self.parse_timestamp,
            hash_value=self.hash_value,
            validate_embedded_digest=self.validate_embedded_digest,
            normalize_ground_truth=self.normalize_ground_truth,
        )

    def normalize_duplicate(self, value: Any, label: str) -> str | None:
        return normalize_duplicate_of(value, label, self.error)

    def validate_adjudication(
        self,
        document: Mapping[str, Any],
        *,
        expected_roles: Sequence[str],
        expected_count: int,
    ) -> dict[str, Any]:
        return validate_adjudication(
            document,
            expected_roles=expected_roles,
            expected_count=expected_count,
            policy=self.adjudication_policy(),
        )

    def validate_evidence_seal(
        self,
        document: Mapping[str, Any],
        *,
        expected_count: int,
    ) -> dict[str, Any]:
        return validate_evidence_seal(
            document,
            expected_count=expected_count,
            policy=self.evidence_seal_policy(),
        )

    def bind_evidence_seal(
        self,
        seal: Mapping[str, Any],
        loaded: Mapping[str, Mapping[str, Any]],
        roles: Sequence[str],
    ) -> dict[str, Any]:
        return bind_evidence_seal(
            seal, loaded, roles, self.evidence_seal_policy()
        )

    def bind_adjudication_ground_truth(
        self,
        adjudication: Mapping[str, Any],
        seal: Mapping[str, Any],
    ) -> None:
        bind_adjudication_ground_truth(
            adjudication, seal, self.evidence_seal_policy()
        )
