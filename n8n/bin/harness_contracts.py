"""Stable facade for immutable harness contracts and safe projections."""
from __future__ import annotations

import dataclasses
import hashlib
import sqlite3
from typing import Any, Iterable, Mapping, Sequence

from harness_contract_job import (
    JobEnvelopeProjectionServices,
    job_envelope_values,
)
from harness_contract_ledger import (
    LEDGER_TABLE_ORDERS,
    LEGACY_RUN_IDENTITY_COLUMNS_V1,
    LEGACY_RUN_IDENTITY_COLUMNS_V2,
    RUN_IDENTITY_COLUMNS,
    SUPPORTED_LEDGER_MANIFEST_SCHEMAS,
    approximate_evidence_rows,
    hypothesis_manifest_digest,
    ledger_manifest,
)
from harness_contract_metadata import (
    _redacted_string,
    bounded_metadata,
    sanitize_metadata,
)
from harness_contract_skill_attestation import (
    investigation_skill_selection_attestation,
)
from harness_execution_contract import (
    build_execution_contract,
    execution_contract_digest,
    execution_contract_json,
    parse_execution_contract,
)
from harness_policy import (
    AgentRole,
    DIGEST_RE,
    HARNESS_SCHEMA,
    HarnessIntegrityError,
    HarnessPolicyError,
    IDENTIFIER_RE,
    INVESTIGATION_SKILL_ADVISORY_MODE,
    INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    LEDGER_MANIFEST_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
    LEDGER_MANIFEST_SCHEMA_V2,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    MAX_EVENT_ITEMS,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENT_STRING,
    SECRET_KEY_RE,
    SECRET_VALUE_PATTERNS,
    _model_route,
    _valid_identifier,
    canonical_json,
    digest_json,
    task_kind_for_role,
    utc_now,
)


_JOB_PROJECTION_SERVICES = JobEnvelopeProjectionServices(
    valid_identifier=_valid_identifier,
    model_route=_model_route,
    digest_value=digest_json,
    task_kind_value=task_kind_for_role,
    skill_attestation=investigation_skill_selection_attestation,
    execution_contract_builder=build_execution_contract,
    execution_contract_json_value=execution_contract_json,
    execution_contract_digest_value=execution_contract_digest,
    now_value=utc_now,
)


@dataclasses.dataclass(frozen=True)
class JobEnvelope:
    run_id: str
    trace_id: str
    correlation_id: str
    case_id: str
    alert_id: str
    role: str
    task_kind: str
    assigned_route: str
    assigned_reviewer_route: str
    prompt_digest: str
    evidence_manifest_digest: str
    configuration_digest: str
    execution_contract_json: str
    execution_contract_digest: str
    skill_selection_attestation: dict[str, Any]
    parent_run_id: str
    created_at: str

    @classmethod
    def from_prompt(
        cls,
        *,
        run_id: str,
        prompt_package: Mapping[str, Any],
        role: str,
        assigned_route: str,
        configuration: Mapping[str, Any],
        source_revision: str,
        policy_version: str,
        reanalysis_attempt_id: str = "",
    ) -> "JobEnvelope":
        values = job_envelope_values(
            run_id=run_id,
            prompt_package=prompt_package,
            role=role,
            assigned_route=assigned_route,
            configuration=configuration,
            source_revision=source_revision,
            policy_version=policy_version,
            reanalysis_attempt_id=reanalysis_attempt_id,
            services=_JOB_PROJECTION_SERVICES,
        )
        return cls(**values)

    @property
    def job_digest(self) -> str:
        value = dataclasses.asdict(self)
        value.pop("created_at", None)
        return digest_json(value)
