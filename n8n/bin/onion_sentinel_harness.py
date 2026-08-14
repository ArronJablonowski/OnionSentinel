#!/usr/bin/env python3
"""Durable, model-neutral investigation harness for Onion Sentinel.

The harness is deliberately a trusted control-plane component. Models may
propose queries, hypotheses, memory candidates, and actions, but this module
owns policy decisions, durable run state, provenance, and audit integrity.

Version 1 is a shadow-capable runtime around the existing production runner.
It does not give a model direct shell, database, Security Onion, or credential
access. Existing typed brokers remain the only query execution boundary.
"""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import enum
import hashlib
import hmac
import importlib.util
import json
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

HARNESS_SOURCE_DIR = Path(__file__).resolve().parent
if str(HARNESS_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(HARNESS_SOURCE_DIR))

try:
    from security_jsonl_log import SecurityJsonlLogger
except ModuleNotFoundError:
    _logging_spec = importlib.util.spec_from_file_location(
        "security_jsonl_log",
        Path(__file__).with_name("security_jsonl_log.py"),
    )
    if _logging_spec is None or _logging_spec.loader is None:
        raise
    _logging_module = importlib.util.module_from_spec(_logging_spec)
    sys.modules.setdefault("security_jsonl_log", _logging_module)
    _logging_spec.loader.exec_module(_logging_module)
    SecurityJsonlLogger = _logging_module.SecurityJsonlLogger


from harness_policy import (
    HARNESS_SCHEMA,
    POLICY_SCHEMA,
    TRACE_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
    LEDGER_MANIFEST_SCHEMA_V2,
    LEDGER_MANIFEST_SCHEMA,
    SQL_SCHEMA_VERSION,
    DEFAULT_POLICY_PATH,
    DEFAULT_DB_PATH,
    DEFAULT_HARNESS_LOG_PATH,
    MAX_POLICY_BYTES,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENT_STRING,
    MAX_EVENT_ITEMS,
    MAX_EVIDENCE_REFS,
    MAX_HYPOTHESES,
    MAX_DECISION_EVIDENCE_REFS,
    IDENTIFIER_RE,
    DIGEST_RE,
    INVESTIGATION_SKILL_ADVISORY_MODE,
    INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    INVESTIGATION_SKILL_ATTESTATION_KEYS,
    EXTERNAL_AGENT_HARNESS_PROVIDERS,
    external_agent_harness_provider,
    should_start_onion_sentinel_harness,
    HarnessError,
    HarnessPolicyError,
    HarnessIntegrityError,
    AgentRole,
    TaskKind,
    RunStatus,
    Stage,
    TrustTier,
    READ_ONLY_CAPABILITIES,
    MUTATING_CAPABILITIES,
    SENSITIVE_ACTIVE_CAPABILITIES,
    APPROVAL_GATED_CAPABILITIES,
    ALL_CAPABILITIES,
    QUERY_BACKEND_CAPABILITIES,
    query_backend_capability,
    query_backend_is_approval_gated,
    DEFAULT_ROLE_CAPABILITIES,
    DEFAULT_BUDGETS,
    MIN_BUDGETS,
    MAX_BUDGETS,
    REQUIRED_POLICY_FIELDS,
    REQUIRED_MEMORY_FIELDS,
    SECRET_KEY_RE,
    SECRET_VALUE_PATTERNS,
    utc_now,
    canonical_json,
    digest_json,
    _valid_identifier,
    _model_route,
    _digest_or_hash,
    _nonnegative_int,
    PolicyDecision,
    policy_decision_is_effective,
    HarnessPolicy,
    load_policy,
    task_kind_for_role,
)


from harness_query_contract import (
    RETURNED_COUNT_KEYS,
    observed_returned_count,
    observed_truncation,
    QUERY_SUCCESS_STATUSES,
    SECURITY_ONION_QUERY_STATUSES,
    resolve_query_binding,
)

from harness_contracts import (
    sanitize_metadata,
    bounded_metadata,
    investigation_skill_selection_attestation,
    hypothesis_manifest_digest,
    LEDGER_TABLE_ORDERS,
    RUN_IDENTITY_COLUMNS,
    LEGACY_RUN_IDENTITY_COLUMNS_V1,
    SUPPORTED_LEDGER_MANIFEST_SCHEMAS,
    ledger_manifest,
    approximate_evidence_rows,
    JobEnvelope,
    _redacted_string,
)


from harness_store_foundation import (
    HarnessStoreFoundation,
    _connect,
    _probe_existing_schema_version,
    _secure_sqlite_files,
)
from harness_store_decision_repository import HarnessStoreDecisionRepository
from harness_store_execution_repository import HarnessStoreExecutionRepository
from harness_store_run_repository import HarnessStoreRunRepository
from harness_store_trace_repository import HarnessStoreTraceRepository
from harness_run_foundation import HarnessRunFoundation
from harness_run_execution import HarnessRunExecution, PHASE_STAGE_MAP
from harness_run_completion import HarnessRunCompletion
from harness_memory import memory_promotion_decision


class HarnessStore(
    HarnessStoreTraceRepository,
    HarnessStoreExecutionRepository,
    HarnessStoreDecisionRepository,
    HarnessStoreRunRepository,
    HarnessStoreFoundation,
):
    """Owner-only SQLite event store with per-run hash chains."""





class HarnessRun(HarnessRunCompletion, HarnessRunExecution, HarnessRunFoundation):
    """Small integration surface used by the existing model runner."""




def start_harness_run(
    *,
    run_id: str,
    source_revision: str = "",
    prompt_package: Mapping[str, Any],
    role: str,
    assigned_route: str,
    configuration: Mapping[str, Any],
    reanalysis_attempt_id: str = "",
    policy_path: Path = DEFAULT_POLICY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    policy: HarnessPolicy | None = None,
) -> HarnessRun | None:
    effective_policy = policy or load_policy(policy_path)
    start_allowed, _ = should_start_onion_sentinel_harness(
        policy_enabled=effective_policy.enabled,
        assigned_route=assigned_route,
        reviewer_route=configuration.get("reviewer_route"),
    )
    if not start_allowed:
        return None
    envelope = JobEnvelope.from_prompt(
        run_id=run_id,
        prompt_package=prompt_package,
        role=role,
        assigned_route=assigned_route,
        configuration=configuration,
        source_revision=source_revision,
        policy_version=effective_policy.version,
        reanalysis_attempt_id=reanalysis_attempt_id,
    )
    run = HarnessRun(HarnessStore(db_path), envelope, effective_policy)
    run.catalogue_prompt_evidence(prompt_package)
    return run


def main() -> int:
    print(
        "onion_sentinel_harness.py is a runtime module; use the read-only "
        "evaluate-harness-traces.py utility for inspection",
        file=os.sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
