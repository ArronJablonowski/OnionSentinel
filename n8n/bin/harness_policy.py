"""Stable facade for investigation harness policy contracts."""
from __future__ import annotations

import sys
from pathlib import Path


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from harness_policy_capabilities import (  # noqa: E402,F401
    ALL_CAPABILITIES,
    APPROVAL_GATED_CAPABILITIES,
    DEFAULT_ROLE_CAPABILITIES,
    EXTERNAL_AGENT_HARNESS_PROVIDERS,
    MUTATING_CAPABILITIES,
    PolicyDecision,
    QUERY_BACKEND_CAPABILITIES,
    READ_ONLY_CAPABILITIES,
    SENSITIVE_ACTIVE_CAPABILITIES,
    external_agent_harness_provider,
    policy_decision_is_effective,
    query_backend_capability,
    query_backend_is_approval_gated,
    should_start_onion_sentinel_harness,
)
from harness_policy_document import (  # noqa: E402,F401
    DEFAULT_BUDGETS,
    MAX_BUDGETS,
    MIN_BUDGETS,
    REQUIRED_MEMORY_FIELDS,
    REQUIRED_POLICY_FIELDS,
    HarnessPolicy,
    load_policy,
)
from harness_policy_primitives import (  # noqa: E402,F401
    DEFAULT_DB_PATH,
    DEFAULT_HARNESS_LOG_PATH,
    DEFAULT_POLICY_PATH,
    DIGEST_RE,
    HARNESS_SCHEMA,
    IDENTIFIER_RE,
    INVESTIGATION_SKILL_ADVISORY_MODE,
    INVESTIGATION_SKILL_ATTESTATION_KEYS,
    INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    LEDGER_MANIFEST_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
    LEDGER_MANIFEST_SCHEMA_V2,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    MAX_DECISION_EVIDENCE_REFS,
    MAX_EVENT_ITEMS,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENT_STRING,
    MAX_EVIDENCE_REFS,
    MAX_HYPOTHESES,
    MAX_POLICY_BYTES,
    POLICY_SCHEMA,
    SECRET_KEY_RE,
    SECRET_VALUE_PATTERNS,
    SQL_SCHEMA_VERSION,
    TRACE_SCHEMA,
    AgentRole,
    HarnessError,
    HarnessIntegrityError,
    HarnessPolicyError,
    RunStatus,
    Stage,
    TaskKind,
    TrustTier,
    _digest_or_hash,
    _model_route,
    _nonnegative_int,
    _valid_identifier,
    canonical_json,
    digest_json,
    task_kind_for_role,
    utc_now,
)
