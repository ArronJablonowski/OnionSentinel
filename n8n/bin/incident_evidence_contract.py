#!/usr/bin/env python3
"""Compatibility facade for restricted incident-evidence validation.

The stable module retains the existing constants, exception identity, private
characterization helpers, and public validator while domain owners perform the
pure fail-closed validation work.
"""

from __future__ import annotations

from pathlib import Path
import sys


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from incident_evidence_artifact_contract import (
    validate_incident_evidence_artifact,
)
from incident_evidence_control_contract import (
    validate_controls as _validate_controls,
)
from incident_evidence_osquery_contract import (
    validate_osquery_results as _validate_osquery_results,
)
from incident_evidence_primitives import (
    ALERT_INDEX_SCOPE,
    ALLOWED_PACKS,
    ALLOWED_STATUSES,
    ELASTIC_PROMPT_PROJECTION_FIELDS,
    INCIDENT_EVIDENCE_CONTRACT,
    LEGACY_INCIDENT_EVIDENCE_CONTRACT,
    MAX_ELASTIC_HITS,
    MAX_OSQUERY_ROWS,
    OSQUERY_PACKS,
    OSQUERY_PROMPT_PROJECTION_FIELDS,
    PACK_INDEX_SCOPES,
    QUERY_PREFERENCE,
    SAFE_ELASTIC_ID_RE,
    SAFE_ELASTIC_INDEX_RE,
    SHA256_RE,
    canonical_dsl_digest as _canonical_dsl_digest,
    canonical_execution_digest as _canonical_execution_digest,
    index_matches_scope as _index_matches_scope,
    negative_control_dsl as _negative_control_dsl,
    positive_control_dsl as _positive_control_dsl,
    query_digest as _query_digest,
    query_endpoint as _query_endpoint,
    validate_anchor as _validate_anchor,
)
from incident_evidence_search_contract import (
    validate_search_result as _validate_search_result,
)
from incident_evidence_validation import (
    IncidentEvidenceContractError,
    require_mapping as _require_mapping,
    require_nonempty_text as _require_nonempty_text,
    require_nonnegative_int as _require_nonnegative_int,
)


__all__ = [
    "ALERT_INDEX_SCOPE",
    "ALLOWED_PACKS",
    "ALLOWED_STATUSES",
    "ELASTIC_PROMPT_PROJECTION_FIELDS",
    "INCIDENT_EVIDENCE_CONTRACT",
    "IncidentEvidenceContractError",
    "LEGACY_INCIDENT_EVIDENCE_CONTRACT",
    "MAX_ELASTIC_HITS",
    "MAX_OSQUERY_ROWS",
    "OSQUERY_PACKS",
    "OSQUERY_PROMPT_PROJECTION_FIELDS",
    "PACK_INDEX_SCOPES",
    "QUERY_PREFERENCE",
    "SAFE_ELASTIC_ID_RE",
    "SAFE_ELASTIC_INDEX_RE",
    "SHA256_RE",
    "validate_incident_evidence_artifact",
]
