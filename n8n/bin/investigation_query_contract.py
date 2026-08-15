#!/usr/bin/env python3
"""Import-compatible facade for the governed investigation query contract."""
from __future__ import annotations

import sys
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

# Kept as a literal assignment for the fail-closed runtime installer. The v1
# compatibility bundle remains frozen and does not import these v2 modules.
INVESTIGATION_QUERY_CONTRACT = "onion-sentinel-investigation-pivots-v2"

from investigation_query_schema import (  # noqa: E402
    _HISTORICAL_OSQUERY_SCHEMA_CONTRACT as HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
    _HISTORICAL_OSQUERY_SCHEMA_PROFILES as HISTORICAL_OSQUERY_SCHEMA_PROFILES,
)
from historical_osquery_schema import (  # noqa: E402
    compile_historical_osquery_schema_discovery,
    historical_osquery_field_caps_body,
    historical_osquery_field_caps_endpoint,
    validate_historical_osquery_schema_discovery,
)
from investigation_query_schema import *  # noqa: E402,F401,F403
from investigation_query_normalization import *  # noqa: E402,F401,F403
from investigation_query_authorization import *  # noqa: E402,F401,F403
from investigation_query_rendering import *  # noqa: E402,F401,F403
from investigation_query_response import *  # noqa: E402,F401,F403

__all__ = [
    "ALLOWED_AGGREGATIONS",
    "ALLOWED_DIALECTS",
    "ALLOWED_PURPOSES",
    "EVENT_TUPLE_FIELDS",
    "EVENT_TUPLE_PATHS",
    "HISTORICAL_OSQUERY_SCHEMA_CONTRACT",
    "HISTORICAL_OSQUERY_SCHEMA_PROFILES",
    "INVESTIGATION_QUERY_CONTRACT",
    "InvestigationQueryContractError",
    "SAFE_ATOM_RE",
    "authorize_investigation_query_request",
    "build_query_dsl",
    "canonical_digest",
    "compile_historical_osquery_schema_discovery",
    "historical_osquery_field_caps_body",
    "historical_osquery_field_caps_endpoint",
    "kql_equivalent",
    "oql_equivalent",
    "pack_event_tuple_fields",
    "result_coverage",
    "tuple_match_semantics",
    "validate_pack_observables",
    "validate_authorized_investigation_query_request",
    "validate_investigation_query_request",
    "validate_investigation_query_response",
    "validate_historical_osquery_schema_discovery",
]
