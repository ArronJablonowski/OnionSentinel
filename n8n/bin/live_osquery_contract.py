#!/usr/bin/env python3
"""Stable facade for the restricted Onion Sentinel live-host OSQuery contract.

The same flat contract unit is installed on the Mac Studio, Relay, and Security
Onion. Cohesive lower-level owners implement policy and validation while this
module preserves the original import namespace at every trust boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

from live_osquery_contract_query import (
    normalize_query,
    projected_columns,
    query_row_limit,
)
from live_osquery_contract_request import (
    normalize_request,
    normalize_requests,
    normalize_target_aliases,
    validate_transport_payload,
)
from live_osquery_contract_result import bounded_json_bytes, validate_result_artifact
from live_osquery_contract_schema import (
    ALLOWED_TABLE_COLUMNS,
    ALLOWED_TABLES,
    DEFAULT_ROWS,
    MAX_PURPOSE_CHARS,
    MAX_QUERY_CHARS,
    MAX_REPORTED_ROWS,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_RESULT_DURATION_MS,
    MAX_ROWS,
    MAX_TARGET_ALIASES,
    SCHEMA,
    TARGET_OSQUERY_VERSION,
    TARGET_PLATFORM,
    LiveOsqueryContractError,
    _ALIAS,
    _FORBIDDEN_QUERY_SHAPES,
    _FORBIDDEN_SQL,
    _FORBIDDEN_TARGETS,
    _FROM_CLAUSE,
    _FUNCTION_CALL,
    _RESULT_STATUSES,
    _SAFE_PROJECTION_ITEM,
    _SELECT_PROJECTION,
    _SQL_IDENTIFIER,
    _SQL_KEYWORDS,
    _SQL_STRING_LITERAL,
    _TABLE_REFERENCE,
    _TERMINAL_LIMIT,
    _bounded_text,
)
