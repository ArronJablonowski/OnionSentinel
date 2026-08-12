"""Stable facade for query-result observation and binding resolution."""
from __future__ import annotations

import hmac
from typing import Any, Mapping, Sequence

from harness_policy import DIGEST_RE, MAX_EVENT_ITEMS
from harness_query_binding import resolve_query_binding
from harness_query_binding_validation import (
    QUERY_SUCCESS_STATUSES,
    SECURITY_ONION_QUERY_STATUSES,
)
from harness_query_observation import (
    RETURNED_COUNT_KEYS,
    observed_returned_count,
    observed_truncation,
)
