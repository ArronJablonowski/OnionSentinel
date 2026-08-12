"""Stable facade for investigation-query normalization and authorization."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_authorization_normalization import (
    _event_tuple_authorization,
    _index_matches_scope,
    _normalize_anchor,
    _normalize_authorization_context,
    _observable_authorizations,
)
from investigation_query_event_tuple_normalization import (
    _normalize_context_event_tuples,
    _normalize_event_tuple,
    _validate_tuple_role_compatibility,
    pack_event_tuple_fields,
    tuple_match_semantics,
)
from investigation_query_normalization_primitives import (
    _iso_utc,
    _normalize_window,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
    _safe_id,
)
from investigation_query_observable_normalization import (
    _normalize_observable,
    _normalize_observables,
    pack_observable_fields,
    validate_pack_observables,
)
