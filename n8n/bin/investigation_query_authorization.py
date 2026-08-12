"""Compatibility facade for investigation request authorization and validation."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_normalization import *  # noqa: F401,F403
from investigation_query_normalization import (  # noqa: F401
    _event_tuple_authorization,
    _iso_utc,
    _normalize_anchor,
    _normalize_authorization_context,
    _normalize_context_event_tuples,
    _normalize_event_tuple,
    _normalize_observable,
    _normalize_observables,
    _normalize_window,
    _observable_authorizations,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
    _safe_id,
    _validate_tuple_role_compatibility,
)
from investigation_query_authorization_proposal import (
    authorize_investigation_query_request,
)
from investigation_query_authorization_adapter import (
    validate_investigation_query_request,
)
from investigation_query_authorization_request import (
    validate_authorized_investigation_query_request,
)
