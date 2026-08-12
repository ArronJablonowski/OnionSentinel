"""Public and legacy-adapter entrypoint for investigation request validation."""
from __future__ import annotations

from typing import Any

from investigation_query_schema import InvestigationQueryContractError
from investigation_query_normalization import _iso_utc, _parse_utc, _require_mapping
from investigation_query_authorization_proposal import (
    authorize_investigation_query_request,
)
from investigation_query_authorization_request import (
    validate_authorized_investigation_query_request,
)


def validate_investigation_query_request(
    payload: object,
    *,
    authorization_context: object | None = None,
    allowed_observables: object | None = None,
    allowed_windows: object | None = None,
) -> dict[str, Any]:
    """Validate a proposal with trusted context or an authorized request."""
    if authorization_context is not None:
        return authorize_investigation_query_request(payload, authorization_context)
    if allowed_observables is not None or allowed_windows is not None:
        if (
            allowed_observables is None
            or not isinstance(allowed_windows, list)
            or not allowed_windows
        ):
            raise InvestigationQueryContractError(
                "allowed_observables and allowed_windows must be supplied together"
            )
        first = _require_mapping(allowed_windows[0], "allowed window")
        last = _require_mapping(allowed_windows[-1], "allowed window")
        first_start = _parse_utc(first.get("start"), "allowed window start")
        last_end = _parse_utc(last.get("end"), "allowed window end")
        authorization_context = {
            "context_id": "adapter-context",
            "case_id": "adapter-case",
            "actor_role": "incident_responder",
            "anchor": {
                "index": "logs-suricata.alerts-so",
                "id": "adapter-anchor",
            },
            "anchor_time": _iso_utc(first_start + (last_end - first_start) / 2),
            "time_envelope": {
                "start": first.get("start"),
                "end": last.get("end"),
            },
            "permitted_observables": allowed_observables,
            "discovered_observables": [],
        }
        return authorize_investigation_query_request(payload, authorization_context)
    return validate_authorized_investigation_query_request(payload)
