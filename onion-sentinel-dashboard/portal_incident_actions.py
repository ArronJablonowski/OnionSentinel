"""Pure validation policy for Incident Response analyst actions."""
from __future__ import annotations


INCIDENT_CASE_STATUSES = frozenset({"open", "in_progress", "resolved"})


class IncidentStatusPayloadError(ValueError):
    """Raised when a requested incident status transition is malformed."""


def normalize_incident_status_payload(
    case_id: str,
    payload: dict | None,
) -> dict:
    payload = payload if isinstance(payload, dict) else {}
    status = str(payload.get("status") or "").strip().lower()
    resolution_reason = str(
        payload.get("resolution_reason") or ""
    ).strip()[:2000]
    updated_by = str(
        payload.get("updated_by")
        or payload.get("reviewer")
        or "dashboard"
    ).strip()[:100]
    if status not in INCIDENT_CASE_STATUSES:
        raise IncidentStatusPayloadError("Invalid incident case status")
    if status == "resolved" and not resolution_reason:
        raise IncidentStatusPayloadError("A resolution reason is required.")
    return {
        "case_id": case_id,
        "status": status,
        "resolution_reason": resolution_reason,
        "updated_by": updated_by,
    }
