"""Manual SOC analysis and Incident Response escalation orchestration."""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


IDENTITY_FIELDS = (
    "representative_alert_id",
    "stable_group_id",
    "stable_group_key",
    "cohort_id",
    "dispatch_id",
)

CONTROLLED_ROUTE_FIELDS = (
    "release_id",
    "expected_assigned_route",
    "expected_reviewer_route",
    "reviewer_required",
)


@dataclass(frozen=True)
class SocActionServiceSources:
    post_json: Callable[..., dict]
    api_error: Callable[[str, int], tuple[int, dict]]
    now_local: Callable[[], str]
    request_error_status: Callable[[BaseException], int | None]


def forward_controlled_dispatch_contract(
    payload: dict,
    request_payload: dict,
) -> None:
    """Forward exact frozen route fields only for controlled dispatches."""
    if "cohort_id" not in payload and "dispatch_id" not in payload:
        return
    for field in CONTROLLED_ROUTE_FIELDS:
        if field in payload:
            request_payload[field] = payload[field]


def _valid_group_id(value: object) -> str:
    group_id = str(value or "").strip().lower()
    return group_id if re.fullmatch(r"[a-f0-9]{12}", group_id) else ""


def _action_request(
    group_id: str,
    payload: dict,
    *,
    default_reason: str,
    reason_limit: int,
    pcap_default: int,
) -> dict:
    request = {
        "group_id": group_id,
        "reason": str(payload.get("reason") or default_reason)[:reason_limit],
        "requested_by": str(payload.get("requested_by") or "dashboard")[:100],
        "related_limit": max(
            1, min(500, int(payload.get("related_limit", 250)))
        ),
        "pcap_analysis_limit": max(
            1, min(25, int(payload.get("pcap_analysis_limit", pcap_default)))
        ),
    }
    for field in IDENTITY_FIELDS:
        if field in payload:
            request[field] = payload[field]
    forward_controlled_dispatch_contract(payload, request)
    return request


def _post_action(
    sources: SocActionServiceSources,
    path: str,
    request: dict,
    *,
    failure_prefix: str,
    limit_error: str,
) -> tuple[dict | None, tuple[int, dict] | None]:
    try:
        return sources.post_json(path, request, timeout=10.0), None
    except Exception as exc:
        if isinstance(exc, (TypeError, ValueError)):
            return None, sources.api_error(limit_error, 400)
        if (status := sources.request_error_status(exc)) is not None:
            return None, sources.api_error(f"{failure_prefix}: {exc}", status)
        if isinstance(exc, RuntimeError):
            return None, sources.api_error(f"{failure_prefix}: {exc}", 503)
        raise


def queue_soc_alert_analysis(
    sources: SocActionServiceSources,
    group_id: object,
    payload: object = None,
) -> tuple[int, dict]:
    """Record durable manual reanalysis intent for one SOC group."""
    normalized_group = _valid_group_id(group_id)
    if not normalized_group:
        return sources.api_error("Invalid SOC alert group id", 400)
    current = payload if isinstance(payload, dict) else {}
    try:
        request = _action_request(
            normalized_group,
            current,
            default_reason="SOC analyst requested fresh AI analysis",
            reason_limit=500,
            pcap_default=8,
        )
    except (TypeError, ValueError):
        return sources.api_error("AI analysis queue limits must be integers", 400)
    data, error = _post_action(
        sources,
        "/ai/request",
        request,
        failure_prefix="Alert-store AI queue request failed",
        limit_error="AI analysis queue limits must be integers",
    )
    if error:
        return error
    return 202, {
        **data,
        "ai_status_key": "queued",
        "ai_status_label": "Queued",
        "ai_status_detail": (
            f"Manual SOC Analyst reanalysis queued at {sources.now_local()}"
        ),
    }


def escalate_soc_alert(
    sources: SocActionServiceSources,
    group_id: object,
    payload: object = None,
) -> tuple[int, dict]:
    """Create or refresh one durable Incident Response case."""
    normalized_group = _valid_group_id(group_id)
    if not normalized_group:
        return sources.api_error("Invalid SOC alert group id", 400)
    current = payload if isinstance(payload, dict) else {}
    try:
        request = _action_request(
            normalized_group,
            current,
            default_reason="Escalated from SOC Alerts for incident response",
            reason_limit=1000,
            pcap_default=25,
        )
    except (TypeError, ValueError):
        return sources.api_error(
            "Incident response queue limits must be integers", 400
        )
    data, error = _post_action(
        sources,
        "/incidents/escalate",
        request,
        failure_prefix="Incident response escalation failed",
        limit_error="Incident response queue limits must be integers",
    )
    if error:
        return error
    return 202, {
        **data,
        "agent_status": "queued",
        "agent_status_label": "Queued",
        "detail": (
            f"Incident Responder analysis queued at {sources.now_local()}"
        ),
    }
