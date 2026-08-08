"""Transport-neutral policy for SOC analyst alert-status mutations."""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus


StatusResult = tuple[bool, dict]
BLOCKING_SUPPRESSION_REVIEW_STATES = frozenset({
    "disputed_pending_human",
    "review_required_failed",
    "review_completed_not_authorized",
})


@dataclass(frozen=True)
class SocAlertStatusWriteSources:
    now_iso: Callable[[], str]
    validate_store_id: Callable[[object], str]
    status_response: Callable[[], dict]
    current_repeat_count: Callable[[str], int]
    suppression_review_state: Callable[[str], dict]
    write_offline_status: Callable[[str, dict], None]
    post_alert_store: Callable[[str, dict], dict]
    alert_store_error: type[Exception]
    alert_store_configured: bool
    direct_write_allowed: bool


def valid_soc_alert_status_id(
    value: object,
    validate_store_id: Callable[[object], str],
) -> str:
    alert_id = str(value or "").strip()
    if re.fullmatch(r"[a-f0-9]{12}", alert_id):
        return alert_id
    return validate_store_id(alert_id)


def _legacy_bulk_payload(payload: dict) -> bool:
    return isinstance(payload.get("statuses"), dict) or isinstance(
        payload.get("acknowledged"), list
    )


def _status_name(payload: dict) -> str:
    status = str(payload.get("status") or "").strip().lower()
    if status:
        return status
    return "acknowledged" if bool(payload.get("acknowledged")) else "open"


def _repeat_count(payload: dict) -> int:
    try:
        return max(
            0,
            int(
                payload.get("repeat_count")
                or payload.get("acknowledged_count")
                or 0
            ),
        )
    except (TypeError, ValueError, OverflowError):
        return 0


def _request_payload(
    payload: dict,
    alert_id: str,
    status: str,
    repeat_count: int,
    now: str,
) -> dict:
    return {
        "id": alert_id,
        "status": status,
        "repeat_count": repeat_count,
        "reason": str(payload.get("reason") or "").strip()[:140],
        "updated_at": now,
        "updated_by": "dashboard",
    }


def _offline_status_update(
    sources: SocAlertStatusWriteSources,
    request_payload: dict,
) -> StatusResult:
    if not sources.direct_write_allowed:
        return False, {
            "ok": False,
            "error": (
                "Direct SQLite writes are disabled; configure the "
                "alert-store API or explicitly enter offline DR mode."
            ),
            "status": int(HTTPStatus.SERVICE_UNAVAILABLE),
        }
    if request_payload["status"] == "suppressed":
        review = sources.suppression_review_state(request_payload["id"])
        if review.get("final_review_status") in (
            BLOCKING_SUPPRESSION_REVIEW_STATES
        ):
            return False, {
                "ok": False,
                "error": (
                    "Required independent review needs explicit analyst "
                    "adjudication before suppression."
                ),
                "status": int(HTTPStatus.CONFLICT),
            }
    sources.write_offline_status(request_payload["id"], request_payload)
    return True, sources.status_response()


def update_soc_alert_status(
    sources: SocAlertStatusWriteSources,
    payload: object,
) -> StatusResult:
    current = payload if isinstance(payload, dict) else {}
    if _legacy_bulk_payload(current):
        # Old tabs may replay stale browser-local state. Preserve route
        # compatibility without allowing them to replace server-owned state.
        return True, sources.status_response()

    alert_id = valid_soc_alert_status_id(
        current.get("id"), sources.validate_store_id
    )
    if not alert_id:
        return False, {"ok": False, "error": "Invalid SOC alert id"}
    status = _status_name(current)
    if status not in {"open", "acknowledged", "suppressed"}:
        return False, {"ok": False, "error": "Invalid SOC alert status"}
    repeat_count = _repeat_count(current)
    if status == "acknowledged" and repeat_count <= 0:
        repeat_count = sources.current_repeat_count(alert_id)
    request_payload = _request_payload(
        current,
        alert_id,
        status,
        repeat_count,
        sources.now_iso(),
    )
    if not sources.alert_store_configured:
        return _offline_status_update(sources, request_payload)
    try:
        result = sources.post_alert_store("/analyst-status", request_payload)
    except sources.alert_store_error as exc:
        return False, {
            "ok": False,
            "error": f"Alert-store state update failed: {exc}",
            "status": int(getattr(exc, "status_code", 503)),
        }
    return True, result
