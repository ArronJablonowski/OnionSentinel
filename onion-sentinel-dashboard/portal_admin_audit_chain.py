"""Canonical metadata-only keyed chain for administrative audit events."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import hmac
import json
import re

from portal_access_policy import ALL_HUMAN_PERMISSIONS, HUMAN_ROLES


AUDIT_SCHEMA = "onion-sentinel-admin-audit-event-v1"
ZERO_DIGEST = "0" * 64
AUDIT_FIELDS = frozenset({
    "occurred_at",
    "request_id",
    "principal_fingerprint",
    "role",
    "permission",
    "action",
    "target_type",
    "target_digest",
    "outcome",
    "http_status",
    "reason_code",
})
EVENT_FIELDS = AUDIT_FIELDS | frozenset({
    "schema", "sequence", "previous_digest", "event_digest",
})
AUDIT_ROLES = HUMAN_ROLES | frozenset({"unauthenticated", "unknown"})
AUDIT_PERMISSIONS = ALL_HUMAN_PERMISSIONS | frozenset({"authentication.login"})
AUDIT_OUTCOMES = frozenset({"allowed", "denied", "error"})
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")


class AuditContractError(ValueError):
    """Raised when audit metadata cannot be safely admitted."""


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    event_count: int
    head_digest: str
    reason: str
    failed_index: int | None = None


def _signing_key(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise AuditContractError("signing_key must contain at least 32 bytes")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        raise AuditContractError("occurred_at must be a bounded UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuditContractError("occurred_at must be a bounded UTC timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditContractError("occurred_at must be a bounded UTC timestamp")
    return value


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise AuditContractError(f"{field} has an unsupported value")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise AuditContractError(f"{field} must be a SHA-256 digest")
    return value


def _status(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 100 <= value <= 599:
        raise AuditContractError("http_status must be an HTTP status code")
    return value


def _validated_fields(fields: object) -> dict[str, object]:
    if not isinstance(fields, dict) or set(fields) != AUDIT_FIELDS:
        raise AuditContractError("audit fields must match the metadata-only schema")
    role = fields.get("role")
    permission = fields.get("permission")
    outcome = fields.get("outcome")
    if role not in AUDIT_ROLES:
        raise AuditContractError("role has an unsupported value")
    if permission not in AUDIT_PERMISSIONS:
        raise AuditContractError("permission has an unsupported value")
    if outcome not in AUDIT_OUTCOMES:
        raise AuditContractError("outcome has an unsupported value")
    request_id = fields.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise AuditContractError("request_id has an unsupported value")
    return {
        "occurred_at": _timestamp(fields.get("occurred_at")),
        "request_id": request_id,
        "principal_fingerprint": _digest(
            fields.get("principal_fingerprint"), "principal_fingerprint"
        ),
        "role": role,
        "permission": permission,
        "action": _identifier(fields.get("action"), "action"),
        "target_type": _identifier(fields.get("target_type"), "target_type"),
        "target_digest": _digest(fields.get("target_digest"), "target_digest"),
        "outcome": outcome,
        "http_status": _status(fields.get("http_status")),
        "reason_code": _identifier(fields.get("reason_code"), "reason_code"),
    }


def _event_digest(event: dict[str, object], signing_key: bytes) -> str:
    payload = {key: value for key, value in event.items() if key != "event_digest"}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hmac.new(signing_key, encoded, hashlib.sha256).hexdigest()


def _previous(previous_event: object) -> tuple[int, str]:
    if previous_event is None:
        return 1, ZERO_DIGEST
    if not isinstance(previous_event, dict):
        raise AuditContractError("previous event is invalid")
    sequence = previous_event.get("sequence")
    digest = previous_event.get("event_digest")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise AuditContractError("previous event is invalid")
    return sequence + 1, _digest(digest, "previous event digest")


def build_event(
    previous_event: object,
    fields: object,
    *,
    signing_key: object,
) -> dict[str, object]:
    key = _signing_key(signing_key)
    sequence, previous_digest = _previous(previous_event)
    values = _validated_fields(fields)
    event: dict[str, object] = {
        "schema": AUDIT_SCHEMA,
        "sequence": sequence,
        **values,
        "previous_digest": previous_digest,
    }
    event["event_digest"] = _event_digest(event, key)
    return event


def _verification_failure(
    events: list[object], head: str, reason: str, index: int
) -> AuditVerification:
    return AuditVerification(False, len(events), head, reason, index)


def _event_failure_reason(
    event: object,
    index: int,
    previous_digest: str,
    signing_key: bytes,
) -> str | None:
    if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
        return "invalid_event"
    try:
        _validated_fields({field: event.get(field) for field in AUDIT_FIELDS})
    except AuditContractError:
        return "invalid_event"
    if event.get("sequence") != index + 1:
        return "sequence_mismatch"
    if event.get("previous_digest") != previous_digest:
        return "previous_digest_mismatch"
    event_digest = event.get("event_digest")
    if not isinstance(event_digest, str):
        return "digest_mismatch"
    if not hmac.compare_digest(event_digest, _event_digest(event, signing_key)):
        return "digest_mismatch"
    return None


def verify_chain(events: object, *, signing_key: object) -> AuditVerification:
    key = _signing_key(signing_key)
    if not isinstance(events, list):
        return AuditVerification(False, 0, ZERO_DIGEST, "invalid_chain")
    previous_digest = ZERO_DIGEST
    for index, event in enumerate(events):
        reason = _event_failure_reason(event, index, previous_digest, key)
        if reason is not None:
            return _verification_failure(events, previous_digest, reason, index)
        previous_digest = str(event["event_digest"])
    return AuditVerification(True, len(events), previous_digest, "verified")


__all__ = (
    "AUDIT_SCHEMA",
    "AuditContractError",
    "AuditVerification",
    "ZERO_DIGEST",
    "build_event",
    "verify_chain",
)
