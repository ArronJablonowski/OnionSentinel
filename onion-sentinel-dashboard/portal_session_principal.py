"""Versioned human-session principal and per-session CSRF policy."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
from collections.abc import Callable

from portal_access_policy import HUMAN_PRINCIPAL_KIND, HUMAN_ROLES


SESSION_SCHEMA = "onion-sentinel-human-session-v1"
TOKEN_MINIMUM_LENGTH = 32
PRINCIPAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SESSION_RECORD_FIELDS = frozenset({
    "schema",
    "principal_kind",
    "principal_id",
    "role",
    "issued_at",
    "last_activity_at",
    "absolute_expires_at",
    "idle_expires_at",
    "policy_generation",
    "client_fingerprint",
    "csrf_digest",
})


class SessionPolicyError(ValueError):
    """Raised when trusted code attempts to create invalid session state."""


@dataclass(frozen=True)
class HumanPrincipal:
    principal_kind: str
    principal_id: str
    role: str


@dataclass(frozen=True)
class SessionDecision:
    authorized: bool
    reason: str
    principal: HumanPrincipal | None = None


@dataclass(frozen=True)
class SessionBundle:
    session_id: str
    csrf_token: str
    record: dict[str, object]


def _positive_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise SessionPolicyError(f"{field} must be a positive integer")
    return value


def _policy_generation(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SessionPolicyError("policy_generation must be a non-negative integer")
    return value


def _token(new_token: Callable[[], str], field: str) -> str:
    value = new_token()
    if not isinstance(value, str) or len(value) < TOKEN_MINIMUM_LENGTH:
        raise SessionPolicyError(f"{field} must contain at least 32 characters")
    return value


def create_session_bundle(
    *,
    principal_id: str,
    role: str,
    now_timestamp: int,
    absolute_ttl_seconds: int,
    idle_ttl_seconds: int,
    policy_generation: int,
    client_fingerprint: str,
    new_token: Callable[[], str],
) -> SessionBundle:
    """Create opaque browser values and their secret-free server record."""
    if not isinstance(principal_id, str) or not PRINCIPAL_ID_RE.fullmatch(principal_id):
        raise SessionPolicyError("principal_id has an unsupported value")
    if role not in HUMAN_ROLES:
        raise SessionPolicyError("role has an unsupported value")
    issued_at = _positive_integer(now_timestamp, "now_timestamp")
    absolute_ttl = _positive_integer(absolute_ttl_seconds, "absolute_ttl_seconds")
    idle_ttl = _positive_integer(idle_ttl_seconds, "idle_ttl_seconds")
    if idle_ttl > absolute_ttl:
        raise SessionPolicyError("idle_ttl_seconds cannot exceed absolute_ttl_seconds")
    generation = _policy_generation(policy_generation)
    if not isinstance(client_fingerprint, str) or not client_fingerprint[:128]:
        raise SessionPolicyError("client_fingerprint is required")
    session_id = _token(new_token, "session_id")
    csrf_token = _token(new_token, "csrf_token")
    record: dict[str, object] = {
        "schema": SESSION_SCHEMA,
        "principal_kind": HUMAN_PRINCIPAL_KIND,
        "principal_id": principal_id,
        "role": role,
        "issued_at": issued_at,
        "last_activity_at": issued_at,
        "absolute_expires_at": issued_at + absolute_ttl,
        "idle_expires_at": issued_at + idle_ttl,
        "policy_generation": generation,
        "client_fingerprint": client_fingerprint[:128],
        "csrf_digest": hashlib.sha256(csrf_token.encode("utf-8")).hexdigest(),
    }
    return SessionBundle(session_id, csrf_token, record)


def _invalid(reason: str) -> SessionDecision:
    return SessionDecision(False, reason)


def _record_integer(record: dict[object, object], field: str) -> int | None:
    value = record.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value


def _session_identity(
    record: dict[object, object],
) -> tuple[str, str] | SessionDecision:
    if record.get("principal_kind") != HUMAN_PRINCIPAL_KIND:
        return _invalid("invalid_principal_kind")
    role = record.get("role")
    if role not in HUMAN_ROLES:
        return _invalid("invalid_role")
    principal_id = record.get("principal_id")
    csrf_digest = record.get("csrf_digest")
    if not isinstance(principal_id, str) or not PRINCIPAL_ID_RE.fullmatch(principal_id):
        return _invalid("malformed_record")
    if not isinstance(csrf_digest, str) or not SHA256_RE.fullmatch(csrf_digest):
        return _invalid("malformed_record")
    return principal_id, str(role)


def _record_timing(
    record: dict[object, object],
) -> tuple[int, int, int, int, int] | None:
    values = tuple(
        _record_integer(record, field)
        for field in (
            "issued_at",
            "last_activity_at",
            "absolute_expires_at",
            "idle_expires_at",
            "policy_generation",
        )
    )
    if any(value is None for value in values):
        return None
    issued_at, last_activity, absolute_expiry, idle_expiry, generation = values
    assert all(value is not None for value in values)
    if (
        issued_at <= 0
        or generation < 0
        or not issued_at <= last_activity < idle_expiry <= absolute_expiry
    ):
        return None
    return issued_at, last_activity, absolute_expiry, idle_expiry, generation


def _record_client_fingerprint_valid(record: dict[object, object]) -> bool:
    value = record.get("client_fingerprint")
    return isinstance(value, str) and 1 <= len(value) <= 128


def _record_validation_failure(record: object) -> SessionDecision | None:
    if (
        not isinstance(record, dict)
        or record.get("schema") != SESSION_SCHEMA
        or set(record) != SESSION_RECORD_FIELDS
    ):
        return _invalid("malformed_record")
    identity = _session_identity(record)
    if isinstance(identity, SessionDecision):
        return identity
    if _record_timing(record) is None:
        return _invalid("malformed_record")
    if not _record_client_fingerprint_valid(record):
        return _invalid("malformed_record")
    return None


def is_valid_session_record(record: object) -> bool:
    """Admit only the exact secret-free persisted session shape."""
    return _record_validation_failure(record) is None


def _session_timing_failure(
    record: dict[object, object],
    now_timestamp: int,
    expected_policy_generation: int,
) -> SessionDecision | None:
    generation = _record_integer(record, "policy_generation")
    absolute_expiry = _record_integer(record, "absolute_expires_at")
    idle_expiry = _record_integer(record, "idle_expires_at")
    if generation is None or absolute_expiry is None or idle_expiry is None:
        return _invalid("malformed_record")
    if generation != expected_policy_generation:
        return _invalid("policy_generation_mismatch")
    if now_timestamp >= absolute_expiry:
        return _invalid("absolute_expired")
    if now_timestamp >= idle_expiry:
        return _invalid("idle_expired")
    return None


def session_decision(
    record: object,
    *,
    now_timestamp: int,
    expected_policy_generation: int,
) -> SessionDecision:
    """Admit one current versioned human-session record, or fail closed."""
    validation_failure = _record_validation_failure(record)
    if validation_failure is not None:
        return validation_failure
    assert isinstance(record, dict)
    identity = _session_identity(record)
    if isinstance(identity, SessionDecision):
        return identity
    timing_failure = _session_timing_failure(
        record, now_timestamp, expected_policy_generation
    )
    if timing_failure is not None:
        return timing_failure
    principal_id, role = identity
    principal = HumanPrincipal(HUMAN_PRINCIPAL_KIND, principal_id, role)
    return SessionDecision(True, "authorized", principal)


def csrf_authorized(value: object, record: object) -> bool:
    if not isinstance(value, str) or not value or not isinstance(record, dict):
        return False
    expected = record.get("csrf_digest")
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        return False
    actual = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual, expected)


def touch_session_record(
    record: dict[str, object],
    *,
    now_timestamp: int,
    idle_ttl_seconds: int,
) -> dict[str, object]:
    if not is_valid_session_record(record):
        raise SessionPolicyError("session record has an invalid shape")
    now = _positive_integer(now_timestamp, "now_timestamp")
    idle_ttl = _positive_integer(idle_ttl_seconds, "idle_ttl_seconds")
    try:
        absolute_expiry = int(record["absolute_expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SessionPolicyError("session record has invalid absolute expiry") from exc
    issued_at = int(record["issued_at"])
    if now < issued_at:
        raise SessionPolicyError("session cannot be touched before issuance")
    if now >= absolute_expiry:
        raise SessionPolicyError("expired session cannot be touched")
    return {
        **record,
        "last_activity_at": now,
        "idle_expires_at": min(absolute_expiry, now + idle_ttl),
    }


__all__ = (
    "HumanPrincipal",
    "SESSION_RECORD_FIELDS",
    "SESSION_SCHEMA",
    "SessionBundle",
    "SessionDecision",
    "SessionPolicyError",
    "create_session_bundle",
    "csrf_authorized",
    "is_valid_session_record",
    "session_decision",
    "touch_session_record",
)
