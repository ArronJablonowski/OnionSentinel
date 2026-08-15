"""Observe-only runtime bridge for versioned human sessions and CSRF."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import threading

from portal_access_enforcement import (
    MODE_ADMIN_ENFORCE,
    MODE_LEGACY,
    MODE_OBSERVE,
    MODE_RBAC_ENFORCE,
    parse_mode,
)
from portal_human_session_store import (
    delete_session_record,
    load_session_record,
    put_session_record,
    replace_session_record,
    validate_session_store,
)
from portal_session_principal import (
    HumanPrincipal,
    create_session_bundle,
    csrf_authorized,
    session_decision,
    touch_session_record,
)


SESSION_STORE_FILENAME = ".human_sessions.json"
CSRF_COOKIE_NAME = "onion_sentinel_csrf"
CSRF_HEADER_NAME = "X-Onion-Sentinel-CSRF"
DEFAULT_ABSOLUTE_TTL_SECONDS = 8 * 60 * 60
DEFAULT_IDLE_TTL_SECONDS = 30 * 60
DEFAULT_POLICY_GENERATION = 1
MODE_POLICY_GENERATIONS = {
    MODE_LEGACY: 0,
    MODE_OBSERVE: DEFAULT_POLICY_GENERATION,
    MODE_ADMIN_ENFORCE: 2,
    MODE_RBAC_ENFORCE: 3,
}
SAFE_COOKIE_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]{32,512}$")


class HumanSessionConfigurationError(RuntimeError):
    """Raised when observe-mode human-session startup is unsafe."""


@dataclass(frozen=True)
class SessionObservation:
    principal: HumanPrincipal | None
    csrf_authorized: bool
    reason: str


def human_session_store_path(home: Path) -> Path:
    return Path(home) / "n8n-local" / "admin-state" / SESSION_STORE_FILENAME


def _client_fingerprint(value: object) -> str:
    text = str(value or "")[:256]
    return hashlib.sha256(
        ("onion-sentinel-human-client-v1:" + text).encode("utf-8")
    ).hexdigest()


def _cookie_value(value: object) -> str:
    if not isinstance(value, str) or not SAFE_COOKIE_VALUE_RE.fullmatch(value):
        raise HumanSessionConfigurationError("CSRF cookie value is invalid")
    return value


def csrf_cookie_header(csrf_token: object, max_age: int) -> str:
    value = _cookie_value(csrf_token)
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
        raise HumanSessionConfigurationError("CSRF cookie lifetime is invalid")
    return (
        f"{CSRF_COOKIE_NAME}={value}; Path=/; Max-Age={max_age}; "
        "SameSite=Strict"
    )


def expired_csrf_cookie_header() -> str:
    return (
        f"{CSRF_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Strict"
    )


def _policy_integer(value: object, *, minimum: int) -> int | None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
    ):
        return None
    return value


def _validate_lifetime_policy(
    absolute_ttl_seconds: object,
    idle_ttl_seconds: object,
    policy_generation: object,
) -> tuple[int, int, int]:
    absolute_ttl = _policy_integer(absolute_ttl_seconds, minimum=1)
    idle_ttl = _policy_integer(idle_ttl_seconds, minimum=1)
    generation = _policy_integer(policy_generation, minimum=0)
    if (
        absolute_ttl is None
        or idle_ttl is None
        or generation is None
        or idle_ttl > absolute_ttl
    ):
        raise HumanSessionConfigurationError(
            "human-session lifetime policy is invalid"
        )
    return absolute_ttl, idle_ttl, generation


class HumanSessionRuntime:
    """Dual-write and resolve target sessions without enforcing decisions."""

    def __init__(
        self,
        *,
        mode: str,
        store_path: Path,
        absolute_ttl_seconds: int = DEFAULT_ABSOLUTE_TTL_SECONDS,
        idle_ttl_seconds: int = DEFAULT_IDLE_TTL_SECONDS,
        policy_generation: int | None = None,
        load_record: Callable[..., object] = load_session_record,
        put_record: Callable[..., object] = put_session_record,
        replace_record: Callable[..., object] = replace_session_record,
        delete_record: Callable[..., object] = delete_session_record,
        failure_sink: Callable[[str], object] | None = None,
    ) -> None:
        selected_mode = parse_mode(mode)
        if selected_mode not in {
            MODE_LEGACY,
            MODE_OBSERVE,
            MODE_ADMIN_ENFORCE,
            MODE_RBAC_ENFORCE,
        }:
            raise HumanSessionConfigurationError(
                "configured human-session mode is not qualified"
            )
        absolute_ttl, idle_ttl, generation = _validate_lifetime_policy(
            absolute_ttl_seconds,
            idle_ttl_seconds,
            MODE_POLICY_GENERATIONS[selected_mode]
            if policy_generation is None
            else policy_generation,
        )
        self.mode = selected_mode
        self.store_path = Path(store_path)
        self.absolute_ttl_seconds = absolute_ttl
        self.idle_ttl_seconds = idle_ttl
        self.policy_generation = generation
        self._load_record = load_record
        self._put_record = put_record
        self._replace_record = replace_record
        self._delete_record = delete_record
        self._failure_sink = failure_sink
        self._lock = threading.Lock()
        self._created_count = 0
        self._resolved_count = 0
        self._failure_count = 0
        self._last_failure_type = ""

    @property
    def enabled(self) -> bool:
        return self.mode != MODE_LEGACY

    @property
    def enforcing(self) -> bool:
        return self.mode in {MODE_ADMIN_ENFORCE, MODE_RBAC_ENFORCE}

    def _record_failure(self, error_type: str) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_type = error_type
        if self._failure_sink is not None:
            try:
                self._failure_sink(error_type)
            except Exception:
                pass

    def record_boundary_failure(self, error_type: str) -> None:
        """Record a safe failure type without accepting exception detail."""
        self._record_failure(error_type)

    def create_session(
        self,
        session_id: str,
        *,
        client_identity: object,
        now_timestamp: int,
        new_token: Callable[[], str],
    ) -> str | None:
        if not self.enabled:
            return None
        try:
            csrf_token = new_token()
            values = iter((session_id, csrf_token))
            bundle = create_session_bundle(
                principal_id="local-administrator",
                role="administrator",
                now_timestamp=now_timestamp,
                absolute_ttl_seconds=self.absolute_ttl_seconds,
                idle_ttl_seconds=self.idle_ttl_seconds,
                policy_generation=self.policy_generation,
                client_fingerprint=_client_fingerprint(client_identity),
                new_token=lambda: next(values),
            )
            self._put_record(
                self.store_path, bundle.session_id, bundle.record
            )
        except Exception as exc:
            self._record_failure(type(exc).__name__)
            return None
        with self._lock:
            self._created_count += 1
        return bundle.csrf_token

    def _remove_invalid(self, session_id: str) -> None:
        try:
            self._delete_record(self.store_path, session_id)
        except Exception as exc:
            self._record_failure(type(exc).__name__)

    def _touch_authorized_session(
        self,
        session_id: str,
        record: dict[str, object],
        now_timestamp: int,
    ) -> bool:
        touched = touch_session_record(
            record,
            now_timestamp=now_timestamp,
            idle_ttl_seconds=self.idle_ttl_seconds,
        )
        replaced = self._replace_record(
            self.store_path,
            session_id,
            expected_record=record,
            replacement=touched,
        )
        if replaced:
            return True
        self._record_failure("SessionTouchConflict")
        return not self.enforcing

    def resolve_session(
        self,
        session_id: str,
        *,
        csrf_value: object,
        now_timestamp: int,
        activity_authorized: bool = True,
    ) -> SessionObservation:
        return self._resolve_session(
            session_id,
            csrf_value=csrf_value,
            now_timestamp=now_timestamp,
            activity_authorized=activity_authorized,
            csrf_required=True,
        )

    def resolve_read_session(
        self,
        session_id: str,
        *,
        now_timestamp: int,
    ) -> SessionObservation:
        """Resolve and touch an authenticated read without requiring CSRF."""
        return self._resolve_session(
            session_id,
            csrf_value=None,
            now_timestamp=now_timestamp,
            activity_authorized=True,
            csrf_required=False,
        )

    def _resolve_session(
        self,
        session_id: str,
        *,
        csrf_value: object,
        now_timestamp: int,
        activity_authorized: bool,
        csrf_required: bool,
    ) -> SessionObservation:
        if not self.enabled:
            return SessionObservation(None, False, "observation_disabled")
        if not session_id:
            return SessionObservation(None, False, "session_missing")
        try:
            current = self._load_current_session(
                session_id, now_timestamp
            )
            if isinstance(current, SessionObservation):
                return current
            record, decision = current
            csrf_ok = csrf_authorized(csrf_value, record)
            if self.enforcing and (
                not activity_authorized or (csrf_required and not csrf_ok)
            ):
                return SessionObservation(
                    decision.principal, csrf_ok, decision.reason
                )
            if not self._touch_authorized_session(
                session_id, record, now_timestamp
            ):
                return SessionObservation(
                    None, False, "session_touch_conflict"
                )
        except Exception as exc:
            self._record_failure(type(exc).__name__)
            return SessionObservation(
                None, False, "session_observation_failed"
            )
        with self._lock:
            self._resolved_count += 1
        return SessionObservation(decision.principal, csrf_ok, decision.reason)

    def _load_current_session(
        self,
        session_id: str,
        now_timestamp: int,
    ) -> tuple[dict[str, object], object] | SessionObservation:
        record = self._load_record(self.store_path, session_id)
        if record is None:
            return SessionObservation(None, False, "session_missing")
        decision = session_decision(
            record,
            now_timestamp=now_timestamp,
            expected_policy_generation=self.policy_generation,
        )
        if not decision.authorized:
            self._remove_invalid(session_id)
            return SessionObservation(None, False, decision.reason)
        assert isinstance(record, dict)
        return record, decision

    def destroy_session(self, session_id: str) -> bool:
        if not self.enabled or not session_id:
            return False
        try:
            return bool(self._delete_record(self.store_path, session_id))
        except Exception as exc:
            self._record_failure(type(exc).__name__)
            return False

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "mode": self.mode,
                "enabled": self.enabled,
                "policy_generation": self.policy_generation,
                "created_count": self._created_count,
                "resolved_count": self._resolved_count,
                "failure_count": self._failure_count,
                "last_failure_type": self._last_failure_type,
            }


def load_human_session_runtime(
    *,
    mode: str,
    home: Path,
    failure_sink: Callable[[str], object] | None = None,
) -> HumanSessionRuntime:
    try:
        selected_mode = parse_mode(mode)
    except Exception as exc:
        raise HumanSessionConfigurationError(
            "configured human-session mode is invalid"
        ) from exc
    path = human_session_store_path(home)
    if selected_mode in {
        MODE_OBSERVE,
        MODE_ADMIN_ENFORCE,
        MODE_RBAC_ENFORCE,
    }:
        try:
            validate_session_store(path)
        except Exception as exc:
            raise HumanSessionConfigurationError(
                "human-session store validation failed"
            ) from exc
    return HumanSessionRuntime(
        mode=selected_mode,
        store_path=path,
        failure_sink=failure_sink,
    )


__all__ = (
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
    "HumanSessionConfigurationError",
    "HumanSessionRuntime",
    "SessionObservation",
    "csrf_cookie_header",
    "expired_csrf_cookie_header",
    "human_session_store_path",
    "load_human_session_runtime",
)
