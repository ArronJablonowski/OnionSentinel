"""Dedicated-server composition for phased human-access admission."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from portal_human_session_runtime import (
    CSRF_HEADER_NAME,
    csrf_cookie_header,
    expired_csrf_cookie_header,
    load_human_session_runtime,
)
from portal_access_observer_runtime import load_access_observer_runtime
from portal_access_enforcement import MODE_RBAC_ENFORCE
from portal_access_policy import ROLE_ADMINISTRATOR, is_authorized
from portal_admin_session_store import (
    load_enforcement_admin_password_record,
    validate_admin_session_store,
    verify_admin_password,
)


@dataclass(frozen=True)
class AccessAdmission:
    allowed: bool
    status: int
    reason: str
    json_request: bool


def _admission_allowed(*, json_request: bool = False) -> AccessAdmission:
    return AccessAdmission(True, 0, "not_enforced", json_request)


def _admission_denied(
    reason: str,
    *,
    json_request: bool,
    unavailable: bool = False,
) -> AccessAdmission:
    if unavailable:
        status = 503
    elif reason == "unauthenticated":
        status = 401
    else:
        status = 403
    return AccessAdmission(False, status, reason, json_request)


def _record_boundary_failure(observer: Any, exc: Exception) -> None:
    try:
        observer.record_boundary_failure(type(exc).__name__)
    except Exception:
        pass


def build_access_observer(
    *,
    environ: Mapping[str, str],
    home: Path,
    application_logger: Any,
) -> Any:
    def failure_sink(error_type: str) -> None:
        application_logger.log(
            "error",
            "access.audit.append_failed",
            error_type=error_type,
        )

    return load_access_observer_runtime(
        environ=environ,
        home=home,
        failure_sink=failure_sink,
    )


def build_human_session_runtime(
    *,
    mode: str,
    home: Path,
    application_logger: Any,
) -> Any:
    def failure_sink(error_type: str) -> None:
        application_logger.log(
            "error",
            "access.session.observation_failed",
            error_type=error_type,
        )

    return load_human_session_runtime(
        mode=mode,
        home=home,
        failure_sink=failure_sink,
    )


def _record_session_failure(session_runtime: Any, exc: Exception) -> None:
    try:
        session_runtime.record_boundary_failure(type(exc).__name__)
    except Exception:
        pass


def create_human_session(
    handler: Any,
    session_id: str,
    *,
    runtime: Any,
    session_runtime: Any,
) -> str | None:
    try:
        return session_runtime.create_session(
            session_id,
            client_identity=handler.client_address[0],
            now_timestamp=int(runtime.time.time()),
            new_token=lambda: runtime.secrets.token_urlsafe(32),
        )
    except Exception as exc:
        _record_session_failure(session_runtime, exc)
        return None


def destroy_human_session(
    session_id: str,
    *,
    session_runtime: Any,
) -> bool:
    try:
        return bool(session_runtime.destroy_session(session_id))
    except Exception as exc:
        _record_session_failure(session_runtime, exc)
        return False


def admin_login_cookie_headers(
    session_id: str,
    csrf_token: str | None,
    *,
    runtime: Any,
    session_runtime: Any,
) -> str | list[str]:
    legacy_cookie = runtime.admin_session_cookie_header(session_id)
    if csrf_token is None:
        return legacy_cookie
    return [
        legacy_cookie,
        csrf_cookie_header(
            csrf_token,
            session_runtime.absolute_ttl_seconds,
        ),
    ]


def admin_logout_cookie_headers(
    *,
    runtime: Any,
    observe_enabled: bool,
) -> str | list[str]:
    legacy_cookie = runtime.expired_admin_session_cookie_header()
    if not observe_enabled:
        return legacy_cookie
    return [legacy_cookie, expired_csrf_cookie_header()]


def _resolve_human_session(
    handler: Any,
    *,
    runtime: Any,
    session_runtime: Any,
    activity_authorized: bool,
) -> Any:
    return session_runtime.resolve_session(
        handler._admin_session_id(),
        csrf_value=handler.headers.get(CSRF_HEADER_NAME),
        now_timestamp=int(runtime.time.time()),
        activity_authorized=activity_authorized,
    )


def _same_origin_authorized(handler: Any) -> bool:
    fetch_site = str(
        handler.headers.get("Sec-Fetch-Site") or ""
    ).strip().lower()
    return bool(
        fetch_site in {"", "same-origin"}
        and handler._soc_review_origin_authorized()
    )


def _decision_admission(
    observation: Any,
    *,
    observer: Any,
    route: Any,
    runtime: Any,
) -> AccessAdmission:
    decision = getattr(observation, "decision", None)
    if decision is None or not decision.enforced:
        return _admission_allowed(json_request=bool(route.json_request))
    if not decision.allowed:
        return _admission_denied(
            decision.reason,
            json_request=bool(route.json_request),
        )
    if observer.precommit(
        observation,
        occurred_at=runtime.now_iso_utc(),
    ):
        return _admission_allowed(json_request=bool(route.json_request))
    return _admission_denied(
        "audit_precommit_failed",
        json_request=bool(route.json_request),
        unavailable=True,
    )


def _session_failure_admission(session: Any, route: Any) -> AccessAdmission | None:
    reason = getattr(session, "reason", "")
    if reason not in {
        "session_observation_failed",
        "session_touch_conflict",
    }:
        return None
    return _admission_denied(
        str(reason),
        json_request=bool(getattr(route, "json_request", False)),
        unavailable=True,
    )


def _classified_route(runtime: Any, path: str) -> Any:
    return runtime.classify_post_route(
        path,
        cti_program_path=runtime.CTI_PROGRAM_API_PATH,
        prompt_paths=runtime.SOC_SETTINGS_PROMPT_API_PATHS,
    )


def _boundary_admission(
    observer: Any,
    enforcing: bool,
    route: Any,
    exc: Exception,
) -> AccessAdmission:
    _record_boundary_failure(observer, exc)
    return (
        _admission_denied(
            "access_boundary_failed",
            json_request=bool(getattr(route, "json_request", False)),
            unavailable=True,
        )
        if enforcing
        else _admission_allowed(
            json_request=bool(getattr(route, "json_request", False))
        )
    )


def begin_access_observation(
    handler: Any,
    path: str,
    *,
    runtime: Any,
    controlled_evaluation: bool,
    observer: Any,
    session_runtime: Any,
) -> AccessAdmission:
    """Attach one pre-body observe decision to a classified human write."""
    handler._access_observation = None
    if controlled_evaluation:
        return _admission_allowed()
    enforcing = bool(getattr(observer, "enforcing", False))
    route = None
    try:
        if not observer.enabled:
            return _admission_allowed()
        route = _classified_route(runtime, path)
        if not route.accepted:
            return _admission_allowed()
        same_origin = _same_origin_authorized(handler)
        session = _resolve_human_session(
            handler,
            runtime=runtime,
            session_runtime=session_runtime,
            activity_authorized=same_origin,
        )
        failure = _session_failure_admission(session, route)
        if enforcing and failure is not None:
            return failure
        handler._access_observation = observer.begin(
            route,
            principal=session.principal,
            same_origin_authorized=same_origin,
            csrf_authorized=session.csrf_authorized,
            request_id=str(
                getattr(handler, "application_request_id", "")
            ),
        )
        return _decision_admission(
            handler._access_observation,
            observer=observer,
            route=route,
            runtime=runtime,
        )
    except Exception as exc:
        return _boundary_admission(observer, enforcing, route, exc)


def finalize_access_observation(
    handler: Any,
    http_status: int,
    *,
    runtime: Any,
    observer: Any,
) -> None:
    observation = getattr(handler, "_access_observation", None)
    if observation is None:
        return
    handler._access_observation = None
    try:
        observer.finalize(
            observation,
            http_status=int(http_status),
            occurred_at=runtime.now_iso_utc(),
        )
    except Exception as exc:
        _record_boundary_failure(observer, exc)


class DedicatedAccessRuntime:
    """Own dedicated-server access composition outside the HTTP entrypoint."""

    def __init__(
        self,
        *,
        runtime: Any,
        observer: Any,
        sessions: Any,
        password_record: Mapping[str, object] | None = None,
    ) -> None:
        self.runtime = runtime
        self.observer = observer
        self.sessions = sessions
        self._password_record = (
            dict(password_record) if password_record is not None else None
        )

    def begin(
        self, handler: Any, path: str, *, controlled_evaluation: bool
    ) -> AccessAdmission:
        return begin_access_observation(
            handler,
            path,
            runtime=self.runtime,
            controlled_evaluation=controlled_evaluation,
            observer=self.observer,
            session_runtime=self.sessions,
        )

    def finalize(self, handler: Any, http_status: int) -> None:
        return finalize_access_observation(
            handler,
            http_status,
            runtime=self.runtime,
            observer=self.observer,
        )

    def create_session(self, handler: Any, session_id: str) -> str | None:
        return create_human_session(
            handler,
            session_id,
            runtime=self.runtime,
            session_runtime=self.sessions,
        )

    def destroy_session(self, session_id: str) -> bool:
        return destroy_human_session(
            session_id,
            session_runtime=self.sessions,
        )

    def login_cookie_headers(
        self, session_id: str, csrf_token: str | None
    ) -> str | list[str]:
        return admin_login_cookie_headers(
            session_id,
            csrf_token,
            runtime=self.runtime,
            session_runtime=self.sessions,
        )

    def logout_cookie_headers(self) -> str | list[str]:
        return admin_logout_cookie_headers(
            runtime=self.runtime,
            observe_enabled=self.sessions.enabled,
        )

    def password_configured(self) -> bool:
        if self.session_required:
            return self._password_record is not None
        return bool(self.runtime.admin_password_configured())

    def verify_password(self, password: str) -> bool:
        if self.session_required:
            return verify_admin_password(password, self._password_record)
        return bool(self.runtime.verify_admin_password(password))

    def admin_authenticated(self, handler: Any) -> bool:
        if not self.session_required:
            return bool(handler._admin_authenticated())
        principal = self._read_principal(handler)
        return bool(
            principal is not None
            and getattr(principal, "role", "") == ROLE_ADMINISTRATOR
        )

    def read_authenticated(self, handler: Any) -> bool:
        if not self.read_session_required:
            return True
        principal = self._read_principal(handler)
        return bool(
            principal is not None
            and is_authorized(
                principal_kind=getattr(principal, "principal_kind", ""),
                role=getattr(principal, "role", ""),
                permission="evidence.view",
            )
        )

    def _read_principal(self, handler: Any) -> Any:
        try:
            observation = self.sessions.resolve_read_session(
                handler._admin_session_id(),
                now_timestamp=int(self.runtime.time.time()),
            )
        except Exception as exc:
            _record_session_failure(self.sessions, exc)
            return None
        return getattr(observation, "principal", None)

    @property
    def session_required(self) -> bool:
        return bool(getattr(self.sessions, "enforcing", False))

    @property
    def read_session_required(self) -> bool:
        return getattr(self.sessions, "mode", "") == MODE_RBAC_ENFORCE


def build_access_runtime(
    *,
    environ: Mapping[str, str],
    home: Path,
    application_logger: Any,
    runtime: Any,
) -> DedicatedAccessRuntime:
    observer = build_access_observer(
        environ=environ,
        home=home,
        application_logger=application_logger,
    )
    password_record = None
    if bool(getattr(observer, "enforcing", False)):
        stack_dir = Path(home) / "n8n-local"
        password_record = load_enforcement_admin_password_record(
            stack_dir / "config/onion-sentinel-admin-password.json"
        )
        validate_admin_session_store(
            stack_dir / "admin-state",
            stack_dir / "admin-state/.admin_sessions.json",
        )
    sessions = build_human_session_runtime(
        mode=observer.mode,
        home=home,
        application_logger=application_logger,
    )
    return DedicatedAccessRuntime(
        runtime=runtime,
        observer=observer,
        sessions=sessions,
        password_record=password_record,
    )


__all__ = (
    "DedicatedAccessRuntime",
    "AccessAdmission",
    "begin_access_observation",
    "admin_login_cookie_headers",
    "admin_logout_cookie_headers",
    "build_access_observer",
    "build_access_runtime",
    "build_human_session_runtime",
    "create_human_session",
    "destroy_human_session",
    "finalize_access_observation",
)
