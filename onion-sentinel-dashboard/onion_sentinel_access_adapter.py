"""Dedicated-server composition for compatibility access observation."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from portal_human_session_runtime import (
    CSRF_HEADER_NAME,
    csrf_cookie_header,
    expired_csrf_cookie_header,
    load_human_session_runtime,
)
from portal_access_observer_runtime import load_access_observer_runtime


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
) -> Any:
    return session_runtime.resolve_session(
        handler._admin_session_id(),
        csrf_value=handler.headers.get(CSRF_HEADER_NAME),
        now_timestamp=int(runtime.time.time()),
    )


def begin_access_observation(
    handler: Any,
    path: str,
    *,
    runtime: Any,
    controlled_evaluation: bool,
    observer: Any,
    session_runtime: Any,
) -> None:
    """Attach one pre-body observe decision to a classified human write."""
    handler._access_observation = None
    if controlled_evaluation:
        return
    try:
        if not observer.enabled:
            return
        route = runtime.classify_post_route(
            path,
            cti_program_path=runtime.CTI_PROGRAM_API_PATH,
            prompt_paths=runtime.SOC_SETTINGS_PROMPT_API_PATHS,
        )
        if not route.accepted:
            return
        fetch_site = str(
            handler.headers.get("Sec-Fetch-Site") or ""
        ).strip().lower()
        same_origin = bool(
            fetch_site in {"", "same-origin"}
            and handler._soc_review_origin_authorized()
        )
        session = _resolve_human_session(
            handler,
            runtime=runtime,
            session_runtime=session_runtime,
        )
        handler._access_observation = observer.begin(
            route,
            principal=session.principal,
            same_origin_authorized=same_origin,
            csrf_authorized=session.csrf_authorized,
            request_id=str(
                getattr(handler, "application_request_id", "")
            ),
        )
    except Exception as exc:
        _record_boundary_failure(observer, exc)


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
    """Own dedicated-server observe composition outside the HTTP entrypoint."""

    def __init__(self, *, runtime: Any, observer: Any, sessions: Any) -> None:
        self.runtime = runtime
        self.observer = observer
        self.sessions = sessions

    def begin(
        self, handler: Any, path: str, *, controlled_evaluation: bool
    ) -> None:
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
    sessions = build_human_session_runtime(
        mode=observer.mode,
        home=home,
        application_logger=application_logger,
    )
    return DedicatedAccessRuntime(
        runtime=runtime,
        observer=observer,
        sessions=sessions,
    )


__all__ = (
    "DedicatedAccessRuntime",
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
