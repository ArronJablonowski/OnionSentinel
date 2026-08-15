"""Dedicated-server composition for compatibility access observation."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from portal_access_observer_runtime import load_access_observer_runtime


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


def begin_access_observation(
    handler: Any,
    path: str,
    *,
    runtime: Any,
    controlled_evaluation: bool,
    observer: Any,
) -> None:
    """Attach one pre-body observe decision to a classified human write."""
    handler._access_observation = None
    if controlled_evaluation or not observer.enabled:
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
    try:
        handler._access_observation = observer.begin(
            route,
            principal=None,
            same_origin_authorized=same_origin,
            csrf_authorized=False,
            request_id=str(
                getattr(handler, "application_request_id", "")
            ),
        )
    except Exception as exc:
        observer.record_boundary_failure(type(exc).__name__)


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
        observer.record_boundary_failure(type(exc).__name__)


__all__ = (
    "begin_access_observation",
    "build_access_observer",
    "finalize_access_observation",
)
