"""Transport-neutral read/write orchestration for the CTI workspace."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_json_body import parse_json_body
from portal_request_routes import PostRoute


@dataclass(frozen=True)
class CtiProgramCallbacks:
    load: Callable[[], dict]
    save: Callable[[object], dict]
    public_response: Callable[[dict], dict]
    audit: Callable[[dict], None]
    conflict_error: type[Exception]
    program_error: type[Exception]


@dataclass(frozen=True)
class CtiProgramResult:
    status: int
    payload: dict


def _error(
    status: int,
    message: str,
    *,
    authentication: bool = False,
) -> CtiProgramResult:
    payload = {"ok": False, "error": message}
    if authentication:
        payload["authentication_required"] = True
    return CtiProgramResult(status, payload)


def prepare_cti_program_write(
    route: PostRoute,
    raw: str,
    *,
    same_origin_authorized: bool,
    admin_authenticated: Callable[[], bool],
    callbacks: CtiProgramCallbacks,
) -> CtiProgramResult | None:
    """Authorize and apply one revisioned CTI workspace mutation."""
    if not route.cti_program_write:
        return None
    if not same_origin_authorized:
        return _error(
            403,
            "CTI workspace changes must come from the same-origin Onion Sentinel dashboard.",
        )
    if not admin_authenticated():
        return _error(
            403,
            "Sign in to Onion Sentinel Administration before editing the CTI workspace.",
            authentication=True,
        )
    payload = parse_json_body(raw).value_or(None)
    try:
        program = callbacks.save(payload)
    except callbacks.conflict_error as exc:
        return _error(409, str(exc))
    except callbacks.program_error as exc:
        return _error(400, str(exc))
    except OSError:
        return _error(500, "Could not persist the CTI workspace.")
    callbacks.audit(program)
    return CtiProgramResult(200, callbacks.public_response(program))


def read_cti_program(callbacks: CtiProgramCallbacks) -> CtiProgramResult:
    """Read and project the public CTI workspace without leaking raw errors."""
    try:
        payload = callbacks.public_response(callbacks.load())
    except callbacks.program_error as exc:
        return _error(500, str(exc))
    except OSError:
        return _error(500, "Could not read the CTI workspace.")
    return CtiProgramResult(200, payload)
