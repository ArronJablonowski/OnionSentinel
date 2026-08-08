"""Pure request acceptance and size policy for portal POST requests."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Callable

from portal_request_routes import PostRoute


@dataclass(frozen=True)
class PostIntakeResult:
    length: int = 0
    status: int | None = None
    body: bytes = b""
    content_type: str = "text/plain; charset=utf-8"
    view: str = ""
    message: str = ""

    @property
    def ready(self) -> bool:
        return self.status is None


def _content_length(raw_value: str | None) -> int:
    try:
        return int(raw_value or "0")
    except ValueError:
        return 0


def _invalid_size_result(
    route: PostRoute,
    admin_authenticated: Callable[[], bool],
) -> PostIntakeResult:
    if route.json_request:
        body = json.dumps({"ok": False, "error": "Invalid request size"}).encode()
        return PostIntakeResult(
            status=400, body=body,
            content_type="application/json; charset=utf-8",
        )
    if route.path == "/admin/action" and admin_authenticated():
        return PostIntakeResult(
            status=400, view="dashboard",
            message="Invalid admin action request size.",
        )
    return PostIntakeResult(
        status=400, view="login", message="Invalid request size.",
    )


def prepare_post_intake(
    route: PostRoute,
    content_length: str | None,
    *,
    cti_file_bytes: int,
    admin_authenticated: Callable[[], bool],
) -> PostIntakeResult:
    """Validate route and request size before the HTTP handler reads a body."""
    if not route.accepted:
        return PostIntakeResult(status=404, body=b"Not found")
    length = _content_length(content_length)
    if length <= 0 or length > route.request_limit(cti_file_bytes):
        return _invalid_size_result(route, admin_authenticated)
    return PostIntakeResult(length=length)
