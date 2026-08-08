"""Transport-neutral dispatch for Resource Library mutations."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_json_body import parse_json_body
from portal_request_routes import PostRoute


MutationResult = tuple[bool, dict]


@dataclass(frozen=True)
class ResourceLibraryWriteCallbacks:
    remove: Callable[[str, str], MutationResult]
    set_tags: Callable[[str, object], MutationResult]
    rename: Callable[[str, str, str], MutationResult]
    set_favorite: Callable[[str, bool], MutationResult]


@dataclass(frozen=True)
class ResourceLibraryWriteResult:
    status: int
    payload: dict


def prepare_resource_library_write(
    route: PostRoute,
    raw: str,
    *,
    callbacks: ResourceLibraryWriteCallbacks,
) -> ResourceLibraryWriteResult | None:
    """Normalize and dispatch one explicitly classified Resource Library write."""
    if not route.resource_write:
        return None
    parsed = parse_json_body(raw, empty_object=True).value_or({})
    payload = parsed if isinstance(parsed, dict) else {}
    resource_id = str(payload.get("id", "")).strip()
    source = str(payload.get("source", "")).strip()
    if route.path == "/api/resource-library/remove":
        ok, response = callbacks.remove(resource_id, source)
    elif route.path == "/api/resource-library/tags":
        ok, response = callbacks.set_tags(resource_id, payload.get("tags", []))
    elif route.path == "/api/resource-library/rename":
        ok, response = callbacks.rename(
            resource_id, source, str(payload.get("new_name", "")).strip(),
        )
    else:
        ok, response = callbacks.set_favorite(
            resource_id, bool(payload.get("favorite")),
        )
    return ResourceLibraryWriteResult(200 if ok else 400, response)
