#!/usr/bin/env python3
"""Bounded JSON response handling for local Onion Sentinel HTTP clients.

Network timeouts only bound elapsed time; they do not bound memory.  These
helpers enforce a byte ceiling before JSON decoding so a malfunctioning local
service cannot make an AI worker or queue reconciler buffer an unlimited body.
"""
from __future__ import annotations

import json
from typing import Any, BinaryIO


DEFAULT_CHUNK_BYTES = 64 * 1024


class BoundedHttpError(RuntimeError):
    """Raised when an HTTP response violates the local client contract."""


def _content_length(response: object) -> int | None:
    headers = getattr(response, "headers", None)
    raw = headers.get("Content-Length") if headers is not None else None
    if raw in (None, ""):
        return None
    try:
        value = int(str(raw))
    except (TypeError, ValueError) as exc:
        raise BoundedHttpError("response contained an invalid Content-Length") from exc
    if value < 0:
        raise BoundedHttpError("response contained a negative Content-Length")
    return value


def read_bounded_body(
    response: BinaryIO,
    *,
    max_bytes: int,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> bytes:
    """Read at most ``max_bytes`` and reject declared or observed overflow."""
    limit = int(max_bytes)
    if limit <= 0:
        raise ValueError("max_bytes must be positive")
    chunk_size = max(1, min(int(chunk_bytes), limit + 1))
    declared = _content_length(response)
    if declared is not None and declared > limit:
        raise BoundedHttpError(f"response exceeded the {limit}-byte limit")

    body = bytearray()
    while len(body) <= limit:
        chunk = response.read(min(chunk_size, limit + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    if len(body) > limit:
        raise BoundedHttpError(f"response exceeded the {limit}-byte limit")
    if declared is not None and len(body) != declared:
        raise BoundedHttpError("response ended before its declared Content-Length")
    return bytes(body)


def read_bounded_json(
    response: BinaryIO,
    *,
    max_bytes: int,
    require_object: bool = True,
) -> Any:
    """Decode one bounded UTF-8 JSON response and optionally require an object."""
    body = read_bounded_body(response, max_bytes=max_bytes)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BoundedHttpError("response was not valid UTF-8 JSON") from exc
    if require_object and not isinstance(payload, dict):
        raise BoundedHttpError("response JSON must be an object")
    return payload
