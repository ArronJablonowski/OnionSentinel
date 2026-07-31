#!/usr/bin/env python3
"""Shared contract for the restricted AC Hunter relay transport.

The Mac submits a named operation and typed values.  Only the Relay compiles
those values into an upstream HTTPS request; callers never control a URL,
origin, HTTP method, redirect policy, proxy, or TLS setting.
"""
from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlencode


CONTRACT = "onion-sentinel-ac-hunter-relay-v1"
DATASET = "security-onion-rolling"
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_LOGIN_FIELD_BYTES = 1024
REQUEST_ID_RE = re.compile(r"^[a-f0-9]{32}$")
JWT_RE = re.compile(r"^Bearer [A-Za-z0-9._~-]{16,16384}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,190}$")


class AcHunterContractError(ValueError):
    """A relay request or response violated the fixed AC Hunter contract."""


@dataclass(frozen=True)
class UpstreamRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    response_kind: str = "json"
    allowed_statuses: tuple[int, ...] = (200,)


def new_request_id() -> str:
    return uuid.uuid4().hex


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcHunterContractError(f"{label} must be an object")
    return value


def _exact_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    extra = set(value) - allowed
    if extra:
        raise AcHunterContractError(
            f"{label} contains unsupported fields: {', '.join(sorted(extra))}"
        )


def _integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AcHunterContractError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise AcHunterContractError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return value


def _number(
    value: object,
    label: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AcHunterContractError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum or result > maximum:
        raise AcHunterContractError(
            f"{label} must be between {minimum:g} and {maximum:g}"
        )
    return result


def _enum(value: object, label: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise AcHunterContractError(
            f"{label} must be one of: {', '.join(sorted(allowed))}"
        )
    return value


def _bounded_text(
    value: object,
    label: str,
    *,
    maximum_bytes: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise AcHunterContractError(f"{label} must be text")
    if any(character in value for character in ("\r", "\n", "\x00")):
        raise AcHunterContractError(f"{label} contains a forbidden control character")
    encoded = value.encode("utf-8")
    if (not allow_empty and not value) or len(encoded) > maximum_bytes:
        raise AcHunterContractError(f"{label} is empty or exceeds its byte limit")
    return value


def _query_path(path: str, pairs: list[tuple[str, object]]) -> str:
    query = urlencode([(key, str(value)) for key, value in pairs])
    return f"{path}?{query}" if query else path


def _auth_headers(value: object) -> dict[str, str]:
    source = _mapping(value, "headers")
    _exact_keys(source, {"authorization", "cookie"}, "headers")
    result: dict[str, str] = {}
    authorization = source.get("authorization")
    if authorization is not None:
        authorization = _bounded_text(
            authorization,
            "authorization header",
            maximum_bytes=MAX_HEADER_BYTES,
        )
        if not JWT_RE.fullmatch(authorization):
            raise AcHunterContractError("authorization header is not a bounded Bearer token")
        result["Authorization"] = authorization
    cookie = source.get("cookie")
    if cookie is not None:
        cookie = _bounded_text(
            cookie,
            "cookie header",
            maximum_bytes=MAX_HEADER_BYTES,
        )
        result["Cookie"] = cookie
    return result


def _empty_params(value: object) -> None:
    source = _mapping(value, "params")
    _exact_keys(source, set(), "params")


def _list_params(
    value: object,
    *,
    threshold_name: str = "thresh",
    threshold_default: float = 0.5,
    sort_allowed: set[str],
) -> tuple[int, int, float, str]:
    source = _mapping(value, "params")
    _exact_keys(source, {"page", "size", threshold_name, "sort"}, "params")
    # AC Hunter 6.3.1 treats page=0 as an unpaged export for several
    # modules and ignores the requested size. Require one-based pagination so
    # the hard row cap is actually honored.
    page = _integer(source.get("page", 1), "page", minimum=1, maximum=10000)
    size = _integer(source.get("size", 100), "size", minimum=1, maximum=100)
    threshold = _number(
        source.get(threshold_name, threshold_default),
        threshold_name,
        minimum=0,
        maximum=10_000_000,
    )
    sort = _enum(source.get("sort"), "sort", sort_allowed)
    return page, size, threshold, sort


def _no_body(value: object) -> None:
    source = _mapping(value, "body")
    _exact_keys(source, set(), "body")


def _base_headers(
    headers: dict[str, str],
    *,
    form: bool = False,
    accept: str = "application/json, text/plain;q=0.5",
) -> dict[str, str]:
    result = {
        "Accept": accept,
        "User-Agent": "Onion-Sentinel-AC-Hunter/1.0",
        **headers,
    }
    if form:
        result["Content-Type"] = "application/x-www-form-urlencoded"
    return result


def _login_form(params: object, body: object, headers: object) -> UpstreamRequest:
    _empty_params(params)
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path="/auth/login",
        headers=_base_headers(
            _auth_headers(headers),
            accept="text/html, application/xhtml+xml;q=0.9",
        ),
        body=b"",
        response_kind="html",
    )


def _login(params: object, body: object, headers: object) -> UpstreamRequest:
    _empty_params(params)
    source = _mapping(body, "body")
    _exact_keys(
        source,
        {"email", "password", "csrf_token", "next", "remember"},
        "body",
    )
    email = _bounded_text(
        source.get("email"),
        "email",
        maximum_bytes=MAX_LOGIN_FIELD_BYTES,
    )
    if not EMAIL_RE.fullmatch(email):
        raise AcHunterContractError("email is invalid")
    password = _bounded_text(
        source.get("password"),
        "password",
        maximum_bytes=MAX_LOGIN_FIELD_BYTES,
    )
    csrf_token = _bounded_text(
        source.get("csrf_token", ""),
        "csrf token",
        maximum_bytes=MAX_LOGIN_FIELD_BYTES,
        allow_empty=True,
    )
    next_value = _bounded_text(
        source.get("next", ""),
        "next",
        maximum_bytes=256,
        allow_empty=True,
    )
    if next_value not in {"", "/jwt/json"}:
        raise AcHunterContractError("next is outside the AC Hunter auth flow")
    remember = source.get("remember", False)
    if not isinstance(remember, bool):
        raise AcHunterContractError("remember must be boolean")
    fields: list[tuple[str, str]] = [
        ("email", email),
        ("password", password),
        ("next", next_value),
        ("submit", "Login"),
    ]
    if csrf_token:
        fields.append(("csrf_token", csrf_token))
    if remember:
        fields.append(("remember", "y"))
    encoded = urlencode(fields).encode("utf-8")
    return UpstreamRequest(
        method="POST",
        path="/auth/login",
        headers=_base_headers(
            _auth_headers(headers),
            form=True,
            accept="text/html, application/xhtml+xml;q=0.9",
        ),
        body=encoded,
        response_kind="none",
        allowed_statuses=(302, 303),
    )


def _simple_get(
    path: str,
    params: object,
    body: object,
    headers: object,
) -> UpstreamRequest:
    _empty_params(params)
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=path,
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


def _beacons_count(params: object, body: object, headers: object) -> UpstreamRequest:
    source = _mapping(params, "params")
    _exact_keys(source, {"thresh"}, "params")
    threshold = _number(
        source.get("thresh", 0.5),
        "thresh",
        minimum=0,
        maximum=1,
    )
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=_query_path(
            f"/api/v0/{DATASET}/beacons/count",
            [("thresh", f"{threshold:g}")],
        ),
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


def _beacon_list(
    suffix: str,
    params: object,
    body: object,
    headers: object,
) -> UpstreamRequest:
    page, size, threshold, sort = _list_params(
        params,
        sort_allowed={"score"},
    )
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=_query_path(
            f"/api/v0/{DATASET}/{suffix}",
            [
                ("page", page),
                ("size", size),
                ("thresh", f"{threshold:g}"),
                ("sort", sort),
            ],
        ),
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


def _long_connections(
    params: object,
    body: object,
    headers: object,
) -> UpstreamRequest:
    page, size, minimum_length, sort = _list_params(
        params,
        threshold_name="min_length",
        threshold_default=18_000,
        sort_allowed={"duration"},
    )
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=_query_path(
            f"/api/v0/{DATASET}/longconns",
            [
                ("page", page),
                ("size", size),
                ("min-length", f"{minimum_length:g}"),
                ("sort", sort),
            ],
        ),
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


def _dns(params: object, body: object, headers: object) -> UpstreamRequest:
    source = _mapping(params, "params")
    _exact_keys(source, {"page", "size", "threshold"}, "params")
    page = _integer(source.get("page", 1), "page", minimum=1, maximum=10000)
    size = _integer(source.get("size", 100), "size", minimum=1, maximum=100)
    threshold = _number(
        source.get("threshold", 100),
        "threshold",
        minimum=0,
        maximum=10_000_000,
    )
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=_query_path(
            f"/api/v0/{DATASET}/dns",
            [
                ("page", page),
                ("size", size),
                ("threshold", f"{threshold:g}"),
            ],
        ),
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


def _strobe(params: object, body: object, headers: object) -> UpstreamRequest:
    source = _mapping(params, "params")
    _exact_keys(source, {"page", "size", "sort"}, "params")
    page = _integer(source.get("page", 1), "page", minimum=1, maximum=10000)
    size = _integer(source.get("size", 100), "size", minimum=1, maximum=100)
    sort = _enum(
        source.get("sort"),
        "sort",
        {"connection_count"},
    )
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=_query_path(
            f"/api/v0/{DATASET}/strobe",
            [("page", page), ("size", size), ("sort", sort)],
        ),
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


def _blacklist(params: object, body: object, headers: object) -> UpstreamRequest:
    source = _mapping(params, "params")
    _exact_keys(source, {"page", "size"}, "params")
    page = _integer(source.get("page", 1), "page", minimum=1, maximum=10000)
    size = _integer(source.get("size", 100), "size", minimum=1, maximum=100)
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=_query_path(
            f"/api/v0/{DATASET}/blacklist/ip",
            [("page", page), ("size", size)],
        ),
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


def _useragent_count(
    params: object,
    body: object,
    headers: object,
) -> UpstreamRequest:
    source = _mapping(params, "params")
    _exact_keys(source, {"ja3flag"}, "params")
    flag = source.get("ja3flag", False)
    if not isinstance(flag, bool):
        raise AcHunterContractError("ja3flag must be boolean")
    _no_body(body)
    return UpstreamRequest(
        method="GET",
        path=f"/api/v0/{DATASET}/useragent/count/{str(flag).lower()}",
        headers=_base_headers(_auth_headers(headers)),
        body=b"",
        allowed_statuses=(200, 302),
    )


OperationBuilder = Callable[[object, object, object], UpstreamRequest]

OPERATIONS: dict[str, OperationBuilder] = {
    "login_form": _login_form,
    "login": _login,
    "jwt": lambda p, b, h: _simple_get("/jwt/json", p, b, h),
    "database": lambda p, b, h: _simple_get("/api/v0/database", p, b, h),
    "dashboard": lambda p, b, h: _simple_get(
        f"/api/v0/{DATASET}/dashboard", p, b, h
    ),
    "dashboard_count": lambda p, b, h: _simple_get(
        f"/api/v0/{DATASET}/dashboard/count", p, b, h
    ),
    "dashboard_c2flag": lambda p, b, h: _simple_get(
        f"/api/v0/{DATASET}/dashboard/c2flag", p, b, h
    ),
    "beacons_count": _beacons_count,
    "beacons": lambda p, b, h: _beacon_list("beacons", p, b, h),
    "beacons_sni": lambda p, b, h: _beacon_list("beaconssni", p, b, h),
    "beacons_proxy": lambda p, b, h: _beacon_list("beaconsproxy", p, b, h),
    "long_connections": _long_connections,
    "dns": _dns,
    "strobe": _strobe,
    "blacklist_ip": _blacklist,
    "certificate_count": lambda p, b, h: _simple_get(
        f"/api/v0/{DATASET}/certificate/count", p, b, h
    ),
    "useragent_count": _useragent_count,
    "unexpected_ports": lambda p, b, h: _simple_get(
        "/custom/unexpectedports.json", p, b, h
    ),
}


def compile_request(payload: object) -> tuple[str, UpstreamRequest]:
    source = _mapping(payload, "request")
    _exact_keys(
        source,
        {"contract", "request_id", "operation", "params", "headers", "body"},
        "request",
    )
    if source.get("contract") != CONTRACT:
        raise AcHunterContractError("unsupported AC Hunter relay contract")
    request_id = source.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise AcHunterContractError("request_id must be 32 lowercase hex characters")
    operation = source.get("operation")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise AcHunterContractError("operation is not allowlisted")
    request = OPERATIONS[operation](
        source.get("params", {}),
        source.get("body", {}),
        source.get("headers", {}),
    )
    if not request.path.startswith("/") or any(
        marker in request.path.lower()
        for marker in ("..", "\\", "%2f", "%5c", "://", "#")
    ):
        raise AcHunterContractError("compiled AC Hunter path is invalid")
    return request_id, request


def validate_relay_response(payload: object, request_id: str) -> dict[str, Any]:
    source = _mapping(payload, "relay response")
    _exact_keys(
        source,
        {
            "contract",
            "request_id",
            "ok",
            "status",
            "content_type",
            "headers",
            "body",
            "duration_ms",
            "error",
        },
        "relay response",
    )
    if source.get("contract") != CONTRACT or source.get("request_id") != request_id:
        raise AcHunterContractError("relay response binding is invalid")
    if not isinstance(source.get("ok"), bool):
        raise AcHunterContractError("relay response ok must be boolean")
    status = source.get("status")
    if isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 599:
        raise AcHunterContractError("relay response status is invalid")
    duration = source.get("duration_ms")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 0 <= duration <= 300_000
    ):
        raise AcHunterContractError("relay response duration is invalid")
    headers = _mapping(source.get("headers"), "relay response headers")
    _exact_keys(headers, {"location", "set_cookie"}, "relay response headers")
    location = headers.get("location", "")
    _bounded_text(
        location,
        "relay response location",
        maximum_bytes=2048,
        allow_empty=True,
    )
    cookies = headers.get("set_cookie", [])
    if not isinstance(cookies, list) or len(cookies) > 8:
        raise AcHunterContractError("relay response cookie list is invalid")
    for cookie in cookies:
        _bounded_text(
            cookie,
            "relay response cookie",
            maximum_bytes=MAX_HEADER_BYTES,
        )
    error = source.get("error", "")
    _bounded_text(
        error,
        "relay response error",
        maximum_bytes=512,
        allow_empty=True,
    )
    content_type = source.get("content_type", "")
    _bounded_text(
        content_type,
        "relay response content type",
        maximum_bytes=256,
        allow_empty=True,
    )
    return source
