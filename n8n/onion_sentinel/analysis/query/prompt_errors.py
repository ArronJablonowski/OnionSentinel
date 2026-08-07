"""Secret-safe model-visible investigation query error policy."""

from __future__ import annotations

from typing import Any, Callable

from . import primitives


def category(reason: Any) -> str:
    """Classify a raw broker/validator error without exposing its content."""
    message = primitives.text(reason, 1000).lower()
    markers = (
        (
            "authorization_denied",
            ("unauthorized", "forbidden", "denied", "approval", "not permitted"),
        ),
        ("execution_timeout", ("timeout", "timed out")),
        (
            "backend_unavailable",
            ("disabled", "unavailable", "unadvertised", "connection refused"),
        ),
        ("duplicate_request", ("already executed", "duplicate")),
        (
            "invalid_broker_response",
            ("invalid response", "invalid result", "invalid envelope", "malformed response"),
        ),
        (
            "request_contract_rejection",
            (
                "contract", "required", "unsupported", "event tuple", "widen",
                "scope", "query_dsl",
            ),
        ),
    )
    for label, candidates in markers:
        if any(marker in message for marker in candidates):
            return label
    return "query_execution_failure"


def digest(reason: Any, canonical_digest: Callable[[Any], str]) -> str:
    """Bind omitted raw error text with the caller's canonical digest."""
    return canonical_digest(primitives.text(reason, 1000))
