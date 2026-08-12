"""Shared fail-closed primitives for incident-evidence validation."""

from __future__ import annotations

from typing import Any


class IncidentEvidenceContractError(ValueError):
    """The restricted incident-evidence chain could not be authenticated."""


def require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IncidentEvidenceContractError(f"{label} must be an object")
    return value


def require_nonempty_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise IncidentEvidenceContractError(f"{label} must be non-empty")
    return text


def require_nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IncidentEvidenceContractError(
            f"{label} must be a non-negative integer"
        )
    return value
