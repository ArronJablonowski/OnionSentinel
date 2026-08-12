"""Shared shape, identifier, and UTC-window normalization primitives."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvestigationQueryContractError(f"{label} must be an object")
    return value


def _require_exact_keys(
    value: dict[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        raise InvestigationQueryContractError(
            f"{label} is missing required fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise InvestigationQueryContractError(
            f"{label} contains unsupported fields: {', '.join(sorted(unknown))}"
        )


def _safe_id(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not SAFE_ID_RE.fullmatch(text):
        raise InvestigationQueryContractError(f"{label} is invalid")
    return text


def _parse_utc(value: object, label: str) -> dt.datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvestigationQueryContractError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise InvestigationQueryContractError(f"{label} must use UTC")
    return parsed.astimezone(dt.timezone.utc)


def _iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def _normalize_window(
    value: object,
    *,
    label: str,
    max_duration: dt.timedelta,
) -> tuple[dict[str, str], dt.datetime, dt.datetime]:
    window = _require_mapping(value, label)
    _require_exact_keys(
        window,
        allowed={"start", "end"},
        required={"start", "end"},
        label=label,
    )
    start = _parse_utc(window["start"], f"{label} start")
    end = _parse_utc(window["end"], f"{label} end")
    if end <= start or end - start > max_duration:
        raise InvestigationQueryContractError(
            f"{label} must be positive and no longer than {max_duration}"
        )
    return {"start": _iso_utc(start), "end": _iso_utc(end)}, start, end
