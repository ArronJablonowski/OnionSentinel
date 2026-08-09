#!/usr/bin/env python3
"""Bounded file, JSON, and output-name helpers for prompt construction."""
from __future__ import annotations

import json
from pathlib import Path
import re


OUTPUT_TIMESTAMP_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$"
)


def safe_output_filename(value: object) -> str:
    """Return the legacy bounded filename projection for a runtime value."""
    return (
        str(value or "alert")
        .replace(":", "")
        .replace("/", "-")
        .replace("\\", "-")
        .replace("|", "-")
        .replace(" ", "-")
    )[:180]


def output_filename_timestamp(value: str) -> str:
    """Compact a projected local timestamp without losing its zone offset."""
    match = OUTPUT_TIMESTAMP_RE.match(value)
    if not match:
        return safe_output_filename(value)
    year, month, day, hour, minute, second, zone = match.groups()
    return f"{year}{month}{day}-{hour}{minute}{second}{zone.replace(':', '')}"


def parse_json_mapping(value: str | None) -> dict:
    """Parse a JSON object and fail soft for malformed or non-object input."""
    try:
        parsed = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def normalized_int(value: object, default: int = 0) -> int:
    """Convert a scalar to an integer while preserving the caller's fallback."""
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def read_bounded_bytes(path: Path, maximum_bytes: int) -> bytes:
    """Read a trusted runtime artifact only when it satisfies its size limit."""
    size = path.stat().st_size
    if size > maximum_bytes:
        raise ValueError(
            f"artifact exceeds {maximum_bytes} byte limit: {path.name}"
        )
    with path.open("rb") as handle:
        data = handle.read(maximum_bytes + 1)
    if len(data) > maximum_bytes:
        raise ValueError(
            f"artifact grew beyond {maximum_bytes} byte limit: {path.name}"
        )
    return data


def load_bounded_json_mapping(path: Path, maximum_bytes: int) -> dict:
    """Load a size-bounded UTF-8 JSON artifact whose root must be an object."""
    parsed = json.loads(
        read_bounded_bytes(path, maximum_bytes).decode(
            "utf-8",
            errors="strict",
        )
    )
    if not isinstance(parsed, dict):
        raise ValueError(f"JSON artifact root must be an object: {path.name}")
    return parsed


def load_prompt_text(path: Path, maximum_bytes: int, fallback: str) -> str:
    """Load an analyst-editable prompt, returning the fallback on any failure."""
    try:
        prompt = read_bounded_bytes(path, maximum_bytes).decode(
            "utf-8",
            errors="replace",
        ).strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return fallback
