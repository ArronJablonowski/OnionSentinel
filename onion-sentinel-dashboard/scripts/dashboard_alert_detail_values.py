"""Pure value-access and Markdown-table primitives for alert details."""
from __future__ import annotations

import json
import re


def json_object(value: object) -> dict:
    """Return a JSON object from a dictionary or encoded string."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def row_value(row: object, key: str, default: object = None) -> object:
    """Read a value from a dictionary or SQLite-compatible mapping row."""
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]  # type: ignore[index]
    except (IndexError, KeyError):
        return default


def nested_value(obj: dict, *keys: str) -> str | None:
    """Return a nested value as text when the entire path exists."""
    current = obj
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    if current is None:
        return None
    return str(current)


def nested_object(obj: dict, *keys: str) -> object | None:
    """Return a nested value without changing its type."""
    current: object = obj
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def markdown_cell(value: object, max_len: int = 420) -> str:
    """Normalize one value so it cannot corrupt a Markdown table."""
    if value is None or value == "" or value == [] or value == {}:
        return ""
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, sort_keys=True)
    else:
        rendered = str(value)
    rendered = re.sub(r"\s+", " ", rendered).strip()
    rendered = rendered.replace("|", "\\|")
    return (rendered[: max_len - 1] + "…") if len(rendered) > max_len else rendered


def detail_table(
    title: str,
    rows: list[tuple[str, object]],
    max_len: int = 420,
) -> list[str]:
    """Render non-empty field/value pairs as one Markdown section table."""
    visible_rows = [(label, markdown_cell(value, max_len)) for label, value in rows]
    visible_rows = [(label, value) for label, value in visible_rows if value]
    if not visible_rows:
        return []
    lines = [
        f"## {title}",
        "",
        "| Field | Value |",
        "| --- | --- |",
    ]
    lines.extend(f"| {label} | {value} |" for label, value in visible_rows)
    lines.append("")
    return lines


def raw_event_for_details(raw: dict) -> dict:
    """Prefer preserved Security Onion event fields over normalized fallback."""
    raw_event = nested_object(raw, "security_onion", "raw_event")
    return raw_event if isinstance(raw_event, dict) else raw


def present_values(*values: object) -> list[object]:
    """Keep compound detail cells empty unless at least one value exists."""
    return [value for value in values if value not in (None, "", [], {})]
