"""Bounded diagnostic projection for incident-evidence transport failures."""

from __future__ import annotations

import json


MAX_ERROR_FIELD_BYTES = 500


def _bounded_diagnostic_text(value: object, maximum_bytes: int) -> str:
    """Return one printable line from an untrusted diagnostic value."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", "replace")
    elif isinstance(value, str):
        text = value
    else:
        return ""
    printable = "".join(
        character if character.isprintable() else " "
        for character in text
    )
    compact = " ".join(printable.split())
    encoded = compact.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return compact
    suffix = b"...[truncated]"
    prefix = encoded[: max(0, maximum_bytes - len(suffix))].decode(
        "utf-8",
        "ignore",
    )
    return prefix + suffix.decode("ascii")


def _json_error_fields(raw: object) -> dict[str, str]:
    """Extract only bounded fields from the inner JSON error envelope."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {}
    elif isinstance(raw, str):
        text = raw
    else:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(value, dict):
        return {}
    fields = {}
    for key in ("error", "detail"):
        diagnostic = _bounded_diagnostic_text(
            value.get(key),
            MAX_ERROR_FIELD_BYTES,
        )
        if diagnostic:
            fields[key] = diagnostic
    return fields


def _failed_command_payload(
    proc: object,
) -> dict[str, object]:
    """Build a bounded two-hop failure without reflecting arbitrary output."""
    payload: dict[str, object] = {
        "ok": False,
        "error": "restricted Security Onion evidence command failed",
    }
    upstream = _json_error_fields(getattr(proc, "stdout", b""))
    if upstream.get("error"):
        payload["upstream_error"] = upstream["error"]
    if upstream.get("detail"):
        payload["upstream_detail"] = upstream["detail"]
    stderr = _bounded_diagnostic_text(
        getattr(proc, "stderr", b""),
        MAX_ERROR_FIELD_BYTES,
    )
    if stderr:
        payload["detail"] = stderr
    return payload
