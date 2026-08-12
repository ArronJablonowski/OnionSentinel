"""Bounded diagnostics for dashboard subprocess readiness failures."""

from __future__ import annotations

from typing import Any, TextIO


MAX_PROBE_CHARS = 512
MAX_OUTPUT_CHARS = 8_192
TRUNCATION_MARKER = "<truncated>"


def _bounded_tail(value: str, *, limit: int, empty: str) -> str:
    if not value:
        return empty
    if len(value) <= limit:
        return value
    return TRUNCATION_MARKER + value[-limit:]


def _terminal_output(log_file: TextIO) -> str:
    try:
        log_file.flush()
        log_file.seek(0, 2)
        end = log_file.tell()
        start = max(0, end - MAX_OUTPUT_CHARS)
        log_file.seek(start)
        output = log_file.read(MAX_OUTPUT_CHARS)
    except (OSError, ValueError) as exc:
        return f"<unavailable:{type(exc).__name__}>"
    if start:
        output = TRUNCATION_MARKER + output
    return output or "<empty>"


def startup_failure_diagnostic(
    process: Any,
    log_file: TextIO,
    *,
    last_probe: str,
) -> str:
    """Describe child state, the last probe, and bounded terminal output."""
    returncode = process.poll()
    process_state = "running" if returncode is None else "exited"
    return (
        f"process_state={process_state}; "
        f"returncode={'none' if returncode is None else returncode}; "
        "last_probe="
        + _bounded_tail(
            str(last_probe),
            limit=MAX_PROBE_CHARS,
            empty="<none>",
        )
        + "; output="
        + _terminal_output(log_file)
    )
