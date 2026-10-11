"""Bounded evidence transport owner."""
from __future__ import annotations

import datetime as dt

import fnmatch



import json




import os

import re

import selectors

import signal

import subprocess

import syslog

import sys

import time

import uuid





def run_bounded_command(
    r,
    command: list[str],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> subprocess.CompletedProcess:
    """Drain a no-shell child incrementally and enforce hard byte ceilings."""
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout: ("stdout", bytearray(), max_stdout_bytes),
        process.stderr: ("stderr", bytearray(), max_stderr_bytes),
    }
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise r.BoundedCommandError(
                    "timeout",
                    f"command timed out after {timeout_seconds:g} seconds",
                )
            events = selector.select(timeout=min(0.25, remaining))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in selector.get_map().values()
                ]
            for key, _mask in events:
                stream = key.fileobj
                label, target, limit = streams[stream]
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                if len(target) + len(chunk) > limit:
                    raise r.BoundedCommandError(
                        "output_limit",
                        f"command {label} exceeded its {limit}-byte limit",
                    )
                target.extend(chunk)
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        raise r.BoundedCommandError(
            "timeout",
            f"command timed out after {timeout_seconds:g} seconds",
        ) from exc
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        command,
        return_code,
        bytes(streams[process.stdout][1]),
        bytes(streams[process.stderr][1]),
    )


def audit_value(r, value: object) -> str:
    text = str(value if value is not None else "")[:160]
    return re.sub(r"[^A-Za-z0-9_.:@+-]", "_", text)


def audit_log(r, event: str, **fields: object) -> None:
    if not r.AUDIT_CONTEXT:
        return
    if "operation" in fields and fields["operation"] not in r.AUDIT_OPERATIONS:
        fields["operation"] = "unknown"
    allowed = {
        "event": event,
        "correlation_id": r.AUDIT_CONTEXT.get("correlation_id", ""),
        "request_digest": r.AUDIT_CONTEXT.get("request_digest", ""),
        **fields,
    }
    try:
        syslog.syslog(
            syslog.LOG_INFO,
            "onion-sentinel-evidence "
            + " ".join(
                f"{key}={r.audit_value(value)}"
                for key, value in allowed.items()
            ),
        )
    except OSError:
        pass


def fail(r, message: str, code: int = 2) -> None:
    r.audit_log(
        "security_onion_terminal",
        status="error",
        elastic_search_count=r.AUDIT_CONTEXT.get("elastic_search_count", 0),
        osquery_query_count=r.AUDIT_CONTEXT.get("osquery_query_count", 0),
        helper_invocation_count=r.AUDIT_CONTEXT.get("helper_invocation_count", 0),
    )
    print(json.dumps({"ok": False, "error": message}, separators=(",", ":")))
    raise SystemExit(code)


def parse_time(r, value: object) -> dt.datetime:
    text = str(value or "").strip().replace("  ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def iso_utc(r, value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def read_request(r) -> dict:
    raw = sys.stdin.buffer.read(r.MAX_TRANSPORT_REQUEST_BYTES + 1)
    if len(raw) > r.MAX_TRANSPORT_REQUEST_BYTES:
        r.fail("request exceeds the transport byte limit")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        r.fail(f"invalid JSON request: {exc}")
    if not isinstance(data, dict):
        r.fail("request root must be an object")
    if data.get("transport_contract") == r.TRANSPORT_AUDIT_CONTRACT:
        if set(data) != {
            "transport_contract", "correlation_id", "request_digest", "payload"
        }:
            r.fail("request transport envelope is invalid")
        payload = data.get("payload")
        correlation_id = data.get("correlation_id")
        request_digest = data.get("request_digest")
        if (
            not isinstance(payload, dict)
            or not isinstance(correlation_id, str)
            or not r.CORRELATION_ID.fullmatch(correlation_id)
            or not isinstance(request_digest, str)
            or not r.SHA256.fullmatch(request_digest)
            or request_digest != r.canonical_digest(payload)
        ):
            r.fail("request transport envelope failed validation")
    else:
        # Transitional compatibility lets the Security Onion wrapper be
        # deployed before the Relay without interrupting the forced lane.
        payload = data
        correlation_id = uuid.uuid4().hex
        request_digest = r.canonical_digest(payload)
    if (
        len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        > r.MAX_REQUEST_BYTES
    ):
        r.fail("request payload exceeds the 16384-byte limit")
    r.AUDIT_CONTEXT.update({
        "correlation_id": correlation_id,
        "request_digest": request_digest,
        "elastic_search_count": 0,
        "osquery_query_count": 0,
        "helper_invocation_count": 0,
    })
    r.audit_log(
        "security_onion_start",
        operation=payload.get("operation", "incident_evidence"),
    )
    return payload


def emit_response(
    r,
    response: dict,
    *,
    maximum_bytes: int = 8 * 1024 * 1024,
    output_error: str = "bounded evidence response exceeded the output contract",
) -> int:
    payload_digest = r.canonical_digest(response)
    terminal_status = "complete" if response.get("complete") is True else "partial"
    receipt = {
        "receipt_contract": r.TRANSPORT_RECEIPT_CONTRACT,
        "correlation_id": r.AUDIT_CONTEXT["correlation_id"],
        "request_digest": r.AUDIT_CONTEXT["request_digest"],
        "response_payload_digest": payload_digest,
        "elastic_search_count": r.AUDIT_CONTEXT["elastic_search_count"],
        "osquery_query_count": r.AUDIT_CONTEXT["osquery_query_count"],
        "helper_invocation_count": r.AUDIT_CONTEXT["helper_invocation_count"],
        "read_only": True,
        "terminal_status": terminal_status,
    }
    emitted = {**response, "audit_receipt": receipt}
    output = json.dumps(emitted, separators=(",", ":"), sort_keys=True).encode()
    if len(output) > maximum_bytes:
        r.fail(output_error, 4)
    r.audit_log(
        "security_onion_terminal",
        status=terminal_status,
        elastic_search_count=receipt["elastic_search_count"],
        osquery_query_count=receipt["osquery_query_count"],
        helper_invocation_count=receipt["helper_invocation_count"],
        response_payload_digest=payload_digest,
    )
    sys.stdout.buffer.write(output + b"\n")
    return 0


def index_matches_scope(r, index_name: str, index_scope: list[str]) -> bool:
    """Return whether an Elasticsearch backing index belongs to a reviewed scope."""
    return any(
        fnmatch.fnmatchcase(index_name, pattern)
        or fnmatch.fnmatchcase(index_name, f".ds-{pattern}-*")
        for pattern in index_scope
    )


def validated_anchor(r, value: object) -> dict[str, str] | None:
    """Validate the collector-owned representative alert identifier.

    Missing anchors remain protocol-compatible with older collectors, but the
    response can never be semantically valid or complete without one.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        r.fail("anchor must be an object")
    index_name = str(value.get("index") or "").strip()
    document_id = str(value.get("id") or "").strip()
    if (
        not index_name
        or not r.SAFE_ELASTIC_INDEX.fullmatch(index_name)
        or not r.index_matches_scope(index_name, r.ALERT_INDEX_SCOPE)
    ):
        r.fail("anchor index is not an allowlisted Security Onion alert index")
    if not r.SAFE_ELASTIC_ID.fullmatch(document_id):
        r.fail("anchor id is invalid")
    return {"index": index_name, "id": document_id}


def validated_request(
    r,
    data: dict,
) -> tuple[list[str], list[str], list[dict], dict[str, list[str]], int, dict[str, str] | None]:
    packs = data.get("packs") or list(r.PACKS)
    if not isinstance(packs, list) or not packs or len(packs) > len(r.PACKS):
        r.fail("packs must be a non-empty bounded list")
    packs = [str(item) for item in packs]
    if len(set(packs)) != len(packs) or any(item not in r.PACKS for item in packs):
        r.fail("one or more evidence packs are not allowlisted")
    osquery_packs = data.get("osquery_packs") or list(r.OSQUERY_PACKS)
    if (
        not isinstance(osquery_packs, list)
        or not osquery_packs
        or len(osquery_packs) > len(r.OSQUERY_PACKS)
    ):
        r.fail("osquery_packs must be a non-empty bounded list")
    osquery_packs = [str(item) for item in osquery_packs]
    if (
        len(set(osquery_packs)) != len(osquery_packs)
        or any(item not in r.OSQUERY_PACKS for item in osquery_packs)
    ):
        r.fail("one or more OSquery packs are not allowlisted")
    windows = data.get("windows")
    if not isinstance(windows, list) or not windows or len(windows) > r.MAX_WINDOWS:
        r.fail(f"windows must contain 1-{r.MAX_WINDOWS} entries")
    clean_windows = []
    for item in windows:
        if not isinstance(item, dict):
            r.fail("each window must be an object")
        try:
            start, end = r.parse_time(item.get("start")), r.parse_time(item.get("end"))
        except (TypeError, ValueError) as exc:
            r.fail(f"invalid evidence window: {exc}")
        if end <= start or end - start > dt.timedelta(hours=24):
            r.fail("each evidence window must be positive and no longer than 24 hours")
        clean_windows.append({"start": r.iso_utc(start), "end": r.iso_utc(end)})
    observables = data.get("observables") or {}
    if not isinstance(observables, dict):
        r.fail("observables must be an object")
    clean_observables: dict[str, list[str]] = {}
    for kind in r.OBSERVABLE_FIELDS:
        values = observables.get(kind) or []
        if not isinstance(values, list) or len(values) > 16:
            r.fail(f"{kind} must contain at most 16 values")
        clean = []
        for value in values:
            text = str(value or "").strip()
            if not r.SAFE_VALUE.fullmatch(text):
                r.fail(f"invalid {kind} observable")
            if text not in clean:
                clean.append(text)
        clean_observables[kind] = clean
    if not any(clean_observables.values()):
        r.fail("at least one exact observable is required")
    size = data.get("size", 100)
    try:
        size = int(size)
    except (TypeError, ValueError):
        r.fail("size must be an integer")
    if size < 1 or size > r.MAX_HITS:
        r.fail(f"size must be between 1 and {r.MAX_HITS}")
    anchor = r.validated_anchor(data.get("anchor"))
    return packs, osquery_packs, clean_windows, clean_observables, size, anchor


