#!/usr/bin/env python3
"""Project bounded AC Hunter snapshot context for one alert.

The only runtime read is the alert store's fixed loopback snapshot endpoint.
This module cannot refresh the snapshot, contact the Relay, or read AC Hunter
credentials. Snapshot text remains untrusted behavioral context.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Mapping
from urllib import error, request


CONTEXT_SCHEMA = "onion-sentinel-ac-hunter-evidence-context-v1"
SNAPSHOT_SCHEMA = "onion-sentinel-ac-hunter-review-v1"
FIXED_DATASET = "security-onion-rolling"
SNAPSHOT_URL = "http://127.0.0.1:8787/ac-hunter/snapshot"
MAX_SNAPSHOT_BYTES = 1024 * 1024
MAX_FINDINGS = 32
MAX_CORRELATED_HOSTS = 16
MAX_MODULES = 32
MAX_LIST_ITEMS = 5000
MAX_TEXT = 500
MAX_DEPTH = 14
DIGEST_RE = re.compile(r"[a-f0-9]{64}")
FORBIDDEN_KEYS = frozenset({
    "authorization", "cookie", "credentials", "email", "jwt", "password",
    "secret", "session", "session_cookie", "token",
})
SUCCESS_STATUSES = frozenset({"ok", "success", "complete"})
FINDING_FIELDS = (
    "id", "module", "source_ip", "destination_ip", "fqdn", "port",
    "protocol", "score", "priority_score", "verdict", "reason", "evidence",
    "watch_match", "count", "duration", "duration_seconds", "timing_mode",
    "data_size_mode", "responding_ips",
)
CORRELATION_FIELDS = (
    "host", "source_ip", "modules", "module_count", "finding_count",
    "priority_score", "verdict", "reason",
)


FetchSnapshot = Callable[[], tuple[int, bytes]]


class AcHunterContextError(ValueError):
    """Fail-closed validation error without upstream content."""


def _fetch_snapshot() -> tuple[int, bytes]:
    incoming = request.Request(
        SNAPSHOT_URL,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with request.urlopen(incoming, timeout=3) as response:
            return int(response.status), response.read(MAX_SNAPSHOT_BYTES + 1)
    except error.HTTPError as caught:
        return int(caught.code), b""
    except (error.URLError, TimeoutError, OSError):
        return 0, b""


def _text(value: Any, maximum: int = MAX_TEXT) -> str:
    normalized = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    return re.sub(r"\s+", " ", normalized).strip()[:maximum]


def _scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _text(value)


def _bounded_value(value: Any, *, maximum_items: int = 24) -> Any:
    if isinstance(value, list):
        return [_scalar(item) for item in value[:maximum_items]]
    return _scalar(value)


def _inspect_list(value: list[Any], depth: int) -> None:
    if len(value) > MAX_LIST_ITEMS:
        raise AcHunterContextError("snapshot list is too large")
    for child in value:
        _inspect_tree(child, depth + 1)


def _valid_key(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 128
        and value.strip().lower() not in FORBIDDEN_KEYS
    )


def _inspect_mapping(value: dict[Any, Any], depth: int) -> None:
    if len(value) > 1000:
        raise AcHunterContextError("snapshot object is too large")
    for key, child in value.items():
        if not _valid_key(key):
            raise AcHunterContextError("snapshot contains prohibited material")
        _inspect_tree(child, depth + 1)


def _inspect_scalar(value: Any) -> None:
    if isinstance(value, str) and len(value) > 8192:
        raise AcHunterContextError("snapshot text is too large")
    if value is not None and not isinstance(value, (str, bool, int, float)):
        raise AcHunterContextError("snapshot value is invalid")


def _inspect_tree(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise AcHunterContextError("snapshot nesting is invalid")
    if isinstance(value, list):
        _inspect_list(value, depth)
    elif isinstance(value, dict):
        _inspect_mapping(value, depth)
    else:
        _inspect_scalar(value)


def _parse_snapshot(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise AcHunterContextError("snapshot exceeds its byte boundary")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as caught:
        raise AcHunterContextError("snapshot JSON is invalid") from caught
    if not isinstance(value, dict):
        raise AcHunterContextError("snapshot must be an object")
    _inspect_tree(value)
    return value


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AcHunterContextError(f"snapshot {field} is invalid")
    return value


def _validate_snapshot(value: dict[str, Any]) -> tuple[Mapping[str, Any], str]:
    dataset = _mapping(value.get("dataset"), "dataset")
    metadata = _mapping(value.get("metadata"), "metadata")
    cache = _mapping(value.get("cache"), "cache")
    modules = _mapping(value.get("modules"), "modules")
    digest = str(cache.get("dataset_digest") or "").strip().lower()
    checks = (
        value.get("schema") == SNAPSHOT_SCHEMA,
        value.get("version") == 1,
        value.get("ok") is True,
        dataset.get("name") == FIXED_DATASET,
        metadata.get("dataset") == FIXED_DATASET,
        metadata.get("storage_backend") == "postgresql",
        cache.get("storage_backend") == "postgresql",
        DIGEST_RE.fullmatch(digest) is not None,
        bool(modules),
        len(modules) <= MAX_MODULES,
    )
    if not all(checks):
        raise AcHunterContextError("snapshot identity is invalid")
    return modules, digest


def _row_value(selected: Any, key: str) -> Any:
    if isinstance(selected, Mapping):
        return selected.get(key)
    try:
        return selected[key]
    except (KeyError, IndexError, TypeError):
        return None


def _alert_observables(selected: Any) -> list[str]:
    result: list[str] = []
    for key in ("source_ip", "destination_ip"):
        value = _text(_row_value(selected, key), 128)
        if value and value not in result:
            result.append(value)
    return result


def _observable_values(value: Mapping[str, Any]) -> set[str]:
    result = {
        _text(value.get(key), 128)
        for key in ("source_ip", "destination_ip", "host")
    }
    for key in ("responding_ips", "destination_ips"):
        raw = value.get(key)
        if isinstance(raw, list):
            result.update(_text(item, 128) for item in raw[:100])
    result.discard("")
    return result


def _matches(value: Any, observables: set[str]) -> bool:
    if not isinstance(value, Mapping):
        return False
    primary = _text(value.get("source_ip") or value.get("host"), 128)
    if primary:
        return primary in observables
    return bool(_observable_values(value) & observables)


def _project_fields(value: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {
        key: _bounded_value(value[key])
        for key in fields
        if key in value and value[key] not in (None, "", [])
    }


def _module_source_truncated(
    module_name: str, raw_findings: list[Any], counts: Mapping[str, Any],
) -> bool:
    if len(raw_findings) >= 100:
        return True
    declared_total = counts.get("beacons" if module_name == "beacons" else module_name)
    if isinstance(declared_total, bool) or not isinstance(declared_total, int):
        return False
    return declared_total > len(raw_findings)


def _project_module(
    module_name: str,
    raw: Any,
    observables: set[str],
    counts: Mapping[str, Any],
    room: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], bool, bool]:
    raw_module = _mapping(raw, f"module {module_name}")
    status = _text(raw_module.get("status"), 40).lower() or "unknown"
    raw_findings = raw_module.get("findings")
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_LIST_ITEMS:
        raise AcHunterContextError("snapshot module findings are invalid")
    matching = [finding for finding in raw_findings if _matches(finding, observables)]
    source_truncated = _module_source_truncated(module_name, raw_findings, counts)
    projected = [
        _project_fields(finding, FINDING_FIELDS)
        for finding in matching[:room]
    ]
    module_status = {
        "module": _text(module_name, 80),
        "status": status,
        "source_count": len(raw_findings),
        "matched_count": len(matching),
        "error_present": bool(raw_module.get("error")),
        "source_truncated": source_truncated,
    }
    return (
        module_status,
        projected,
        status in SUCCESS_STATUSES and not source_truncated,
        source_truncated or len(matching) > room,
    )


def _project_modules(
    modules: Mapping[str, Any], observables: set[str], counts: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, bool]:
    statuses: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    complete = True
    truncated = False
    for module_name in sorted(modules):
        projected = _project_module(
            module_name, modules[module_name], observables, counts,
            max(0, MAX_FINDINGS - len(findings)),
        )
        status, module_findings, module_complete, module_truncated = projected
        statuses.append(status)
        findings.extend(module_findings)
        complete = complete and module_complete
        truncated = truncated or module_truncated
    return statuses, findings, complete, truncated


def _project_correlations(
    value: Any, observables: set[str],
) -> tuple[list[dict[str, Any]], bool]:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise AcHunterContextError("snapshot correlations are invalid")
    matching = [item for item in value if _matches(item, observables)]
    return (
        [_project_fields(item, CORRELATION_FIELDS) for item in matching[:MAX_CORRELATED_HOSTS]],
        len(matching) > MAX_CORRELATED_HOSTS,
    )


def _unavailable(status: str) -> dict[str, Any]:
    return {
        "schema": CONTEXT_SCHEMA,
        "status": status,
        "available": False,
        "complete": False,
        "stale": False,
        "evidence_ref": "",
        "evidence_digest": "",
        "returned": 0,
        "findings": [],
        "correlated_hosts": [],
        "module_statuses": [],
        "negative_evidence_allowed": False,
        "truncated": False,
        "trust": "untrusted_behavioral_context",
        "malware_verdict_authority": False,
        "collection_triggered": False,
    }


def _status(*, stale: bool, complete: bool, returned: int) -> str:
    if not complete:
        return "partial"
    if stale:
        return "stale"
    return "fresh" if returned else "empty"


def _load_snapshot(
    fetch_snapshot: FetchSnapshot,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        http_status, raw = fetch_snapshot()
    except Exception:  # the boundary exposes a stable state, never upstream text
        return None, _unavailable("unavailable")
    if http_status in {401, 403}:
        return None, _unavailable("auth_failure")
    if http_status == 404:
        return None, _unavailable("not_collected")
    if http_status != 200:
        return None, _unavailable("unavailable")
    return _parse_snapshot(raw), None


def _bounded_notes(value: Any) -> list[str]:
    return [_text(item) for item in value[:16]] if isinstance(value, list) else []


def _bounded_time_range(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {
        key: _text(value.get(key), 80)
        for key in ("start", "end", "min", "max")
        if value.get(key)
    }


def _context_payload(
    value: dict[str, Any],
    digest: str,
    observables: list[str],
    module_statuses: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    correlated: list[dict[str, Any]],
    *,
    complete: bool,
    stale: bool,
    truncated: bool,
) -> dict[str, Any]:
    returned = len(findings) + len(correlated)
    status = _status(stale=stale, complete=complete, returned=returned)
    notes = value.get("analyst_notes")
    return {
        "schema": CONTEXT_SCHEMA,
        "status": status,
        "available": True,
        "complete": complete,
        "stale": stale,
        "dataset": FIXED_DATASET,
        "dataset_time_range": _bounded_time_range(value.get("time_range")),
        "collected_at": _text(value.get("last_pulled_at"), 80),
        "matched_observables": observables,
        "evidence_ref": f"ac-hunter:{digest}",
        "evidence_digest": digest,
        "returned": returned,
        "findings": findings,
        "correlated_hosts": correlated,
        "module_statuses": module_statuses,
        "analyst_notes": _bounded_notes(notes),
        "disclaimer": _text(value.get("disclaimer")),
        "negative_evidence_allowed": bool(status == "empty" and not truncated),
        "truncated": truncated,
        "trust": "untrusted_behavioral_context",
        "malware_verdict_authority": False,
        "collection_triggered": False,
    }


def _project_context(selected: Any, value: dict[str, Any]) -> dict[str, Any]:
    modules, digest = _validate_snapshot(value)
    observables = _alert_observables(selected)
    if not observables:
        return _unavailable("unavailable")
    counts = value.get("counts")
    counts = counts if isinstance(counts, Mapping) else {}
    module_statuses, findings, modules_complete, findings_truncated = (
        _project_modules(modules, set(observables), counts)
    )
    correlated, correlations_truncated = _project_correlations(
        value.get("correlated_hosts", []), set(observables)
    )
    metadata = _mapping(value.get("metadata"), "metadata")
    cache = _mapping(value.get("cache"), "cache")
    return _context_payload(
        value,
        digest,
        observables,
        module_statuses,
        findings,
        correlated,
        complete=metadata.get("complete") is True and modules_complete,
        stale=cache.get("stale") is True or metadata.get("stale") is True,
        truncated=findings_truncated or correlations_truncated,
    )


def build_ac_hunter_context(
    selected: Any, *, fetch_snapshot: FetchSnapshot = _fetch_snapshot,
) -> dict[str, Any]:
    """Return a source-bounded projection without triggering collection."""
    try:
        value, state = _load_snapshot(fetch_snapshot)
        if state is not None:
            return state
        assert value is not None
        return _project_context(selected, value)
    except (AcHunterContextError, TypeError, ValueError):
        return _unavailable("invalid")


__all__ = (
    "CONTEXT_SCHEMA", "MAX_FINDINGS", "MAX_SNAPSHOT_BYTES",
    "build_ac_hunter_context",
)
