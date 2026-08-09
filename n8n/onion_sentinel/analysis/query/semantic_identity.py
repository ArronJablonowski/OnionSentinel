"""Canonical semantic identity for deduplicating investigation requests."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, Callable


@dataclass(frozen=True)
class Dependencies:
    normalize_live_query: Callable[[Any], str]


def digest(request: dict[str, Any], dependencies: Dependencies) -> str:
    """Identify equivalent execution independently of model labels and purpose."""
    parameters = json.loads(json.dumps(
        request.get("parameters") or {}, sort_keys=True, default=str,
    ))
    backend = request.get("backend")
    if isinstance(parameters, dict):
        _canonicalize(backend, parameters, dependencies)
    canonical = {"backend": backend, "parameters": parameters}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _canonicalize(
    backend: Any, parameters: dict[str, Any], dependencies: Dependencies,
) -> None:
    if backend in {"elastic", "oql"}:
        _security_onion(parameters)
    elif backend == "osquery":
        parameters["query"] = _osquery(parameters.get("query"), dependencies)
    elif backend == "pcap_zeek":
        _derived(parameters)
    elif backend == "enrichment":
        _enrichment(parameters)


def _security_onion(parameters: dict[str, Any]) -> None:
    observables = parameters.get("observables")
    if isinstance(observables, dict):
        for kind in ("ips", "domains", "hosts", "users"):
            values = observables.get(kind)
            if isinstance(values, list):
                observables[kind] = _observable_values(kind, values)
    window = parameters.get("window")
    if isinstance(window, dict):
        for boundary in ("start", "end"):
            canonical = _utc_boundary(window.get(boundary))
            if canonical is not None:
                window[boundary] = canonical


def _observable_values(kind: str, values: list[Any]) -> list[str]:
    normalized: list[str] = []
    for raw in values:
        text = str(raw or "").strip().rstrip(".")
        if kind == "ips":
            text = _canonical_ip(text)
        elif kind == "domains":
            text = text.lower()
        if text:
            normalized.append(text)
    return sorted(set(normalized))


def _canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _utc_boundary(value: Any) -> str | None:
    text = str(value or "").strip()
    parseable = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = dt.datetime.fromisoformat(parseable)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc).isoformat(
        timespec="milliseconds",
    ).replace("+00:00", "Z")


def _osquery(value: Any, dependencies: Dependencies) -> str:
    normalized = dependencies.normalize_live_query(value)
    parts = re.split(r"('(?:''|[^'])*')", normalized)
    return "".join(
        part if index % 2 else " ".join(part.lower().split())
        for index, part in enumerate(parts)
    )


def _derived(parameters: dict[str, Any]) -> None:
    if isinstance(parameters.get("indicator"), str):
        parameters["indicator"] = parameters["indicator"].casefold()
    filters = parameters.get("filters")
    if isinstance(filters, dict):
        parameters["filters"] = {
            key: value.casefold() if isinstance(value, str) else value
            for key, value in filters.items()
        }


def _enrichment(parameters: dict[str, Any]) -> None:
    parameters["indicator_type"] = str(
        parameters.get("indicator_type") or ""
    ).lower()
    parameters["indicator"] = str(
        parameters.get("indicator") or ""
    ).strip().rstrip(".").lower()
