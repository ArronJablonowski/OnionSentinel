"""Bounded Suricata application-buffer projection for detection validation."""

from __future__ import annotations

import re
from typing import Any

from detection_validation_rule import MAX_PACKET_BYTES, _nested


def _decoded_application_text(raw: dict[str, Any], message: dict[str, Any]) -> str:
    decoded_value = (
        _nested(raw, "network.data.decoded")
        or message.get("payload_printable")
        or ""
    )
    if not isinstance(decoded_value, str):
        return ""
    if len(decoded_value.encode("utf-8", "replace")) > MAX_PACKET_BYTES:
        return ""
    return str(decoded_value)


def _http_application_buffers(decoded: str) -> dict[str, bytes]:
    buffers: dict[str, bytes] = {}
    if not decoded:
        return buffers
    lines = re.split(r"\r?\n", decoded)
    if lines:
        request = lines[0].split()
        if len(request) >= 2 and re.fullmatch(r"[A-Z]{2,16}", request[0]):
            buffers["http.method"] = request[0].encode("latin-1", "replace")
            buffers["http.uri"] = request[1].encode("latin-1", "replace")
    for line in lines[1:256]:
        name, separator, value = line.partition(":")
        if not separator:
            continue
        key = {
            "host": "http.host",
            "server": "http.server",
            "user-agent": "http.user_agent",
        }.get(name.strip().lower())
        if key and value.strip():
            buffers[key] = value.strip().encode("latin-1", "replace")[
                :MAX_PACKET_BYTES
            ]
    return buffers


def _dns_query_name(
    raw: dict[str, Any],
    message: dict[str, Any],
    alert: dict[str, Any],
) -> str:
    return str(
        _nested(raw, "dns.query.name")
        or _nested(raw, "dns.question.name")
        or _nested(raw, "dns.query_name")
        or _nested(alert, "dns.query_name")
        or _nested(message, "dns.rrname")
        or ""
    ).strip().rstrip(".")


def _configured_tls_name(
    raw: dict[str, Any],
    message: dict[str, Any],
    alert: dict[str, Any],
) -> str:
    return str(
        _nested(raw, "tls.server.name")
        or _nested(raw, "tls.sni")
        or _nested(alert, "tls.server.name")
        or _nested(alert, "tls.sni")
        or _nested(message, "tls.sni")
        or ""
    ).strip().rstrip(".")


def _inferred_tls_name(
    decoded: str,
    marker_values: list[tuple[dict[str, Any], bytes]] | None,
) -> str:
    candidates = {
        value.rstrip(".").lower()
        for value in re.findall(
            r"(?i)(?<![A-Za-z0-9-])"
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63}(?![A-Za-z0-9-])",
            decoded,
        )
        if len(value) <= 253
    }
    tls_markers = {
        marker.decode("latin-1", "ignore").lower().lstrip(".")
        for spec, marker in marker_values or []
        if str(spec.get("buffer") or "").strip().lower() == "tls.sni"
    }
    matching = {
        candidate
        for candidate in candidates
        if any(
            candidate == marker or candidate.endswith(f".{marker}")
            for marker in tls_markers
            if marker
        )
    }
    return next(iter(matching)) if len(matching) == 1 else ""


def _bounded_application_buffers(
    raw: dict[str, Any],
    message: dict[str, Any],
    alert: dict[str, Any],
    marker_values: list[tuple[dict[str, Any], bytes]] | None = None,
) -> dict[str, bytes]:
    """Project Suricata application evidence without retaining raw payloads."""
    decoded = _decoded_application_text(raw, message)
    buffers = _http_application_buffers(decoded)
    dns_name = _dns_query_name(raw, message, alert)
    if dns_name and len(dns_name.encode("utf-8", "replace")) <= 253:
        buffers["dns.query"] = dns_name.encode("utf-8", "replace")
    tls_name = _configured_tls_name(raw, message, alert)
    if not tls_name and decoded:
        tls_name = _inferred_tls_name(decoded, marker_values)
    if tls_name and len(tls_name.encode("utf-8", "replace")) <= 253:
        buffers["tls.sni"] = tls_name.encode("utf-8", "replace")
    return buffers
