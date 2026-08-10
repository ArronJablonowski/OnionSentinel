"""Bounded Ollama transport and exact installed-model discovery."""
from __future__ import annotations

import json
import urllib.request
from typing import Any


def bounded_json_request(
    url: str,
    payload: dict[str, Any],
    timeout: int,
    *,
    max_response_bytes: int,
) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(max_response_bytes + 1)
    if len(raw) > max_response_bytes:
        raise RuntimeError(f"Ollama response exceeded {max_response_bytes} bytes")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("Ollama returned a non-object response")
    return parsed


def installed_models(
    ollama_url: str,
    timeout: int = 10,
    *,
    max_response_bytes: int,
) -> list[str]:
    request = urllib.request.Request(
        ollama_url.rstrip("/") + "/api/tags",
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(max_response_bytes + 1)
    if len(raw) > max_response_bytes:
        raise RuntimeError("Ollama tags response exceeded safety limit")
    payload = json.loads(raw.decode("utf-8"))
    return [
        str(item.get("name") or "").strip()
        for item in payload.get("models", [])
        if item.get("name")
    ]
