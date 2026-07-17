#!/usr/bin/env python3
"""Forced-command SSH intake for durable relay-to-alert-store delivery.

The associated SSH key cannot open a shell, forward ports, or choose a target.
This command accepts a bounded JSON batch on stdin and submits each message to
the host-native alert-store.  Per-message acknowledgements make replay safe and
isolate malformed messages from healthy alerts in the same relay backlog.
"""
from __future__ import annotations

import json
import os
import sys
import time
from urllib import request
from urllib.error import HTTPError, URLError


PROTOCOL = "onion-sentinel-alert-batch/v1"
ALERT_STORE_URL = os.environ.get("ONION_SENTINEL_ALERT_STORE_URL", "http://127.0.0.1:8787/alert")
MAX_BATCH_BYTES = max(1024, int(os.environ.get("ONION_SENTINEL_ALERT_BATCH_MAX_BYTES", str(8 * 1024 * 1024))))
MAX_BATCH_ITEMS = max(1, min(1000, int(os.environ.get("ONION_SENTINEL_ALERT_BATCH_MAX_ITEMS", "100"))))
REQUEST_TIMEOUT_SECONDS = max(5, min(120, int(os.environ.get("ONION_SENTINEL_ALERT_REQUEST_TIMEOUT_SECONDS", "35"))))
BATCH_DEADLINE_SECONDS = max(30, min(300, int(os.environ.get("ONION_SENTINEL_ALERT_BATCH_DEADLINE_SECONDS", "120"))))
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504, 507}


def reject(reason: str) -> None:
    print(json.dumps({"ok": False, "status": "rejected", "error": reason}, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)


def read_batch() -> dict:
    data = sys.stdin.buffer.read(MAX_BATCH_BYTES + 1)
    if len(data) > MAX_BATCH_BYTES:
        reject("alert batch exceeds configured byte limit")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("alert batch is not valid UTF-8 JSON")
    if not isinstance(payload, dict) or payload.get("protocol") != PROTOCOL:
        reject("unsupported alert intake protocol")
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages or len(messages) > MAX_BATCH_ITEMS:
        reject("alert batch item count is outside configured bounds")
    return payload


def response_detail(body: object, fallback: str) -> str:
    if isinstance(body, dict):
        return str(body.get("reason") or body.get("error") or body.get("status") or fallback)[:500]
    return fallback[:500]


def post_message(delivery_id: str, payload: dict) -> dict:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    req = request.Request(
        ALERT_STORE_URL,
        data=encoded,
        headers={"Content-Type": "application/json", "User-Agent": "Onion-Sentinel-SSH-Intake/1.0"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body_text = response.read(1024 * 1024).decode("utf-8", errors="replace")
            try:
                body = json.loads(body_text) if body_text else {}
            except json.JSONDecodeError:
                body = {"error": "alert-store returned non-JSON data"}
            ok = 200 <= response.status < 300 and isinstance(body, dict) and body.get("ok") is not False
            return {
                "delivery_id": delivery_id,
                "ok": ok,
                "retryable": not ok,
                "status": body.get("status") if isinstance(body, dict) else "invalid_response",
                "reason": "" if ok else response_detail(body, f"HTTP {response.status}"),
            }
    except HTTPError as exc:
        try:
            body = json.loads(exc.read(1024 * 1024).decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {}
        return {
            "delivery_id": delivery_id,
            "ok": False,
            "retryable": exc.code in RETRYABLE_STATUS,
            "status": "http_error",
            "reason": response_detail(body, f"HTTP {exc.code}"),
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "delivery_id": delivery_id,
            "ok": False,
            "retryable": True,
            "status": "transport_error",
            "reason": str(getattr(exc, "reason", exc))[:500],
        }


def main() -> int:
    if os.environ.get("SSH_ORIGINAL_COMMAND", "").strip() != "onion-sentinel-alert-intake batch":
        reject("interactive sessions and unsupported commands are not permitted")
    batch = read_batch()
    results = []
    seen_ids = set()
    deadline = time.monotonic() + BATCH_DEADLINE_SECONDS
    for item in batch["messages"]:
        if not isinstance(item, dict):
            reject("alert batch entries must be objects")
        delivery_id = str(item.get("delivery_id") or "").strip()
        payload = item.get("payload")
        if not delivery_id or len(delivery_id) > 512 or delivery_id in seen_ids:
            reject("delivery ids must be unique, non-empty, and bounded")
        if not isinstance(payload, dict):
            reject("alert message payload must be an object")
        seen_ids.add(delivery_id)
        if time.monotonic() >= deadline:
            results.append({
                "delivery_id": delivery_id,
                "ok": False,
                "retryable": True,
                "status": "batch_deadline",
                "reason": "batch deadline reached before delivery",
            })
        else:
            results.append(post_message(delivery_id, payload))
    print(json.dumps({
        "ok": all(item["ok"] for item in results),
        "protocol": PROTOCOL,
        "processed": len(results),
        "results": results,
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
