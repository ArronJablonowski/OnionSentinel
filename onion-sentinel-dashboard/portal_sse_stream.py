"""Bounded server-sent-event delivery for live SOC alert revisions."""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Protocol


class SseHandler(Protocol):
    wfile: object

    def send_response(self, status: int) -> None: ...
    def send_header(self, name: str, value: str) -> None: ...
    def end_headers(self) -> None: ...


def send_soc_alert_events(
    handler: SseHandler,
    *,
    snapshot: Callable[[], dict],
    revision_digest: Callable[[dict], str],
    now_seconds: Callable[[], float],
    sleep: Callable[[float], None],
    iterations: int = 60,
    interval_seconds: float = 5,
) -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Connection", "keep-alive")
    handler.send_header("X-Accel-Buffering", "no")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    last_digest = ""
    for _ in range(iterations):
        try:
            payload = snapshot()
            raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            stable_payload = dict(payload)
            stable_payload.pop("time", None)
            digest = revision_digest(stable_payload)
            if digest != last_digest:
                event_id = str(int(now_seconds()))
                handler.wfile.write(
                    f"id: {event_id}\nevent: soc-alerts\ndata: {raw}\n\n".encode("utf-8")
                )
                last_digest = digest
            else:
                handler.wfile.write(b": keepalive\n\n")
            handler.wfile.flush()
            sleep(interval_seconds)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
