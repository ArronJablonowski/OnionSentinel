"""Bounded HTTP runtime primitives for the dedicated Onion Sentinel service.

The standard-library ``ThreadingHTTPServer`` creates an unbounded thread for
every accepted socket. A burst of slow clients can therefore exhaust memory or
file descriptors before normal health and analyst requests get a chance to run.
This module keeps that simple server model, but places a hard admission limit in
front of worker creation and applies a timeout to every accepted connection.
"""
from __future__ import annotations

import socket
import json
import threading
from http.server import ThreadingHTTPServer
from typing import Any


class BoundedResponseError(RuntimeError):
    """Raised when an internal HTTP response violates its size/JSON contract."""


def read_bounded_body(response: Any, *, max_bytes: int) -> bytes:
    """Read one internal response with declared and observed byte ceilings."""
    limit = int(max_bytes)
    if limit <= 0:
        raise ValueError("max_bytes must be positive")
    raw_length = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
    if raw_length not in (None, ""):
        try:
            declared = int(str(raw_length))
        except (TypeError, ValueError) as exc:
            raise BoundedResponseError("invalid Content-Length") from exc
        if declared < 0 or declared > limit:
            raise BoundedResponseError(f"response exceeded the {limit}-byte limit")
    body = response.read(limit + 1)
    if len(body) > limit:
        raise BoundedResponseError(f"response exceeded the {limit}-byte limit")
    if raw_length not in (None, "") and len(body) != int(str(raw_length)):
        raise BoundedResponseError("truncated response body")
    return body


def read_bounded_json(response: Any, *, max_bytes: int) -> dict[str, Any]:
    """Decode a bounded UTF-8 JSON object from an internal service."""
    try:
        value = json.loads(read_bounded_body(response, max_bytes=max_bytes).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BoundedResponseError("response was not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise BoundedResponseError("response JSON must be an object")
    return value


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Thread-per-request HTTP server with explicit resource ceilings.

    Admission is intentionally non-blocking. Waiting in another unbounded queue
    would only move overload elsewhere; excess clients receive a small 503 and
    can retry while established requests continue to make progress.
    """

    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type,
        *,
        max_active_requests: int = 96,
        request_timeout_seconds: float = 30.0,
        bind_and_activate: bool = True,
    ) -> None:
        self.max_active_requests = max(1, int(max_active_requests))
        self.request_timeout_seconds = max(1.0, float(request_timeout_seconds))
        self._request_slots = threading.BoundedSemaphore(self.max_active_requests)
        self._active_lock = threading.Lock()
        self._active_requests = 0
        self._rejected_requests = 0
        super().__init__(server_address, request_handler_class, bind_and_activate=bind_and_activate)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, client_address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            with self._active_lock:
                self._rejected_requests += 1
            self._reject_overload(request)
            self.shutdown_request(request)
            return
        with self._active_lock:
            self._active_requests += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release_request_slot()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_request_slot()

    def runtime_snapshot(self) -> dict[str, int]:
        """Return lock-protected counters suitable for a health response."""
        with self._active_lock:
            return {
                "active_requests": self._active_requests,
                "max_active_requests": self.max_active_requests,
                "rejected_requests": self._rejected_requests,
            }

    def _release_request_slot(self) -> None:
        with self._active_lock:
            self._active_requests = max(0, self._active_requests - 1)
        self._request_slots.release()

    @staticmethod
    def _reject_overload(request: socket.socket) -> None:
        body = b'{"ok":false,"error":"server busy"}\n'
        response = (
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Cache-Control: no-store\r\n"
            + b"Connection: close\r\n"
            + b"Retry-After: 1\r\n\r\n"
            + body
        )
        try:
            # An overloaded server must not spend a normal request timeout
            # trying to notify another slow client. Best-effort delivery keeps
            # the admission path bounded even during a connection flood.
            request.settimeout(0.25)
            request.sendall(response)
        except OSError:
            pass
