#!/usr/bin/env python3
"""Dedicated Onion Sentinel HTTP service.

This process deliberately exposes only Onion Sentinel static files and APIs.
The Hermes LAN Portal is a separate application and may link here, but it is
not a runtime dependency and cannot publish or mutate Onion Sentinel content.
"""
from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
import shutil
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import report_portal as runtime
from http_runtime import BoundedThreadingHTTPServer


HOME = Path.home()
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8766
DEFAULT_DASHBOARD_ROOT = HOME / "SOC Alerts Web"

GET_API_ROUTES = {
    "/api/system-health/beacons",
    "/api/llm-analysis/current",
    "/api/llm-analysis/logs",
    "/api/soc-alerts",
    "/api/soc-alerts/events",
    "/api/soc-alerts/metrics",
    "/api/soc-alerts/status",
    "/api/soc-alerts/suppressions",
    "/api/soc-settings/agent-memory",
    "/api/soc-settings/ai-model",
    "/api/soc-settings/analyst-prompt",
    "/api/soc-settings/cyber-threat-intel-prompt",
    "/api/soc-settings/incident-responder-prompt",
    "/api/soc-settings/ollama-models",
    "/api/soc-settings/siem-engineer-prompt",
    "/api/soc-settings/threat-hunter-prompt",
}
POST_API_ROUTES = {
    "/api/soc-alerts/status",
    "/api/soc-settings/ai-model",
    "/api/soc-settings/analyst-prompt",
    "/api/soc-settings/cyber-threat-intel-prompt",
    "/api/soc-settings/incident-responder-prompt",
    "/api/soc-settings/siem-engineer-prompt",
    "/api/soc-settings/threat-hunter-prompt",
}
POST_ALERT_SUFFIXES = ("/ack", "/analyze", "/pcap")


def configure_runtime_paths(dashboard_root: Path) -> None:
    """Point legacy SOC helpers at Onion Sentinel-owned runtime paths."""
    root = dashboard_root.expanduser().resolve()
    runtime.SOC_ALERT_DASHBOARD_DIR = root
    runtime.SOC_ALERT_DETAIL_DIR = root / "details"
    runtime.SOC_ALERT_STATIC_STATUS_FILE = root / "soc-alerts-status.json"
    runtime.SOC_ALERT_N8N_BEACON_FILE = root / "n8n-beacon.json"
    runtime.SOC_ALERT_N8N_BEACON_HISTORY_FILE = root / "n8n-beacon-history.json"
    runtime.SOC_ALERT_STATUS_FILE = HOME / "n8n-local" / "alert_store_data" / ".soc_alert_status.json"
    runtime.SCAN_ROOTS = [root]
    runtime.LAST_UPDATED_FILE = root / ".last_updated"

    # Authentication state is intentionally separate from the Hermes portal.
    runtime.ADMIN_STATE_DIR = HOME / "n8n-local" / "admin-state"
    runtime.ADMIN_TOKEN_FILE = runtime.ADMIN_STATE_DIR / ".admin_token"
    runtime.ADMIN_PASSWORD_FILE = HOME / "n8n-local" / "config" / "onion-sentinel-admin-password.json"
    runtime.ADMIN_SESSIONS_FILE = runtime.ADMIN_STATE_DIR / ".admin_sessions.json"
    runtime.ADMIN_LOCK_FILE = runtime.ADMIN_STATE_DIR / ".admin_action.lock"
    runtime.ADMIN_SESSION_COOKIE = "onion_sentinel_admin"


def is_soc_get_api(path: str) -> bool:
    if path in GET_API_ROUTES:
        return True
    return path.startswith("/api/soc-alerts/") and not path.endswith(POST_ALERT_SUFFIXES)


def is_soc_post_api(path: str) -> bool:
    if path in POST_API_ROUTES:
        return True
    return path.startswith("/api/soc-alerts/") and path.endswith(POST_ALERT_SUFFIXES)


def is_same_origin_json_request(headers: object) -> tuple[bool, int, str]:
    """Validate the browser contract for state-changing SOC API requests.

    The service is intentionally LAN-only, but a browser can still be induced
    to send cross-site requests. JSON-only mutations plus Origin/Fetch-Metadata
    checks block ordinary CSRF while retaining support for trusted local CLI
    clients, which normally omit both browser-specific headers.
    """
    get = getattr(headers, "get", lambda _name, _default=None: _default)
    content_type = str(get("Content-Type", "")).split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return False, HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "SOC API mutations require application/json"
    if str(get("Sec-Fetch-Site", "")).strip().lower() == "cross-site":
        return False, HTTPStatus.FORBIDDEN, "Cross-site SOC API mutation rejected"
    origin = str(get("Origin", "")).strip()
    if origin:
        parsed = urlparse(origin)
        host = str(get("Host", "")).strip().lower()
        if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != host:
            return False, HTTPStatus.FORBIDDEN, "Origin did not match the Onion Sentinel service"
    return True, HTTPStatus.OK, ""


def resolve_dashboard_target(root: Path, request_path: str) -> Path | None:
    """Resolve a static request without allowing traversal or dot-file reads."""
    decoded = unquote(urlparse(request_path).path)
    relative = "index.html" if decoded in ("", "/") else decoded.lstrip("/")
    parts = Path(relative).parts
    if not parts or any(part in ("", ".", "..") or part.startswith(".") for part in parts):
        return None
    base = root.expanduser().resolve()
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def render_login(message: str = "", error: bool = False) -> bytes:
    token = runtime.ensure_admin_token()
    note = ""
    if message:
        cls = "error" if error else "note"
        note = f'<p class="{cls}">{html.escape(message)}</p>'
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Onion Sentinel Administration</title><style>
body{{margin:0;background:#07131d;color:#edf7ff;font:16px system-ui;display:grid;place-items:center;min-height:100vh}}
main{{width:min(420px,calc(100% - 32px));border:1px solid #16485a;padding:24px;background:#0b1823}}
label{{display:block;color:#a9bbcf;margin:16px 0 8px}}input,button{{box-sizing:border-box;width:100%;min-height:44px;font:inherit}}
input{{background:#07131d;color:#edf7ff;border:1px solid #315064;padding:10px}}button{{margin-top:16px;background:#16bfd5;color:#041016;border:0;font-weight:700}}
.error{{color:#ff7188}}.note{{color:#71e6f4}}a{{color:#71e6f4}}</style></head>
<body><main><h1>Onion Sentinel</h1><p>Administration sign in</p>{note}
<form method="post" action="/admin/login"><input type="hidden" name="token" value="{html.escape(token)}">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form><p><a href="/settings.html">Return to Settings</a></p></main></body></html>"""
    return body.encode("utf-8")


def render_admin_status() -> bytes:
    body = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Onion Sentinel Administration</title></head><body><h1>Onion Sentinel Administration</h1>
<p>Authenticated. Settings changes are enabled for this browser session.</p>
<p><a href="/settings.html">Open Settings</a></p><form method="post" action="/admin/logout">
<input type="hidden" name="token" value="TOKEN"><button type="submit">Sign out</button></form></body></html>"""
    return body.replace("TOKEN", html.escape(runtime.ensure_admin_token())).encode("utf-8")


class OnionSentinelHandler(runtime.PortalHandler):
    server_version = "OnionSentinel/1.0"

    @property
    def dashboard_root(self) -> Path:
        return self.server.dashboard_root  # type: ignore[attr-defined]

    def _security_headers(self) -> dict[str, str]:
        return {
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
        }

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8", extra: dict[str, str] | None = None) -> None:
        headers = self._security_headers()
        if extra:
            headers.update(extra)
        return super()._send(status, body, content_type, headers)

    def _serve_file(self, target: Path) -> None:
        """Stream static assets so large generated pages do not double in RAM."""
        try:
            size = target.stat().st_size
            source = target.open("rb")
        except FileNotFoundError:
            return self._send(HTTPStatus.NOT_FOUND, b"Asset not found", "text/plain; charset=utf-8")
        except OSError:
            return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, b"Asset read failed", "text/plain; charset=utf-8")
        try:
            content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if target.suffix.lower() in (".html", ".htm"):
                content_type = "text/html; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for key, value in self._security_headers().items():
                self.send_header(key, value)
            self.end_headers()
            with source:
                shutil.copyfileobj(source, self.wfile, length=64 * 1024)
        except (BrokenPipeError, ConnectionResetError):
            return
        except OSError:
            # Headers may already be committed; closing the connection is the
            # only protocol-safe response to a mid-stream filesystem failure.
            self.close_connection = True

    def do_HEAD(self) -> None:
        path = urlparse(self.path).path
        target = resolve_dashboard_target(self.dashboard_root, self.path)
        if path in ("/healthz", "/admin", "/admin/login") or is_soc_get_api(path) or target:
            self.send_response(HTTPStatus.OK)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for key, value in self._security_headers().items():
                self.send_header(key, value)
            self.end_headers()
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            data = {
                "ok": (self.dashboard_root / "index.html").is_file() and runtime.SOC_ALERT_STORE_DB.is_file(),
                "service": "onion-sentinel",
                "dashboard_ready": (self.dashboard_root / "index.html").is_file(),
                "alert_store_ready": runtime.SOC_ALERT_STORE_DB.is_file(),
                "time": runtime.now_iso_local(),
                "http_runtime": self.server.runtime_snapshot(),  # type: ignore[attr-defined]
            }
            status = HTTPStatus.OK if data["ok"] else HTTPStatus.SERVICE_UNAVAILABLE
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/admin/login":
            if self._admin_authenticated():
                return self._redirect("/admin")
            return self._send(HTTPStatus.OK, render_login())
        if path == "/admin":
            if not self._admin_authenticated():
                return self._redirect("/admin/login")
            return self._send(HTTPStatus.OK, render_admin_status())
        if is_soc_get_api(path):
            return super().do_GET()
        target = resolve_dashboard_target(self.dashboard_root, self.path)
        if target is not None:
            return self._serve_file(target)
        return self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/admin/login", "/admin/logout"):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > 8192:
                return self._send(HTTPStatus.BAD_REQUEST, render_login("Invalid request size.", True))
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"), keep_blank_values=True)
            if form.get("token", [""])[0] != runtime.ensure_admin_token():
                return self._send(HTTPStatus.FORBIDDEN, render_login("Form token validation failed.", True))
            if path == "/admin/logout":
                runtime.destroy_admin_session(self._admin_session_id())
                return self._redirect("/admin/login", {"Set-Cookie": runtime.expired_admin_session_cookie_header()})
            if not runtime.admin_password_configured():
                return self._send(HTTPStatus.SERVICE_UNAVAILABLE, render_login("An Onion Sentinel admin password has not been configured.", True))
            if not runtime.verify_admin_password(form.get("password", [""])[0]):
                return self._send(HTTPStatus.UNAUTHORIZED, render_login("Invalid password.", True))
            session_id = runtime.create_admin_session(self.client_address[0])
            return self._redirect("/admin", {"Set-Cookie": runtime.admin_session_cookie_header(session_id)})
        if is_soc_post_api(path):
            valid, status, message = is_same_origin_json_request(self.headers)
            if not valid:
                return self._send(
                    status,
                    json.dumps({"ok": False, "error": message}).encode(),
                    "application/json; charset=utf-8",
                )
            return super().do_POST()
        return self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")


class OnionSentinelHTTPServer(BoundedThreadingHTTPServer):
    def __init__(
        self,
        address: tuple[str, int],
        dashboard_root: Path,
        *,
        max_active_requests: int = 96,
        request_timeout_seconds: float = 30.0,
    ):
        self.dashboard_root = dashboard_root.expanduser().resolve()
        super().__init__(
            address,
            OnionSentinelHandler,
            max_active_requests=max_active_requests,
            request_timeout_seconds=request_timeout_seconds,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Dedicated Onion Sentinel web service")
    parser.add_argument("--host", default=os.environ.get("ONION_SENTINEL_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ONION_SENTINEL_PORT", DEFAULT_PORT)))
    parser.add_argument("--dashboard-root", type=Path, default=Path(os.environ.get("ONION_SENTINEL_DASHBOARD_ROOT", DEFAULT_DASHBOARD_ROOT)))
    parser.add_argument("--max-active-requests", type=int, default=int(os.environ.get("ONION_SENTINEL_MAX_ACTIVE_REQUESTS", "96")))
    parser.add_argument("--request-timeout-seconds", type=float, default=float(os.environ.get("ONION_SENTINEL_REQUEST_TIMEOUT_SECONDS", "30")))
    args = parser.parse_args()
    configure_runtime_paths(args.dashboard_root)
    args.dashboard_root.mkdir(parents=True, exist_ok=True)
    server = OnionSentinelHTTPServer(
        (args.host, args.port),
        args.dashboard_root,
        max_active_requests=args.max_active_requests,
        request_timeout_seconds=args.request_timeout_seconds,
    )
    print(f"Onion Sentinel listening on http://{runtime.local_ip()}:{args.port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
