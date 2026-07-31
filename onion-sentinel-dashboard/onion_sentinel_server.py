#!/usr/bin/env python3
"""Dedicated Onion Sentinel HTTP service.

This process deliberately exposes only Onion Sentinel static files and APIs.
The Hermes LAN Portal is a separate application and may link here, but it is
not a runtime dependency and cannot publish or mutate Onion Sentinel content.
"""
from __future__ import annotations

import argparse
import hmac
import html
import importlib.util
import json
import mimetypes
import os
import re
import shutil
import stat
import sys
import time
import uuid
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import report_portal as runtime
import ac_hunter_review
from http_runtime import BoundedThreadingHTTPServer

try:
    from security_jsonl_log import SecurityJsonlLogger
except ModuleNotFoundError:
    _logging_spec = importlib.util.spec_from_file_location(
        "security_jsonl_log",
        Path(__file__).resolve().parents[1]
        / "n8n/bin/security_jsonl_log.py",
    )
    if _logging_spec is None or _logging_spec.loader is None:
        raise
    _logging_module = importlib.util.module_from_spec(_logging_spec)
    sys.modules.setdefault("security_jsonl_log", _logging_module)
    _logging_spec.loader.exec_module(_logging_module)
    SecurityJsonlLogger = _logging_module.SecurityJsonlLogger


HOME = Path.home()
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8766
DEFAULT_DASHBOARD_ROOT = HOME / "SOC Alerts Web"
RUNTIME_RELEASE_ENV_KEY = "ONION_SENTINEL_RELEASE_ID"
DEFAULT_RUNTIME_ENV_PATH = HOME / "n8n-local" / ".env"
RUNTIME_RELEASE_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{6,99}$"
)
MAX_RUNTIME_ENV_BYTES = 1024 * 1024
APPLICATION_LOGGER = SecurityJsonlLogger(
    Path(
        os.environ.get(
            "ONION_SENTINEL_APPLICATION_LOG",
            HOME / "n8n-local/logs/onion-sentinel-application.jsonl",
        )
    ),
    service="onion-sentinel-web",
)


def current_runtime_release_id(
    *,
    environ: object | None = None,
    env_path: Path | None = None,
) -> str:
    """Read the deployed release without evaluating or exposing runtime secrets.

    The production LaunchAgent starts this server directly and does not source
    ``n8n-local/.env``. An explicit process value remains authoritative for
    controlled evaluations; otherwise read only the literal release entry from
    the bounded, owner-only runtime file written by the installer.
    """

    source = os.environ if environ is None else environ
    try:
        explicitly_supplied = RUNTIME_RELEASE_ENV_KEY in source
    except TypeError:
        explicitly_supplied = False
    if explicitly_supplied:
        candidate = source.get(RUNTIME_RELEASE_ENV_KEY, "")
        return (
            candidate
            if isinstance(candidate, str)
            and RUNTIME_RELEASE_ID_RE.fullmatch(candidate)
            else ""
        )

    path = DEFAULT_RUNTIME_ENV_PATH if env_path is None else Path(env_path)
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > MAX_RUNTIME_ENV_BYTES
        ):
            return ""
        raw = path.read_bytes()
    except OSError:
        return ""
    if len(raw) > MAX_RUNTIME_ENV_BYTES:
        return ""
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return ""

    candidates: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == RUNTIME_RELEASE_ENV_KEY:
            candidates.append(value.strip())
    if len(candidates) != 1:
        return ""
    candidate = candidates[0]
    return candidate if RUNTIME_RELEASE_ID_RE.fullmatch(candidate) else ""


EVALUATION_MODE_VALUE = str(
    os.environ.get("ONION_SENTINEL_EVALUATION_MODE") or ""
).strip()
if EVALUATION_MODE_VALUE not in {"", "0", "1"}:
    raise RuntimeError(
        "ONION_SENTINEL_EVALUATION_MODE must be unset, 0, or 1"
    )
CONTROLLED_EVALUATION_MODE = EVALUATION_MODE_VALUE == "1"
RUNTIME_RELEASE_ID = current_runtime_release_id()
CONTROLLED_EVALUATION_TOKEN = str(
    os.environ.get("ONION_SENTINEL_EVALUATION_TOKEN") or ""
).strip()
CONTROLLED_EVALUATION_DISPATCH_ROUTES = (
    "POST /api/soc-alerts/{12hex}/analyze",
    "POST /api/soc-incidents/{case_id}/reanalyze",
)

GET_API_ROUTES = {
    "/api/ac-hunter/deep-review",
    "/api/admin/session-status",
    "/api/asset-inventory",
    "/api/cyber-threat-intel/program",
    "/api/dhcp-asset-discovery",
    "/api/software-inventory",
    "/api/system-health/beacons",
    "/api/llm-analysis/current",
    "/api/llm-analysis/logs",
    "/api/soc-alerts",
    "/api/soc-alerts/events",
    "/api/soc-alerts/metrics",
    "/api/soc-alerts/status",
    "/api/soc-alerts/suppressions",
    "/api/soc-incidents",
    "/api/soc-incidents/reanalysis-runs",
    "/api/soc-settings/agent-memory",
    "/api/soc-settings/ai-model",
    "/api/soc-settings/ollama-models",
} | set(runtime.SOC_SETTINGS_PROMPT_API_PATHS)
POST_API_ROUTES = {
    "/api/ac-hunter/refresh",
    "/api/assets/approve-dhcp-ip-change",
    "/api/assets/demote",
    "/api/assets/promote-dhcp",
    "/api/assets/update",
    "/api/cyber-threat-intel/program",
    "/api/soc-alerts/status",
    "/api/soc-incidents/reanalyze-all",
    "/api/soc-settings/agent-model",
    "/api/soc-settings/ai-model",
} | set(runtime.SOC_SETTINGS_PROMPT_API_PATHS)
ALERT_GET_SUFFIXES = ("/detail", "/adjudications")
ALERT_POST_SUFFIXES = ("/ack", "/analyze", "/pcap", "/escalate", "/adjudicate")
INCIDENT_GET_SUFFIXES = ("/detail", "/adjudications")
INCIDENT_POST_SUFFIXES = ("/adjudicate", "/status", "/reanalyze")
ALERT_ROUTE_ID_PATTERN = re.compile(r"[A-Za-z0-9._:@=-]{1,256}")
INCIDENT_ROUTE_ID_PATTERN = re.compile(r"ir-[a-z0-9_-]{1,64}", re.IGNORECASE)


def configure_runtime_paths(dashboard_root: Path) -> None:
    """Point legacy SOC helpers at Onion Sentinel-owned runtime paths."""
    root = dashboard_root.expanduser().resolve()
    runtime.SOC_ALERT_DASHBOARD_DIR = root
    runtime.SOC_ALERT_DETAIL_DIR = root / "details"
    runtime.SOC_ALERT_STATIC_STATUS_FILE = root / "soc-alerts-status.json"
    runtime.SOC_ALERT_N8N_BEACON_FILE = root / "n8n-beacon.json"
    runtime.SOC_ALERT_N8N_BEACON_HISTORY_FILE = root / "n8n-beacon-history.json"
    runtime.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE = root / "pcap-workflow-state.json"
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


def _dynamic_route_identifier(path: str, prefix: str, suffix: str = "") -> str | None:
    """Return one decoded resource identifier only for an exact dynamic route."""
    if not path.startswith(prefix):
        return None
    remainder = path[len(prefix):]
    if suffix:
        if not remainder.endswith(suffix):
            return None
        remainder = remainder[:-len(suffix)]
    if not remainder or "/" in remainder:
        return None
    identifier = unquote(remainder)
    if not identifier or "/" in identifier or "\\" in identifier:
        return None
    return identifier


def _matches_dynamic_route(
    path: str,
    prefix: str,
    suffix: str,
    identifier_pattern: re.Pattern[str],
) -> bool:
    identifier = _dynamic_route_identifier(path, prefix, suffix)
    return identifier is not None and identifier_pattern.fullmatch(identifier) is not None


def is_soc_get_api(path: str) -> bool:
    if path in GET_API_ROUTES:
        return True
    if any(
        _matches_dynamic_route(
            path,
            "/api/soc-incidents/",
            suffix,
            INCIDENT_ROUTE_ID_PATTERN,
        )
        for suffix in INCIDENT_GET_SUFFIXES
    ):
        return True
    if any(
        _matches_dynamic_route(
            path,
            "/api/soc-alerts/",
            suffix,
            ALERT_ROUTE_ID_PATTERN,
        )
        for suffix in ALERT_GET_SUFFIXES
    ):
        return True
    return _matches_dynamic_route(
        path,
        "/api/soc-alerts/",
        "",
        ALERT_ROUTE_ID_PATTERN,
    )


def is_soc_post_api(path: str) -> bool:
    if path in POST_API_ROUTES:
        return True
    if any(
        _matches_dynamic_route(
            path,
            "/api/soc-alerts/",
            suffix,
            ALERT_ROUTE_ID_PATTERN,
        )
        for suffix in ALERT_POST_SUFFIXES
    ):
        return True
    return any(
        _matches_dynamic_route(
            path,
            "/api/soc-incidents/",
            suffix,
            INCIDENT_ROUTE_ID_PATTERN,
        )
        for suffix in INCIDENT_POST_SUFFIXES
    )


def is_controlled_evaluation_dispatch(path: str) -> bool:
    """Allow only the two frozen-cohort queue routes in evaluation mode."""
    return bool(
        re.fullmatch(r"/api/soc-alerts/[a-f0-9]{12}/analyze", path)
        or re.fullmatch(
            r"/api/soc-incidents/ir-[a-z0-9_-]{1,64}/reanalyze",
            path,
            re.IGNORECASE,
        )
    )


def controlled_alert_store_readiness() -> tuple[bool, dict[str, object]]:
    """Verify that the configured downstream is this evaluation's store."""
    origin = urlparse(runtime.SOC_ALERT_STORE_API_URL)
    expected_port = origin.port
    try:
        health = runtime.alert_store_get_json("/health", timeout=1.0)
    except Exception:
        return False, {"status": "unavailable"}
    ready = bool(
        health.get("service") == "onion-sentinel-alert-store"
        and health.get("controlled_evaluation") is True
        and health.get("runtime_mode") == "controlled-evaluation"
        and health.get("release_id") == RUNTIME_RELEASE_ID
        and health.get("listen_host") == "127.0.0.1"
        and health.get("listen_port") == expected_port
        and health.get("accepting_requests") is True
    )
    return ready, {
        "status": "ready" if ready else "identity_mismatch",
        "service": str(health.get("service") or ""),
        "controlled_evaluation": (
            health.get("controlled_evaluation") is True
        ),
        "runtime_mode": str(health.get("runtime_mode") or ""),
        "release_id": str(health.get("release_id") or ""),
        "listen_host": str(health.get("listen_host") or ""),
        "listen_port": health.get("listen_port"),
        "accepting_requests": health.get("accepting_requests") is True,
    }


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
<p>Authenticated. Administration access is enabled for this browser session.</p>
<p><a href="/settings.html">Open Settings</a></p><form method="post" action="/admin/logout">
<input type="hidden" name="token" value="TOKEN"><button type="submit">Sign out</button></form></body></html>"""
    return body.replace("TOKEN", html.escape(runtime.ensure_admin_token())).encode("utf-8")


class OnionSentinelHandler(runtime.PortalHandler):
    server_version = "OnionSentinel/1.0"

    def handle(self) -> None:
        self.application_request_id = uuid.uuid4().hex
        self.application_request_started = time.monotonic()
        super().handle()

    def log_message(self, fmt: str, *args: object) -> None:
        message = fmt % args
        parsed = urlparse(getattr(self, "path", "") or "")
        status_code = 0
        if args:
            try:
                status_code = int(args[1])
            except (IndexError, TypeError, ValueError):
                status_code = 0
        APPLICATION_LOGGER.log(
            "error"
            if status_code >= 500
            else "warning"
            if status_code >= 400
            else "info",
            "http.request.completed",
            request_id=getattr(self, "application_request_id", ""),
            method=getattr(self, "command", ""),
            path=parsed.path[:512],
            status_code=status_code,
            duration_ms=round(
                max(
                    0.0,
                    time.monotonic()
                    - getattr(self, "application_request_started", time.monotonic()),
                )
                * 1000,
                3,
            ),
            remote_address=self.client_address[0],
            message=message,
        )
        super().log_message(fmt, *args)

    def parse_request(self) -> bool:
        """Reject request targets normalized by the standard-library parser.

        ``BaseHTTPRequestHandler`` rewrites a leading ``//`` to ``/`` before
        dispatch. Controlled evaluation authorizes only byte-for-byte route
        shapes, so accepting that rewrite would let an alternate raw target
        reach an allowlisted handler.
        """
        accepted = super().parse_request()
        if not accepted or not CONTROLLED_EVALUATION_MODE:
            return accepted
        fields = self.requestline.split()
        raw_target = fields[1] if len(fields) >= 2 else ""
        if raw_target == self.path:
            return True
        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in self._security_headers().items():
            self.send_header(key, value)
        self.end_headers()
        return False

    def _soc_settings_write_authorized(self) -> bool:
        """Allow Settings saves until the dedicated service ships its sign-in UI.

        This override is intentionally limited to the port 8766 service. Its
        ``do_POST`` validates JSON and same-origin browser metadata before
        delegating to the shared route implementation. Administration actions
        continue to use the inherited session checks.
        """
        return True

    def _cti_program_mutation_audit(self, program: dict[str, object]) -> None:
        """Record CTI governance changes without logging source content."""
        sources = program.get("sources") if isinstance(program.get("sources"), list) else []
        technologies = (
            program.get("technologies")
            if isinstance(program.get("technologies"), list)
            else []
        )
        APPLICATION_LOGGER.log(
            "info",
            "cti.program.updated",
            request_id=getattr(self, "application_request_id", ""),
            remote_address=self.client_address[0],
            revision=int(program.get("revision") or 0),
            source_count=len(sources),
            enabled_source_count=sum(
                1 for source in sources
                if isinstance(source, dict) and source.get("enabled") is True
            ),
            technology_count=len(technologies),
            enabled_technology_count=sum(
                1 for technology in technologies
                if isinstance(technology, dict) and technology.get("enabled") is True
            ),
            digest=runtime.cti_program.program_digest(program),
        )

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
        parsed = urlparse(self.path)
        path = parsed.path
        if (
            CONTROLLED_EVALUATION_MODE
            and self.path != "/healthz"
        ):
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            return
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
        if (
            CONTROLLED_EVALUATION_MODE
            and self.path != "/healthz"
        ):
            return self._send(
                HTTPStatus.FORBIDDEN,
                json.dumps(
                    {
                        "ok": False,
                        "error": (
                            "route is disabled in controlled evaluation mode"
                        ),
                    }
                ).encode(),
                "application/json; charset=utf-8",
            )
        if path == "/healthz":
            alert_store_ready = runtime.SOC_ALERT_STORE_DB.is_file()
            alert_store_health: dict[str, object] = {
                "status": (
                    "local_database_ready"
                    if alert_store_ready
                    else "local_database_missing"
                ),
            }
            if CONTROLLED_EVALUATION_MODE:
                (
                    downstream_ready,
                    alert_store_health,
                ) = controlled_alert_store_readiness()
                alert_store_ready = (
                    alert_store_ready and downstream_ready
                )
            data = {
                "ok": (
                    (self.dashboard_root / "index.html").is_file()
                    and alert_store_ready
                ),
                "service": "onion-sentinel",
                "controlled_evaluation": CONTROLLED_EVALUATION_MODE,
                "release_id": RUNTIME_RELEASE_ID or "unversioned",
                "listen_host": self.server.server_address[0],  # type: ignore[attr-defined]
                "listen_port": self.server.server_address[1],  # type: ignore[attr-defined]
                "alert_store_origin": runtime.SOC_ALERT_STORE_API_URL,
                "dispatch_route_patterns": (
                    list(CONTROLLED_EVALUATION_DISPATCH_ROUTES)
                    if CONTROLLED_EVALUATION_MODE
                    else []
                ),
                "dashboard_ready": (self.dashboard_root / "index.html").is_file(),
                "alert_store_ready": alert_store_ready,
                "alert_store_health": alert_store_health,
                "time": runtime.now_iso_local(),
                "http_runtime": self.server.runtime_snapshot(),  # type: ignore[attr-defined]
            }
            status = HTTPStatus.OK if data["ok"] else HTTPStatus.SERVICE_UNAVAILABLE
            return self._send(status, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
        if path == "/api/ac-hunter/deep-review":
            status, data = ac_hunter_review.deep_review_response(
                force_refresh=False
            )
            return self._send(
                status,
                json.dumps(data, indent=2).encode(),
                "application/json; charset=utf-8",
            )
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
        if (
            CONTROLLED_EVALUATION_MODE
            and (
                not is_controlled_evaluation_dispatch(path)
                or self.path != path
            )
        ):
            return self._send(
                HTTPStatus.FORBIDDEN,
                json.dumps(
                    {
                        "ok": False,
                        "error": (
                            "route is disabled in controlled evaluation mode"
                        ),
                    }
                ).encode(),
                "application/json; charset=utf-8",
            )
        if CONTROLLED_EVALUATION_MODE and not hmac.compare_digest(
            str(
                self.headers.get(
                    "X-Onion-Sentinel-Evaluation-Token",
                    "",
                )
            ),
            CONTROLLED_EVALUATION_TOKEN,
        ):
            self.close_connection = True
            return self._send(
                HTTPStatus.FORBIDDEN,
                json.dumps(
                    {
                        "ok": False,
                        "error": (
                            "controlled evaluation authorization failed"
                        ),
                    }
                ).encode(),
                "application/json; charset=utf-8",
            )
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
            if path == "/api/ac-hunter/refresh":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length <= 0 or length > 1024:
                    return self._send(
                        HTTPStatus.BAD_REQUEST,
                        json.dumps(
                            {
                                "ok": False,
                                "error": "Invalid AC Hunter refresh request size.",
                            }
                        ).encode(),
                        "application/json; charset=utf-8",
                    )
                try:
                    payload = json.loads(
                        self.rfile.read(length).decode(
                            "utf-8",
                            errors="strict",
                        )
                    )
                except (UnicodeDecodeError, json.JSONDecodeError):
                    payload = None
                if not isinstance(payload, dict) or payload:
                    return self._send(
                        HTTPStatus.BAD_REQUEST,
                        json.dumps(
                            {
                                "ok": False,
                                "error": (
                                    "AC Hunter refresh requires an empty "
                                    "JSON object."
                                ),
                            }
                        ).encode(),
                        "application/json; charset=utf-8",
                    )
                status, data = ac_hunter_review.deep_review_response(
                    force_refresh=False
                )
                return self._send(
                    status,
                    json.dumps(data, indent=2).encode(),
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

    def handle_error(self, request: object, client_address: object) -> None:
        APPLICATION_LOGGER.log(
            "error",
            "http.request.unhandled_exception",
            remote_address=(
                client_address[0]
                if isinstance(client_address, tuple) and client_address
                else ""
            ),
        )
        super().handle_error(request, client_address)


def main() -> None:
    parser = argparse.ArgumentParser(description="Dedicated Onion Sentinel web service")
    parser.add_argument("--host", default=os.environ.get("ONION_SENTINEL_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ONION_SENTINEL_PORT", DEFAULT_PORT)))
    parser.add_argument("--dashboard-root", type=Path, default=Path(os.environ.get("ONION_SENTINEL_DASHBOARD_ROOT", DEFAULT_DASHBOARD_ROOT)))
    parser.add_argument("--max-active-requests", type=int, default=int(os.environ.get("ONION_SENTINEL_MAX_ACTIVE_REQUESTS", "96")))
    parser.add_argument("--request-timeout-seconds", type=float, default=float(os.environ.get("ONION_SENTINEL_REQUEST_TIMEOUT_SECONDS", "30")))
    args = parser.parse_args()
    if CONTROLLED_EVALUATION_MODE:
        dashboard_root = args.dashboard_root.expanduser()
        try:
            dashboard_metadata = dashboard_root.lstat()
            resolved_dashboard_root = dashboard_root.resolve(strict=True)
        except OSError as exc:
            raise SystemExit(
                f"controlled evaluation dashboard root is unsafe: {exc}"
            ) from exc
        alert_store_origin = urlparse(runtime.SOC_ALERT_STORE_API_URL)
        if (
            args.host != "127.0.0.1"
            or not 1024 <= args.port <= 65535
            or args.port == DEFAULT_PORT
            or not re.fullmatch(r"[a-f0-9]{40}", RUNTIME_RELEASE_ID)
            or not re.fullmatch(
                r"[a-f0-9]{64}",
                CONTROLLED_EVALUATION_TOKEN,
            )
            or not dashboard_root.is_absolute()
            or resolved_dashboard_root != dashboard_root
            or dashboard_root.is_symlink()
            or not dashboard_root.is_dir()
            or (
                hasattr(os, "getuid")
                and dashboard_metadata.st_uid != os.getuid()
            )
            or dashboard_metadata.st_mode & 0o022
            or alert_store_origin.scheme != "http"
            or alert_store_origin.hostname != "127.0.0.1"
            or alert_store_origin.port is None
            or alert_store_origin.port == 8787
            or alert_store_origin.username is not None
            or alert_store_origin.password is not None
            or alert_store_origin.path not in {"", "/"}
            or alert_store_origin.params
            or alert_store_origin.query
            or alert_store_origin.fragment
        ):
            raise SystemExit(
                "controlled evaluation requires owner-only runtime content, "
                "loopback listeners, and an exact release ID"
            )
    configure_runtime_paths(args.dashboard_root)
    if not CONTROLLED_EVALUATION_MODE:
        args.dashboard_root.mkdir(parents=True, exist_ok=True)
    server = OnionSentinelHTTPServer(
        (args.host, args.port),
        args.dashboard_root,
        max_active_requests=args.max_active_requests,
        request_timeout_seconds=args.request_timeout_seconds,
    )
    APPLICATION_LOGGER.log(
        "info",
        "service.ready",
        release_id=RUNTIME_RELEASE_ID or "unversioned",
        listen_host=args.host,
        listen_port=args.port,
        dashboard_root=str(args.dashboard_root),
        controlled_evaluation=CONTROLLED_EVALUATION_MODE,
    )
    print(f"Onion Sentinel listening on http://{runtime.local_ip()}:{args.port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
