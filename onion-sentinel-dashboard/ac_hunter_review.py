#!/usr/bin/env python3
"""Relay-only AC Hunter collection and PostgreSQL-backed triage reads.

The scheduled collector uses the source-restricted, forced-command SSH path to
submit named operations to the Relay.  The Relay is the only component that can
contact AC Hunter.  Public web routes call :func:`deep_review_response`, which
reads the latest normalized snapshot from the loopback alert-store API and can
never initiate a Relay or AC Hunter request.

Authentication cookies and JWTs exist only in the scheduled collector process.
PostgreSQL contains normalized analyst-facing findings and never raw
authentication responses, credentials, cookies, tokens, or arbitrary AC
Hunter response bodies.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import html.parser
import importlib.util
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


CONFIG_SCHEMA = "onion-sentinel-ac-hunter-client-config-v1"
CREDENTIALS_SCHEMA = "onion-sentinel-ac-hunter-credentials-v1"
REVIEW_SCHEMA = "onion-sentinel-ac-hunter-review-v1"
REVIEW_VERSION = 1
FIXED_DATASET = "security-onion-rolling"
FIXED_RELAY_HOST = "10.88.8.8"
FIXED_RELAY_USER = "aj"
FIXED_RELAY_PORT = 22
DEFAULT_CONFIG = Path.home() / "n8n-local" / "config" / "ac-hunter.json"
DEFAULT_CACHE = (
    Path.home()
    / "n8n-local"
    / "cache"
    / "ac-hunter-deep-review.json"
)
DEFAULT_DATABASE_API_URL = "http://127.0.0.1:8787/ac-hunter/snapshot"
MAX_CONFIG_BYTES = 64 * 1024
MAX_CREDENTIAL_BYTES = 16 * 1024
MAX_CACHE_BYTES = 32 * 1024 * 1024
MAX_KEY_BYTES = 1024 * 1024
MAX_KNOWN_HOSTS_BYTES = 1024 * 1024
MAX_RELAY_STDERR_BYTES = 128 * 1024
MAX_FINDINGS_PER_MODULE = 100
MAX_TEXT = 2048
JWT_REFRESH_SKEW_SECONDS = 45
MIN_FORCE_REFRESH_INTERVAL_SECONDS = 300

VERDICT_ORDER = {
    "Informational": 0,
    "Likely benign": 1,
    "Needs review": 2,
    "High concern": 3,
}
MODULE_KEYS = (
    "beacons",
    "beacons_sni",
    "beacons_proxy",
    "long_connections",
    "dns_anomalies",
    "unexpected_ports",
    "blacklist",
    "strobe",
)
FORBIDDEN_CACHE_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "csrf",
    "csrf_token",
    "email",
    "jwt",
    "password",
    "session",
    "set_cookie",
    "token",
}


class AcHunterError(RuntimeError):
    """A sanitized AC Hunter integration failure."""


class AcHunterConfigurationError(AcHunterError):
    """The local trust or configuration boundary is invalid."""


class AcHunterAuthenticationError(AcHunterError):
    """AC Hunter did not accept or refresh the service identity."""


class AcHunterTransportError(AcHunterError):
    """The forced-command Relay transport failed."""


def _utc_iso(epoch: Optional[float] = None) -> str:
    value = time.time() if epoch is None else float(epoch)
    return (
        dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: object) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000.0
        return number if 0 < number < 100_000_000_000 else None
    text = str(value or "").strip()
    if not text or len(text) > 80:
        return None
    if text.isdigit():
        return _parse_timestamp(int(text))
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def _safe_error(value: object, fallback: str = "AC Hunter request failed") -> str:
    text = " ".join(
        "".join(
            character if character.isprintable() else " "
            for character in str(value or "")
        ).split()
    )
    if not text:
        return fallback
    lowered = text.lower()
    if any(
        marker in lowered
        for marker in ("bearer ", "password", "set-cookie", "session=", "csrf")
    ):
        return fallback
    return text[:400]


def _safe_text(value: object, maximum: int = MAX_TEXT) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return ""
    text = " ".join(
        "".join(
            character if character.isprintable() else " "
            for character in str(value)
        ).split()
    )
    return text[:maximum]


def _bounded_int(
    value: object,
    *,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AcHunterConfigurationError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise AcHunterConfigurationError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return value


def _secure_file_bytes(
    path: Path,
    *,
    maximum_bytes: int,
    exact_mode: int = 0o600,
    allow_empty: bool = False,
) -> bytes:
    """Read a same-UID regular file without following symlinks."""

    try:
        before = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise AcHunterConfigurationError(
            f"AC Hunter trust file is unavailable: {path.name}"
        ) from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != exact_mode
        or (not allow_empty and before.st_size <= 0)
        or before.st_size > maximum_bytes
    ):
        raise AcHunterConfigurationError(
            f"AC Hunter trust file failed owner-only validation: {path.name}"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_uid != before.st_uid
                or opened.st_size != before.st_size
                or stat.S_IMODE(opened.st_mode) != exact_mode
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise AcHunterConfigurationError(
                    f"AC Hunter trust file changed while opening: {path.name}"
                )
            chunks: List[bytes] = []
            remaining = maximum_bytes + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(descriptor)
    except AcHunterConfigurationError:
        raise
    except OSError as exc:
        raise AcHunterConfigurationError(
            f"AC Hunter trust file could not be read: {path.name}"
        ) from exc
    if len(raw) > maximum_bytes:
        raise AcHunterConfigurationError(
            f"AC Hunter trust file exceeds its byte limit: {path.name}"
        )
    return raw


def _private_json(path: Path, maximum_bytes: int) -> Dict[str, Any]:
    raw = _secure_file_bytes(path, maximum_bytes=maximum_bytes)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcHunterConfigurationError(
            f"AC Hunter JSON file is invalid: {path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise AcHunterConfigurationError(
            f"AC Hunter JSON file must be an object: {path.name}"
        )
    return value


def _configured_path(value: object, label: str) -> Path:
    text = str(value or "")
    if (
        not text
        or len(text) > 2048
        or "\x00" in text
        or "\r" in text
        or "\n" in text
    ):
        raise AcHunterConfigurationError(f"{label} is invalid")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise AcHunterConfigurationError(f"{label} must be absolute")
    return path


def load_config(path: Path = DEFAULT_CONFIG) -> Dict[str, Any]:
    """Load and validate the owner-only Mac-side client configuration."""

    source = _private_json(path, MAX_CONFIG_BYTES)
    allowed = {
        "schema",
        "enabled",
        "dataset",
        "relay_host",
        "relay_user",
        "relay_port",
        "ssh_key",
        "known_hosts",
        "credentials_file",
        "cache_file",
        "cache_ttl_seconds",
        "connect_timeout_seconds",
        "timeout_seconds",
        "max_response_bytes",
        "max_stderr_bytes",
    }
    if set(source) - allowed or source.get("schema") != CONFIG_SCHEMA:
        raise AcHunterConfigurationError(
            "AC Hunter client configuration schema is unsupported"
        )
    if not isinstance(source.get("enabled"), bool):
        raise AcHunterConfigurationError("AC Hunter enabled must be boolean")
    if source.get("dataset") != FIXED_DATASET:
        raise AcHunterConfigurationError(
            "AC Hunter dataset is outside the fixed allowlist"
        )
    if source.get("relay_host") != FIXED_RELAY_HOST:
        raise AcHunterConfigurationError(
            "AC Hunter Relay host is outside the fixed allowlist"
        )
    if source.get("relay_user") != FIXED_RELAY_USER:
        raise AcHunterConfigurationError(
            "AC Hunter Relay user is outside the fixed allowlist"
        )
    relay_port = _bounded_int(
        source.get("relay_port", FIXED_RELAY_PORT),
        minimum=FIXED_RELAY_PORT,
        maximum=FIXED_RELAY_PORT,
        label="AC Hunter Relay port",
    )
    normalized: Dict[str, Any] = {
        "schema": CONFIG_SCHEMA,
        "enabled": source["enabled"],
        "dataset": FIXED_DATASET,
        "relay_host": FIXED_RELAY_HOST,
        "relay_user": FIXED_RELAY_USER,
        "relay_port": relay_port,
        "ssh_key": _configured_path(source.get("ssh_key"), "AC Hunter SSH key"),
        "known_hosts": _configured_path(
            source.get("known_hosts"), "AC Hunter known_hosts"
        ),
        "credentials_file": _configured_path(
            source.get("credentials_file"), "AC Hunter credentials file"
        ),
        "cache_file": _configured_path(
            source.get("cache_file"), "AC Hunter cache file"
        ),
    }
    configured_cache = Path(
        os.path.abspath(str(normalized["cache_file"]))
    )
    expected_cache = Path(os.path.abspath(str(DEFAULT_CACHE)))
    if configured_cache != expected_cache:
        raise AcHunterConfigurationError(
            "AC Hunter cache path is outside the fixed runtime location"
        )
    protected_paths = (
        Path(path).expanduser(),
        normalized["ssh_key"],
        normalized["known_hosts"],
        normalized["credentials_file"],
        normalized["cache_file"],
    )
    resolved_paths = [
        candidate.resolve(strict=False) for candidate in protected_paths
    ]
    if len(set(resolved_paths)) != len(resolved_paths):
        raise AcHunterConfigurationError(
            "AC Hunter configuration, trust, credential, and cache paths "
            "must be distinct"
        )
    for key, default, minimum, maximum in (
        ("cache_ttl_seconds", 300, 30, 3600),
        ("connect_timeout_seconds", 8, 1, 15),
        ("timeout_seconds", 45, 5, 120),
        ("max_response_bytes", 8 * 1024 * 1024, 1024, 8 * 1024 * 1024),
        ("max_stderr_bytes", MAX_RELAY_STDERR_BYTES, 1024, MAX_RELAY_STDERR_BYTES),
    ):
        normalized[key] = _bounded_int(
            source.get(key, default),
            minimum=minimum,
            maximum=maximum,
            label=f"AC Hunter {key}",
        )
    if normalized["enabled"]:
        _secure_file_bytes(
            normalized["ssh_key"], maximum_bytes=MAX_KEY_BYTES
        )
        _secure_file_bytes(
            normalized["known_hosts"], maximum_bytes=MAX_KNOWN_HOSTS_BYTES
        )
        load_credentials(normalized["credentials_file"])
    return normalized


def load_credentials(path: Path) -> Tuple[str, str]:
    source = _private_json(path, MAX_CREDENTIAL_BYTES)
    if (
        set(source) != {"schema", "email", "password"}
        or source.get("schema") != CREDENTIALS_SCHEMA
    ):
        raise AcHunterConfigurationError(
            "AC Hunter credentials schema is unsupported"
        )
    email = str(source.get("email") or "")
    password = str(source.get("password") or "")
    if (
        not re.fullmatch(r"[^@\s]{1,128}@[^@\s]{1,190}", email)
        or not password
        or len(password.encode("utf-8")) > 1024
        or any(character in password for character in ("\r", "\n", "\x00"))
    ):
        raise AcHunterConfigurationError("AC Hunter service credentials are invalid")
    return email, password


def _dependency(name: str) -> ModuleType:
    """Load a repository/runtime helper without requiring global sys.path edits."""

    module_path = Path(__file__).resolve()
    candidates = (
        module_path.parent.parent / "n8n" / "bin" / f"{name}.py",
        module_path.parent.parent / "bin" / f"{name}.py",
    )
    for candidate in candidates:
        if not candidate.is_file():
            continue
        module_name = f"_onion_sentinel_{name}"
        existing = sys.modules.get(module_name)
        if isinstance(existing, ModuleType):
            return existing
        spec = importlib.util.spec_from_file_location(
            module_name, candidate
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(module_name, None)
            raise
        return module
    raise AcHunterConfigurationError(
        f"required Onion Sentinel helper is unavailable: {name}"
    )


def _relay_diagnostic(stdout: object, stderr: object) -> str:
    """Return only broker-authored, non-sensitive diagnostics."""

    message = ""
    try:
        value = json.loads(str(stdout or ""))
    except (TypeError, json.JSONDecodeError):
        value = None
    if isinstance(value, dict):
        message = _safe_error(value.get("error"), "")
    if not message:
        message = _safe_error(stderr, "")
    return message or "the forced AC Hunter Relay request failed"


class RelayTransport:
    """One fixed forced-command SSH transport to 10.88.8.8."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        runner: Optional[Callable[..., Any]] = None,
        contract: Optional[ModuleType] = None,
    ) -> None:
        self.config = dict(config)
        self.contract = contract or _dependency("ac_hunter_contract")
        if runner is None:
            runner = _dependency("bounded_process").run_bounded_command
        self.runner = runner

    def command(self) -> List[str]:
        return [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            f"UserKnownHostsFile={self.config['known_hosts']}",
            "-o",
            f"ConnectTimeout={self.config['connect_timeout_seconds']}",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "LogLevel=ERROR",
            "-i",
            str(self.config["ssh_key"]),
            "-p",
            str(self.config["relay_port"]),
            f"{FIXED_RELAY_USER}@{FIXED_RELAY_HOST}",
        ]

    def call(
        self,
        operation: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        request_id = self.contract.new_request_id()
        request = {
            "contract": self.contract.CONTRACT,
            "request_id": request_id,
            "operation": operation,
            "params": dict(params or {}),
            "headers": dict(headers or {}),
            "body": dict(body or {}),
        }
        # Compile locally as well as on the Relay.  This ensures a caller can
        # never turn a named operation into a URL, hostname, method, or path.
        self.contract.compile_request(request)
        stdin_text = json.dumps(request, separators=(",", ":"), sort_keys=True)
        completed = self.runner(
            self.command(),
            stdin_text=stdin_text,
            timeout_seconds=float(self.config["timeout_seconds"]),
            max_stdout_bytes=int(self.config["max_response_bytes"]),
            max_stderr_bytes=int(self.config["max_stderr_bytes"]),
        )
        try:
            value = json.loads(str(completed.stdout or ""))
            response = self.contract.validate_relay_response(value, request_id)
        except Exception as exc:
            raise AcHunterTransportError(
                "the forced AC Hunter Relay returned an invalid response"
            ) from exc
        if completed.returncode != 0 and int(response.get("status", 0)) == 0:
            raise AcHunterTransportError(
                _relay_diagnostic(completed.stdout, completed.stderr)
            )
        return response


class _CsrfParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.token = ""

    def handle_starttag(
        self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]
    ) -> None:
        if tag.lower() != "input" or self.token:
            return
        values = {key.lower(): value or "" for key, value in attrs}
        if values.get("name") == "csrf_token":
            self.token = values.get("value", "")[:1024]


class AcHunterApiClient:
    """Stateful cookie/JWT client whose only I/O path is RelayTransport."""

    def __init__(
        self,
        transport: Any,
        credentials_loader: Callable[[], Tuple[str, str]],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.transport = transport
        self.credentials_loader = credentials_loader
        self.clock = clock
        self._cookies: Dict[str, str] = {}
        self._jwt = ""
        self._jwt_expiry = 0.0
        self._auth_lock = threading.RLock()

    def _cookie_header(self) -> str:
        return "; ".join(
            f"{name}={value}" for name, value in sorted(self._cookies.items())
        )

    def _accept_cookies(self, response: Mapping[str, Any]) -> None:
        response_headers = response.get("headers")
        if not isinstance(response_headers, dict):
            return
        raw_values = response_headers.get("set_cookie", [])
        if not isinstance(raw_values, list):
            return
        for raw in raw_values:
            if not isinstance(raw, str):
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(raw)
            except Exception:
                continue
            for name, morsel in parsed.items():
                if (
                    re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
                    and len(morsel.value.encode("utf-8")) <= 4096
                    and not any(
                        character in morsel.value
                        for character in ("\r", "\n", "\x00", ";")
                    )
                ):
                    if morsel.value:
                        self._cookies[name] = morsel.value
                    else:
                        self._cookies.pop(name, None)
        if len(self._cookies) > 16:
            self._cookies = dict(sorted(self._cookies.items())[:16])

    @staticmethod
    def _token_expiry(token: str) -> float:
        parts = token.split(".")
        if len(parts) != 3:
            raise AcHunterAuthenticationError("AC Hunter returned an invalid JWT")
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            payload = json.loads(
                base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8")
            )
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcHunterAuthenticationError(
                "AC Hunter returned an invalid JWT"
            ) from exc
        expiry = payload.get("exp") if isinstance(payload, dict) else None
        if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
            raise AcHunterAuthenticationError("AC Hunter JWT has no valid expiry")
        return float(expiry)

    @staticmethod
    def _success(
        response: Mapping[str, Any],
        statuses: Iterable[int] = (200,),
    ) -> bool:
        return response.get("ok") is True and response.get("status") in set(statuses)

    def _authenticate(self) -> None:
        with self._auth_lock:
            if (
                self._jwt
                and self._jwt_expiry
                > self.clock() + JWT_REFRESH_SKEW_SECONDS
            ):
                return
            self._jwt = ""
            self._jwt_expiry = 0.0
            self._cookies.clear()

            form = self.transport.call("login_form")
            self._accept_cookies(form)
            if not self._success(form):
                raise AcHunterAuthenticationError(
                    "AC Hunter login form was unavailable"
                )
            parser = _CsrfParser()
            raw_html = form.get("body")
            if isinstance(raw_html, str):
                try:
                    parser.feed(raw_html)
                except Exception:
                    parser.token = ""

            email, password = self.credentials_loader()
            login_headers: Dict[str, str] = {}
            cookie = self._cookie_header()
            if cookie:
                login_headers["cookie"] = cookie
            login = self.transport.call(
                "login",
                headers=login_headers,
                body={
                    "email": email,
                    "password": password,
                    "csrf_token": parser.token,
                    "next": "/jwt/json",
                    "remember": False,
                },
            )
            # Drop the only local references to the credential strings as soon
            # as the bounded relay invocation has returned.
            del email
            del password
            self._accept_cookies(login)
            if not self._success(login, (302, 303)):
                raise AcHunterAuthenticationError(
                    "AC Hunter service-account login failed"
                )

            jwt_headers: Dict[str, str] = {}
            cookie = self._cookie_header()
            if cookie:
                jwt_headers["cookie"] = cookie
            token_response = self.transport.call("jwt", headers=jwt_headers)
            self._accept_cookies(token_response)
            if not self._success(token_response):
                raise AcHunterAuthenticationError(
                    "AC Hunter JWT issuance failed"
                )
            payload = token_response.get("body")
            token = payload.get("token") if isinstance(payload, dict) else None
            if (
                not isinstance(token, str)
                or not 16 <= len(token) <= 16384
                or not re.fullmatch(r"[A-Za-z0-9._~-]+", token)
            ):
                raise AcHunterAuthenticationError(
                    "AC Hunter JWT issuance returned an invalid token"
                )
            expiry = self._token_expiry(token)
            now = self.clock()
            if expiry <= now + 10 or expiry > now + 15 * 60:
                raise AcHunterAuthenticationError(
                    "AC Hunter JWT expiry is outside the expected window"
                )
            self._jwt = token
            self._jwt_expiry = expiry

    def invalidate_authentication(self) -> None:
        with self._auth_lock:
            self._jwt = ""
            self._jwt_expiry = 0.0
            self._cookies.clear()

    def get(
        self,
        operation: str,
        params: Optional[Mapping[str, Any]] = None,
    ) -> object:
        for attempt in range(2):
            self._authenticate()
            headers = {"authorization": f"Bearer {self._jwt}"}
            cookie = self._cookie_header()
            if cookie:
                headers["cookie"] = cookie
            response = self.transport.call(
                operation,
                params=params or {},
                headers=headers,
            )
            self._accept_cookies(response)
            status = response.get("status")
            if status in {302, 401, 403}:
                self.invalidate_authentication()
                if attempt == 0:
                    continue
                raise AcHunterAuthenticationError(
                    "AC Hunter authentication expired during collection"
                )
            if response.get("ok") is not True or status != 200:
                raise AcHunterTransportError(
                    _safe_error(
                        response.get("error"),
                        f"AC Hunter {operation} request failed",
                    )
                )
            return response.get("body")
        raise AcHunterAuthenticationError(
            "AC Hunter authentication could not be refreshed"
        )


def _first(mapping: object, names: Sequence[str]) -> object:
    if not isinstance(mapping, dict):
        return None
    for name in names:
        current: object = mapping
        found = True
        for component in name.split("."):
            if not isinstance(current, dict) or component not in current:
                found = False
                break
            current = current[component]
        if found and current not in (None, ""):
            return current
    return None


def _rows(value: object, names: Sequence[str] = ()) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value[:MAX_FINDINGS_PER_MODULE] if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    priority = tuple(names) + (
        "data",
        "results",
        "items",
        "rows",
        "records",
        "findings",
        "hosts",
    )
    for key in priority:
        candidate = value.get(key)
        if isinstance(candidate, list):
            return [
                item
                for item in candidate[:MAX_FINDINGS_PER_MODULE]
                if isinstance(item, dict)
            ]
        if isinstance(candidate, dict):
            nested = _rows(candidate, ())
            if nested:
                return nested
    # Some AC Hunter responses are objects keyed by an address/domain.
    converted: List[Dict[str, Any]] = []
    for key, item in list(value.items())[:MAX_FINDINGS_PER_MODULE]:
        if isinstance(item, dict):
            row = dict(item)
            row.setdefault("host", key)
            converted.append(row)
    return converted


def _number(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        result = float(value)
        return result if result == result and abs(result) != float("inf") else default
    text = str(value or "").strip().replace(",", "")
    try:
        result = float(text)
    except ValueError:
        return default
    return result if result == result and abs(result) != float("inf") else default


def _integer_value(value: object) -> int:
    if isinstance(value, (list, tuple, set)):
        return len(value)
    if isinstance(value, dict):
        candidate = _first(value, ("count", "value", "base", "points", "total"))
        if candidate is value:
            return 0
        return _integer_value(candidate)
    return max(0, int(_number(value, 0)))


def _duration_seconds(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, float(value))
    text = str(value or "").strip()
    if not text:
        return 0.0
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return max(0.0, float(text))
    match = re.fullmatch(
        r"(?:(\d+)\s*d(?:ays?)?\s*)?(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)",
        text,
        re.IGNORECASE,
    )
    if not match:
        return 0.0
    days, hours, minutes, seconds = match.groups()
    return (
        int(days or 0) * 86400
        + int(hours or 0) * 3600
        + int(minutes or 0) * 60
        + float(seconds)
    )


def _ip(value: object) -> str:
    text = _safe_text(value, 128)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _is_internal(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private


def _string_list(value: object, maximum: int = 20) -> List[str]:
    if isinstance(value, str):
        candidates: Sequence[object] = re.split(r"[,;\s]+", value)
    elif isinstance(value, (list, tuple, set)):
        candidates = list(value)
    else:
        return []
    result: List[str] = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            candidate = _first(
                candidate,
                ("ip", "address", "host", "fqdn", "domain", "value"),
            )
        text = _safe_text(candidate, 256)
        if text and text not in result:
            result.append(text)
        if len(result) >= maximum:
            break
    return result


def _finding_id(module: str, values: Mapping[str, object]) -> str:
    canonical = json.dumps(
        [module, values.get("source_ip"), values.get("destination_ip"),
         values.get("fqdn"), values.get("port"), values.get("protocol")],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]


def _normalize_finding(module: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    source = _ip(
        _first(
            row,
            (
                "source_ip",
                "src_ip",
                "src",
                "source",
                "orig_h",
                "id.orig_h",
                "source.address",
                "client_ip",
            ),
        )
    )
    destination = _ip(
        _first(
            row,
            (
                "destination_ip",
                "dst_ip",
                "dst",
                "destination",
                "resp_h",
                "id.resp_h",
                "destination.address",
                "server_ip",
                "host",
            ),
        )
    )
    fqdn = _safe_text(
        _first(
            row,
            (
                "fqdn",
                "domain",
                "dst_fqdn",
                "destination_fqdn",
                "server_name",
                "sni",
                "hostname",
                "ptr",
                "reverse_dns",
                "queried_fqdn",
            ),
        ),
        512,
    )
    if not fqdn:
        queried = _string_list(_first(row, ("queried_fqdns",)))
        fqdn = queried[0] if queried else ""
    responding_ips = [
        item for item in (_ip(value) for value in _string_list(
            _first(row, ("responding_ips", "resolved_ips", "dst_ips", "answers"))
        )) if item
    ]
    if module == "blacklist":
        host = _ip(_first(row, ("host", "ip", "address")))
        if host:
            if _is_internal(host):
                source = source or host
            else:
                destination = destination or host
    if module == "dns_anomalies" and not source:
        query_rows = _first(row, ("queries", "directs", "clients"))
        if isinstance(query_rows, list):
            for query in query_rows:
                candidate = _ip(_first(query, ("ip", "source_ip", "src")))
                if candidate:
                    source = candidate
                    break
    score = _number(
        _first(row, ("score", "beacon_score", "risk_score", "c2_score")),
        0.0,
    )
    count = _integer_value(
        _first(
            row,
            (
                "count",
                "connection_count",
                "connections",
                "conn_count",
                "seen",
                "queries",
                "query_count",
                "subdomains",
                "visited",
            ),
        )
    )
    duration = _duration_seconds(
        _first(
            row,
            (
                "duration",
                "duration_seconds",
                "length",
                "connection_duration",
            ),
        )
    )
    port_value = _first(
        row,
        (
            "port",
            "destination_port",
            "dst_port",
            "resp_p",
            "id.resp_p",
            "service_port",
        ),
    )
    port = _integer_value(port_value)
    if not 0 < port <= 65535:
        port = 0
    protocol = _safe_text(
        _first(row, ("protocol", "proto", "service", "transport")), 64
    ).upper()
    tuples = _first(row, ("tuples",))
    if isinstance(tuples, list) and tuples:
        if not count:
            count = len(tuples)
        first_tuple = tuples[0]
        if isinstance(first_tuple, dict):
            if not port:
                tuple_port = _integer_value(
                    _first(
                        first_tuple,
                        ("port", "destination_port", "dst_port", "resp_p"),
                    )
                )
                if 0 < tuple_port <= 65535:
                    port = tuple_port
            if not protocol:
                protocol = _safe_text(
                    _first(first_tuple, ("protocol", "proto", "transport")), 64
                ).upper()
    timing_mode = _safe_text(
        _first(row, ("timing_mode", "ts_mode", "time_mode", "mode")), 128
    )
    data_size_mode = _safe_text(
        _first(row, ("data_size_mode", "ds_mode", "size_mode")), 128
    )
    evidence = {
        "timing_mode": timing_mode,
        "data_size_mode": data_size_mode,
        "bytes": _integer_value(
            _first(row, ("bytes", "total_bytes", "byte_count"))
        ),
        "network": _safe_text(
            _first(row, ("network_name", "src_network_name")), 256
        ),
        "destination_network": _safe_text(
            _first(row, ("dst_network_name", "destination_network_name")), 256
        ),
        "ptr": _safe_text(
            _first(row, ("ptr", "reverse_dns", "destination_ptr")), 512
        ),
        "open": bool(_first(row, ("open", "is_open")) is True),
    }
    evidence = {key: value for key, value in evidence.items() if value not in ("", 0, False)}
    finding: Dict[str, Any] = {
        "source_ip": source,
        "destination_ip": destination,
        "fqdn": fqdn,
        "module": module,
        "score": round(max(0.0, score), 6),
        "count": count,
        "duration": round(duration, 3),
        "duration_seconds": round(duration, 3),
        "port": port,
        "protocol": protocol,
        "timing_mode": timing_mode,
        "data_size_mode": data_size_mode,
        "responding_ips": responding_ips,
        "evidence": evidence,
    }
    finding["id"] = _finding_id(module, finding)
    return finding


KNOWN_BENIGN_DOMAINS = (
    ("courier.push.apple.com", "Apple push/courier"),
    ("safebrowsing.apple", "Apple Safe Browsing"),
    ("apple.com", "Apple service"),
    ("icloud.com", "Apple service"),
    ("mzstatic.com", "Apple software distribution"),
    ("apple-dns.net", "Apple service"),
    ("push.services.mozilla.com", "Mozilla push/telemetry"),
    ("telemetry.mozilla.org", "Mozilla push/telemetry"),
    ("services.mozilla.com", "Mozilla service"),
    ("docker.com", "Docker service"),
    ("docker.io", "Docker service"),
    ("raw.githubusercontent.com", "GitHub raw content"),
    ("raw.github.com", "GitHub raw content"),
    ("obsidian.md", "Obsidian release service"),
    ("update.code.visualstudio.com", "Visual Studio Code update service"),
    ("vscode.download.prss.microsoft.com", "Visual Studio Code update service"),
    ("artifacts.elastic.co", "Elastic artifact/update service"),
    ("api.telegram.org", "Telegram API"),
    ("spotify.com", "Spotify service"),
    ("oaistatic.com", "OpenAI static/service infrastructure"),
    ("openai.com", "OpenAI service"),
    ("chatgpt.com", "OpenAI ChatGPT service"),
    ("n8n.io", "n8n service"),
    ("brave.com", "Brave browser service/update"),
)
KNOWN_BENIGN_NETWORKS = (
    (ipaddress.ip_network("17.0.0.0/8"), "Apple service network"),
)
GENERIC_INFRASTRUCTURE_MARKERS = (
    "amazonaws",
    "compute.amazonaws",
    "ec2-",
    "cloudfront",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "azure",
    "cloudapp",
    "googleusercontent",
    "vps",
)


def _known_benign_explanation(finding: Mapping[str, Any]) -> str:
    evidence = finding.get("evidence")
    ptr = (
        _safe_text(evidence.get("ptr"), 512)
        if isinstance(evidence, dict)
        else ""
    )
    for raw_hostname in (
        _safe_text(finding.get("fqdn"), 512),
        ptr,
    ):
        hostname = raw_hostname.strip().lower().rstrip(".")
        if not re.fullmatch(
            r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
            hostname,
        ):
            continue
        for domain, explanation in KNOWN_BENIGN_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return explanation
    destination = _safe_text(finding.get("destination_ip"), 128)
    try:
        destination_address = ipaddress.ip_address(destination)
    except ValueError:
        destination_address = None
    if destination_address is not None:
        for network, explanation in KNOWN_BENIGN_NETWORKS:
            if destination_address in network:
                return explanation
    port = _integer_value(finding.get("port"))
    protocol = _safe_text(finding.get("protocol"), 32).upper()
    if port == 123 and protocol in {"", "UDP", "NTP"}:
        return "expected NTP pool traffic"
    if port == 5228:
        return "common Google/Android push port"
    if port == 4070:
        return "common Spotify service port"
    return ""


def _score_finding(
    finding: Dict[str, Any],
    module_count: int,
    rare_signature_count: int = 0,
) -> Dict[str, Any]:
    """Apply deterministic behavioral priority; never infer malware."""

    points = 0
    reasons: List[str] = []
    module = str(finding.get("module") or "")
    score = _number(finding.get("score"), 0.0)
    duration = _number(finding.get("duration_seconds"), 0.0)
    fqdn = _safe_text(finding.get("fqdn"), 512)
    source = _safe_text(finding.get("source_ip"), 128)
    destination = _safe_text(finding.get("destination_ip"), 128)
    port = _integer_value(finding.get("port"))
    protocol = _safe_text(finding.get("protocol"), 64)
    searchable = (
        fqdn
        + " "
        + json.dumps(finding.get("evidence", {}), sort_keys=True)
    ).lower()
    benign = _known_benign_explanation(finding)
    generic_infrastructure = any(
        marker in searchable for marker in GENERIC_INFRASTRUCTURE_MARKERS
    )

    if module == "blacklist":
        points += 70
        reasons.append("AC Hunter reported a blacklist match")
    if module == "strobe":
        points += 55
        reasons.append("AC Hunter reported strobe/scanning behavior")
    if score >= 0.95:
        points += 35
        reasons.append(f"high AC Hunter behavioral score ({score:.3f})")
    elif score >= 0.80:
        points += 22
        reasons.append(f"elevated AC Hunter behavioral score ({score:.3f})")
    elif score >= 0.50:
        points += 12
        reasons.append(f"AC Hunter behavioral score met the review threshold ({score:.3f})")
    if not fqdn and module in {
        "beacons",
        "beacons_sni",
        "beacons_proxy",
        "long_connections",
        "unexpected_ports",
    }:
        points += 12
        reasons.append("no FQDN/SNI/DNS explanation was present")
    if generic_infrastructure:
        points += 12
        reasons.append("destination context is generic cloud/VPS infrastructure")
    elif (fqdn or destination) and not benign:
        points += 8
        reasons.append(
            "destination was not recognized as a common vendor, update, "
            "push, or other expected service"
        )
    if module == "unexpected_ports":
        points += 25
        reasons.append("protocol/port behavior was unexpected")
    if duration >= 18_000:
        points += 20
        reasons.append(f"connection lasted {duration / 3600:.1f} hours")
    if module_count > 1:
        added = min(30, (module_count - 1) * 10)
        points += added
        reasons.append(f"source appeared across {module_count} AC Hunter modules")
    if rare_signature_count >= 10:
        points += 10
        reasons.append(
            f"source was associated with {rare_signature_count} rare client-signature observations"
        )

    watch_one = (
        source == "10.66.6.209"
        and destination == "208.70.182.48"
        and port == 1610
        and protocol
        in {
            "",
            "TCP",
            "TLS",
            "SSL",
            "UNKNOWN",
            "TLS/UNKNOWN",
            "SSL/UNKNOWN",
        }
        and not fqdn
    )
    watch_two = (
        source == "10.100.4.245"
        and destination == "98.84.79.102"
        and port == 443
        and duration >= 18_000
    )
    if watch_one:
        points = max(points, 40)
        reasons.append(
            "environment watch: TCP/1610 TLS/unknown traffic to 208.70.182.48 lacks FQDN context"
        )
    if watch_two:
        points = max(points, 40)
        reasons.append(
            "environment watch: very long TCP/443 connection to a generic AWS destination"
        )

    hard_signal = module in {"blacklist", "strobe"} or watch_one or watch_two
    if benign and not hard_signal:
        points = max(0, points - 35)
        if (
            score >= 0.95
            and module
            in {"beacons", "beacons_sni", "beacons_proxy"}
        ):
            # Recognized vendor context lowers urgency but cannot erase a
            # strong periodicity signal on its own.
            points = max(points, 25)
        reasons.append(f"lowered priority: {benign}")

    # These environment-specific pivots were supplied as "Needs review"
    # exemplars. Keep that label stable even when correlation adds enough
    # generic points to cross the broad high-concern threshold; a blacklist or
    # strobe module remains independently high concern.
    if (watch_one or watch_two) and module not in {"blacklist", "strobe"}:
        verdict = "Needs review"
    elif points >= 65:
        verdict = "High concern"
    elif points >= 25:
        verdict = "Needs review"
    elif benign:
        verdict = "Likely benign"
    else:
        verdict = "Informational"
    if not reasons:
        reasons.append("behavioral evidence is limited and requires context before escalation")
    finding["priority_score"] = points
    finding["verdict"] = verdict
    finding["reason"] = "; ".join(reasons)
    finding["watch_match"] = bool(watch_one or watch_two)
    return finding


def _count_value(value: object) -> int:
    if isinstance(value, dict):
        for key in ("count", "total", "value", "records", "results"):
            candidate = value.get(key)
            if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
                return max(0, int(candidate))
        for candidate in value.values():
            count = _count_value(candidate)
            if count:
                return count
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, int(value))
    return 0


def _extract_time_range(database: object, dashboard: object) -> Dict[str, str]:
    candidates: List[Mapping[str, Any]] = []

    def visit(value: object, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, dict):
            candidates.append(value)
            for item in list(value.values())[:100]:
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:100]:
                visit(item, depth + 1)

    visit(database)
    visit(dashboard)
    starts = (
        "start",
        "min",
        "from",
        "first_seen",
        "start_time",
        "min_timestamp",
        "ts_min",
    )
    ends = (
        "end",
        "max",
        "to",
        "last_seen",
        "end_time",
        "max_timestamp",
        "ts_max",
    )
    best: Tuple[Optional[float], Optional[float]] = (None, None)
    for candidate in candidates:
        start = _parse_timestamp(_first(candidate, starts))
        end = _parse_timestamp(_first(candidate, ends))
        if start is not None and end is not None and start <= end:
            best = (start, end)
            break
    return {
        "start": _utc_iso(best[0]) if best[0] is not None else "",
        "end": _utc_iso(best[1]) if best[1] is not None else "",
    }


def _rare_signature_sources(value: object) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for row in _rows(value, ("useragents", "user_agents")):
        seen = _integer_value(_first(row, ("seen", "count", "observations")))
        for raw in _string_list(
            _first(row, ("orig_ips", "source_ips", "hosts", "sources"))
        ):
            source = _ip(raw)
            if source:
                result[source] = result.get(source, 0) + seen
    return result


def _dashboard_rare_signature_sources(value: object) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for row in _rows(value, ("dashboard", "hosts", "data")):
        source = _ip(
            _first(row, ("source_ip", "src", "host", "ip", "address", "orig_h"))
        )
        if not source:
            continue
        raw = _first(row, ("rare_sig_count", "rare_signature_count"))
        if isinstance(raw, dict):
            # AC Hunter exposes both the underlying observation count (`base`)
            # and the dashboard weighting (`points`).  Investigation rationale
            # must report the evidence count, not the score contribution.
            raw = _first(raw, ("base", "count", "value"))
        count = _integer_value(raw)
        if count:
            result[source] = count
    return result


def _dashboard_hosts(value: object) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    seen: set = set()
    for row in _rows(value, ("dashboard", "hosts", "data")):
        host = _ip(
            _first(row, ("source_ip", "src", "host", "ip", "address", "orig_h"))
        )
        if not host or not _is_internal(host) or host in seen:
            continue
        seen.add(host)
        result.append(
            {
                "source_ip": host,
                "host": host,
                "score": round(
                    max(
                        0.0,
                        _number(
                            _first(
                                row,
                                ("score", "dashboard_score", "risk_score", "c2_score"),
                            )
                        ),
                    ),
                    6,
                ),
                "count": _integer_value(
                    _first(row, ("count", "connection_count", "connections"))
                ),
            }
        )
    return result


def normalize_collection(
    raw: Mapping[str, object],
    *,
    pulled_at: str,
    source_statuses: Mapping[str, Mapping[str, object]],
) -> Dict[str, Any]:
    operation_to_module = {
        "beacons": "beacons",
        "beacons_sni": "beacons_sni",
        "beacons_proxy": "beacons_proxy",
        "long_connections": "long_connections",
        "dns": "dns_anomalies",
        "unexpected_ports": "unexpected_ports",
        "blacklist_ip": "blacklist",
        "strobe": "strobe",
    }
    findings_by_module: Dict[str, List[Dict[str, Any]]] = {
        key: [] for key in MODULE_KEYS
    }
    for operation, module in operation_to_module.items():
        names = (
            operation,
            module,
            "data",
            "results",
            "items",
        )
        findings_by_module[module] = [
            _normalize_finding(module, row)
            for row in _rows(raw.get(operation), names)
        ][:MAX_FINDINGS_PER_MODULE]

    source_modules: Dict[str, set] = {}
    for module, findings in findings_by_module.items():
        for finding in findings:
            source = finding["source_ip"]
            if source:
                source_modules.setdefault(source, set()).add(module)
    rare_sources = _rare_signature_sources(raw.get("useragent_count_false"))
    for source, count in _rare_signature_sources(
        raw.get("useragent_count_true")
    ).items():
        rare_sources[source] = rare_sources.get(source, 0) + count
    for source, count in _dashboard_rare_signature_sources(
        raw.get("dashboard")
    ).items():
        rare_sources[source] = max(rare_sources.get(source, 0), count)

    for findings in findings_by_module.values():
        for finding in findings:
            source = finding["source_ip"]
            _score_finding(
                finding,
                len(source_modules.get(source, set())),
                rare_sources.get(source, 0),
            )

    correlated_hosts: List[Dict[str, Any]] = []
    all_sources = set(source_modules)
    for source in all_sources:
        modules = sorted(source_modules[source])
        source_findings = [
            finding
            for findings in findings_by_module.values()
            for finding in findings
            if finding["source_ip"] == source
        ]
        highest = max(
            (finding["verdict"] for finding in source_findings),
            key=lambda value: VERDICT_ORDER.get(value, -1),
        )
        correlated_hosts.append(
            {
                "source_ip": source,
                "host": source,
                "modules": modules,
                "module_count": len(modules),
                "finding_count": len(source_findings),
                "priority_score": max(
                    (finding["priority_score"] for finding in source_findings),
                    default=0,
                ),
                "verdict": highest,
                "reason": (
                    f"Source appears across {len(modules)} AC Hunter modules: "
                    + ", ".join(modules)
                ),
            }
        )
    correlated_hosts.sort(
        key=lambda item: (
            VERDICT_ORDER.get(str(item["verdict"]), -1),
            int(item["module_count"]),
            int(item["priority_score"]),
        ),
        reverse=True,
    )

    dashboard_hosts = _dashboard_hosts(raw.get("dashboard"))
    indexed_correlated = {
        item["source_ip"]: item for item in correlated_hosts
    }
    top_hosts: List[Dict[str, Any]] = []
    seen_hosts: set = set()
    for host in dashboard_hosts:
        source = host["source_ip"]
        correlation = indexed_correlated.get(source, {})
        host.update(
            {
                "modules": correlation.get("modules", []),
                "module_count": correlation.get("module_count", 0),
                "finding_count": correlation.get("finding_count", 0),
                "verdict": correlation.get(
                    "verdict",
                    "Needs review" if host["score"] >= 0.95 else "Informational",
                ),
                "reason": correlation.get(
                    "reason", "AC Hunter dashboard behavioral score"
                ),
            }
        )
        top_hosts.append(host)
        seen_hosts.add(source)
    for correlation in correlated_hosts:
        if correlation["source_ip"] not in seen_hosts:
            top_hosts.append(
                {
                    **correlation,
                    "score": 0.0,
                    "count": correlation["finding_count"],
                }
            )
    top_hosts.sort(
        key=lambda item: (
            _number(item.get("score"), 0.0),
            VERDICT_ORDER.get(str(item.get("verdict")), -1),
            _integer_value(item.get("module_count")),
        ),
        reverse=True,
    )
    top_hosts = top_hosts[:25]

    all_findings = [
        finding
        for module in MODULE_KEYS
        for finding in findings_by_module[module]
    ]
    verdict_counts = {name: 0 for name in VERDICT_ORDER}
    for finding in all_findings:
        verdict_counts[finding["verdict"]] += 1

    analyst_notes: List[Dict[str, Any]] = []
    notable = sorted(
        (
            finding
            for finding in all_findings
            if finding["verdict"] in {"High concern", "Needs review"}
        ),
        key=lambda finding: (
            bool(finding.get("watch_match")),
            VERDICT_ORDER.get(str(finding["verdict"]), -1),
            int(finding["priority_score"]),
        ),
        reverse=True,
    )
    for finding in notable[:20]:
        source = finding["source_ip"] or "unknown source"
        destination = finding["destination_ip"] or finding["fqdn"] or "unknown destination"
        analyst_notes.append(
            {
                "id": finding["id"],
                "title": f"{source} → {destination}",
                "summary": finding["reason"],
                "reason": finding["reason"],
                "verdict": finding["verdict"],
                "source_ip": finding["source_ip"],
                "destination_ip": finding["destination_ip"],
                "module": finding["module"],
                "watch_match": finding["watch_match"],
            }
        )
    if not analyst_notes:
        analyst_notes.append(
            {
                "id": "no-priority-findings",
                "title": "No priority findings in the cached pull",
                "summary": (
                    "AC Hunter behavioral data did not produce a High concern or "
                    "Needs review result under the deterministic triage rules."
                ),
                "reason": "Continue routine analyst validation; absence of a score is not proof of safety.",
                "verdict": "Informational",
                "source_ip": "",
                "destination_ip": "",
                "module": "summary",
                "watch_match": False,
            }
        )

    modules: Dict[str, Dict[str, Any]] = {}
    reverse_operations = {module: operation for operation, module in operation_to_module.items()}
    for module in MODULE_KEYS:
        operation = reverse_operations[module]
        status = dict(source_statuses.get(operation, {}))
        modules[module] = {
            "count": len(findings_by_module[module]),
            "status": status.get("status", "unknown"),
            "error": _safe_error(status.get("error"), "")
            if status.get("error")
            else "",
            "findings": findings_by_module[module],
        }

    complete = all(
        status.get("status") == "ok"
        for operation, status in source_statuses.items()
        if operation != "unexpected_ports"
    )
    time_range = _extract_time_range(
        raw.get("database"), raw.get("dashboard")
    )
    cache = {
        "status": "fresh",
        "stale": False,
        "refreshed_at": pulled_at,
        "age_seconds": 0,
    }
    return {
        "schema": REVIEW_SCHEMA,
        "version": REVIEW_VERSION,
        "ok": True,
        "last_pulled_at": pulled_at,
        "metadata": {
            "dataset": FIXED_DATASET,
            "last_pulled_at": pulled_at,
            "source": "AC Hunter behavioral triage via the Onion Sentinel Relay",
            "transport_path": "Onion Sentinel → Relay → AC Hunter",
            "complete": complete,
            "stale": False,
            "source_statuses": {
                key: {
                    "status": value.get("status", "unknown"),
                    "http_status": _integer_value(value.get("http_status")),
                    "error": _safe_error(value.get("error"), "")
                    if value.get("error")
                    else "",
                }
                for key, value in source_statuses.items()
            },
        },
        "dataset": {
            "name": FIXED_DATASET,
            "time_range": time_range,
        },
        "time_range": time_range,
        "cache": cache,
        "verdict_counts": verdict_counts,
        "top_hosts": top_hosts,
        "top_risky_internal_hosts": top_hosts,
        "correlated_hosts": correlated_hosts,
        "modules": modules,
        "analyst_notes": analyst_notes,
        "counts": {
            "dashboard": _count_value(raw.get("dashboard_count")),
            "c2_flags": _count_value(raw.get("dashboard_c2flag")),
            "beacons": _count_value(raw.get("beacons_count")),
            "certificates": _count_value(raw.get("certificate_count")),
            "user_agents_without_ja3": _count_value(
                raw.get("useragent_count_false")
            ),
            "user_agents_with_ja3": _count_value(
                raw.get("useragent_count_true")
            ),
        },
        "disclaimer": (
            "AC Hunter is a behavioral triage source. Scores and correlations "
            "prioritize analyst review; they do not by themselves establish "
            "malware, compromise, or malicious intent."
        ),
    }


COLLECTION_OPERATIONS: Tuple[Tuple[str, Dict[str, Any], bool], ...] = (
    ("database", {}, False),
    ("dashboard", {}, False),
    ("dashboard_count", {}, False),
    ("dashboard_c2flag", {}, False),
    ("beacons_count", {"thresh": 0.5}, False),
    (
        "beacons",
        {"page": 1, "size": 100, "thresh": 0.5, "sort": "score"},
        False,
    ),
    (
        "beacons_sni",
        {"page": 1, "size": 100, "thresh": 0.5, "sort": "score"},
        False,
    ),
    (
        "beacons_proxy",
        {"page": 1, "size": 100, "thresh": 0.5, "sort": "score"},
        False,
    ),
    (
        "long_connections",
        {"page": 1, "size": 100, "min_length": 18_000, "sort": "duration"},
        False,
    ),
    (
        "dns",
        {"page": 1, "size": 100, "threshold": 100},
        False,
    ),
    (
        "strobe",
        {"page": 1, "size": 100, "sort": "connection_count"},
        False,
    ),
    ("blacklist_ip", {"page": 1, "size": 100}, False),
    ("certificate_count", {}, False),
    ("useragent_count_false", {"ja3flag": False}, False),
    ("useragent_count_true", {"ja3flag": True}, False),
    ("unexpected_ports", {}, True),
)


def collect(client: AcHunterApiClient, clock: Callable[[], float]) -> Dict[str, Any]:
    raw: Dict[str, object] = {}
    statuses: Dict[str, Dict[str, object]] = {}
    successes = 0
    for operation, params, optional in COLLECTION_OPERATIONS:
        api_operation = (
            "useragent_count"
            if operation in {"useragent_count_false", "useragent_count_true"}
            else operation
        )
        try:
            raw[operation] = client.get(api_operation, params)
            statuses[operation] = {"status": "ok", "http_status": 200, "error": ""}
            successes += 1
        except AcHunterError as exc:
            statuses[operation] = {
                "status": "unavailable" if optional else "failed",
                "http_status": 0,
                "error": _safe_error(exc),
            }
    if successes == 0:
        raise AcHunterTransportError("all AC Hunter collection operations failed")
    return normalize_collection(
        raw,
        pulled_at=_utc_iso(clock()),
        source_statuses=statuses,
    )


def collect_from_relay(
    config_path: Path = DEFAULT_CONFIG,
    *,
    clock: Callable[[], float] = time.time,
) -> Dict[str, Any]:
    """Run one scheduled, normalized collection through the fixed Relay path."""

    config = load_config(config_path)
    if config.get("enabled") is not True:
        raise AcHunterConfigurationError("AC Hunter Deep Review is disabled")
    transport = RelayTransport(config)
    client = AcHunterApiClient(
        transport,
        lambda: load_credentials(Path(config["credentials_file"])),
        clock=clock,
    )
    return validate_cache(collect(client, clock))


def _validate_cache_tree(value: object, depth: int = 0) -> None:
    if depth > 12:
        raise AcHunterConfigurationError("AC Hunter cache nesting is invalid")
    if isinstance(value, dict):
        if len(value) > 1000:
            raise AcHunterConfigurationError("AC Hunter cache object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise AcHunterConfigurationError("AC Hunter cache key is invalid")
            if key.lower() in FORBIDDEN_CACHE_KEYS:
                raise AcHunterConfigurationError(
                    "AC Hunter cache contains authentication material"
                )
            _validate_cache_tree(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 5000:
            raise AcHunterConfigurationError("AC Hunter cache list is too large")
        for item in value:
            _validate_cache_tree(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 8192 or any(
            ord(character) < 9
            or 13 < ord(character) < 32
            for character in value
        ):
            raise AcHunterConfigurationError("AC Hunter cache text is invalid")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise AcHunterConfigurationError("AC Hunter cache value is invalid")


def validate_cache(payload: object) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise AcHunterConfigurationError("AC Hunter cache must be an object")
    if (
        payload.get("schema") != REVIEW_SCHEMA
        or payload.get("version") != REVIEW_VERSION
        or payload.get("ok") is not True
        or not isinstance(payload.get("modules"), dict)
        or not isinstance(payload.get("metadata"), dict)
        or not isinstance(payload.get("cache"), dict)
    ):
        raise AcHunterConfigurationError("AC Hunter cache schema is unsupported")
    metadata = payload["metadata"]
    if metadata.get("dataset") != FIXED_DATASET:
        raise AcHunterConfigurationError("AC Hunter cache dataset is invalid")
    if _parse_timestamp(payload.get("last_pulled_at")) is None:
        raise AcHunterConfigurationError("AC Hunter cache timestamp is invalid")
    _validate_cache_tree(payload)
    return copy.deepcopy(payload)


def _prepare_private_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise AcHunterConfigurationError(
            "AC Hunter cache directory is not owner-controlled"
        )


def load_cache(path: Path) -> Optional[Dict[str, Any]]:
    if Path(os.path.abspath(str(path))) != Path(
        os.path.abspath(str(DEFAULT_CACHE))
    ):
        raise AcHunterConfigurationError(
            "AC Hunter cache path is outside the fixed runtime location"
        )
    try:
        raw = _secure_file_bytes(path, maximum_bytes=MAX_CACHE_BYTES)
    except AcHunterConfigurationError:
        if not path.exists() and not path.is_symlink():
            return None
        raise
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcHunterConfigurationError("AC Hunter cache JSON is invalid") from exc
    return validate_cache(payload)


def atomic_write_cache(path: Path, payload: Mapping[str, Any]) -> None:
    if Path(os.path.abspath(str(path))) != Path(
        os.path.abspath(str(DEFAULT_CACHE))
    ):
        raise AcHunterConfigurationError(
            "AC Hunter cache path is outside the fixed runtime location"
        )
    normalized = validate_cache(dict(payload))
    encoded = (
        json.dumps(normalized, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_CACHE_BYTES:
        raise AcHunterConfigurationError("AC Hunter normalized cache is too large")
    _prepare_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        _secure_file_bytes(path, maximum_bytes=MAX_CACHE_BYTES)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(str(temporary), str(path))
        os.chmod(path, 0o600)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _cache_age(payload: Mapping[str, Any], now: float) -> float:
    refreshed = _parse_timestamp(payload.get("last_pulled_at"))
    if refreshed is None:
        return float("inf")
    return max(0.0, now - refreshed)


def _cache_view(
    payload: Mapping[str, Any],
    *,
    now: float,
    ttl: int,
    stale: bool,
    error: str = "",
) -> Dict[str, Any]:
    value = copy.deepcopy(dict(payload))
    age = int(_cache_age(value, now))
    status = "stale" if stale else "fresh"
    value["cache"] = {
        "status": status,
        "stale": stale,
        "refreshed_at": value.get("last_pulled_at", ""),
        "age_seconds": age,
        "ttl_seconds": ttl,
        "last_error": _safe_error(error, "") if error else "",
    }
    metadata = value.setdefault("metadata", {})
    metadata["stale"] = stale
    if error:
        metadata["collection_error"] = _safe_error(error)
    else:
        metadata.pop("collection_error", None)
    return value


class AcHunterReviewService:
    """Single-flight collection with normalized fresh/stale cache semantics."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        client: Optional[AcHunterApiClient] = None,
        clock: Callable[[], float] = time.time,
        collector: Callable[[AcHunterApiClient, Callable[[], float]], Dict[str, Any]] = collect,
    ) -> None:
        self.config = dict(config)
        self.clock = clock
        self.collector = collector
        self._lock = threading.RLock()
        self._memory_cache: Optional[Dict[str, Any]] = None
        if client is None and self.config.get("enabled") is True:
            transport = RelayTransport(self.config)
            credentials_path = Path(self.config["credentials_file"])
            client = AcHunterApiClient(
                transport,
                lambda: load_credentials(credentials_path),
                clock=clock,
            )
        self.client = client

    @classmethod
    def from_config_path(
        cls, path: Path = DEFAULT_CONFIG
    ) -> "AcHunterReviewService":
        return cls(load_config(path))

    def _cached(self) -> Optional[Dict[str, Any]]:
        if self._memory_cache is not None:
            return copy.deepcopy(self._memory_cache)
        value = load_cache(Path(self.config["cache_file"]))
        if value is not None:
            self._memory_cache = value
            return copy.deepcopy(value)
        return None

    def response(self, force_refresh: bool = False) -> Tuple[int, Dict[str, Any]]:
        with self._lock:
            if self.config.get("enabled") is not True:
                return 503, _error_payload(
                    "AC Hunter Deep Review is disabled", stale=False
                )
            if self.client is None:
                return 503, _error_payload(
                    "AC Hunter client is unavailable", stale=False
                )
            now = self.clock()
            ttl = int(self.config["cache_ttl_seconds"])
            try:
                cached = self._cached()
            except AcHunterError:
                cached = None
            if (
                cached is not None
                and _cache_age(cached, now) <= ttl
                and (
                    not force_refresh
                    or _cache_age(cached, now)
                    < MIN_FORCE_REFRESH_INTERVAL_SECONDS
                )
            ):
                view = _cache_view(
                    cached, now=now, ttl=ttl, stale=False
                )
                if force_refresh:
                    view["cache"]["refresh_limited"] = True
                    view["cache"]["refresh_available_in_seconds"] = max(
                        0,
                        MIN_FORCE_REFRESH_INTERVAL_SECONDS
                        - int(_cache_age(cached, now)),
                    )
                return 200, view
            try:
                fresh = self.collector(self.client, self.clock)
                fresh = validate_cache(fresh)
                atomic_write_cache(Path(self.config["cache_file"]), fresh)
                self._memory_cache = fresh
                return 200, _cache_view(
                    fresh, now=self.clock(), ttl=ttl, stale=False
                )
            except Exception as exc:
                safe = (
                    _safe_error(exc)
                    if isinstance(exc, AcHunterError)
                    else "AC Hunter normalized collection failed"
                )
                if cached is not None:
                    return 200, _cache_view(
                        cached,
                        now=self.clock(),
                        ttl=ttl,
                        stale=True,
                        error=safe,
                    )
                return 503, _error_payload(safe, stale=False)


def _error_payload(error: str, *, stale: bool) -> Dict[str, Any]:
    return {
        "schema": REVIEW_SCHEMA,
        "version": REVIEW_VERSION,
        "ok": False,
        "last_pulled_at": "",
        "metadata": {
            "dataset": FIXED_DATASET,
            "source": "AC Hunter behavioral triage via the Onion Sentinel Relay",
            "transport_path": "Onion Sentinel → Relay → AC Hunter",
            "complete": False,
            "stale": stale,
            "collection_error": _safe_error(error),
        },
        "dataset": {"name": FIXED_DATASET, "time_range": {"start": "", "end": ""}},
        "time_range": {"start": "", "end": ""},
        "cache": {
            "status": "unavailable",
            "stale": stale,
            "refreshed_at": "",
            "age_seconds": 0,
            "ttl_seconds": 0,
            "last_error": _safe_error(error),
        },
        "verdict_counts": {name: 0 for name in VERDICT_ORDER},
        "top_hosts": [],
        "top_risky_internal_hosts": [],
        "correlated_hosts": [],
        "modules": {
            key: {
                "count": 0,
                "status": "unavailable",
                "error": "",
                "findings": [],
            }
            for key in MODULE_KEYS
        },
        "analyst_notes": [],
        "counts": {},
        "disclaimer": (
            "AC Hunter is a behavioral triage source. Scores and correlations "
            "do not by themselves establish malware or compromise."
        ),
    }


def database_review_response(
    api_url: str = DEFAULT_DATABASE_API_URL,
    *,
    timeout: float = 10.0,
) -> Tuple[int, Dict[str, Any]]:
    """Read one bounded normalized snapshot from loopback PostgreSQL storage."""

    if api_url != DEFAULT_DATABASE_API_URL:
        return 503, _error_payload(
            "AC Hunter database endpoint is outside the fixed allowlist",
            stale=False,
        )
    request = urllib.request.Request(
        api_url,
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_CACHE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        message = (
            "AC Hunter has not completed a scheduled database collection yet"
            if exc.code == 404
            else "AC Hunter PostgreSQL cache is unavailable"
        )
        return 503, _error_payload(message, stale=False)
    except (OSError, urllib.error.URLError, TimeoutError):
        return 503, _error_payload(
            "AC Hunter PostgreSQL cache is unavailable", stale=False
        )
    if len(raw) > MAX_CACHE_BYTES:
        return 503, _error_payload(
            "AC Hunter PostgreSQL response exceeds its size boundary",
            stale=False,
        )
    try:
        payload = validate_cache(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, AcHunterError):
        return 503, _error_payload(
            "AC Hunter PostgreSQL returned an invalid snapshot", stale=False
        )
    return 200, payload


def deep_review_response(
    force_refresh: bool = False,
) -> Tuple[int, Dict[str, object]]:
    """Read the database cache; web requests never trigger AC Hunter pulls."""

    del force_refresh
    return database_review_response()
