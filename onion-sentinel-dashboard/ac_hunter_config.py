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

from ac_hunter_secure_files import read_secure_file_bytes


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
    return read_secure_file_bytes(
        path,
        maximum_bytes=maximum_bytes,
        exact_mode=exact_mode,
        allow_empty=allow_empty,
        error_type=AcHunterConfigurationError,
    )


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
