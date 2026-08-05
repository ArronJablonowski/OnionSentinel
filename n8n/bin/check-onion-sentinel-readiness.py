#!/usr/bin/env python3
"""Emit a bounded, secret-safe, non-mutating production readiness snapshot."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable


MAX_CONFIG_BYTES = 1024 * 1024
MAX_HEALTH_BYTES = 64 * 1024
RELEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{6,99}$")


def result(component: str, state: str, reason: str, started: float) -> dict[str, Any]:
    return {
        "component": component,
        "state": state,
        "reason_code": reason,
        "duration_ms": max(0, round((time.monotonic() - started) * 1000)),
    }


def safe_file(
    path: Path,
    *,
    owner_only: bool = False,
    maximum_bytes: int | None = MAX_CONFIG_BYTES,
) -> tuple[bool, str]:
    try:
        info = path.lstat()
    except OSError:
        return False, "missing"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False, "unsafe_file_type"
    if info.st_uid != os.getuid():
        return False, "wrong_owner"
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o022:
        return False, "writable_by_other"
    if owner_only and mode & 0o077:
        return False, "permissions_too_open"
    if maximum_bytes is not None and info.st_size > maximum_bytes:
        return False, "oversized"
    return True, "ready"


def read_json(path: Path, *, owner_only: bool = False) -> dict[str, Any]:
    ok, reason = safe_file(path, owner_only=owner_only)
    if not ok:
        raise ValueError(reason)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("not_object")
    return value


def env_release(path: Path) -> str:
    ok, reason = safe_file(path, owner_only=True)
    if not ok:
        raise ValueError(reason)
    release = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "ONION_SENTINEL_RELEASE_ID":
            release = value.strip()
            break
    if not RELEASE_RE.fullmatch(release):
        raise ValueError("release_id_invalid")
    return release


def check_configuration(stack: Path) -> dict[str, Any]:
    started = time.monotonic()
    try:
        release = env_release(stack / ".env")
        settings = read_json(stack / "config" / "ai_model_settings.json")
        read_json(stack / "config" / "investigation_harness_policy.json")
        read_json(stack / "config" / "investigation_skills.json")
        read_json(stack / "config" / "incident-evidence.json", owner_only=True)
        if not isinstance(settings.get("agent_models"), dict):
            raise ValueError("agent_routes_missing")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return result("configuration", "failed", str(exc), started)
    item = result("configuration", "ready", "validated", started)
    item["release_id"] = release
    return item


def check_database(path: Path, component: str) -> dict[str, Any]:
    started = time.monotonic()
    ok, reason = safe_file(path, maximum_bytes=None)
    if not ok:
        return result(component, "failed", reason, started)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"file:{path}?mode=ro",
            uri=True,
            timeout=1.0,
        )
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute("PRAGMA quick_check(1)").fetchone()
        if not row or row[0] != "ok":
            raise sqlite3.DatabaseError("quick_check_failed")
    except sqlite3.Error as exc:
        return result(component, "failed", str(exc).split(":", 1)[0], started)
    finally:
        if connection is not None:
            connection.close()
    return result(component, "ready", "read_only_quick_check_ok", started)


def check_storage(stack: Path, minimum_free_bytes: int) -> dict[str, Any]:
    started = time.monotonic()
    for name in ("run", "logs", "soc-alerts", "alert_store_data"):
        path = stack / name
        try:
            info = path.lstat()
        except OSError:
            return result("storage", "failed", f"{name}_missing", started)
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            return result("storage", "failed", f"{name}_unsafe_type", started)
        if info.st_uid != os.getuid() or not os.access(path, os.W_OK | os.X_OK):
            return result("storage", "failed", f"{name}_not_writable", started)
    free = shutil.disk_usage(stack).free
    if free < minimum_free_bytes:
        return result("storage", "failed", "free_space_below_threshold", started)
    return result("storage", "ready", "directories_and_capacity_ready", started)


def configured_routes(settings: dict[str, Any]) -> list[str]:
    routes: list[str] = []
    for field in ("agent_models", "agent_second_opinion_models", "agent_adjudicator_models"):
        value = settings.get(field)
        if isinstance(value, dict):
            routes.extend(str(route) for route in value.values() if route)
    return sorted(set(routes))


def check_providers(stack: Path) -> dict[str, Any]:
    started = time.monotonic()
    try:
        settings = read_json(stack / "config" / "ai_model_settings.json")
        routes = configured_routes(settings)
        if not routes:
            raise ValueError("no_assigned_routes")
        for route in routes:
            provider = route.split(":", 1)[0]
            if provider == "codex-cli":
                candidate = str(settings.get("codex_cli_path") or "codex")
            elif provider == "ollama":
                endpoint = urllib.parse.urlsplit(
                    str(settings.get("ollama_url") or "")
                )
                if (
                    endpoint.scheme not in {"http", "https"}
                    or not endpoint.hostname
                    or endpoint.username
                    or endpoint.password
                    or endpoint.query
                    or endpoint.fragment
                ):
                    raise ValueError("ollama_endpoint_invalid")
                continue
            elif provider == "hermes-agent":
                candidate = str(settings.get("hermes_agent_path") or "")
            elif provider == "openclaw":
                candidate = str(settings.get("openclaw_path") or "")
            else:
                raise ValueError("unsupported_assigned_provider")
            executable = candidate if os.path.isabs(candidate) else shutil.which(candidate)
            if not executable or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
                raise ValueError(f"{provider}_executable_unavailable")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return result("providers", "failed", str(exc), started)
    item = result("providers", "ready", "assigned_executables_available", started)
    item["assigned_route_count"] = len(routes)
    return item


def bounded_health(url: str, service: str) -> bool:
    with urllib.request.urlopen(url, timeout=2.0) as response:
        raw = response.read(MAX_HEALTH_BYTES + 1)
    if len(raw) > MAX_HEALTH_BYTES:
        return False
    value = json.loads(raw)
    return bool(value.get("ok") is True and value.get("service") == service)


def check_services() -> dict[str, Any]:
    started = time.monotonic()
    checks = (
        ("http://127.0.0.1:8766/healthz", "onion-sentinel"),
        ("http://127.0.0.1:8787/health", "onion-sentinel-alert-store"),
    )
    try:
        if not all(bounded_health(url, service) for url, service in checks):
            raise ValueError("identity_mismatch")
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return result("services", "failed", "health_or_identity_failed", started)
    return result("services", "ready", "identity_health_ready", started)


def relay_endpoint(stack: Path) -> tuple[str, int]:
    config = read_json(stack / "config" / "incident-evidence.json", owner_only=True)
    host = str(config.get("host") or "").strip()
    port = int(config.get("port") or 22)
    if not host or not 1 <= port <= 65535:
        raise ValueError("relay_endpoint_invalid")
    return host, port


def check_relay(stack: Path, network: bool) -> dict[str, Any]:
    started = time.monotonic()
    try:
        host, port = relay_endpoint(stack)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return result("relay", "failed", "transport_configuration_invalid", started)
    if not network:
        return result("relay", "unverified", "network_check_not_requested", started)
    try:
        with socket.create_connection((host, port), timeout=2.0):
            pass
    except OSError:
        return result("relay", "failed", "tcp_unreachable", started)
    return result("relay", "ready", "tcp_reachable", started)


def snapshot(stack: Path, *, network: bool, minimum_free_bytes: int) -> dict[str, Any]:
    checks: list[Callable[[], dict[str, Any]]] = [
        lambda: check_configuration(stack),
        lambda: check_database(stack / "alert_store_data" / "alerts.sqlite3", "alert_store_database"),
        lambda: check_database(stack / "alert_store_data" / "investigation-harness.sqlite3", "harness_database"),
        lambda: check_storage(stack, minimum_free_bytes),
        lambda: check_providers(stack),
        check_services,
        lambda: check_relay(stack, network),
    ]
    components = [check() for check in checks]
    return {
        "schema": "onion-sentinel-readiness-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "check_only": True,
        "network_check_requested": network,
        "ok": all(item["state"] in {"ready", "unverified"} for item in components),
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--network", action="store_true", help="TCP-connect to the configured Relay only")
    parser.add_argument("--minimum-free-bytes", type=int, default=10 * 1024**3)
    args = parser.parse_args()
    value = snapshot(
        args.stack_dir.expanduser().resolve(),
        network=args.network,
        minimum_free_bytes=max(0, args.minimum_free_bytes),
    )
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
