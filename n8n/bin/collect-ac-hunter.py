#!/usr/bin/env python3
"""Scheduled AC Hunter collector and PostgreSQL publisher.

This process is the only Mac-side component that contacts the Relay for AC
Hunter data. The dashboard API is database-read-only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any


HOME = Path.home()
DEFAULT_STACK = HOME / "n8n-local"
DEFAULT_CONFIG = DEFAULT_STACK / "config" / "ac-hunter.json"
DEFAULT_ENV = DEFAULT_STACK / ".env"
DEFAULT_MODULE = (
    DEFAULT_STACK / "onion-sentinel-dashboard" / "ac_hunter_review.py"
)
DEFAULT_API_URL = "http://127.0.0.1:8787/ac-hunter/snapshots"
MAX_RESPONSE_BYTES = 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def load_module(path: Path) -> ModuleType:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("AC Hunter collector module is unavailable")
    spec = importlib.util.spec_from_file_location(
        "onion_sentinel_scheduled_ac_hunter", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("AC Hunter collector module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def database_write_token(path: Path) -> str:
    metadata = path.lstat()
    if (
        not path.is_file()
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    ):
        raise RuntimeError("runtime environment file is not owner-controlled")
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    token = values.get("ASSET_STORE_WRITE_TOKEN") or values.get(
        "N8N_POST_COMMIT_TOKEN"
    )
    if not token or len(token) < 32:
        raise RuntimeError("AC Hunter database write token is missing")
    return token


def publish(api_url: str, token: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    if api_url != DEFAULT_API_URL:
        raise RuntimeError("AC Hunter database endpoint is outside the fixed allowlist")
    encoded = json.dumps(
        snapshot, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    request = urllib.request.Request(
        api_url,
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(encoded)),
            "X-Onion-Sentinel-Asset-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"AC Hunter PostgreSQL publisher returned HTTP {exc.code}"
        ) from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError("AC Hunter PostgreSQL publisher is unavailable") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RuntimeError("AC Hunter PostgreSQL response exceeds its size boundary")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("AC Hunter PostgreSQL response is invalid") from exc
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError("AC Hunter PostgreSQL publisher rejected the snapshot")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    args = parser.parse_args()
    try:
        module = load_module(args.module.expanduser())
        snapshot = module.collect_from_relay(args.config.expanduser())
        token = database_write_token(args.env.expanduser())
        result = publish(args.api_url, token, snapshot)
        print(
            json.dumps(
                {
                    "timestamp": utc_now(),
                    "event": "ac_hunter.collection_completed",
                    "changed": result.get("changed") is True,
                    "dataset_digest": str(result.get("dataset_digest") or ""),
                    "checked_at": str(result.get("checked_at") or ""),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "timestamp": utc_now(),
                    "event": "ac_hunter.collection_failed",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
