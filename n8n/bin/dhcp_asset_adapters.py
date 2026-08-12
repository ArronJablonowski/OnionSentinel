#!/usr/bin/env python3
"""Credential-isolated persistence and bounded Relay transport adapters."""
from __future__ import annotations

import datetime as dt
import json
import os
import stat
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from dhcp_asset_contract import CONTRACT, MAX_RESPONSE_OBSERVATIONS, format_timestamp


MAX_ASSET_API_RESPONSE_BYTES = 1024 * 1024


def asset_store_token(path: Path) -> str:
    metadata = path.lstat()
    if (
        not path.is_file()
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 1024 * 1024
    ):
        raise ValueError("runtime environment file is not owner-controlled")
    values = {}
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
        raise ValueError("asset-store write token is missing or too short")
    return token


def persist_database_state(api_url: str, token: str, state: dict) -> dict:
    payload = json.dumps(
        {"state": state, "actor": "scheduled-dhcp-collector"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    request = urllib_request.Request(
        f"{api_url.rstrip('/')}/assets/dhcp-state",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "X-Onion-Sentinel-Asset-Token": token,
        },
    )
    try:
        with urllib_request.urlopen(request, timeout=30) as response:
            encoded = response.read(MAX_ASSET_API_RESPONSE_BYTES + 1)
    except urllib_error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise RuntimeError(
            f"asset database returned HTTP {exc.code}: {detail[:300]}"
        ) from exc
    except (OSError, urllib_error.URLError) as exc:
        raise RuntimeError(f"asset database is unavailable: {exc}") from exc
    if len(encoded) > MAX_ASSET_API_RESPONSE_BYTES:
        raise RuntimeError("asset database response exceeded its byte limit")
    result = json.loads(encoded)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError("asset database rejected DHCP state")
    return result


def relay_failure_diagnostic(stdout: object, stderr: object) -> str:
    """Return bounded, allowlisted diagnostics from the forced relay envelope."""
    fields: list[str] = []
    try:
        payload = json.loads(str(stdout or ""))
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        for key in ("error", "upstream_error", "upstream_detail"):
            value = payload.get(key)
            if not isinstance(value, str):
                continue
            text = "".join(
                character if character.isprintable() else " "
                for character in value
            )
            text = " ".join(text.split())
            if text:
                fields.append(text[:300])
    stderr_text = "".join(
        character if character.isprintable() else " "
        for character in str(stderr or "")
    )
    stderr_text = " ".join(stderr_text.split())
    if stderr_text:
        fields.append(stderr_text[:300])
    return "; ".join(fields)[:700]


def query_dhcp(
    config: dict,
    start: dt.datetime,
    end: dt.datetime,
    size: int,
    *,
    now_fn,
    run_command_fn,
    validate_response_fn,
    diagnostic_fn,
) -> dict:
    """Run one bounded, read-only DHCP query through the forced Relay lane."""
    start = start.astimezone(dt.timezone.utc)
    end = end.astimezone(dt.timezone.utc)
    if start >= end or end - start > dt.timedelta(hours=24):
        raise ValueError("DHCP query window must be positive and no longer than 24 hours")
    if end > now_fn() + dt.timedelta(minutes=5):
        raise ValueError("DHCP query window ends too far in the future")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= MAX_RESPONSE_OBSERVATIONS
    ):
        raise ValueError("DHCP query size must be from 1 through 1000")
    request = {
        "contract": CONTRACT,
        "operation": "dhcp_observations",
        "window": {"start": format_timestamp(start), "end": format_timestamp(end)},
        "size": size,
    }
    command = [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        f"ConnectTimeout={config['connect_timeout_seconds']}",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config['known_hosts']}",
        "-i",
        config["ssh_key"],
        f"{config['ssh_user']}@{config['host']}",
    ]
    proc = run_command_fn(
        command,
        stdin_text=json.dumps(request, separators=(",", ":"), sort_keys=True),
        timeout_seconds=config["timeout_seconds"],
        max_stdout_bytes=config["max_response_bytes"],
        max_stderr_bytes=config["max_stderr_bytes"],
    )
    if proc.returncode != 0:
        detail = diagnostic_fn(proc.stdout, proc.stderr)
        raise RuntimeError(
            f"relay returned {proc.returncode}: {detail or 'no diagnostic'}"
        )
    return validate_response_fn(
        json.loads(proc.stdout),
        expected_window=request["window"],
    )
