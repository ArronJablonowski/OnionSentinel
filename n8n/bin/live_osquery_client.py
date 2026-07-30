#!/usr/bin/env python3
"""Collect bounded live-host OSQuery evidence through the restricted relay.

The Mac Studio never receives Fleet agent identifiers or Security Onion API
credentials. It submits model-requested queries against operator-defined
aliases, then independently validates that every returned result matches the
exact alias, SQL digest, and purpose that crossed the first SSH boundary.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from bounded_process import BoundedProcessError, run_bounded_command
from live_osquery_contract import (
    ALLOWED_TABLE_COLUMNS,
    ALLOWED_TABLES,
    MAX_REQUESTS,
    MAX_RESPONSE_BYTES,
    MAX_ROWS,
    TARGET_OSQUERY_VERSION,
    TARGET_PLATFORM,
    LiveOsqueryContractError,
    bounded_json_bytes,
    normalize_requests,
    normalize_target_aliases,
    validate_result_artifact,
)


DEFAULT_CONFIG_FILE = Path.home() / "n8n-local" / "config" / "live-osquery.json"
DEFAULT_ARTIFACT_DIR = (
    Path.home()
    / "n8n-local"
    / "soc-alerts"
    / "incident-evidence"
    / "live-osquery"
)
MAX_CONFIG_BYTES = 64 * 1024
MAX_STDERR_BYTES = 256 * 1024
DEFAULT_MAX_SAVED_BATCHES_PER_CASE = 8
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SAFE_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_SAFE_BINDING_HOST = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$"
)
ALLOWED_AGENT_ROLES = frozenset({"soc-analyst", "incident-responder"})
DEFAULT_ALLOWED_AGENT_ROLES = ("incident-responder",)


class LiveOsqueryClientError(RuntimeError):
    """The local live-query client could not satisfy its restricted contract."""


def project_now() -> str:
    return dt.datetime.now().astimezone().isoformat().replace("T", "  ")


def _bounded_int(
    value: Any,
    *,
    label: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value if value not in (None, "") else default)
    except (TypeError, ValueError) as exc:
        raise LiveOsqueryClientError(f"{label} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise LiveOsqueryClientError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return parsed


def _read_json(path: Path, maximum: int = MAX_CONFIG_BYTES) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise LiveOsqueryClientError(f"live OSQuery config not found: {path}") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise LiveOsqueryClientError(
            "live OSQuery config must be an owner-controlled regular file with mode 0600"
        )
    if info.st_size > maximum:
        raise LiveOsqueryClientError(
            f"live OSQuery config exceeds the {maximum}-byte limit"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LiveOsqueryClientError(f"cannot read live OSQuery config: {exc}") from exc
    if not isinstance(value, dict):
        raise LiveOsqueryClientError("live OSQuery config must be a JSON object")
    return value


def load_live_osquery_config(path: Path = DEFAULT_CONFIG_FILE) -> dict[str, Any]:
    """Load a capability-only client config; credentials never belong here."""
    source = _read_json(path.expanduser())
    enabled_value = source.get("enabled", False)
    if not isinstance(enabled_value, bool):
        raise LiveOsqueryClientError("enabled must be boolean")
    enabled = enabled_value
    aliases = normalize_target_aliases(source.get("allowed_target_aliases") or [])
    raw_roles = source.get("allowed_agent_roles", list(DEFAULT_ALLOWED_AGENT_ROLES))
    if not isinstance(raw_roles, list):
        raise LiveOsqueryClientError("allowed_agent_roles must be an array")
    allowed_agent_roles: list[str] = []
    for raw_role in raw_roles:
        role = str(raw_role or "").strip().lower()
        if role not in ALLOWED_AGENT_ROLES:
            raise LiveOsqueryClientError(
                f"allowed_agent_roles contains unsupported role: {role or 'empty'}"
            )
        if role not in allowed_agent_roles:
            allowed_agent_roles.append(role)
    raw_bindings = source.get("target_bindings") or {}
    if not isinstance(raw_bindings, dict):
        raise LiveOsqueryClientError("target_bindings must be an object")
    unknown_bindings = sorted(set(raw_bindings).difference(aliases))
    if unknown_bindings:
        raise LiveOsqueryClientError(
            "target_bindings contains unconfigured aliases: "
            + ", ".join(unknown_bindings)
        )
    target_bindings: dict[str, dict[str, list[str]]] = {}
    for alias, raw_binding in raw_bindings.items():
        if not isinstance(raw_binding, dict):
            raise LiveOsqueryClientError(
                f"target binding {alias} must be an object"
            )
        unknown_keys = sorted(set(raw_binding).difference({"ips", "hosts"}))
        if unknown_keys:
            raise LiveOsqueryClientError(
                f"target binding {alias} contains unsupported fields: "
                + ", ".join(unknown_keys)
            )
        ips: list[str] = []
        raw_ips = raw_binding.get("ips") or []
        if not isinstance(raw_ips, list):
            raise LiveOsqueryClientError(
                f"target binding {alias}.ips must be an array"
            )
        for raw_ip in raw_ips:
            try:
                ip = str(ipaddress.ip_address(str(raw_ip).strip()))
            except ValueError as exc:
                raise LiveOsqueryClientError(
                    f"target binding {alias} contains an invalid IP"
                ) from exc
            if ip not in ips:
                ips.append(ip)
        hosts: list[str] = []
        raw_hosts = raw_binding.get("hosts") or []
        if not isinstance(raw_hosts, list):
            raise LiveOsqueryClientError(
                f"target binding {alias}.hosts must be an array"
            )
        for raw_host in raw_hosts:
            host = str(raw_host or "").strip().lower().rstrip(".")
            if not _SAFE_BINDING_HOST.fullmatch(host):
                raise LiveOsqueryClientError(
                    f"target binding {alias} contains an invalid host"
                )
            if host not in hosts:
                hosts.append(host)
        if not ips and not hosts:
            raise LiveOsqueryClientError(
                f"target binding {alias} must contain at least one IP or host"
            )
        target_bindings[alias] = {"ips": ips, "hosts": hosts}
    config: dict[str, Any] = {
        "enabled": enabled,
        "allowed_target_aliases": aliases,
        "allowed_agent_roles": allowed_agent_roles,
        "target_bindings": target_bindings,
        "connect_timeout_seconds": _bounded_int(
            source.get("connect_timeout_seconds"),
            label="connect_timeout_seconds",
            default=10,
            minimum=1,
            maximum=60,
        ),
        "timeout_seconds": _bounded_int(
            source.get("timeout_seconds"),
            label="timeout_seconds",
            default=180,
            minimum=10,
            maximum=600,
        ),
        "port": _bounded_int(
            source.get("port"),
            label="port",
            default=22,
            minimum=1,
            maximum=65535,
        ),
        "artifact_dir": Path(
            str(source.get("artifact_dir") or DEFAULT_ARTIFACT_DIR)
        ).expanduser(),
        "max_saved_batches_per_case": _bounded_int(
            source.get("max_saved_batches_per_case"),
            label="max_saved_batches_per_case",
            default=DEFAULT_MAX_SAVED_BATCHES_PER_CASE,
            minimum=1,
            maximum=32,
        ),
    }
    approval_source = source.get("harness_operator_approval") or {}
    if not isinstance(approval_source, dict):
        raise LiveOsqueryClientError("harness_operator_approval must be an object")
    approval_enabled = approval_source.get("approved", False)
    if not isinstance(approval_enabled, bool):
        raise LiveOsqueryClientError(
            "harness_operator_approval.approved must be boolean"
        )
    approval_aliases = normalize_target_aliases(
        approval_source.get("target_aliases") or []
    )
    if any(alias not in aliases for alias in approval_aliases):
        raise LiveOsqueryClientError(
            "harness operator approval contains an unconfigured target alias"
        )
    expires_at = str(approval_source.get("expires_at") or "").strip()
    parsed_expiration: dt.datetime | None = None
    if expires_at:
        candidate = (
            expires_at[:-1] + "+00:00"
            if expires_at.endswith("Z")
            else expires_at
        )
        try:
            parsed_expiration = dt.datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise LiveOsqueryClientError(
                "harness_operator_approval.expires_at must be an ISO-8601 timestamp"
            ) from exc
        if parsed_expiration.tzinfo is None:
            raise LiveOsqueryClientError(
                "harness_operator_approval.expires_at must include a timezone"
            )
        parsed_expiration = parsed_expiration.astimezone(dt.timezone.utc)
    if approval_enabled and (not approval_aliases or parsed_expiration is None):
        raise LiveOsqueryClientError(
            "approved harness OSQuery requires target aliases and an expiration"
        )
    config["harness_operator_approval"] = {
        "approved": approval_enabled,
        "target_aliases": approval_aliases,
        "expires_at": (
            parsed_expiration.isoformat().replace("+00:00", "Z")
            if parsed_expiration is not None
            else ""
        ),
    }
    if not enabled:
        return config
    host = str(source.get("relay_host") or "").strip()
    user = str(source.get("relay_user") or "").strip()
    if not _SAFE_HOST.fullmatch(host):
        raise LiveOsqueryClientError("relay_host is missing or invalid")
    if not _SAFE_USER.fullmatch(user):
        raise LiveOsqueryClientError("relay_user is missing or invalid")
    identity_file = Path(str(source.get("identity_file") or "")).expanduser()
    known_hosts = Path(str(source.get("known_hosts") or "")).expanduser()
    if not aliases:
        raise LiveOsqueryClientError(
            "enabled live OSQuery requires at least one endpoint target alias"
        )
    missing_bindings = sorted(set(aliases).difference(target_bindings))
    if missing_bindings:
        raise LiveOsqueryClientError(
            "enabled live OSQuery requires a trusted asset binding for every "
            "target alias: " + ", ".join(missing_bindings)
        )
    for label, file_path in (
        ("identity_file", identity_file),
        ("known_hosts", known_hosts),
    ):
        if not file_path.is_file():
            raise LiveOsqueryClientError(f"{label} is not a regular file: {file_path}")
    config.update(
        {
            "relay_host": host,
            "relay_user": user,
            "identity_file": identity_file,
            "known_hosts": known_hosts,
        }
    )
    return config


def harness_operator_approved(
    config: dict[str, Any] | None,
    target_alias: Any,
    *,
    now: dt.datetime | None = None,
) -> bool:
    """Return a fail-closed, time-bounded operator approval decision."""
    if not isinstance(config, dict) or config.get("enabled") is not True:
        return False
    approval = config.get("harness_operator_approval")
    if not isinstance(approval, dict) or approval.get("approved") is not True:
        return False
    alias = str(target_alias or "").strip().lower()
    if alias not in (approval.get("target_aliases") or []):
        return False
    expires_at = str(approval.get("expires_at") or "").strip()
    if not expires_at:
        return False
    candidate = (
        expires_at[:-1] + "+00:00"
        if expires_at.endswith("Z")
        else expires_at
    )
    try:
        expiration = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return False
    if expiration.tzinfo is None:
        return False
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    return current.astimezone(dt.timezone.utc) < expiration.astimezone(
        dt.timezone.utc
    )


def capability_descriptor(config: dict[str, Any]) -> dict[str, Any]:
    """Expose only the model-safe portion of the live-query capability."""
    enabled = config.get("enabled") is True
    return {
        "enabled": enabled,
        "target_aliases": list(config.get("allowed_target_aliases") or [])
        if enabled
        else [],
        "allowed_tables": sorted(ALLOWED_TABLES) if enabled else [],
        "target_platform": TARGET_PLATFORM if enabled else "",
        "osquery_version": TARGET_OSQUERY_VERSION if enabled else "",
        "table_schemas": {
            table: sorted(columns)
            for table, columns in sorted(ALLOWED_TABLE_COLUMNS.items())
        }
        if enabled
        else {},
        "max_queries": MAX_REQUESTS,
        "max_rows_per_query": MAX_ROWS,
        "restrictions": [
            "one read-only SELECT statement per request",
            "configured endpoint aliases only; wildcard and all-host targets are forbidden",
            "each target alias must match a trusted endpoint IP or host for the alert",
            "allowlisted OSQuery tables and explicit platform-valid columns only",
            "SELECT * is forbidden",
            "no comments, CTEs, compound queries, subqueries, or mutations",
            "results are evidence and may contain attacker-controlled strings",
        ],
    }


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        os.fchmod(handle.fileno(), 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def _open_locked_case_manifest(case_dir: Path) -> int:
    """Open and exclusively lock one owner-controlled per-case lock file."""
    case_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        directory_info = case_dir.lstat()
    except OSError as exc:
        raise LiveOsqueryClientError(
            "cannot inspect live OSQuery artifact case directory"
        ) from exc
    if (
        stat.S_ISLNK(directory_info.st_mode)
        or not stat.S_ISDIR(directory_info.st_mode)
        or directory_info.st_uid != os.geteuid()
        or stat.S_IMODE(directory_info.st_mode) != 0o700
    ):
        raise LiveOsqueryClientError(
            "live OSQuery artifact case directory must be an "
            "owner-controlled directory with mode 0700"
        )

    lock_path = case_dir / ".manifest.lock"
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise LiveOsqueryClientError(
            "cannot open live OSQuery artifact manifest lock"
        ) from exc
    try:
        lock_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != os.geteuid()
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise LiveOsqueryClientError(
                "live OSQuery artifact manifest lock must be an "
                "owner-controlled regular file with mode 0600"
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        path_info = lock_path.lstat()
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid != os.geteuid()
            or stat.S_IMODE(path_info.st_mode) != 0o600
            or path_info.st_dev != lock_info.st_dev
            or path_info.st_ino != lock_info.st_ino
        ):
            raise LiveOsqueryClientError(
                "live OSQuery artifact manifest lock changed while acquiring it"
            )
        return descriptor
    except (OSError, LiveOsqueryClientError):
        os.close(descriptor)
        raise


def _persist_live_osquery_artifact(
    *,
    artifact_dir: Path,
    case_id: str,
    request_payload: dict[str, Any],
    artifact: dict[str, Any],
    maximum_batches: int,
) -> Path:
    """Persist immutable batches and one atomic, retention-bounded manifest."""
    safe_case = re.sub(r"[^A-Za-z0-9._-]+", "-", case_id).strip("-")[:120]
    case_dir = artifact_dir / (safe_case or "incident")
    request_digest = hashlib.sha256(
        bounded_json_bytes(request_payload)
    ).hexdigest()
    artifact_bytes = bounded_json_bytes(artifact)
    artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
    manifest_path = case_dir / "manifest.json"
    lock_descriptor = _open_locked_case_manifest(case_dir)
    try:
        created = dt.datetime.now(dt.timezone.utc)
        stamp = created.strftime("%Y%m%dT%H%M%S.%fZ")
        artifact_name = (
            f"{stamp}-{request_digest[:16]}-{os.urandom(4).hex()}.json"
        )
        artifact_path = case_dir / artifact_name
        if manifest_path.exists():
            manifest = _read_json(manifest_path)
            if (
                manifest.get("schema")
                != "onion-sentinel-live-osquery-manifest-v1"
                or manifest.get("case_id") != case_id
                or not isinstance(manifest.get("entries"), list)
            ):
                raise LiveOsqueryClientError(
                    "existing live OSQuery artifact manifest is invalid"
                )
            entries = list(manifest["entries"])
        else:
            entries = []
        if artifact_path.exists():
            raise LiveOsqueryClientError(
                "live OSQuery immutable artifact identity collided"
            )
        _atomic_write_json(artifact_path, artifact)
        entries.append(
            {
                "artifact": artifact_name,
                "artifact_sha256": artifact_digest,
                "request_sha256": request_digest,
                "generated_at": str(artifact.get("generated_at") or ""),
                "complete": artifact.get("complete") is True,
                "results": len(artifact.get("results") or []),
                "size_bytes": len(artifact_bytes),
            }
        )
        dropped = entries[:-maximum_batches]
        retained = entries[-maximum_batches:]
        manifest = {
            "schema": "onion-sentinel-live-osquery-manifest-v1",
            "case_id": case_id,
            "updated_at": created.isoformat().replace("+00:00", "Z"),
            "current": artifact_name,
            "retention_limit": maximum_batches,
            "entries": retained,
        }
        _atomic_write_json(manifest_path, manifest)
        for entry in dropped:
            name = (
                str(entry.get("artifact") or "")
                if isinstance(entry, dict)
                else ""
            )
            if (
                not name
                or Path(name).name != name
                or not name.endswith(".json")
                or name == "manifest.json"
            ):
                continue
            candidate = case_dir / name
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISREG(info.st_mode)
                and not stat.S_ISLNK(info.st_mode)
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600
            ):
                candidate.unlink()
        return artifact_path
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def collect_live_osquery(
    *,
    case_id: str,
    requests: Any,
    config: dict[str, Any],
    persist: bool = True,
) -> dict[str, Any]:
    """Submit and validate one bounded live-query batch through the relay."""
    if config.get("enabled") is not True:
        raise LiveOsqueryClientError("live-host OSQuery is disabled")
    normalized = normalize_requests(
        requests,
        allowed_aliases=config.get("allowed_target_aliases") or [],
    )
    if not normalized:
        raise LiveOsqueryClientError("no valid live-host OSQuery requests were supplied")
    unapproved_aliases = sorted(
        {
            item["target_alias"]
            for item in normalized
            if not harness_operator_approved(config, item["target_alias"])
        }
    )
    if unapproved_aliases:
        raise LiveOsqueryClientError(
            "live-host OSQuery operator approval is missing, expired, or "
            "not scoped to every requested target"
        )
    payload = {
        "schema": "onion-sentinel-live-osquery-v1",
        "case_id": str(case_id or "").strip(),
        "requests": normalized,
    }
    stdin_text = bounded_json_bytes(payload).decode("ascii")
    command = [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={config['known_hosts']}",
        "-o",
        f"ConnectTimeout={config['connect_timeout_seconds']}",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-i",
        str(config["identity_file"]),
        "-p",
        str(config["port"]),
        f"{config['relay_user']}@{config['relay_host']}",
    ]
    try:
        completed = run_bounded_command(
            command,
            stdin_text=stdin_text,
            timeout_seconds=float(config["timeout_seconds"]),
            max_stdout_bytes=MAX_RESPONSE_BYTES,
            max_stderr_bytes=MAX_STDERR_BYTES,
        )
    except (OSError, BoundedProcessError) as exc:
        raise LiveOsqueryClientError(f"restricted live OSQuery transport failed: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()[:1000]
        raise LiveOsqueryClientError(
            f"restricted live OSQuery transport exited {completed.returncode}: {detail}"
        )
    try:
        raw_result = json.loads(completed.stdout)
        artifact = validate_result_artifact(
            raw_result,
            expected_requests=normalized,
        )
    except (json.JSONDecodeError, LiveOsqueryContractError) as exc:
        raise LiveOsqueryClientError(
            f"restricted live OSQuery response was invalid: {exc}"
        ) from exc
    if artifact["case_id"] != payload["case_id"]:
        raise LiveOsqueryClientError(
            "restricted live OSQuery response case_id did not match the request"
        )
    if not artifact.get("generated_at"):
        artifact["generated_at"] = project_now()
    if persist:
        artifact_dir = Path(config.get("artifact_dir") or DEFAULT_ARTIFACT_DIR)
        _persist_live_osquery_artifact(
            artifact_dir=artifact_dir,
            case_id=payload["case_id"],
            request_payload=payload,
            artifact=artifact,
            maximum_batches=_bounded_int(
                config.get("max_saved_batches_per_case"),
                label="max_saved_batches_per_case",
                default=DEFAULT_MAX_SAVED_BATCHES_PER_CASE,
                minimum=1,
                maximum=32,
            ),
        )
    return artifact
