"""Owner-controlled configuration admission for the live OSQuery client."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import stat
from pathlib import Path
from typing import Any

from live_osquery_client_primitives import (
    DEFAULT_ALLOWED_AGENT_ROLES,
    DEFAULT_ARTIFACT_DIR,
    DEFAULT_MAX_SAVED_BATCHES_PER_CASE,
    MAX_CONFIG_BYTES,
    SAFE_BINDING_HOST,
    SAFE_HOST,
    SAFE_USER,
    ALLOWED_AGENT_ROLES,
    LiveOsqueryClientError,
    bounded_int,
)
from live_osquery_contract import normalize_target_aliases


def read_json(path: Path, maximum: int = MAX_CONFIG_BYTES) -> dict[str, Any]:
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


def _allowed_roles(source: dict[str, Any]) -> list[str]:
    raw_roles = source.get("allowed_agent_roles", list(DEFAULT_ALLOWED_AGENT_ROLES))
    if not isinstance(raw_roles, list):
        raise LiveOsqueryClientError("allowed_agent_roles must be an array")
    roles: list[str] = []
    for raw_role in raw_roles:
        role = str(raw_role or "").strip().lower()
        if role not in ALLOWED_AGENT_ROLES:
            raise LiveOsqueryClientError(
                f"allowed_agent_roles contains unsupported role: {role or 'empty'}"
            )
        if role not in roles:
            roles.append(role)
    return roles


def _binding_ips(alias: str, raw_binding: dict[str, Any]) -> list[str]:
    raw_ips = raw_binding.get("ips") or []
    if not isinstance(raw_ips, list):
        raise LiveOsqueryClientError(f"target binding {alias}.ips must be an array")
    ips: list[str] = []
    for raw_ip in raw_ips:
        try:
            ip = str(ipaddress.ip_address(str(raw_ip).strip()))
        except ValueError as exc:
            raise LiveOsqueryClientError(
                f"target binding {alias} contains an invalid IP"
            ) from exc
        if ip not in ips:
            ips.append(ip)
    return ips


def _binding_hosts(alias: str, raw_binding: dict[str, Any]) -> list[str]:
    raw_hosts = raw_binding.get("hosts") or []
    if not isinstance(raw_hosts, list):
        raise LiveOsqueryClientError(f"target binding {alias}.hosts must be an array")
    hosts: list[str] = []
    for raw_host in raw_hosts:
        host = str(raw_host or "").strip().lower().rstrip(".")
        if not SAFE_BINDING_HOST.fullmatch(host):
            raise LiveOsqueryClientError(
                f"target binding {alias} contains an invalid host"
            )
        if host not in hosts:
            hosts.append(host)
    return hosts


def _target_bindings(
    source: dict[str, Any],
    aliases: list[str],
) -> dict[str, dict[str, list[str]]]:
    raw_bindings = source.get("target_bindings") or {}
    if not isinstance(raw_bindings, dict):
        raise LiveOsqueryClientError("target_bindings must be an object")
    unknown_bindings = sorted(set(raw_bindings).difference(aliases))
    if unknown_bindings:
        raise LiveOsqueryClientError(
            "target_bindings contains unconfigured aliases: "
            + ", ".join(unknown_bindings)
        )
    bindings: dict[str, dict[str, list[str]]] = {}
    for alias, raw_binding in raw_bindings.items():
        if not isinstance(raw_binding, dict):
            raise LiveOsqueryClientError(f"target binding {alias} must be an object")
        unknown_keys = sorted(set(raw_binding).difference({"ips", "hosts"}))
        if unknown_keys:
            raise LiveOsqueryClientError(
                f"target binding {alias} contains unsupported fields: "
                + ", ".join(unknown_keys)
            )
        ips = _binding_ips(alias, raw_binding)
        hosts = _binding_hosts(alias, raw_binding)
        if not ips and not hosts:
            raise LiveOsqueryClientError(
                f"target binding {alias} must contain at least one IP or host"
            )
        bindings[alias] = {"ips": ips, "hosts": hosts}
    return bindings


def _base_config(
    source: dict[str, Any],
    enabled: bool,
    aliases: list[str],
    roles: list[str],
    bindings: dict[str, dict[str, list[str]]],
) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "allowed_target_aliases": aliases,
        "allowed_agent_roles": roles,
        "target_bindings": bindings,
        "connect_timeout_seconds": bounded_int(
            source.get("connect_timeout_seconds"),
            label="connect_timeout_seconds", default=10, minimum=1, maximum=60,
        ),
        "timeout_seconds": bounded_int(
            source.get("timeout_seconds"),
            label="timeout_seconds", default=180, minimum=10, maximum=600,
        ),
        "port": bounded_int(
            source.get("port"),
            label="port", default=22, minimum=1, maximum=65535,
        ),
        "artifact_dir": Path(
            str(source.get("artifact_dir") or DEFAULT_ARTIFACT_DIR)
        ).expanduser(),
        "max_saved_batches_per_case": bounded_int(
            source.get("max_saved_batches_per_case"),
            label="max_saved_batches_per_case",
            default=DEFAULT_MAX_SAVED_BATCHES_PER_CASE,
            minimum=1,
            maximum=32,
        ),
    }


def _expiration(value: object) -> dt.datetime | None:
    expires_at = str(value or "").strip()
    if not expires_at:
        return None
    candidate = expires_at[:-1] + "+00:00" if expires_at.endswith("Z") else expires_at
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise LiveOsqueryClientError(
            "harness_operator_approval.expires_at must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise LiveOsqueryClientError(
            "harness_operator_approval.expires_at must include a timezone"
        )
    return parsed.astimezone(dt.timezone.utc)


def _harness_approval(
    source: dict[str, Any],
    aliases: list[str],
) -> dict[str, Any]:
    approval_source = source.get("harness_operator_approval") or {}
    if not isinstance(approval_source, dict):
        raise LiveOsqueryClientError("harness_operator_approval must be an object")
    approved = approval_source.get("approved", False)
    if not isinstance(approved, bool):
        raise LiveOsqueryClientError(
            "harness_operator_approval.approved must be boolean"
        )
    approval_aliases = _harness_aliases(approval_source, aliases)
    expiration = _expiration(approval_source.get("expires_at"))
    if approved and (not approval_aliases or expiration is None):
        raise LiveOsqueryClientError(
            "approved harness OSQuery requires target aliases and an expiration"
        )
    return {
        "approved": approved,
        "target_aliases": approval_aliases,
        "expires_at": (
            expiration.isoformat().replace("+00:00", "Z")
            if expiration is not None
            else ""
        ),
    }


def _harness_aliases(
    approval_source: dict[str, Any],
    aliases: list[str],
) -> list[str]:
    approval_aliases = normalize_target_aliases(
        approval_source.get("target_aliases") or []
    )
    if any(alias not in aliases for alias in approval_aliases):
        raise LiveOsqueryClientError(
            "harness operator approval contains an unconfigured target alias"
        )
    return approval_aliases


def _scheduled_approval(
    source: dict[str, Any],
    aliases: list[str],
) -> dict[str, Any]:
    scheduled_source = source.get("scheduled_inventory_approval") or {}
    if not isinstance(scheduled_source, dict):
        raise LiveOsqueryClientError("scheduled_inventory_approval must be an object")
    approved = scheduled_source.get("approved", False)
    if not isinstance(approved, bool):
        raise LiveOsqueryClientError(
            "scheduled_inventory_approval.approved must be boolean"
        )
    scheduled_aliases = normalize_target_aliases(
        scheduled_source.get("target_aliases") or []
    )
    if any(alias not in aliases for alias in scheduled_aliases):
        raise LiveOsqueryClientError(
            "scheduled inventory approval contains an unconfigured target alias"
        )
    return {"approved": approved, "target_aliases": scheduled_aliases}


def _enabled_transport(
    source: dict[str, Any],
    aliases: list[str],
    bindings: dict[str, dict[str, list[str]]],
) -> dict[str, Any]:
    host = str(source.get("relay_host") or "").strip()
    user = str(source.get("relay_user") or "").strip()
    if not SAFE_HOST.fullmatch(host):
        raise LiveOsqueryClientError("relay_host is missing or invalid")
    if not SAFE_USER.fullmatch(user):
        raise LiveOsqueryClientError("relay_user is missing or invalid")
    identity_file = Path(str(source.get("identity_file") or "")).expanduser()
    known_hosts = Path(str(source.get("known_hosts") or "")).expanduser()
    if not aliases:
        raise LiveOsqueryClientError(
            "enabled live OSQuery requires at least one endpoint target alias"
        )
    missing_bindings = sorted(set(aliases).difference(bindings))
    if missing_bindings:
        raise LiveOsqueryClientError(
            "enabled live OSQuery requires a trusted asset binding for every "
            "target alias: " + ", ".join(missing_bindings)
        )
    _require_transport_files(identity_file, known_hosts)
    return {
        "relay_host": host,
        "relay_user": user,
        "identity_file": identity_file,
        "known_hosts": known_hosts,
    }


def _require_transport_files(identity_file: Path, known_hosts: Path) -> None:
    for label, file_path in (
        ("identity_file", identity_file),
        ("known_hosts", known_hosts),
    ):
        if not file_path.is_file():
            raise LiveOsqueryClientError(
                f"{label} is not a regular file: {file_path}"
            )


def load_config(path: Path) -> dict[str, Any]:
    source = read_json(path.expanduser())
    enabled = source.get("enabled", False)
    if not isinstance(enabled, bool):
        raise LiveOsqueryClientError("enabled must be boolean")
    aliases = normalize_target_aliases(source.get("allowed_target_aliases") or [])
    roles = _allowed_roles(source)
    bindings = _target_bindings(source, aliases)
    config = _base_config(source, enabled, aliases, roles, bindings)
    config["harness_operator_approval"] = _harness_approval(source, aliases)
    config["scheduled_inventory_approval"] = _scheduled_approval(source, aliases)
    if not enabled:
        return config
    config.update(_enabled_transport(source, aliases, bindings))
    return config
