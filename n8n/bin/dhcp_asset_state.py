#!/usr/bin/env python3
"""Owner-controlled DHCP discovery configuration and state storage."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tempfile
from pathlib import Path

from dhcp_asset_contract import (
    MAX_RESPONSE_OBSERVATIONS,
    STATE_SCHEMA,
    format_timestamp,
    observation_identity,
    parse_timestamp,
)


MAX_CONFIG_BYTES = 64 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_OBSERVATIONS = 5000
CONFIG_KEYS = {
    "enabled",
    "host",
    "ssh_user",
    "ssh_key",
    "known_hosts",
    "connect_timeout_seconds",
    "timeout_seconds",
    "max_response_bytes",
    "max_stderr_bytes",
    "query_window_minutes",
    "query_size",
    "retention_days",
}


def bounded_json(path: Path, maximum_bytes: int) -> object:
    metadata = path.stat()
    if not path.is_file() or metadata.st_size > maximum_bytes:
        raise ValueError(f"{path.name} is not a bounded regular file")
    return json.loads(path.read_text(encoding="utf-8"))


def load_config(path: Path) -> dict:
    config = bounded_json(path, MAX_CONFIG_BYTES)
    if not isinstance(config, dict) or set(config) - CONFIG_KEYS:
        raise ValueError("DHCP discovery config contains unsupported fields")
    if not isinstance(config.get("enabled"), bool):
        raise ValueError("DHCP discovery config requires a boolean enabled field")
    for key in ("host", "ssh_user", "ssh_key", "known_hosts"):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise ValueError(f"DHCP discovery config requires {key}")
    numeric_limits = {
        "connect_timeout_seconds": (1, 120),
        "timeout_seconds": (5, 300),
        "max_response_bytes": (1024, 4 * 1024 * 1024),
        "max_stderr_bytes": (1024, 128 * 1024),
        "query_window_minutes": (5, 24 * 60),
        "query_size": (1, MAX_RESPONSE_OBSERVATIONS),
        "retention_days": (1, 365),
    }
    for key, (minimum, maximum) in numeric_limits.items():
        value = config.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not minimum <= value <= maximum
        ):
            raise ValueError(
                f"DHCP discovery config {key} must be from {minimum} through {maximum}"
            )
    config["ssh_key"] = str(Path(config["ssh_key"]).expanduser())
    config["known_hosts"] = str(Path(config["known_hosts"]).expanduser())
    return config


def empty_state(status: str = "never_run") -> dict:
    return {
        "schema": STATE_SCHEMA,
        "version": 1,
        "updated_at": "",
        "collection": {
            "status": status,
            "last_attempt_at": "",
            "last_success_at": "",
            "last_error": "",
            "last_window": {},
            "last_returned": 0,
            "last_hits_total": 0,
            "last_truncated": False,
            "last_query_segments": 0,
        },
        "observations": [],
    }


def load_state(path: Path) -> dict:
    try:
        state = bounded_json(path, MAX_STATE_BYTES)
    except FileNotFoundError:
        return empty_state()
    if (
        not isinstance(state, dict)
        or state.get("schema") != STATE_SCHEMA
        or not isinstance(state.get("collection"), dict)
        or not isinstance(state.get("observations"), list)
        or len(state["observations"]) > MAX_OBSERVATIONS
    ):
        raise ValueError("DHCP observation state failed schema validation")
    return state


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("DHCP observation state exceeds its byte limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _new_record(
    identity_type: str,
    identity_value: str,
    item: dict,
) -> dict:
    return {
        "discovery_id": hashlib.sha256(
            f"{identity_type}\0{identity_value}".encode("utf-8")
        ).hexdigest()[:20],
        "identity_type": identity_type,
        "identity_value": identity_value,
        "current_ip": item["ip_address"],
        "ip_addresses": [],
        "mac_address": item["mac_address"],
        "hostname": item["hostname"],
        "hostnames": [],
        "first_seen": item["observed_at"],
        "last_seen": item["observed_at"],
        "lease_expires_at": "",
        "message_types": [],
        "sensors": [],
        "evidence_ids": [],
        "observation_count": 0,
    }


def _bounded_union(record: dict, key: str, value: str, maximum: int) -> None:
    values = list(record.get(key) or [])
    if value:
        values.append(value)
    record[key] = sorted(set(values))[-maximum:]


def _merge_one(records: dict[tuple[str, str], dict], item: dict) -> None:
    identity_type, identity_value = observation_identity(item)
    key = (identity_type, identity_value)
    record = records.get(key)
    observed = parse_timestamp(item["observed_at"])
    lease_expires = observed + dt.timedelta(seconds=item["lease_seconds"])
    if record is None:
        record = _new_record(identity_type, identity_value, item)
        records[key] = record
    if item["evidence_id"] in (record.get("evidence_ids") or []):
        return
    if observed >= parse_timestamp(record["last_seen"]):
        record["current_ip"] = item["ip_address"]
        record["last_seen"] = item["observed_at"]
        if item["mac_address"]:
            record["mac_address"] = item["mac_address"]
        if item["hostname"]:
            record["hostname"] = item["hostname"]
        if item["lease_seconds"]:
            record["lease_expires_at"] = format_timestamp(lease_expires)
    record["first_seen"] = min(str(record["first_seen"]), item["observed_at"])
    _bounded_union(record, "ip_addresses", item["ip_address"], 32)
    _bounded_union(record, "hostnames", item["hostname"], 32)
    _bounded_union(record, "message_types", item["message_type"], 16)
    _bounded_union(record, "sensors", item["sensor"], 16)
    record["evidence_ids"] = (
        list(record.get("evidence_ids") or []) + [item["evidence_id"]]
    )[-32:]
    record["observation_count"] = int(record.get("observation_count") or 0) + 1


def merge_observations(
    state: dict,
    incoming: list[dict],
    now: dt.datetime,
    retention_days: int,
) -> list[dict]:
    records: dict[tuple[str, str], dict] = {}
    for raw in state.get("observations", []):
        if not isinstance(raw, dict):
            continue
        identity_type = str(raw.get("identity_type") or "")
        identity_value = str(raw.get("identity_value") or "")
        if identity_type in {"mac", "hostname", "ip"} and identity_value:
            records[(identity_type, identity_value)] = dict(raw)
    for item in sorted(
        incoming,
        key=lambda value: (value["observed_at"], value["evidence_id"]),
    ):
        _merge_one(records, item)
    cutoff = now - dt.timedelta(days=retention_days)
    retained = []
    for record in records.values():
        try:
            if parse_timestamp(record["last_seen"]) >= cutoff:
                retained.append(record)
        except (TypeError, ValueError):
            continue
    retained.sort(
        key=lambda item: (item["last_seen"], item["discovery_id"]),
        reverse=True,
    )
    return retained[:MAX_OBSERVATIONS]
