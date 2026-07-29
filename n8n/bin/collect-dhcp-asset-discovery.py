#!/usr/bin/env python3
"""Collect and retain bounded DHCP asset observations through the SSH relay."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path

from bounded_process import BoundedProcessError, run_bounded_command
from security_jsonl_log import SecurityJsonlLogger


CONTRACT = "onion-sentinel-dhcp-asset-discovery-v1"
STATE_SCHEMA = "onion-sentinel-dhcp-asset-observations-v1"
MAX_CONFIG_BYTES = 64 * 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_OBSERVATIONS = 5000
MAX_RESPONSE_OBSERVATIONS = 1000
HOME = Path.home()
DEFAULT_CONFIG = HOME / "n8n-local" / "config" / "dhcp-asset-discovery.json"
DEFAULT_STATE = HOME / "n8n-local" / "asset-discovery" / "dhcp-observations.json"
DEFAULT_LOG = HOME / "n8n-local" / "logs" / "dhcp-asset-discovery.jsonl"
HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})?))*\.?"
)
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
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


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks offset")
    return parsed.astimezone(dt.timezone.utc)


def format_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"DHCP discovery config {key} must be from {minimum} through {maximum}")
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
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
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


def validate_response(payload: object, expected_window: dict | None = None) -> dict:
    if not isinstance(payload, dict) or payload.get("ok") is not True or payload.get("contract") != CONTRACT:
        raise ValueError("relay response failed the DHCP discovery contract")
    observations = payload.get("observations")
    if not isinstance(observations, list) or len(observations) > MAX_RESPONSE_OBSERVATIONS:
        raise ValueError("relay response contains an invalid observation list")
    if payload.get("status") not in {"ok", "partial"}:
        raise ValueError("relay response contains an invalid status")
    hits_total = payload.get("hits_total")
    returned = payload.get("returned")
    if (
        isinstance(hits_total, bool)
        or not isinstance(hits_total, int)
        or hits_total < 0
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(observations)
        or not isinstance(payload.get("truncated"), bool)
    ):
        raise ValueError("relay response contains invalid result accounting")
    audit = payload.get("query_audit")
    if (
        not isinstance(audit, dict)
        or audit.get("index") != "logs-zeek-so"
        or audit.get("dataset") != "zeek.dhcp"
        or not re.fullmatch(r"[0-9a-f]{64}", str(audit.get("query_digest") or ""))
    ):
        raise ValueError("relay response contains an invalid fixed-query audit")
    response_window = payload.get("window")
    if not isinstance(response_window, dict) or set(response_window) != {"start", "end"}:
        raise ValueError("relay response contains an invalid query window")
    window_start = parse_timestamp(response_window["start"])
    window_end = parse_timestamp(response_window["end"])
    if window_start >= window_end or window_end - window_start > dt.timedelta(hours=24):
        raise ValueError("relay response query window is out of bounds")
    if expected_window is not None and (
        format_timestamp(window_start) != format_timestamp(parse_timestamp(expected_window["start"]))
        or format_timestamp(window_end) != format_timestamp(parse_timestamp(expected_window["end"]))
    ):
        raise ValueError("relay response query window does not match the request")
    cleaned = []
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("relay response contains a non-object observation")
        observed = parse_timestamp(item.get("observed_at"))
        if observed < window_start or observed > window_end + dt.timedelta(minutes=5):
            raise ValueError("relay response observation is outside the requested window")
        address = str(ipaddress.ip_address(str(item.get("ip_address") or "").strip()))
        mac_raw = str(item.get("mac_address") or "").strip()
        if mac_raw and not MAC_RE.fullmatch(mac_raw):
            raise ValueError("relay response contains an invalid MAC address")
        hostname_raw = str(item.get("hostname") or "").strip().rstrip(".").lower()
        if hostname_raw and not HOSTNAME_RE.fullmatch(hostname_raw):
            raise ValueError("relay response contains an invalid hostname")
        lease = item.get("lease_seconds", 0)
        if isinstance(lease, bool) or not isinstance(lease, int) or not 0 <= lease <= 31 * 24 * 60 * 60:
            raise ValueError("relay response contains an invalid lease duration")
        evidence_id = str(item.get("evidence_id") or "")
        if not re.fullmatch(r"[0-9a-f]{24}", evidence_id):
            raise ValueError("relay response contains an invalid evidence identifier")
        cleaned.append({
            "observed_at": format_timestamp(observed),
            "ip_address": address,
            "mac_address": mac_raw.lower(),
            "hostname": hostname_raw,
            "message_type": str(item.get("message_type") or "")[:80],
            "lease_seconds": lease,
            "sensor": str(item.get("sensor") or "")[:160],
            "evidence_id": evidence_id,
        })
    payload = dict(payload)
    payload["observations"] = cleaned
    return payload


def observation_identity(item: dict) -> tuple[str, str]:
    if item["mac_address"]:
        return "mac", item["mac_address"]
    if item["hostname"]:
        return "hostname", item["hostname"]
    return "ip", item["ip_address"]


def merge_observations(state: dict, incoming: list[dict], now: dt.datetime, retention_days: int) -> list[dict]:
    records: dict[tuple[str, str], dict] = {}
    for raw in state.get("observations", []):
        if not isinstance(raw, dict):
            continue
        identity_type = str(raw.get("identity_type") or "")
        identity_value = str(raw.get("identity_value") or "")
        if identity_type in {"mac", "hostname", "ip"} and identity_value:
            records[(identity_type, identity_value)] = dict(raw)
    for item in sorted(incoming, key=lambda value: (value["observed_at"], value["evidence_id"])):
        identity_type, identity_value = observation_identity(item)
        key = (identity_type, identity_value)
        record = records.get(key)
        observed = parse_timestamp(item["observed_at"])
        lease_expires = observed + dt.timedelta(seconds=item["lease_seconds"])
        if record is None:
            record = {
                "discovery_id": hashlib.sha256(f"{identity_type}\0{identity_value}".encode("utf-8")).hexdigest()[:20],
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
            records[key] = record
        if item["evidence_id"] in (record.get("evidence_ids") or []):
            continue
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
        record["ip_addresses"] = sorted(
            set(list(record.get("ip_addresses") or []) + [item["ip_address"]])
        )[-32:]
        record["hostnames"] = sorted(
            set(
                list(record.get("hostnames") or [])
                + ([item["hostname"]] if item["hostname"] else [])
            )
        )[-32:]
        record["message_types"] = sorted(
            set(
                list(record.get("message_types") or [])
                + ([item["message_type"]] if item["message_type"] else [])
            )
        )[-16:]
        record["sensors"] = sorted(
            set(
                list(record.get("sensors") or [])
                + ([item["sensor"]] if item["sensor"] else [])
            )
        )[-16:]
        record["evidence_ids"] = (list(record.get("evidence_ids") or []) + [item["evidence_id"]])[-32:]
        record["observation_count"] = int(record.get("observation_count") or 0) + 1
    cutoff = now - dt.timedelta(days=retention_days)
    retained = []
    for record in records.values():
        try:
            if parse_timestamp(record["last_seen"]) >= cutoff:
                retained.append(record)
        except (TypeError, ValueError):
            continue
    retained.sort(key=lambda item: (item["last_seen"], item["discovery_id"]), reverse=True)
    return retained[:MAX_OBSERVATIONS]


def collection_window(state: dict, now: dt.datetime, default_minutes: int) -> tuple[dt.datetime, dt.datetime]:
    start = now - dt.timedelta(minutes=default_minutes)
    last_success = state.get("collection", {}).get("last_success_at")
    if last_success:
        try:
            start = max(now - dt.timedelta(hours=24), parse_timestamp(last_success) - dt.timedelta(minutes=5))
        except (TypeError, ValueError):
            pass
    return start, now


def query_dhcp(config: dict, start: dt.datetime, end: dt.datetime, size: int) -> dict:
    """Run one bounded, read-only DHCP query through the forced Relay lane."""
    start = start.astimezone(dt.timezone.utc)
    end = end.astimezone(dt.timezone.utc)
    if start >= end or end - start > dt.timedelta(hours=24):
        raise ValueError("DHCP query window must be positive and no longer than 24 hours")
    if end > utc_now() + dt.timedelta(minutes=5):
        raise ValueError("DHCP query window ends too far in the future")
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_RESPONSE_OBSERVATIONS:
        raise ValueError("DHCP query size must be from 1 through 1000")
    request = {
        "contract": CONTRACT,
        "operation": "dhcp_observations",
        "window": {"start": format_timestamp(start), "end": format_timestamp(end)},
        "size": size,
    }
    command = [
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", f"ConnectTimeout={config['connect_timeout_seconds']}",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={config['known_hosts']}",
        "-i", config["ssh_key"],
        f"{config['ssh_user']}@{config['host']}",
    ]
    proc = run_bounded_command(
        command,
        input_bytes=json.dumps(request, separators=(",", ":")).encode("utf-8"),
        timeout_seconds=config["timeout_seconds"],
        max_stdout_bytes=config["max_response_bytes"],
        max_stderr_bytes=config["max_stderr_bytes"],
    )
    if proc.returncode != 0:
        detail = " ".join(proc.stderr.decode("utf-8", "replace").split())[:300]
        raise RuntimeError(f"relay returned {proc.returncode}: {detail or 'no diagnostic'}")
    return validate_response(
        json.loads(proc.stdout.decode("utf-8")),
        expected_window=request["window"],
    )


def collect(config: dict, state: dict, now: dt.datetime) -> dict:
    start, end = collection_window(state, now, config["query_window_minutes"])
    response = query_dhcp(config, start, end, config["query_size"])
    observations = merge_observations(state, response["observations"], now, config["retention_days"])
    result = dict(state)
    result.update({
        "schema": STATE_SCHEMA,
        "version": 1,
        "updated_at": format_timestamp(now),
        "observations": observations,
    })
    result["collection"] = {
        "status": "partial" if response.get("status") == "partial" or response.get("truncated") else "ok",
        "last_attempt_at": format_timestamp(now),
        "last_success_at": format_timestamp(now),
        "last_error": "",
        "last_window": response.get("window") if isinstance(response.get("window"), dict) else request["window"],
        "last_returned": len(response["observations"]),
        "last_hits_total": int(response.get("hits_total") or 0),
        "last_truncated": bool(response.get("truncated")),
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = parser.parse_args()
    logger = SecurityJsonlLogger(args.log, service="dhcp-asset-discovery")
    attempted_at = utc_now()
    try:
        config = load_config(args.config)
        state = load_state(args.state)
        if not config["enabled"]:
            state["updated_at"] = format_timestamp(attempted_at)
            state["collection"] = {
                **state.get("collection", {}),
                "status": "disabled",
                "last_attempt_at": format_timestamp(attempted_at),
                "last_error": "",
            }
            atomic_write_json(args.state, state)
            logger.log("info", "dhcp_asset_discovery.disabled", state_file=str(args.state))
            return 0
        updated = collect(config, state, attempted_at)
        atomic_write_json(args.state, updated)
        logger.log(
            "info",
            "dhcp_asset_discovery.completed",
            status=updated["collection"]["status"],
            returned=updated["collection"]["last_returned"],
            retained=len(updated["observations"]),
            truncated=updated["collection"]["last_truncated"],
        )
        return 0
    except (BoundedProcessError, OSError, UnicodeError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        message = " ".join(str(exc).split())[:300]
        try:
            state = load_state(args.state)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            state = empty_state()
        state["updated_at"] = format_timestamp(attempted_at)
        state["collection"] = {
            **state.get("collection", {}),
            "status": "failed",
            "last_attempt_at": format_timestamp(attempted_at),
            "last_error": message,
        }
        try:
            atomic_write_json(args.state, state)
        except (OSError, ValueError):
            pass
        logger.log("error", "dhcp_asset_discovery.failed", error=message, state_file=str(args.state))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
