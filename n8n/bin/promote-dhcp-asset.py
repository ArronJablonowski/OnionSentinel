#!/usr/bin/env python3
"""Promote one reviewed DHCP identity into operator-owned asset inventory."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from asset_inventory import MAX_INVENTORY_BYTES, validate_asset_inventory
from security_jsonl_log import SecurityJsonlLogger


MAX_STATE_BYTES = 8 * 1024 * 1024
DISCOVERY_ID_RE = re.compile(r"^[0-9a-f]{20}$")
DEFAULT_INVENTORY = Path.home() / "n8n-local" / "config" / "asset_inventory.json"
DEFAULT_STATE = Path.home() / "n8n-local" / "asset-discovery" / "dhcp-observations.json"
DEFAULT_LOG = Path.home() / "n8n-local" / "logs" / "dhcp-asset-review.jsonl"
DEFAULT_ENV = Path.home() / "n8n-local" / ".env"
DEFAULT_EXPORT = (
    Path.home()
    / "n8n-local"
    / "config"
    / "asset_inventory.database-export.json"
)
DEFAULT_API_URL = "http://127.0.0.1:8787"


def _validate_environment(path: Path, info: os.stat_result) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 1024 * 1024
    ):
        raise ValueError("runtime environment file is not owner-controlled")


def _environment_values(path: Path) -> dict[str, str]:
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _asset_store_write_token(values: dict[str, str]) -> str:
    token = values.get("ASSET_STORE_WRITE_TOKEN") or values.get(
        "N8N_POST_COMMIT_TOKEN"
    )
    if not token or len(token) < 32:
        raise ValueError("asset-store write token is missing or too short")
    return token


def env_token(path: Path) -> str:
    info = path.lstat()
    _validate_environment(path, info)
    return _asset_store_write_token(_environment_values(path))


def api_json(
    url: str,
    *,
    payload: dict | None = None,
    token: str = "",
) -> dict:
    encoded = (
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        if payload is not None
        else None
    )
    headers = {"Accept": "application/json"}
    if encoded is not None:
        headers.update({
            "Content-Type": "application/json",
            "Content-Length": str(len(encoded)),
            "X-Onion-Sentinel-Asset-Token": token,
        })
    request = urllib_request.Request(
        url,
        data=encoded,
        method="POST" if encoded is not None else "GET",
        headers=headers,
    )
    try:
        with urllib_request.urlopen(request, timeout=30) as response:
            body = response.read(MAX_INVENTORY_BYTES + 1)
    except urllib_error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise ValueError(f"asset database returned HTTP {exc.code}: {detail[:300]}") from exc
    except (OSError, urllib_error.URLError) as exc:
        raise ValueError(f"asset database is unavailable: {exc}") from exc
    if len(body) > MAX_INVENTORY_BYTES:
        raise ValueError("asset database response exceeded its byte limit")
    result = json.loads(body)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise ValueError("asset database returned an invalid response")
    return result


def timestamp(value: object) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks an offset")
    return parsed.astimezone(dt.timezone.utc)


def timestamp_text(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def controlled_json(path: Path, maximum: int) -> dict:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > maximum
    ):
        raise ValueError(f"{path.name} is not an owner-controlled bounded file")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return payload


def mac_scope(value: str) -> str:
    first_octet = int(value.split(":", 1)[0], 16)
    if first_octet & 1:
        return "multicast"
    if first_octet & 2:
        return "locally_administered"
    return "globally_administered"


def _matched_observation(state: dict, discovery_id: str) -> dict:
    if (
        state.get("schema") != "onion-sentinel-dhcp-asset-observations-v1"
        or not isinstance(state.get("observations"), list)
        or len(state["observations"]) > 5000
    ):
        raise ValueError("DHCP observation state failed schema validation")
    matches = [
        item
        for item in state["observations"]
        if isinstance(item, dict) and item.get("discovery_id") == discovery_id
    ]
    if len(matches) != 1:
        raise ValueError("DHCP discovery identity is missing or ambiguous")
    return matches[0]


def _observation_identity(item: dict) -> tuple[str, str, str]:
    current_ip = str(ipaddress.ip_address(str(item.get("current_ip") or "")))
    mac = str(item.get("mac_address") or "").strip().lower()
    hostname = str(item.get("hostname") or "").strip().rstrip(".").lower()
    return current_ip, mac, hostname


def _validate_observation_identity(
    identity: tuple[str, str, str],
    expected: tuple[str, str, str],
) -> None:
    current_ip, mac, hostname = identity
    expected_ip, expected_mac, expected_hostname = expected
    if (
        current_ip != expected_ip
        or mac != expected_mac
        or hostname != expected_hostname
    ):
        raise ValueError("DHCP identity changed after operator review")


def _validate_observation_freshness(
    item: dict,
    now: dt.datetime,
) -> None:
    last_seen = timestamp(item.get("last_seen"))
    lease_expires = (
        timestamp(item["lease_expires_at"])
        if item.get("lease_expires_at")
        else last_seen
    )
    if last_seen < now - dt.timedelta(hours=24) and lease_expires < now:
        raise ValueError("stale DHCP identity cannot be promoted")


def reviewed_observation(
    state: dict,
    *,
    discovery_id: str,
    expected_ip: str,
    expected_mac: str,
    expected_hostname: str,
    now: dt.datetime,
) -> dict:
    item = _matched_observation(state, discovery_id)
    identity = _observation_identity(item)
    _validate_observation_identity(
        identity,
        (expected_ip, expected_mac, expected_hostname),
    )
    _validate_observation_freshness(item, now)
    return item


def atomic_write(path: Path, payload: dict) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_INVENTORY_BYTES:
        raise ValueError("promoted inventory exceeds its byte limit")
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


def _normalized_discovery(args: argparse.Namespace) -> str:
    discovery_id = str(args.discovery_id or "").strip().lower()
    if not DISCOVERY_ID_RE.fullmatch(discovery_id):
        raise ValueError("invalid DHCP discovery id")
    if args.confirm != f"PROMOTE:{discovery_id}":
        raise ValueError("explicit PROMOTE:<discovery-id> confirmation is required")
    return discovery_id


def _normalized_expected_mac(args: argparse.Namespace) -> tuple[str, str]:
    expected_mac = str(args.expected_mac or "").strip().lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", expected_mac):
        raise ValueError("expected MAC address is invalid")
    scope = mac_scope(expected_mac)
    if scope == "multicast":
        raise ValueError("multicast MAC address cannot identify an asset")
    if scope == "locally_administered" and not args.accept_locally_administered_mac:
        raise ValueError(
            "locally administered MAC requires --accept-locally-administered-mac"
        )
    return expected_mac, scope


def _promotion_identity(args: argparse.Namespace) -> dict[str, str]:
    discovery_id = _normalized_discovery(args)
    expected_ip = str(ipaddress.ip_address(str(args.expected_ip or "").strip()))
    expected_mac, scope = _normalized_expected_mac(args)
    expected_hostname = str(args.expected_hostname or "").strip().rstrip(".").lower()
    hostname = str(args.hostname or expected_hostname).strip().rstrip(".").lower()
    return {
        "discovery_id": discovery_id,
        "expected_ip": expected_ip,
        "expected_mac": expected_mac,
        "scope": scope,
        "expected_hostname": expected_hostname,
        "hostname": hostname,
    }


def _open_legacy_lock(inventory_path: Path) -> int:
    lock_path = inventory_path.with_suffix(inventory_path.suffix + ".lock")
    lock_flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        lock_flags |= os.O_NOFOLLOW
    lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    os.fchmod(lock_descriptor, 0o600)
    return lock_descriptor


def _validate_authoritative_overlap(
    validated: dict,
    identity: dict[str, str],
) -> None:
    for asset in validated["assets"]:
        identifiers = asset["identifiers"]
        if (
            identity["expected_ip"] in identifiers["ip"]
            or identity["expected_mac"] in identifiers["mac"]
            or (
                identity["expected_hostname"]
                and identity["expected_hostname"] in identifiers["hostname"]
            )
        ):
            raise ValueError(
                f"DHCP identity overlaps authoritative asset {asset['asset_id']}"
            )


def _reviewed_legacy_inventory(
    args: argparse.Namespace,
    identity: dict[str, str],
    now: dt.datetime,
) -> tuple[dict, dict]:
    inventory = controlled_json(args.inventory, MAX_INVENTORY_BYTES)
    state = controlled_json(args.state, MAX_STATE_BYTES)
    item = reviewed_observation(
        state,
        discovery_id=identity["discovery_id"],
        expected_ip=identity["expected_ip"],
        expected_mac=identity["expected_mac"],
        expected_hostname=identity["expected_hostname"],
        now=now,
    )
    validated = validate_asset_inventory(inventory)
    _validate_authoritative_overlap(validated, identity)
    return inventory, item


def _promoted_asset(
    args: argparse.Namespace,
    identity: dict[str, str],
    now: dt.datetime,
) -> dict:
    return {
        "asset_id": args.asset_id,
        "valid_from": timestamp_text(now),
        "valid_until": None,
        "identifiers": {
            "ip_addresses": [identity["expected_ip"]],
            "mac_addresses": [identity["expected_mac"]],
            "hostnames": [identity["hostname"]] if identity["hostname"] else [],
        },
        "role": args.role,
        "platform": args.platform,
        "owner_ref": args.owner_ref,
        "criticality": args.criticality,
        "expected_services": [],
        "expected_behaviors": [],
        "source_type": "operator-approved-dhcp",
        "source_ref": (
            f"DHCP discovery {identity['discovery_id']}; "
            f"approved {timestamp_text(now)}"
        ),
        "confidence": "medium",
        "share_with_hosted_models": False,
    }


def _updated_inventory(inventory: dict, asset: dict, now: dt.datetime) -> dict:
    updated = dict(inventory)
    updated["generated_at"] = timestamp_text(now)
    updated["assets"] = list(inventory.get("assets") or []) + [asset]
    validate_asset_inventory(updated)
    return updated


def _backup_inventory(inventory_path: Path, now: dt.datetime) -> Path:
    backup = inventory_path.with_name(
        f"{inventory_path.name}.pre-dhcp-promotion-{now.strftime('%Y%m%dT%H%M%SZ')}"
    )
    backup_descriptor = os.open(
        backup,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        0o600,
    )
    with os.fdopen(backup_descriptor, "wb") as backup_file:
        backup_file.write(inventory_path.read_bytes())
        backup_file.flush()
        os.fsync(backup_file.fileno())
    return backup


def _legacy_result(
    args: argparse.Namespace,
    identity: dict[str, str],
    item: dict,
) -> dict:
    return {
        "asset_id": args.asset_id,
        "discovery_id": identity["discovery_id"],
        "ip_address": identity["expected_ip"],
        "mac_address": identity["expected_mac"],
        "mac_address_scope": identity["scope"],
        "hostname": identity["hostname"],
        "observation_count": int(item.get("observation_count") or 0),
    }


def _legacy_promotion(
    args: argparse.Namespace,
    identity: dict[str, str],
    now: dt.datetime,
) -> tuple[dict, Path]:
    lock_descriptor = _open_legacy_lock(args.inventory)
    with os.fdopen(lock_descriptor, "r+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        inventory, item = _reviewed_legacy_inventory(args, identity, now)
        new_asset = _promoted_asset(args, identity, now)
        updated = _updated_inventory(inventory, new_asset, now)
        backup = _backup_inventory(args.inventory, now)
        atomic_write(args.inventory, updated)
        return _legacy_result(args, identity, item), backup


def _database_payload(
    args: argparse.Namespace,
    identity: dict[str, str],
) -> dict:
    return {
        "discovery_id": identity["discovery_id"],
        "expected_ip": identity["expected_ip"],
        "expected_mac": identity["expected_mac"],
        "expected_hostname": identity["expected_hostname"],
        "asset_id": args.asset_id,
        "hostname": identity["hostname"],
        "role": args.role,
        "platform": args.platform,
        "owner_ref": args.owner_ref,
        "operator_ref": args.owner_ref,
        "criticality": args.criticality,
        "reason": "operator-approved DHCP promotion",
        "confirm": args.confirm,
        "accept_locally_administered_mac": args.accept_locally_administered_mac,
    }


def _database_result(
    args: argparse.Namespace,
    identity: dict[str, str],
    result: dict,
) -> dict:
    return {
        "asset_id": args.asset_id,
        "discovery_id": identity["discovery_id"],
        "ip_address": identity["expected_ip"],
        "mac_address": identity["expected_mac"],
        "mac_address_scope": identity["scope"],
        "hostname": identity["hostname"],
        "observation_fingerprint": result.get("observation_fingerprint"),
    }


def _database_promotion(
    args: argparse.Namespace,
    identity: dict[str, str],
) -> tuple[dict, Path]:
    token = env_token(args.env)
    result = api_json(
        f"{args.api_url.rstrip('/')}/assets/promote-dhcp",
        token=token,
        payload=_database_payload(args, identity),
    )
    snapshot = api_json(f"{args.api_url.rstrip('/')}/assets/snapshot").get(
        "inventory"
    )
    if not isinstance(snapshot, dict):
        raise ValueError("asset database snapshot is unavailable after promotion")
    validate_asset_inventory(snapshot)
    atomic_write(args.export, snapshot)
    return _database_result(args, identity, result), args.export


def promote(args: argparse.Namespace, now: dt.datetime) -> tuple[dict, Path]:
    identity = _promotion_identity(args)
    # Direct function callers from the offline DR/unit-test contract predate
    # the PostgreSQL CLI arguments. Keep that isolated path deterministic; the
    # installed command always receives env/export/api_url from argparse and
    # therefore cannot silently write the legacy JSON source of truth.
    if not all(hasattr(args, name) for name in ("env", "export", "api_url")):
        return _legacy_promotion(args, identity, now)
    return _database_promotion(args, identity)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--export", type=Path, default=DEFAULT_EXPORT)
    parser.add_argument("--api-url", default=DEFAULT_API_URL)
    parser.add_argument("--discovery-id", required=True)
    parser.add_argument("--expected-ip", required=True)
    parser.add_argument("--expected-mac", required=True)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--hostname", default="")
    parser.add_argument("--role", required=True)
    parser.add_argument("--platform", default="")
    parser.add_argument("--owner-ref", default="operator-reviewed")
    parser.add_argument(
        "--criticality",
        choices=("low", "medium", "high", "critical", "unknown"),
        default="unknown",
    )
    parser.add_argument("--accept-locally-administered-mac", action="store_true")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    logger = SecurityJsonlLogger(args.log, service="dhcp-asset-review")
    now = dt.datetime.now(dt.timezone.utc)
    try:
        result, export = promote(args, now)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        message = " ".join(str(exc).split())[:300]
        logger.log("error", "dhcp_asset_promotion.rejected", error=message)
        print(json.dumps({"ok": False, "error": message}, sort_keys=True))
        return 1
    logger.log(
        "info",
        "dhcp_asset_promotion.completed",
        asset_id=result["asset_id"],
        discovery_id=result["discovery_id"],
        mac_address_scope=result["mac_address_scope"],
    )
    print(json.dumps({
        "ok": True,
        "status": "promoted",
        **result,
        "database_export": str(export),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
