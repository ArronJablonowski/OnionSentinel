#!/usr/bin/env python3
"""One-time, verified migration of asset and DHCP JSON state into PostgreSQL."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from asset_inventory import validate_asset_inventory


HOME = Path.home()
DEFAULT_ENV = HOME / "n8n-local" / ".env"
DEFAULT_INVENTORY = HOME / "n8n-local" / "config" / "asset_inventory.json"
DEFAULT_DHCP = HOME / "n8n-local" / "asset-discovery" / "dhcp-observations.json"
DEFAULT_EXPORT = HOME / "n8n-local" / "config" / "asset_inventory.database-export.json"
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_DHCP_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


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
        raise ValueError(f"{path.name} must contain an object")
    return payload


def env_value(path: Path, key: str) -> str:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > 1024 * 1024
    ):
        raise ValueError("runtime environment file is not owner-controlled")
    values = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip()
    return values.get(key) or values.get("N8N_POST_COMMIT_TOKEN", "")


def request_json(
    url: str,
    *,
    method: str = "GET",
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
    req = urllib_request.Request(url, data=encoded, method=method, headers=headers)
    try:
        with urllib_request.urlopen(req, timeout=30) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib_error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail[:500]}") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError("asset-store response exceeded its byte limit")
    result = json.loads(body)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError("asset-store returned an invalid response")
    return result


def canonical(inventory: dict) -> list[dict]:
    validated = validate_asset_inventory(inventory)
    output = []
    for item in validated["assets"]:
        output.append({
            "asset_id": item["asset_id"],
            "valid_from": item["valid_from"],
            "valid_until": item["valid_until"],
            "identifiers": item["identifiers"],
            "role": item["role"],
            "platform": item["platform"],
            "owner_ref": item["owner_ref"],
            "criticality": item["criticality"],
            "expected_services": item["expected_services"],
            "expected_behaviors": item["expected_behaviors"],
            "source_type": item["source_type"],
            "source_ref": item["source_ref"],
            "confidence": item["confidence"],
            "share_with_hosted_models": item["share_with_hosted_models"],
        })
    return sorted(
        output,
        key=lambda item: (item["asset_id"], item["valid_from"]),
    )


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--dhcp-state", type=Path, default=DEFAULT_DHCP)
    parser.add_argument("--export", type=Path, default=DEFAULT_EXPORT)
    parser.add_argument("--api-url", default="http://127.0.0.1:8787")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    if args.confirm != "MIGRATE-ASSETS-TO-POSTGRESQL":
        raise SystemExit("exact migration confirmation is required")

    token = env_value(args.env, "ASSET_STORE_WRITE_TOKEN")
    if len(token) < 32:
        raise SystemExit("ASSET_STORE_WRITE_TOKEN is missing or too short")
    inventory = controlled_json(args.inventory, MAX_INVENTORY_BYTES)
    dhcp = controlled_json(args.dhcp_state, MAX_DHCP_BYTES)
    source_records = canonical(inventory)
    source_digest = digest(source_records)

    imported = request_json(
        f"{args.api_url.rstrip('/')}/assets/import",
        method="POST",
        token=token,
        payload={
            "inventory": inventory,
            "replace": args.replace,
            "actor": "verified-json-migration",
        },
    )
    dhcp_result = request_json(
        f"{args.api_url.rstrip('/')}/assets/dhcp-state",
        method="POST",
        token=token,
        payload={"state": dhcp, "actor": "verified-json-migration"},
    )
    snapshot_response = request_json(
        f"{args.api_url.rstrip('/')}/assets/snapshot"
    )
    snapshot = snapshot_response["inventory"]
    target_records = canonical(snapshot)
    target_digest = digest(target_records)
    if source_digest != target_digest or len(source_records) != len(target_records):
        raise SystemExit("PostgreSQL verification failed: asset snapshot differs")
    database_dhcp = request_json(
        f"{args.api_url.rstrip('/')}/assets/dhcp-state"
    )["state"]
    source_dhcp_ids = sorted(
        str(item.get("discovery_id") or "")
        for item in dhcp.get("observations", [])
    )
    target_dhcp_ids = sorted(
        str(item.get("discovery_id") or "")
        for item in database_dhcp.get("observations", [])
    )
    if source_dhcp_ids != target_dhcp_ids:
        raise SystemExit("PostgreSQL verification failed: DHCP identities differ")
    atomic_write(args.export, snapshot)
    print(json.dumps({
        "ok": True,
        "asset_records": len(target_records),
        "asset_digest": target_digest,
        "dhcp_observations": len(target_dhcp_ids),
        "imported": imported.get("imported"),
        "dhcp_retained": dhcp_result.get("retained"),
        "export": str(args.export),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
