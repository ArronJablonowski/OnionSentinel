#!/usr/bin/env python3
"""Load and resolve bounded, time-aware asset facts for AI investigations.

The inventory is operator-owned runtime configuration. Resolution is exact and
deterministic: an address, MAC, or hostname is associated with an asset only
when the identifier is registered for the alert timestamp. Expected services
and behaviors are context, never proof that observed activity was authorized.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ASSET_INVENTORY_SCHEMA = "onion-sentinel-asset-inventory-v1"
MAX_INVENTORY_BYTES = 1024 * 1024
MAX_ASSETS = 5000
MAX_IDENTIFIERS_PER_TYPE = 128
MAX_EXPECTATIONS = 64
MAX_NORMALIZED_OBSERVABLES = 512
MAX_NETWORK_EVENTS = 512
MAX_MATCHED_ASSETS = 256
MAX_MATCHED_OBSERVABLES_PER_ASSET = 128
MAX_CONFLICTS = 128
MAX_CONFLICT_ASSET_IDS = 32
MAX_EXPECTATION_MATCHES = 128
ASSET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
CONFIDENCE_VALUES = {"low", "medium", "high"}
CRITICALITY_VALUES = {"low", "medium", "high", "critical", "unknown"}
PROTOCOL_VALUES = {"tcp", "udp", "icmp", "icmpv6", "any"}
OBSERVABLE_TYPES = {"ip", "mac", "hostname"}


def _bounded_string(value: object, *, field: str, maximum: int = 300) -> str:
    text = str(value or "").strip()
    if len(text) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    return text


def _timestamp(value: object, *, field: str, required: bool = False) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        if required:
            raise ValueError(f"{field} is required")
        return None
    normalized = re.sub(r"(?<=\d)\s+(?=\d{2}:)", "T", text, count=1)
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{field} is not a valid ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def _timestamp_text(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError as error:
        raise ValueError(f"invalid IP address: {value}") from error


def _normalize_mac(value: object) -> str:
    text = str(value or "").strip()
    if not MAC_RE.fullmatch(text):
        raise ValueError(f"invalid MAC address: {value}")
    return text.replace("-", ":").lower()


def _normalize_hostname(value: object) -> str:
    text = str(value or "").strip().rstrip(".").lower()
    if not HOSTNAME_RE.fullmatch(text):
        raise ValueError(f"invalid hostname: {value}")
    return text


def normalize_observable(observable_type: str, value: object) -> str:
    if observable_type == "ip":
        return _normalize_ip(value)
    if observable_type == "mac":
        return _normalize_mac(value)
    if observable_type == "hostname":
        return _normalize_hostname(value)
    raise ValueError(f"unsupported observable type: {observable_type}")


def _identifier_list(raw: object, *, observable_type: str, field: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{field} must be a list")
    if len(raw) > MAX_IDENTIFIERS_PER_TYPE:
        raise ValueError(f"{field} exceeds {MAX_IDENTIFIERS_PER_TYPE} entries")
    normalized: list[str] = []
    for value in raw:
        item = normalize_observable(observable_type, value)
        if item not in normalized:
            normalized.append(item)
    return normalized


def _string_list(raw: object, *, field: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{field} must be a list")
    if len(raw) > MAX_EXPECTATIONS:
        raise ValueError(f"{field} exceeds {MAX_EXPECTATIONS} entries")
    result: list[str] = []
    for value in raw:
        item = _bounded_string(value, field=field, maximum=500)
        if item and item not in result:
            result.append(item)
    return result


def _expected_services(raw: object, *, asset_id: str) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{asset_id}.expected_services must be a list")
    if len(raw) > MAX_EXPECTATIONS:
        raise ValueError(f"{asset_id}.expected_services exceeds {MAX_EXPECTATIONS} entries")
    services = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"{asset_id}.expected_services[{index}] must be an object")
        protocol = str(item.get("protocol") or "").strip().lower()
        if protocol not in PROTOCOL_VALUES:
            raise ValueError(f"{asset_id}.expected_services[{index}].protocol is invalid")
        try:
            port = int(item.get("port")) if item.get("port") is not None else None
        except (TypeError, ValueError) as error:
            raise ValueError(f"{asset_id}.expected_services[{index}].port is invalid") from error
        if protocol in {"tcp", "udp", "any"}:
            if port is None or port < 0 or port > 65535:
                raise ValueError(f"{asset_id}.expected_services[{index}].port must be 0..65535")
        elif port is not None:
            raise ValueError(f"{asset_id}.expected_services[{index}].port must be omitted for ICMP")
        services.append(
            {
                "protocol": protocol,
                "port": port,
                "purpose": _bounded_string(
                    item.get("purpose"),
                    field=f"{asset_id}.expected_services[{index}].purpose",
                    maximum=300,
                ),
            }
        )
    return services


def validate_asset_inventory(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != ASSET_INVENTORY_SCHEMA:
        raise ValueError("unsupported asset inventory schema")
    if payload.get("version", 1) != 1:
        raise ValueError("unsupported asset inventory version")
    raw_assets = payload.get("assets")
    if not isinstance(raw_assets, list):
        raise ValueError("asset inventory assets must be a list")
    if len(raw_assets) > MAX_ASSETS:
        raise ValueError(f"asset inventory exceeds {MAX_ASSETS} records")
    assets = []
    records_by_asset_id: dict[str, list[tuple[dt.datetime, dt.datetime | None]]] = {}
    for index, item in enumerate(raw_assets):
        if not isinstance(item, dict):
            raise ValueError(f"assets[{index}] must be an object")
        asset_id = _bounded_string(item.get("asset_id"), field=f"assets[{index}].asset_id", maximum=128)
        if not ASSET_ID_RE.fullmatch(asset_id):
            raise ValueError(f"assets[{index}].asset_id is invalid")
        valid_from = _timestamp(item.get("valid_from"), field=f"{asset_id}.valid_from", required=True)
        valid_until = _timestamp(item.get("valid_until"), field=f"{asset_id}.valid_until")
        if valid_until is not None and valid_from is not None and valid_until <= valid_from:
            raise ValueError(f"{asset_id}.valid_until must be after valid_from")
        assert valid_from is not None
        for previous_from, previous_until in records_by_asset_id.setdefault(asset_id, []):
            previous_end = previous_until or dt.datetime.max.replace(tzinfo=dt.timezone.utc)
            current_end = valid_until or dt.datetime.max.replace(tzinfo=dt.timezone.utc)
            if valid_from < previous_end and previous_from < current_end:
                raise ValueError(f"{asset_id} has overlapping validity intervals")
        records_by_asset_id[asset_id].append((valid_from, valid_until))
        identifiers = item.get("identifiers")
        if not isinstance(identifiers, dict):
            raise ValueError(f"{asset_id}.identifiers must be an object")
        normalized_identifiers = {
            "ip": _identifier_list(
                identifiers.get("ip_addresses"),
                observable_type="ip",
                field=f"{asset_id}.identifiers.ip_addresses",
            ),
            "mac": _identifier_list(
                identifiers.get("mac_addresses"),
                observable_type="mac",
                field=f"{asset_id}.identifiers.mac_addresses",
            ),
            "hostname": _identifier_list(
                identifiers.get("hostnames"),
                observable_type="hostname",
                field=f"{asset_id}.identifiers.hostnames",
            ),
        }
        if not any(normalized_identifiers.values()):
            raise ValueError(f"{asset_id} must register at least one identifier")
        confidence = str(item.get("confidence") or "medium").strip().lower()
        if confidence not in CONFIDENCE_VALUES:
            raise ValueError(f"{asset_id}.confidence is invalid")
        criticality = str(item.get("criticality") or "unknown").strip().lower()
        if criticality not in CRITICALITY_VALUES:
            raise ValueError(f"{asset_id}.criticality is invalid")
        share_with_hosted = item.get("share_with_hosted_models", False)
        if not isinstance(share_with_hosted, bool):
            raise ValueError(f"{asset_id}.share_with_hosted_models must be boolean")
        assets.append(
            {
                "asset_id": asset_id,
                "valid_from": _timestamp_text(valid_from),
                "valid_until": _timestamp_text(valid_until),
                "identifiers": normalized_identifiers,
                "role": _bounded_string(item.get("role"), field=f"{asset_id}.role"),
                "platform": _bounded_string(item.get("platform"), field=f"{asset_id}.platform"),
                "owner_ref": _bounded_string(item.get("owner_ref"), field=f"{asset_id}.owner_ref"),
                "criticality": criticality,
                "expected_services": _expected_services(item.get("expected_services"), asset_id=asset_id),
                "expected_behaviors": _string_list(
                    item.get("expected_behaviors"),
                    field=f"{asset_id}.expected_behaviors",
                ),
                "source_type": _bounded_string(item.get("source_type"), field=f"{asset_id}.source_type"),
                "source_ref": _bounded_string(item.get("source_ref"), field=f"{asset_id}.source_ref"),
                "confidence": confidence,
                "share_with_hosted_models": share_with_hosted,
            }
        )
    return {
        "schema": ASSET_INVENTORY_SCHEMA,
        "version": payload.get("version", 1),
        "generated_at": _bounded_string(payload.get("generated_at"), field="generated_at", maximum=80),
        "assets": assets,
    }


def load_asset_inventory(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_INVENTORY_BYTES:
            raise ValueError("asset inventory exceeds its byte limit")
        with path.open("rb") as handle:
            raw = handle.read(MAX_INVENTORY_BYTES + 1)
    except FileNotFoundError:
        return {
            "schema": ASSET_INVENTORY_SCHEMA,
            "version": 0,
            "generated_at": "",
            "assets": [],
            "inventory_status": "missing",
        }
    if len(raw) > MAX_INVENTORY_BYTES:
        raise ValueError("asset inventory exceeds its byte limit")
    payload = json.loads(raw.decode("utf-8"))
    validated = validate_asset_inventory(payload)
    validated["inventory_status"] = "loaded"
    return validated


def _record_active(asset: dict[str, Any], observed_at: dt.datetime) -> bool:
    valid_from = _timestamp(asset.get("valid_from"), field="valid_from", required=True)
    valid_until = _timestamp(asset.get("valid_until"), field="valid_until")
    return bool(valid_from and valid_from <= observed_at and (valid_until is None or observed_at < valid_until))


def _normalized_observables(observables: Iterable[object]) -> list[dict[str, str]]:
    normalized = []
    seen = set()
    for item in observables:
        if not isinstance(item, dict):
            continue
        observable_type = str(item.get("type") or "").strip().lower()
        if observable_type not in OBSERVABLE_TYPES:
            continue
        try:
            value = normalize_observable(observable_type, item.get("value"))
        except ValueError:
            continue
        role = _bounded_string(item.get("role"), field="observable role", maximum=80)
        key = (observable_type, value, role)
        if key not in seen:
            seen.add(key)
            normalized.append({"type": observable_type, "value": value, "role": role})
        if len(normalized) >= MAX_NORMALIZED_OBSERVABLES:
            break
    return normalized


def _normalized_network_events(
    network_events: Iterable[object],
) -> tuple[list[dict[str, Any]], bool]:
    normalized: list[dict[str, Any]] = []
    truncated = False
    for raw_event in network_events:
        if len(normalized) >= MAX_NETWORK_EVENTS:
            truncated = True
            break
        if not isinstance(raw_event, dict):
            continue
        try:
            destination_ip = _normalize_ip(raw_event.get("destination_ip"))
            destination_port = int(raw_event.get("destination_port"))
        except (ValueError, TypeError):
            continue
        if destination_port < 0 or destination_port > 65535:
            continue
        protocol = str(raw_event.get("protocol") or "any").strip().lower()
        if protocol not in PROTOCOL_VALUES:
            continue
        normalized.append(
            {
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": protocol,
            }
        )
    return normalized, truncated


def resolve_asset_context(
    inventory: dict[str, Any],
    observables: Iterable[object],
    observed_at: object,
    network_events: Iterable[object] = (),
) -> dict[str, Any]:
    try:
        event_time = _timestamp(observed_at, field="observed_at", required=True)
    except ValueError as error:
        return {
            "inventory_status": inventory.get("inventory_status", "loaded"),
            "resolution_status": "event_time_invalid",
            "observed_at": str(observed_at or ""),
            "matched_assets": [],
            "conflicts": [],
            "unmatched_observables": _normalized_observables(observables),
            "errors": [str(error)],
            "usage_guidance": "No asset association was made because the event timestamp was invalid.",
        }
    normalized = _normalized_observables(observables)
    normalized_events, network_events_truncated = _normalized_network_events(network_events)
    relevant_keys = {
        (observable["type"], observable["value"])
        for observable in normalized
    }
    relevant_keys.update(
        ("ip", event["destination_ip"])
        for event in normalized_events
    )
    lookup: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for asset in inventory.get("assets", []) if isinstance(inventory.get("assets"), list) else []:
        if not isinstance(asset, dict) or event_time is None or not _record_active(asset, event_time):
            continue
        identifiers = asset.get("identifiers") if isinstance(asset.get("identifiers"), dict) else {}
        for observable_type in OBSERVABLE_TYPES:
            for value in identifiers.get(observable_type, []) if isinstance(identifiers.get(observable_type), list) else []:
                key = (observable_type, str(value))
                if key in relevant_keys:
                    lookup.setdefault(key, []).append(asset)

    matches_by_asset: dict[str, dict[str, Any]] = {}
    unmatched = []
    conflicts = []
    omitted_matched_assets: set[str] = set()
    omitted_conflicts = 0
    for observable in normalized:
        matching_assets = lookup.get((observable["type"], observable["value"]), [])
        if not matching_assets:
            unmatched.append(observable)
            continue
        if len(matching_assets) > 1:
            if len(conflicts) < MAX_CONFLICTS:
                active_asset_ids = sorted(
                    {
                        str(asset.get("asset_id") or "")
                        for asset in matching_assets
                        if str(asset.get("asset_id") or "")
                    }
                )
                conflicts.append(
                    {
                        "observable": observable,
                        "active_asset_ids": active_asset_ids[:MAX_CONFLICT_ASSET_IDS],
                        "active_asset_count": len(active_asset_ids),
                        "active_asset_ids_truncated": len(active_asset_ids) > MAX_CONFLICT_ASSET_IDS,
                        "reason": "multiple asset records claim the same identifier at the event time",
                    }
                )
            else:
                omitted_conflicts += 1
        for asset in matching_assets:
            asset_id = str(asset["asset_id"])
            if asset_id not in matches_by_asset and len(matches_by_asset) >= MAX_MATCHED_ASSETS:
                omitted_matched_assets.add(asset_id)
                continue
            current = matches_by_asset.setdefault(
                asset_id,
                {
                    key: value
                    for key, value in asset.items()
                    if key not in {"identifiers"}
                }
                | {"matched_observables": []},
            )
            if len(current["matched_observables"]) < MAX_MATCHED_OBSERVABLES_PER_ASSET:
                current["matched_observables"].append(observable)

    expectation_matches = []
    expectation_matches_truncated = False
    for raw_event in normalized_events:
        destination_ip = raw_event["destination_ip"]
        destination_port = raw_event["destination_port"]
        protocol = raw_event["protocol"]
        for asset in lookup.get(("ip", destination_ip), []):
            for service in asset.get("expected_services", []) if isinstance(asset.get("expected_services"), list) else []:
                if not isinstance(service, dict):
                    continue
                service_protocol = str(service.get("protocol") or "")
                registered_port = service.get("port")
                if registered_port is None or int(registered_port) != destination_port:
                    continue
                if service_protocol not in {"any", protocol}:
                    continue
                if len(expectation_matches) >= MAX_EXPECTATION_MATCHES:
                    expectation_matches_truncated = True
                    break
                expectation_matches.append(
                    {
                        "asset_id": asset.get("asset_id"),
                        "destination_ip": destination_ip,
                        "destination_port": destination_port,
                        "protocol": protocol,
                        "registered_purpose": service.get("purpose"),
                        "interpretation": "registered expected service; this does not prove the activity was authorized or benign",
                    }
                )
            if expectation_matches_truncated:
                break
        if expectation_matches_truncated:
            break

    return {
        "inventory_status": inventory.get("inventory_status", "loaded"),
        "resolution_status": "resolved",
        "observed_at": _timestamp_text(event_time),
        "matched_assets": sorted(matches_by_asset.values(), key=lambda asset: str(asset["asset_id"])),
        "registered_expectation_matches": expectation_matches,
        "conflicts": conflicts,
        "unmatched_observables": unmatched,
        "truncation": {
            "network_events": network_events_truncated,
            "matched_assets": bool(omitted_matched_assets),
            "omitted_matched_asset_count": len(omitted_matched_assets),
            "conflicts": omitted_conflicts > 0,
            "omitted_conflict_count": omitted_conflicts,
            "registered_expectation_matches": expectation_matches_truncated,
        },
        "usage_guidance": (
            "Asset records are time-scoped operator assertions. Use roles, ownership aliases, criticality, and "
            "registered expectations as context only. They do not prove identity, authorization, benignness, or maliciousness."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    """Validate one inventory without printing its potentially sensitive facts."""
    parser = argparse.ArgumentParser(
        description="Validate an Onion Sentinel asset inventory JSON file.",
    )
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args(argv)
    try:
        inventory = load_asset_inventory(args.inventory)
        if inventory.get("inventory_status") != "loaded":
            raise ValueError("asset inventory file does not exist")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"invalid asset inventory: {exc}", file=sys.stderr)
        return 1
    print(
        "valid Onion Sentinel asset inventory: "
        f"{len(inventory.get('assets') or [])} record(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
