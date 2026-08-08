"""Pure Asset Inventory projection and response composition."""
from __future__ import annotations

import datetime as dt
from http import HTTPStatus
import ipaddress
from typing import Callable


Query = dict[str, list[str]]
TimestampParser = Callable[[object], dt.datetime]


def asset_record_state(
    asset: dict,
    observed_at: dt.datetime,
    parse_timestamp: TimestampParser,
) -> str:
    """Classify one validated inventory record at an event time."""
    try:
        valid_from = parse_timestamp(asset.get("valid_from"))
        valid_until = (
            parse_timestamp(asset.get("valid_until"))
            if asset.get("valid_until") else None
        )
    except (TypeError, ValueError):
        return "invalid"
    if valid_from.tzinfo is None:
        return "invalid"
    if observed_at < valid_from:
        return "scheduled"
    if valid_until is not None and observed_at >= valid_until:
        return "expired"
    return "current"


def asset_public_record(asset: dict, state: str) -> dict:
    """Expose operational identity fields while withholding private notes."""
    identifiers = asset.get("identifiers")
    identifiers = identifiers if isinstance(identifiers, dict) else {}
    return {
        "asset_id": _text(asset, "asset_id"),
        "state": state,
        "ip_addresses": _identifier_values(identifiers, "ip"),
        "hostnames": _identifier_values(identifiers, "hostname"),
        "mac_addresses": _identifier_values(identifiers, "mac"),
        "role": _text(asset, "role"),
        "platform": _text(asset, "platform"),
        "criticality": _text(asset, "criticality", "unknown"),
        "confidence": _text(asset, "confidence", "unknown"),
        "valid_from": _text(asset, "valid_from"),
        "valid_until": _text(asset, "valid_until"),
        "source_type": _text(asset, "source_type"),
        "source_ref": _text(asset, "source_ref"),
    }


def _text(source: dict, key: str, default: str = "") -> str:
    value = source.get(key)
    return str(value) if value else default


def _identifier_values(identifiers: dict, key: str) -> list:
    values = identifiers.get(key)
    return list(values) if values else []


def _asset_ip_matches(
    inventory: dict,
    address: str,
    observed_at: dt.datetime,
    parse_timestamp: TimestampParser,
) -> list[dict]:
    matches: list[dict] = []
    for raw in inventory.get("assets", []):
        if not isinstance(raw, dict):
            continue
        if asset_record_state(raw, observed_at, parse_timestamp) != "current":
            continue
        identifiers = raw.get("identifiers")
        identifiers = identifiers if isinstance(identifiers, dict) else {}
        if address in (identifiers.get("ip") or []):
            matches.append(raw)
    return matches


def _resolved_ip_record(address: str, asset: dict) -> dict:
    identifiers = asset.get("identifiers")
    identifiers = identifiers if isinstance(identifiers, dict) else {}
    hostnames = list(identifiers.get("hostname") or [])
    return {
        "status": "resolved" if hostnames else "known_without_hostname",
        "ip": address,
        "asset_id": _text(asset, "asset_id"),
        "hostname": hostnames[0] if hostnames else "",
        "hostnames": hostnames,
        "role": _text(asset, "role"),
        "platform": _text(asset, "platform"),
        "criticality": _text(asset, "criticality", "unknown"),
        "confidence": _text(asset, "confidence", "unknown"),
        "valid_from": _text(asset, "valid_from"),
        "valid_until": _text(asset, "valid_until"),
        "source_type": _text(asset, "source_type"),
    }


def _lookup_address(value: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def _lookup_time(
    value: object,
    parse_timestamp: TimestampParser,
) -> dt.datetime | None:
    try:
        parsed = parse_timestamp(value)
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def resolve_asset_ip(
    value: object,
    observed_at: object,
    inventory: dict | None,
    *,
    parse_timestamp: TimestampParser,
    load_inventory: Callable[[], tuple[dict, str]],
) -> dict:
    """Resolve one IP only when one event-time inventory record claims it."""
    address = _lookup_address(value)
    if address is None:
        return {"status": "not_applicable", "ip": str(value or "")}
    when = _lookup_time(observed_at, parse_timestamp)
    if when is None:
        return {"status": "time_invalid", "ip": address}
    if inventory is None:
        inventory, error = load_inventory()
        if error:
            return {"status": "inventory_unavailable", "ip": address}
    matches = _asset_ip_matches(inventory, address, when, parse_timestamp)
    if not matches:
        return {"status": "unmapped", "ip": address}
    if len(matches) == 1:
        return _resolved_ip_record(address, matches[0])
    return {
        "status": "ambiguous",
        "ip": address,
        "asset_ids": sorted(_text(item, "asset_id") for item in matches),
    }


def database_query_parameters(query: Query | None) -> dict[str, str]:
    """Allowlist the Asset Inventory query sent to PostgreSQL."""
    query = query or {}
    defaults = {
        "limit": "100",
        "offset": "0",
        "search": "",
        "sort": "asset_id",
        "direction": "asc",
        "state": "current",
    }
    return {
        key: str((query.get(key) or [default])[0])
        for key, default in defaults.items()
    }


def database_unavailable_payload(error: Exception) -> dict:
    """Return the fail-closed PostgreSQL response contract."""
    return {
        "ok": False,
        "inventory_status": "unavailable",
        "storage_backend": "postgresql",
        "error": f"Asset inventory unavailable: {error}",
        "assets": [],
    }


def current_asset_projection(
    inventory: dict,
    observed_at: dt.datetime,
    parse_timestamp: TimestampParser,
) -> tuple[list[dict], dict[str, int]]:
    """Project current public records and complete validity counts."""
    counts = {"current": 0, "scheduled": 0, "expired": 0, "invalid": 0}
    records: list[dict] = []
    for raw in inventory.get("assets", []):
        if not isinstance(raw, dict):
            continue
        state = asset_record_state(raw, observed_at, parse_timestamp)
        counts[state] = counts.get(state, 0) + 1
        if state == "current":
            records.append(asset_public_record(raw, state))
    return records, counts


def apply_asset_overlays(
    records: list[dict],
    overlays: dict[str, dict],
    discovered: list[dict],
) -> list[dict]:
    """Apply display-only evidence and append provisional observations."""
    for record in records:
        overlay = overlays.get(str(record.get("asset_id") or ""))
        if overlay:
            record.update(overlay)
    records.extend(discovered)
    records.sort(key=lambda item: (
        str(item.get("asset_id") or "").lower(),
        str(item.get("valid_from") or ""),
    ))
    return records


def compose_local_response(
    *,
    inventory: dict,
    error: str,
    observed_at: dt.datetime,
    records: list[dict],
    state_counts: dict[str, int],
    discovered: list[dict],
    discovery_status: dict,
    format_timestamp: Callable[..., str],
) -> tuple[int, dict]:
    """Compose the disaster-recovery/test Asset Inventory contract."""
    state_counts["observed"] = len(discovered)
    payload = {
        "ok": not error,
        "inventory_status": str(inventory.get("inventory_status") or "loaded"),
        "dhcp_discovery": discovery_status,
        "generated_at": str(inventory.get("generated_at") or ""),
        "observed_at": format_timestamp(observed_at, utc_z=True),
        "records_total": sum(state_counts.values()),
        "authoritative_asset_count": len(records) - len(discovered),
        "discovered_asset_count": len(discovered),
        "current_asset_count": len(records),
        "current_ip_count": sum(len(item["ip_addresses"]) for item in records),
        "current_hostname_count": sum(len(item["hostnames"]) for item in records),
        "state_counts": state_counts,
        "assets": records,
    }
    if not error:
        return HTTPStatus.OK, payload
    payload["error"] = f"Asset inventory unavailable: {error}"
    return HTTPStatus.SERVICE_UNAVAILABLE, payload
