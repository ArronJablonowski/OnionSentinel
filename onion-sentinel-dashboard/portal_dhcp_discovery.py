"""Pure DHCP observation reconciliation for the Asset Inventory API."""
from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from http import HTTPStatus
from typing import Callable


JsonObject = dict[str, object]


@dataclass(frozen=True)
class DhcpDiscoveryDependencies:
    asset_record_state: Callable[[dict, dt.datetime], str]
    asset_public_record: Callable[[dict, str], dict]
    parse_timestamp: Callable[[object], dt.datetime]
    format_timestamp: Callable[..., str]
    mac_address_scope: Callable[[object], str]


@dataclass(frozen=True)
class _InventoryIndex:
    assets: dict[str, dict]
    identities: dict[str, dict[str, set[str]]]


@dataclass(frozen=True)
class _Observation:
    raw: dict
    address: str
    last_seen: dt.datetime
    hostname: str
    mac: str


def _nonnegative_int(value: object, maximum: int = 2**63 - 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(0, min(parsed, maximum))


def _text_list(value: object, maximum_items: int, maximum_length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        str(item)[:maximum_length]
        for item in value[:maximum_items]
        if isinstance(item, (str, int, float))
    ]


def _empty_counts() -> dict[str, int]:
    return {"total": 0, "verified_match": 0, "candidate": 0, "conflict": 0, "stale": 0}


def _state_unavailable(error: str) -> tuple[int, JsonObject]:
    return HTTPStatus.SERVICE_UNAVAILABLE, {
        "ok": False,
        "error": f"DHCP discovery state unavailable: {error}",
        "collection": {"status": "invalid"},
        "counts": _empty_counts(),
        "observations": [],
    }


def _identity_values(raw_asset: dict, kind: str) -> list[object]:
    identifiers = raw_asset.get("identifiers")
    if not isinstance(identifiers, dict):
        return []
    values = identifiers.get(kind)
    return values if isinstance(values, list) else []


def _inventory_index(inventory: dict, now: dt.datetime,
                     deps: DhcpDiscoveryDependencies) -> _InventoryIndex:
    assets: dict[str, dict] = {}
    identities: dict[str, dict[str, set[str]]] = {"ip": {}, "hostname": {}, "mac": {}}
    raw_assets = inventory.get("assets")
    raw_assets = raw_assets if isinstance(raw_assets, list) else []
    for raw_asset in raw_assets:
        indexed = _current_public_asset(raw_asset, now, deps)
        if not indexed:
            continue
        asset_id, public_asset = indexed
        assets[asset_id] = public_asset
        for kind in identities:
            for raw_value in _identity_values(raw_asset, kind):
                value = str(raw_value or "").strip().rstrip(".").lower()
                if value:
                    identities[kind].setdefault(value, set()).add(asset_id)
    return _InventoryIndex(assets, identities)


def _current_public_asset(raw_asset: object, now: dt.datetime,
                          deps: DhcpDiscoveryDependencies) -> tuple[str, dict] | None:
    if not isinstance(raw_asset, dict):
        return None
    if deps.asset_record_state(raw_asset, now) != "current":
        return None
    public_asset = deps.asset_public_record(raw_asset, "current")
    asset_id = str(public_asset.get("asset_id") or "")
    return (asset_id, public_asset) if asset_id else None


def _parse_observation(raw: object, deps: DhcpDiscoveryDependencies) -> _Observation | None:
    if not isinstance(raw, dict):
        return None
    try:
        address = str(ipaddress.ip_address(str(raw.get("current_ip") or "").strip()))
        last_seen = deps.parse_timestamp(raw.get("last_seen"))
        if last_seen.tzinfo is None:
            raise ValueError("last_seen lacks offset")
        last_seen = last_seen.astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return None
    return _Observation(
        raw=raw,
        address=address,
        last_seen=last_seen,
        hostname=str(raw.get("hostname") or "").strip().rstrip(".").lower(),
        mac=str(raw.get("mac_address") or "").strip().lower(),
    )


def _matching_assets(observation: _Observation, index: _InventoryIndex) -> tuple[set[str], set[str]]:
    ip_matches = index.identities["ip"].get(observation.address, set())
    hostname_matches = (
        index.identities["hostname"].get(observation.hostname, set()) if observation.hostname else set()
    )
    mac_matches = index.identities["mac"].get(observation.mac, set()) if observation.mac else set()
    stable_matches = hostname_matches | mac_matches
    return ip_matches | stable_matches, stable_matches


def _resolved_asset(observation: _Observation, asset_id: str, asset: dict,
                    stable_matches: set[str]) -> JsonObject:
    hostnames = list(asset.get("hostnames") or [])
    return {
        "status": "resolved" if hostnames else "known_without_hostname",
        "ip": observation.address,
        "asset_id": asset_id,
        "hostname": hostnames[0] if hostnames else "",
        "hostnames": hostnames,
        "role": str(asset.get("role") or ""),
        "platform": str(asset.get("platform") or ""),
        "criticality": str(asset.get("criticality") or "unknown"),
        "configured_ip_addresses": list(asset.get("ip_addresses") or []),
        "stable_identity_match": asset_id in stable_matches,
    }


def _resolution(observation: _Observation, index: _InventoryIndex, inventory_error: str) -> JsonObject:
    matches, stable_matches = _matching_assets(observation, index)
    if inventory_error:
        return {"status": "inventory_unavailable", "ip": observation.address}
    if len(matches) > 1:
        return {"status": "ambiguous", "ip": observation.address, "asset_ids": sorted(matches)}
    if not matches:
        return {"status": "unmapped", "ip": observation.address}
    asset_id = next(iter(matches))
    return _resolved_asset(observation, asset_id, index.assets[asset_id], stable_matches)


def _authoritative_hostnames(resolution: JsonObject) -> list[str]:
    values = resolution.get("hostnames")
    values = values if isinstance(values, list) else []
    return [str(value).strip().rstrip(".").lower() for value in values if str(value).strip()]


def _reconciliation(observation: _Observation, resolution: JsonObject,
                    hostnames: list[str]) -> tuple[str, str]:
    if resolution.get("status") in {"resolved", "known_without_hostname"}:
        hostname_conflict = (
            observation.hostname and hostnames and observation.hostname not in hostnames
            and not resolution.get("stable_identity_match")
        )
        if hostname_conflict:
            return "conflict", "DHCP hostname differs from the authoritative assignment."
        configured = resolution.get("configured_ip_addresses") or []
        if observation.address not in configured:
            return (
                "verified_match",
                "A stable DHCP hostname or MAC maps this asset to a new current address.",
            )
        return "verified_match", "DHCP address agrees with the authoritative inventory."
    if resolution.get("status") == "ambiguous":
        return "conflict", "More than one authoritative asset claims this address."
    return "candidate", "Review before adding this observation to the authoritative inventory."


def _lease_expiration(raw: dict, deps: DhcpDiscoveryDependencies) -> dt.datetime | None:
    if not raw.get("lease_expires_at"):
        return None
    try:
        return deps.parse_timestamp(raw["lease_expires_at"]).astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def _is_stale(observation: _Observation, now: dt.datetime,
              deps: DhcpDiscoveryDependencies) -> bool:
    lease_expires = _lease_expiration(observation.raw, deps)
    return observation.last_seen < now - dt.timedelta(hours=24) and (
        lease_expires is None or lease_expires < now
    )


def _authoritative_asset(resolution: JsonObject, hostnames: list[str]) -> JsonObject | None:
    if resolution.get("status") not in {"resolved", "known_without_hostname"}:
        return None
    configured = resolution.get("configured_ip_addresses")
    configured = configured if isinstance(configured, list) else []
    return {
        "asset_id": str(resolution.get("asset_id") or ""),
        "hostname": str(resolution.get("hostname") or ""),
        "hostnames": hostnames,
        "role": str(resolution.get("role") or ""),
        "platform": str(resolution.get("platform") or ""),
        "criticality": str(resolution.get("criticality") or ""),
        "configured_ip_addresses": list(configured)[:32],
    }


def _public_observation(observation: _Observation, resolution: JsonObject, now: dt.datetime,
                        deps: DhcpDiscoveryDependencies) -> JsonObject:
    hostnames = _authoritative_hostnames(resolution)
    reconciliation, detail = _reconciliation(observation, resolution, hostnames)
    raw = observation.raw
    return {
        "discovery_id": str(raw.get("discovery_id") or "")[:64],
        "reconciliation": reconciliation,
        "reconciliation_detail": detail,
        "stale": _is_stale(observation, now, deps),
        "current_ip": observation.address,
        "ip_addresses": _text_list(raw.get("ip_addresses"), 32, 64),
        "mac_address": str(raw.get("mac_address") or "")[:32],
        "mac_address_scope": deps.mac_address_scope(raw.get("mac_address")),
        "hostname": str(raw.get("hostname") or "")[:253],
        "hostnames": _text_list(raw.get("hostnames"), 32, 253),
        "first_seen": str(raw.get("first_seen") or "")[:64],
        "last_seen": str(raw.get("last_seen") or "")[:64],
        "lease_expires_at": str(raw.get("lease_expires_at") or "")[:64],
        "message_types": _text_list(raw.get("message_types"), 16, 80),
        "sensors": _text_list(raw.get("sensors"), 16, 160),
        "observation_count": _nonnegative_int(raw.get("observation_count")),
        "authoritative_asset": _authoritative_asset(resolution, hostnames),
    }


def _records(state: dict, inventory: dict, inventory_error: str, now: dt.datetime,
             deps: DhcpDiscoveryDependencies) -> tuple[list[JsonObject], dict[str, int]]:
    index = _inventory_index(inventory, now, deps) if not inventory_error else _InventoryIndex(
        {}, {"ip": {}, "hostname": {}, "mac": {}}
    )
    values = state.get("observations")
    values = values if isinstance(values, list) else []
    records: list[JsonObject] = []
    counts = _empty_counts()
    for raw in values:
        observation = _parse_observation(raw, deps)
        if not observation:
            continue
        record = _public_observation(observation, _resolution(observation, index, inventory_error), now, deps)
        counts[str(record["reconciliation"])] += 1
        counts["stale"] += int(bool(record["stale"]))
        counts["total"] += 1
        records.append(record)
    rank = {"conflict": 0, "candidate": 1, "verified_match": 2}
    records.sort(key=lambda item: (
        rank.get(str(item["reconciliation"]), 9), bool(item["stale"]), str(item["last_seen"]),
    ))
    return records, counts


def _public_collection(value: object) -> JsonObject:
    collection = value if isinstance(value, dict) else {}
    last_window = collection.get("last_window")
    return {
        "status": str(collection.get("status") or "unknown")[:32],
        "last_attempt_at": str(collection.get("last_attempt_at") or "")[:64],
        "last_success_at": str(collection.get("last_success_at") or "")[:64],
        "last_error": str(collection.get("last_error") or "")[:300],
        "last_window": last_window if isinstance(last_window, dict) else {},
        "last_returned": _nonnegative_int(collection.get("last_returned"), 1000),
        "last_hits_total": _nonnegative_int(collection.get("last_hits_total")),
        "last_truncated": bool(collection.get("last_truncated")),
        "last_query_segments": _nonnegative_int(collection.get("last_query_segments"), 64),
    }


def _public_backfill(value: object) -> JsonObject:
    backfill = value if isinstance(value, dict) else {}
    return {
        "status": str(backfill.get("status") or "never_run")[:32],
        "last_attempt_at": str(backfill.get("last_attempt_at") or "")[:64],
        "last_success_at": str(backfill.get("last_success_at") or "")[:64],
        "last_error": str(backfill.get("last_error") or "")[:300],
        "requested_start": str(backfill.get("requested_start") or "")[:64],
        "requested_end": str(backfill.get("requested_end") or "")[:64],
        "covered_through": str(backfill.get("covered_through") or "")[:64],
        "last_returned": _nonnegative_int(backfill.get("last_returned"), 1_000_000),
        "last_hits_total": _nonnegative_int(backfill.get("last_hits_total")),
        "last_query_segments": _nonnegative_int(backfill.get("last_query_segments"), 64),
    }


def compose_dhcp_discovery_response(*, state: dict, state_error: str, inventory: dict,
                                    inventory_error: str, observed_at: dt.datetime,
                                    dependencies: DhcpDiscoveryDependencies) -> tuple[int, JsonObject]:
    """Reconcile bounded DHCP observations against the authoritative inventory."""
    if state_error:
        return _state_unavailable(state_error)
    records, counts = _records(state, inventory, inventory_error, observed_at, dependencies)
    inventory_status = "unavailable" if inventory_error else str(
        inventory.get("inventory_status") or "loaded"
    )
    return HTTPStatus.OK, {
        "ok": True,
        "updated_at": str(state.get("updated_at") or ""),
        "observed_at": dependencies.format_timestamp(observed_at, utc_z=True),
        "authoritative_inventory_status": inventory_status,
        "collection": _public_collection(state.get("collection")),
        "backfill": _public_backfill(state.get("backfill")),
        "counts": counts,
        "observations": records,
    }
