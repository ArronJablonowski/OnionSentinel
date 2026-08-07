"""Passive DHCP evidence policy for the public Asset Inventory."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import ipaddress
import re
from typing import Callable

from portal_asset_inventory_service import asset_public_record, asset_record_state


TimestampParser = Callable[[object], dt.datetime]


@dataclass(frozen=True)
class DhcpObservation:
    raw: dict
    current_ip: str
    hostname: str
    mac: str
    last_seen: dt.datetime
    lease_expires: dt.datetime | None

    @property
    def discovery_id(self) -> str:
        return str(self.raw.get("discovery_id") or "")[:64]


def mac_address_scope(value: object) -> str:
    """Classify a normalized MAC without claiming a vendor identity."""
    text = str(value or "").strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", text):
        return "unknown"
    first_octet = int(text[:2], 16)
    if first_octet & 1:
        return "multicast"
    if first_octet & 2:
        return "locally_administered"
    return "globally_administered"


def discovery_status(state: dict, state_error: str) -> dict:
    """Project bounded collector status for the UI."""
    collection = state.get("collection")
    collection = collection if isinstance(collection, dict) else {}
    return {
        "status": str(collection.get("status") or "unknown")[:32],
        "updated_at": str(state.get("updated_at") or "")[:64],
        "error": str(state_error or collection.get("last_error") or "")[:300],
    }


def _optional_timestamp(
    value: object,
    parse_timestamp: TimestampParser,
) -> dt.datetime | None:
    if not value:
        return None
    try:
        return parse_timestamp(value).astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def parse_observation(
    raw: object,
    parse_timestamp: TimestampParser,
) -> DhcpObservation | None:
    """Parse the bounded fields used by overlay policy."""
    if not isinstance(raw, dict):
        return None
    try:
        current_ip = str(ipaddress.ip_address(str(raw.get("current_ip") or "").strip()))
        last_seen = parse_timestamp(raw.get("last_seen"))
        if last_seen.tzinfo is None:
            return None
        last_seen = last_seen.astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        return None
    return DhcpObservation(
        raw=raw,
        current_ip=current_ip,
        hostname=str(raw.get("hostname") or "").strip().rstrip(".").lower(),
        mac=str(raw.get("mac_address") or "").strip().lower(),
        last_seen=last_seen,
        lease_expires=_optional_timestamp(raw.get("lease_expires_at"), parse_timestamp),
    )


def observation_is_stale(
    observation: DhcpObservation,
    observed_at: dt.datetime,
) -> bool:
    """Treat an old observation as usable while its lease remains active."""
    cutoff = observed_at - dt.timedelta(hours=24)
    lease = observation.lease_expires
    return observation.last_seen < cutoff and (lease is None or lease < observed_at)


def _parsed_observations(
    state: dict,
    parse_timestamp: TimestampParser,
) -> list[DhcpObservation]:
    raw_items = state.get("observations")
    raw_items = raw_items if isinstance(raw_items, list) else []
    parsed = [parse_observation(item, parse_timestamp) for item in raw_items]
    return [item for item in parsed if item is not None]


def _mac_evidence(observation: DhcpObservation, stale: bool) -> dict | None:
    scope = mac_address_scope(observation.mac)
    if scope in {"unknown", "multicast"}:
        return None
    return {
        "mac": observation.mac,
        "scope": scope,
        "last_seen": str(observation.raw.get("last_seen") or "")[:64],
        "last_seen_value": observation.last_seen,
        "stale": stale,
    }


def _evidence_by_ip(
    observations: list[DhcpObservation],
    observed_at: dt.datetime,
) -> dict[str, list[dict]]:
    by_ip: dict[str, list[dict]] = {}
    for observation in observations:
        evidence = _mac_evidence(
            observation,
            observation_is_stale(observation, observed_at),
        )
        if evidence is not None:
            by_ip.setdefault(observation.current_ip, []).append(evidence)
    return by_ip


def _record_candidates(record: dict, by_ip: dict[str, list[dict]]) -> list[dict]:
    candidates: list[dict] = []
    for raw_address in record.get("ip_addresses") or []:
        try:
            address = str(ipaddress.ip_address(str(raw_address).strip()))
        except ValueError:
            continue
        candidates.extend(by_ip.get(address, []))
    return candidates


def _select_mac(candidates: list[dict]) -> tuple[dict | None, bool]:
    fresh = [item for item in candidates if not item["stale"]]
    selected = fresh or candidates
    by_mac: dict[str, dict] = {}
    for item in sorted(selected, key=lambda entry: entry["last_seen_value"], reverse=True):
        by_mac.setdefault(str(item["mac"]), item)
    if len(by_mac) != 1:
        return None, bool(by_mac)
    return next(iter(by_mac.values())), False


def annotate_exact_ip_dhcp_macs(
    records: list[dict],
    observed_at: dt.datetime,
    state: dict,
    state_error: str,
    parse_timestamp: TimestampParser,
) -> dict:
    """Attach display-only DHCP MAC evidence to exact-IP asset matches."""
    status = discovery_status(state, state_error)
    if state_error:
        return status
    by_ip = _evidence_by_ip(_parsed_observations(state, parse_timestamp), observed_at)
    for record in records:
        if not isinstance(record, dict):
            continue
        evidence, ambiguous = _select_mac(_record_candidates(record, by_ip))
        if ambiguous:
            record["observed_mac_ambiguous"] = True
            record["observed_mac_source"] = "zeek-dhcp-exact-ip"
        elif evidence is not None:
            record.update(_mac_annotation(evidence))
    return status


def _mac_annotation(evidence: dict) -> dict:
    return {
        "observed_mac_addresses": [str(evidence["mac"])],
        "observed_mac_source": "zeek-dhcp-exact-ip",
        "observed_mac_scope": str(evidence["scope"]),
        "observed_mac_last_seen": str(evidence["last_seen"]),
        "observed_mac_stale": bool(evidence["stale"]),
    }


def _identifier_indexes(
    inventory: dict,
    observed_at: dt.datetime,
    parse_timestamp: TimestampParser,
) -> tuple[dict[str, dict], dict[str, dict[str, set[str]]]]:
    assets: dict[str, dict] = {}
    indexes: dict[str, dict[str, set[str]]] = {"ip": {}, "hostname": {}, "mac": {}}
    for raw in inventory.get("assets", []):
        if not isinstance(raw, dict):
            continue
        if asset_record_state(raw, observed_at, parse_timestamp) != "current":
            continue
        asset_id = str(raw.get("asset_id") or "")
        if not asset_id:
            continue
        assets[asset_id] = asset_public_record(raw, "current")
        _index_asset_identifiers(indexes, asset_id, raw.get("identifiers"))
    return assets, indexes


def _index_asset_identifiers(
    indexes: dict[str, dict[str, set[str]]],
    asset_id: str,
    raw_identifiers: object,
) -> None:
    identifiers = raw_identifiers if isinstance(raw_identifiers, dict) else {}
    for kind in indexes:
        for raw_value in identifiers.get(kind) or []:
            value = str(raw_value or "").strip().rstrip(".").lower()
            if value:
                indexes[kind].setdefault(value, set()).add(asset_id)


def _stable_matches(
    observation: DhcpObservation,
    indexes: dict[str, dict[str, set[str]]],
) -> set[str]:
    matches: set[str] = set()
    if observation.hostname:
        matches.update(indexes["hostname"].get(observation.hostname, set()))
    if observation.mac:
        matches.update(indexes["mac"].get(observation.mac, set()))
    return matches


def _known_asset_overlay(asset: dict, observation: DhcpObservation) -> dict:
    return {
        "configured_ip_addresses": list(asset.get("ip_addresses") or []),
        "ip_addresses": [observation.current_ip],
        "current_ip_source": "zeek-dhcp",
        "dhcp_last_seen": str(observation.raw.get("last_seen") or "")[:64],
        "dhcp_lease_expires_at": str(
            observation.raw.get("lease_expires_at") or ""
        )[:64],
    }


def _provisional_asset(observation: DhcpObservation) -> dict | None:
    if not observation.discovery_id:
        return None
    raw = observation.raw
    return {
        "asset_id": f"dhcp-{observation.discovery_id}",
        "state": "observed",
        "ip_addresses": [observation.current_ip],
        "configured_ip_addresses": [],
        "hostnames": [observation.hostname] if observation.hostname else [],
        "mac_addresses": [observation.mac] if observation.mac else [],
        "mac_address_scope": mac_address_scope(observation.mac),
        "role": "DHCP-discovered LAN client",
        "platform": "",
        "criticality": "unknown",
        "confidence": "low",
        "valid_from": str(raw.get("first_seen") or "")[:64],
        "valid_until": str(raw.get("lease_expires_at") or "")[:64],
        "source_type": "zeek-dhcp-observation",
        "source_ref": "Passive DHCP evidence; operator verification required",
        "current_ip_source": "zeek-dhcp",
        "dhcp_last_seen": str(raw.get("last_seen") or "")[:64],
        "dhcp_lease_expires_at": str(raw.get("lease_expires_at") or "")[:64],
    }


def _apply_observation(
    observation: DhcpObservation,
    assets: dict[str, dict],
    indexes: dict[str, dict[str, set[str]]],
    overlays: dict[str, dict],
    discovered: dict[str, dict],
) -> None:
    stable = _stable_matches(observation, indexes)
    ip_matches = indexes["ip"].get(observation.current_ip, set())
    if len(stable) == 1 and not (ip_matches - stable):
        asset_id = next(iter(stable))
        overlays[asset_id] = _known_asset_overlay(assets[asset_id], observation)
        return
    if stable or ip_matches:
        return
    provisional = _provisional_asset(observation)
    if provisional is not None:
        discovered[provisional["asset_id"]] = provisional


def dhcp_asset_inventory_overlay(
    inventory: dict,
    observed_at: dt.datetime,
    state: dict,
    state_error: str,
    parse_timestamp: TimestampParser,
) -> tuple[dict[str, dict], list[dict], dict]:
    """Build a display-only overlay without changing authoritative facts."""
    status = discovery_status(state, state_error)
    if state_error:
        return {}, [], status
    assets, indexes = _identifier_indexes(inventory, observed_at, parse_timestamp)
    observations = _parsed_observations(state, parse_timestamp)
    observations.sort(key=lambda item: (
        str(item.raw.get("last_seen") or ""), item.discovery_id,
    ))
    overlays: dict[str, dict] = {}
    discovered: dict[str, dict] = {}
    for observation in observations:
        if not observation_is_stale(observation, observed_at):
            _apply_observation(observation, assets, indexes, overlays, discovered)
    return overlays, list(discovered.values()), status
