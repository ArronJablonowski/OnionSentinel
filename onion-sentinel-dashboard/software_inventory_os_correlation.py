"""Fail-closed endpoint OS correlation for Software Inventory."""
from __future__ import annotations

import datetime as dt
import ipaddress

from software_inventory_query import _freshness
from software_inventory_state import (
    ASSET_OS_ASSOCIATION,
    ENDPOINT_OS_SOURCES,
    InventoryStateError,
    _parse_timestamp,
    _utc_iso,
)


def _assets_by_id(assets: list[object]) -> dict[str, dict]:
    return {
        str(item.get("asset_id") or "").strip(): item
        for item in assets
        if isinstance(item, dict)
        and str(item.get("asset_id") or "").strip()
    }


def _valid_at(asset: dict, when: dt.datetime) -> bool:
    try:
        valid_from = _parse_timestamp(
            asset.get("valid_from"), "asset.valid_from"
        )
        valid_until = (
            _parse_timestamp(asset.get("valid_until"), "asset.valid_until")
            if asset.get("valid_until")
            else None
        )
    except InventoryStateError:
        return False
    return valid_from <= when and (valid_until is None or when < valid_until)


def _trusted_asset(
    assets: dict[str, dict],
    asset_label: str,
    when: dt.datetime,
) -> dict | None:
    asset = assets.get(asset_label)
    if (
        not isinstance(asset, dict)
        or str(asset.get("state") or "").strip().lower() != "current"
        or str(asset.get("confidence") or "").strip().lower() != "high"
        or str(asset.get("source_type") or "").strip().lower()
        == "zeek-dhcp-observation"
        or str(asset.get("current_ip_source") or "").strip().lower()
        == "zeek-dhcp"
        or not _valid_at(asset, when)
    ):
        return None
    return asset


def _endpoint_candidate(
    item: object,
    now: dt.datetime,
    assets: dict[str, dict],
) -> tuple[str, dt.datetime, tuple[str, str], dict[str, object]] | None:
    if not isinstance(item, dict):
        return None
    asset_label = str(item.get("asset_label") or "").strip()
    os_type = str(item.get("operating_system_type") or "").strip()
    os_version = str(item.get("operating_system_version") or "").strip()
    if (
        not asset_label
        or item.get("source") != "osquery_apps"
        or item.get("operating_system_source") not in ENDPOINT_OS_SOURCES
        or item.get("operating_system_confidence") != "high"
        or not os_type
        or not os_version
    ):
        return None
    last_seen = item.get("_last_seen")
    if not isinstance(last_seen, dt.datetime):
        try:
            last_seen = _parse_timestamp(
                item.get("last_seen"), "operating_system_observed_at"
            )
        except InventoryStateError:
            return None
    last_seen = last_seen.astimezone(dt.timezone.utc)
    if (
        last_seen > now + dt.timedelta(minutes=5)
        or _trusted_asset(assets, asset_label, last_seen) is None
    ):
        return None
    candidate = {
        "operating_system_type": os_type,
        "operating_system_version": os_version,
        "operating_system_source": str(item["operating_system_source"]),
        "operating_system_observed_at": _utc_iso(last_seen),
        "operating_system_freshness": _freshness(item, now),
    }
    return (
        asset_label,
        last_seen,
        (os_type.casefold(), os_version.casefold()),
        candidate,
    )


def _trusted_candidates(
    endpoint_evidence: list[object],
    now: dt.datetime,
    assets: dict[str, dict],
) -> dict[str, dict[str, object]]:
    candidates: dict[
        str,
        dict[dt.datetime, dict[tuple[str, str], dict[str, object]]],
    ] = {}
    for item in endpoint_evidence:
        candidate = _endpoint_candidate(item, now, assets)
        if candidate is None:
            continue
        asset_label, last_seen, identity, projection = candidate
        candidates.setdefault(asset_label, {}).setdefault(
            last_seen, {}
        )[identity] = projection
    trusted: dict[str, dict[str, object]] = {}
    for asset_label, observations in candidates.items():
        newest = max(observations)
        values = observations[newest]
        if len(values) == 1:
            trusted[asset_label] = next(iter(values.values()))
    return trusted


def _static_addresses(asset: dict) -> set[str]:
    values = asset.get("configured_ip_addresses")
    if not isinstance(values, list) or not values:
        values = asset.get("ip_addresses")
    normalized: set[str] = set()
    if isinstance(values, list):
        for value in values:
            try:
                normalized.add(str(ipaddress.ip_address(str(value))))
            except ValueError:
                continue
    return normalized


def _item_last_seen(item: dict) -> dt.datetime | None:
    last_seen = item.get("_last_seen")
    if not isinstance(last_seen, dt.datetime):
        try:
            last_seen = _parse_timestamp(item.get("last_seen"), "last_seen")
        except InventoryStateError:
            return None
    return last_seen.astimezone(dt.timezone.utc)


def _trusted_asset_reference(
    item: dict,
    assets: dict[str, dict],
    asset_label: str,
) -> bool:
    last_seen = _item_last_seen(item)
    if last_seen is None:
        return False
    asset = _trusted_asset(assets, asset_label, last_seen)
    if asset is None or item.get("asset_ref_type") != "ip":
        return False
    return str(item.get("asset_ref") or "") in _static_addresses(asset)


def _compatible_operating_system(
    item: dict,
    candidate: dict[str, object],
) -> bool:
    current_type = str(item.get("operating_system_type") or "").strip()
    current_version = str(item.get("operating_system_version") or "").strip()
    candidate_type = str(candidate["operating_system_type"])
    candidate_version = str(candidate["operating_system_version"])
    return not (
        current_type and current_type.casefold() != candidate_type.casefold()
    ) and not (
        current_version
        and current_version.casefold() != candidate_version.casefold()
    )


def _correlate_item(
    item: object,
    trusted: dict[str, dict[str, object]],
    assets: dict[str, dict],
) -> bool:
    if not isinstance(item, dict):
        return False
    asset_label = str(item.get("asset_label") or "").strip()
    candidate = trusted.get(asset_label)
    if not candidate:
        return False
    current_source = str(item.get("operating_system_source") or "").strip()
    if current_source in ENDPOINT_OS_SOURCES:
        return False
    if item.get("source") not in {"zeek_software", "http_user_agent"}:
        return False
    if not _trusted_asset_reference(item, assets, asset_label):
        return False
    if not _compatible_operating_system(item, candidate):
        return False
    item.update(candidate)
    item["operating_system_confidence"] = "high"
    item["operating_system_association"] = ASSET_OS_ASSOCIATION
    return True


def correlate_asset_operating_systems(
    items: object,
    endpoint_evidence: object,
    *,
    assets: object,
    observed_at: dt.datetime,
) -> int:
    """Carry one trusted endpoint OS observation across one validated asset."""
    if (
        not isinstance(items, list)
        or not isinstance(endpoint_evidence, list)
        or not isinstance(assets, list)
    ):
        return 0
    if observed_at.tzinfo is None:
        raise ValueError("observed_at must include a UTC offset")
    now = observed_at.astimezone(dt.timezone.utc)
    indexed_assets = _assets_by_id(assets)
    trusted = _trusted_candidates(endpoint_evidence, now, indexed_assets)
    return sum(
        1 for item in items if _correlate_item(item, trusted, indexed_assets)
    )
