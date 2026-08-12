"""Software Inventory asset identity and operating-system correlation."""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress

from software_inventory_query import _freshness
from software_inventory_state import (
    ASSET_LABEL_MAX_RECORDS,
    ASSET_OS_ASSOCIATION,
    ENDPOINT_OS_SOURCES,
    InventoryStateError,
    _parse_timestamp,
    _utc_iso,
)


def apply_asset_labels(
    items: object,
    assets: object,
    *,
    inventory_complete: bool,
    maximum_assets: int = ASSET_LABEL_MAX_RECORDS,
) -> int:
    """Label software references only from one complete, bounded asset view.

    A partial asset page cannot establish uniqueness because a later page
    could contain a second claimant. In that case every visible software
    record remains deliberately unlabeled.
    """
    if not isinstance(items, list):
        return 0
    for item in items:
        if isinstance(item, dict):
            item["asset_label"] = ""
    if (
        not inventory_complete
        or not isinstance(assets, list)
        or len(assets) > maximum_assets
    ):
        return 0

    claims: dict[tuple[str, str], set[str]] = {}
    assets_by_id: dict[str, dict] = {}
    for raw in assets:
        if not isinstance(raw, dict):
            continue
        asset_id = str(raw.get("asset_id") or "").strip()
        if not asset_id:
            continue
        assets_by_id[asset_id] = raw
        hostnames = raw.get("hostnames")
        if isinstance(hostnames, list):
            for hostname in hostnames:
                normalized = str(hostname or "").strip().rstrip(".").lower()
                if not normalized:
                    continue
                digest = hashlib.sha256(
                    ("host\0" + normalized).encode("utf-8")
                ).hexdigest()[:24]
                claims.setdefault(("host", digest), set()).add(asset_id)
        addresses = raw.get("ip_addresses")
        if isinstance(addresses, list):
            for address in addresses:
                try:
                    normalized_ip = str(ipaddress.ip_address(str(address)))
                except ValueError:
                    continue
                claims.setdefault(("ip", normalized_ip), set()).add(asset_id)

    labeled = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        matches = claims.get(
            (
                str(item.get("asset_ref_type") or ""),
                str(item.get("asset_ref") or ""),
            ),
            set(),
        )
        if len(matches) == 1:
            asset_id = next(iter(matches))
            item["asset_label"] = asset_id
            asset = assets_by_id.get(asset_id, {})
            operating_system_type = str(
                asset.get("operating_system_type")
                or asset.get("platform")
                or ""
            ).strip()[:160]
            operating_system_version = str(
                asset.get("operating_system_version") or ""
            ).strip()[:512]
            if not str(item.get("operating_system_type") or "").strip():
                item["operating_system_type"] = operating_system_type
            if not str(item.get("operating_system_version") or "").strip():
                item["operating_system_version"] = operating_system_version
            if (
                (
                    operating_system_type
                    or operating_system_version
                )
                and not str(item.get("operating_system_source") or "").strip()
            ):
                item["operating_system_source"] = "asset_inventory"
                confidence = str(asset.get("confidence") or "").strip().lower()
                item["operating_system_confidence"] = (
                    confidence
                    if confidence in {"low", "medium", "high"}
                    else ""
                )
            labeled += 1
    return labeled


def correlate_asset_operating_systems(
    items: object,
    endpoint_evidence: object,
    *,
    assets: object,
    observed_at: dt.datetime,
) -> int:
    """Carry one trusted endpoint OS observation across one validated asset.

    Both collections must already have passed ``apply_asset_labels`` against
    the same complete Asset Inventory.  Passive IP evidence never supplies
    the OS value; it can only receive a separately observed endpoint value
    after both references resolve to one asset.  Conflicting or incomplete
    candidates fail closed.
    """
    if (
        not isinstance(items, list)
        or not isinstance(endpoint_evidence, list)
        or not isinstance(assets, list)
    ):
        return 0
    if observed_at.tzinfo is None:
        raise ValueError("observed_at must include a UTC offset")
    now = observed_at.astimezone(dt.timezone.utc)
    assets_by_id = {
        str(item.get("asset_id") or "").strip(): item
        for item in assets
        if isinstance(item, dict)
        and str(item.get("asset_id") or "").strip()
    }

    def valid_at(asset: dict, when: dt.datetime) -> bool:
        try:
            valid_from = _parse_timestamp(
                asset.get("valid_from"), "asset.valid_from"
            )
            valid_until = (
                _parse_timestamp(
                    asset.get("valid_until"), "asset.valid_until"
                )
                if asset.get("valid_until")
                else None
            )
        except InventoryStateError:
            return False
        return valid_from <= when and (
            valid_until is None or when < valid_until
        )

    def trusted_asset(asset_label: str, when: dt.datetime) -> dict | None:
        asset = assets_by_id.get(asset_label)
        if (
            not isinstance(asset, dict)
            or str(asset.get("state") or "").strip().lower() != "current"
            or str(asset.get("confidence") or "").strip().lower() != "high"
            or str(asset.get("source_type") or "").strip().lower()
            == "zeek-dhcp-observation"
            or str(asset.get("current_ip_source") or "").strip().lower()
            == "zeek-dhcp"
            or not valid_at(asset, when)
        ):
            return None
        return asset

    candidates: dict[
        str,
        dict[dt.datetime, dict[tuple[str, str], dict[str, object]]],
    ] = {}
    for item in endpoint_evidence:
        if not isinstance(item, dict):
            continue
        asset_label = str(item.get("asset_label") or "").strip()
        os_type = str(item.get("operating_system_type") or "").strip()
        os_version = str(
            item.get("operating_system_version") or ""
        ).strip()
        if (
            not asset_label
            or item.get("source") != "osquery_apps"
            or item.get("operating_system_source") not in ENDPOINT_OS_SOURCES
            or item.get("operating_system_confidence") != "high"
            or not os_type
            or not os_version
        ):
            continue
        last_seen = item.get("_last_seen")
        if not isinstance(last_seen, dt.datetime):
            try:
                last_seen = _parse_timestamp(
                    item.get("last_seen"),
                    "operating_system_observed_at",
                )
            except InventoryStateError:
                continue
        last_seen = last_seen.astimezone(dt.timezone.utc)
        if (
            last_seen > now + dt.timedelta(minutes=5)
            or trusted_asset(asset_label, last_seen) is None
        ):
            continue
        candidate = {
            "operating_system_type": os_type,
            "operating_system_version": os_version,
            "operating_system_source": str(item["operating_system_source"]),
            "operating_system_observed_at": _utc_iso(last_seen),
            "operating_system_freshness": _freshness(item, now),
        }
        candidates.setdefault(asset_label, {}).setdefault(
            last_seen, {}
        )[(os_type.casefold(), os_version.casefold())] = candidate

    trusted: dict[str, dict[str, object]] = {}
    for asset_label, observations in candidates.items():
        newest = max(observations)
        values = observations[newest]
        if len(values) == 1:
            trusted[asset_label] = next(iter(values.values()))

    correlated = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        asset_label = str(item.get("asset_label") or "").strip()
        candidate = trusted.get(asset_label)
        if not candidate:
            continue
        current_source = str(
            item.get("operating_system_source") or ""
        ).strip()
        if current_source in ENDPOINT_OS_SOURCES:
            continue
        if item.get("source") not in {"zeek_software", "http_user_agent"}:
            continue
        item_last_seen = item.get("_last_seen")
        if not isinstance(item_last_seen, dt.datetime):
            try:
                item_last_seen = _parse_timestamp(
                    item.get("last_seen"), "last_seen"
                )
            except InventoryStateError:
                continue
        item_last_seen = item_last_seen.astimezone(dt.timezone.utc)
        asset = trusted_asset(asset_label, item_last_seen)
        if asset is None or item.get("asset_ref_type") != "ip":
            continue
        static_addresses = asset.get("configured_ip_addresses")
        if not isinstance(static_addresses, list) or not static_addresses:
            static_addresses = asset.get("ip_addresses")
        normalized_addresses: set[str] = set()
        if isinstance(static_addresses, list):
            for value in static_addresses:
                try:
                    normalized_addresses.add(
                        str(ipaddress.ip_address(str(value)))
                    )
                except ValueError:
                    continue
        if str(item.get("asset_ref") or "") not in normalized_addresses:
            continue
        current_type = str(
            item.get("operating_system_type") or ""
        ).strip()
        current_version = str(
            item.get("operating_system_version") or ""
        ).strip()
        candidate_type = str(candidate["operating_system_type"])
        candidate_version = str(candidate["operating_system_version"])
        if (
            current_type
            and current_type.casefold() != candidate_type.casefold()
        ) or (
            current_version
            and current_version.casefold() != candidate_version.casefold()
        ):
            continue
        item.update(candidate)
        item["operating_system_confidence"] = "high"
        item["operating_system_association"] = ASSET_OS_ASSOCIATION
        correlated += 1
    return correlated
