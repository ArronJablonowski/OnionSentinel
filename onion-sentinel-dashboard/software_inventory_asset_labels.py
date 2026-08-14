"""Complete-inventory asset identity labeling for Software Inventory."""
from __future__ import annotations

import hashlib
import ipaddress

from software_inventory_state import ASSET_LABEL_MAX_RECORDS


ClaimKey = tuple[str, str]


def _clear_asset_labels(items: list[object]) -> None:
    for item in items:
        if isinstance(item, dict):
            item["asset_label"] = ""


def _hostname_claims(
    claims: dict[ClaimKey, set[str]],
    asset_id: str,
    values: object,
) -> None:
    if not isinstance(values, list):
        return
    for hostname in values:
        normalized = str(hostname or "").strip().rstrip(".").lower()
        if not normalized:
            continue
        digest = hashlib.sha256(
            ("host\0" + normalized).encode("utf-8")
        ).hexdigest()[:24]
        claims.setdefault(("host", digest), set()).add(asset_id)


def _address_claims(
    claims: dict[ClaimKey, set[str]],
    asset_id: str,
    values: object,
) -> None:
    if not isinstance(values, list):
        return
    for address in values:
        try:
            normalized = str(ipaddress.ip_address(str(address)))
        except ValueError:
            continue
        claims.setdefault(("ip", normalized), set()).add(asset_id)


def _asset_claims(
    assets: list[object],
) -> tuple[dict[ClaimKey, set[str]], dict[str, dict]]:
    claims: dict[ClaimKey, set[str]] = {}
    assets_by_id: dict[str, dict] = {}
    for raw in assets:
        if not isinstance(raw, dict):
            continue
        asset_id = str(raw.get("asset_id") or "").strip()
        if not asset_id:
            continue
        assets_by_id[asset_id] = raw
        _hostname_claims(claims, asset_id, raw.get("hostnames"))
        _address_claims(claims, asset_id, raw.get("ip_addresses"))
    return claims, assets_by_id


def _asset_operating_system_values(asset: dict) -> tuple[str, str]:
    os_type = str(
        asset.get("operating_system_type")
        or asset.get("platform")
        or ""
    ).strip()[:160]
    os_version = str(
        asset.get("operating_system_version") or ""
    ).strip()[:512]
    return os_type, os_version


def _set_missing_os_value(item: dict, key: str, value: str) -> None:
    if not str(item.get(key) or "").strip():
        item[key] = value


def _asset_operating_system(item: dict, asset: dict) -> None:
    os_type, os_version = _asset_operating_system_values(asset)
    _set_missing_os_value(item, "operating_system_type", os_type)
    _set_missing_os_value(item, "operating_system_version", os_version)
    if (
        (os_type or os_version)
        and not str(item.get("operating_system_source") or "").strip()
    ):
        item["operating_system_source"] = "asset_inventory"
        confidence = str(asset.get("confidence") or "").strip().lower()
        item["operating_system_confidence"] = (
            confidence if confidence in {"low", "medium", "high"} else ""
        )


def _label_item(
    item: object,
    claims: dict[ClaimKey, set[str]],
    assets_by_id: dict[str, dict],
) -> bool:
    if not isinstance(item, dict):
        return False
    matches = claims.get(
        (
            str(item.get("asset_ref_type") or ""),
            str(item.get("asset_ref") or ""),
        ),
        set(),
    )
    if len(matches) != 1:
        return False
    asset_id = next(iter(matches))
    item["asset_label"] = asset_id
    _asset_operating_system(item, assets_by_id.get(asset_id, {}))
    return True


def apply_asset_labels(
    items: object,
    assets: object,
    *,
    inventory_complete: bool,
    maximum_assets: int = ASSET_LABEL_MAX_RECORDS,
) -> int:
    """Label software references only from one complete, bounded asset view."""
    if not isinstance(items, list):
        return 0
    _clear_asset_labels(items)
    if (
        not inventory_complete
        or not isinstance(assets, list)
        or len(assets) > maximum_assets
    ):
        return 0
    claims, assets_by_id = _asset_claims(assets)
    return sum(
        1 for item in items if _label_item(item, claims, assets_by_id)
    )
