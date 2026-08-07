"""Software Inventory source orchestration and public enrichment policy."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from typing import Callable


Query = dict[str, list[str]]
AssetPageReader = Callable[[Query], tuple[int, dict]]


@dataclass(frozen=True)
class AssetLabelSnapshot:
    assets: list[dict]
    complete: bool


INCOMPLETE_ASSET_WARNING = (
    "Asset labels are withheld because the complete bounded "
    "Asset Inventory could not be read."
)


def _accepted_asset_page(
    status: int,
    payload: object,
    *,
    page_size: int,
    remaining: int,
) -> tuple[list[object], list[dict], bool] | None:
    if int(status) != 200 or not isinstance(payload, dict):
        return None
    page_assets = payload.get("assets")
    if not isinstance(page_assets, list) or len(page_assets) > page_size:
        return None
    if len(page_assets) > remaining:
        return None
    assets = [item for item in page_assets if isinstance(item, dict)]
    page = payload.get("page")
    complete = not isinstance(page, dict) or page.get("has_more") is not True
    return page_assets, assets, complete


def load_asset_label_snapshot(
    read_page: AssetPageReader,
    *,
    page_size: int,
    maximum_pages: int,
    maximum_records: int,
) -> AssetLabelSnapshot:
    """Load one complete bounded public asset view or mark it incomplete."""
    assets: list[dict] = []
    offset = 0
    for _page_number in range(maximum_pages):
        status, payload = read_page({
            "limit": [str(page_size)],
            "offset": [str(offset)],
            "search": [""],
            "sort": ["asset_id"],
            "direction": ["asc"],
            "state": ["current"],
        })
        page = _accepted_asset_page(
            status,
            payload,
            page_size=page_size,
            remaining=maximum_records - len(assets),
        )
        if page is None:
            break
        page_assets, accepted_assets, complete = page
        assets.extend(accepted_assets)
        if complete:
            return AssetLabelSnapshot(assets, True)
        returned = len(page_assets)
        if returned <= 0:
            break
        offset += returned
    return AssetLabelSnapshot(assets, False)


def database_query_parameters(
    query: Query | None,
    observed_at: dt.datetime | None,
    utc_iso: Callable[[dt.datetime], str],
) -> dict[str, str]:
    """Allowlist the query contract forwarded to the PostgreSQL API."""
    query = query or {}
    defaults = {
        "limit": "100",
        "offset": "0",
        "search": "",
        "tier": "all",
        "confidence": "all",
        "freshness": "all",
        "platform": "all",
        "window": "30d",
        "sort": "last_seen",
        "direction": "desc",
    }
    allowed = {
        key: str((query.get(key) or [default])[0])
        for key, default in defaults.items()
    }
    if observed_at is not None:
        allowed["observed_at"] = utc_iso(
            observed_at.astimezone(dt.timezone.utc)
        )
    return allowed


def append_incomplete_asset_warning(payload: dict, complete: bool) -> None:
    """Expose withheld labels without manufacturing a warning container."""
    if complete:
        return
    warnings = payload.get("warnings")
    if isinstance(warnings, list):
        warnings.append(INCOMPLETE_ASSET_WARNING)


def enrich_database_payload(
    payload: dict,
    snapshot: AssetLabelSnapshot,
    *,
    observed_at: dt.datetime,
    apply_asset_labels: Callable[..., object],
    correlate_operating_systems: Callable[..., object],
) -> dict:
    """Apply public asset identity and endpoint OS evidence to visible rows."""
    items = payload.get("items")
    if isinstance(items, list):
        apply_asset_labels(
            items,
            snapshot.assets,
            inventory_complete=snapshot.complete,
        )
        correlate_operating_systems(
            items,
            items,
            assets=snapshot.assets,
            observed_at=observed_at,
        )
        coverage = payload.get("coverage")
        if isinstance(coverage, dict):
            coverage.update({
                "labeled_visible_records": sum(
                    bool(item.get("asset_label"))
                    for item in items
                    if isinstance(item, dict)
                ),
                "asset_label_inventory_complete": snapshot.complete,
                "asset_os_correlated_records": sum(
                    bool(item.get("operating_system_association"))
                    for item in items
                    if isinstance(item, dict)
                ),
            })
    append_incomplete_asset_warning(payload, snapshot.complete)
    return payload
