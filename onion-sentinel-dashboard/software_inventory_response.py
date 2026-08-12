"""Software Inventory bounded response compatibility orchestrator."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from software_inventory_assets import (
    apply_asset_labels,
    correlate_asset_operating_systems,
)
from software_inventory_query import (
    _empty_payload,
    parse_filters,
)
from software_inventory_response_projection import build_success_payload
from software_inventory_response_selection import select_response_records
from software_inventory_state import (
    InventoryQueryError,
    InventoryStateError,
    MAX_STATE_BYTES,
    load_state,
)


def _enrich_records(
    records: list[dict[str, object]],
    assets: object,
    inventory_complete: bool,
    observed_at: dt.datetime,
) -> None:
    apply_asset_labels(
        records, assets, inventory_complete=inventory_complete
    )
    correlate_asset_operating_systems(
        records, records, assets=assets, observed_at=observed_at
    )


def build_response(
    path: Path,
    query: dict[str, list[str]] | None = None,
    *,
    observed_at: dt.datetime | None = None,
    maximum_bytes: int = MAX_STATE_BYTES,
    assets: object = None,
    asset_inventory_complete: bool = False,
) -> tuple[int, dict[str, object]]:
    """Build one bounded public response from the local derived snapshot."""
    now = observed_at or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.astimezone()
    now = now.astimezone(dt.timezone.utc)
    try:
        filters = parse_filters(query)
    except InventoryQueryError as exc:
        filters = parse_filters(None)
        payload = _empty_payload(now, filters, error=str(exc))
        return 400, payload
    try:
        state, revision = load_state(path, maximum_bytes=maximum_bytes)
    except InventoryStateError as exc:
        return 503, _empty_payload(now, filters, error=str(exc))

    state_records = state["records"]  # type: ignore[assignment]
    _enrich_records(
        state_records, assets, asset_inventory_complete, now
    )
    all_window_records, records, selected, limit, offset = (
        select_response_records(state_records, filters, now)
    )
    return 200, build_success_payload(
        state=state,
        revision=revision,
        filters=filters,
        observed_at=now,
        all_window_records=all_window_records,
        records=records,
        selected=selected,
        limit=limit,
        offset=offset,
        asset_inventory_complete=asset_inventory_complete,
    )
