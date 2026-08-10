"""Compatibility orchestration for portal asset, DHCP, and software reads.

The caller supplies the report portal runtime so host configuration and
test-time overrides remain owned by the compatibility facade.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


def asset_inventory_module(runtime: Any):
    existing = runtime.sys.modules.get("_onion_sentinel_asset_inventory")
    if existing is not None:
        return existing
    candidates = (
        runtime.PORTAL_SOURCE_DIR / "asset_inventory.py",
        runtime.PORTAL_SOURCE_DIR.parent / "n8n" / "bin" / "asset_inventory.py",
        runtime.HOME / "n8n-local" / "bin" / "asset_inventory.py",
    )
    for candidate in candidates:
        if not candidate.is_file():
            continue
        spec = runtime.importlib.util.spec_from_file_location(
            "_onion_sentinel_asset_inventory", candidate
        )
        if spec is None or spec.loader is None:
            continue
        module = runtime.importlib.util.module_from_spec(spec)
        runtime.sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    raise RuntimeError("asset inventory validator is unavailable")


def load_asset_inventory_data(runtime: Any) -> tuple[dict, str]:
    validator = runtime._asset_inventory_module()
    repository = runtime.AssetInventoryRepository(
        database_enabled=runtime.ASSET_DATABASE_READ_ENABLED,
        cache=runtime.ASSET_INVENTORY_CACHE,
        cache_lock=runtime.ASSET_INVENTORY_CACHE_LOCK,
        epoch_seconds=runtime.time.time,
        fetch_json=runtime.alert_store_get_json,
        validate_inventory=validator.validate_asset_inventory,
        load_inventory_file=validator.load_asset_inventory,
        inventory_path=Path(runtime.ASSET_INVENTORY_FILE),
        maximum_bytes=runtime.ASSET_INVENTORY_MAX_BYTES,
    )
    return repository.load()


def annotate_exact_ip_dhcp_macs(
    runtime: Any,
    records: list[dict],
    observed_at: dt.datetime,
) -> dict:
    state, state_error = runtime.load_dhcp_asset_discovery_state_data()
    return runtime.annotate_exact_ip_dhcp_macs(
        records, observed_at, state, state_error, runtime.parse_iso_timestamp
    )


def dhcp_asset_inventory_overlay(
    runtime: Any,
    inventory: dict,
    observed_at: dt.datetime,
) -> tuple[dict[str, dict], list[dict], dict]:
    state, state_error = runtime.load_dhcp_asset_discovery_state_data()
    return runtime.dhcp_asset_inventory_overlay(
        inventory, observed_at, state, state_error, runtime.parse_iso_timestamp
    )


def asset_inventory_response(
    runtime: Any,
    *,
    observed_at: dt.datetime | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    if runtime.ASSET_DATABASE_READ_ENABLED and observed_at is None:
        encoded = urlencode(runtime.asset_database_query_parameters(query))
        try:
            payload = runtime.alert_store_get_json(
                f"/assets/inventory?{encoded}", timeout=5.0
            )
        except RuntimeError as exc:
            return runtime.HTTPStatus.SERVICE_UNAVAILABLE, runtime.asset_database_unavailable_payload(exc)
        now = dt.datetime.now(dt.timezone.utc)
        records = payload.get("assets")
        discovery_status = (
            runtime._annotate_exact_ip_dhcp_macs(records, now)
            if isinstance(records, list)
            else {"status": "unavailable"}
        )
        payload["dhcp_discovery"] = discovery_status
        payload.setdefault("discovered_asset_count", 0)
        return runtime.HTTPStatus.OK, payload

    now = observed_at or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.astimezone()
    now = now.astimezone(dt.timezone.utc)
    inventory, error = runtime.load_asset_inventory_data()
    records, state_counts = runtime.current_asset_projection(
        inventory, now, runtime.parse_iso_timestamp
    )
    overlays, discovered, discovery_status = runtime._dhcp_asset_inventory_overlay(
        inventory, now
    )
    records = runtime.apply_asset_overlays(records, overlays, discovered)
    return runtime.compose_local_asset_inventory_response(
        inventory=inventory,
        error=error,
        observed_at=now,
        records=records,
        state_counts=state_counts,
        discovered=discovered,
        discovery_status=discovery_status,
        format_timestamp=runtime.format_iso_timestamp,
    )


def software_asset_label_snapshot(runtime: Any):
    return runtime.load_asset_label_snapshot(
        lambda page_query: runtime.asset_inventory_response(query=page_query),
        page_size=runtime.software_inventory.ASSET_LABEL_PAGE_SIZE,
        maximum_pages=runtime.software_inventory.ASSET_LABEL_MAX_PAGES,
        maximum_records=runtime.software_inventory.ASSET_LABEL_MAX_RECORDS,
    )


def software_inventory_response(
    runtime: Any,
    *,
    observed_at: dt.datetime | None = None,
    query: dict[str, list[str]] | None = None,
) -> tuple[int, dict]:
    snapshot = runtime.software_asset_label_snapshot()
    if runtime.SOFTWARE_DATABASE_READ_ENABLED:
        allowed = runtime.database_query_parameters(
            query, observed_at, runtime.software_inventory._utc_iso
        )
        try:
            payload = runtime.alert_store_get_json(
                f"/software-inventory?{urlencode(allowed)}", timeout=10.0
            )
        except RuntimeError as exc:
            filters = runtime.software_inventory.parse_filters(query)
            return runtime.HTTPStatus.SERVICE_UNAVAILABLE, runtime.software_inventory._empty_payload(
                observed_at or dt.datetime.now(dt.timezone.utc),
                filters,
                error=f"PostgreSQL software inventory unavailable: {exc}",
            )
        return runtime.HTTPStatus.OK, runtime.enrich_database_payload(
            payload,
            snapshot,
            observed_at=observed_at or dt.datetime.now(dt.timezone.utc),
            apply_asset_labels=runtime.software_inventory.apply_asset_labels,
            correlate_operating_systems=runtime.software_inventory.correlate_asset_operating_systems,
        )

    status, payload = runtime.software_inventory.build_response(
        Path(runtime.SOFTWARE_INVENTORY_STATE_FILE),
        query,
        observed_at=observed_at,
        maximum_bytes=runtime.SOFTWARE_INVENTORY_MAX_BYTES,
        assets=snapshot.assets,
        asset_inventory_complete=snapshot.complete,
    )
    if status != runtime.HTTPStatus.OK or not isinstance(payload.get("items"), list):
        return status, payload
    runtime.append_incomplete_asset_warning(payload, snapshot.complete)
    return status, payload


def resolve_asset_ip(
    runtime: Any,
    value: object,
    observed_at: object,
    inventory: dict | None = None,
) -> dict:
    return runtime.resolve_asset_ip_record(
        value,
        observed_at,
        inventory,
        parse_timestamp=runtime.parse_iso_timestamp,
        load_inventory=runtime.load_asset_inventory_data,
    )


def dhcp_asset_discovery_response(
    runtime: Any,
    *,
    observed_at: dt.datetime | None = None,
) -> tuple[int, dict]:
    now = observed_at or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.astimezone()
    now = now.astimezone(dt.timezone.utc)
    state, state_error = runtime.load_dhcp_asset_discovery_state_data()
    dependencies = runtime.DhcpDiscoveryDependencies(
        asset_record_state=runtime._asset_record_state,
        asset_public_record=runtime._asset_public_record,
        parse_timestamp=runtime.parse_iso_timestamp,
        format_timestamp=runtime.format_iso_timestamp,
        mac_address_scope=runtime._mac_address_scope,
    )
    if state_error:
        return runtime.compose_dhcp_discovery_response(
            state=state,
            state_error=state_error,
            inventory={},
            inventory_error="",
            observed_at=now,
            dependencies=dependencies,
        )
    inventory, inventory_error = runtime.load_asset_inventory_data()
    return runtime.compose_dhcp_discovery_response(
        state=state,
        state_error="",
        inventory=inventory,
        inventory_error=inventory_error,
        observed_at=now,
        dependencies=dependencies,
    )
