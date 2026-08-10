#!/usr/bin/env python3
"""Bounded, provenance-aware Software Inventory compatibility facade."""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
from pathlib import Path
import sys
from typing import Any

SOFTWARE_INVENTORY_SOURCE_DIR = Path(__file__).resolve().parent
if str(SOFTWARE_INVENTORY_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(SOFTWARE_INVENTORY_SOURCE_DIR))

from software_inventory_state import (
    AGENT_UUID_RE,
    API_SCHEMA,
    ASSET_LABEL_MAX_PAGES,
    ASSET_LABEL_MAX_RECORDS,
    ASSET_LABEL_PAGE_SIZE,
    ASSET_OS_ASSOCIATION,
    CONFIDENCES,
    DEFAULT_LIMIT,
    ENDPOINT_OS_SOURCES,
    EVIDENCE_ID_RE,
    FRESHNESS_VALUES,
    InventoryQueryError,
    InventoryStateError,
    LAN_NETWORKS,
    MAX_LIMIT,
    MAX_OFFSET,
    MAX_RECORDS,
    MAX_STATE_BYTES,
    SAFE_ASSET_REF_RE,
    SORT_FIELDS,
    SOURCE_DATASETS,
    SOURCES,
    STATE_SCHEMA,
    TIERS,
    WINDOWS,
    _parse_timestamp,
    _read_bounded_regular_json,
    _safe_text,
    _sanitize_collection,
    _sanitize_record,
    _sanitize_source_statuses,
    _utc_iso,
    load_state,
)


def _one(query: dict[str, list[str]], key: str, default: str) -> str:
    values = query.get(key)
    if not values:
        return default
    if len(values) != 1:
        raise InventoryQueryError(f"{key} must appear once")
    return str(values[0])


def parse_filters(query: dict[str, list[str]] | None) -> dict[str, object]:
    query = query or {}
    allowed = {
        "limit",
        "offset",
        "search",
        "tier",
        "confidence",
        "freshness",
        "platform",
        "window",
        "sort",
        "direction",
    }
    unknown = set(query) - allowed
    if unknown:
        raise InventoryQueryError(
            f"unsupported query parameter: {sorted(unknown)[0]}"
        )
    try:
        limit = int(_one(query, "limit", str(DEFAULT_LIMIT)))
        offset = int(_one(query, "offset", "0"))
    except ValueError as exc:
        raise InventoryQueryError("limit and offset must be integers") from exc
    if not 1 <= limit <= MAX_LIMIT:
        raise InventoryQueryError(f"limit must be between 1 and {MAX_LIMIT}")
    if not 0 <= offset <= MAX_OFFSET:
        raise InventoryQueryError(f"offset must be between 0 and {MAX_OFFSET}")
    search = _one(query, "search", "").strip()
    if len(search) > 253 or any(ord(char) < 32 for char in search):
        raise InventoryQueryError("search is invalid")
    tier = _one(query, "tier", "all").strip().lower()
    confidence = _one(query, "confidence", "all").strip().lower()
    freshness = _one(query, "freshness", "all").strip().lower()
    platform = _one(query, "platform", "all").strip()
    window = _one(query, "window", "30d").strip().lower()
    sort_field = _one(query, "sort", "last_seen").strip().lower()
    direction = _one(query, "direction", "desc").strip().lower()
    if tier != "all" and tier not in TIERS:
        raise InventoryQueryError("tier is unsupported")
    if confidence != "all" and confidence not in CONFIDENCES:
        raise InventoryQueryError("confidence is unsupported")
    if freshness != "all" and freshness not in FRESHNESS_VALUES:
        raise InventoryQueryError("freshness is unsupported")
    if (
        not platform
        or len(platform) > 160
        or any(ord(char) < 32 for char in platform)
    ):
        raise InventoryQueryError("platform is invalid")
    if window not in WINDOWS:
        raise InventoryQueryError("window is unsupported")
    if sort_field not in SORT_FIELDS:
        raise InventoryQueryError("sort is unsupported")
    if direction not in {"asc", "desc"}:
        raise InventoryQueryError("direction is unsupported")
    return {
        "limit": limit,
        "offset": offset,
        "search": search,
        "tier": tier,
        "confidence": confidence,
        "freshness": freshness,
        "platform": platform,
        "window": window,
        "sort": sort_field,
        "direction": direction,
    }


def _freshness(record: dict[str, object], observed_at: dt.datetime) -> str:
    age = observed_at - record["_last_seen"]  # type: ignore[operator]
    if age <= dt.timedelta(hours=24):
        return "current"
    if age <= dt.timedelta(days=7):
        return "recent"
    if record["tier"] in {"observed", "inferred"} and age <= dt.timedelta(days=30):
        return "historical"
    return "expired"


def _public_record(
    record: dict[str, object], observed_at: dt.datetime
) -> dict[str, object]:
    freshness = _freshness(record, observed_at)
    public = {
        key: value
        for key, value in record.items()
        if not key.startswith("_")
    } | {
        "freshness": freshness,
        "operating_system_observed_at": str(
            record.get("operating_system_observed_at") or ""
        ),
        "operating_system_freshness": str(
            record.get("operating_system_freshness") or ""
        ),
        "operating_system_association": str(
            record.get("operating_system_association") or ""
        ),
    }
    if (
        record["source"] == "osquery_apps"
        and record["operating_system_source"] in ENDPOINT_OS_SOURCES
        and (
            record["operating_system_type"]
            or record["operating_system_version"]
        )
    ):
        public["operating_system_observed_at"] = record["last_seen"]
        public["operating_system_freshness"] = freshness
    observed_user_agent = ""
    if record["source"] == "http_user_agent":
        observed_user_agent = str(record["product"])
    elif (
        record["source"] == "zeek_software"
        and str(record["category"]).casefold() == "http::browser"
    ):
        observed_user_agent = str(record["version"])
    if observed_user_agent:
        public["observed_user_agent"] = observed_user_agent
    return public


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


def _empty_payload(
    observed_at: dt.datetime,
    filters: dict[str, object],
    *,
    error: str,
) -> dict[str, object]:
    return {
        "ok": False,
        "schema": API_SCHEMA,
        "generated_at": "",
        "observed_at": _utc_iso(observed_at),
        "collection": {
            "status": "unavailable",
            "complete": False,
            "window": {},
            "last_attempt_at": "",
            "last_success_at": "",
            "last_error": error,
            "source_statuses": {},
        },
        "summary": {
            "records": 0,
            "products": 0,
            "assets": 0,
            "installed": 0,
            "observed": 0,
            "inferred": 0,
            "current": 0,
            "recent": 0,
            "historical": 0,
            "expired": 0,
        },
        "coverage": {
            "authoritative_denominator": None,
            "denominator_status": "unknown",
            "osquery_ready": None,
            "fresh_endpoint_inventories": 0,
            "network_observed_assets": 0,
            "coverage_gaps": None,
            "labeled_visible_records": 0,
            "asset_label_inventory_complete": False,
            "asset_os_correlated_records": 0,
        },
        "filters": filters,
        "platforms": [],
        "page": {
            "limit": filters["limit"],
            "offset": filters["offset"],
            "filtered_total": 0,
            "has_more": False,
        },
        "items": [],
        "warnings": [error],
        "revision": "",
        "error": error,
    }


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
    apply_asset_labels(
        state_records,
        assets,
        inventory_complete=asset_inventory_complete,
    )
    correlate_asset_operating_systems(
        state_records,
        state_records,
        assets=assets,
        observed_at=now,
    )
    window_start = now - WINDOWS[str(filters["window"])]
    all_window_records = [
        item
        for item in state_records
        if item["_last_seen"] >= window_start  # type: ignore[index,operator]
    ]
    records = list(all_window_records)
    if filters["tier"] != "all":
        records = [item for item in records if item["tier"] == filters["tier"]]
    if filters["confidence"] != "all":
        records = [
            item
            for item in records
            if item["confidence"] == filters["confidence"]
        ]
    if filters["freshness"] != "all":
        records = [
            item
            for item in records
            if _freshness(item, now) == filters["freshness"]
        ]
    if str(filters["platform"]).lower() != "all":
        platform = str(filters["platform"]).casefold()
        records = [
            item
            for item in records
            if str(item["platform"]).casefold() == platform
        ]
    if filters["search"]:
        needle = str(filters["search"]).casefold()
        records = [
            item
            for item in records
            if needle
            in " ".join(
                str(item[key])
                for key in (
                    "product",
                    "version",
                    "asset_ref",
                    "platform",
                    "operating_system_type",
                    "operating_system_version",
                    "category",
                    "source",
                )
            ).casefold()
        ]

    sort_key = {
        "last_seen": lambda item: (item["_last_seen"], item["evidence_id"]),
        "first_seen": lambda item: (item["_first_seen"], item["evidence_id"]),
        "product": lambda item: (
            str(item["product"]).casefold(),
            str(item["version"]).casefold(),
            item["evidence_id"],
        ),
        "asset": lambda item: (
            str(item["asset_ref"]).casefold(),
            str(item["product"]).casefold(),
            item["evidence_id"],
        ),
        "tier": lambda item: (
            str(item["tier"]),
            str(item["product"]).casefold(),
            item["evidence_id"],
        ),
        "confidence": lambda item: (
            str(item["confidence"]),
            str(item["product"]).casefold(),
            item["evidence_id"],
        ),
    }[str(filters["sort"])]
    records.sort(key=sort_key, reverse=filters["direction"] == "desc")
    offset = int(filters["offset"])
    limit = int(filters["limit"])
    selected = records[offset : offset + limit]
    public_records = [_public_record(item, now) for item in records]
    summary = {
        "records": len(records),
        "products": len(
            {
                str(item["product"]).casefold()
                for item in records
            }
        ),
        "assets": len({str(item["asset_ref"]) for item in records}),
    }
    for tier in sorted(TIERS):
        summary[tier] = sum(item["tier"] == tier for item in records)
    for freshness in ("current", "recent", "historical", "expired"):
        summary[freshness] = sum(
            item["freshness"] == freshness for item in public_records
        )

    window_public = [_public_record(item, now) for item in all_window_records]
    fresh_endpoint_assets = {
        str(item["asset_ref"])
        for item in window_public
        if item["tier"] == "installed" and item["freshness"] == "current"
    }
    network_assets = {
        str(item["asset_ref"])
        for item in window_public
        if item["tier"] in {"observed", "inferred"}
    }
    collection = state["collection"]
    osquery_ready = collection.get("osquery_ready")  # type: ignore[union-attr]
    if isinstance(osquery_ready, bool) or not isinstance(osquery_ready, int):
        osquery_ready = None
    coverage_gaps = (
        max(osquery_ready - len(fresh_endpoint_assets), 0)
        if osquery_ready is not None
        else None
    )
    warnings = [
        (
            "LAN software coverage has no authoritative asset denominator; "
            "counts describe only observable evidence."
        )
    ]
    if not collection.get("complete"):  # type: ignore[union-attr]
        warnings.append(
            "The latest collection was incomplete; showing the last valid snapshot."
        )
    last_error = str(collection.get("last_error") or "")  # type: ignore[union-attr]
    if last_error:
        warnings.append(f"Latest collection warning: {last_error}")
    if not fresh_endpoint_assets:
        warnings.append(
            "No current endpoint-reported inventory is visible; passive "
            "network evidence cannot prove software is absent."
        )

    return 200, {
        "ok": True,
        "schema": API_SCHEMA,
        "generated_at": state["updated_at"],
        "observed_at": _utc_iso(now),
        "collection": collection,
        "summary": summary,
        "coverage": {
            "authoritative_denominator": None,
            "denominator_status": "unknown",
            "osquery_ready": osquery_ready,
            "fresh_endpoint_inventories": len(fresh_endpoint_assets),
            "network_observed_assets": len(network_assets),
            "coverage_gaps": coverage_gaps,
            "labeled_visible_records": sum(
                bool(item.get("asset_label")) for item in records
            ),
            "asset_label_inventory_complete": asset_inventory_complete,
            "asset_os_correlated_records": sum(
                bool(item.get("operating_system_association"))
                for item in records
            ),
        },
        "filters": filters,
        "platforms": sorted(
            {
                str(item["platform"])
                for item in all_window_records
                if str(item["platform"])
            },
            key=str.casefold,
        ),
        "page": {
            "limit": limit,
            "offset": offset,
            "filtered_total": len(records),
            "has_more": offset + len(selected) < len(records),
        },
        "items": [_public_record(item, now) for item in selected],
        "warnings": warnings,
        "revision": revision,
    }
