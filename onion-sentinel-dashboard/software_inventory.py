#!/usr/bin/env python3
"""Bounded, provenance-aware Software Inventory compatibility facade."""
from __future__ import annotations

from pathlib import Path
import sys

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

from software_inventory_assets import (
    apply_asset_labels,
    correlate_asset_operating_systems,
)
from software_inventory_query import (
    _empty_payload,
    _freshness,
    _one,
    _public_record,
    parse_filters,
)
from software_inventory_response import build_response
