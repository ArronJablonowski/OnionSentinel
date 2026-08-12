"""Compatibility facade for Software Inventory asset correlation."""
from __future__ import annotations

from software_inventory_asset_labels import apply_asset_labels
from software_inventory_os_correlation import correlate_asset_operating_systems


__all__ = [
    "apply_asset_labels",
    "correlate_asset_operating_systems",
]
