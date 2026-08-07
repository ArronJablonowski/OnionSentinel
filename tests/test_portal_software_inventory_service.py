"""Direct contracts for Software Inventory source orchestration."""
from __future__ import annotations

import datetime as dt
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_software_inventory_service import (  # noqa: E402
    AssetLabelSnapshot,
    INCOMPLETE_ASSET_WARNING,
    database_query_parameters,
    enrich_database_payload,
    load_asset_label_snapshot,
)


UTC = dt.timezone.utc


class SoftwareInventoryServiceTests(unittest.TestCase):
    def test_asset_snapshot_pages_until_complete_with_stable_offsets(self) -> None:
        offsets: list[int] = []

        def read_page(query):
            offset = int(query["offset"][0])
            offsets.append(offset)
            rows = [{"asset_id": "a"}] if offset == 0 else [{"asset_id": "b"}]
            return 200, {"assets": rows, "page": {"has_more": offset == 0}}

        snapshot = load_asset_label_snapshot(
            read_page, page_size=1, maximum_pages=3, maximum_records=3,
        )

        self.assertEqual(offsets, [0, 1])
        self.assertEqual([item["asset_id"] for item in snapshot.assets], ["a", "b"])
        self.assertTrue(snapshot.complete)

    def test_asset_snapshot_never_claims_completeness_after_bounded_exhaustion(self) -> None:
        snapshot = load_asset_label_snapshot(
            lambda query: (200, {"assets": [{"asset_id": "a"}], "page": {"has_more": True}}),
            page_size=1,
            maximum_pages=2,
            maximum_records=2,
        )

        self.assertEqual(len(snapshot.assets), 2)
        self.assertFalse(snapshot.complete)

    def test_database_parameters_are_allowlisted_and_include_observation_time(self) -> None:
        observed = dt.datetime(2026, 8, 7, 12, tzinfo=UTC)
        params = database_query_parameters(
            {"search": ["Firefox"], "dsl": ["not-forwarded"]},
            observed,
            lambda value: value.isoformat(),
        )

        self.assertEqual(params["search"], "Firefox")
        self.assertEqual(params["limit"], "100")
        self.assertNotIn("dsl", params)
        self.assertEqual(params["observed_at"], observed.isoformat())

    def test_database_enrichment_counts_visible_labels_and_os_associations(self) -> None:
        payload = {
            "items": [{"asset_label": ""}, {"asset_label": ""}],
            "coverage": {},
            "warnings": [],
        }
        calls: list[str] = []

        def labels(items, assets, *, inventory_complete):
            calls.append("labels")
            items[0]["asset_label"] = assets[0]["asset_id"]

        def operating_systems(items, all_items, *, assets, observed_at):
            calls.append("os")
            items[0]["operating_system_association"] = "asset_inventory:unit"

        result = enrich_database_payload(
            payload,
            AssetLabelSnapshot([{"asset_id": "studio"}], True),
            observed_at=dt.datetime.now(UTC),
            apply_asset_labels=labels,
            correlate_operating_systems=operating_systems,
        )

        self.assertEqual(calls, ["labels", "os"])
        self.assertEqual(result["coverage"]["labeled_visible_records"], 1)
        self.assertEqual(result["coverage"]["asset_os_correlated_records"], 1)
        self.assertTrue(result["coverage"]["asset_label_inventory_complete"])

    def test_incomplete_snapshot_withholds_claim_and_adds_existing_warning(self) -> None:
        payload = {"items": [], "coverage": {}, "warnings": []}
        result = enrich_database_payload(
            payload,
            AssetLabelSnapshot([], False),
            observed_at=dt.datetime.now(UTC),
            apply_asset_labels=lambda *args, **kwargs: None,
            correlate_operating_systems=lambda *args, **kwargs: None,
        )

        self.assertFalse(result["coverage"]["asset_label_inventory_complete"])
        self.assertEqual(result["warnings"], [INCOMPLETE_ASSET_WARNING])


if __name__ == "__main__":
    unittest.main()
