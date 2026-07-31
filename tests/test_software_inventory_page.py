#!/usr/bin/env python3
"""Frontend contracts for truth-preserving software inventory evidence."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = (
    ROOT
    / "onion-sentinel-dashboard"
    / "scripts"
    / "build_soc_alerts_dashboard.py"
)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "software_inventory_page_builder",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()
        cls.page = cls.builder.render_static_page(
            cls.builder.build_html([]),
            "software_inventory",
            [],
        )

    def test_navigation_and_page_identity_are_generated(self) -> None:
        keys = [definition[0] for definition in self.builder.PAGE_DEFS]

        self.assertEqual(
            keys[keys.index("asset_inventory") + 1],
            "software_inventory",
        )
        self.assertEqual(
            keys[keys.index("software_inventory") + 1],
            "system_health",
        )
        self.assertIn(
            '<a class="nav-item active" href="software-inventory.html"',
            self.page,
        )
        self.assertIn(
            '<h1 id="page-title">Software Inventory</h1>',
            self.page,
        )
        self.assertIn('id="software-inventory-view"', self.page)
        self.assertIn(
            "Endpoint-reported, network-observed, and inferred software evidence",
            self.page,
        )

    def test_coverage_and_provenance_never_inflate_passive_evidence(self) -> None:
        for identifier in (
            "software-denominator",
            "software-osquery-ready-total",
            "software-fresh-endpoint-total",
            "software-network-observed-total",
            "software-coverage-gap-total",
            "software-installed-total",
            "software-observed-total",
            "software-inferred-total",
            "software-current-total",
            "software-recent-total",
            "software-historical-total",
            "software-expired-total",
        ):
            self.assertIn(f'id="{identifier}"', self.page)

        self.assertIn("Endpoint-reported", self.page)
        self.assertIn(
            "It does not prove a complete endpoint inventory or a current installation.",
            self.page,
        )
        self.assertNotIn(
            "successful, complete, target-bound endpoint query",
            self.page,
        )
        self.assertIn("Observed network", self.page)
        self.assertIn("Inferred", self.page)
        self.assertIn(
            "Coverage percentage cannot be calculated without an authoritative LAN denominator.",
            self.page,
        )
        self.assertIn(
            "Endpoint, passive, and inferred populations are not interchangeable.",
            self.page,
        )
        self.assertIn(
            "it does not prove a current installation",
            self.page,
        )
        self.assertIn(
            "never count as installed-software truth",
            self.page,
        )
        self.assertIn("Evidence freshness", self.page)
        self.assertIn("Passive evidence within 30 days", self.page)

    def test_filters_table_and_api_query_match_the_public_contract(self) -> None:
        for identifier in (
            "software-search",
            "software-tier-filter",
            "software-confidence-filter",
            "software-freshness-filter",
            "software-platform-filter",
            "software-window-filter",
            "software-sort",
            "software-direction",
            "software-page-size",
            "software-clear-filters",
            "software-retry",
        ):
            self.assertIn(f'id="{identifier}"', self.page)

        self.assertIn("fetch('/api/software-inventory'", self.page)
        self.assertIn('<option value="installed">Endpoint-reported</option>', self.page)
        self.assertIn('<option value="observed">Observed network</option>', self.page)
        self.assertIn('<option value="all">All confidence</option>', self.page)
        self.assertIn('<option value="asset">Asset</option>', self.page)
        self.assertNotIn('<option value="asset_ref">Asset</option>', self.page)
        self.assertNotIn('<option value="freshness">Freshness</option>', self.page)
        self.assertIn(
            "limit:pageSize.value,offset:String(pageOffset),search:search.value.trim(),"
            "tier:tier.value,confidence:confidence.value,freshness:freshness.value,"
            "platform:platform.value,window:timeWindow.value,sort:sort.value,"
            "direction:direction.value",
            self.page,
        )
        self.assertIn(
            "<th>Asset / host</th><th>Software</th><th>Version</th>"
            "<th>Evidence tier</th>",
            self.page,
        )
        self.assertIn(
            "<th>First seen</th><th>Last seen</th><th>Collection</th>",
            self.page,
        )
        self.assertIn(
            'colspan="10" class="ir-loading">Loading software evidence',
            self.page,
        )
        self.assertIn("payload.summary||{}", self.page)
        self.assertIn("payload.coverage||{}", self.page)
        self.assertIn("payload.collection||{}", self.page)
        self.assertIn(
            "collection.window&&typeof collection.window==='object'",
            self.page,
        )
        self.assertIn(
            "collectionWindow.start&&collectionWindow.end",
            self.page,
        )
        self.assertNotIn(
            "String(collection.window)",
            self.page,
        )
        self.assertIn(
            "softwareItems=Array.isArray(payload.items)?payload.items:[]",
            self.page,
        )
        self.assertIn("pageMeta=payload.page||", self.page)
        self.assertIn("hydratePlatforms(payload.platforms||[])", self.page)
        self.assertIn("Array.isArray(payload.warnings)", self.page)
        self.assertIn(
            "payload.summary&&payload.coverage&&payload.page",
            self.page,
        )

    def test_values_are_escaped_and_empty_states_preserve_uncertainty(self) -> None:
        self.assertIn("const esc=value=>", self.page)
        self.assertIn("${esc(first(item.product,'Unknown software'))}", self.page)
        self.assertIn("${esc(first(item.version,'Unknown version'))}", self.page)
        self.assertIn("first(item?.asset_label,item?.asset_ref,'Unresolved asset')", self.page)
        self.assertIn(
            "const assetLabel=String(item?.asset_label??'').trim()",
            self.page,
        )
        self.assertNotIn(
            "const assetLabel=String(first(item?.asset_label,''))",
            self.page,
        )
        self.assertIn("asset-inventory.html?asset=${esc(encodeURIComponent(assetLabel))}", self.page)
        self.assertIn("${esc(first(item.asset_ref,'Not supplied'))}", self.page)
        self.assertIn("warnings.map(value=>`<li>${esc(value)}</li>`)", self.page)
        self.assertIn(
            "No successful endpoint software inventory was collected in this window. "
            "This does not mean no software is installed.",
            self.page,
        )
        self.assertIn(
            "No network-observed software was seen in this window. "
            "Passive absence is not evidence of absence.",
            self.page,
        )
        self.assertIn(
            "No software evidence has been collected in this window. "
            "Absence is not evidence of absence.",
            self.page,
        )
        self.assertIn(
            "Software inventory is temporarily unavailable. Retry the request.",
            self.page,
        )
        self.assertIn(
            "No inventory conclusion can be drawn.",
            self.page,
        )
        self.assertIn(
            "metric(coverage.osquery_ready,'Unknown')",
            self.page,
        )
        self.assertIn(
            "metric(coverage.coverage_gaps,'Unknown')",
            self.page,
        )

    def test_responsive_cards_and_refresh_preserve_interaction_state(self) -> None:
        self.assertIn('id="software-mobile-list"', self.page)
        self.assertIn("@media(max-width:900px)", self.page)
        self.assertIn(".software-table-wrap{display:none}", self.page)
        self.assertIn(".software-mobile-list{display:grid;gap:10px}", self.page)
        self.assertIn("min-height:44px", self.page)
        self.assertIn("captureViewState()", self.page)
        self.assertIn("restoreViewState(viewState)", self.page)
        self.assertIn("data-software-evidence-id=", self.page)
        self.assertIn("if(softwareLoadPromise){", self.page)
        self.assertIn("if(announce)softwareReloadPending=true", self.page)
        self.assertIn(
            "if(requestKey!==requestParams().toString())return false",
            self.page,
        )
        self.assertIn(
            "if(nextSignature===softwareSignature)return false",
            self.page,
        )
        self.assertIn(
            "snapshotTime=payload=>String(first(payload?.collection?.last_success_at,"
            "payload?.generated_at,''))",
            self.page,
        )
        self.assertNotIn(
            "lastSuccessfulAt=String(first(payload.observed_at",
            self.page,
        )
        self.assertIn(
            "softwareItems.length&&requestKey===lastSuccessfulRequestKey",
            self.page,
        )
        self.assertIn(
            "Previous results are hidden because they belong to a different request.",
            self.page,
        )
        self.assertIn(
            "register('software-inventory-table',load,"
            "{intervalMs:60000,revisionKey:'software_inventory'})",
            self.page,
        )

    def test_desktop_software_column_does_not_wrap(self) -> None:
        self.assertIn(".software-table{table-layout:auto}", self.page)
        self.assertIn(
            ".software-table th:nth-child(2),.software-table td:nth-child(2)"
            "{white-space:nowrap}",
            self.page,
        )
        self.assertIn(
            ".software-table td:nth-child(2) .software-name"
            "{overflow-wrap:normal;word-break:normal}",
            self.page,
        )
        self.assertNotIn(
            ".software-mobile-title{white-space:nowrap}",
            self.page,
        )


if __name__ == "__main__":
    unittest.main()
