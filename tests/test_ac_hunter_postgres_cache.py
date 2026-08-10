#!/usr/bin/env python3
"""Deployment contracts for scheduled PostgreSQL-backed AC Hunter caching."""
from __future__ import annotations

import plistlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AcHunterPostgresCacheTests(unittest.TestCase):
    def test_schema_has_content_addressed_snapshots_and_24_hour_pruning(self) -> None:
        schema = (ROOT / "n8n/postgres/ac-hunter-schema.sql").read_text()
        store = (
            ROOT / "n8n/alert_store/lib/postgres_ac_hunter_store.js"
        ).read_text()
        self.assertIn("dataset_digest TEXT PRIMARY KEY", schema)
        self.assertIn("current_state", schema)
        self.assertIn("pull_runs", schema)
        self.assertIn("interval '24 hours'", store)
        self.assertIn("previousDigest !== digest", store)
        self.assertIn("if (changed)", store)
        self.assertIn("ON CONFLICT (dataset_digest) DO NOTHING", store)

    def test_launch_agent_runs_hourly_at_minute_35_without_run_at_load(self) -> None:
        plist_path = ROOT / "n8n/launchd/com.arron.soc.ac-hunter.plist"
        value = plistlib.loads(plist_path.read_bytes())
        self.assertEqual(value["Label"], "com.arron.soc.ac-hunter")
        self.assertEqual(value["StartCalendarInterval"], {"Minute": 35})
        self.assertNotIn("StartInterval", value)
        self.assertNotIn("RunAtLoad", value)

    def test_installer_deploys_store_schema_collector_and_launch_agent(self) -> None:
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        for required in (
            "postgres_ac_hunter_store.js",
            "ac-hunter-schema.sql",
            "collect-ac-hunter.py",
            "com.arron.soc.ac-hunter.plist",
        ):
            self.assertIn(required, installer)

    def test_web_read_path_cannot_collect_from_relay(self) -> None:
        backend = (
            ROOT / "onion-sentinel-dashboard/ac_hunter_review.py"
        ).read_text()
        page = (
            ROOT / "onion-sentinel-dashboard/scripts/dashboard_ac_hunter_page.py"
        ).read_text()
        self.assertIn("return database_review_response()", backend)
        self.assertNotIn("fetchJson(REFRESH_ENDPOINT", page)
        self.assertIn("Reload stored snapshot", page)

    def test_reactive_revision_uses_only_the_database_digest(self) -> None:
        delivery = (
            ROOT / "onion-sentinel-dashboard/portal_delivery_runtime.py"
        ).read_text()
        self.assertIn('"ac_hunter": r.ac_hunter_live_revision()', delivery)
        self.assertIn('r.alert_store_get_json("/ac-hunter/snapshot"', delivery)
        self.assertIn('cache.get("dataset_digest")', delivery)


if __name__ == "__main__":
    unittest.main()
