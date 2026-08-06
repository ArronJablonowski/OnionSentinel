#!/usr/bin/env python3
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "collect-endpoint-software-inventory.py"
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))


def load_module():
    loader = importlib.machinery.SourceFileLoader(
        "endpoint_software_inventory_test", str(SCRIPT)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class EndpointSoftwareInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def config(self):
        return {
            "enabled": True,
            "allowed_target_aliases": ["studio"],
            "scheduled_inventory_approval": {
                "approved": True,
                "target_aliases": ["studio"],
            },
        }

    def test_collects_apps_homebrew_and_full_os_version(self):
        calls = []

        def fake_collect(*, requests, **_kwargs):
            query = requests[0]["query"]
            calls.append(query)
            if "FROM system_info" in query:
                rows = [{"hostname": "studio.example"}]
            elif "FROM os_version" in query:
                rows = [{
                    "name": "macOS", "version": "26.0", "build": "25A1",
                    "platform": "darwin", "arch": "arm64",
                }]
            elif "FROM apps" in query:
                rows = [{
                    "name": "Firefox", "path": "/Applications/Firefox.app",
                    "bundle_identifier": "org.mozilla.firefox",
                    "bundle_name": "Firefox", "bundle_short_version": "153.0",
                    "bundle_version": "15300", "bundle_package_type": "APPL",
                }]
            elif "FROM homebrew_packages" in query:
                rows = [{
                    "name": "ripgrep", "path": "/opt/homebrew/Cellar/ripgrep",
                    "version": "15.1", "type": "formula",
                }]
            else:
                raise AssertionError(query)
            return {
                "complete": True,
                "results": [{
                    "status": "ok", "truncated": False, "rows": rows,
                }],
            }

        with mock.patch.object(self.module, "collect_live_osquery", fake_collect):
            result = self.module.collect(self.config())

        self.assertTrue(result["complete"])
        self.assertEqual(len(result["targets"]), 1)
        self.assertEqual(
            {item["product"] for item in result["records"]},
            {"Firefox", "ripgrep"},
        )
        self.assertTrue(
            all(item["source_dataset"] == "osquery.live.software_inventory"
                for item in result["records"])
        )
        self.assertTrue(
            all(item["operating_system_version"] == "macOS 26.0 (build 25A1)"
                for item in result["records"])
        )
        self.assertTrue(any("ORDER BY path" in query for query in calls))

    def test_cache_is_private_and_main_collector_accepts_live_provenance(self):
        value = {
            "schema": self.module.SCHEMA,
            "version": 1,
            "updated_at": "2026-08-06T13:00:00.000Z",
            "complete": True,
            "targets": [{
                "asset_ref": "a" * 24,
                "status": "ok",
                "records": 1,
                "observed_at": "2026-08-06T13:00:00.000Z",
            }],
            "records": [{
                "evidence_id": "b" * 24,
                "source": "osquery_apps",
                "source_dataset": "osquery.live.software_inventory",
                "tier": "installed",
                "confidence": "high",
                "asset_ref_type": "host",
                "asset_ref": "a" * 24,
                "platform": "darwin",
                "operating_system_type": "macOS",
                "operating_system_version": "macOS 26.0",
                "operating_system_source": "osquery.live:os_version",
                "operating_system_confidence": "high",
                "product": "Firefox",
                "version": "153",
                "category": "application",
                "first_seen": "2026-08-06T13:00:00.000Z",
                "last_seen": "2026-08-06T13:00:00.000Z",
                "observation_count": 1,
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private" / "cache.json"
            self.module.atomic_write(path, value)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(self.module.load_cache(path), value)

            from tests.test_software_inventory_collector import load_collector
            collector = load_collector()
            loaded = collector.load_endpoint_cache(
                path,
                collector.parse_timestamp("2026-08-06T14:00:00.000Z"),
            )
            self.assertEqual(loaded["targets"], 1)
            self.assertEqual(
                loaded["records"][0]["operating_system_source"],
                "osquery.live:os_version",
            )


if __name__ == "__main__":
    unittest.main()
