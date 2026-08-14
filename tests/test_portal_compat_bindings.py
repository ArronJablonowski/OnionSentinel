from __future__ import annotations

import functools
import hashlib
import importlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

bindings = importlib.import_module("portal_compat_bindings")
portal = importlib.import_module("report_portal")


class PortalCompatibilityBindingTests(unittest.TestCase):
    def test_binding_catalog_and_every_delegate_identity_are_exact(self) -> None:
        self.assertEqual(len(bindings._BINDINGS), 357)
        self.assertEqual(len({entry[0] for entry in bindings._BINDINGS}), 357)
        digest = hashlib.sha256(
            json.dumps(bindings._BINDINGS, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(
            digest,
            "f93becfc4aeb256e90ed5a63ff99db0223d5a25b23ee1cf640d9691ad8cc2490",
        )
        for public_name, module_name, target_name in bindings._BINDINGS:
            with self.subTest(public_name=public_name):
                delegate = getattr(portal, public_name)
                self.assertIsInstance(delegate, functools.partial)
                self.assertIs(delegate.func, getattr(getattr(portal, module_name), target_name))
                self.assertEqual(delegate.args, (portal,))
                self.assertEqual(delegate.keywords, {})

    def test_runtime_markers_callbacks_and_mutable_state_are_portal_owned(self) -> None:
        for marker in (
            "_FOUNDATION_RUNTIME", "_ACCESS_RUNTIME", "_SETTINGS_RUNTIME",
            "_ADMIN_RUNTIME", "_CATALOG_RUNTIME", "_OPERATIONAL_RUNTIME",
            "_DASHBOARD_RUNTIME", "_SOC_DETAIL_RUNTIME", "_SOC_PCAP_RUNTIME",
            "_WRITE_RUNTIME", "_SOC_STATUS_RUNTIME", "_LLM_RUNTIME",
            "_SOC_CORE_RUNTIME", "_SOC_RECORD_RUNTIME",
            "_INCIDENT_ACTION_RUNTIME", "_INCIDENT_READ_RUNTIME",
            "_SOC_QUERY_RUNTIME", "_DELIVERY_RUNTIME",
        ):
            self.assertIs(getattr(portal, marker), portal)
        self.assertEqual(portal.DISK_INVENTORY_CACHE, {
            "generated": 0.0, "dirs": [], "files": [], "warnings": []
        })
        self.assertEqual(portal.LLM_ANALYSIS_COMBINED_HISTORY_LIMIT, 5000)
        self.assertTrue(portal.SOC_ALERT_DETAIL_LAYOUT_MARKERS)
        self.assertTrue(portal.SOC_ALERT_SORT_SQL)
        self.assertTrue(portal.SOC_ALERT_DETECTION_OUTCOME_LABELS)
        self.assertIsNotNone(portal.INCIDENT_ROW_CALLBACKS)
        self.assertIsNotNone(portal.PORTAL_SOC_WRITE_CALLBACKS)
        self.assertTrue(issubclass(portal.PortalHandler, portal.BaseHTTPRequestHandler))


if __name__ == "__main__":
    unittest.main()
