import datetime as dt
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))
inventory = importlib.import_module("software_inventory")
portal = importlib.import_module("report_portal")


NOW = dt.datetime(2026, 7, 30, 18, 0, tzinfo=dt.timezone.utc)


def iso(days_ago=0, hours_ago=0):
    value = NOW - dt.timedelta(days=days_ago, hours=hours_ago)
    return value.isoformat().replace("+00:00", "Z")


def record(
    evidence_id,
    source,
    asset_ref,
    product,
    *,
    days_ago=0,
    hours_ago=0,
    version="1.0",
):
    tier, confidence = inventory.SOURCES[source]
    return {
        "evidence_id": evidence_id,
        "source": source,
        "source_dataset": {
            "osquery_apps": "osquery_manager.result",
            "zeek_software": "zeek.software",
            "http_user_agent": "zeek.http",
        }[source],
        "tier": tier,
        "confidence": confidence,
        "asset_ref_type": "host" if source == "osquery_apps" else "ip",
        "asset_ref": asset_ref,
        "platform": "macOS" if source == "osquery_apps" else "network",
        "operating_system_type": (
            "macOS" if source == "osquery_apps" else ""
        ),
        "operating_system_version": (
            "macOS 26.0 (25A5306g)"
            if source == "osquery_apps"
            else ""
        ),
        "operating_system_source": (
            "osquery_manager.result:host.os"
            if source == "osquery_apps"
            else ""
        ),
        "operating_system_confidence": (
            "high" if source == "osquery_apps" else ""
        ),
        "product": product,
        "version": version,
        "category": "application",
        "first_seen": iso(days_ago=days_ago + 1, hours_ago=hours_ago),
        "last_seen": iso(days_ago=days_ago, hours_ago=hours_ago),
        "observation_count": 1,
        "private_agent_id": "must-not-be-public",
    }


def state():
    return {
        "schema": inventory.STATE_SCHEMA,
        "version": 1,
        "updated_at": iso(),
        "collection": {
            "status": "succeeded",
            "complete": True,
            "window": {
                "start": iso(days_ago=30),
                "end": iso(),
            },
            "last_attempt_at": iso(),
            "last_success_at": iso(),
            "last_error": "",
            "osquery_ready": 2,
            "source_statuses": {
                "osquery_apps": {"status": "succeeded", "records": 2, "pages": 1},
                "zeek_software": {"status": "succeeded", "records": 1, "pages": 1},
                "http_user_agent": {"status": "succeeded", "records": 1, "pages": 1},
            },
            "relay_token": "must-not-be-public",
        },
        "records": [
            record(
                "000000000000000000000001",
                "osquery_apps",
                "aaaaaaaaaaaaaaaaaaaaaaaa",
                "Firefox",
                hours_ago=0,
                version="140.0",
            ),
            record(
                "000000000000000000000002",
                "osquery_apps",
                "bbbbbbbbbbbbbbbbbbbbbbbb",
                "Old Utility",
                days_ago=8,
            ),
            record(
                "000000000000000000000003",
                "zeek_software",
                "10.100.4.21",
                "OpenSSH",
                days_ago=2,
                version="9.9",
            ),
            record(
                "000000000000000000000004",
                "http_user_agent",
                "10.100.4.22",
                "Safari",
                days_ago=10,
                version="",
            ),
        ],
        "secret": "must-not-be-public",
    }


class SoftwareInventoryApiTests(unittest.TestCase):
    def write_state(self, directory, payload=None, mode=0o600):
        path = Path(directory) / "software-inventory.json"
        path.write_text(json.dumps(payload or state()), encoding="utf-8")
        path.chmod(mode)
        return path

    def test_response_preserves_provenance_and_truthful_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp)
            status, payload = inventory.build_response(
                path, observed_at=NOW
            )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["summary"]["records"], 4)
        self.assertEqual(payload["summary"]["installed"], 2)
        self.assertEqual(payload["summary"]["observed"], 1)
        self.assertEqual(payload["summary"]["inferred"], 1)
        self.assertEqual(payload["summary"]["current"], 1)
        self.assertEqual(payload["summary"]["recent"], 1)
        self.assertEqual(payload["summary"]["historical"], 1)
        self.assertEqual(payload["summary"]["expired"], 1)
        self.assertIsNone(payload["coverage"]["authoritative_denominator"])
        self.assertEqual(payload["coverage"]["denominator_status"], "unknown")
        self.assertEqual(payload["coverage"]["fresh_endpoint_inventories"], 1)
        self.assertEqual(payload["coverage"]["coverage_gaps"], 1)
        self.assertNotIn("secret", payload)
        self.assertNotIn("relay_token", payload["collection"])
        self.assertNotIn("private_agent_id", payload["items"][0])
        self.assertTrue(
            any("observable evidence" in warning for warning in payload["warnings"])
        )

    def test_response_exposes_user_agent_only_for_http_evidence(self):
        raw = state()
        raw["records"][2]["category"] = "HTTP::BROWSER"
        raw["records"][2]["version"] = "OpenSSH-browser-agent/9.9"
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp, raw)
            status, payload = inventory.build_response(
                path, observed_at=NOW
            )

        self.assertEqual(status, 200)
        items = {
            item["evidence_id"]: item
            for item in payload["items"]
        }
        self.assertEqual(
            items["000000000000000000000004"]["observed_user_agent"],
            "Safari",
        )
        self.assertEqual(
            items["000000000000000000000003"]["observed_user_agent"],
            "OpenSSH-browser-agent/9.9",
        )
        self.assertNotIn(
            "observed_user_agent",
            items["000000000000000000000001"],
        )

    def test_summary_products_counts_distinct_names_not_versions(self):
        raw = state()
        raw["records"].append(
            record(
                "000000000000000000000005",
                "osquery_apps",
                "cccccccccccccccccccccccc",
                "fireFOX",
                version="141.0",
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp, raw)
            status, payload = inventory.build_response(
                path, observed_at=NOW
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload["summary"]["records"], 5)
        self.assertEqual(payload["summary"]["products"], 4)

    def test_initial_disabled_collector_state_is_api_readable(self):
        from tests.test_software_inventory_collector import load_collector

        collector = load_collector()
        raw = collector.disabled_state(collector.empty_state(), NOW)
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp, raw)
            status, payload = inventory.build_response(
                path, observed_at=NOW
            )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["generated_at"], iso())
        self.assertEqual(payload["collection"]["status"], "disabled")
        self.assertEqual(
            payload["collection"]["window"],
            {
                "start": iso(days_ago=30),
                "end": iso(),
            },
        )
        self.assertEqual(payload["summary"]["records"], 0)

    def test_initial_failed_collector_state_is_api_readable(self):
        from tests.test_software_inventory_collector import load_collector

        collector = load_collector()
        raw = collector.failed_state(
            collector.empty_state(),
            NOW,
            "relay unavailable",
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp, raw)
            status, payload = inventory.build_response(
                path, observed_at=NOW
            )
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["generated_at"], iso())
        self.assertEqual(payload["collection"]["status"], "failed")
        self.assertEqual(payload["collection"]["last_error"], "relay unavailable")
        self.assertEqual(
            payload["collection"]["window"],
            {
                "start": iso(days_ago=30),
                "end": iso(),
            },
        )
        self.assertEqual(payload["summary"]["records"], 0)

    def test_filters_sort_and_pagination_are_fixed_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp)
            status, payload = inventory.build_response(
                path,
                {
                    "tier": ["installed"],
                    "search": ["fire"],
                    "window": ["24h"],
                    "sort": ["product"],
                    "direction": ["asc"],
                    "limit": ["1"],
                    "offset": ["0"],
                },
                observed_at=NOW,
            )
        self.assertEqual(status, 200)
        self.assertEqual(payload["page"]["filtered_total"], 1)
        self.assertFalse(payload["page"]["has_more"])
        self.assertEqual(payload["items"][0]["product"], "Firefox")
        self.assertEqual(payload["items"][0]["freshness"], "current")

    def test_invalid_or_arbitrary_query_parameters_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp)
            for query in (
                {"dsl": ['{"query":{"match_all":{}}}']},
                {"limit": ["100000"]},
                {"tier": ["authoritative"]},
                {"window": ["365d"]},
            ):
                status, payload = inventory.build_response(
                    path, query, observed_at=NOW
                )
                self.assertEqual(status, 400)
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["items"], [])

    def test_missing_symlink_and_other_user_writable_state_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            status, _payload = inventory.build_response(
                root / "missing.json", observed_at=NOW
            )
            self.assertEqual(status, 503)

            target = self.write_state(tmp)
            target.chmod(0o666)
            status, payload = inventory.build_response(target, observed_at=NOW)
            self.assertEqual(status, 503)
            self.assertIn("writable by another user", payload["error"])

            target.chmod(0o600)
            link = root / "link.json"
            os.symlink(target, link)
            status, payload = inventory.build_response(link, observed_at=NOW)
            self.assertEqual(status, 503)
            self.assertIn("regular file", payload["error"])

    def test_raw_osquery_agent_identifier_is_rejected(self):
        raw = state()
        raw["records"][0]["asset_ref"] = "b8a8c75a-6d61-4ea8-a5bf-b08ddf6f3f22"
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp, raw)
            status, payload = inventory.build_response(path, observed_at=NOW)
        self.assertEqual(status, 503)
        self.assertIn("pseudonymous", payload["error"])

    def test_portal_wrapper_uses_the_collector_snapshot_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp)
            original = portal.SOFTWARE_INVENTORY_STATE_FILE
            portal.SOFTWARE_INVENTORY_STATE_FILE = path
            try:
                status, payload = portal.software_inventory_response(
                    observed_at=NOW,
                    query={"platform": ["macOS"]},
                )
            finally:
                portal.SOFTWARE_INVENTORY_STATE_FILE = original
        self.assertEqual(status, 200)
        self.assertEqual(payload["summary"]["records"], 2)
        self.assertTrue(all(item["platform"] == "macOS" for item in payload["items"]))
        self.assertTrue(all("asset_label" in item for item in payload["items"]))

    def test_portal_labels_only_unambiguous_known_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = state()
            hostname = "studio.example.test"
            raw["records"][0]["asset_ref"] = __import__("hashlib").sha256(
                ("host\0" + hostname).encode("utf-8")
            ).hexdigest()[:24]
            path = self.write_state(tmp, raw)
            original_state = portal.SOFTWARE_INVENTORY_STATE_FILE
            original_inventory = portal.asset_inventory_response
            portal.SOFTWARE_INVENTORY_STATE_FILE = path
            portal.asset_inventory_response = lambda **_kwargs: (
                200,
                {
                    "assets": [
                        {
                            "asset_id": "studio",
                            "hostnames": [hostname.upper() + "."],
                            "ip_addresses": ["10.100.4.21"],
                            "platform": "macOS",
                            "confidence": "high",
                        }
                    ]
                },
            )
            try:
                status, payload = portal.software_inventory_response(
                    observed_at=NOW
                )
            finally:
                portal.SOFTWARE_INVENTORY_STATE_FILE = original_state
                portal.asset_inventory_response = original_inventory
        self.assertEqual(status, 200)
        labels = {
            item["product"]: item["asset_label"] for item in payload["items"]
        }
        self.assertEqual(labels["Firefox"], "studio")
        self.assertEqual(labels["OpenSSH"], "studio")
        self.assertEqual(labels["Safari"], "")
        items = {item["product"]: item for item in payload["items"]}
        self.assertEqual(
            items["Firefox"]["operating_system_source"],
            "osquery_manager.result:host.os",
        )
        self.assertEqual(
            items["Firefox"]["operating_system_version"],
            "macOS 26.0 (25A5306g)",
        )
        self.assertEqual(
            items["OpenSSH"]["operating_system_type"],
            "macOS",
        )
        self.assertEqual(
            items["OpenSSH"]["operating_system_version"],
            "",
        )
        self.assertEqual(
            items["OpenSSH"]["operating_system_source"],
            "asset_inventory",
        )
        self.assertEqual(
            items["OpenSSH"]["operating_system_confidence"],
            "high",
        )

    def test_portal_pages_beyond_the_default_asset_inventory_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = state()
            hostname = "studio.example.test"
            raw["records"][0]["asset_ref"] = __import__("hashlib").sha256(
                ("host\0" + hostname).encode("utf-8")
            ).hexdigest()[:24]
            path = self.write_state(tmp, raw)
            known_assets = [
                {
                    "asset_id": f"asset-{index:03d}",
                    "hostnames": [f"host-{index:03d}.example.test"],
                    "ip_addresses": [],
                }
                for index in range(inventory.ASSET_LABEL_PAGE_SIZE)
            ]
            known_assets.append(
                {
                    "asset_id": "studio",
                    "hostnames": [hostname],
                    "ip_addresses": [],
                }
            )
            offsets = []

            def paged_inventory(**kwargs):
                query = kwargs["query"]
                offset = int(query["offset"][0])
                limit = int(query["limit"][0])
                offsets.append(offset)
                assets = known_assets[offset : offset + limit]
                return 200, {
                    "assets": assets,
                    "page": {
                        "limit": limit,
                        "offset": offset,
                        "returned": len(assets),
                        "filtered_total": len(known_assets),
                        "has_more": offset + len(assets) < len(known_assets),
                    },
                }

            original_state = portal.SOFTWARE_INVENTORY_STATE_FILE
            original_inventory = portal.asset_inventory_response
            portal.SOFTWARE_INVENTORY_STATE_FILE = path
            portal.asset_inventory_response = paged_inventory
            try:
                status, payload = portal.software_inventory_response(
                    observed_at=NOW
                )
            finally:
                portal.SOFTWARE_INVENTORY_STATE_FILE = original_state
                portal.asset_inventory_response = original_inventory

        self.assertEqual(status, 200)
        self.assertEqual(offsets, [0, inventory.ASSET_LABEL_PAGE_SIZE])
        labels = {
            item["product"]: item["asset_label"] for item in payload["items"]
        }
        self.assertEqual(labels["Firefox"], "studio")

    def test_partial_bounded_asset_inventory_never_claims_uniqueness(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = state()
            hostname = "studio.example.test"
            raw["records"][0]["asset_ref"] = __import__("hashlib").sha256(
                ("host\0" + hostname).encode("utf-8")
            ).hexdigest()[:24]
            path = self.write_state(tmp, raw)
            calls = []

            def endless_inventory(**kwargs):
                calls.append(kwargs["query"]["offset"][0])
                return 200, {
                    "assets": [
                        {
                            "asset_id": "studio",
                            "hostnames": [hostname],
                            "ip_addresses": [],
                        }
                    ],
                    "page": {"has_more": True},
                }

            original_state = portal.SOFTWARE_INVENTORY_STATE_FILE
            original_inventory = portal.asset_inventory_response
            portal.SOFTWARE_INVENTORY_STATE_FILE = path
            portal.asset_inventory_response = endless_inventory
            try:
                status, payload = portal.software_inventory_response(
                    observed_at=NOW
                )
            finally:
                portal.SOFTWARE_INVENTORY_STATE_FILE = original_state
                portal.asset_inventory_response = original_inventory

        self.assertEqual(status, 200)
        self.assertEqual(len(calls), inventory.ASSET_LABEL_MAX_PAGES)
        self.assertTrue(all(not item["asset_label"] for item in payload["items"]))
        self.assertTrue(
            all(
                not item["operating_system_type"]
                or item["source"] == "osquery_apps"
                for item in payload["items"]
            )
        )
        self.assertFalse(
            payload["coverage"]["asset_label_inventory_complete"]
        )
        self.assertTrue(
            any("Asset labels are withheld" in item for item in payload["warnings"])
        )

    def test_collector_validated_state_is_accepted_end_to_end(self):
        from tests.test_software_inventory_collector import load_collector

        collector = load_collector()
        raw = state()
        raw.pop("secret")
        raw["collection"].pop("osquery_ready")
        raw["collection"].pop("relay_token")
        raw["collection"]["status"] = "ok"
        for item in raw["records"]:
            item.pop("private_agent_id")
        raw["records"][0]["platform"] = "darwin"
        raw["records"][1]["platform"] = "darwin"
        raw["records"][2]["platform"] = ""
        raw["records"][3]["platform"] = ""
        raw["records"][3]["version"] = ""
        for item in raw["records"]:
            item["source_dataset"] = collector.SOURCE_POLICY[
                item["source"]
            ]["dataset"]
        counts = {"osquery_apps": 2, "zeek_software": 1, "http_user_agent": 1}
        raw["collection"]["source_statuses"] = {
            source: {
                "status": "ok",
                "complete": True,
                "pages": 1,
                "returned": count,
                "freshness": "fresh",
                "latest_observation_at": iso(),
            }
            for source, count in counts.items()
        }
        normalized = collector.validate_state(raw)
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp, normalized)
            status, payload = inventory.build_response(
                path, observed_at=NOW
            )
        self.assertEqual(status, 200)
        self.assertTrue(payload["collection"]["complete"])
        self.assertEqual(
            payload["collection"]["source_statuses"]["osquery_apps"]["returned"],
            2,
        )
        self.assertEqual(payload["summary"]["records"], 4)

    def test_collection_complete_must_be_a_boolean(self):
        raw = state()
        raw["collection"]["complete"] = "true"
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_state(tmp, raw)
            status, payload = inventory.build_response(
                path, observed_at=NOW
            )
        self.assertEqual(status, 503)
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["collection"]["complete"])


if __name__ == "__main__":
    unittest.main()
