from __future__ import annotations

import copy
import datetime as dt
import hashlib
import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import software_inventory_assets as inventory_assets


NOW = dt.datetime(2026, 8, 12, 12, 0, tzinfo=dt.timezone.utc)


class SoftwareInventoryAssetsArchitectureTests(unittest.TestCase):
    @staticmethod
    def host_ref(hostname: str) -> str:
        normalized = hostname.strip().rstrip(".").lower()
        return hashlib.sha256(
            ("host\0" + normalized).encode("utf-8")
        ).hexdigest()[:24]

    @staticmethod
    def asset(**updates: object) -> dict[str, object]:
        value: dict[str, object] = {
            "asset_id": "studio",
            "state": "current",
            "hostnames": ["Studio.Example.Test."],
            "ip_addresses": ["10.100.4.21", "invalid"],
            "configured_ip_addresses": ["10.100.4.21"],
            "platform": "macOS",
            "operating_system_version": "macOS 26.0",
            "confidence": "high",
            "valid_from": "2026-07-01T00:00:00Z",
            "valid_until": "",
            "source_type": "manual-inventory",
            "current_ip_source": "manual",
        }
        value.update(updates)
        return value

    @staticmethod
    def endpoint(**updates: object) -> dict[str, object]:
        value: dict[str, object] = {
            "asset_label": "studio",
            "source": "osquery_apps",
            "operating_system_type": "macOS",
            "operating_system_version": "macOS 26.0",
            "operating_system_source": "osquery_manager.result:host.os",
            "operating_system_confidence": "high",
            "tier": "installed",
            "last_seen": "2026-08-12T11:00:00Z",
            "_last_seen": NOW - dt.timedelta(hours=1),
        }
        value.update(updates)
        return value

    @staticmethod
    def passive(**updates: object) -> dict[str, object]:
        value: dict[str, object] = {
            "asset_label": "studio",
            "asset_ref_type": "ip",
            "asset_ref": "10.100.4.21",
            "source": "zeek_software",
            "operating_system_type": "",
            "operating_system_version": "",
            "operating_system_source": "",
            "operating_system_confidence": "",
            "tier": "observed",
            "last_seen": "2026-08-12T11:30:00Z",
            "_last_seen": NOW - dt.timedelta(minutes=30),
        }
        value.update(updates)
        return value

    def test_owner_dependency_chain_is_inward_and_bounded(self) -> None:
        facade = (DASHBOARD / "software_inventory_assets.py").read_text()
        labels = (
            DASHBOARD / "software_inventory_asset_labels.py"
        ).read_text()
        correlation = (
            DASHBOARD / "software_inventory_os_correlation.py"
        ).read_text()
        self.assertLessEqual(len(facade.splitlines()), 250)
        self.assertLessEqual(len(labels.splitlines()), 600)
        self.assertLessEqual(len(correlation.splitlines()), 600)
        self.assertNotIn("software_inventory_assets", labels)
        self.assertNotIn("software_inventory_assets", correlation)
        self.assertIn(
            "from software_inventory_asset_labels import apply_asset_labels",
            facade,
        )
        self.assertIn(
            "from software_inventory_os_correlation import",
            facade,
        )

    def test_public_signatures_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(inventory_assets.apply_asset_labels)),
            "(items: 'object', assets: 'object', *, inventory_complete: 'bool', maximum_assets: 'int' = 5000) -> 'int'",
        )
        self.assertEqual(
            str(
                inspect.signature(
                    inventory_assets.correlate_asset_operating_systems
                )
            ),
            "(items: 'object', endpoint_evidence: 'object', *, assets: 'object', observed_at: 'dt.datetime') -> 'int'",
        )

    def test_asset_labels_preserve_exact_mutation_and_os_fallback(self) -> None:
        host = {
            "asset_label": "stale",
            "asset_ref_type": "host",
            "asset_ref": self.host_ref("studio.example.test"),
            "operating_system_type": "",
            "operating_system_version": "",
            "operating_system_source": "",
            "operating_system_confidence": "",
        }
        address = {
            "asset_label": "",
            "asset_ref_type": "ip",
            "asset_ref": "10.100.4.21",
            "operating_system_type": "Existing",
            "operating_system_version": "",
            "operating_system_source": "",
            "operating_system_confidence": "",
        }
        items = [host, address, "ignored"]
        self.assertEqual(
            inventory_assets.apply_asset_labels(
                items,
                [self.asset()],
                inventory_complete=True,
            ),
            2,
        )
        self.assertEqual(host["asset_label"], "studio")
        self.assertEqual(host["operating_system_type"], "macOS")
        self.assertEqual(host["operating_system_version"], "macOS 26.0")
        self.assertEqual(host["operating_system_source"], "asset_inventory")
        self.assertEqual(host["operating_system_confidence"], "high")
        self.assertEqual(address["asset_label"], "studio")
        self.assertEqual(address["operating_system_type"], "Existing")
        self.assertEqual(address["operating_system_version"], "macOS 26.0")
        self.assertEqual(address["operating_system_source"], "asset_inventory")

    def test_asset_labels_fail_closed_for_partial_oversized_and_ambiguous_views(self) -> None:
        item = {
            "asset_label": "stale",
            "asset_ref_type": "host",
            "asset_ref": self.host_ref("studio.example.test"),
        }
        self.assertEqual(
            inventory_assets.apply_asset_labels(
                [item], [self.asset()], inventory_complete=False
            ),
            0,
        )
        self.assertEqual(item["asset_label"], "")
        item["asset_label"] = "stale"
        self.assertEqual(
            inventory_assets.apply_asset_labels(
                [item],
                [self.asset()],
                inventory_complete=True,
                maximum_assets=0,
            ),
            0,
        )
        self.assertEqual(item["asset_label"], "")
        ambiguous = [
            self.asset(asset_id="one"),
            self.asset(asset_id="two"),
        ]
        self.assertEqual(
            inventory_assets.apply_asset_labels(
                [item], ambiguous, inventory_complete=True
            ),
            0,
        )
        self.assertEqual(item["asset_label"], "")
        self.assertEqual(
            inventory_assets.apply_asset_labels(
                None, ambiguous, inventory_complete=True
            ),
            0,
        )

    def test_os_correlation_projection_and_count_are_exact(self) -> None:
        passive = self.passive()
        self.assertEqual(
            inventory_assets.correlate_asset_operating_systems(
                [passive],
                [self.endpoint()],
                assets=[self.asset()],
                observed_at=NOW,
            ),
            1,
        )
        self.assertEqual(
            passive,
            self.passive(
                operating_system_type="macOS",
                operating_system_version="macOS 26.0",
                operating_system_source="osquery_manager.result:host.os",
                operating_system_confidence="high",
                operating_system_observed_at="2026-08-12T11:00:00Z",
                operating_system_freshness="current",
                operating_system_association=(
                    "asset_inventory:unique-host-static-ip"
                ),
            ),
        )

    def test_os_correlation_rejection_matrix_is_fail_closed_and_nonmutating(self) -> None:
        variants = (
            (self.asset(confidence="low"), self.endpoint(), self.passive()),
            (self.asset(state="observed"), self.endpoint(), self.passive()),
            (
                self.asset(source_type="zeek-dhcp-observation"),
                self.endpoint(),
                self.passive(),
            ),
            (
                self.asset(current_ip_source="zeek-dhcp"),
                self.endpoint(),
                self.passive(),
            ),
            (
                self.asset(valid_from="2026-08-12T12:01:00Z"),
                self.endpoint(),
                self.passive(),
            ),
            (
                self.asset(configured_ip_addresses=["10.100.4.99"]),
                self.endpoint(),
                self.passive(),
            ),
            (
                self.asset(),
                self.endpoint(operating_system_confidence="medium"),
                self.passive(),
            ),
            (
                self.asset(),
                self.endpoint(_last_seen=NOW + dt.timedelta(minutes=6)),
                self.passive(),
            ),
            (
                self.asset(),
                self.endpoint(),
                self.passive(source="other"),
            ),
            (
                self.asset(),
                self.endpoint(),
                self.passive(operating_system_type="Linux"),
            ),
        )
        for asset, endpoint, passive in variants:
            with self.subTest(asset=asset, endpoint=endpoint, passive=passive):
                before = copy.deepcopy(passive)
                self.assertEqual(
                    inventory_assets.correlate_asset_operating_systems(
                        [passive],
                        [endpoint],
                        assets=[asset],
                        observed_at=NOW,
                    ),
                    0,
                )
                self.assertEqual(passive, before)

    def test_os_correlation_conflicting_newest_values_and_input_errors_are_exact(self) -> None:
        passive = self.passive()
        conflicting = self.endpoint(
            operating_system_type="Linux",
            operating_system_version="Linux 9.9",
        )
        self.assertEqual(
            inventory_assets.correlate_asset_operating_systems(
                [passive],
                [self.endpoint(), conflicting],
                assets=[self.asset()],
                observed_at=NOW,
            ),
            0,
        )
        self.assertEqual(passive, self.passive())
        for args in (
            (None, [self.endpoint()], [self.asset()]),
            ([passive], None, [self.asset()]),
            ([passive], [self.endpoint()], None),
        ):
            with self.subTest(args=args):
                self.assertEqual(
                    inventory_assets.correlate_asset_operating_systems(
                        args[0],
                        args[1],
                        assets=args[2],
                        observed_at=NOW,
                    ),
                    0,
                )
        with self.assertRaisesRegex(
            ValueError, "observed_at must include a UTC offset"
        ):
            inventory_assets.correlate_asset_operating_systems(
                [self.passive()],
                [self.endpoint()],
                assets=[self.asset()],
                observed_at=NOW.replace(tzinfo=None),
            )


if __name__ == "__main__":
    unittest.main()
