#!/usr/bin/env python3
"""Focused tests for the bounded Mac Studio software inventory collector."""
from __future__ import annotations

import ast
import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import plistlib
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "n8n" / "bin" / "collect-software-inventory.py"
CONFIG_EXAMPLE = ROOT / "n8n" / "config" / "software-inventory.example.json"
PLIST = ROOT / "n8n" / "launchd" / "com.arron.soc.software-inventory.plist"
INSTALLER = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_collector():
    dependency = str(ROOT / "n8n" / "bin")
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    loader = importlib.machinery.SourceFileLoader(
        "software_inventory_collector_test",
        str(COLLECTOR),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


class SoftwareInventoryCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.collector = load_collector()
        cls.now = dt.datetime(
            2026,
            7,
            30,
            18,
            0,
            tzinfo=dt.timezone.utc,
        )

    def config(self, *, page_size: int = 2, max_pages: int = 8) -> dict:
        return {
            "enabled": True,
            "host": "10.88.8.8",
            "ssh_user": "aj",
            "ssh_key": "/tmp/read-only-key",
            "known_hosts": "/tmp/read-only-known-hosts",
            "port": 22,
            "connect_timeout_seconds": 20,
            "timeout_seconds": 120,
            "max_collection_seconds": 900,
            "max_response_bytes": 4 * 1024 * 1024,
            "max_stderr_bytes": 128 * 1024,
            "page_size": page_size,
            "max_pages_per_source": max_pages,
        }

    @staticmethod
    def host_ref(hostname: str) -> str:
        normalized = hostname.strip().rstrip(".").lower()
        return hashlib.sha256(
            ("host\0" + normalized).encode("utf-8")
        ).hexdigest()[:24]

    def record(
        self,
        source: str,
        *,
        asset: str,
        product: str,
        version: str,
        evidence: str,
    ) -> dict:
        policy = self.collector.SOURCE_POLICY[source]
        return {
            "evidence_id": evidence * 24,
            "source": source,
            "source_dataset": policy["dataset"],
            "tier": policy["tier"],
            "confidence": policy["confidence"],
            "asset_ref_type": policy["asset_ref_type"],
            "asset_ref": asset,
            "platform": policy["platform"],
            "operating_system_type": "",
            "operating_system_version": "",
            "operating_system_source": "",
            "operating_system_confidence": "",
            "product": product,
            "version": version,
            "category": (
                "application"
                if source == "osquery_apps"
                else "http_client"
                if source == "http_user_agent"
                else "software"
            ),
            "first_seen": "2026-07-30T16:00:00.000Z",
            "last_seen": "2026-07-30T17:00:00.000Z",
            "observation_count": 2,
        }

    def test_endpoint_operating_system_provenance_is_preserved(self) -> None:
        value = self.record(
            "osquery_apps",
            asset=self.host_ref("studio.example"),
            product="Example",
            version="1",
            evidence="a",
        )
        value.update(
            {
                "operating_system_type": "macOS",
                "operating_system_version": "macOS 26.0 (25A5306g)",
                "operating_system_source": "osquery_manager.result:host.os",
                "operating_system_confidence": "high",
            }
        )

        normalized = self.collector._normalize_record(value)

        self.assertEqual(normalized["operating_system_type"], "macOS")
        self.assertEqual(
            normalized["operating_system_version"],
            "macOS 26.0 (25A5306g)",
        )
        passive = self.record(
            "zeek_software",
            asset="10.66.6.20",
            product="Example",
            version="1",
            evidence="b",
        )
        passive["operating_system_type"] = "Linux"
        with self.assertRaisesRegex(
            ValueError,
            "passive software evidence",
        ):
            self.collector._normalize_record(passive)

    def response(
        self,
        source: str,
        window: dict,
        records: list,
        *,
        complete: bool,
        after=None,
    ) -> dict:
        policy = self.collector.SOURCE_POLICY[source]
        return {
            "ok": True,
            "contract": self.collector.CONTRACT,
            "read_only": True,
            "source": source,
            "window": window,
            "returned": len(records),
            "complete": complete,
            "truncated": not complete,
            "after": after,
            "records": records,
            "query_audit": {
                "index": policy["index"],
                "dataset": policy["dataset"],
                "query_digest": "d" * 64,
            },
        }

    def test_database_publish_is_chunked_and_committed_last(self) -> None:
        records = [
            self.record(
                "osquery_apps",
                asset=self.host_ref("studio.example"),
                product=f"Product {index}",
                version="1",
                evidence=f"{index % 16:x}",
            )
            for index in range(501)
        ]
        # Evidence fixtures above repeat after sixteen values; give each record
        # the full unique 24-hex identity required by the collector contract.
        for index, item in enumerate(records):
            item["evidence_id"] = f"{index:024x}"
        value = self.collector.empty_state()
        value.update(
            {
                "updated_at": "2026-07-30T18:00:00.000Z",
                "collection": {
                    "status": "ok",
                    "last_attempt_at": "2026-07-30T18:00:00.000Z",
                    "last_success_at": "2026-07-30T18:00:00.000Z",
                    "last_error": "",
                    "window": {
                        "start": "2026-06-30T18:00:00.000Z",
                        "end": "2026-07-30T18:00:00.000Z",
                    },
                    "source_statuses": {
                        source: {
                            "status": "ok",
                            "complete": True,
                            "pages": 1,
                            "returned": (
                                len(records) if source == "osquery_apps" else 0
                            ),
                            "freshness": (
                                "fresh" if source == "osquery_apps" else "empty"
                            ),
                            "latest_observation_at": (
                                "2026-07-30T17:00:00.000Z"
                                if source == "osquery_apps"
                                else ""
                            ),
                        }
                        for source in self.collector.SOURCES
                    },
                    "complete": True,
                },
                "records": records,
            }
        )
        calls = []

        def post(_url, _token, route, payload):
            calls.append((route, payload))
            return {"ok": True, "already_active": False}

        with mock.patch.object(self.collector, "_database_post", post):
            result = self.collector.publish_database_snapshot(
                value,
                api_url="http://127.0.0.1:8787",
                token="x" * 32,
            )

        self.assertEqual(result["records"], 501)
        self.assertEqual(
            [route for route, _payload in calls],
            [
                "/software-inventory/import/start",
                "/software-inventory/import/chunk",
                "/software-inventory/import/chunk",
                "/software-inventory/import/commit",
            ],
        )
        self.assertEqual(len(calls[1][1]["records"]), 500)
        self.assertEqual(len(calls[2][1]["records"]), 1)
        self.assertRegex(result["snapshot_id"], r"^[0-9a-f]{64}$")

    def test_complete_three_source_snapshot_replaces_last_good_records(self) -> None:
        window = self.collector.collection_window(self.now)
        old = self.collector.empty_state()
        old["records"] = [
            self.record(
                "zeek_software",
                asset="10.66.6.99",
                product="Retired Client",
                version="1",
                evidence="f",
            )
        ]
        pages = {
            ("osquery_apps", "first"): self.response(
                "osquery_apps",
                window,
                [
                    self.record(
                        "osquery_apps",
                        asset=self.host_ref("alpha.example"),
                        product="Alpha",
                        version="1",
                        evidence="a",
                    ),
                    self.record(
                        "osquery_apps",
                        asset=self.host_ref("beta.example."),
                        product="Beta",
                        version="2",
                        evidence="b",
                    ),
                ],
                complete=False,
                after={
                    "asset": "beta.example.",
                    "product": "Beta",
                    "version": "2",
                },
            ),
            ("osquery_apps", "next"): self.response(
                "osquery_apps",
                window,
                [
                    self.record(
                        "osquery_apps",
                        asset=self.host_ref("gamma.example"),
                        product="Gamma",
                        version="3",
                        evidence="c",
                    )
                ],
                complete=True,
            ),
            ("zeek_software", "first"): self.response(
                "zeek_software",
                window,
                [
                    self.record(
                        "zeek_software",
                        asset="10.66.6.210",
                        product="OpenSSH",
                        version="9.9",
                        evidence="e",
                    )
                ],
                complete=True,
            ),
            ("http_user_agent", "first"): self.response(
                "http_user_agent",
                window,
                [
                    self.record(
                        "http_user_agent",
                        asset="10.66.6.211",
                        product="Mozilla/5.0",
                        version="",
                        evidence="9",
                    )
                ],
                complete=True,
            ),
        }
        calls = []

        def fetcher(config, source, requested_window, page_size, after, timeout):
            del config, page_size, timeout
            self.assertEqual(requested_window, window)
            calls.append((source, json.loads(json.dumps(after))))
            return pages[(source, "next" if after else "first")]

        state = self.collector.collect_snapshot(
            self.config(),
            old,
            self.now,
            page_fetcher=fetcher,
        )
        self.assertEqual(state["collection"]["status"], "ok")
        self.assertTrue(state["collection"]["complete"])
        self.assertEqual(len(state["records"]), 5)
        self.assertNotIn("f" * 24, {item["evidence_id"] for item in state["records"]})
        self.assertEqual(
            calls,
            [
                ("osquery_apps", None),
                (
                    "osquery_apps",
                    {
                        "asset": "beta.example.",
                        "product": "Beta",
                        "version": "2",
                    },
                ),
                ("zeek_software", None),
                ("http_user_agent", None),
            ],
        )
        self.assertEqual(
            state["collection"]["source_statuses"]["osquery_apps"]["pages"],
            2,
        )
        self.assertEqual(
            set(state["collection"]["source_statuses"]["osquery_apps"]),
            self.collector.SOURCE_STATUS_KEYS,
        )
        serialized = json.dumps(state)
        self.assertNotIn("beta.example", serialized)
        self.assertNotIn('"after"', serialized)

    def test_partial_page_limit_failure_retains_last_good_records(self) -> None:
        window = self.collector.collection_window(self.now)
        previous = self.collector.empty_state()
        previous["updated_at"] = "2026-07-29T18:00:00.000Z"
        previous["collection"]["last_success_at"] = "2026-07-29T18:00:00.000Z"
        previous["collection"]["window"] = {
            "start": "2026-06-29T18:00:00.000Z",
            "end": "2026-07-29T18:00:00.000Z",
        }
        previous["records"] = [
            self.record(
                "zeek_software",
                asset="10.66.6.200",
                product="Known Good",
                version="1",
                evidence="7",
            )
        ]

        def fetcher(config, source, requested_window, page_size, after, timeout):
            del config, requested_window, page_size, after, timeout
            return self.response(
                source,
                window,
                [
                    self.record(
                        source,
                        asset=self.host_ref("only.example"),
                        product="Only",
                        version="1",
                        evidence="8",
                    )
                ],
                complete=False,
                after={
                    "asset": "only.example",
                    "product": "Only",
                    "version": "1",
                },
            )

        with self.assertRaises(self.collector.SoftwareInventoryError) as caught:
            self.collector.collect_snapshot(
                self.config(page_size=1, max_pages=1),
                previous,
                self.now,
                page_fetcher=fetcher,
            )
        failed = self.collector.failed_state(
            previous,
            self.now,
            str(caught.exception),
            caught.exception.source_statuses,
        )
        self.assertEqual(failed["collection"]["status"], "failed")
        self.assertFalse(failed["collection"]["complete"])
        self.assertEqual(failed["records"], previous["records"])
        self.assertEqual(failed["updated_at"], previous["updated_at"])
        self.assertEqual(
            failed["collection"]["window"],
            previous["collection"]["window"],
        )
        self.assertEqual(
            failed["collection"]["last_attempt_at"],
            "2026-07-30T18:00:00.000Z",
        )
        self.assertEqual(
            failed["collection"]["last_success_at"],
            "2026-07-29T18:00:00.000Z",
        )
        source_status = failed["collection"]["source_statuses"]["osquery_apps"]
        self.assertEqual(source_status["status"], "failed")
        self.assertEqual(source_status["pages"], 1)
        self.assertEqual(source_status["returned"], 1)
        self.assertNotIn("only.example", json.dumps(failed))

    def test_disabled_attempt_preserves_last_good_snapshot_evidence_time(self) -> None:
        previous = self.collector.empty_state()
        previous["updated_at"] = "2026-07-29T18:00:00.000Z"
        previous["collection"]["last_attempt_at"] = previous["updated_at"]
        previous["collection"]["last_success_at"] = previous["updated_at"]
        previous["collection"]["window"] = {
            "start": "2026-06-29T18:00:00.000Z",
            "end": "2026-07-29T18:00:00.000Z",
        }
        previous["records"] = [
            self.record(
                "zeek_software",
                asset="10.66.6.200",
                product="Known Good",
                version="1",
                evidence="7",
            )
        ]

        disabled = self.collector.disabled_state(previous, self.now)

        self.assertEqual(disabled["collection"]["status"], "disabled")
        self.assertFalse(disabled["collection"]["complete"])
        self.assertEqual(disabled["records"], previous["records"])
        self.assertEqual(disabled["updated_at"], previous["updated_at"])
        self.assertEqual(
            disabled["collection"]["window"],
            previous["collection"]["window"],
        )
        self.assertEqual(
            disabled["collection"]["last_attempt_at"],
            "2026-07-30T18:00:00.000Z",
        )
        self.assertEqual(
            disabled["collection"]["last_success_at"],
            previous["collection"]["last_success_at"],
        )

    def test_osquery_cursor_hash_and_monotonicity_are_enforced(self) -> None:
        window = self.collector.collection_window(self.now)
        record = self.record(
            "osquery_apps",
            asset=self.host_ref("studio.example."),
            product="Example",
            version="5",
            evidence="3",
        )
        valid = self.response(
            "osquery_apps",
            window,
            [record],
            complete=False,
            after={
                "asset": "Studio.Example.",
                "product": "Example",
                "version": "5",
            },
        )
        normalized = self.collector.validate_response(
            valid,
            expected_source="osquery_apps",
            expected_window=window,
            requested_page_size=1,
            previous_after=None,
        )
        self.assertEqual(normalized["records"][0]["asset_ref"], self.host_ref("studio.example"))
        mismatched = json.loads(json.dumps(valid))
        mismatched["after"]["asset"] = "different.example"
        with self.assertRaisesRegex(ValueError, "last public record"):
            self.collector.validate_response(
                mismatched,
                expected_source="osquery_apps",
                expected_window=window,
                requested_page_size=1,
                previous_after=None,
            )
        with self.assertRaisesRegex(ValueError, "did not advance"):
            self.collector.validate_response(
                valid,
                expected_source="osquery_apps",
                expected_window=window,
                requested_page_size=1,
                previous_after=valid["after"],
            )

    def test_contract_rejects_uuid_cursor_non_lan_and_invented_http_version(self) -> None:
        window = self.collector.collection_window(self.now)
        request = self.collector.build_request(
            "osquery_apps",
            window,
            500,
            None,
        )
        self.assertEqual(
            set(request),
            {"contract", "operation", "source", "window", "page_size", "after"},
        )
        self.assertNotIn("query", request)
        self.assertNotIn("action", request)
        with self.assertRaisesRegex(ValueError, "UUID-shaped"):
            self.collector.build_request(
                "osquery_apps",
                window,
                500,
                {
                    "asset": "550e8400-e29b-41d4-a716-446655440000",
                    "product": "Example",
                    "version": "1",
                },
            )
        off_lan = self.record(
            "zeek_software",
            asset="203.0.113.10",
            product="Example",
            version="1",
            evidence="4",
        )
        with self.assertRaisesRegex(ValueError, "LAN"):
            self.collector._normalize_record(
                off_lan,
                expected_source="zeek_software",
                expected_window=window,
            )
        invented = self.record(
            "http_user_agent",
            asset="10.66.6.210",
            product="Mozilla/5.0",
            version="HTTP/2",
            evidence="5",
        )
        with self.assertRaisesRegex(ValueError, "must not invent"):
            self.collector._normalize_record(
                invented,
                expected_source="http_user_agent",
                expected_window=window,
            )

    def test_duplicate_evidence_across_pages_fails_closed(self) -> None:
        window = self.collector.collection_window(self.now)
        first = self.record(
            "zeek_software",
            asset="10.66.6.210",
            product="Alpha",
            version="1",
            evidence="6",
        )
        second = self.record(
            "zeek_software",
            asset="10.66.6.211",
            product="Beta",
            version="2",
            evidence="6",
        )

        def fetcher(config, source, requested_window, page_size, after, timeout):
            del config, source, requested_window, page_size, timeout
            if after is None:
                return self.response(
                    "zeek_software",
                    window,
                    [first],
                    complete=False,
                    after={
                        "asset": "10.66.6.210",
                        "product": "Alpha",
                        "version": "1",
                    },
                )
            return self.response(
                "zeek_software",
                window,
                [second],
                complete=True,
            )

        with self.assertRaisesRegex(
            self.collector.SoftwareInventoryError,
            "repeated an evidence identity",
        ):
            self.collector.collect_source(
                self.config(page_size=1),
                "zeek_software",
                window,
                self.now,
                time.monotonic() + 30,
                page_fetcher=fetcher,
            )

    def test_atomic_state_is_owner_only_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private" / "software-inventory.json"
            state = self.collector.disabled_state(
                self.collector.empty_state(),
                self.now,
            )
            self.collector.atomic_write_json(path, state)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(self.collector.load_state(path), state)

    def test_collector_refuses_a_symlinked_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "not owner-controlled"):
                with self.collector.collector_lock(linked / "state.json"):
                    self.fail("collector accepted a symlinked state directory")

    def test_python39_launchd_and_installer_contracts(self) -> None:
        ast.parse(COLLECTOR.read_text(encoding="utf-8"), feature_version=(3, 9))
        example = json.loads(CONFIG_EXAMPLE.read_text(encoding="utf-8"))
        self.assertFalse(example["enabled"])
        self.assertEqual(example["page_size"], 500)
        self.assertEqual(example["max_pages_per_source"], 64)
        self.assertIn("incident-evidence", example["ssh_key"])
        plist = plistlib.loads(PLIST.read_bytes())
        self.assertEqual(plist["Label"], "com.arron.soc.software-inventory")
        self.assertEqual(plist["StartInterval"], 3600)
        self.assertTrue(plist["RunAtLoad"])
        installer = INSTALLER.read_text(encoding="utf-8")
        for required in (
            "collect-software-inventory.py",
            "software-inventory.example.json",
            "com.arron.soc.software-inventory.plist",
            "onion-sentinel-dashboard/software_inventory.py",
            'software_snapshot_complete=',
            'software-inventory?limit=1',
            'value.get("storage_backend") == "postgresql"',
            'value.get("collection", {}).get("complete") is True',
            'int(value.get("summary", {}).get("records") or 0) > 0',
            "neither the local nor PostgreSQL Software Inventory is complete",
        ):
            self.assertIn(required, installer)


if __name__ == "__main__":
    unittest.main()
