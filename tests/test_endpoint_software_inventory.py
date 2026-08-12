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

    def test_query_preserves_safe_remote_failure_classification(self):
        expected_codes = {
            "timeout": "remote_timeout",
            "error": "remote_error",
            "invalid_response": "remote_invalid_response",
            "cancelled": "remote_cancelled",
        }
        for status, expected_code in expected_codes.items():
            artifact = {
                "complete": False,
                "results": [{
                    "status": status,
                    "truncated": False,
                    "rows": [],
                    "error": "raw remote detail must not cross this boundary",
                }],
            }
            with (
                self.subTest(status=status),
                mock.patch.object(
                    self.module,
                    "collect_live_osquery",
                    return_value=artifact,
                ),
                self.assertRaises(self.module.EndpointInventoryError) as raised,
            ):
                self.module._query(
                    self.config(),
                    "studio",
                    "SELECT hostname FROM system_info LIMIT 1;",
                    "Bind endpoint identity",
                    "scheduled-endpoint-software-20260811",
                )

            self.assertEqual(raised.exception.reason_code, expected_code)
            self.assertNotIn("raw remote detail", str(raised.exception))

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

    def test_transient_timeout_retries_once_with_redacted_classification(self):
        expected = {"schema": self.module.SCHEMA, "records": [], "targets": []}
        logger = mock.Mock()
        timeout = self.module.LiveOsqueryClientError(
            "restricted live OSQuery transport timed out at endpoint-a",
            reason_code="broker_timeout",
        )
        with (
            mock.patch.object(
                self.module,
                "collect",
                side_effect=[timeout, expected],
            ) as collect,
            mock.patch.object(self.module.time, "sleep") as sleep,
        ):
            result = self.module.collect_with_retries(
                self.config(),
                {"updated_at": "2026-08-09T20:32:59.752Z"},
                attempts=2,
                retry_delay_seconds=7,
                logger=logger,
            )

        self.assertIs(result, expected)
        self.assertEqual(collect.call_count, 2)
        sleep.assert_called_once_with(7)
        logger.log.assert_called_once_with(
            "warning",
            "endpoint_software_inventory.retry",
            attempt=1,
            attempts=2,
            failure_code="broker_timeout",
            retry_delay_seconds=7,
            last_good_cache_state="stale",
        )

    def test_non_retryable_configuration_failure_does_not_retry(self):
        logger = mock.Mock()
        failure = self.module.LiveOsqueryClientError(
            "operator approval is missing",
            reason_code="configuration_error",
        )
        with (
            mock.patch.object(self.module, "collect", side_effect=failure) as collect,
            mock.patch.object(self.module.time, "sleep") as sleep,
            self.assertRaises(self.module.LiveOsqueryClientError),
        ):
            self.module.collect_with_retries(
                self.config(),
                None,
                attempts=3,
                retry_delay_seconds=7,
                logger=logger,
            )

        collect.assert_called_once()
        sleep.assert_not_called()
        logger.log.assert_not_called()

    def test_persistent_failure_preserves_cache_and_omits_raw_evidence_from_log(self):
        prior = {
            "schema": self.module.SCHEMA,
            "version": 1,
            "updated_at": "2026-08-09T20:32:59.752Z",
            "complete": True,
            "targets": [],
            "records": [],
        }
        secret_text = "endpoint-a token=do-not-log response={raw-row}"
        failure = self.module.LiveOsqueryClientError(
            secret_text,
            reason_code="broker_timeout",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache.json"
            log = root / "collector.jsonl"
            self.module.atomic_write(cache, prior)
            before = cache.read_bytes()
            argv = [
                str(SCRIPT),
                "--config", str(root / "config.json"),
                "--cache", str(cache),
                "--log", str(log),
                "--attempts", "2",
                "--retry-delay-seconds", "7",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    self.module,
                    "load_live_osquery_config",
                    return_value=self.config(),
                ),
                mock.patch.object(
                    self.module,
                    "collect",
                    side_effect=failure,
                ) as collect,
                mock.patch.object(self.module.time, "sleep") as sleep,
            ):
                status = self.module.main()

            self.assertEqual(status, 1)
            self.assertEqual(collect.call_count, 2)
            sleep.assert_called_once_with(7)
            self.assertEqual(cache.read_bytes(), before)
            receipts = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(
                [receipt["event"] for receipt in receipts],
                [
                    "endpoint_software_inventory.retry",
                    "endpoint_software_inventory.failed",
                ],
            )
            self.assertEqual(receipts[-1]["failure_code"], "broker_timeout")
            self.assertEqual(receipts[-1]["attempts"], 2)
            self.assertEqual(receipts[-1]["last_good_cache_state"], "stale")
            encoded = json.dumps(receipts)
            for forbidden in ("endpoint-a", "do-not-log", "raw-row"):
                self.assertNotIn(forbidden, encoded)

    def test_main_rejects_symlink_lock_without_touching_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache.json"
            target = root / "unrelated.txt"
            target.write_text("preserve me", encoding="utf-8")
            target.chmod(0o640)
            cache.with_suffix(".json.lock").symlink_to(target)
            argv = [
                str(SCRIPT),
                "--config", str(root / "config.json"),
                "--cache", str(cache),
                "--log", str(root / "collector.jsonl"),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.module, "collect") as collect,
            ):
                status = self.module.main()

            self.assertEqual(status, 1)
            collect.assert_not_called()
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve me")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
