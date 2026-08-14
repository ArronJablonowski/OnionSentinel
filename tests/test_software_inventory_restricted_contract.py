#!/usr/bin/env python3
"""Restricted-node contracts for bounded software inventory observations."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "security-onion" / "bin" / "export-software-observations"
DISPATCHER = ROOT / "security-onion" / "bin" / "export-incident-evidence"
BROKER = ROOT / "relay" / "app" / "incident_evidence_broker.py"


def load_module(name: str, path: Path):
    relay_app = ROOT / "relay" / "app"
    if str(relay_app) not in sys.path:
        sys.path.insert(0, str(relay_app))
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


class SoftwareInventorySecurityOnionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper = load_module("software_inventory_so_test", HELPER)

    def request(
        self,
        *,
        source: str = "zeek_software",
        page_size: int = 100,
        after: dict | None = None,
    ) -> dict:
        return {
            "contract": self.helper.CONTRACT,
            "operation": self.helper.OPERATION,
            "source": source,
            "window": {
                "start": "2026-07-01T00:00:00Z",
                "end": "2026-07-30T00:00:00Z",
            },
            "page_size": page_size,
            "after": after,
        }

    @staticmethod
    def bucket(
        *,
        asset: str,
        product: str,
        version: str | None,
        first_seen: str = "2026-07-10T01:02:03.000Z",
        last_seen: str = "2026-07-20T04:05:06.000Z",
        count: int = 3,
        latest: dict | None = None,
    ) -> dict:
        value = {
            "key": {
                "asset": asset,
                "product": product,
                "version": version,
            },
            "doc_count": count,
            "first_seen": {"value_as_string": first_seen},
            "last_seen": {"value_as_string": last_seen},
        }
        if latest is not None:
            value["latest"] = {
                "hits": {
                    "hits": [
                        {"_source": latest},
                    ]
                }
            }
        return value

    def test_request_rejects_dsl_indices_extra_fields_and_oversized_windows(self) -> None:
        valid = self.request()
        source, start, end, page_size, after = self.helper.validate_request(
            valid,
            now=dt.datetime(2026, 7, 30, 1, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(source, "zeek_software")
        self.assertLess(start, end)
        self.assertEqual(page_size, 100)
        self.assertIsNone(after)
        for extra in (
            {"query": {"match_all": {}}},
            {"index": "*"},
            {"dsl": "{}"},
            {"credential": "not-allowed"},
        ):
            with self.subTest(extra=next(iter(extra))):
                with self.assertRaises(ValueError):
                    self.helper.validate_request(
                        {**valid, **extra},
                        now=dt.datetime(2026, 7, 30, 1, tzinfo=dt.timezone.utc),
                    )
        too_long = json.loads(json.dumps(valid))
        too_long["window"]["start"] = "2026-06-28T23:59:59Z"
        with self.assertRaises(ValueError):
            self.helper.validate_request(
                too_long,
                now=dt.datetime(2026, 7, 30, 1, tzinfo=dt.timezone.utc),
            )
        with self.assertRaises(ValueError):
            self.helper.validate_request(
                {**valid, "page_size": 501},
                now=dt.datetime(2026, 7, 30, 1, tzinfo=dt.timezone.utc),
            )

    def test_cursor_is_exact_bounded_and_allows_only_null_version(self) -> None:
        cursor = {
            "asset": "workstation.example.test",
            "product": "Example Browser",
            "version": None,
        }
        self.assertEqual(self.helper.validate_cursor(cursor), cursor)
        for invalid in (
            {**cursor, "index": "*"},
            {**cursor, "asset": ""},
            {**cursor, "product": "bad\nvalue"},
            {**cursor, "version": ["1.2.3"]},
            {**cursor, "product": "x" * 4097},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.helper.validate_cursor(invalid)

    def test_query_dsl_is_fixed_read_only_and_source_specific(self) -> None:
        start = dt.datetime(2026, 7, 1, tzinfo=dt.timezone.utc)
        end = dt.datetime(2026, 7, 2, tzinfo=dt.timezone.utc)
        expected = {
            "osquery_apps": (
                "logs-osquery_manager.result-default",
                "osquery_manager.result",
                "host.name",
                "osquery.name",
                "osquery.bundle_short_version",
            ),
            "zeek_software": (
                "logs-zeek-so",
                "zeek.software",
                "source.ip",
                "software.name",
                "software.version.unparsed",
            ),
            "http_user_agent": (
                "logs-zeek-so",
                "zeek.http",
                "source.ip",
                "http.useragent",
                None,
            ),
        }
        for source, (
            index,
            dataset,
            asset_field,
            product_field,
            version_field,
        ) in expected.items():
            with self.subTest(source=source):
                query = self.helper.build_query(source, start, end, 500, None)
                self.assertEqual(query["size"], 0)
                composite = query["aggs"]["software"]["composite"]
                self.assertEqual(composite["size"], 501)
                self.assertEqual(
                    composite["sources"][0]["asset"]["terms"]["field"],
                    asset_field,
                )
                self.assertEqual(
                    composite["sources"][1]["product"]["terms"]["field"],
                    product_field,
                )
                if version_field is None:
                    self.assertEqual(len(composite["sources"]), 2)
                else:
                    self.assertEqual(
                        composite["sources"][2]["version"]["terms"]["field"],
                        version_field,
                    )
                filters = query["query"]["bool"]["filter"]
                self.assertIn({"term": {"event.dataset": dataset}}, filters)
                lan_filters = [
                    item
                    for item in filters
                    if isinstance(item, dict)
                    and isinstance(item.get("bool"), dict)
                    and "should" in item["bool"]
                ]
                if source == "osquery_apps":
                    self.assertEqual(lan_filters, [])
                    latest = query["aggs"]["software"]["aggs"]["latest"]
                    self.assertIn(
                        "host.os.full",
                        latest["top_hits"]["_source"],
                    )
                    self.assertIn(
                        "host.os.version",
                        latest["top_hits"]["_source"],
                    )
                else:
                    self.assertEqual(len(lan_filters), 1)
                    self.assertEqual(
                        lan_filters[0]["bool"]["minimum_should_match"],
                        1,
                    )
                    self.assertEqual(
                        lan_filters[0]["bool"]["should"],
                        [
                            {"term": {"source.ip": cidr}}
                            for cidr in self.helper.LAN_SOURCE_CIDRS
                        ],
                    )
                self.assertEqual(
                    self.helper.SOURCE_SPECS[source]["index"],
                    index,
                )
                self.assertNotIn("runtime_mappings", query)
                self.assertNotIn('"script"', json.dumps(query))
                if source == "http_user_agent":
                    paged = self.helper.build_query(
                        source,
                        start,
                        end,
                        500,
                        {
                            "asset": "10.66.6.10",
                            "product": "ExampleBrowser/1.0",
                            "version": None,
                        },
                    )
                    self.assertEqual(
                        paged["aggs"]["software"]["composite"]["after"],
                        {
                            "asset": "10.66.6.10",
                            "product": "ExampleBrowser/1.0",
                        },
                    )
        source_text = HELPER.read_text(encoding="utf-8")
        self.assertIn("endpoint = f\"{spec['index']}/_search\"", source_text)
        for forbidden in ("/_update", "/_delete", "/_bulk", "/_scripts", "api_key"):
            self.assertNotIn(forbidden, source_text)

    def test_records_have_expected_evidence_tiers_and_redacted_host_identity(self) -> None:
        record, cursor = self.helper.normalize_bucket(
            "osquery_apps",
            self.bucket(
                asset="MAC-Workstation.Example.Test.",
                product="Example App",
                version="7.8.9",
                latest={
                    "host": {
                        "os": {
                            "name": "macOS",
                            "platform": "darwin",
                            "version": "26.0",
                            "full": "macOS 26.0 (25A5306g)",
                            "build": "25A5306g",
                        }
                    },
                    "osquery": {"category": "public.app-category.productivity"},
                },
            ),
        )
        self.assertEqual(cursor["asset"], "MAC-Workstation.Example.Test.")
        self.assertEqual(record["source"], "osquery_apps")
        self.assertEqual(record["tier"], "installed")
        self.assertEqual(record["confidence"], "high")
        self.assertEqual(record["asset_ref_type"], "host")
        self.assertEqual(record["platform"], "darwin")
        self.assertEqual(record["operating_system_type"], "macOS")
        self.assertEqual(
            record["operating_system_version"],
            "macOS 26.0 (25A5306g)",
        )
        self.assertEqual(
            record["operating_system_source"],
            "osquery_manager.result:host.os",
        )
        self.assertEqual(record["operating_system_confidence"], "high")
        self.assertEqual(len(record["asset_ref"]), 24)
        self.assertNotIn("mac-workstation", json.dumps(record))
        expected = hashlib.sha256(
            "host\0mac-workstation.example.test".encode("utf-8")
        ).hexdigest()[:24]
        self.assertEqual(record["asset_ref"], expected)
        with self.assertRaisesRegex(ValueError, "UUID-shaped"):
            self.helper.validate_cursor(
                {
                    "asset": "123e4567-e89b-12d3-a456-426614174000",
                    "product": "Example App",
                    "version": "1",
                },
                "osquery_apps",
            )

        zeek, _ = self.helper.normalize_bucket(
            "zeek_software",
            self.bucket(
                asset="10.66.6.10",
                product="Example Client",
                version=None,
                latest={"software": {"type": "HTTP::BROWSER"}},
            ),
        )
        self.assertEqual(zeek["tier"], "observed")
        self.assertEqual(zeek["confidence"], "medium")
        self.assertEqual(zeek["version"], "")
        self.assertEqual(zeek["asset_ref"], "10.66.6.10")
        self.assertEqual(zeek["operating_system_type"], "")
        self.assertEqual(zeek["operating_system_version"], "")

        user_agent_bucket = self.bucket(
            asset="fd00::20",
            product="ExampleBrowser/1.0",
            version=None,
        )
        user_agent_bucket["key"].pop("version")
        user_agent, _ = self.helper.normalize_bucket(
            "http_user_agent",
            user_agent_bucket,
        )
        self.assertEqual(user_agent["tier"], "inferred")
        self.assertEqual(user_agent["confidence"], "low")
        self.assertEqual(user_agent["category"], "http_client")
        with self.assertRaisesRegex(RuntimeError, "non-LAN"):
            self.helper.normalize_bucket(
                "zeek_software",
                self.bucket(
                    asset="203.0.113.10",
                    product="Internet Server",
                    version="1",
                ),
            )

    def test_execution_uses_only_fixed_index_and_unambiguous_lookahead_cursor(self) -> None:
        buckets = [
            self.bucket(
                asset="10.66.6.10",
                product="Client A",
                version="1.0",
            ),
            self.bucket(
                asset="10.66.6.11",
                product="Client B",
                version="2.0",
            ),
        ]
        elastic = {
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "failed": 0},
            "aggregations": {"software": {"buckets": buckets}},
        }
        runner = mock.Mock(
            return_value=SimpleNamespace(
                returncode=0,
                stdout=json.dumps(elastic).encode("utf-8"),
                stderr=b"",
            )
        )
        request = self.request(source="zeek_software", page_size=1)
        with mock.patch.object(self.helper, "run_bounded_command", runner):
            response = self.helper.execute_request(request)
        self.assertEqual(response["returned"], 1)
        self.assertFalse(response["complete"])
        self.assertTrue(response["truncated"])
        self.assertEqual(response["after"], buckets[0]["key"])
        self.assertEqual(
            response["query_audit"]["index"],
            "logs-zeek-so",
        )
        command = runner.call_args.args[0]
        self.assertEqual(command[1], "logs-zeek-so/_search")
        body = json.loads(command[3])
        self.assertEqual(body["aggs"]["software"]["composite"]["size"], 2)
        self.assertNotIn("after", body["aggs"]["software"]["composite"])

    def test_execution_fails_closed_on_partial_shards(self) -> None:
        elastic = {
            "timed_out": False,
            "_shards": {"total": 2, "successful": 1, "failed": 1},
            "aggregations": {"software": {"buckets": []}},
        }
        runner = mock.Mock(
            return_value=SimpleNamespace(
                returncode=0,
                stdout=json.dumps(elastic).encode("utf-8"),
                stderr=b"",
            )
        )
        with mock.patch.object(self.helper, "run_bounded_command", runner):
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                self.helper.execute_request(self.request())

    def test_dispatcher_loads_only_the_colocated_fixed_helper(self) -> None:
        source = DISPATCHER.read_text(encoding="utf-8")
        self.assertIn(
            'SOFTWARE_INVENTORY_CONTRACT = "onion-sentinel-software-inventory-v1"',
            source,
        )
        self.assertIn('"export-software-observations"', source)
        self.assertIn("return execute_software_inventory(request_data)", source)
        self.assertIn(
            "bounded software inventory response exceeded the output contract",
            source,
        )
        installer = (
            ROOT
            / "security-onion"
            / "bin"
            / "install-security-onion-wrapper.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '"$REPO_DIR/security-onion/bin/export-software-observations" '
            "/usr/local/sbin/export-software-observations",
            installer,
        )


class SoftwareInventoryRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.broker = load_module("software_inventory_relay_test", BROKER)

    def request(
        self,
        *,
        source: str = "osquery_apps",
        page_size: int = 100,
    ) -> dict:
        return {
            "contract": self.broker.SOFTWARE_INVENTORY_CONTRACT,
            "operation": self.broker.SOFTWARE_INVENTORY_OPERATION,
            "source": source,
            "window": {
                "start": "2026-07-29T00:00:00Z",
                "end": "2026-07-30T00:00:00Z",
            },
            "page_size": page_size,
            "after": None,
        }

    def response(self, request: dict, *, records: list[dict] | None = None) -> dict:
        source = request["source"]
        spec = self.broker.SOFTWARE_INVENTORY_SOURCES[source]
        values = records or []
        return {
            "ok": True,
            "contract": self.broker.SOFTWARE_INVENTORY_CONTRACT,
            "read_only": True,
            "source": source,
            "window": dict(request["window"]),
            "returned": len(values),
            "complete": True,
            "truncated": False,
            "after": None,
            "records": values,
            "query_audit": {
                "index": spec["index"],
                "dataset": spec["dataset"],
                "query_digest": "a" * 64,
            },
        }

    def record(self, source: str) -> dict:
        spec = self.broker.SOFTWARE_INVENTORY_SOURCES[source]
        return {
            "evidence_id": "b" * 24,
            "source": source,
            "source_dataset": spec["dataset"],
            "tier": spec["tier"],
            "confidence": spec["confidence"],
            "asset_ref_type": spec["asset_ref_type"],
            "asset_ref": (
                "c" * 24
                if spec["asset_ref_type"] == "host"
                else "10.66.6.10"
            ),
            "platform": "darwin" if source == "osquery_apps" else "",
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
            "product": "Example App",
            "version": "1.2.3",
            "category": "application",
            "first_seen": "2026-07-29T01:00:00Z",
            "last_seen": "2026-07-29T02:00:00Z",
            "observation_count": 2,
        }

    def test_relay_revalidates_exact_request_and_response_contracts(self) -> None:
        for source in self.broker.SOFTWARE_INVENTORY_SOURCES:
            with self.subTest(source=source):
                request = self.request(source=source)
                self.broker.validate_software_request(request)
                response = self.response(
                    request,
                    records=[self.record(source)],
                )
                self.broker.validate_software_response(response, request)
        request = self.request()
        for extra in ({"index": "*"}, {"query": {}}, {"token": "secret"}):
            with self.subTest(extra=next(iter(extra))):
                with self.assertRaises(ValueError):
                    self.broker.validate_software_request({**request, **extra})
        valid_cursor = json.loads(json.dumps(request))
        valid_cursor["after"] = {
            "asset": "HOST.EXAMPLE.TEST.",
            "product": "Example App",
            "version": "1",
        }
        self.broker.validate_software_request(valid_cursor)
        invalid_cursor = json.loads(json.dumps(request))
        invalid_cursor["after"] = {
            "asset": "123e4567-e89b-12d3-a456-426614174000",
            "product": "Example App",
            "version": "1",
        }
        with self.assertRaises(ValueError):
            self.broker.validate_software_request(invalid_cursor)

    def test_relay_rejects_response_scope_drift_and_identifier_leakage(self) -> None:
        request = self.request()
        response = self.response(
            request,
            records=[self.record("osquery_apps")],
        )
        mutated = json.loads(json.dumps(response))
        mutated["query_audit"]["index"] = "*"
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(mutated, request)

        mutated = json.loads(json.dumps(response))
        mutated["records"][0]["agent_id"] = "raw-agent-id"
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(mutated, request)

        mutated = json.loads(json.dumps(response))
        mutated["records"][0]["asset_ref"] = "raw-host-identity"
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(mutated, request)

        mutated = json.loads(json.dumps(response))
        mutated["records"][0]["operating_system_source"] = "untrusted"
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(mutated, request)

        network_request = self.request(source="zeek_software")
        network_response = self.response(
            network_request,
            records=[self.record("zeek_software")],
        )
        network_response["records"][0]["asset_ref"] = "203.0.113.10"
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(
                network_response,
                network_request,
            )

    def test_operating_system_rejection_precedence_and_messages_are_exact(self) -> None:
        endpoint_request = self.request(source="osquery_apps")
        endpoint_response = self.response(
            endpoint_request,
            records=[self.record("osquery_apps")],
        )
        cases = (
            (
                {"operating_system_type": 1},
                "record.operating_system_type must be a string",
            ),
            (
                {"operating_system_source": "untrusted"},
                "endpoint operating-system provenance failed validation",
            ),
            (
                {
                    "operating_system_type": "",
                    "operating_system_version": "",
                },
                "empty endpoint operating-system evidence claims provenance",
            ),
        )
        for changes, message in cases:
            mutated = json.loads(json.dumps(endpoint_response))
            mutated["records"][0].update(changes)
            with self.subTest(message=message, changes=changes):
                with self.assertRaisesRegex(ValueError, message):
                    self.broker.validate_software_response(
                        mutated,
                        endpoint_request,
                    )

        passive_request = self.request(source="zeek_software")
        passive_response = self.response(
            passive_request,
            records=[self.record("zeek_software")],
        )
        passive_response["records"][0]["operating_system_confidence"] = "high"
        with self.assertRaisesRegex(
            ValueError,
            "passive software evidence cannot assert an exact operating system",
        ):
            self.broker.validate_software_response(
                passive_response,
                passive_request,
            )

        legacy = self.record("zeek_software")
        for field in (
            "operating_system_type",
            "operating_system_version",
            "operating_system_source",
            "operating_system_confidence",
        ):
            legacy.pop(field)
        self.broker.validate_software_response(
            self.response(passive_request, records=[legacy]),
            passive_request,
        )

    def test_response_page_rejection_precedence_and_messages_are_exact(self) -> None:
        request = self.request(source="zeek_software", page_size=1)
        response = self.response(
            request,
            records=[self.record("zeek_software")],
        )
        count_cases = (
            {"records": {}, "returned": 0},
            {"returned": True},
            {"returned": 0},
            {"returned": 2},
        )
        for changes in count_cases:
            mutated = json.loads(json.dumps(response))
            mutated.update(changes)
            with self.subTest(count_changes=changes):
                with self.assertRaisesRegex(
                    ValueError,
                    "software inventory response count failed validation",
                ):
                    self.broker.validate_software_response(mutated, request)

        pagination_cases = (
            {"complete": 1},
            {"truncated": 0},
            {"complete": True, "truncated": True},
            {"complete": False, "truncated": False},
        )
        for changes in pagination_cases:
            mutated = json.loads(json.dumps(response))
            mutated.update(changes)
            with self.subTest(page_changes=changes):
                with self.assertRaisesRegex(
                    ValueError,
                    "software inventory pagination state failed validation",
                ):
                    self.broker.validate_software_response(mutated, request)

        complete_cursor = json.loads(json.dumps(response))
        complete_cursor["after"] = {
            "asset": "10.66.6.10",
            "product": "Example App",
            "version": "1.2.3",
        }
        with self.assertRaisesRegex(
            ValueError,
            "complete software inventory response retained a cursor",
        ):
            self.broker.validate_software_response(complete_cursor, request)

        truncated = json.loads(json.dumps(response))
        truncated.update(complete=False, truncated=True, after=None)
        with self.assertRaisesRegex(
            ValueError,
            "truncated software inventory response omitted its cursor",
        ):
            self.broker.validate_software_response(truncated, request)

    def test_relay_rejects_inconsistent_pagination_and_semantic_tiers(self) -> None:
        request = self.request(source="zeek_software")
        response = self.response(
            request,
            records=[self.record("zeek_software")],
        )
        mutated = json.loads(json.dumps(response))
        mutated["complete"] = False
        mutated["truncated"] = True
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(mutated, request)

        mutated = json.loads(json.dumps(response))
        mutated["records"][0]["tier"] = "installed"
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(mutated, request)

        mutated = json.loads(json.dumps(response))
        mutated["window"]["end"] = "2026-07-29T23:59:59Z"
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(mutated, request)

        host_request = self.request(source="osquery_apps")
        host_response = self.response(
            host_request,
            records=[self.record("osquery_apps")],
        )
        host_response["complete"] = False
        host_response["truncated"] = True
        host_response["after"] = {
            "asset": "HOST.EXAMPLE.TEST.",
            "product": "Example App",
            "version": "1.2.3",
        }
        self.broker.validate_software_response(host_response, host_request)
        host_response["after"]["asset"] = (
            "123e4567-e89b-12d3-a456-426614174000"
        )
        with self.assertRaises(ValueError):
            self.broker.validate_software_response(host_response, host_request)


if __name__ == "__main__":
    unittest.main()
