import importlib.machinery
import importlib.util
import datetime as dt
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
SO_WRAPPER = ROOT / "security-onion" / "bin" / "run-live-osquery"
SO_CONFIG_EXAMPLE = (
    ROOT / "security-onion" / "config" / "live-osquery.example.json"
)
SO_LAUNCHER = ROOT / "security-onion" / "bin" / "run-live-osquery-forced"
SO_AUTHORIZED_KEY = (
    ROOT / "security-onion" / "ssh" / "authorized_keys.live-osquery.example"
)
SO_INSTALLER = ROOT / "security-onion" / "bin" / "install-security-onion-wrapper.sh"
RELAY_AUTHORIZED_KEY = (
    ROOT / "relay" / "config" / "authorized_keys.live-osquery.example"
)
RELAY_INSTALLER = ROOT / "relay" / "bin" / "install-pi-relay.sh"
RELAY_SUDOERS = ROOT / "relay" / "sudoers" / "so-live-osquery"
RELAY_LAUNCHER = ROOT / "relay" / "bin" / "run-live-osquery-broker"
RELAY_BROKER = ROOT / "relay" / "app" / "live_osquery_broker.py"
sys.path.insert(0, str(BIN))
sys.path.insert(0, str(ROOT / "relay" / "app"))

from live_osquery_contract import (  # noqa: E402
    LiveOsqueryContractError,
    normalize_query,
    normalize_requests,
    validate_result_artifact,
)
from live_osquery_client import (  # noqa: E402
    LiveOsqueryClientError,
    _persist_live_osquery_artifact,
    capability_descriptor,
    collect_live_osquery,
    harness_operator_approved,
    load_live_osquery_config,
    scheduled_inventory_approved,
)
from bounded_process import BoundedProcessError  # noqa: E402


def load_security_onion_wrapper():
    loader = importlib.machinery.SourceFileLoader("run_live_osquery", str(SO_WRAPPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def load_relay_broker():
    loader = importlib.machinery.SourceFileLoader(
        "live_osquery_broker_test",
        str(RELAY_BROKER),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class LiveOsqueryContractTests(unittest.TestCase):
    def test_normalizes_read_only_select_and_adds_bound(self):
        self.assertEqual(
            normalize_query(" SELECT pid, name FROM processes "),
            "SELECT pid, name FROM processes LIMIT 100;",
        )

    def test_rejects_joins_even_between_allowlisted_tables(self):
        with self.assertRaises(LiveOsqueryContractError):
            normalize_query(
                "SELECT p.pid, p.name, s.remote_address "
                "FROM processes p JOIN process_open_sockets s ON p.pid = s.pid LIMIT 25;"
            )

    def test_rejects_mutations_comments_unknown_tables_and_excessive_limits(self):
        rejected = (
            "DELETE FROM processes;",
            "SELECT * FROM processes -- bypass",
            "SELECT * FROM socket_events;",
            "SELECT * FROM processes LIMIT 201;",
            "SELECT * FROM processes UNION SELECT * FROM users;",
            "WITH p AS (SELECT * FROM processes) SELECT * FROM p;",
            "SELECT * FROM processes, users;",
        )
        for query in rejected:
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)

    def test_rejects_quoted_tables_functions_and_projection_aliases(self):
        rejected = (
            'SELECT * FROM processes JOIN "shell_history" ON 1=1 LIMIT 1;',
            "SELECT * FROM processes JOIN `ssh_keys` ON 1=1 LIMIT 1;",
            "SELECT * FROM processes JOIN [file] ON 1=1 LIMIT 1;",
            "SELECT randomblob(1000000000) FROM processes LIMIT 1;",
            "SELECT zeroblob(1000000000) FROM processes LIMIT 1;",
            "SELECT printf('%1000000000s', name) FROM processes LIMIT 1;",
            'SELECT "8.8.8.8" AS "source.ip" FROM processes LIMIT 1;',
            "SELECT '8.8.8.8' AS source_ip FROM processes LIMIT 1;",
            "SELECT name AS source_ip FROM processes LIMIT 1;",
            "SELECT * FROM processes LIMIT 200, 1000000;",
            "SELECT * FROM processes LIMIT 1 + 1000000;",
            "SELECT * FROM processes LIMIT 10 OFFSET 1000000;",
        )
        for query in rejected:
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)

    def test_allows_single_table_native_columns_and_string_predicates(self):
        self.assertEqual(
            normalize_query(
                "SELECT pid, name, path FROM processes "
                "WHERE name = 'launchd' LIMIT 20"
            ),
            "SELECT pid, name, path FROM processes "
            "WHERE name = 'launchd' LIMIT 20;",
        )

    def test_rejects_wildcard_and_nonexistent_darwin_columns(self):
        for query in (
            "SELECT * FROM processes LIMIT 1;",
            "SELECT package_arch FROM homebrew_packages LIMIT 1;",
            "SELECT auto_updates FROM homebrew_packages LIMIT 1;",
            "SELECT app_name FROM homebrew_packages LIMIT 1;",
            "SELECT definitely_not_a_column FROM system_info LIMIT 1;",
            "SELECT pid FROM processes "
            "WHERE definitely_not_a_column = 'x' LIMIT 1;",
            "SELECT pid FROM processes "
            "ORDER BY definitely_not_a_column LIMIT 1;",
            "SELECT system_info.pid FROM processes LIMIT 1;",
        ):
            with self.subTest(query=query):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_query(query)

    def test_allows_mac_osquery_identity_and_version_probes(self):
        self.assertEqual(
            normalize_query(
                "SELECT version, build_platform FROM osquery_info LIMIT 1;"
            ),
            "SELECT version, build_platform FROM osquery_info LIMIT 1;",
        )
        self.assertEqual(
            normalize_query("SELECT version, build, arch FROM os_version LIMIT 1;"),
            "SELECT version, build, arch FROM os_version LIMIT 1;",
        )
        self.assertEqual(
            normalize_query(
                "SELECT name, path, version, type, prefix "
                "FROM homebrew_packages LIMIT 5;"
            ),
            "SELECT name, path, version, type, prefix "
            "FROM homebrew_packages LIMIT 5;",
        )

    def test_rejects_wildcard_or_unconfigured_endpoint_targets(self):
        for alias in ("*", "all", "unknown-endpoint"):
            with self.subTest(alias=alias):
                with self.assertRaises(LiveOsqueryContractError):
                    normalize_requests(
                        [
                            {
                                "target_alias": alias,
                                "query": "SELECT * FROM system_info;",
                                "purpose": "inventory",
                            }
                        ],
                        allowed_aliases=["workstation-01"],
                    )

    def test_binds_every_result_to_the_exact_submitted_request(self):
        requests = normalize_requests(
            [
                {
                    "target_alias": "workstation-01",
                    "query": "SELECT pid, name FROM processes LIMIT 10;",
                    "purpose": "correlate running processes",
                }
            ],
            allowed_aliases=["workstation-01"],
        )
        artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-1",
            "generated_at": "2026-07-23T00:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    **requests[0],
                    "status": "ok",
                    "rows": [{"pid": "42", "name": "launchd"}],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 50,
                    "error": "",
                }
            ],
        }
        normalized = validate_result_artifact(
            json.loads(json.dumps(artifact)),
            expected_requests=requests,
        )
        self.assertTrue(normalized["complete"])
        self.assertEqual(normalized["results"][0]["rows"][0]["pid"], "42")

        substituted = json.loads(json.dumps(artifact))
        substituted["results"][0]["target_alias"] = "workstation-02"
        with self.assertRaises(LiveOsqueryContractError):
            validate_result_artifact(substituted, expected_requests=requests)

        missing = json.loads(json.dumps(artifact))
        missing["results"] = []
        with self.assertRaises(LiveOsqueryContractError):
            validate_result_artifact(missing, expected_requests=requests)

        unexpected_column = json.loads(json.dumps(artifact))
        unexpected_column["results"][0]["rows"][0]["unexpected_secret"] = "value"
        with self.assertRaisesRegex(
            LiveOsqueryContractError,
            "query projection",
        ):
            validate_result_artifact(
                unexpected_column,
                expected_requests=requests,
            )

        missing_column = json.loads(json.dumps(artifact))
        missing_column["results"][0]["rows"][0].pop("name")
        with self.assertRaisesRegex(
            LiveOsqueryContractError,
            "query projection",
        ):
            validate_result_artifact(
                missing_column,
                expected_requests=requests,
            )

        impossible_count = json.loads(json.dumps(artifact))
        impossible_count["results"][0]["query"] = (
            "SELECT pid, name FROM processes LIMIT 1;"
        )
        impossible_count["results"][0]["total_rows"] = 2
        impossible_count["results"][0]["truncated"] = True
        requests_with_one_row_limit = normalize_requests(
            [
                {
                    "target_alias": "workstation-01",
                    "query": "SELECT pid, name FROM processes LIMIT 1;",
                    "purpose": "correlate running processes",
                }
            ],
            allowed_aliases=["workstation-01"],
        )
        with self.assertRaisesRegex(
            LiveOsqueryContractError,
            "query LIMIT",
        ):
            validate_result_artifact(
                impossible_count,
                expected_requests=requests_with_one_row_limit,
            )


class SecurityOnionLiveOsqueryResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = load_security_onion_wrapper()

    def test_reads_query_level_execution_counters(self):
        state = self.wrapper._query_state(
            {
                "data": {
                    "action_id": "action-id",
                    "agents": ["agent-id"],
                    "status": "completed",
                    "queries": [
                        {
                            "action_id": "query-action-id",
                            "agents": ["agent-id"],
                            "query": "SELECT hostname FROM system_info LIMIT 1;",
                            "status": "completed",
                            "successful": 1,
                            "failed": 0,
                            "pending": 0,
                            "responded": 1,
                            "docs": 1,
                        }
                    ],
                }
            },
            expected_parent_action_id="action-id",
            expected_query_action_id="query-action-id",
            expected_agent_id="agent-id",
            expected_query="SELECT hostname FROM system_info LIMIT 1;",
        )
        self.assertEqual(state, ("completed", 1, 0, 0, 1, 1))

    def test_rejects_unbound_or_inconsistent_query_details(self):
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        mutations = {
            "parent action": lambda value: value["data"].update(
                action_id="other-action"
            ),
            "parent agent": lambda value: value["data"].update(
                agents=["other-agent"]
            ),
            "multiple queries": lambda value: value["data"]["queries"].append(
                dict(value["data"]["queries"][0])
            ),
            "child action": lambda value: value["data"]["queries"][0].update(
                action_id="other-query-action"
            ),
            "child agent": lambda value: value["data"]["queries"][0].update(
                agents=["other-agent"]
            ),
            "sql": lambda value: value["data"]["queries"][0].update(
                query="SELECT * FROM processes LIMIT 1;"
            ),
            "unknown state": lambda value: value["data"]["queries"][0].update(
                status="expired"
            ),
            "boolean counter": lambda value: value["data"]["queries"][0].update(
                successful=True
            ),
            "negative counter": lambda value: value["data"]["queries"][0].update(
                docs=-1
            ),
            "counter mismatch": lambda value: value["data"]["queries"][0].update(
                responded=0
            ),
            "terminal pending": lambda value: value["data"]["queries"][0].update(
                pending=1
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(details))
                mutate(candidate)
                with self.assertRaises(self.wrapper.LiveQueryError):
                    self.wrapper._query_state(
                        candidate,
                        expected_parent_action_id="action-id",
                        expected_query_action_id="query-action-id",
                        expected_agent_id="agent-id",
                        expected_query=(
                            "SELECT hostname FROM system_info LIMIT 1;"
                        ),
                    )

    def test_rejects_parent_and_child_state_mismatch(self):
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "running",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "completion state was inconsistent",
        ):
            self.wrapper._query_state(
                details,
                expected_parent_action_id="action-id",
                expected_query_action_id="query-action-id",
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            )

    def test_rejects_inflight_details_with_missing_counters(self):
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "running",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "running",
                    }
                ],
            }
        }
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "omitted the successful counter",
        ):
            self.wrapper._query_state(
                details,
                expected_parent_action_id="action-id",
                expected_query_action_id="query-action-id",
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            )

    def test_waits_for_reported_result_documents_to_become_visible(self):
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        # Pagination, index refresh, or authorization can expose a positive
        # hit total before any usable edge is returned. Total metadata alone
        # must not satisfy the result-visibility gate.
        empty_results = {"data": {"edges": [], "total": 1}}
        visible_results = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "agent-id"},
                            "action_id": "query-action-id",
                            "osquery": {"hostname": "endpoint-a"},
                        }
                    }
                ],
                "total": 1,
            }
        }
        with (
            mock.patch.object(
                self.wrapper,
                "_http_json",
                side_effect=[
                    submitted,
                    details,
                    empty_results,
                    details,
                    visible_results,
                ],
            ) as http_json,
            mock.patch.object(self.wrapper.time, "sleep"),
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 1;",
                purpose="result visibility test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 10,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [{"hostname": "endpoint-a"}])
        result_urls = [
            call.kwargs["url"]
            for call in http_json.call_args_list
            if "/results/" in call.kwargs["url"]
        ]
        self.assertTrue(result_urls)
        self.assertTrue(all("?page=0&pageSize=200" in url for url in result_urls))
        self.assertTrue(all("?page=1" not in url for url in result_urls))

    def test_waits_before_accepting_an_initial_zero_row_snapshot(self):
        query = "SELECT hostname FROM system_info LIMIT 1;"
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": query,
                    }
                ],
            }
        }

        def details(docs):
            return {
                "data": {
                    "action_id": "action-id",
                    "agents": ["agent-id"],
                    "status": "completed",
                    "queries": [
                        {
                            "action_id": "query-action-id",
                            "agents": ["agent-id"],
                            "query": query,
                            "status": "completed",
                            "successful": 1,
                            "failed": 0,
                            "pending": 0,
                            "responded": 1,
                            "docs": docs,
                        }
                    ],
                }
            }

        visible_results = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "agent-id"},
                            "action_id": "query-action-id",
                            "osquery": {"hostname": "endpoint-a"},
                        }
                    }
                ],
                "total": 1,
            }
        }
        with (
            mock.patch.object(
                self.wrapper,
                "_http_json",
                side_effect=[
                    submitted,
                    details(0),
                    {"data": {"edges": [], "total": 0}},
                    details(1),
                    visible_results,
                ],
            ),
            mock.patch.object(self.wrapper.time, "sleep"),
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query=query,
                purpose="zero snapshot visibility test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 10,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [{"hostname": "endpoint-a"}])

    def test_missing_reported_result_documents_fails_closed(self):
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 1,
                    }
                ],
            }
        }
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=[submitted, details, {"data": {"edges": [], "total": 1}}],
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 1;",
                purpose="missing result test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 0,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "error")
        self.assertIn("did not match readable rows", result["error"])

    def test_partial_reported_result_documents_fail_closed(self):
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 2;",
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 2;",
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 2,
                    }
                ],
            }
        }
        partial_results = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "agent-id"},
                            "action_id": "query-action-id",
                            "osquery": {"hostname": "endpoint-a"},
                        }
                    }
                ],
                "total": 2,
            }
        }
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=[submitted, details, partial_results],
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 2;",
                purpose="partial result test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 0,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["total_rows"], 2)
        self.assertIn("did not match readable rows", result["error"])

    def test_successful_zero_row_query_is_complete_evidence(self):
        query = "SELECT hostname FROM system_info WHERE hostname = 'absent' LIMIT 1;"
        submitted = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": query,
                    }
                ],
            }
        }
        details = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "status": "completed",
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": query,
                        "status": "completed",
                        "successful": 1,
                        "failed": 0,
                        "pending": 0,
                        "responded": 1,
                        "docs": 0,
                    }
                ],
            }
        }
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=[submitted, details, {"data": {"edges": [], "total": 0}}],
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query=query,
                purpose="zero result test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                    "result_visibility_seconds": 0,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=time.monotonic() + 60,
            )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["total_rows"], 0)
        self.assertFalse(result["truncated"])

    def test_reads_current_elastic_result_shape(self):
        rows, total = self.wrapper._result_rows(
            {
                "data": {
                    "edges": [
                        {
                            "_id": "result-1",
                            "_source": {
                                "agent": {"id": "agent-id"},
                                "action_id": "query-action-id",
                                "osquery": {"pid": "42", "name": "launchd"},
                            }
                        }
                    ],
                    "total": 1,
                }
            },
            expected_agent_id="agent-id",
            expected_action_id="query-action-id",
        )
        self.assertEqual(rows, [{"pid": "42", "name": "launchd"}])
        self.assertEqual(total, 1)

    def test_accepts_legacy_nested_columns_shape(self):
        rows, total = self.wrapper._result_rows(
            {
                "data": {
                    "edges": [
                        {
                            "_id": "result-1",
                            "_source": {
                                "agent": {"id": "agent-id"},
                                "action_id": "query-action-id",
                                "osquery": {"columns": {"uid": "501"}},
                            }
                        }
                    ],
                    "total": {"value": 1, "relation": "eq"},
                }
            },
            expected_agent_id="agent-id",
            expected_action_id="query-action-id",
        )
        self.assertEqual(rows, [{"uid": "501"}])
        self.assertEqual(total, 1)

    def test_rejects_invalid_or_impossible_result_totals(self):
        edge = {
            "_id": "result-1",
            "_source": {
                "agent": {"id": "agent-id"},
                "action_id": "query-action-id",
                "osquery": {"pid": "42"},
            }
        }
        invalid_totals = (None, True, "1", -1, 201)
        for total in invalid_totals:
            with (
                self.subTest(total=total),
                self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "total was invalid",
                ),
            ):
                self.wrapper._result_rows(
                    {"data": {"edges": [edge], "total": total}},
                    expected_agent_id="agent-id",
                    expected_action_id="query-action-id",
                )
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "smaller than its readable rows",
        ):
            self.wrapper._result_rows(
                {"data": {"edges": [edge], "total": 0}},
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "total was inexact",
        ):
            self.wrapper._result_rows(
                {
                    "data": {
                        "edges": [edge],
                        "total": {"value": 1, "relation": "gte"},
                    }
                },
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )
        with self.assertRaisesRegex(
            self.wrapper.LiveQueryError,
            "total was inexact",
        ):
            self.wrapper._result_rows(
                {
                    "data": {
                        "edges": [edge],
                        "total": {"value": 1},
                    }
                },
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )

    def test_rejects_missing_or_duplicate_result_edge_identities(self):
        edge = {
            "_id": "result-1",
            "_source": {
                "agent": {"id": "agent-id"},
                "action_id": "query-action-id",
                "osquery": {"pid": "42"},
            },
        }
        for edges in (
            [{key: value for key, value in edge.items() if key != "_id"}],
            [edge, dict(edge)],
        ):
            with self.assertRaisesRegex(
                self.wrapper.LiveQueryError,
                "invalid or duplicate identity",
            ):
                self.wrapper._result_rows(
                    {"data": {"edges": edges, "total": len(edges)}},
                    expected_agent_id="agent-id",
                    expected_action_id="query-action-id",
                )

    def test_rejects_result_rows_from_a_different_agent_or_action(self):
        response = {
            "data": {
                "edges": [
                    {
                        "_id": "result-1",
                        "_source": {
                            "agent": {"id": "other-agent"},
                            "action_id": "query-action-id",
                            "osquery": {"pid": "42"},
                        }
                    }
                ],
                "total": 1,
            }
        }
        with self.assertRaisesRegex(self.wrapper.LiveQueryError, "target agent"):
            self.wrapper._result_rows(
                response,
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )

        response["data"]["edges"][0]["_source"]["agent"]["id"] = "agent-id"
        response["data"]["edges"][0]["_source"]["action_id"] = "other-action"
        with self.assertRaisesRegex(self.wrapper.LiveQueryError, "query action"):
            self.wrapper._result_rows(
                response,
                expected_agent_id="agent-id",
                expected_action_id="query-action-id",
            )

    def test_submission_identity_is_exact(self):
        response = {
            "data": {
                "action_id": "action-id",
                "agents": ["agent-id"],
                "queries": [
                    {
                        "action_id": "query-action-id",
                        "agents": ["agent-id"],
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                    }
                ],
            }
        }
        self.assertEqual(
            self.wrapper._extract_action_ids(
                response,
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            ),
            ("action-id", "query-action-id"),
        )
        response["data"]["agents"] = ["other-agent"]
        with self.assertRaisesRegex(self.wrapper.LiveQueryError, "exact target"):
            self.wrapper._extract_action_ids(
                response,
                expected_agent_id="agent-id",
                expected_query="SELECT hostname FROM system_info LIMIT 1;",
            )

    def test_allows_only_explicit_loopback_http_or_verified_https(self):
        base = {
            "enabled": True,
            "authorization_profile": self.wrapper.AUTHORIZATION_PROFILE,
            "kibana_url": "http://127.0.0.1:5601",
            "allow_loopback_http": True,
            "verify_tls": False,
            "target_aliases": {"endpoint-a": "agent-id"},
        }
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "config.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            with mock.patch.object(
                self.wrapper,
                "_require_secure_regular_file",
            ):
                loaded = self.wrapper._load_config(path)
                self.assertEqual(loaded["kibana_url"], "http://127.0.0.1:5601")

                external = dict(base, kibana_url="http://192.168.1.7:5601")
                path.write_text(json.dumps(external), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "loopback-only",
                ):
                    self.wrapper._load_config(path)

                missing_profile = dict(base)
                missing_profile.pop("authorization_profile")
                path.write_text(json.dumps(missing_profile), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "authorization profile",
                ):
                    self.wrapper._load_config(path)

                unverified = dict(
                    base,
                    kibana_url="https://127.0.0.1:5601",
                    verify_tls=False,
                )
                path.write_text(json.dumps(unverified), encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "TLS verification",
                ):
                    self.wrapper._load_config(path)

    def test_authorization_requires_the_dedicated_api_key_scheme(self):
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "authorization"
            with mock.patch.object(
                self.wrapper,
                "_require_secure_regular_file",
            ):
                path.write_text("ApiKey opaque-value\n", encoding="utf-8")
                self.assertEqual(
                    self.wrapper._load_authorization(path),
                    "ApiKey opaque-value",
                )
                path.write_text("Bearer opaque-value\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    self.wrapper.LiveQueryError,
                    "dedicated ApiKey",
                ):
                    self.wrapper._load_authorization(path)

    def test_expired_global_deadline_never_dispatches_http(self):
        with mock.patch.object(
            self.wrapper,
            "_http_json",
            side_effect=AssertionError("HTTP should not run after deadline"),
        ):
            result = self.wrapper._run_query(
                target_alias="endpoint-a",
                agent_id="agent-id",
                query="SELECT hostname FROM system_info LIMIT 1;",
                purpose="deadline test",
                config={
                    "kibana_url": "http://127.0.0.1:5601",
                    "query_timeout_seconds": 60,
                    "poll_seconds": 0.5,
                },
                authorization="ApiKey redacted",
                context=None,
                deadline=0.0,
            )
        self.assertEqual(result["status"], "timeout")
        self.assertIn("global batch deadline", result["error"])

    def test_http_transport_disables_proxies_and_redirects(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"data":{}}'

        opener = mock.Mock()
        opener.open.return_value = FakeResponse()
        with mock.patch.object(
            self.wrapper.urllib.request,
            "build_opener",
            return_value=opener,
        ) as build_opener:
            self.assertEqual(
                self.wrapper._http_json(
                    method="GET",
                    url="http://127.0.0.1:5601/api/osquery/live_queries/id",
                    authorization="ApiKey redacted",
                    context=None,
                    timeout_seconds=5,
                ),
                {"data": {}},
            )
        handlers = build_opener.call_args.args
        proxy_handlers = [
            handler
            for handler in handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})
        self.assertTrue(
            any(isinstance(handler, self.wrapper._RejectRedirects) for handler in handlers)
        )

        redirect = urllib.error.HTTPError(
            "http://127.0.0.1:5601/api",
            302,
            "Found",
            {},
            io.BytesIO(),
        )
        opener.open.side_effect = redirect
        with (
            mock.patch.object(
                self.wrapper.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            self.assertRaisesRegex(
                self.wrapper.LiveQueryError,
                "redirects are forbidden",
            ),
        ):
            self.wrapper._http_json(
                method="GET",
                url="http://127.0.0.1:5601/api",
                authorization="ApiKey redacted",
                context=None,
                timeout_seconds=5,
            )
        redirect.close()

    def test_eight_query_batch_shares_one_capped_deadline(self):
        requests = [
            {
                "target_alias": "endpoint-a",
                "query": f"SELECT hostname FROM system_info LIMIT {index + 1};",
                "purpose": f"deadline test {index}",
            }
            for index in range(8)
        ]
        deadlines: list[float] = []

        def fake_run_query(**kwargs):
            deadlines.append(kwargs["deadline"])
            return {
                "target_alias": kwargs["target_alias"],
                "query": kwargs["query"],
                "purpose": kwargs["purpose"],
                "status": "timeout",
                "rows": [],
                "total_rows": 0,
                "truncated": False,
                "duration_ms": 0,
                "error": "test",
            }

        with (
            mock.patch.object(self.wrapper.time, "monotonic", return_value=1000.0),
            mock.patch.object(self.wrapper, "_run_query", side_effect=fake_run_query),
        ):
            results = self.wrapper._run_batch(
                requests=requests,
                alias_map={"endpoint-a": "agent-id"},
                config={
                    "batch_timeout_seconds": 999,
                    "max_concurrent_queries": 4,
                },
                authorization="ApiKey redacted",
                context=None,
            )
        self.assertEqual(len(results), 8)
        self.assertEqual(set(deadlines), {1130.0})


class LiveOsqueryClientConfigTests(unittest.TestCase):
    @staticmethod
    def scheduled_config(temp_name: str) -> dict[str, object]:
        return {
            "enabled": True,
            "allowed_target_aliases": ["endpoint-a"],
            "scheduled_inventory_approval": {
                "approved": True,
                "target_aliases": ["endpoint-a"],
            },
            "relay_host": "relay.invalid",
            "relay_user": "broker",
            "identity_file": Path(temp_name) / "identity",
            "known_hosts": Path(temp_name) / "known_hosts",
            "connect_timeout_seconds": 5,
            "timeout_seconds": 30,
            "port": 22,
            "artifact_dir": Path(temp_name) / "artifacts",
        }

    def test_capability_exposes_only_explicit_darwin_schemas(self):
        descriptor = capability_descriptor(
            {
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
            }
        )
        self.assertEqual(descriptor["target_platform"], "darwin")
        self.assertEqual(descriptor["osquery_version"], "5.15.0")
        self.assertEqual(
            descriptor["table_schemas"]["system_info"][:2],
            ["board_model", "board_serial"],
        )
        self.assertIn("osquery_info", descriptor["allowed_tables"])
        self.assertIn("os_version", descriptor["allowed_tables"])
        self.assertIn("apps", descriptor["allowed_tables"])
        self.assertIn("bundle_identifier", descriptor["table_schemas"]["apps"])
        for unsafe_or_non_darwin in ("deb_packages", "rpm_packages", "suid_bin"):
            self.assertNotIn(unsafe_or_non_darwin, descriptor["allowed_tables"])
        self.assertIn("SELECT * is forbidden", descriptor["restrictions"])

    def test_time_bounded_operator_approval_is_alias_scoped(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            identity = root / "identity"
            known_hosts = root / "known_hosts"
            identity.write_text("private-key-placeholder", encoding="utf-8")
            known_hosts.write_text("host-key-placeholder", encoding="utf-8")
            config_path = root / "live-osquery.json"
            config_path.write_text(
                json.dumps(
                    {
                        "enabled": True,
                        "relay_host": "10.88.8.8",
                        "relay_user": "aj",
                        "identity_file": str(identity),
                        "known_hosts": str(known_hosts),
                        "allowed_target_aliases": ["endpoint-a"],
                        "target_bindings": {
                            "endpoint-a": {
                                "ips": ["192.0.2.10"],
                                "hosts": ["endpoint-a.example"],
                            }
                        },
                        "allowed_agent_roles": ["incident-responder"],
                        "harness_operator_approval": {
                            "approved": True,
                            "expires_at": "2099-01-01T00:00:00Z",
                            "target_aliases": ["endpoint-a"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            config_path.chmod(0o600)
            config = load_live_osquery_config(config_path)

        self.assertTrue(
            harness_operator_approved(
                config,
                "endpoint-a",
                now=dt.datetime(2098, 1, 1, tzinfo=dt.timezone.utc),
            )
        )
        self.assertFalse(
            harness_operator_approved(
                config,
                "endpoint-b",
                now=dt.datetime(2098, 1, 1, tzinfo=dt.timezone.utc),
            )
        )
        self.assertEqual(
            config["target_bindings"]["endpoint-a"]["ips"],
            ["192.0.2.10"],
        )
        self.assertFalse(
            harness_operator_approved(
                config,
                "endpoint-a",
                now=dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc),
            )
        )

    def test_scheduled_inventory_approval_is_independent_and_alias_scoped(self):
        config = {
            "enabled": True,
            "scheduled_inventory_approval": {
                "approved": True,
                "target_aliases": ["endpoint-a"],
            },
        }
        self.assertTrue(scheduled_inventory_approved(config, "endpoint-a"))
        self.assertFalse(scheduled_inventory_approved(config, "endpoint-b"))

    def test_enabled_config_requires_safe_target_asset_bindings(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            identity = root / "identity"
            known_hosts = root / "known_hosts"
            identity.write_text("private-key-placeholder", encoding="utf-8")
            known_hosts.write_text("host-key-placeholder", encoding="utf-8")
            base = {
                "enabled": True,
                "relay_host": "10.88.8.8",
                "relay_user": "aj",
                "identity_file": str(identity),
                "known_hosts": str(known_hosts),
                "allowed_target_aliases": ["endpoint-a"],
            }
            for binding, message in (
                ({}, "trusted asset binding"),
                (
                    {"endpoint-a": {"ips": ["not-an-ip"]}},
                    "invalid IP",
                ),
                (
                    {"endpoint-b": {"ips": ["192.0.2.10"]}},
                    "unconfigured aliases",
                ),
            ):
                config_path = root / "live-osquery.json"
                config_path.write_text(
                    json.dumps({**base, "target_bindings": binding}),
                    encoding="utf-8",
                )
                config_path.chmod(0o600)
                with self.subTest(binding=binding):
                    with self.assertRaisesRegex(
                        LiveOsqueryClientError,
                        message,
                    ):
                        load_live_osquery_config(config_path)

    def test_config_rejects_insecure_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            source = root / "source.json"
            source.write_text("{}", encoding="utf-8")
            source.chmod(0o644)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "mode 0600",
            ):
                load_live_osquery_config(source)
            source.chmod(0o600)
            link = root / "link.json"
            link.symlink_to(source)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "regular file",
            ):
                load_live_osquery_config(link)

    def test_config_rejects_string_false_enabled_value(self):
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "live-osquery.json"
            path.write_text('{"enabled":"false"}', encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "enabled must be boolean",
            ):
                load_live_osquery_config(path)

    def test_collector_enforces_approval_before_transport(self):
        config = {
            "enabled": True,
            "allowed_target_aliases": ["endpoint-a"],
            "harness_operator_approval": {
                "approved": True,
                "target_aliases": ["endpoint-a"],
                "expires_at": "2000-01-01T00:00:00Z",
            },
        }
        with (
            mock.patch(
                "live_osquery_client.run_bounded_command",
                side_effect=AssertionError("transport must not run"),
            ),
            self.assertRaisesRegex(LiveOsqueryClientError, "approval"),
        ):
            collect_live_osquery(
                case_id="case-1",
                requests=[
                    {
                        "target_alias": "endpoint-a",
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "purpose": "verify endpoint",
                    }
                ],
                config=config,
                persist=False,
            )

    def test_collector_preserves_broker_timeout_failure_code(self):
        with tempfile.TemporaryDirectory() as temp_name:
            with (
                mock.patch(
                    "live_osquery_client.run_bounded_command",
                    side_effect=BoundedProcessError(
                        "command timed out after 60 seconds"
                    ),
                ),
                self.assertRaisesRegex(
                    LiveOsqueryClientError,
                    "transport failed",
                ) as raised,
            ):
                collect_live_osquery(
                    case_id="case-timeout",
                    requests=[{
                        "target_alias": "endpoint-a",
                        "query": "SELECT hostname FROM system_info LIMIT 1;",
                        "purpose": "verify endpoint",
                    }],
                    config=self.scheduled_config(temp_name),
                    persist=False,
                    approval_scope="scheduled_inventory",
                )

        self.assertEqual(raised.exception.reason_code, "broker_timeout")

    def test_collector_distinguishes_connect_failure_and_broker_rejection(self):
        with tempfile.TemporaryDirectory() as temp_name:
            config = self.scheduled_config(temp_name)
            for returncode, expected in ((255, "connect_failure"), (17, "broker_rejection")):
                completed = SimpleNamespace(
                    returncode=returncode,
                    stdout="",
                    stderr="restricted transport rejected the request",
                )
                with (
                    self.subTest(returncode=returncode),
                    mock.patch(
                        "live_osquery_client.run_bounded_command",
                        return_value=completed,
                    ),
                    self.assertRaises(LiveOsqueryClientError) as raised,
                ):
                    collect_live_osquery(
                        case_id="case-rejected",
                        requests=[{
                            "target_alias": "endpoint-a",
                            "query": "SELECT hostname FROM system_info LIMIT 1;",
                            "purpose": "verify endpoint",
                        }],
                        config=config,
                        persist=False,
                        approval_scope="scheduled_inventory",
                    )
                self.assertEqual(raised.exception.reason_code, expected)

    def test_collector_persists_immutable_batches_with_bounded_manifest(self):
        query = "SELECT hostname FROM system_info LIMIT 1;"
        purpose = "verify endpoint identity"
        raw_artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-immutable",
            "generated_at": "2026-07-30T19:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    "target_alias": "endpoint-a",
                    "query": query,
                    "purpose": purpose,
                    "status": "ok",
                    "rows": [{"hostname": "endpoint-a"}],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 10,
                    "error": "",
                }
            ],
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(raw_artifact),
            stderr="",
        )
        with tempfile.TemporaryDirectory() as temp_name:
            artifact_dir = Path(temp_name) / "artifacts"
            config = {
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
                "harness_operator_approval": {
                    "approved": True,
                    "target_aliases": ["endpoint-a"],
                    "expires_at": "2099-01-01T00:00:00Z",
                },
                "relay_host": "relay.invalid",
                "relay_user": "broker",
                "identity_file": Path(temp_name) / "identity",
                "known_hosts": Path(temp_name) / "known_hosts",
                "connect_timeout_seconds": 5,
                "timeout_seconds": 30,
                "port": 22,
                "artifact_dir": artifact_dir,
                "max_saved_batches_per_case": 2,
            }
            with mock.patch(
                "live_osquery_client.run_bounded_command",
                return_value=completed,
            ):
                for _ in range(3):
                    collect_live_osquery(
                        case_id="case-immutable",
                        requests=[
                            {
                                "target_alias": "endpoint-a",
                                "query": query,
                                "purpose": purpose,
                            }
                        ],
                        config=config,
                        persist=True,
                    )
            case_dir = artifact_dir / "case-immutable"
            manifest = json.loads(
                (case_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["schema"],
                "onion-sentinel-live-osquery-manifest-v1",
            )
            self.assertEqual(manifest["retention_limit"], 2)
            self.assertEqual(len(manifest["entries"]), 2)
            artifact_files = sorted(
                path
                for path in case_dir.glob("*.json")
                if path.name != "manifest.json"
            )
            self.assertEqual(len(artifact_files), 2)
            self.assertTrue((case_dir / manifest["current"]).is_file())
            self.assertTrue(
                all(
                    stat.S_IMODE(path.stat().st_mode) == 0o600
                    for path in [*artifact_files, case_dir / "manifest.json"]
                )
            )

    def test_concurrent_collectors_preserve_manifest_and_retention(self):
        query = "SELECT hostname FROM system_info LIMIT 1;"
        purpose = "verify endpoint identity"
        raw_artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-concurrent",
            "generated_at": "2026-07-30T19:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [
                {
                    "target_alias": "endpoint-a",
                    "query": query,
                    "purpose": purpose,
                    "status": "ok",
                    "rows": [{"hostname": "endpoint-a"}],
                    "total_rows": 1,
                    "truncated": False,
                    "duration_ms": 10,
                    "error": "",
                }
            ],
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(raw_artifact),
            stderr="",
        )
        with tempfile.TemporaryDirectory() as temp_name:
            artifact_dir = Path(temp_name) / "artifacts"
            config = {
                "enabled": True,
                "allowed_target_aliases": ["endpoint-a"],
                "harness_operator_approval": {
                    "approved": True,
                    "target_aliases": ["endpoint-a"],
                    "expires_at": "2099-01-01T00:00:00Z",
                },
                "relay_host": "relay.invalid",
                "relay_user": "broker",
                "identity_file": Path(temp_name) / "identity",
                "known_hosts": Path(temp_name) / "known_hosts",
                "connect_timeout_seconds": 5,
                "timeout_seconds": 30,
                "port": 22,
                "artifact_dir": artifact_dir,
                "max_saved_batches_per_case": 8,
            }

            def collect_one(_: int) -> dict[str, object]:
                return collect_live_osquery(
                    case_id="case-concurrent",
                    requests=[
                        {
                            "target_alias": "endpoint-a",
                            "query": query,
                            "purpose": purpose,
                        }
                    ],
                    config=config,
                    persist=True,
                )

            with mock.patch(
                "live_osquery_client.run_bounded_command",
                return_value=completed,
            ):
                with ThreadPoolExecutor(max_workers=12) as executor:
                    results = list(executor.map(collect_one, range(24)))

            self.assertEqual(len(results), 24)
            case_dir = artifact_dir / "case-concurrent"
            manifest = json.loads(
                (case_dir / "manifest.json").read_text(encoding="utf-8")
            )
            entries = manifest["entries"]
            self.assertEqual(len(entries), 8)
            self.assertEqual(
                len({entry["artifact"] for entry in entries}),
                len(entries),
            )
            artifact_files = {
                path.name
                for path in case_dir.glob("*.json")
                if path.name != "manifest.json"
            }
            self.assertEqual(
                artifact_files,
                {entry["artifact"] for entry in entries},
            )
            self.assertIn(manifest["current"], artifact_files)
            lock_path = case_dir / ".manifest.lock"
            lock_info = lock_path.lstat()
            self.assertTrue(stat.S_ISREG(lock_info.st_mode))
            self.assertEqual(lock_info.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(lock_info.st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(case_dir.stat().st_mode), 0o700)

    def test_persistence_rejects_unsafe_case_directory_and_lock(self):
        request_payload = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-lock",
            "requests": [],
        }
        artifact = {
            "schema": "onion-sentinel-live-osquery-v1",
            "case_id": "case-lock",
            "generated_at": "2026-07-30T19:00:00Z",
            "read_only": True,
            "complete": True,
            "results": [],
        }
        with tempfile.TemporaryDirectory() as temp_name:
            artifact_dir = Path(temp_name) / "artifacts"
            case_dir = artifact_dir / "case-lock"
            case_dir.mkdir(parents=True, mode=0o700)

            case_dir.chmod(0o755)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "case directory.*0700",
            ):
                _persist_live_osquery_artifact(
                    artifact_dir=artifact_dir,
                    case_id="case-lock",
                    request_payload=request_payload,
                    artifact=artifact,
                    maximum_batches=2,
                )

            case_dir.chmod(0o700)
            lock_path = case_dir / ".manifest.lock"
            lock_path.write_text("", encoding="utf-8")
            lock_path.chmod(0o644)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "manifest lock.*0600",
            ):
                _persist_live_osquery_artifact(
                    artifact_dir=artifact_dir,
                    case_id="case-lock",
                    request_payload=request_payload,
                    artifact=artifact,
                    maximum_batches=2,
                )

            lock_path.unlink()
            target = case_dir / "not-a-lock"
            target.write_text("", encoding="utf-8")
            target.chmod(0o600)
            lock_path.symlink_to(target)
            with self.assertRaisesRegex(
                LiveOsqueryClientError,
                "manifest lock",
            ):
                _persist_live_osquery_artifact(
                    artifact_dir=artifact_dir,
                    case_id="case-lock",
                    request_payload=request_payload,
                    artifact=artifact,
                    maximum_batches=2,
                )
            self.assertFalse((case_dir / "manifest.json").exists())


class LiveOsqueryDeploymentContractTests(unittest.TestCase):
    def test_security_onion_example_allows_observed_index_visibility_lag(self):
        config = json.loads(SO_CONFIG_EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(config["result_visibility_seconds"], 60)

    def test_mac_forced_key_runs_only_broker_as_service_account(self):
        authorized_key = RELAY_AUTHORIZED_KEY.read_text(encoding="utf-8")
        self.assertIn(
            'command="/usr/local/sbin/run-live-osquery-broker"',
            authorized_key,
        )
        self.assertNotIn("/opt/so-alert-relay/bin", authorized_key)
        for restriction in (
            "no-agent-forwarding",
            "no-X11-forwarding",
            "no-port-forwarding",
            "no-pty",
            "no-user-rc",
        ):
            self.assertIn(restriction, authorized_key)

    def test_pre_sudo_launcher_rejects_supplied_ssh_command(self):
        completed = subprocess.run(
            [str(RELAY_LAUNCHER)],
            env={**os.environ, "SSH_ORIGINAL_COMMAND": "id"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("commands are not accepted", completed.stderr)

    def test_response_newline_is_inside_four_mib_ceiling(self):
        for module in (load_relay_broker(), load_security_onion_wrapper()):
            with self.subTest(module=module.__name__):
                sink = SimpleNamespace(buffer=io.BytesIO())
                encoded = b"x" * (module.MAX_RESPONSE_BYTES - 1)
                with (
                    mock.patch.object(module.sys, "stdout", sink),
                    mock.patch.object(
                        module,
                        "bounded_json_bytes",
                        return_value=encoded,
                    ) as serializer,
                ):
                    self.assertEqual(module._emit({"ok": True}), 0)
                serializer.assert_called_once_with(
                    {"ok": True},
                    maximum=module.MAX_RESPONSE_BYTES - 1,
                )
                self.assertEqual(
                    len(sink.buffer.getvalue()),
                    module.MAX_RESPONSE_BYTES,
                )
                self.assertTrue(sink.buffer.getvalue().endswith(b"\n"))

    def test_security_onion_forced_key_uses_pre_sudo_launcher(self):
        authorized_key = SO_AUTHORIZED_KEY.read_text(encoding="utf-8")
        self.assertIn(
            'command="/usr/local/sbin/run-live-osquery-forced"',
            authorized_key,
        )
        self.assertNotIn('command="sudo ', authorized_key)
        for restriction in (
            "no-agent-forwarding",
            "no-X11-forwarding",
            "no-port-forwarding",
            "no-pty",
            "no-user-rc",
        ):
            self.assertIn(restriction, authorized_key)

        completed = subprocess.run(
            [str(SO_LAUNCHER)],
            env={**os.environ, "SSH_ORIGINAL_COMMAND": "id"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("commands are not accepted", completed.stderr)
        self.assertIn(
            "security-onion/bin/run-live-osquery-forced",
            SO_INSTALLER.read_text(encoding="utf-8"),
        )

    def test_relay_config_requires_root_service_group_mode_0640(self):
        broker = load_relay_broker()
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "live-osquery.json"
            path.write_text('{"enabled":true}', encoding="utf-8")
            secure = SimpleNamespace(
                st_uid=0,
                st_gid=4242,
                st_mode=stat.S_IFREG | 0o640,
                st_size=path.stat().st_size,
            )
            with (
                mock.patch.object(Path, "lstat", return_value=secure),
                mock.patch.object(broker.os, "getegid", return_value=4242),
            ):
                self.assertTrue(broker._load_config(path)["enabled"])

            wrong_mode = SimpleNamespace(
                **{**secure.__dict__, "st_mode": stat.S_IFREG | 0o600}
            )
            with (
                mock.patch.object(Path, "lstat", return_value=wrong_mode),
                mock.patch.object(broker.os, "getegid", return_value=4242),
                self.assertRaisesRegex(broker.BrokerError, "mode 0640"),
            ):
                broker._load_config(path)

    def test_installer_validates_dedicated_live_osquery_sudoers_rule(self):
        installer = RELAY_INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            'RELAY_ADMIN_USER="${ONION_SENTINEL_RELAY_ADMIN_USER:-${SUDO_USER:-}}"',
            installer,
        )
        self.assertIn(
            'sed "s/__RELAY_ADMIN_USER__/${RELAY_ADMIN_USER}/g"',
            installer,
        )
        self.assertIn(
            'install -o root -g root -m 0440 "$LIVE_OSQUERY_SUDOERS_TMP" '
            "/etc/sudoers.d/92-so-alert-relay-live-osquery",
            installer,
        )
        self.assertIn(
            "visudo -cf /etc/sudoers.d/92-so-alert-relay-live-osquery",
            installer,
        )

        sudoers = RELAY_SUDOERS.read_text(encoding="utf-8")
        self.assertIn("__RELAY_ADMIN_USER__ ALL=(soalert) NOPASSWD:", sudoers)
        self.assertNotIn("aj ALL=", sudoers)
        self.assertIn(
            "/usr/bin/python3 /opt/so-alert-relay/app/live_osquery_broker.py",
            sudoers,
        )
        self.assertIn(
            'install -o root -g root -m 0755 '
            '"$REPO_DIR/relay/bin/run-live-osquery-broker" '
            "/usr/local/sbin/run-live-osquery-broker",
            installer,
        )
        self.assertIn(
            "install -o soalert -g soalert -m 0700 -d /opt/so-alert-relay",
            installer,
        )


if __name__ == "__main__":
    unittest.main()
