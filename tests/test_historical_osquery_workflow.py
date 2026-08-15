#!/usr/bin/env python3
"""ARR-25 contract tests for stored, read-only OSQuery evidence."""
from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from investigation_query_contract import (  # noqa: E402
    HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
    HISTORICAL_OSQUERY_SCHEMA_PROFILES,
    PACKS,
    InvestigationQueryContractError,
    authorize_investigation_query_request,
    compile_historical_osquery_schema_discovery,
    historical_osquery_field_caps_body,
    historical_osquery_field_caps_endpoint,
    result_coverage,
    validate_historical_osquery_schema_discovery,
    validate_investigation_query_response,
)
from tests.test_investigation_query_pivots import (  # noqa: E402
    controls_for,
    search_result_for,
)


WRAPPER_PATH = ROOT / "security-onion" / "bin" / "export-incident-evidence"
SO_INSTALLER = ROOT / "security-onion" / "bin" / "install-security-onion-wrapper.sh"


def load_wrapper():
    loader = importlib.machinery.SourceFileLoader(
        "historical_osquery_wrapper_test", str(WRAPPER_PATH)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def field_caps(*fields: str) -> dict:
    return {
        "fields": {
            field: {
                "keyword": {
                    "type": "keyword",
                    "searchable": True,
                    "aggregatable": True,
                }
            }
            for field in fields
        }
    }


def authorization_context() -> dict:
    return {
        "context_id": "history-context",
        "case_id": "history-case",
        "group_id": "history-group",
        "actor_role": "soc_analyst",
        "anchor": {
            "index": ".ds-logs-suricata.alerts-so-2026.07.24-000001",
            "id": "history-anchor",
        },
        "anchor_time": "2026-07-24T12:00:00.000Z",
        "time_envelope": {
            "start": "2026-07-24T10:00:00.000Z",
            "end": "2026-07-24T16:00:00.000Z",
        },
        "permitted_observables": {
            "ips": [],
            "domains": [],
            "hosts": ["endpoint-1"],
            "users": [],
        },
    }


def authorized_query() -> tuple[dict, dict]:
    request = authorize_investigation_query_request({
        "query_contract": "onion-sentinel-investigation-pivots-v2",
        "batch_id": "history-batch",
        "queries": [{
            "query_id": "history-query",
            "dialect": "elastic",
            "pack": "osquery_history",
            "purpose": "test_benign_hypothesis",
            "window": {
                "start": "2026-07-24T11:00:00.000Z",
                "end": "2026-07-24T13:00:00.000Z",
            },
            "observables": {
                "ips": [],
                "domains": [],
                "hosts": ["endpoint-1"],
                "users": [],
            },
            "size": 25,
            "aggregation": "timeline",
        }],
    }, authorization_context())
    return request, request["queries"][0]


class HistoricalOsquerySchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pack = PACKS["osquery_history"]
        self.observable_fields = ["host.name", "host.hostname", "agent.id"]

    def test_security_onion_installer_deploys_schema_discovery_owner(self) -> None:
        source = SO_INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            'install -o root -g root -m 0644 '
            '"$REPO_DIR/n8n/bin/historical_osquery_schema.py" '
            '/usr/local/lib/onion-sentinel/historical_osquery_schema.py',
            source,
        )

    def test_reviewed_profiles_cover_deployed_results_and_action_responses(self) -> None:
        self.assertEqual(
            HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
            "onion-sentinel-historical-osquery-schema-v1",
        )
        self.assertEqual(
            set(HISTORICAL_OSQUERY_SCHEMA_PROFILES),
            {
                "ecs-endpoint-events-v1",
                "elastic-osquery-manager-flat-v1",
                "elastic-osquery-manager-action-responses-v1",
            },
        )
        fields = set(self.pack["fields"])
        required = {
            "host.hostname",
            "agent.id",
            "agent.name",
            "osquery.hostname",
            "osquery.uuid",
            "osquery.name",
            "osquery.path",
            "osquery.pid",
            "osquery.parent",
            "osquery.bundle_identifier",
            "osquery.bundle_name",
            "osquery.bundle_short_version",
            "osquery.category",
            "action_id",
            "schedule_id",
            "pack_id",
            "pack_name",
            "query_name",
            "response_id",
            "started_at",
            "completed_at",
            "action_response.osquery.count",
        }
        self.assertTrue(required.issubset(fields), sorted(required - fields))
        self.assertFalse(any("*" in field for field in fields))
        self.assertNotIn("action_data.query", fields)
        self.assertNotIn("osquery.query", fields)
        self.assertNotIn("osquery.sql", fields)

    def test_field_caps_request_is_exact_and_read_only(self) -> None:
        endpoint = historical_osquery_field_caps_endpoint(self.pack["indices"])
        self.assertEqual(
            endpoint,
            ",".join(self.pack["indices"])
            + "/_field_caps?ignore_unavailable=true&expand_wildcards=open",
        )
        self.assertEqual(
            historical_osquery_field_caps_body(self.pack["fields"]),
            {"fields": self.pack["fields"]},
        )
        self.assertNotIn("_search", endpoint)
        self.assertNotIn("query", historical_osquery_field_caps_body(
            self.pack["fields"]
        ))

    def test_deployed_flat_mapping_is_compatible_and_digest_bound(self) -> None:
        raw = field_caps(
            "@timestamp",
            "event.dataset",
            "host.name",
            "agent.id",
            "osquery.name",
            "osquery.path",
            "osquery.bundle_identifier",
        )
        discovery = compile_historical_osquery_schema_discovery(
            raw,
            index_scope=self.pack["indices"],
            projection_fields=self.pack["fields"],
            observable_fields=self.observable_fields,
        )

        self.assertTrue(discovery["mapping_compatible"])
        self.assertEqual(
            discovery["compatible_profiles"],
            ["elastic-osquery-manager-flat-v1"],
        )
        self.assertEqual(discovery["mapped_identity_fields"], [
            "agent.id", "host.name",
        ])
        self.assertEqual(
            validate_historical_osquery_schema_discovery(
                discovery,
                index_scope=self.pack["indices"],
                projection_fields=self.pack["fields"],
                observable_fields=self.observable_fields,
            ),
            discovery,
        )
        tampered = copy.deepcopy(discovery)
        tampered["mapped_fields"].append("action_data.query")
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "schema discovery",
        ):
            validate_historical_osquery_schema_discovery(
                tampered,
                index_scope=self.pack["indices"],
                projection_fields=self.pack["fields"],
                observable_fields=self.observable_fields,
            )

    def test_mapping_drift_cannot_be_reported_as_a_trustworthy_zero(self) -> None:
        discovery = compile_historical_osquery_schema_discovery(
            field_caps("@timestamp", "event.dataset"),
            index_scope=self.pack["indices"],
            projection_fields=self.pack["fields"],
            observable_fields=self.observable_fields,
        )

        self.assertFalse(discovery["mapping_compatible"])
        self.assertEqual(discovery["compatible_profiles"], [])
        self.assertEqual(discovery["mapped_observable_fields"], [])


class HistoricalOsqueryExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = load_wrapper()

    def discovery(self) -> dict:
        pack = PACKS["osquery_history"]
        return compile_historical_osquery_schema_discovery(
            field_caps(
                "@timestamp", "event.dataset", "host.name", "agent.id",
                "osquery.name", "osquery.path",
            ),
            index_scope=pack["indices"],
            projection_fields=pack["fields"],
            observable_fields=[
                "host.id", "host.name", "host.hostname", "agent.id",
                "agent.name", "osquery.hostname", "osquery.uuid",
            ],
        )

    def test_soc_and_incident_responder_authorize_only_indexed_history(self) -> None:
        for actor_role in ("soc_analyst", "incident_responder"):
            context = authorization_context()
            context["actor_role"] = actor_role
            with self.subTest(actor_role=actor_role):
                request = authorize_investigation_query_request({
                    "query_contract": "onion-sentinel-investigation-pivots-v2",
                    "batch_id": f"history-{actor_role}",
                    "queries": [{
                        "query_id": "history-query",
                        "dialect": "elastic",
                        "pack": "osquery_history",
                        "purpose": "correlate_observable",
                        "window": {
                            "start": "2026-07-24T11:00:00.000Z",
                            "end": "2026-07-24T13:00:00.000Z",
                        },
                        "observables": context["permitted_observables"],
                        "size": 25,
                        "aggregation": "timeline",
                    }],
                }, context)
                self.assertEqual(request["queries"][0]["pack"], "osquery_history")
                self.assertNotIn("target", request["queries"][0])
                self.assertNotIn("sql", request["queries"][0])

    def test_mapping_timeout_prevents_the_historical_search(self) -> None:
        _request, query = authorized_query()
        timeout = self.wrapper.BoundedCommandError(
            "timeout", "field caps timed out"
        )
        with (
            mock.patch.object(
                self.wrapper, "run_bounded_command", side_effect=timeout
            ),
            mock.patch.object(self.wrapper, "execute_search") as search,
        ):
            result = self.wrapper.execute_pivot_query(query)

        search.assert_not_called()
        self.assertEqual(result["status"], "timeout")
        self.assertFalse(result["semantic_valid"])
        self.assertFalse(result["schema_discovery"]["mapping_compatible"])
        self.assertEqual(
            result["result_coverage"]["interpretation"],
            "query_execution_incomplete",
        )

    def test_malformed_mapping_response_prevents_the_historical_search(self) -> None:
        _request, query = authorized_query()
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"{}", stderr=b""
        )
        with (
            mock.patch.object(
                self.wrapper, "run_bounded_command", return_value=completed
            ),
            mock.patch.object(self.wrapper, "execute_search") as search,
        ):
            result = self.wrapper.execute_pivot_query(query)

        search.assert_not_called()
        self.assertEqual(result["status"], "invalid_response")
        self.assertEqual(
            result["schema_discovery"]["status"], "invalid_response"
        )
        self.assertFalse(result["result_coverage"]["zero_hits"])

    def test_compatible_zero_is_distinct_from_mapping_failure(self) -> None:
        request, query = authorized_query()
        discovery = self.discovery()
        search = search_result_for(query, hit=False)
        response = {
            "ok": True,
            "complete": True,
            "partial": False,
            "read_only": True,
            "query_contract": request["query_contract"],
            "batch_id": request["batch_id"],
            "request_digest": self.wrapper.canonical_digest(request),
            "generated_at": "2026-07-24T12:01:00Z",
            "results": [{**search, "schema_discovery": discovery}],
            "controls": controls_for(request["authorization"]["anchor"]),
            "semantic_validity": {
                "transport_valid": True,
                "controls_valid": True,
                "query_execution_valid": True,
                "coverage_valid": True,
                "semantic_valid": True,
                "reasons": [],
            },
        }

        validated = validate_investigation_query_response(response, request)

        self.assertTrue(validated["results"][0]["result_coverage"]["zero_hits"])
        tampered = copy.deepcopy(response)
        tampered["results"][0]["schema_discovery"][
            "mapping_compatible"
        ] = False
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "schema discovery",
        ):
            validate_investigation_query_response(tampered, request)

    def test_compatible_truncated_result_remains_a_bounded_sample(self) -> None:
        request, query = authorized_query()
        discovery = self.discovery()
        search = search_result_for(query, hit=False)
        search["hits"] = [{
            "id": "history-hit-1",
            "index": ".ds-logs-osquery_manager.result-default-2026.07.24-000001",
            "source": {
                "@timestamp": "2026-07-24T12:00:00.000Z",
                "event": {"dataset": "osquery_manager.result"},
                "host": {"name": "endpoint-1"},
                "osquery": {"name": "browser"},
            },
        }]
        search.update({
            "total_hits": 2,
            "returned_hits": 1,
            "truncated": True,
            "result_coverage": result_coverage(
                query,
                status="ok",
                total_hits=2,
                total_hits_relation="eq",
                returned_hits=1,
            ),
            "schema_discovery": discovery,
        })
        response = {
            "ok": True,
            "complete": True,
            "partial": False,
            "read_only": True,
            "query_contract": request["query_contract"],
            "batch_id": request["batch_id"],
            "request_digest": self.wrapper.canonical_digest(request),
            "generated_at": "2026-07-24T12:01:00Z",
            "results": [search],
            "controls": controls_for(request["authorization"]["anchor"]),
            "semantic_validity": {
                "transport_valid": True,
                "controls_valid": True,
                "query_execution_valid": True,
                "coverage_valid": True,
                "semantic_valid": True,
                "reasons": [],
            },
        }

        validated = validate_investigation_query_response(response, request)

        coverage = validated["results"][0]["result_coverage"]
        self.assertEqual(coverage["coverage_status"], "bounded_sample")
        self.assertFalse(coverage["zero_hits"])

    def test_flat_result_is_preserved_but_unreviewed_query_text_is_rejected(self) -> None:
        _request, query = authorized_query()
        source = {
            "@timestamp": "2026-07-24T12:00:00.000Z",
            "event": {"dataset": "osquery_manager.result"},
            "host": {"name": "endpoint-1"},
            "osquery": {"name": "browser", "path": "/Applications/browser"},
        }
        self.assertTrue(self.wrapper.valid_pivot_hit_source(source, query))
        poisoned = copy.deepcopy(source)
        poisoned["action_data"] = {"query": "SELECT * FROM users"}
        self.assertFalse(self.wrapper.valid_pivot_hit_source(poisoned, query))

    def test_discovery_submits_only_the_fixed_field_caps_body(self) -> None:
        payload = field_caps(
            "@timestamp", "event.dataset", "host.name", "osquery.name"
        )
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(payload).encode(), stderr=b""
        )
        with mock.patch.object(
            self.wrapper, "run_bounded_command", return_value=completed
        ) as run:
            discovery = self.wrapper.discover_historical_osquery_schema({
                "ips": [], "domains": [], "hosts": ["endpoint-1"],
                "users": [],
            })

        command = run.call_args.args[0]
        self.assertEqual(
            command[1],
            historical_osquery_field_caps_endpoint(
                PACKS["osquery_history"]["indices"]
            ),
        )
        self.assertEqual(
            json.loads(command[3]),
            historical_osquery_field_caps_body(
                PACKS["osquery_history"]["fields"]
            ),
        )
        self.assertNotIn("query", json.loads(command[3]))
        self.assertTrue(discovery["mapping_compatible"])


if __name__ == "__main__":
    unittest.main()
