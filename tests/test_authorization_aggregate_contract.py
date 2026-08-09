#!/usr/bin/env python3
"""Focused end-to-end contracts for count-only authorization evidence."""
from __future__ import annotations

import copy
import contextlib
import importlib
import importlib.machinery
import importlib.util
import json
import io
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
RELAY_APP_DIR = ROOT / "relay" / "app"
WRAPPER_PATH = ROOT / "security-onion" / "bin" / "export-incident-evidence"
COLLECTOR_PATH = BIN_DIR / "collect-incident-evidence.py"
BROKER_PATH = RELAY_APP_DIR / "incident_evidence_broker.py"
for directory in (BIN_DIR, RELAY_APP_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import authorization_aggregate_contract as contract  # noqa: E402
import incident_evidence_contract as incident_contract  # noqa: E402


SAMPLE_ALERT_INDEX = ".ds-logs-suricata.alerts-so-2026.07.22-000001"
SAMPLE_ALERT_DOCUMENT_ID = "elastic-anchor-unit"
SAMPLE_ALERT_ID = f"{SAMPLE_ALERT_INDEX}:{SAMPLE_ALERT_DOCUMENT_ID}"
SAMPLE_ANCHOR = {
    "index": SAMPLE_ALERT_INDEX,
    "id": SAMPLE_ALERT_DOCUMENT_ID,
}


def load_source_module(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def sample_request(selected_alert_id: str = SAMPLE_ALERT_ID) -> dict:
    return contract.build_authorization_aggregate_request(
        selected_alert_id=selected_alert_id,
        campaign_id="campaign-0123456789abcdef0123",
        policy_id="authorized-tls-unit",
        membership_observed_at="2026-07-31T23:10:00Z",
        campaign_window={
            "start": "2026-07-31T23:00:00Z",
            "end": "2026-07-31T23:15:00Z",
        },
        authorization_window={
            "start": "2026-07-31T22:15:00Z",
            "end": "2026-08-03T05:59:59Z",
        },
        selectors={
            "source_ips": [],
            "destination_ips": ["10.77.7.222"],
            "rule_ids": ["2029340"],
            "source_ports": [8443, 443],
            "destination_ports": [],
            "destination_port_ranges": [[49152, 65535]],
            "transport_protocols": ["TCP"],
        },
    )


def search_result(request: dict, partition: dict, count: int) -> dict:
    query_dsl = contract.build_authorization_aggregate_query_dsl(
        request, partition
    )
    return {
        "query_digest": contract.canonical_digest(query_dsl),
        "execution_digest": contract.authorization_aggregate_execution_digest(
            query_dsl
        ),
        "query_dsl": query_dsl,
        "index_scope": contract.AUTHORIZATION_AGGREGATE_INDEX_SCOPE,
        "query_endpoint": contract.authorization_aggregate_query_endpoint(),
        "status": "ok",
        "semantic_valid": True,
        "total_hits": count,
        "total_hits_relation": "eq",
        "returned_hits": 0,
        "truncated": False,
        "duration_ms": 5,
        "timed_out": False,
        "took_ms": 3,
        "shards": {
            "total": 2,
            "successful": 2,
            "skipped": 0,
            "failed": 0,
            "failures": [],
        },
        "hits": [],
        "source_port_buckets": (
            [
                {"source_port": 443, "exact_count": count - 1},
                {"source_port": 8443, "exact_count": 1},
            ]
            if count > 1
            else ([{"source_port": 443, "exact_count": 1}] if count else [])
        ),
    }


def complete_response(request: dict, counts: list[int] | None = None) -> dict:
    counts = counts or list(range(1, len(request["partitions"]) + 1))
    results = [
        contract.bind_authorization_aggregate_partition_result(
            request,
            partition,
            search_result(request, partition, count),
        )
        for partition, count in zip(request["partitions"], counts)
    ]
    return contract.build_authorization_aggregate_response(request, results)


def query_clause_matches(clause: dict, document: dict[str, object]) -> bool:
    if "term" in clause:
        field, expected = next(iter(clause["term"].items()))
        return document.get(field) == expected
    if "terms" in clause:
        field, expected = next(iter(clause["terms"].items()))
        return document.get(field) in expected
    if "exists" in clause:
        return clause["exists"]["field"] in document
    boolean = clause.get("bool")
    if not isinstance(boolean, dict):
        raise AssertionError(f"unsupported test query clause: {clause}")
    filters = boolean.get("filter", [])
    must_not = boolean.get("must_not", [])
    should = boolean.get("should", [])
    return (
        all(query_clause_matches(item, document) for item in filters)
        and not any(query_clause_matches(item, document) for item in must_not)
        and (
            not should
            or sum(query_clause_matches(item, document) for item in should)
            >= int(boolean.get("minimum_should_match", 1))
        )
    )


class AuthorizationAggregateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = load_source_module("authorization_aggregate_wrapper_test", WRAPPER_PATH)
        cls.collector = load_source_module("authorization_aggregate_collector_test", COLLECTOR_PATH)
        cls.broker = load_source_module("authorization_aggregate_broker_test", BROKER_PATH)

    def test_policy_window_is_partitioned_at_utc_days_and_full_selectors_are_anded(self) -> None:
        request = sample_request()

        self.assertEqual(len(request["partitions"]), 4)
        self.assertEqual(
            request["partitions"][0]["window"]["end"],
            "2026-08-01T00:00:00.000Z",
        )
        self.assertFalse(request["partitions"][0]["end_inclusive"])
        self.assertTrue(request["partitions"][-1]["end_inclusive"])

        first = contract.build_authorization_aggregate_query_dsl(
            request, request["partitions"][0]
        )
        last = contract.build_authorization_aggregate_query_dsl(
            request, request["partitions"][-1]
        )
        self.assertEqual(first["size"], 0)
        self.assertFalse(first["_source"])
        self.assertNotIn(
            "ignore_unavailable",
            contract.authorization_aggregate_query_endpoint(),
        )
        self.assertEqual(
            first["aggs"],
            {
                "by_source_port": {
                    "terms": {
                        "field": "source.port",
                        "size": 2,
                        "min_doc_count": 1,
                        "order": {"_key": "asc"},
                    }
                }
            },
        )
        self.assertIn('"lt":"2026-08-01T00:00:00.000Z"', json.dumps(first, separators=(",", ":")))
        self.assertIn('"lte":"2026-08-03T05:59:59.000Z"', json.dumps(last, separators=(",", ":")))
        rendered = json.dumps(first, separators=(",", ":"), sort_keys=True)
        for expected in (
            '"destination.ip":"10.77.7.222"',
            '"rule.id":"2029340"',
            '"rule.uuid":"2029340"',
            '"source.port":[443,8443]',
            '"destination.port":{"gte":49152,"lte":65535}',
            '"network.transport":"tcp"',
            '"network.protocol":"tcp"',
        ):
            self.assertIn(expected, rendered)

        filters = first["query"]["bool"]["filter"]
        rule_clause = filters[2]
        transport_clause = filters[-1]
        self.assertTrue(query_clause_matches(
            rule_clause,
            {"rule.uuid": "2029340", "rule.id": "conflict"},
        ))
        self.assertTrue(query_clause_matches(
            rule_clause,
            {"rule.id": "2029340"},
        ))
        self.assertFalse(query_clause_matches(
            rule_clause,
            {"rule.uuid": "conflict", "rule.id": "2029340"},
        ))
        self.assertTrue(query_clause_matches(
            transport_clause,
            {"network.transport": "tcp", "network.protocol": "udp"},
        ))
        self.assertTrue(query_clause_matches(
            transport_clause,
            {"network.protocol": "tcp"},
        ))
        self.assertFalse(query_clause_matches(
            transport_clause,
            {"network.transport": "udp", "network.protocol": "tcp"},
        ))

    def test_complete_response_merges_exact_counts_without_event_bodies(self) -> None:
        request = sample_request()
        response = complete_response(request, [11, 17, 5, 2])

        validated = contract.validate_authorization_aggregate_response(
            response, request
        )
        self.assertIs(validated, response)
        self.assertEqual(response["merged"]["exact_count"], 35)
        self.assertEqual(
            response["merged"]["source_port_buckets"],
            [
                {"source_port": 443, "exact_count": 31},
                {"source_port": 8443, "exact_count": 4},
            ],
        )
        self.assertEqual(response["event_bodies_returned"], 0)
        self.assertTrue(response["complete"])
        self.assertTrue(all(item["hits"] == [] for item in response["partitions"]))
        tampered = copy.deepcopy(response)
        tampered["merged"]["exact_count"] = 36
        with self.assertRaises(contract.AuthorizationAggregateContractError):
            contract.validate_authorization_aggregate_response(tampered, request)
        tampered_bucket = copy.deepcopy(response)
        first = tampered_bucket["partitions"][0]
        first["source_port_buckets"][0]["exact_count"] += 1
        first["result_digest"] = contract.canonical_digest(
            {key: value for key, value in first.items() if key != "result_digest"}
        )
        with self.assertRaisesRegex(
            contract.AuthorizationAggregateContractError,
            "do not sum",
        ):
            contract.validate_authorization_aggregate_response(
                tampered_bucket, request
            )

    def test_wrapper_executes_only_count_queries_and_binds_each_partition(self) -> None:
        request = sample_request()

        def execute(query_dsl, index_scope):
            self.assertEqual(query_dsl["size"], 0)
            self.assertFalse(query_dsl["_source"])
            self.assertEqual(index_scope, contract.AUTHORIZATION_AGGREGATE_INDEX_SCOPE)
            partition = next(
                item
                for item in request["partitions"]
                if contract.build_authorization_aggregate_query_dsl(request, item)
                == query_dsl
            )
            return search_result(request, partition, partition["partition_index"] + 1)

        with mock.patch.object(self.wrapper, "execute_search", side_effect=execute) as called:
            response = self.wrapper.execute_authorization_aggregate(request)

        self.assertEqual(called.call_count, len(request["partitions"]))
        self.assertEqual(response["merged"]["exact_count"], 10)
        contract.validate_authorization_aggregate_response(response, request)

    def test_wrapper_binds_aggregate_identity_to_collector_anchor(self) -> None:
        request = {
            "packs": ["alert_context"],
            "osquery_packs": ["system_inventory"],
            "windows": [{
                "start": "2026-07-31T23:00:00.000Z",
                "end": "2026-07-31T23:15:00.000Z",
            }],
            "observables": {
                "ips": ["10.77.7.222"],
                "domains": [],
                "hosts": [],
                "users": [],
            },
            "size": 25,
            "anchor": SAMPLE_ANCHOR,
            "authorization_aggregate": sample_request(),
        }
        validated = self.wrapper.validated_request(request)
        self.assertEqual(
            validated[-1]["selected_alert_id"], SAMPLE_ALERT_ID
        )

        swapped = copy.deepcopy(request)
        swapped["authorization_aggregate"] = sample_request(
            f"{SAMPLE_ALERT_INDEX}:different-alert"
        )
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.wrapper.validated_request(swapped)

    def test_wrapper_parses_exact_443_and_8443_terms_buckets(self) -> None:
        request = sample_request()
        partition = request["partitions"][0]
        query_dsl = contract.build_authorization_aggregate_query_dsl(
            request, partition
        )
        elastic = {
            "took": 4,
            "timed_out": False,
            "_shards": {
                "total": 2,
                "successful": 2,
                "skipped": 0,
                "failed": 0,
                "failures": [],
            },
            "hits": {
                "total": {"value": 49, "relation": "eq"},
                "hits": [],
            },
            "aggregations": {
                "by_source_port": {
                    "doc_count_error_upper_bound": 0,
                    "sum_other_doc_count": 0,
                    "buckets": [
                        {"key": 443, "doc_count": 48},
                        {"key": 8443, "doc_count": 1},
                    ],
                }
            },
        }
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(elastic).encode("utf-8"),
            stderr=b"",
        )
        with mock.patch.object(
            self.wrapper, "run_bounded_command", return_value=completed
        ) as run:
            result = self.wrapper.execute_search(
                query_dsl, contract.AUTHORIZATION_AGGREGATE_INDEX_SCOPE
            )

        self.assertEqual(
            run.call_args.args[0][1],
            contract.authorization_aggregate_query_endpoint(),
        )
        self.assertNotIn("ignore_unavailable", run.call_args.args[0][1])
        self.assertEqual(
            result["source_port_buckets"],
            [
                {"source_port": 443, "exact_count": 48},
                {"source_port": 8443, "exact_count": 1},
            ],
        )
        self.assertEqual(sum(
            item["exact_count"] for item in result["source_port_buckets"]
        ), result["total_hits"])

        inexact = copy.deepcopy(elastic)
        inexact["aggregations"]["by_source_port"][
            "sum_other_doc_count"
        ] = 1
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(inexact).encode("utf-8"),
            stderr=b"",
        )
        with mock.patch.object(
            self.wrapper, "run_bounded_command", return_value=completed
        ):
            rejected = self.wrapper.execute_search(
                query_dsl, contract.AUTHORIZATION_AGGREGATE_INDEX_SCOPE
            )
        self.assertEqual(rejected["status"], "invalid_response")

    def test_collector_builds_only_from_selected_campaign_membership_and_stored_policy(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE authorized_activity_campaigns (
              campaign_id TEXT, policy_id TEXT, bucket_start TEXT,
              bucket_end TEXT, authorization_json TEXT
            );
            CREATE TABLE authorized_activity_campaign_members (
              campaign_id TEXT, alert_id TEXT, observed_at TEXT
            );
            """
        )
        policy = {
            "status": "operator_authorized",
            "policy_id": "authorized-tls-unit",
            "source_ips": [],
            "destination_ips": ["10.77.7.222"],
            "rule_ids": ["2029340"],
            "source_ports": [443, 8443],
            "destination_ports": [],
            "destination_port_ranges": [[49152, 65535]],
            "transport_protocols": ["tcp"],
            "authorization_start": "2026-07-31T22:15:00Z",
            "authorization_end": "2026-08-03T05:59:59Z",
        }
        conn.execute(
            "INSERT INTO authorized_activity_campaigns VALUES (?, ?, ?, ?, ?)",
            (
                "campaign-0123456789abcdef0123",
                "authorized-tls-unit",
                "2026-07-31T23:00:00Z",
                "2026-07-31T23:15:00Z",
                json.dumps(policy),
            ),
        )
        conn.execute(
            "INSERT INTO authorized_activity_campaign_members VALUES (?, ?, ?)",
            (
                "campaign-0123456789abcdef0123",
                SAMPLE_ALERT_ID,
                "2026-07-31T23:10:00Z",
            ),
        )

        request = self.collector.selected_authorization_aggregate_request(
            conn, {"alert_id": SAMPLE_ALERT_ID}, SAMPLE_ANCHOR
        )
        self.assertEqual(request["source"], contract.AUTHORIZATION_AGGREGATE_SOURCE)
        self.assertEqual(request["selectors"]["source_ports"], [443, 8443])
        with self.assertRaisesRegex(RuntimeError, "collector-owned alert anchor"):
            self.collector.selected_authorization_aggregate_request(
                conn,
                {"alert_id": SAMPLE_ALERT_ID},
                {"index": SAMPLE_ALERT_INDEX, "id": "different-alert"},
            )
        self.assertIsNone(
            self.collector.selected_authorization_aggregate_request(
                conn, {"alert_id": "not-a-member"}, SAMPLE_ANCHOR
            )
        )
        policy["source_ports"] = []
        conn.execute(
            "UPDATE authorized_activity_campaigns SET authorization_json = ?",
            (json.dumps(policy),),
        )
        self.assertIsNone(
            self.collector.selected_authorization_aggregate_request(
                conn, {"alert_id": SAMPLE_ALERT_ID}, SAMPLE_ANCHOR
            )
        )
        conn.close()

    def test_relay_rejects_request_or_response_provenance_drift(self) -> None:
        request = {
            "anchor": SAMPLE_ANCHOR,
            "authorization_aggregate": sample_request(),
        }
        response = {"authorization_aggregate": complete_response(request["authorization_aggregate"])}

        self.broker.validate_incident_authorization_aggregate_request(request)
        self.broker.validate_incident_authorization_aggregate_response(
            response, request
        )
        changed_request = copy.deepcopy(request)
        changed_request["authorization_aggregate"]["selectors"]["source_ports"] = [443]
        with self.assertRaises(contract.AuthorizationAggregateContractError):
            self.broker.validate_incident_authorization_aggregate_request(
                changed_request
            )
        swapped_anchor = copy.deepcopy(request)
        swapped_anchor["anchor"]["id"] = "different-alert"
        with self.assertRaisesRegex(
            contract.AuthorizationAggregateContractError,
            "does not match request anchor",
        ):
            self.broker.validate_incident_authorization_aggregate_request(
                swapped_anchor
            )
        changed_response = copy.deepcopy(response)
        changed_response["authorization_aggregate"]["partitions"][0]["shards"][
            "successful"
        ] = 1
        with self.assertRaises(contract.AuthorizationAggregateContractError):
            self.broker.validate_incident_authorization_aggregate_response(
                changed_response, request
            )

    def test_incident_artifact_contract_binds_optional_aggregate_end_to_end(self) -> None:
        fixture_module = importlib.import_module(
            "tests.test_incident_evidence_contract"
        )
        artifact = fixture_module.evidence_artifact()
        request = sample_request()
        response = complete_response(request)
        artifact["alert_id"] = SAMPLE_ALERT_ID
        artifact["request"]["authorization_aggregate"] = request
        artifact["security_onion_response"]["authorization_aggregate"] = response
        artifact["security_onion_response"]["semantic_validity"][
            "authorization_aggregate_valid"
        ] = True

        validated = incident_contract.validate_incident_evidence_artifact(
            artifact
        )
        self.assertIs(validated, artifact)
        tampered = copy.deepcopy(artifact)
        tampered["security_onion_response"]["authorization_aggregate"][
            "partitions"
        ][0]["query_digest"] = "0" * 64
        with self.assertRaises(incident_contract.IncidentEvidenceContractError):
            incident_contract.validate_incident_evidence_artifact(tampered)

        transplanted = copy.deepcopy(artifact)
        transplanted["alert_id"] = f"{SAMPLE_ALERT_INDEX}:different-alert"
        with self.assertRaisesRegex(
            incident_contract.IncidentEvidenceContractError,
            "selected alert identity",
        ):
            incident_contract.validate_incident_evidence_artifact(transplanted)

        swapped_request = sample_request(
            f"{SAMPLE_ALERT_INDEX}:different-alert"
        )
        swapped = copy.deepcopy(artifact)
        swapped["request"]["authorization_aggregate"] = swapped_request
        swapped["security_onion_response"][
            "authorization_aggregate"
        ] = complete_response(swapped_request)
        with self.assertRaisesRegex(
            incident_contract.IncidentEvidenceContractError,
            "selected alert identity",
        ):
            incident_contract.validate_incident_evidence_artifact(swapped)

    def test_incomplete_shard_coverage_never_claims_a_merged_exact_count(self) -> None:
        request = sample_request()
        results = []
        for partition in request["partitions"]:
            item = search_result(request, partition, 3)
            if partition["partition_index"] == 1:
                item.update(
                    {
                        "status": "error",
                        "semantic_valid": False,
                        "total_hits": 0,
                        "source_port_buckets": [],
                        "shards": {
                            "total": 2,
                            "successful": 1,
                            "skipped": 0,
                            "failed": 1,
                            "failures": [
                                {
                                    "index": "unit",
                                    "type": "synthetic_failure",
                                    "reason": "failure",
                                }
                            ],
                        },
                    }
                )
            results.append(
                contract.bind_authorization_aggregate_partition_result(
                    request, partition, item
                )
            )
        response = contract.build_authorization_aggregate_response(request, results)

        self.assertFalse(response["complete"])
        self.assertIsNone(response["merged"]["exact_count"])
        self.assertIsNone(response["merged"]["buckets"][1]["exact_count"])
        contract.validate_authorization_aggregate_response(response, request)

    def test_installers_deploy_shared_contract_to_all_three_hosts(self) -> None:
        mac = (BIN_DIR / "install-macstudio-stack.zsh").read_text(encoding="utf-8")
        relay = (ROOT / "relay" / "bin" / "install-pi-relay.sh").read_text(encoding="utf-8")
        security_onion = (
            ROOT / "security-onion" / "bin" / "install-security-onion-wrapper.sh"
        ).read_text(encoding="utf-8")
        for source in (mac, relay, security_onion):
            self.assertIn("authorization_aggregate_contract.py", source)

    def test_prompt_preserves_and_explains_count_only_aggregate(self) -> None:
        builder = (BIN_DIR / "build-ai-investigation-prompt.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"authorization_aggregate": response.get("authorization_aggregate")',
            builder,
        )
        self.assertIn(
            "Use only complete merged exact_count and bucket counts",
            builder,
        )
        self.assertIn("no event bodies were returned", builder)


if __name__ == "__main__":
    unittest.main()
