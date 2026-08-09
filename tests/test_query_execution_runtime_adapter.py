#!/usr/bin/env python3
"""Characterization tests for governed query execution runtime binding."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.query import execution_runtime_adapter


class ContractError(ValueError):
    pass


class QueryExecutionRuntimeAdapterTests(unittest.TestCase):
    def test_controlled_evaluation_never_discovers_runtime_secret(self) -> None:
        bindings = {
            "os": os,
            "CONTROLLED_EVALUATION_MODE_ENV": "ONION_SENTINEL_CONTROLLED",
        }
        with mock.patch.dict(os.environ, {
            "ONION_SENTINEL_CONTROLLED": "1",
            "N8N_POST_COMMIT_TOKEN": "x" * 64,
        }, clear=True), mock.patch.object(
            Path, "home", side_effect=AssertionError("home must not be inspected")
        ):
            self.assertEqual(
                execution_runtime_adapter.runtime_env_value(
                    bindings, "N8N_POST_COMMIT_TOKEN"),
                "",
            )

    def test_enrichment_requires_role_and_long_runtime_token(self) -> None:
        package = {
            "investigation_query_capability": {
                "enabled": False,
                "backends": {"enrichment": {"enabled": False}},
            }
        }
        bindings = {
            "os": SimpleNamespace(environ={}),
            "_runtime_env_value": lambda _name: "t" * 32,
        }
        config = execution_runtime_adapter.prepare_enrichment_context(
            bindings, package, "incident-responder", "http://alerts/",
        )
        self.assertTrue(config["enabled"])
        self.assertEqual(config["token"], "t" * 32)
        self.assertEqual(config["alert_store_url"], "http://alerts")
        self.assertTrue(package["investigation_query_capability"]["enabled"])
        self.assertTrue(
            package["investigation_query_capability"]["backends"]
            ["enrichment"]["enabled"])

        untrusted = execution_runtime_adapter.prepare_enrichment_context(
            bindings, {}, "reporter", "http://alerts",
        )
        self.assertFalse(untrusted["enabled"])

    def test_security_onion_projection_is_deep_and_fails_closed(self) -> None:
        bindings = {
            "INVESTIGATION_SECURITY_ONION_AUTHORIZATION_CONTEXT_FIELDS":
                frozenset({"case_id", "permitted_observables"}),
            "INVESTIGATION_LOCAL_ONLY_AUTHORIZATION_CONTEXT_FIELDS":
                frozenset({"permitted_enrichment_indicators"}),
            "InvestigationQueryContractError": ContractError,
        }
        source = {
            "case_id": "case-1",
            "permitted_observables": {"ips": ["192.0.2.10"]},
            "permitted_enrichment_indicators": {"ip": ["192.0.2.10"]},
        }
        projected = execution_runtime_adapter.security_onion_authorization_context(
            bindings, source)
        self.assertEqual(set(projected), {"case_id", "permitted_observables"})
        projected["permitted_observables"]["ips"].append("198.51.100.20")
        self.assertEqual(source["permitted_observables"]["ips"], ["192.0.2.10"])
        with self.assertRaisesRegex(ContractError, "unsupported fields: secret"):
            execution_runtime_adapter.security_onion_authorization_context(
                bindings, {"secret": "must-not-cross-boundary"})

    def test_mixed_batch_preserves_backend_order_and_live_runner_seams(self) -> None:
        calls: list[tuple[str, list[str]]] = []

        class Module:
            Policy = lambda **values: SimpleNamespace(**values)
            Dependencies = lambda **values: SimpleNamespace(**values)

            @staticmethod
            def execute(requests, *, round_number, policy, dependencies):
                outcomes = (
                    dependencies.security_onion([requests[0]]),
                    dependencies.endpoint([requests[1]]),
                    dependencies.derived([requests[2]]),
                    dependencies.enrichment([requests[3]]),
                )
                return {
                    "schema": policy.result_schema,
                    "round": round_number,
                    "generated_at": dependencies.now(),
                    "outcomes": outcomes,
                }

        def transition(name):
            def invoke(selected, *_args):
                calls.append((name, [item["query_id"] for item in selected]))
                return name
            return invoke

        bindings = {
            "_query_execution_batch": lambda: Module,
            "INVESTIGATION_QUERY_RESULT_SCHEMA": "result-v1",
            "collect_security_onion_pivots": mock.Mock(),
            "collect_live_osquery": mock.Mock(),
            "query_derived_pcap_evidence": mock.Mock(),
            "collect_investigation_enrichment": mock.Mock(),
            "_execute_security_query_backend": transition("security_onion"),
            "_execute_endpoint_query_backend": transition("endpoint"),
            "_execute_derived_query_backend": transition("derived"),
            "_execute_enrichment_query_backend": transition("enrichment"),
            "project_now": lambda: "2026-08-09 12:00:00-06:00",
        }
        requests = [
            {"query_id": "elastic", "backend": "elastic"},
            {"query_id": "endpoint", "backend": "osquery"},
            {"query_id": "pcap", "backend": "pcap_zeek"},
            {"query_id": "intel", "backend": "enrichment"},
        ]
        result = execution_runtime_adapter.execute_batch(
            bindings, {"_local_investigation_query_context": {"case_id": "one"}},
            requests, round_number=2,
        )
        self.assertEqual(result["schema"], "result-v1")
        self.assertEqual(result["round"], 2)
        self.assertEqual(calls, [
            ("security_onion", ["elastic"]),
            ("endpoint", ["endpoint"]),
            ("derived", ["pcap"]),
            ("enrichment", ["intel"]),
        ])


if __name__ == "__main__":
    unittest.main()
