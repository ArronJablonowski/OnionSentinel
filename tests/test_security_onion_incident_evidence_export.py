#!/usr/bin/env python3
"""Regression tests for fail-closed Security Onion incident evidence queries."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
WRAPPER_PATH = REPO_ROOT / "security-onion" / "bin" / "export-incident-evidence"
BIN_DIR = REPO_ROOT / "n8n" / "bin"
COLLECTOR_PATH = BIN_DIR / "collect-incident-evidence.py"


def load_source_module(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def completed_response(payload: dict, *, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
    )


def es_response(
    *,
    hits: list[dict] | None = None,
    total: int | None = None,
    failed_shards: int = 0,
    timed_out: bool = False,
    total_shards: int = 2,
) -> dict:
    hits = list(hits or [])
    return {
        "took": 5,
        "timed_out": timed_out,
        "_shards": {
            "total": total_shards,
            "successful": max(0, total_shards - failed_shards),
            "skipped": 0,
            "failed": failed_shards,
            "failures": (
                [{
                    "index": ".ds-logs-suricata.alerts-so-unit",
                    "reason": {
                        "type": "illegal_argument_exception",
                        "reason": "synthetic shard failure",
                    },
                }]
                if failed_shards
                else []
            ),
        },
        "hits": {
            "total": {"value": len(hits) if total is None else total, "relation": "eq"},
            "hits": hits,
        },
    }


class SecurityOnionIncidentEvidenceExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = load_source_module("incident_evidence_export_test", WRAPPER_PATH)
        if str(BIN_DIR) not in sys.path:
            sys.path.insert(0, str(BIN_DIR))
        cls.collector = load_source_module("incident_evidence_collector_test", COLLECTOR_PATH)
        cls.window = {
            "start": "2026-07-22T18:00:00.000Z",
            "end": "2026-07-22T19:00:00.000Z",
        }
        cls.observables = {
            "ips": ["192.0.2.10"],
            "domains": [],
            "hosts": [],
            "users": [],
        }

    def test_pack_uses_reviewed_indices_and_shard_doc_sort(self) -> None:
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            return_value=completed_response(es_response()),
        ) as run:
            result = self.wrapper.execute_pack(
                "network_flow",
                self.window,
                self.observables,
                25,
            )

        command = run.call_args.args[0]
        submitted = json.loads(command[3])
        self.assertEqual(command[1], self.wrapper.query_endpoint(
            self.wrapper.PACKS["network_flow"]["indices"]
        ))
        self.assertNotEqual(command[1], "/_search")
        self.assertEqual(
            submitted["sort"],
            [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}, "_shard_doc"],
        )
        self.assertTrue(result["semantic_valid"])
        self.assertEqual(result["index_scope"], self.wrapper.PACKS["network_flow"]["indices"])

    def test_failed_shards_are_an_explicit_query_failure(self) -> None:
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            return_value=completed_response(es_response(failed_shards=1)),
        ):
            result = self.wrapper.execute_pack(
                "alert_context",
                self.window,
                self.observables,
                25,
            )

        self.assertEqual(result["status"], "error")
        self.assertFalse(result["semantic_valid"])
        self.assertEqual(result["shards"]["failed"], 1)
        self.assertEqual(result["hits"], [])

    def test_root_error_is_not_misread_as_a_zero_hit_success(self) -> None:
        root_error = {
            "error": {
                "type": "search_phase_execution_exception",
                "reason": "synthetic all shards failed",
            },
            "status": 400,
        }
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            return_value=completed_response(root_error),
        ):
            result = self.wrapper.execute_pack(
                "alert_context",
                self.window,
                self.observables,
                25,
            )

        self.assertEqual(result["status"], "error")
        self.assertFalse(result["semantic_valid"])
        self.assertIn("search_phase_execution_exception", result["error"])

    def test_zero_shards_are_not_misread_as_a_valid_empty_result(self) -> None:
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            return_value=completed_response(es_response(total_shards=0)),
        ):
            result = self.wrapper.execute_pack(
                "dns_activity",
                self.window,
                self.observables,
                25,
            )

        self.assertEqual(result["status"], "invalid_response")
        self.assertFalse(result["semantic_valid"])
        self.assertIn("no searchable shards", result["error"])

    def test_out_of_scope_hit_index_invalidates_the_response(self) -> None:
        hit = {
            "_id": "unit-hit",
            "_index": ".ds-logs-unreviewed.secret-default-2026.07.22-000001",
            "_source": {"@timestamp": "2026-07-22T18:30:00Z"},
        }
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            return_value=completed_response(es_response(hits=[hit])),
        ):
            result = self.wrapper.execute_pack(
                "alert_context",
                self.window,
                self.observables,
                25,
            )

        self.assertEqual(result["status"], "invalid_response")
        self.assertFalse(result["semantic_valid"])
        self.assertIn("out-of-scope", result["error"])

    def test_missing_anchor_forces_partial_semantic_validity(self) -> None:
        controls = self.wrapper.execute_controls(None)
        validity = self.wrapper.semantic_validity(
            [{"status": "ok", "semantic_valid": True}],
            [{"status": "ok"}],
            controls,
        )

        self.assertFalse(validity["controls_valid"])
        self.assertFalse(validity["semantic_valid"])
        self.assertFalse(controls["positive_anchor"]["passed"])

    def test_positive_and_negative_controls_must_both_pass(self) -> None:
        anchor = {
            "index": ".ds-logs-suricata.alerts-so-2026.07.22-000001",
            "id": "elastic-anchor-unit",
        }
        positive_hit = {
            "_id": anchor["id"],
            "_index": anchor["index"],
            "_source": {
                "@timestamp": "2026-07-22T18:30:00Z",
                "event": {"dataset": "suricata.alert"},
            },
        }
        with mock.patch.object(
            self.wrapper,
            "run_bounded_command",
            side_effect=[
                completed_response(es_response(hits=[positive_hit])),
                completed_response(es_response()),
            ],
        ):
            controls = self.wrapper.execute_controls(anchor)

        self.assertTrue(controls["positive_anchor"]["passed"])
        self.assertTrue(controls["negative_filter"]["passed"])

    def test_collector_recovers_wrapper_owned_elasticsearch_anchor(self) -> None:
        row = {
            "alert_id": ".ds-logs-suricata.alerts-so-2026.07.22-000001:fallback-id",
            "alert_json": json.dumps({
                "elastic_index": ".ds-logs-suricata.alerts-so-2026.07.22-000001",
                "elastic_id": "preferred-id",
                "message": "attacker-controlled text is irrelevant",
            }),
        }

        anchor = self.collector.representative_alert_anchor(row)

        self.assertEqual(anchor, {
            "index": ".ds-logs-suricata.alerts-so-2026.07.22-000001",
            "id": "preferred-id",
        })

    def test_collector_observables_exclude_enrichment_and_sensor_metadata(self) -> None:
        row = {
            "alert_id": (
                ".ds-logs-suricata.alerts-so-2026.07.22-000001:"
                "source-event"
            ),
            "event_dataset": "suricata.alert",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "alert_json": json.dumps({
                "event": {"dataset": "suricata.alert"},
                "source": {"ip": "192.0.2.10"},
                "destination": {"ip": "198.51.100.20"},
                "tls": {"server": {"name": "observed.example"}},
                "host": {
                    "ip": ["172.17.1.1"],
                    "name": "security-onion-sensor",
                },
                "enrichment": {
                    "external_intel": {
                        "records": [{
                            "raw_response": {
                                "ip": "203.0.113.200",
                                "domain": "provider-result.example",
                                "username": "intel-author",
                            },
                        }],
                    },
                },
            }),
            "raw_event_json": json.dumps({
                "metadata": {
                    "input": {
                        "beats": {
                            "host": {"ip": "192.168.1.7"},
                        },
                    },
                },
                "event_data": {
                    "event": {"dataset": "suricata.alert"},
                    "dns": {
                        "question": {"name": "wire-observed.example"},
                    },
                },
            }),
        }

        result = self.collector.observables([row])

        self.assertEqual(
            result["ips"],
            ["192.0.2.10", "198.51.100.20"],
        )
        self.assertEqual(
            result["domains"],
            ["observed.example", "wire-observed.example"],
        )
        self.assertEqual(result["hosts"], [])
        self.assertEqual(result["users"], [])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("203.0.113.200", serialized)
        self.assertNotIn("provider-result.example", serialized)
        self.assertNotIn("intel-author", serialized)
        self.assertNotIn("192.168.1.7", serialized)
        self.assertNotIn("security-onion-sensor", serialized)

    def test_collector_retains_explicit_endpoint_observables_with_global_bound(self) -> None:
        row = {
            "alert_id": (
                ".ds-logs-detections.alerts-so-2026.07.22-000001:"
                "endpoint-event"
            ),
            "event_dataset": "sigma.alert",
            "source_ip": "",
            "destination_ip": "",
            "alert_json": json.dumps({
                "event": {"dataset": "sigma.alert"},
                "host": {
                    "name": "endpoint-01",
                    "id": "host-id-01",
                    "ip": ["203.0.113.77"],
                },
                "agent": {"id": "agent-id-01"},
                "user": {"name": "alice"},
                "destination": {"address": "destination-observed.example"},
                "related": {
                    "ip": [f"192.0.2.{value}" for value in range(1, 17)],
                },
            }),
            "raw_event_json": json.dumps({
                "event_data": {
                    "event": {"dataset": "endpoint.events.network"},
                    "source": {"ip": "198.51.100.10"},
                    "destination": {"ip": "198.51.100.20"},
                    "dns": {
                        "question": {
                            "name": "endpoint-observed.example",
                        },
                    },
                },
            }),
        }

        result = self.collector.observables([row])

        self.assertIn("198.51.100.10", result["ips"])
        self.assertIn("198.51.100.20", result["ips"])
        self.assertIn("203.0.113.77", result["ips"])
        self.assertIn("endpoint-observed.example", result["domains"])
        self.assertIn("destination-observed.example", result["domains"])
        self.assertEqual(
            result["hosts"],
            ["endpoint-01", "host-id-01", "agent-id-01"],
        )
        self.assertEqual(result["users"], ["alice"])
        self.assertLessEqual(
            sum(len(values) for values in result.values()),
            self.collector.MAX_TOTAL_OBSERVABLES,
        )
        for kind, values in result.items():
            self.assertLessEqual(
                len(values),
                self.collector.MAX_OBSERVABLES_BY_KIND[kind],
            )

    def test_collector_classifies_explicit_ecs_address_values(self) -> None:
        row = {
            "alert_id": (
                ".ds-logs-detections.alerts-so-2026.07.22-000001:"
                "endpoint-address-event"
            ),
            "event_dataset": "sigma.alert",
            "source_ip": "",
            "destination_ip": "",
            "alert_json": json.dumps({
                "event": {"dataset": "sigma.alert"},
                "source": {"address": "192.0.2.44"},
                "destination": {"address": "destination.example."},
                "client": {"address": "198.51.100.44"},
                "server": {"address": "server.example"},
            }),
            "raw_event_json": "{}",
        }

        result = self.collector.observables([row])

        self.assertEqual(
            result["ips"],
            ["192.0.2.44", "198.51.100.44"],
        )
        self.assertEqual(
            result["domains"],
            ["destination.example", "server.example"],
        )

    def test_collector_prioritizes_endpoints_and_excludes_sensor_host_ip(self) -> None:
        grouped = []
        for value in range(1, 10):
            grouped.append({
                "alert_id": (
                    ".ds-logs-suricata.alerts-so-2026.07.22-000001:"
                    f"sensor-event-{value}"
                ),
                "event_dataset": "suricata.alert",
                "source_ip": f"192.0.2.{value}",
                "destination_ip": f"198.51.100.{value}",
                "alert_json": json.dumps({
                    "event": {"dataset": "suricata.alert"},
                    "host": {"ip": [f"203.0.113.{value}"]},
                    "related": {
                        "ip": [f"10.0.0.{value}"],
                    },
                    "dns": {
                        "question": {
                            "name": f"observed-{value}.example",
                        },
                    },
                    "url": {
                        "domain": f"url-{value}.example",
                    },
                }),
                "raw_event_json": "{}",
            })

        result = self.collector.observables(grouped)

        self.assertEqual(
            result["ips"],
            [
                "192.0.2.1",
                "198.51.100.1",
                "192.0.2.2",
                "198.51.100.2",
                "192.0.2.3",
                "198.51.100.3",
                "192.0.2.4",
                "198.51.100.4",
            ],
        )
        self.assertEqual(len(result["domains"]), 8)
        self.assertFalse(
            any(value.startswith("203.0.113.") for value in result["ips"])
        )
        self.assertFalse(
            any(value.startswith("10.0.0.") for value in result["ips"])
        )
        self.assertLessEqual(
            sum(len(values) for values in result.values()),
            self.collector.MAX_TOTAL_OBSERVABLES,
        )
        for kind, values in result.items():
            self.assertLessEqual(
                len(values),
                self.collector.MAX_OBSERVABLES_BY_KIND[kind],
            )


if __name__ == "__main__":
    unittest.main()
