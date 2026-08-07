"""Direct composition contracts for mixed investigation query batches."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query.execution import batch  # noqa: E402


class BatchExecutionPackageTests(unittest.TestCase):
    def test_partitions_backends_and_assembles_stable_transition_order(self) -> None:
        requests = [
            {"query_id": "oql", "backend": "oql"},
            {"query_id": "endpoint", "backend": "osquery"},
            {"query_id": "derived", "backend": "pcap_zeek"},
            {"query_id": "elastic", "backend": "elastic"},
            {"query_id": "enrich", "backend": "enrichment"},
        ]
        calls: list[tuple[str, list[str]]] = []

        def transition(name):
            def run(selected):
                calls.append((name, [item["query_id"] for item in selected]))
                return SimpleNamespace(
                    results=[{"backend": name}], audits=[{"audit": name}]
                )
            return run

        artifact = batch.execute(
            requests,
            round_number=3,
            policy=batch.Policy(result_schema="results-v1"),
            dependencies=batch.Dependencies(
                security_onion=transition("security_onion"),
                endpoint=transition("endpoint"),
                derived=transition("derived"),
                enrichment=transition("enrichment"),
                now=lambda: "2026-07-24T01:00:00Z",
            ),
        )
        self.assertEqual(calls, [
            ("security_onion", ["oql", "elastic"]),
            ("endpoint", ["endpoint"]),
            ("derived", ["derived"]),
            ("enrichment", ["enrich"]),
        ])
        self.assertEqual(
            [item["backend"] for item in artifact["results"]],
            ["security_onion", "endpoint", "derived", "enrichment"],
        )
        self.assertEqual(artifact["schema"], "results-v1")
        self.assertEqual(artifact["round"], 3)
        self.assertEqual(artifact["generated_at"], "2026-07-24T01:00:00Z")
        self.assertIs(artifact["requests"], requests)

    def test_empty_batch_still_runs_noop_transitions_and_emits_round_artifact(self) -> None:
        calls: list[list] = []

        def noop(selected):
            calls.append(selected)
            return SimpleNamespace(results=[], audits=[])

        artifact = batch.execute(
            [], round_number=1, policy=batch.Policy(result_schema="results-v1"),
            dependencies=batch.Dependencies(
                security_onion=noop, endpoint=noop, derived=noop,
                enrichment=noop, now=lambda: "now",
            ),
        )
        self.assertEqual(calls, [[], [], [], []])
        self.assertEqual(artifact["results"], [])
        self.assertEqual(artifact["audit"], [])


if __name__ == "__main__":
    unittest.main()
