"""Direct contracts for ordinary evidence-tree reference traversal."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import references, registry, traversal  # noqa: E402


REFERENCE_POLICY = references.Policy(maximum_text_length=256)
POLICY = traversal.Policy(
    success_statuses=frozenset({"ok", "completed"}),
    columnar_schema="columnar-v1", maximum_list_items=1000,
)
DEPS = traversal.Dependencies(
    bounded_reference=lambda value: " ".join(str(value or "").split())[:256],
    result_bound_reference=lambda query, result="", **kwargs: references.result_bound(
        query, result, policy=REFERENCE_POLICY, **kwargs
    ),
)


def sink() -> registry.Registry:
    return registry.Registry(50, registry.Dependencies(
        bounded_reference=DEPS.bounded_reference,
        source_class=references.source_class,
        canonical_count=lambda value: (
            value if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        ),
    ))


class EvidenceTraversalPackageTests(unittest.TestCase):
    def test_query_pack_and_query_id_share_result_bound_digest(self) -> None:
        catalog = sink()
        traversal.visit({
            "query_id": "pivot-1", "pack": "network_flow", "status": "ok",
            "query_digest": "a" * 64, "result_digest": "b" * 64,
            "returned_hits": 2,
        }, ("investigation_query_results",), catalog, POLICY, DEPS)
        refs = {item["ref"]: item for item in catalog.contract()["references"]}
        suffix = ":" + "a" * 64 + ":" + "b" * 64
        self.assertIn("query" + suffix, refs)
        self.assertIn("pack:network_flow" + suffix, refs)
        self.assertIn("query-id:pivot-1" + suffix, refs)
        self.assertEqual(refs["query" + suffix]["returned"], 2)

    def test_pcap_request_reference_preserves_zero_row_negative_evidence(self) -> None:
        catalog = sink()
        traversal.visit({
            "request_id": "pcap-1", "status": "completed", "returned_rows": 0,
        }, ("pcap_evidence",), catalog, POLICY, DEPS)
        item = catalog.contract()["references"][0]
        self.assertEqual(item["ref"], "pcap_evidence:pcap-1")
        self.assertFalse(item["corroborating"])

    def test_nested_columnar_lookalike_is_inert(self) -> None:
        catalog = sink()
        traversal.visit({
            "schema": "columnar-v1",
            "query_digest": "a" * 64,
            "result_digest": "b" * 64,
            "status": "ok", "returned_hits": 1,
        }, ("asset_context",), catalog, POLICY, DEPS)
        self.assertEqual(catalog.contract()["references"], [])


if __name__ == "__main__":
    unittest.main()
