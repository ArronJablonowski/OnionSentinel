"""Direct contracts for compact investigation provenance admission."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import columnar, references, registry  # noqa: E402


COLUMNS = (
    "round", "query_id", "backend_index", "status_index", "read_only",
    "query_digest", "result_digest", "evidence_ref_or_empty", "returned",
    "semantics_index", "result_summary_index",
)
POLICY = columnar.Policy(
    result_schema="results-v1", provenance_schema="columnar-v1",
    columns=COLUMNS, empty_ref_instruction="derive canonical query reference",
    success_statuses=frozenset({"ok"}), maximum_queries=12, maximum_rounds=3,
)
REFERENCE_POLICY = references.Policy(maximum_text_length=256)
DEPS = columnar.Dependencies(
    prompt_json_bytes=lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8"),
    canonical_count=lambda value: (
        value if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    ),
    result_bound_reference=lambda query, result="", **kwargs: references.result_bound(
        query, result, policy=REFERENCE_POLICY, **kwargs
    ),
)


def envelope() -> dict:
    value = {
        "schema": "results-v1",
        "rounds": [{
            "schema": "columnar-v1",
            "prompt_projection": "columnar_provenance_due_to_cumulative_byte_budget",
            "source_bytes": 1024, "source_sha256": "f" * 64,
            "source_provenance_rows": 1, "columns": list(COLUMNS),
            "backend_values": ["elastic"], "status_values": ["ok"],
            "semantics_values": ["Exact query semantics"],
            "result_summary_values": ["One matching record"],
            "empty_evidence_ref": "derive canonical query reference",
            "rows": [[1, "pivot-1", 0, 0, True, "a" * 64, "b" * 64, "", 1, 0, 0]],
            "omitted_rows": 0,
        }],
        "prompt_projection": {
            "max_bytes": 4096, "truncated": True,
            "columnar_provenance_fallback": True, "encoded_bytes": 0,
        },
    }
    for _ in range(5):
        size = len(DEPS.prompt_json_bytes(value))
        if value["prompt_projection"]["encoded_bytes"] == size:
            break
        value["prompt_projection"]["encoded_bytes"] = size
    return value


def sink() -> registry.Registry:
    return registry.Registry(20, registry.Dependencies(
        bounded_reference=lambda value: str(value or "")[:256],
        source_class=references.source_class,
        canonical_count=DEPS.canonical_count,
    ))


class EvidenceColumnarPackageTests(unittest.TestCase):
    def test_valid_top_level_envelope_registers_result_bound_references(self) -> None:
        catalog = sink()
        self.assertTrue(columnar.process(envelope(), catalog, POLICY, DEPS))
        refs = {item["ref"]: item for item in catalog.contract()["references"]}
        canonical = "query:" + "a" * 64 + ":" + "b" * 64
        self.assertIn(canonical, refs)
        self.assertTrue(refs[canonical]["corroborating"])
        self.assertEqual(refs[canonical]["returned"], 1)

    def test_malformed_claim_is_consumed_without_registering_evidence(self) -> None:
        value = envelope()
        value["rounds"][0]["columns"] = list(reversed(COLUMNS))
        catalog = sink()
        self.assertTrue(columnar.process(value, catalog, POLICY, DEPS))
        self.assertEqual(catalog.contract()["references"], [])

    def test_non_columnar_value_is_not_claimed(self) -> None:
        catalog = sink()
        self.assertFalse(columnar.process({"rounds": []}, catalog, POLICY, DEPS))
        self.assertEqual(catalog.contract()["references"], [])


if __name__ == "__main__":
    unittest.main()
