#!/usr/bin/env python3
"""Direct contracts for deterministic prompt package compaction."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_package_compactor import (  # noqa: E402
    PackageCompactionSources,
    compact_package_to_budget,
)


class PromptPackageCompactorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = PackageCompactionSources(
            mandatory_grounding_digest=lambda _package: "a" * 64,
            project_hits=lambda *_args, **_kwargs: 0,
            project_osquery_rows=lambda *_args, **_kwargs: 0,
            validate_incident_evidence=lambda value: value,
        )

    def test_small_package_remains_pretty_and_size_is_self_consistent(self):
        package, output = compact_package_to_budget(
            self.sources,
            {"instructions": ["small"]},
            262_144,
        )

        self.assertEqual(package["package_budget"]["serialization"], "pretty")
        self.assertFalse(package["package_budget"]["compacted"])
        self.assertEqual(json.loads(output), package)
        self.assertEqual(
            package["package_budget"]["serialized_bytes"],
            len(output.encode("utf-8")),
        )

    def test_lossless_compact_json_precedes_evidence_reduction(self):
        package, output = compact_package_to_budget(
            self.sources,
            {"instructions": ["bounded"] * 20_000, "related_alerts": list(range(20))},
            240_000,
        )

        self.assertLessEqual(len(output.encode("utf-8")), 240_000)
        self.assertEqual(package["related_alerts"], list(range(20)))
        self.assertEqual(package["package_budget"]["compaction_steps"], ["json_whitespace"])

    def test_pcap_compaction_prioritizes_exact_alert_evidence(self):
        package = {
            "related_alerts": [
                {"id": index, "detail": "x" * 200}
                for index in range(200)
            ],
            "pcap_evidence": {
                "parsed_evidence": [
                    {"request_id": "related", "evidence_relationship": "stable_group_related"},
                    {
                        "request_id": "exact",
                        "evidence_relationship": "exact_alert",
                        "_local_query_index": {"connections": list(range(40))},
                    },
                ]
            },
        }

        compacted, _output = compact_package_to_budget(
            self.sources,
            package,
            5_000,
        )

        pcap = compacted["pcap_evidence"]
        self.assertEqual(pcap["parsed_evidence"][0]["request_id"], "exact")
        self.assertEqual(pcap["exact_alert_evidence_count"], 1)
        self.assertEqual(
            len(pcap["parsed_evidence"][0]["_local_query_index"]["connections"]),
            8,
        )

    def test_unshrinkable_package_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "remains above"):
            compact_package_to_budget(
                self.sources,
                {"instructions": ["essential" * 1000]},
                100,
            )


if __name__ == "__main__":
    unittest.main()
