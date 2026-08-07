"""Direct contracts for bounded and result-bound evidence references."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import references  # noqa: E402


POLICY = references.Policy(maximum_text_length=512)


class EvidenceReferencesPackageTests(unittest.TestCase):
    def test_result_digest_binds_same_query_to_distinct_snapshots(self) -> None:
        first, first_digest = references.result_bound(
            "a" * 64, "b" * 64, policy=POLICY
        )
        second, second_digest = references.result_bound(
            "a" * 64, "c" * 64, policy=POLICY
        )
        self.assertNotEqual(first, second)
        self.assertEqual(first_digest, "b" * 64)
        self.assertEqual(second_digest, "c" * 64)

    def test_query_digest_is_fallback_when_result_digest_is_absent(self) -> None:
        reference, digest = references.result_bound("d" * 64, policy=POLICY)
        self.assertEqual(reference, "query:" + "d" * 64)
        self.assertEqual(digest, "d" * 64)

    def test_invalid_digest_namespace_or_missing_label_fails_closed(self) -> None:
        for args in (
            ("invalid", "", "query", ""),
            ("a" * 64, "", "unsafe", "label"),
            ("a" * 64, "", "pack", ""),
        ):
            self.assertEqual(
                references.result_bound(
                    args[0], args[1], namespace=args[2], label=args[3], policy=POLICY
                ),
                ("", ""),
            )

    def test_source_classes_group_related_security_onion_citations(self) -> None:
        self.assertEqual(
            references.source_class("grouped_alert_context.items"),
            "security_onion_detection",
        )
        self.assertEqual(
            references.source_class("investigation_query_results.rounds"),
            "security_onion_investigation_query",
        )


if __name__ == "__main__":
    unittest.main()
