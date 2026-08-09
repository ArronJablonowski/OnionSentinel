#!/usr/bin/env python3
"""Compatibility contracts for the configured prompt evidence facade."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import prompt_builder_policy as policy  # noqa: E402
import prompt_evidence_facade as facade  # noqa: E402


def load_builder():
    path = BIN / "build-ai-investigation-prompt.py"
    spec = importlib.util.spec_from_file_location("prompt_builder_facade_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load prompt builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PromptEvidenceFacadeTests(unittest.TestCase):
    def test_legacy_builder_reexports_evidence_entry_points(self):
        builder = load_builder()
        names = (
            "alert_group_rows",
            "authorized_activity_context",
            "canonical_authorized_activity_entry",
            "compact_alert",
            "compact_pcap_analysis",
            "correlated_alert_context",
            "execution_lineage",
            "pcap_evidence_context",
            "public_enrichment_context",
            "select_alert",
        )

        for name in names:
            with self.subTest(name=name):
                self.assertIs(getattr(builder, name), getattr(facade, name))

    def test_facade_uses_the_shared_test_alert_policy(self):
        sql, params = facade.test_filter_sql("a.alert_id")

        self.assertEqual(params, list(policy.TEST_PREFIXES))
        self.assertEqual(sql.count("a.alert_id NOT LIKE ?"), len(policy.TEST_PREFIXES))

    def test_facade_source_records_bind_local_adapters(self):
        group_sources = facade._alert_group_sources()
        query_sources = facade._alert_query_sources()

        self.assertIs(group_sources.query_rows, facade.rows)
        self.assertIs(group_sources.alert_group_key, facade.alert_group_key)
        self.assertIs(query_sources.query_row, facade.row)
        self.assertIs(query_sources.test_filter_sql, facade.test_filter_sql)


if __name__ == "__main__":
    unittest.main()
