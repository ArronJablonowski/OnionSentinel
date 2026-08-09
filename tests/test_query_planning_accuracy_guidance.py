#!/usr/bin/env python3
"""Regression checks for evidence-driven query and correlation guidance."""

from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROMPT_BUILDER = REPO_ROOT / "n8n" / "bin" / "build-ai-investigation-prompt.py"
PROMPT_CONTRACT = REPO_ROOT / "n8n" / "bin" / "prompt_response_contract.py"


class QueryPlanningAccuracyGuidanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder_source = PROMPT_BUILDER.read_text(encoding="utf-8")
        self.source = PROMPT_CONTRACT.read_text(encoding="utf-8")

    def test_builder_uses_extracted_response_contract(self) -> None:
        self.assertIn("from prompt_response_contract import (", self.builder_source)
        self.assertIn("build_prompt_contract(", self.builder_source)

    def test_v2_schema_advertises_anchor_nearest(self) -> None:
        self.assertIn(
            '("|anchor_nearest" if request.query_v2 else "")',
            self.source,
        )
        self.assertIn(
            "anchor_nearest is Elastic-only and uses the trusted alert anchor",
            self.source,
        )

    def test_endpoint_history_guidance_rejects_broad_causal_inference(self) -> None:
        self.assertIn("For osquery_history, prefer Elastic anchor_nearest", self.source)
        self.assertIn(
            "broad timeline sample from a high-volume endpoint index is context, not causal process attribution",
            self.source,
        )
        self.assertIn("network source port as ephemeral", self.source)
        self.assertIn("process.executable", self.source)
        self.assertIn("not proof of trust or authorization", self.source)

    def test_episode_correlation_requires_exact_join_evidence(self) -> None:
        self.assertIn("Correlate DNS resolution followed by TLS", self.source)
        self.assertIn("same exact process.entity_id", self.source)
        self.assertIn("Do not merge events merely because", self.source)
        self.assertIn("Require a bounded time relationship", self.source)


if __name__ == "__main__":
    unittest.main()
