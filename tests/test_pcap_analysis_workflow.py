#!/usr/bin/env python3
"""Regression checks for Mac Studio PCAP evidence parsing and AI ingestion."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PCAP_WORKER_PATH = REPO_ROOT / "n8n" / "bin" / "process-pcap-evidence.py"
PROMPT_BUILDER_PATH = REPO_ROOT / "n8n" / "bin" / "build-ai-investigation-prompt.py"
AI_RUNNER_PATH = REPO_ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PcapAnalysisWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.worker = load_module("process_pcap_evidence", PCAP_WORKER_PATH)
        self.prompt_builder = load_module("build_ai_investigation_prompt", PROMPT_BUILDER_PATH)
        self.ai_runner = load_module("run_local_ai_analysis", AI_RUNNER_PATH)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_worker_records_missing_local_artifact_without_failing(self) -> None:
        args = type(
            "Args",
            (),
            {
                "artifact_dir": self.root / "artifacts",
                "out_dir": self.root / "pcap-analysis",
            },
        )()
        request = {
            "request_id": "pcap-unit-test",
            "alert_id": "alert-1",
            "group_id": "group-1",
            "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
            "status": "fulfilled",
        }

        analysis = self.worker.process_one(request, args)

        self.assertEqual(analysis["artifact_state"], "artifact-not-copied-to-mac")
        self.assertFalse(analysis["zeek"]["available"])
        self.assertFalse(analysis["tshark"]["available"])
        self.assertTrue((self.root / "pcap-analysis" / "pcap-unit-test-pcap-analysis.json").exists())
        self.assertTrue((self.root / "pcap-analysis" / "pcap-unit-test-pcap-analysis.md").exists())

    def test_prompt_package_includes_compact_pcap_evidence(self) -> None:
        analysis_dir = self.root / "pcap-analysis"
        analysis_dir.mkdir()
        (analysis_dir / "pcap-unit-test-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "generated_at": "2026-07-07  10:00:00-06:00",
                    "artifact_state": "copied-artifact",
                    "request": {"request_id": "pcap-unit-test", "alert_id": "alert-1", "group_id": "group-1"},
                    "pcap_files": [{"name": "capture.pcap", "size_bytes": 12, "sha256": "a" * 64, "path": "/tmp/capture.pcap"}],
                    "tool_paths": {"zeek": "/usr/local/bin/zeek", "tshark": "/usr/local/bin/tshark"},
                    "zeek": {
                        "available": True,
                        "record_counts": {"conn": 1, "dns": 1},
                        "top_connections": [{"count": 1, "id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.10"}],
                        "dns_queries": [{"count": 1, "query": "example.test"}],
                    },
                    "tshark": {"available": True, "samples": [{"pcap": "/tmp/capture.pcap", "conversations": "TCP Conversations"}]},
                }
            ),
            encoding="utf-8",
        )
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE pcap_requests (
              request_id TEXT,
              alert_id TEXT,
              group_id TEXT,
              status TEXT,
              created_at TEXT,
              claimed_at TEXT,
              completed_at TEXT,
              artifact_path TEXT,
              artifact_sha256 TEXT,
              artifact_size_bytes INTEGER,
              error TEXT
            );
            INSERT INTO pcap_requests VALUES (
              'pcap-unit-test', 'alert-1', 'group-1', 'fulfilled',
              '2026-07-07  09:59:00-06:00', NULL, '2026-07-07  10:00:00-06:00',
              '/nsm/pcapout/onion-sentinel/pcap-unit-test.tar', 'bbbb', 99, NULL
            );
            """
        )
        selected = {"alert_id": "alert-1"}

        context = self.prompt_builder.pcap_evidence_context(conn, selected, analysis_dir, 3)
        conn.close()

        self.assertEqual(len(context["pcap_requests"]), 1)
        self.assertEqual(len(context["parsed_evidence"]), 1)
        evidence = context["parsed_evidence"][0]
        self.assertEqual(evidence["zeek"]["record_counts"]["conn"], 1)
        self.assertEqual(evidence["tshark"]["samples"][0]["conversations"], "TCP Conversations")

    def test_ai_runner_renders_pcap_analysis_findings(self) -> None:
        response = {
            "summary": "Synthetic alert summary.",
            "likely_meaning": "Synthetic meaning.",
            "severity_reasoning": "Synthetic severity.",
            "alert_frequency_assessment": "Synthetic frequency.",
            "pcap_analysis_findings": ["Zeek saw one DNS query for example.test."],
            "false_positive_possibilities": [],
            "recommended_next_steps": ["Pivot in Security Onion."],
            "evidence_used": ["Synthetic evidence."],
            "evidence_gaps": [],
            "confidence": "medium",
            "escalation_needed": False,
            "hosted_second_opinion_recommended": False,
            "tuning_recommendation": "none",
            "tuning_reason": "No tuning needed.",
            "recommended_tuning_actions": [],
        }
        normalized = self.ai_runner.validate_response(response)
        markdown = self.ai_runner.render_markdown(
            {"alert": {"alert_id": "alert-1", "rule_name": "Unit Test", "triage_level": "low"}, "analysis_policy": {}},
            normalized,
            "2026-07-07  10:00:00-06:00",
            self.root / "analysis.json",
        )

        self.assertIn("## PCAP Analysis Findings", markdown)
        self.assertIn("Zeek saw one DNS query for example.test.", markdown)


if __name__ == "__main__":
    unittest.main()
